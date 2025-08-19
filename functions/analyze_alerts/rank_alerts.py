"""
Rank alerts by specified criteria
"""
from typing import Dict, Any
import structlog
from .._shared.opensearch_client import WazuhOpenSearchClient

logger = structlog.get_logger()

def get_field_mapping() -> Dict[str, str]:
    """Get field mapping for user-friendly field names"""
    return {
        "severity": "rule.level",
        "host": "agent.name", 
        "hosts": "agent.name",
        "rule": "rule.id",
        "rules": "rule.id",
        "user": "data.win.eventdata.targetUserName",
        "users": "data.win.eventdata.targetUserName", 
        "time": "@timestamp",
        "temporal": "@timestamp",
        "rule_groups": "rule.groups",
        "groups": "rule.groups",
        "rule_group": "rule.groups",
        "geographic": "agent.ip",
        "geo": "agent.ip", 
        "location": "agent.ip",
        "locations": "agent.ip",
        "ip": "agent.ip",
        "process": "data.win.eventdata.processName",
        "processes": "data.win.eventdata.processName"
    }

async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Rank alerts by specified criteria (e.g., top alerting hosts, users, rules)
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including group_by, filters, limit, time_range
        
    Returns:
        Ranked results with counts and latest alert details
    """
    try:
        # Extract parameters
        raw_group_by = params.get("group_by") or "agent.name"
        
        # Apply field mapping for user-friendly field names
        field_mapping = get_field_mapping()
        group_by = field_mapping.get(raw_group_by.lower(), raw_group_by) if isinstance(raw_group_by, str) else raw_group_by
        limit = params.get("limit", 10)
        time_range = params.get("time_range", "7d")
        filters = params.get("filters", {})
        
        # Handle case where filters is None
        if filters is None:
            filters = {}
        
        # Handle separate time_start and time_end parameters from LLM
        time_start = filters.pop("time_start", None)
        time_end = filters.pop("time_end", None)
        
        # If we have separate start/end times, construct a time range
        if time_start and time_end:
            from datetime import date
            today = date.today().strftime("%Y-%m-%d")
            time_range = f"{time_start} until {time_end}"
            logger.info("Converting separate time parameters to range", 
                       time_start=time_start, time_end=time_end, time_range=time_range)
        
        # Handle time_range in filters (LLM sometimes puts it there instead of main params)
        filter_time_range = filters.pop("time_range", None)
        if filter_time_range:
            time_range = filter_time_range
            logger.info("Using time_range from filters", time_range=time_range)
        
        logger.info("Ranking alerts", 
                   group_by=group_by, 
                   limit=limit, 
                   time_range=time_range)
        
        # Build base query
        query = {
            "query": {
                "bool": {
                    "must": [
                        opensearch_client.build_time_range_filter(time_range)
                    ]
                }
            },
            "aggs": {
                "ranked_entities": {
                    "terms": {
                        "field": group_by,
                        "size": limit,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "latest_alert": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"timestamp": {"order": "desc"}}],
                                "_source": [
                                    "rule.description", 
                                    "rule.level", 
                                    "rule.id",
                                    "rule.groups",
                                    "timestamp",
                                    "data.srcip",
                                    "data.srcuser"
                                ]
                            }
                        },
                        "severity_breakdown": {
                            "terms": {
                                "field": "rule.level",
                                "size": 10
                            }
                        }
                    }
                }
            }
        }
        
        # Add filters if provided
        if filters:
            filter_queries = opensearch_client.build_filters_query(filters)
            query["query"]["bool"]["must"].extend(filter_queries)
        
        # Execute query
        response = await opensearch_client.search(
            opensearch_client.alerts_index, 
            query, 
            size=0  # We only want aggregations
        )
        
        # Format results
        total_alerts = response["hits"]["total"]["value"] if isinstance(response["hits"]["total"], dict) else response["hits"]["total"]
        
        ranked_results = []
        for bucket in response["aggregations"]["ranked_entities"]["buckets"]:
            entity_data = {
                "entity": bucket["key"],
                "alert_count": bucket["doc_count"],
                "latest_alert": None,
                "severity_breakdown": {}
            }
            
            # Extract latest alert details
            if bucket["latest_alert"]["hits"]["hits"]:
                latest = bucket["latest_alert"]["hits"]["hits"][0]["_source"]
                entity_data["latest_alert"] = {
                    "rule_description": latest.get("rule", {}).get("description", ""),
                    "rule_level": latest.get("rule", {}).get("level", 0),
                    "rule_id": latest.get("rule", {}).get("id", ""),
                    "rule_groups": latest.get("rule", {}).get("groups", []),
                    "timestamp": latest.get("timestamp", ""),
                    "source_ip": latest.get("data", {}).get("srcip", ""),
                    "source_user": latest.get("data", {}).get("srcuser", "")
                }
            
            # Extract severity breakdown
            for severity_bucket in bucket["severity_breakdown"]["buckets"]:
                entity_data["severity_breakdown"][str(severity_bucket["key"])] = severity_bucket["doc_count"]
            
            ranked_results.append(entity_data)
        
        result = {
            "total_alerts": total_alerts,
            "time_range": time_range,
            "grouped_by": group_by,
            "ranked_entities": ranked_results,
            "query_info": {
                "filters_applied": bool(filters),
                "result_count": len(ranked_results)
            }
        }
        
        logger.info("Alert ranking completed", 
                   total_alerts=total_alerts,
                   entities_found=len(ranked_results),
                   group_by=group_by)
        
        return result
        
    except Exception as e:
        logger.error("Alert ranking failed", 
                    error=str(e), 
                    params=params)
        raise Exception(f"Failed to rank alerts: {str(e)}")

def get_severity_name(level: int) -> str:
    """
    Convert Wazuh alert level to severity name
    
    Args:
        level: Alert level number
        
    Returns:
        Severity name string
    """
    if level >= 12:
        return "Critical"
    elif level >= 8:
        return "High"
    elif level >= 5:
        return "Medium"
    elif level >= 3:
        return "Low"
    else:
        return "Informational"
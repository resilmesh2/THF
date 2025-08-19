"""
Filter alerts by specific criteria
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
    Filter alerts by specific criteria and return matching results
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including filters, time_range, limit
        
    Returns:
        Filtered alerts with details and metadata
    """
    try:
        # Extract parameters
        time_range = params.get("time_range", "7d")
        filters = params.get("filters", {})
        limit = params.get("limit", 50)
        
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
        
        logger.info("Filtering alerts", 
                   time_range=time_range, 
                   filters=filters,
                   limit=limit)
        
        # Build base query
        query = {
            "query": {
                "bool": {
                    "must": [
                        opensearch_client.build_time_range_filter(time_range)
                    ]
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ],
            "aggs": {
                "severity_summary": {
                    "terms": {
                        "field": "rule.level",
                        "size": 10,
                        "order": {"_key": "desc"}
                    }
                },
                "rule_summary": {
                    "terms": {
                        "field": "rule.id",
                        "size": 10,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "rule_details": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["rule.description", "rule.level", "rule.groups"]
                            }
                        }
                    }
                },
                "host_summary": {
                    "terms": {
                        "field": "agent.name",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                },
                "time_distribution": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "interval": "1h",
                        "format": "yyyy-MM-dd HH:mm"
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
            size=limit
        )
        
        # Format results
        total_alerts = response["hits"]["total"]["value"] if isinstance(response["hits"]["total"], dict) else response["hits"]["total"]
        
        # Process filtered alerts
        filtered_alerts = []
        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            alert = {
                "alert_id": hit["_id"],
                "timestamp": source.get("@timestamp", ""),
                "rule_id": source.get("rule", {}).get("id", ""),
                "rule_description": source.get("rule", {}).get("description", ""),
                "rule_level": source.get("rule", {}).get("level", 0),
                "rule_groups": source.get("rule", {}).get("groups", []),
                "agent_name": source.get("agent", {}).get("name", ""),
                "agent_ip": source.get("agent", {}).get("ip", ""),
                "source_ip": source.get("data", {}).get("srcip", ""),
                "source_user": source.get("data", {}).get("srcuser", ""),
                "destination_ip": source.get("data", {}).get("dstip", ""),
                "process_name": source.get("data", {}).get("win", {}).get("eventdata", {}).get("processName", ""),
                "full_log": source.get("full_log", "")[:200] + "..." if len(source.get("full_log", "")) > 200 else source.get("full_log", "")
            }
            filtered_alerts.append(alert)
        
        # Process severity summary
        severity_summary = {}
        for bucket in response["aggregations"]["severity_summary"]["buckets"]:
            level = bucket["key"]
            severity_summary[str(level)] = {
                "count": bucket["doc_count"],
                "severity_name": get_severity_name(level)
            }
        
        # Process rule summary
        rule_summary = []
        for bucket in response["aggregations"]["rule_summary"]["buckets"]:
            rule_data = {
                "rule_id": bucket["key"],
                "count": bucket["doc_count"]
            }
            
            # Get rule details
            if bucket["rule_details"]["hits"]["hits"]:
                rule_source = bucket["rule_details"]["hits"]["hits"][0]["_source"]
                rule_data["description"] = rule_source.get("rule", {}).get("description", "")
                rule_data["level"] = rule_source.get("rule", {}).get("level", 0)
                rule_data["groups"] = rule_source.get("rule", {}).get("groups", [])
            
            rule_summary.append(rule_data)
        
        # Process host summary
        host_summary = []
        for bucket in response["aggregations"]["host_summary"]["buckets"]:
            host_summary.append({
                "host_name": bucket["key"],
                "count": bucket["doc_count"]
            })
        
        # Process time distribution
        time_distribution = []
        for bucket in response["aggregations"]["time_distribution"]["buckets"]:
            time_distribution.append({
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"]
            })
        
        result = {
            "total_matching_alerts": total_alerts,
            "returned_alerts": len(filtered_alerts),
            "time_range": time_range,
            "filters_applied": filters,
            "filtered_alerts": filtered_alerts,
            "severity_summary": severity_summary,
            "rule_summary": rule_summary,
            "host_summary": host_summary,
            "time_distribution": time_distribution,
            "query_info": {
                "limit": limit,
                "filters_count": len(filters) if filters else 0
            }
        }
        
        logger.info("Alert filtering completed", 
                   total_matching=total_alerts,
                   returned=len(filtered_alerts),
                   time_range=time_range)
        
        return result
        
    except Exception as e:
        logger.error("Alert filtering failed", 
                    error=str(e), 
                    params=params)
        raise Exception(f"Failed to filter alerts: {str(e)}")

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
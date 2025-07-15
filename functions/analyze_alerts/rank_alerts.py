"""
Rank alerts by specified criteria
"""
from typing import Dict, Any
import structlog
from .._shared.opensearch_client import WazuhOpenSearchClient

logger = structlog.get_logger()

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
        group_by = params.get("group_by", "agent.name")
        limit = params.get("limit", 10)
        time_range = params.get("time_range", "7d")
        filters = params.get("filters", {})
        
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
"""
Get alerts for a specific entity (host, user, process, file)
"""
from typing import Dict, Any
import structlog
from .._shared.opensearch_client import WazuhOpenSearchClient

logger = structlog.get_logger()


async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get alerts associated with a specific entity
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including entity_type, entity_id, time_range
        
    Returns:
        Alerts for the specified entity with details and statistics
    """
    try:
        # Extract parameters
        entity_type = params.get("entity_type", "host")
        entity_id = params.get("entity_id")
        time_range = params.get("time_range", "24h")
        
        if not entity_id:
            raise ValueError("entity_id is required")
        
        logger.info("Getting alerts for entity",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    time_range=time_range)
        
        # Build entity query
        entity_query = opensearch_client.build_entity_query(entity_type, entity_id)
        
        # Build main query
        query = {
            "query": {
                "bool": {
                    "must": [
                        opensearch_client.build_time_range_filter(time_range),
                        entity_query
                    ]
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ],
            "aggs": {
                "severity_distribution": {
                    "terms": {
                        "field": "rule.level",
                        "size": 20
                    }
                },
                "rule_distribution": {
                    "terms": {
                        "field": "rule.id",
                        "size": 10
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
                "timeline": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "1h",
                        "format": "yyyy-MM-dd HH:mm"
                    }
                }
            }
        }
        
        # Execute query
        response = await opensearch_client.search(
            opensearch_client.alerts_index, 
            query, 
            size=50  # Return up to 50 recent alerts
        )
        
        # Format results
        total_alerts = response["hits"]["total"]["value"] if isinstance(response["hits"]["total"], dict) else response["hits"]["total"]
        
        # Process alerts
        alerts = []
        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            alert = {
                "timestamp": source.get("@timestamp", ""),
                "rule_id": source.get("rule", {}).get("id", ""),
                "rule_description": source.get("rule", {}).get("description", ""),
                "rule_level": source.get("rule", {}).get("level", 0),
                "rule_groups": source.get("rule", {}).get("groups", []),
                "agent_name": source.get("agent", {}).get("name", ""),
                "source_ip": source.get("data", {}).get("srcip", ""),
                "source_user": source.get("data", {}).get("srcuser", ""),
                "destination_ip": source.get("data", {}).get("dstip", ""),
                "process_name": source.get("data", {}).get("process", {}).get("name", ""),
                "file_name": source.get("data", {}).get("file", {}).get("name", ""),
                "full_log": source.get("full_log", "")
            }
            alerts.append(alert)
        
        # Process severity distribution
        severity_stats = {}
        for bucket in response["aggregations"]["severity_distribution"]["buckets"]:
            level = bucket["key"]
            severity_stats[str(level)] = {
                "count": bucket["doc_count"],
                "severity_name": get_severity_name(level)
            }
        
        # Process rule distribution
        rule_stats = []
        for bucket in response["aggregations"]["rule_distribution"]["buckets"]:
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
            
            rule_stats.append(rule_data)
        
        # Process timeline
        timeline = []
        for bucket in response["aggregations"]["timeline"]["buckets"]:
            timeline.append({
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"]
            })
        
        result = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "time_range": time_range,
            "total_alerts": total_alerts,
            "alerts": alerts,
            "severity_distribution": severity_stats,
            "top_rules": rule_stats,
            "timeline": timeline,
            "summary": {
                "most_common_rule": rule_stats[0] if rule_stats else None,
                "highest_severity": max([int(k) for k in severity_stats.keys()]) if severity_stats else 0,
                "alert_frequency": total_alerts / max(1, len(timeline)) if timeline else 0
            }
        }
        
        logger.info("Entity alert investigation completed",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    total_alerts=total_alerts)
        
        return result
        
    except Exception as e:
        logger.error("Entity alert investigation failed",
                     error=str(e),
                     params=params)
        raise Exception(f"Failed to get alerts for entity: {str(e)}")


def get_severity_name(level: int) -> str:
    """Convert Wazuh alert level to severity name"""
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

"""
Count alerts with optional filters
"""
from typing import Dict, Any
import structlog
from .._shared.opensearch_client import WazuhOpenSearchClient

logger = structlog.get_logger()

async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Count alerts matching specified criteria
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including filters, time_range
        
    Returns:
        Count results with breakdown by severity, rules, etc.
    """
    try:
        # Extract parameters
        time_range = params.get("time_range", "7d")
        filters = params.get("filters", {})
        
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
        
        logger.info("Counting alerts", 
                   time_range=time_range, 
                   filters=filters)
        
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
                "severity_counts": {
                    "terms": {
                        "field": "rule.level",
                        "size": 20,
                        "order": {"_key": "desc"}
                    }
                },
                "rule_counts": {
                    "terms": {
                        "field": "rule.id",
                        "size": 10,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "rule_description": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["rule.description", "rule.level"]
                            }
                        }
                    }
                },
                "hourly_distribution": {
                    "date_histogram": {
                        "field": "timestamp",
                        "interval": "1h",
                        "format": "yyyy-MM-dd HH:mm"
                    }
                },
                "agent_counts": {
                    "terms": {
                        "field": "agent.name",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                }
            }
        }
        
        # Add filters if provided
        if filters:
            filter_queries = opensearch_client.build_filters_query(filters)
            query["query"]["bool"]["must"].extend(filter_queries)
            logger.info("Applied filters to query", 
                       filters=filters, 
                       filter_queries=filter_queries)
        
        # Log the complete query for debugging
        logger.info("Executing OpenSearch query", 
                   index=opensearch_client.alerts_index,
                   query=query)
        
        # Execute query
        response = await opensearch_client.search(
            opensearch_client.alerts_index, 
            query, 
            size=0  # We only want aggregations
        )
        
        # Log the response for debugging
        logger.info("OpenSearch query response", 
                   total_hits=response.get("hits", {}).get("total", 0),
                   aggregations_keys=list(response.get("aggregations", {}).keys()) if response.get("aggregations") else [])
        
        # Format results
        total_alerts = response["hits"]["total"]["value"] if isinstance(response["hits"]["total"], dict) else response["hits"]["total"]
        
        # Process severity breakdown
        severity_breakdown = {}
        for bucket in response["aggregations"]["severity_counts"]["buckets"]:
            level = bucket["key"]
            count = bucket["doc_count"]
            severity_breakdown[str(level)] = {
                "count": count,
                "severity_name": get_severity_name(level)
            }
        
        # Process top rules
        top_rules = []
        for bucket in response["aggregations"]["rule_counts"]["buckets"]:
            rule_data = {
                "rule_id": bucket["key"],
                "count": bucket["doc_count"]
            }
            
            # Get rule description from top hit
            if bucket["rule_description"]["hits"]["hits"]:
                rule_source = bucket["rule_description"]["hits"]["hits"][0]["_source"]
                rule_data["description"] = rule_source.get("rule", {}).get("description", "")
                rule_data["level"] = rule_source.get("rule", {}).get("level", 0)
            
            top_rules.append(rule_data)
        
        # Process hourly distribution
        hourly_distribution = []
        for bucket in response["aggregations"]["hourly_distribution"]["buckets"]:
            hourly_distribution.append({
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"]
            })
        
        # Process top agents
        top_agents = []
        for bucket in response["aggregations"]["agent_counts"]["buckets"]:
            top_agents.append({
                "agent_name": bucket["key"],
                "count": bucket["doc_count"]
            })
        
        result = {
            "total_count": total_alerts,
            "time_range": time_range,
            "severity_breakdown": severity_breakdown,
            "top_rules": top_rules,
            "hourly_distribution": hourly_distribution,
            "top_agents": top_agents,
            "query_info": {
                "filters_applied": bool(filters),
                "filters": filters
            }
        }
        
        logger.info("Alert counting completed", 
                   total_count=total_alerts,
                   time_range=time_range)
        
        return result
        
    except Exception as e:
        logger.error("Alert counting failed", 
                    error=str(e), 
                    params=params)
        raise Exception(f"Failed to count alerts: {str(e)}")

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
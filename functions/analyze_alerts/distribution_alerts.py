"""
Analyze alert distribution patterns across various dimensions with multi-criteria grouping support
"""
from typing import Dict, Any, List, Union
import structlog
from .._shared.opensearch_client import WazuhOpenSearchClient

logger = structlog.get_logger()

async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze distribution patterns of alerts across multiple dimensions with dynamic grouping
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including time_range, filters, group_by, dimensions
        
    Returns:
        Multi-dimensional distribution analysis with cross-correlations
    """
    try:
        # Extract parameters
        time_range = params.get("time_range", "7d")
        filters = params.get("filters", {})
        group_by = params.get("group_by", "severity")  # Can be string or list for multi-criteria
        dimensions = params.get("dimensions", "all")  # Selective dimension calculation
        
        # Parse group_by parameter for multi-criteria support
        if isinstance(group_by, str):
            group_by_list = [dim.strip() for dim in group_by.split(",")] if "," in group_by else [group_by]
        else:
            group_by_list = group_by if isinstance(group_by, list) else [group_by]
        
        logger.info("Analyzing alert distribution", 
                   time_range=time_range, 
                   filters=bool(filters),
                   group_by=group_by_list,
                   dimensions=dimensions)
        
        # Build dynamic aggregation query based on group_by and dimensions
        query = {
            "query": {
                "bool": {
                    "must": [
                        opensearch_client.build_time_range_filter(time_range)
                    ]
                }
            },
            "aggs": {}
        }
        
        # Build dynamic aggregations based on parameters
        if len(group_by_list) > 1:
            # Multi-dimensional grouping using composite aggregation
            query["aggs"]["multi_dimensional_distribution"] = build_composite_aggregation(group_by_list)
        else:
            # Single dimension or all dimensions
            single_dim = group_by_list[0].lower()
            
            if dimensions == "all" or single_dim in ["severity", "all"]:
                query["aggs"]["severity_distribution"] = build_severity_distribution()
            
            if dimensions == "all" or single_dim in ["host", "hosts", "all"]:
                query["aggs"]["host_distribution"] = build_host_distribution()
            
            if dimensions == "all" or single_dim in ["rule", "rules", "all"]:
                query["aggs"]["rule_distribution"] = build_rule_distribution()
            
            if dimensions == "all" or single_dim in ["user", "users", "all"]:
                query["aggs"]["user_distribution"] = build_user_distribution()
            
            if dimensions == "all" or single_dim in ["time", "temporal", "all"]:
                query["aggs"]["time_distribution"] = build_time_distribution()
            
            if dimensions == "all" or single_dim in ["rule_groups", "groups", "all"]:
                query["aggs"]["rule_groups_distribution"] = build_rule_groups_distribution()
            
            if dimensions == "all" or single_dim in ["geographic", "geo", "ip", "all"]:
                query["aggs"]["geographic_distribution"] = build_geographic_distribution()
            
            if dimensions == "all" or single_dim in ["process", "processes", "all"]:
                query["aggs"]["process_distribution"] = build_process_distribution()
        
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
        
        # Process results based on aggregation type
        result_data = {}
        
        if "multi_dimensional_distribution" in response["aggregations"]:
            # Process composite aggregation results
            result_data = process_composite_results(response["aggregations"]["multi_dimensional_distribution"], total_alerts, group_by_list)
        else:
            # Process individual dimension results
            if "severity_distribution" in response["aggregations"]:
                result_data["severity"] = process_severity_distribution(response["aggregations"]["severity_distribution"], total_alerts)
            
            if "host_distribution" in response["aggregations"]:
                result_data["hosts"] = process_host_distribution(response["aggregations"]["host_distribution"], total_alerts)
            
            if "rule_distribution" in response["aggregations"]:
                result_data["rules"] = process_rule_distribution(response["aggregations"]["rule_distribution"], total_alerts)
            
            if "user_distribution" in response["aggregations"]:
                result_data["users"] = process_user_distribution(response["aggregations"]["user_distribution"], total_alerts)
            
            if "time_distribution" in response["aggregations"]:
                result_data["time"] = process_time_distribution(response["aggregations"]["time_distribution"], total_alerts)
            
            if "rule_groups_distribution" in response["aggregations"]:
                result_data["rule_groups"] = process_rule_groups_distribution(response["aggregations"]["rule_groups_distribution"], total_alerts)
            
            if "geographic_distribution" in response["aggregations"]:
                result_data["geographic"] = process_geographic_distribution(response["aggregations"]["geographic_distribution"], total_alerts)
            
            if "process_distribution" in response["aggregations"]:
                result_data["processes"] = process_process_distribution(response["aggregations"]["process_distribution"], total_alerts)
        
        result = {
            "total_alerts": total_alerts,
            "time_range": time_range,
            "analysis_type": "multi_dimensional" if len(group_by_list) > 1 else "distribution",
            "group_by_criteria": group_by_list,
            "dimensions_analyzed": list(result_data.keys()),
            "distributions": result_data,
            "summary": calculate_summary_stats(result_data),
            "query_info": {
                "filters_applied": bool(filters),
                "group_by": group_by_list,
                "dimensions": dimensions,
                "filters": filters,
                "multi_dimensional": len(group_by_list) > 1
            }
        }
        
        logger.info("Alert distribution analysis completed", 
                   total_alerts=total_alerts,
                   group_by_criteria=group_by_list,
                   dimensions_count=len(result_data),
                   multi_dimensional=len(group_by_list) > 1,
                   time_range=time_range)
        
        return result
        
    except Exception as e:
        logger.error("Alert distribution analysis failed", 
                    error=str(e), 
                    params=params)
        raise Exception(f"Failed to analyze alert distribution: {str(e)}")


# Dynamic Aggregation Builders
def build_composite_aggregation(group_by_list: List[str]) -> Dict[str, Any]:
    """Build composite aggregation for multi-dimensional grouping"""
    field_map = get_field_mapping()
    sources = []
    
    for dimension in group_by_list:
        dim_key = dimension.lower()
        if dim_key in field_map:
            sources.append({
                dim_key: {
                    "terms": {"field": field_map[dim_key]}
                }
            })
    
    return {
        "composite": {
            "sources": sources,
            "size": 100
        },
        "aggs": {
            "correlation_metrics": {
                "stats": {"field": "rule.level"}
            }
        }
    }

def build_severity_distribution() -> Dict[str, Any]:
    """Build severity distribution aggregation"""
    return {
        "terms": {
            "field": "rule.level",
            "size": 15,
            "order": {"_key": "desc"}
        },
        "aggs": {
            "severity_over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "interval": "4h",
                    "format": "yyyy-MM-dd HH:mm"
                }
            }
        }
    }

def build_host_distribution() -> Dict[str, Any]:
    """Build host distribution aggregation"""
    return {
        "terms": {
            "field": "agent.name",
            "size": 15,
            "order": {"_count": "desc"}
        },
        "aggs": {
            "host_severity_breakdown": {
                "terms": {
                    "field": "rule.level",
                    "size": 10
                }
            }
        }
    }

def build_rule_distribution() -> Dict[str, Any]:
    """Build rule distribution aggregation"""
    return {
        "terms": {
            "field": "rule.id",
            "size": 15,
            "order": {"_count": "desc"}
        },
        "aggs": {
            "rule_details": {
                "top_hits": {
                    "size": 1,
                    "_source": ["rule.description", "rule.level", "rule.groups"]
                }
            },
            "rule_hosts": {
                "terms": {
                    "field": "agent.name",
                    "size": 5
                }
            }
        }
    }

def build_user_distribution() -> Dict[str, Any]:
    """Build user distribution aggregation"""
    return {
        "terms": {
            "field": "data.win.eventdata.targetUserName",
            "size": 10,
            "order": {"_count": "desc"}
        },
        "aggs": {
            "user_activity_timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "interval": "2h",
                    "format": "yyyy-MM-dd HH:mm"
                }
            }
        }
    }

def build_time_distribution() -> Dict[str, Any]:
    """Build time distribution aggregation"""
    return {
        "date_histogram": {
            "field": "@timestamp",
            "interval": "1h",
            "format": "yyyy-MM-dd HH:mm"
        },
        "aggs": {
            "hourly_severity": {
                "terms": {
                    "field": "rule.level",
                    "size": 5
                }
            }
        }
    }

def build_rule_groups_distribution() -> Dict[str, Any]:
    """Build rule groups distribution aggregation"""
    return {
        "terms": {
            "field": "rule.groups",
            "size": 10,
            "order": {"_count": "desc"}
        }
    }

def build_geographic_distribution() -> Dict[str, Any]:
    """Build geographic distribution aggregation"""
    return {
        "terms": {
            "field": "agent.ip",
            "size": 10,
            "order": {"_count": "desc"}
        },
        "aggs": {
            "geo_hosts": {
                "terms": {
                    "field": "agent.name",
                    "size": 3
                }
            }
        }
    }

def build_process_distribution() -> Dict[str, Any]:
    """Build process distribution aggregation"""
    return {
        "terms": {
            "field": "data.win.eventdata.processName",
            "size": 10,
            "order": {"_count": "desc"}
        },
        "aggs": {
            "process_severity": {
                "terms": {
                    "field": "rule.level",
                    "size": 5
                }
            }
        }
    }

def get_field_mapping() -> Dict[str, str]:
    """Get field mapping for composite aggregations"""
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
        "geographic": "agent.ip",
        "geo": "agent.ip",
        "ip": "agent.ip",
        "process": "data.win.eventdata.processName",
        "processes": "data.win.eventdata.processName"
    }

# Result Processors
def process_composite_results(composite_agg: Dict[str, Any], total_alerts: int, group_by_list: List[str]) -> Dict[str, Any]:
    """Process composite aggregation results"""
    composite_data = []
    
    for bucket in composite_agg["buckets"]:
        bucket_data = {
            "key": bucket["key"],
            "count": bucket["doc_count"],
            "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0
        }
        
        # Add correlation metrics if available
        if "correlation_metrics" in bucket:
            bucket_data["correlation_metrics"] = bucket["correlation_metrics"]
        
        composite_data.append(bucket_data)
    
    return {
        "multi_dimensional": composite_data,
        "grouping_criteria": group_by_list,
        "total_combinations": len(composite_data)
    }

def process_severity_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process severity distribution results"""
    severity_distribution = []
    for bucket in agg_data["buckets"]:
        severity_data = {
            "severity_level": bucket["key"],
            "severity_name": get_severity_name(bucket["key"]),
            "count": bucket["doc_count"],
            "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0,
            "time_series": []
        }
        
        # Add time series data
        for time_bucket in bucket["severity_over_time"]["buckets"]:
            severity_data["time_series"].append({
                "timestamp": time_bucket["key_as_string"],
                "count": time_bucket["doc_count"]
            })
        
        severity_distribution.append(severity_data)
    
    return severity_distribution

def process_host_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process host distribution results"""
    host_distribution = []
    for bucket in agg_data["buckets"]:
        host_data = {
            "host_name": bucket["key"],
            "count": bucket["doc_count"],
            "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0,
            "severity_breakdown": {}
        }
        
        # Add severity breakdown for each host
        for severity_bucket in bucket["host_severity_breakdown"]["buckets"]:
            host_data["severity_breakdown"][str(severity_bucket["key"])] = {
                "count": severity_bucket["doc_count"],
                "severity_name": get_severity_name(severity_bucket["key"])
            }
        
        host_distribution.append(host_data)
    
    return host_distribution

def process_rule_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process rule distribution results"""
    rule_distribution = []
    for bucket in agg_data["buckets"]:
        rule_data = {
            "rule_id": bucket["key"],
            "count": bucket["doc_count"],
            "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0,
            "affected_hosts": []
        }
        
        # Add rule details
        if bucket["rule_details"]["hits"]["hits"]:
            rule_source = bucket["rule_details"]["hits"]["hits"][0]["_source"]
            rule_data["description"] = rule_source.get("rule", {}).get("description", "")
            rule_data["level"] = rule_source.get("rule", {}).get("level", 0)
            rule_data["groups"] = rule_source.get("rule", {}).get("groups", [])
        
        # Add affected hosts
        for host_bucket in bucket["rule_hosts"]["buckets"]:
            rule_data["affected_hosts"].append({
                "host_name": host_bucket["key"],
                "count": host_bucket["doc_count"]
            })
        
        rule_distribution.append(rule_data)
    
    return rule_distribution

def process_user_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process user distribution results"""
    user_distribution = []
    for bucket in agg_data["buckets"]:
        if bucket["key"]:  # Skip empty usernames
            user_data = {
                "username": bucket["key"],
                "count": bucket["doc_count"],
                "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0,
                "activity_timeline": []
            }
            
            # Add activity timeline
            for time_bucket in bucket["user_activity_timeline"]["buckets"]:
                user_data["activity_timeline"].append({
                    "timestamp": time_bucket["key_as_string"],
                    "count": time_bucket["doc_count"]
                })
            
            user_distribution.append(user_data)
    
    return user_distribution

def process_time_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process time distribution results"""
    time_distribution = []
    for bucket in agg_data["buckets"]:
        time_data = {
            "timestamp": bucket["key_as_string"],
            "count": bucket["doc_count"],
            "severity_breakdown": {}
        }
        
        # Add severity breakdown for each time period
        for severity_bucket in bucket["hourly_severity"]["buckets"]:
            time_data["severity_breakdown"][str(severity_bucket["key"])] = {
                "count": severity_bucket["doc_count"],
                "severity_name": get_severity_name(severity_bucket["key"])
            }
        
        time_distribution.append(time_data)
    
    return time_distribution

def process_rule_groups_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process rule groups distribution results"""
    rule_groups_distribution = []
    for bucket in agg_data["buckets"]:
        rule_groups_distribution.append({
            "rule_group": bucket["key"],
            "count": bucket["doc_count"],
            "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0
        })
    
    return rule_groups_distribution

def process_geographic_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process geographic distribution results"""
    geographic_distribution = []
    for bucket in agg_data["buckets"]:
        geo_data = {
            "ip_address": bucket["key"],
            "count": bucket["doc_count"],
            "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0,
            "hosts": []
        }
        
        # Add hosts for each IP
        for host_bucket in bucket["geo_hosts"]["buckets"]:
            geo_data["hosts"].append({
                "host_name": host_bucket["key"],
                "count": host_bucket["doc_count"]
            })
        
        geographic_distribution.append(geo_data)
    
    return geographic_distribution

def process_process_distribution(agg_data: Dict[str, Any], total_alerts: int) -> List[Dict[str, Any]]:
    """Process process distribution results"""
    process_distribution = []
    for bucket in agg_data["buckets"]:
        if bucket["key"]:  # Skip empty process names
            process_data = {
                "process_name": bucket["key"],
                "count": bucket["doc_count"],
                "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0,
                "severity_breakdown": {}
            }
            
            # Add severity breakdown for each process
            for severity_bucket in bucket["process_severity"]["buckets"]:
                process_data["severity_breakdown"][str(severity_bucket["key"])] = {
                    "count": severity_bucket["doc_count"],
                    "severity_name": get_severity_name(severity_bucket["key"])
                }
            
            process_distribution.append(process_data)
    
    return process_distribution

def calculate_summary_stats(result_data: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate summary statistics from result data"""
    summary = {}
    
    if "hosts" in result_data:
        summary["unique_hosts"] = len(result_data["hosts"])
    if "rules" in result_data:
        summary["unique_rules"] = len(result_data["rules"])
    if "users" in result_data:
        summary["unique_users"] = len(result_data["users"])
    if "processes" in result_data:
        summary["unique_processes"] = len(result_data["processes"])
    if "time" in result_data:
        summary["time_span_hours"] = len(result_data["time"])
    if "multi_dimensional" in result_data:
        summary["total_combinations"] = result_data["multi_dimensional"]["total_combinations"]
    
    return summary

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
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
        
        logger.info("Parameter extraction", group_by=group_by, group_by_type=type(group_by))
        
        # Parse group_by parameter for multi-criteria support
        if isinstance(group_by, str):
            # logger.info("Processing string group_by", group_by=group_by, contains_comma="," in group_by)
            if "," in group_by:
                split_result = group_by.split(",")
                # logger.info("Split result", split_result=split_result)
                group_by_list = [dim.strip() for dim in split_result]
                # logger.info("Processed group_by_list", group_by_list=group_by_list)
            else:
                group_by_list = [group_by]
        elif isinstance(group_by, list):
            group_by_list = group_by
            # logger.info("Using list group_by", group_by_list=group_by_list)
        else:
            group_by_list = [str(group_by)] if group_by else ["severity"]
            # logger.info("Fallback group_by_list", group_by_list=group_by_list)
        
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
        logger.info("Group by list length", length=len(group_by_list))
        if len(group_by_list) > 1:
            # Multi-dimensional grouping using composite aggregation
            logger.info("Attempting multi-dimensional analysis", group_by_list=group_by_list)
            try:
                composite_agg = build_composite_aggregation(group_by_list)
                query["aggs"]["multi_dimensional_distribution"] = composite_agg
                logger.info("Successfully built composite aggregation")
            except Exception as e:
                logger.error("Failed to build composite aggregation", error=str(e))
                # Fallback to single dimension analysis
                single_dim = group_by_list[0].lower() if group_by_list else "severity"
                query["aggs"]["severity_distribution"] = build_severity_distribution()
        else:
            # Single dimension or all dimensions
            if not group_by_list:
                group_by_list = ["severity"]  # Default fallback
            single_dim = group_by_list[0].lower() if isinstance(group_by_list[0], str) else "severity"
            
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
            try:
                logger.info("Processing composite aggregation response", 
                           group_by_list=group_by_list,
                           aggregation_type=type(response["aggregations"]["multi_dimensional_distribution"]))
                result_data = process_composite_results(response["aggregations"]["multi_dimensional_distribution"], total_alerts, group_by_list)
                logger.info("Successfully processed composite results")
            except Exception as e:
                import traceback
                logger.error("Error processing composite results", 
                           error=str(e), 
                           group_by_list=group_by_list,
                           traceback=traceback.format_exc())
                # Fallback to empty result
                result_data = {
                    "multi_dimensional": [],
                    "grouping_criteria": group_by_list,
                    "total_combinations": 0,
                    "error": f"Multi-dimensional processing failed: {str(e)}"
                }
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
        
        summary_stats = calculate_summary_stats(result_data)
        
        result = {
            "total_alerts": total_alerts,
            "time_range": time_range,
            "analysis_type": "multi_dimensional" if len(group_by_list) > 1 else "distribution",
            "group_by_criteria": group_by_list,
            "dimensions_analyzed": list(result_data.keys()),
            "distributions": result_data,
            "summary": summary_stats,
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
            field_name = field_map[dim_key]
            # logger.info("Found field mapping", dim_key=dim_key, field_name=field_name)
            
            # Handle timestamp fields differently for composite aggregations
            if field_name == "@timestamp":
                sources.append({
                    dim_key: {
                        "date_histogram": {
                            "field": field_name,
                            "calendar_interval": "1h"
                        }
                    }
                })
            else:
                sources.append({
                    dim_key: {
                        "terms": {"field": field_name}
                    }
                })
        else:
            logger.warning("No field mapping found for dimension", dim_key=dim_key)
    
    if not sources:
        logger.error("No valid sources created for composite aggregation")
        # Fallback to simple terms aggregation
        return {
            "terms": {
                "field": "rule.level",
                "size": 10
            }
        }
    
    logger.info("Created composite aggregation", sources_count=len(sources))
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
        "location": "agent.ip",
        "locations": "agent.ip",
        "ip": "agent.ip",
        "process": "data.win.eventdata.processName",
        "processes": "data.win.eventdata.processName"
    }

# Result Processors
def process_composite_results(composite_agg: Dict[str, Any], total_alerts: int, group_by_list: List[str]) -> Dict[str, Any]:
    """Process composite aggregation results"""
    logger.info("Processing composite results", buckets_count=len(composite_agg.get("buckets", [])))
    composite_data = []
    
    for i, bucket in enumerate(composite_agg["buckets"]):
        try:
            # In composite aggregations, key is a dict with multiple dimensions
            composite_key = bucket["key"]
            logger.info("Processing bucket", key_type=type(composite_key), key_value=composite_key)
            
            bucket_data = {
                "composite_key": composite_key,  # Keep the full composite key
                "dimensions": {},  # Break down individual dimensions
                "count": bucket["doc_count"],
                "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0
            }
            
            # Extract individual dimension values from composite key
            if isinstance(composite_key, dict):
                for dim_name, dim_value in composite_key.items():
                    bucket_data["dimensions"][dim_name] = dim_value
            
            # Add correlation metrics if available
            if "correlation_metrics" in bucket:
                bucket_data["correlation_metrics"] = bucket["correlation_metrics"]
            
            composite_data.append(bucket_data)
            
        except Exception as e:
            logger.error("Error processing individual bucket", error=str(e), bucket=bucket)
            continue
    
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
    
    # Handle single-dimensional distributions
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
    
    # Handle multi-dimensional distributions
    if "multi_dimensional" in result_data:
        multi_data = result_data["multi_dimensional"]
        if isinstance(multi_data, list):
            # Multi-dimensional data is a list of bucket combinations
            summary["total_combinations"] = len(multi_data)
            
            # Extract unique hosts and severity levels from combinations
            unique_hosts = set()
            unique_severities = set()
            total_alerts = 0
            max_alerts = 0
            max_combination = None
            
            for bucket in multi_data:
                if "dimensions" in bucket:
                    dims = bucket["dimensions"]
                    if "host" in dims:
                        unique_hosts.add(dims["host"])
                    if "severity" in dims:
                        unique_severities.add(dims["severity"])
                
                if "count" in bucket:
                    alerts_count = bucket["count"]
                    total_alerts += alerts_count
                    if alerts_count > max_alerts:
                        max_alerts = alerts_count
                        max_combination = bucket.get("composite_key", {})
            
            summary["unique_hosts"] = len(unique_hosts)
            summary["unique_severity_levels"] = len(unique_severities)
            summary["total_distributed_alerts"] = total_alerts
            summary["max_alerts_in_combination"] = max_alerts
            summary["most_active_combination"] = max_combination
            
            # Calculate average alerts per combination
            if len(multi_data) > 0:
                summary["average_alerts_per_combination"] = round(total_alerts / len(multi_data), 2)
        
        elif isinstance(multi_data, dict) and "total_combinations" in multi_data:
            # Legacy format support
            summary["total_combinations"] = multi_data["total_combinations"]
    
    # Handle total_combinations at root level (current format)
    if "total_combinations" in result_data:
        summary["total_combinations"] = result_data["total_combinations"]
    
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
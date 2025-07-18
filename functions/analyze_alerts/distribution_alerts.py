"""
Analyze alert distribution patterns across various dimensions
"""
from typing import Dict, Any
import structlog
from .._shared.opensearch_client import WazuhOpenSearchClient

logger = structlog.get_logger()

async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze distribution patterns of alerts across multiple dimensions
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including time_range, filters, group_by
        
    Returns:
        Distribution analysis across severity, time, hosts, rules, users, etc.
    """
    try:
        # Extract parameters
        time_range = params.get("time_range", "7d")
        filters = params.get("filters", {})
        group_by = params.get("group_by", "severity")  # severity, time, host, rule, user
        
        logger.info("Analyzing alert distribution", 
                   time_range=time_range, 
                   filters=bool(filters),
                   group_by=group_by)
        
        # Build comprehensive distribution query
        query = {
            "query": {
                "bool": {
                    "must": [
                        opensearch_client.build_time_range_filter(time_range)
                    ]
                }
            },
            "aggs": {
                "severity_distribution": {
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
                },
                "host_distribution": {
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
                },
                "rule_distribution": {
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
                },
                "user_distribution": {
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
                },
                "time_distribution": {
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
                },
                "rule_groups_distribution": {
                    "terms": {
                        "field": "rule.groups",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                },
                "geographic_distribution": {
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
                },
                "process_distribution": {
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
        
        # Process severity distribution
        severity_distribution = []
        for bucket in response["aggregations"]["severity_distribution"]["buckets"]:
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
        
        # Process host distribution
        host_distribution = []
        for bucket in response["aggregations"]["host_distribution"]["buckets"]:
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
        
        # Process rule distribution
        rule_distribution = []
        for bucket in response["aggregations"]["rule_distribution"]["buckets"]:
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
        
        # Process user distribution
        user_distribution = []
        for bucket in response["aggregations"]["user_distribution"]["buckets"]:
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
        
        # Process time distribution
        time_distribution = []
        for bucket in response["aggregations"]["time_distribution"]["buckets"]:
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
        
        # Process rule groups distribution
        rule_groups_distribution = []
        for bucket in response["aggregations"]["rule_groups_distribution"]["buckets"]:
            rule_groups_distribution.append({
                "rule_group": bucket["key"],
                "count": bucket["doc_count"],
                "percentage": round((bucket["doc_count"] / total_alerts) * 100, 2) if total_alerts > 0 else 0
            })
        
        # Process geographic distribution
        geographic_distribution = []
        for bucket in response["aggregations"]["geographic_distribution"]["buckets"]:
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
        
        # Process process distribution
        process_distribution = []
        for bucket in response["aggregations"]["process_distribution"]["buckets"]:
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
        
        result = {
            "total_alerts": total_alerts,
            "time_range": time_range,
            "analysis_type": "distribution",
            "distributions": {
                "severity": severity_distribution,
                "hosts": host_distribution,
                "rules": rule_distribution,
                "users": user_distribution,
                "time": time_distribution,
                "rule_groups": rule_groups_distribution,
                "geographic": geographic_distribution,
                "processes": process_distribution
            },
            "summary": {
                "unique_hosts": len(host_distribution),
                "unique_rules": len(rule_distribution),
                "unique_users": len(user_distribution),
                "unique_processes": len(process_distribution),
                "time_span_hours": len(time_distribution)
            },
            "query_info": {
                "filters_applied": bool(filters),
                "group_by": group_by,
                "filters": filters
            }
        }
        
        logger.info("Alert distribution analysis completed", 
                   total_alerts=total_alerts,
                   unique_hosts=len(host_distribution),
                   unique_rules=len(rule_distribution),
                   time_range=time_range)
        
        return result
        
    except Exception as e:
        logger.error("Alert distribution analysis failed", 
                    error=str(e), 
                    params=params)
        raise Exception(f"Failed to analyze alert distribution: {str(e)}")

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
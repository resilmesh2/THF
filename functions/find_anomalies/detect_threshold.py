"""
Detect threshold-based anomalies in Wazuh alerts
"""
from typing import Dict, Any, List
import structlog
from datetime import datetime, timedelta

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect threshold-based anomalies in alerts
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including threshold, metric, timeframe, baseline
        
    Returns:
        Threshold anomaly results with exceeded thresholds, affected entities, and analysis
    """
    try:
        # Extract parameters
        threshold = params.get("threshold", 50)  # Default threshold
        metric = params.get("metric", "alert_count")  # What to measure
        timeframe = params.get("timeframe", "24h")
        baseline = params.get("baseline", "7d")  # Baseline period for comparison
        limit = params.get("limit", 20)
        
        logger.info("Detecting threshold anomalies", 
                   threshold=threshold,
                   metric=metric,
                   timeframe=timeframe,
                   baseline=baseline)
        
        # Build base query for current timeframe
        must_conditions = [
            opensearch_client.build_time_range_filter(timeframe)
        ]
        
        # Build main query for threshold analysis
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "size": 0,  # We only need aggregations
            "aggs": {
                "host_alert_counts": {
                    "terms": {
                        "field": "agent.name",
                        "size": 100,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "severity_breakdown": {
                            "terms": {
                                "field": "rule.level",
                                "size": 10
                            }
                        },
                        "rule_breakdown": {
                            "terms": {
                                "field": "rule.groups",
                                "size": 10
                            }
                        },
                        "hourly_distribution": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "1h"
                            }
                        }
                    }
                },
                "user_alert_counts": {
                    "terms": {
                        "field": "data.win.eventdata.targetUserName",
                        "size": 50,
                        "order": {"_count": "desc"}
                    }
                },
                "rule_alert_counts": {
                    "terms": {
                        "field": "rule.id",
                        "size": 50,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "rule_description": {
                            "terms": {
                                "field": "rule.description",
                                "size": 1
                            }
                        }
                    }
                },
                "failed_login_analysis": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"wildcard": {"rule.description": "*failed*"}},
                                {"wildcard": {"rule.description": "*authentication*failure*"}},
                                {"wildcard": {"rule.description": "*logon*failed*"}},
                                {"terms": {"rule.groups": ["authentication_failed", "authentication_failures"]}}
                            ]
                        }
                    },
                    "aggs": {
                        "hosts_with_failures": {
                            "terms": {
                                "field": "agent.name",
                                "size": 20
                            }
                        },
                        "users_with_failures": {
                            "terms": {
                                "field": "data.win.eventdata.targetUserName",
                                "size": 20
                            }
                        }
                    }
                },
                "high_severity_analysis": {
                    "filter": {
                        "range": {
                            "rule.level": {"gte": 8}
                        }
                    },
                    "aggs": {
                        "hosts_high_severity": {
                            "terms": {
                                "field": "agent.name",
                                "size": 20
                            }
                        }
                    }
                },
                "new_entities": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "interval": "1d"
                    },
                    "aggs": {
                        "unique_hosts": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "unique_users": {
                            "cardinality": {
                                "field": "data.win.eventdata.targetUserName"
                            }
                        }
                    }
                }
            }
        }
        
        # Execute search
        response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=query
        )
        
        # Extract results
        hits = response.get("hits", {})
        total_alerts = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else hits.get("total", 0)
        
        # Process aggregations
        hosts_agg = response.get("aggregations", {}).get("host_alert_counts", {})
        users_agg = response.get("aggregations", {}).get("user_alert_counts", {})
        rules_agg = response.get("aggregations", {}).get("rule_alert_counts", {})
        failed_logins_agg = response.get("aggregations", {}).get("failed_login_analysis", {})
        high_severity_agg = response.get("aggregations", {}).get("high_severity_analysis", {})
        new_entities_agg = response.get("aggregations", {}).get("new_entities", {})
        
        # Analyze host threshold anomalies
        host_anomalies = []
        for bucket in hosts_agg.get("buckets", []):
            host = bucket["key"]
            alert_count = bucket["doc_count"]
            
            if alert_count > threshold:
                # Get severity breakdown
                severity_breakdown = {}
                for sev_bucket in bucket.get("severity_breakdown", {}).get("buckets", []):
                    severity_breakdown[str(sev_bucket["key"])] = sev_bucket["doc_count"]
                
                # Get rule breakdown
                rule_breakdown = []
                for rule_bucket in bucket.get("rule_breakdown", {}).get("buckets", []):
                    rule_breakdown.append({
                        "rule_group": rule_bucket["key"],
                        "count": rule_bucket["doc_count"]
                    })
                
                # Get hourly distribution
                hourly_pattern = []
                for hour_bucket in bucket.get("hourly_distribution", {}).get("buckets", []):
                    hourly_pattern.append({
                        "hour": hour_bucket["key_as_string"],
                        "count": hour_bucket["doc_count"]
                    })
                
                # Calculate anomaly score
                anomaly_score = min(100, (alert_count / threshold) * 10)
                
                host_anomalies.append({
                    "entity": host,
                    "entity_type": "host",
                    "alert_count": alert_count,
                    "threshold_exceeded": alert_count - threshold,
                    "anomaly_score": round(anomaly_score, 2),
                    "severity_breakdown": severity_breakdown,
                    "rule_breakdown": rule_breakdown,
                    "hourly_pattern": hourly_pattern[:24],  # Last 24 hours
                    "risk_level": "Critical" if alert_count > threshold * 3 else "High" if alert_count > threshold * 2 else "Medium"
                })
        
        # Analyze user threshold anomalies
        user_anomalies = []
        for bucket in users_agg.get("buckets", []):
            user = bucket["key"]
            alert_count = bucket["doc_count"]
            
            if alert_count > (threshold // 2):  # Lower threshold for users
                anomaly_score = min(100, (alert_count / (threshold // 2)) * 10)
                
                user_anomalies.append({
                    "entity": user,
                    "entity_type": "user",
                    "alert_count": alert_count,
                    "threshold_exceeded": alert_count - (threshold // 2),
                    "anomaly_score": round(anomaly_score, 2),
                    "risk_level": "High" if alert_count > threshold else "Medium"
                })
        
        # Analyze rule threshold anomalies
        rule_anomalies = []
        for bucket in rules_agg.get("buckets", []):
            rule_id = bucket["key"]
            alert_count = bucket["doc_count"]
            
            # Get rule description
            rule_description = "Unknown"
            desc_buckets = bucket.get("rule_description", {}).get("buckets", [])
            if desc_buckets:
                rule_description = desc_buckets[0]["key"]
            
            if alert_count > (threshold * 1.5):  # Higher threshold for rules
                anomaly_score = min(100, (alert_count / (threshold * 1.5)) * 10)
                
                rule_anomalies.append({
                    "entity": rule_id,
                    "entity_type": "rule",
                    "rule_description": rule_description,
                    "alert_count": alert_count,
                    "threshold_exceeded": alert_count - (threshold * 1.5),
                    "anomaly_score": round(anomaly_score, 2),
                    "risk_level": "Critical" if alert_count > threshold * 5 else "High"
                })
        
        # Analyze failed login anomalies
        failed_login_anomalies = []
        failed_login_total = failed_logins_agg.get("doc_count", 0)
        
        if failed_login_total > (threshold // 5):  # Failed login threshold
            # Hosts with most failures
            failed_hosts = []
            for bucket in failed_logins_agg.get("hosts_with_failures", {}).get("buckets", []):
                failed_hosts.append({
                    "host": bucket["key"],
                    "failed_attempts": bucket["doc_count"]
                })
            
            # Users with most failures
            failed_users = []
            for bucket in failed_logins_agg.get("users_with_failures", {}).get("buckets", []):
                failed_users.append({
                    "user": bucket["key"],
                    "failed_attempts": bucket["doc_count"]
                })
            
            failed_login_anomalies.append({
                "anomaly_type": "failed_authentication",
                "total_failures": failed_login_total,
                "threshold": threshold // 5,
                "affected_hosts": failed_hosts[:10],
                "affected_users": failed_users[:10],
                "risk_level": "High" if failed_login_total > threshold else "Medium"
            })
        
        # Analyze high severity anomalies
        high_severity_anomalies = []
        high_severity_total = high_severity_agg.get("doc_count", 0)
        
        if high_severity_total > 5:  # High severity threshold
            high_severity_hosts = []
            for bucket in high_severity_agg.get("hosts_high_severity", {}).get("buckets", []):
                high_severity_hosts.append({
                    "host": bucket["key"],
                    "high_severity_count": bucket["doc_count"]
                })
            
            high_severity_anomalies.append({
                "anomaly_type": "high_severity_alerts",
                "total_high_severity": high_severity_total,
                "threshold": 5,
                "affected_hosts": high_severity_hosts[:10],
                "risk_level": "Critical"
            })
        
        # Analyze new entity anomalies
        new_entity_anomalies = []
        for bucket in new_entities_agg.get("buckets", []):
            day = bucket["key_as_string"]
            unique_hosts = bucket.get("unique_hosts", {}).get("value", 0)
            unique_users = bucket.get("unique_users", {}).get("value", 0)
            
            if unique_hosts > 10 or unique_users > 20:  # New entity thresholds
                new_entity_anomalies.append({
                    "date": day,
                    "new_hosts": unique_hosts,
                    "new_users": unique_users,
                    "anomaly_reason": "High number of new entities"
                })
        
        # Sort anomalies by score
        host_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        user_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        rule_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        
        # Build result
        result = {
            "total_alerts": total_alerts,
            "analysis_period": timeframe,
            "threshold_settings": {
                "base_threshold": threshold,
                "host_threshold": threshold,
                "user_threshold": threshold // 2,
                "rule_threshold": threshold * 1.5,
                "failed_login_threshold": threshold // 5
            },
            "host_anomalies": host_anomalies[:limit],
            "user_anomalies": user_anomalies[:limit],
            "rule_anomalies": rule_anomalies[:limit],
            "failed_login_anomalies": failed_login_anomalies,
            "high_severity_anomalies": high_severity_anomalies,
            "new_entity_anomalies": new_entity_anomalies,
            "summary": {
                "total_anomalies": len(host_anomalies) + len(user_anomalies) + len(rule_anomalies),
                "hosts_above_threshold": len(host_anomalies),
                "users_above_threshold": len(user_anomalies),
                "rules_above_threshold": len(rule_anomalies),
                "highest_anomaly_host": host_anomalies[0]["entity"] if host_anomalies else None,
                "highest_anomaly_score": host_anomalies[0]["anomaly_score"] if host_anomalies else 0,
                "critical_anomalies": len([a for a in host_anomalies + user_anomalies + rule_anomalies if a.get("risk_level") == "Critical"]),
                "risk_assessment": "Critical" if any(a.get("risk_level") == "Critical" for a in host_anomalies + user_anomalies + rule_anomalies) else "High" if host_anomalies or user_anomalies or rule_anomalies else "Low"
            }
        }
        
        logger.info("Threshold anomaly detection completed", 
                   total_alerts=total_alerts,
                   anomalies_found=result["summary"]["total_anomalies"],
                   critical_anomalies=result["summary"]["critical_anomalies"])
        
        return result
        
    except Exception as e:
        logger.error("Threshold anomaly detection failed", error=str(e))
        raise Exception(f"Failed to detect threshold anomalies: {str(e)}")
"""
Detect behavioral anomalies in Wazuh alerts by comparing current behavior to baselines
"""
from typing import Dict, Any, List
import structlog
from datetime import datetime, timedelta
import statistics

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect behavioral anomalies by comparing current behavior to historical baselines
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including timeframe, baseline, metric
        
    Returns:
        Behavioral anomaly results with baseline deviations, behavioral shifts, and risk assessment
    """
    try:
        # Extract parameters
        timeframe = params.get("timeframe", "24h")
        baseline = params.get("baseline", "7d")  # Baseline comparison period
        metric = params.get("metric", "activity_level")
        threshold = params.get("threshold", 2.0)  # Standard deviation threshold
        limit = params.get("limit", 20)
        
        logger.info("Detecting behavioral anomalies", 
                   timeframe=timeframe,
                   baseline=baseline,
                   metric=metric,
                   threshold=threshold)
        
        # Build queries for current period and baseline period
        current_query = {
            "query": {
                "bool": {
                    "must": [opensearch_client.build_time_range_filter(timeframe)]
                }
            },
            "size": 0,
            "aggs": {
                "host_behavior": {
                    "terms": {
                        "field": "agent.name",
                        "size": 100
                    },
                    "aggs": {
                        "hourly_activity": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "1h"
                            }
                        },
                        "rule_diversity": {
                            "cardinality": {
                                "field": "rule.id"
                            }
                        },
                        "severity_profile": {
                            "terms": {
                                "field": "rule.level",
                                "size": 10
                            }
                        },
                        "rule_groups": {
                            "terms": {
                                "field": "rule.groups",
                                "size": 15
                            }
                        }
                    }
                },
                "user_behavior": {
                    "terms": {
                        "field": "data.win.eventdata.targetUserName",
                        "size": 50
                    },
                    "aggs": {
                        "activity_timeline": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "2h"
                            }
                        },
                        "host_diversity": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "activity_types": {
                            "terms": {
                                "field": "rule.groups",
                                "size": 10
                            }
                        }
                    }
                },
                "rule_behavior": {
                    "terms": {
                        "field": "rule.id",
                        "size": 50
                    },
                    "aggs": {
                        "firing_pattern": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "2h"
                            }
                        },
                        "host_spread": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "rule_description": {
                            "terms": {
                                "field": "rule.description",
                                "size": 1
                            }
                        }
                    }
                }
            }
        }
        
        # Build baseline query (excluding current timeframe)
        baseline_end = "now"
        if timeframe.endswith('h'):
            baseline_end = f"now-{timeframe}"
        elif timeframe.endswith('d'):
            baseline_end = f"now-{timeframe}"
        
        baseline_query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"now-{baseline}", "lte": baseline_end}}}
                    ]
                }
            },
            "size": 0,
            "aggs": current_query["aggs"]  # Same aggregations for baseline
        }
        
        # Execute both queries
        current_response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=current_query
        )
        
        baseline_response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=baseline_query
        )
        
        # Extract results
        current_total = current_response.get("hits", {}).get("total", {}).get("value", 0)
        baseline_total = baseline_response.get("hits", {}).get("total", {}).get("value", 0)
        
        # Process current period data
        current_hosts = {bucket["key"]: {
            "alert_count": bucket["doc_count"],
            "rule_diversity": bucket.get("rule_diversity", {}).get("value", 0),
            "hourly_pattern": [b["doc_count"] for b in bucket.get("hourly_activity", {}).get("buckets", [])],
            "severity_profile": {str(b["key"]): b["doc_count"] for b in bucket.get("severity_profile", {}).get("buckets", [])},
            "rule_groups": {b["key"]: b["doc_count"] for b in bucket.get("rule_groups", {}).get("buckets", [])}
        } for bucket in current_response.get("aggregations", {}).get("host_behavior", {}).get("buckets", [])}
        
        current_users = {bucket["key"]: {
            "activity_count": bucket["doc_count"],
            "host_diversity": bucket.get("host_diversity", {}).get("value", 0),
            "activity_pattern": [b["doc_count"] for b in bucket.get("activity_timeline", {}).get("buckets", [])],
            "activity_types": {b["key"]: b["doc_count"] for b in bucket.get("activity_types", {}).get("buckets", [])}
        } for bucket in current_response.get("aggregations", {}).get("user_behavior", {}).get("buckets", [])}
        
        current_rules = {bucket["key"]: {
            "firing_count": bucket["doc_count"],
            "host_spread": bucket.get("host_spread", {}).get("value", 0),
            "firing_pattern": [b["doc_count"] for b in bucket.get("firing_pattern", {}).get("buckets", [])],
            "description": bucket.get("rule_description", {}).get("buckets", [{}])[0].get("key", "Unknown")
        } for bucket in current_response.get("aggregations", {}).get("rule_behavior", {}).get("buckets", [])}
        
        # Process baseline data
        baseline_hosts = {bucket["key"]: {
            "alert_count": bucket["doc_count"],
            "rule_diversity": bucket.get("rule_diversity", {}).get("value", 0),
            "hourly_pattern": [b["doc_count"] for b in bucket.get("hourly_activity", {}).get("buckets", [])],
            "severity_profile": {str(b["key"]): b["doc_count"] for b in bucket.get("severity_profile", {}).get("buckets", [])},
            "rule_groups": {b["key"]: b["doc_count"] for b in bucket.get("rule_groups", {}).get("buckets", [])}
        } for bucket in baseline_response.get("aggregations", {}).get("host_behavior", {}).get("buckets", [])}
        
        baseline_users = {bucket["key"]: {
            "activity_count": bucket["doc_count"],
            "host_diversity": bucket.get("host_diversity", {}).get("value", 0),
            "activity_pattern": [b["doc_count"] for b in bucket.get("activity_timeline", {}).get("buckets", [])],
            "activity_types": {b["key"]: b["doc_count"] for b in bucket.get("activity_types", {}).get("buckets", [])}
        } for bucket in baseline_response.get("aggregations", {}).get("user_behavior", {}).get("buckets", [])}
        
        baseline_rules = {bucket["key"]: {
            "firing_count": bucket["doc_count"],
            "host_spread": bucket.get("host_spread", {}).get("value", 0),
            "firing_pattern": [b["doc_count"] for b in bucket.get("firing_pattern", {}).get("buckets", [])],
            "description": bucket.get("rule_description", {}).get("buckets", [{}])[0].get("key", "Unknown")
        } for bucket in baseline_response.get("aggregations", {}).get("rule_behavior", {}).get("buckets", [])}
        
        # Analyze host behavioral anomalies
        host_anomalies = []
        for host, current_data in current_hosts.items():
            baseline_data = baseline_hosts.get(host)
            
            if not baseline_data:
                # New host that wasn't in baseline
                host_anomalies.append({
                    "entity": host,
                    "entity_type": "host",
                    "anomaly_type": "new_entity",
                    "current_activity": current_data["alert_count"],
                    "baseline_activity": 0,
                    "deviation": "N/A - New entity",
                    "anomaly_score": 75,
                    "risk_level": "Medium",
                    "behavioral_changes": ["New host not seen in baseline period"]
                })
                continue
            
            # Calculate behavioral changes
            behavioral_changes = []
            anomaly_score = 0
            
            # Activity level change
            activity_change = abs(current_data["alert_count"] - baseline_data["alert_count"])
            if baseline_data["alert_count"] > 0:
                activity_ratio = current_data["alert_count"] / baseline_data["alert_count"]
                if activity_ratio > 3 or activity_ratio < 0.3:
                    behavioral_changes.append(f"Activity level changed by {activity_ratio:.1f}x")
                    anomaly_score += 30
            
            # Rule diversity change
            diversity_change = abs(current_data["rule_diversity"] - baseline_data["rule_diversity"])
            if baseline_data["rule_diversity"] > 0:
                diversity_ratio = current_data["rule_diversity"] / baseline_data["rule_diversity"]
                if diversity_ratio > 2 or diversity_ratio < 0.5:
                    behavioral_changes.append(f"Rule diversity changed by {diversity_ratio:.1f}x")
                    anomaly_score += 25
            
            # Severity profile change
            current_severities = set(current_data["severity_profile"].keys())
            baseline_severities = set(baseline_data["severity_profile"].keys())
            new_severities = current_severities - baseline_severities
            if new_severities:
                behavioral_changes.append(f"New severity levels: {', '.join(new_severities)}")
                anomaly_score += 20
            
            # Rule group changes
            current_groups = set(current_data["rule_groups"].keys())
            baseline_groups = set(baseline_data["rule_groups"].keys())
            new_groups = current_groups - baseline_groups
            if len(new_groups) > 2:
                behavioral_changes.append(f"New rule groups: {len(new_groups)} new types")
                anomaly_score += 15
            
            if behavioral_changes:
                host_anomalies.append({
                    "entity": host,
                    "entity_type": "host",
                    "anomaly_type": "behavioral_change",
                    "current_activity": current_data["alert_count"],
                    "baseline_activity": baseline_data["alert_count"],
                    "deviation": f"{activity_ratio:.2f}x baseline" if baseline_data["alert_count"] > 0 else "N/A",
                    "anomaly_score": min(100, anomaly_score),
                    "risk_level": "Critical" if anomaly_score > 70 else "High" if anomaly_score > 40 else "Medium",
                    "behavioral_changes": behavioral_changes
                })
        
        # Analyze user behavioral anomalies
        user_anomalies = []
        for user, current_data in current_users.items():
            baseline_data = baseline_users.get(user)
            
            if not baseline_data:
                # New user
                if current_data["activity_count"] > 5:  # Only flag active new users
                    user_anomalies.append({
                        "entity": user,
                        "entity_type": "user",
                        "anomaly_type": "new_entity",
                        "current_activity": current_data["activity_count"],
                        "baseline_activity": 0,
                        "deviation": "N/A - New user",
                        "anomaly_score": 60,
                        "risk_level": "Medium",
                        "behavioral_changes": ["New user not seen in baseline period"]
                    })
                continue
            
            behavioral_changes = []
            anomaly_score = 0
            
            # Activity level change
            if baseline_data["activity_count"] > 0:
                activity_ratio = current_data["activity_count"] / baseline_data["activity_count"]
                if activity_ratio > 5 or activity_ratio < 0.2:
                    behavioral_changes.append(f"Activity level changed by {activity_ratio:.1f}x")
                    anomaly_score += 40
            
            # Host diversity change (potential lateral movement)
            if baseline_data["host_diversity"] > 0:
                host_diversity_ratio = current_data["host_diversity"] / baseline_data["host_diversity"]
                if host_diversity_ratio > 3:
                    behavioral_changes.append(f"Host diversity increased by {host_diversity_ratio:.1f}x (potential lateral movement)")
                    anomaly_score += 50
            
            # Activity type changes
            current_types = set(current_data["activity_types"].keys())
            baseline_types = set(baseline_data["activity_types"].keys())
            new_types = current_types - baseline_types
            if len(new_types) > 3:
                behavioral_changes.append(f"New activity types: {len(new_types)} new patterns")
                anomaly_score += 30
            
            if behavioral_changes:
                user_anomalies.append({
                    "entity": user,
                    "entity_type": "user",
                    "anomaly_type": "behavioral_change",
                    "current_activity": current_data["activity_count"],
                    "baseline_activity": baseline_data["activity_count"],
                    "deviation": f"{activity_ratio:.2f}x baseline" if baseline_data["activity_count"] > 0 else "N/A",
                    "anomaly_score": min(100, anomaly_score),
                    "risk_level": "Critical" if anomaly_score > 80 else "High" if anomaly_score > 50 else "Medium",
                    "behavioral_changes": behavioral_changes
                })
        
        # Analyze rule behavioral anomalies
        rule_anomalies = []
        for rule_id, current_data in current_rules.items():
            baseline_data = baseline_rules.get(rule_id)
            
            if not baseline_data:
                # New rule firing
                if current_data["firing_count"] > 10:
                    rule_anomalies.append({
                        "entity": rule_id,
                        "entity_type": "rule",
                        "rule_description": current_data["description"],
                        "anomaly_type": "new_rule_activity",
                        "current_activity": current_data["firing_count"],
                        "baseline_activity": 0,
                        "deviation": "N/A - New rule activity",
                        "anomaly_score": 70,
                        "risk_level": "High",
                        "behavioral_changes": ["Rule started firing (not active in baseline)"]
                    })
                continue
            
            behavioral_changes = []
            anomaly_score = 0
            
            # Firing frequency change
            if baseline_data["firing_count"] > 0:
                firing_ratio = current_data["firing_count"] / baseline_data["firing_count"]
                if firing_ratio > 4 or firing_ratio < 0.25:
                    behavioral_changes.append(f"Firing frequency changed by {firing_ratio:.1f}x")
                    anomaly_score += 35
            
            # Host spread change
            if baseline_data["host_spread"] > 0:
                spread_ratio = current_data["host_spread"] / baseline_data["host_spread"]
                if spread_ratio > 3:
                    behavioral_changes.append(f"Host spread increased by {spread_ratio:.1f}x")
                    anomaly_score += 40
            
            if behavioral_changes:
                rule_anomalies.append({
                    "entity": rule_id,
                    "entity_type": "rule",
                    "rule_description": current_data["description"],
                    "anomaly_type": "behavioral_change",
                    "current_activity": current_data["firing_count"],
                    "baseline_activity": baseline_data["firing_count"],
                    "deviation": f"{firing_ratio:.2f}x baseline" if baseline_data["firing_count"] > 0 else "N/A",
                    "anomaly_score": min(100, anomaly_score),
                    "risk_level": "Critical" if anomaly_score > 75 else "High" if anomaly_score > 45 else "Medium",
                    "behavioral_changes": behavioral_changes
                })
        
        # Sort anomalies by score
        host_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        user_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        rule_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        
        # Build result
        result = {
            "current_period": {
                "timeframe": timeframe,
                "total_alerts": current_total
            },
            "baseline_period": {
                "timeframe": baseline,
                "total_alerts": baseline_total
            },
            "behavioral_analysis": {
                "host_anomalies": host_anomalies[:limit],
                "user_anomalies": user_anomalies[:limit],
                "rule_anomalies": rule_anomalies[:limit]
            },
            "summary": {
                "total_behavioral_anomalies": len(host_anomalies) + len(user_anomalies) + len(rule_anomalies),
                "hosts_with_anomalies": len(host_anomalies),
                "users_with_anomalies": len(user_anomalies),
                "rules_with_anomalies": len(rule_anomalies),
                "new_entities": len([a for a in host_anomalies + user_anomalies + rule_anomalies if a.get("anomaly_type") == "new_entity"]),
                "behavioral_changes": len([a for a in host_anomalies + user_anomalies + rule_anomalies if a.get("anomaly_type") == "behavioral_change"]),
                "highest_anomaly_score": max([a["anomaly_score"] for a in host_anomalies + user_anomalies + rule_anomalies]) if (host_anomalies or user_anomalies or rule_anomalies) else 0,
                "critical_anomalies": len([a for a in host_anomalies + user_anomalies + rule_anomalies if a.get("risk_level") == "Critical"]),
                "activity_change_ratio": current_total / baseline_total if baseline_total > 0 else float('inf'),
                "risk_assessment": "Critical" if any(a.get("risk_level") == "Critical" for a in host_anomalies + user_anomalies + rule_anomalies) else "High" if host_anomalies or user_anomalies or rule_anomalies else "Low"
            }
        }
        
        logger.info("Behavioral anomaly detection completed", 
                   current_alerts=current_total,
                   baseline_alerts=baseline_total,
                   behavioral_anomalies=result["summary"]["total_behavioral_anomalies"],
                   critical_anomalies=result["summary"]["critical_anomalies"])
        
        return result
        
    except Exception as e:
        logger.error("Behavioral anomaly detection failed", error=str(e))
        raise Exception(f"Failed to detect behavioral anomalies: {str(e)}")
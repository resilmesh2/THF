"""
Detect pattern-based anomalies in Wazuh alerts
"""
from typing import Dict, Any, List
import structlog
from datetime import datetime, timedelta
from collections import defaultdict

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect pattern-based anomalies in alerts
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including metric, timeframe, baseline
        
    Returns:
        Pattern anomaly results with unusual patterns, temporal anomalies, and behavioral shifts
    """
    try:
        # Extract parameters
        metric = params.get("metric", "time_pattern")
        timeframe = params.get("timeframe", "24h")
        baseline = params.get("baseline", "7d")
        limit = params.get("limit", 20)
        
        logger.info("Detecting pattern anomalies", 
                   metric=metric,
                   timeframe=timeframe,
                   baseline=baseline)
        
        # Build base query
        must_conditions = [
            opensearch_client.build_time_range_filter(timeframe)
        ]
        
        # Build main query for pattern analysis
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            },
            "size": 0,
            "aggs": {
                "hourly_patterns": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "interval": "1h"
                    },
                    "aggs": {
                        "hosts_active": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "unique_rules": {
                            "cardinality": {
                                "field": "rule.id"
                            }
                        },
                        "severity_distribution": {
                            "terms": {
                                "field": "rule.level",
                                "size": 10
                            }
                        }
                    }
                },
                "daily_patterns": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "interval": "1d"
                    },
                    "aggs": {
                        "peak_hours": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "1h"
                            }
                        }
                    }
                },
                "host_activity_patterns": {
                    "terms": {
                        "field": "agent.name",
                        "size": 50
                    },
                    "aggs": {
                        "activity_timeline": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "2h"
                            }
                        },
                        "rule_diversity": {
                            "cardinality": {
                                "field": "rule.id"
                            }
                        },
                        "unusual_hours": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "1h"
                            },
                            "aggs": {
                                "hour_of_day": {
                                    "date_histogram": {
                                        "field": "@timestamp",
                                        "interval": "1h",
                                        "format": "HH"
                                    }
                                }
                            }
                        }
                    }
                },
                "user_login_patterns": {
                    "terms": {
                        "field": "data.win.eventdata.targetUserName",
                        "size": 30
                    },
                    "aggs": {
                        "login_times": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "1h",
                                "format": "HH"
                            }
                        },
                        "login_hosts": {
                            "terms": {
                                "field": "agent.name",
                                "size": 10
                            }
                        }
                    }
                },
                "rule_firing_patterns": {
                    "terms": {
                        "field": "rule.id",
                        "size": 30
                    },
                    "aggs": {
                        "firing_timeline": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "1h"
                            }
                        },
                        "affected_hosts": {
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
                },
                "network_patterns": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"exists": {"field": "data.srcip"}},
                                {"exists": {"field": "data.dstip"}},
                                {"terms": {"rule.groups": ["network", "firewall", "web"]}}
                            ]
                        }
                    },
                    "aggs": {
                        "source_ips": {
                            "terms": {
                                "field": "data.srcip",
                                "size": 20
                            },
                            "aggs": {
                                "connection_times": {
                                    "date_histogram": {
                                        "field": "@timestamp",
                                        "interval": "1h"
                                    }
                                }
                            }
                        },
                        "destination_patterns": {
                            "terms": {
                                "field": "data.dstip",
                                "size": 20
                            }
                        }
                    }
                },
                "process_patterns": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"exists": {"field": "data.win.eventdata.image"}},
                                {"exists": {"field": "data.win.eventdata.commandLine"}},
                                {"terms": {"rule.groups": ["sysmon", "process_creation"]}}
                            ]
                        }
                    },
                    "aggs": {
                        "process_execution_times": {
                            "terms": {
                                "field": "data.win.eventdata.image",
                                "size": 20
                            },
                            "aggs": {
                                "execution_timeline": {
                                    "date_histogram": {
                                        "field": "@timestamp",
                                        "interval": "1h"
                                    }
                                }
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
        hourly_agg = response.get("aggregations", {}).get("hourly_patterns", {})
        daily_agg = response.get("aggregations", {}).get("daily_patterns", {})
        hosts_agg = response.get("aggregations", {}).get("host_activity_patterns", {})
        users_agg = response.get("aggregations", {}).get("user_login_patterns", {})
        rules_agg = response.get("aggregations", {}).get("rule_firing_patterns", {})
        network_agg = response.get("aggregations", {}).get("network_patterns", {})
        process_agg = response.get("aggregations", {}).get("process_patterns", {})
        
        # Analyze temporal patterns (unusual activity hours)
        temporal_anomalies = []
        hourly_activity = {}
        
        for bucket in hourly_agg.get("buckets", []):
            hour = datetime.fromisoformat(bucket["key_as_string"].replace('Z', '+00:00')).hour
            count = bucket["doc_count"]
            hosts_active = bucket.get("hosts_active", {}).get("value", 0)
            
            hourly_activity[hour] = {
                "count": count,
                "hosts_active": hosts_active
            }
        
        # Identify unusual hours (activity outside 8AM-6PM)
        unusual_hours = []
        for hour, data in hourly_activity.items():
            if (hour < 8 or hour > 18) and data["count"] > (total_alerts / 24 * 1.5):  # 150% of average
                unusual_hours.append({
                    "hour": f"{hour:02d}:00",
                    "alert_count": data["count"],
                    "hosts_active": data["hosts_active"],
                    "anomaly_reason": "High activity outside business hours"
                })
        
        if unusual_hours:
            temporal_anomalies.append({
                "pattern_type": "unusual_time_activity",
                "anomalous_hours": unusual_hours,
                "risk_level": "Medium"
            })
        
        # Analyze host activity patterns
        host_pattern_anomalies = []
        for bucket in hosts_agg.get("buckets", []):
            host = bucket["key"]
            alert_count = bucket["doc_count"]
            rule_diversity = bucket.get("rule_diversity", {}).get("value", 0)
            
            # Analyze activity timeline
            activity_spikes = []
            for time_bucket in bucket.get("activity_timeline", {}).get("buckets", []):
                time_count = time_bucket["doc_count"]
                if time_count > (alert_count / 12 * 3):  # 300% of average per 2-hour period
                    activity_spikes.append({
                        "time": time_bucket["key_as_string"],
                        "spike_count": time_count
                    })
            
            if activity_spikes or rule_diversity > 20:  # High rule diversity anomaly
                anomaly_score = min(100, (rule_diversity / 10) + (len(activity_spikes) * 20))
                
                host_pattern_anomalies.append({
                    "host": host,
                    "pattern_type": "unusual_activity_pattern",
                    "total_alerts": alert_count,
                    "rule_diversity": rule_diversity,
                    "activity_spikes": activity_spikes[:5],  # Top 5 spikes
                    "anomaly_score": round(anomaly_score, 2),
                    "anomaly_reasons": [
                        f"High rule diversity ({rule_diversity} different rules)" if rule_diversity > 20 else None,
                        f"Activity spikes detected ({len(activity_spikes)} spikes)" if activity_spikes else None
                    ],
                    "risk_level": "High" if anomaly_score > 60 else "Medium"
                })
        
        # Analyze user login patterns
        user_pattern_anomalies = []
        for bucket in users_agg.get("buckets", []):
            user = bucket["key"]
            login_count = bucket["doc_count"]
            
            # Analyze login times
            unusual_login_times = []
            for time_bucket in bucket.get("login_times", {}).get("buckets", []):
                hour = int(time_bucket["key_as_string"])
                if (hour < 6 or hour > 22) and time_bucket["doc_count"] > 1:
                    unusual_login_times.append({
                        "hour": f"{hour:02d}:00",
                        "login_count": time_bucket["doc_count"]
                    })
            
            # Analyze login hosts diversity
            login_hosts = []
            for host_bucket in bucket.get("login_hosts", {}).get("buckets", []):
                login_hosts.append({
                    "host": host_bucket["key"],
                    "login_count": host_bucket["doc_count"]
                })
            
            if unusual_login_times or len(login_hosts) > 5:
                user_pattern_anomalies.append({
                    "user": user,
                    "pattern_type": "unusual_login_pattern",
                    "total_logins": login_count,
                    "unusual_login_times": unusual_login_times,
                    "login_hosts": login_hosts,
                    "host_diversity": len(login_hosts),
                    "anomaly_reasons": [
                        f"Logins at unusual hours ({len(unusual_login_times)} instances)" if unusual_login_times else None,
                        f"High host diversity ({len(login_hosts)} different hosts)" if len(login_hosts) > 5 else None
                    ],
                    "risk_level": "High" if len(login_hosts) > 10 or len(unusual_login_times) > 5 else "Medium"
                })
        
        # Analyze rule firing patterns
        rule_pattern_anomalies = []
        for bucket in rules_agg.get("buckets", []):
            rule_id = bucket["key"]
            firing_count = bucket["doc_count"]
            affected_hosts = bucket.get("affected_hosts", {}).get("value", 0)
            
            # Get rule description
            rule_description = "Unknown"
            desc_buckets = bucket.get("rule_description", {}).get("buckets", [])
            if desc_buckets:
                rule_description = desc_buckets[0]["key"]
            
            # Analyze firing timeline for bursts
            firing_bursts = []
            for time_bucket in bucket.get("firing_timeline", {}).get("buckets", []):
                if time_bucket["doc_count"] > (firing_count / 24 * 5):  # 500% of average per hour
                    firing_bursts.append({
                        "time": time_bucket["key_as_string"],
                        "burst_count": time_bucket["doc_count"]
                    })
            
            if firing_bursts or affected_hosts > 10:
                rule_pattern_anomalies.append({
                    "rule_id": rule_id,
                    "rule_description": rule_description,
                    "pattern_type": "unusual_rule_firing",
                    "total_fires": firing_count,
                    "affected_hosts": affected_hosts,
                    "firing_bursts": firing_bursts[:3],  # Top 3 bursts
                    "anomaly_reasons": [
                        f"Firing bursts detected ({len(firing_bursts)} bursts)" if firing_bursts else None,
                        f"Wide host impact ({affected_hosts} hosts)" if affected_hosts > 10 else None
                    ],
                    "risk_level": "High" if affected_hosts > 20 or len(firing_bursts) > 3 else "Medium"
                })
        
        # Analyze network patterns
        network_pattern_anomalies = []
        network_total = network_agg.get("doc_count", 0)
        
        if network_total > 0:
            unusual_connections = []
            for bucket in network_agg.get("source_ips", {}).get("buckets", []):
                src_ip = bucket["key"]
                connection_count = bucket["doc_count"]
                
                if connection_count > 50:  # High connection threshold
                    unusual_connections.append({
                        "source_ip": src_ip,
                        "connection_count": connection_count,
                        "ip_type": "external" if not (src_ip.startswith("10.") or src_ip.startswith("192.168.") or src_ip.startswith("172.")) else "internal"
                    })
            
            if unusual_connections:
                network_pattern_anomalies.append({
                    "pattern_type": "unusual_network_connections",
                    "total_network_events": network_total,
                    "unusual_connections": unusual_connections[:10],
                    "risk_level": "High" if any(c["ip_type"] == "external" for c in unusual_connections) else "Medium"
                })
        
        # Analyze process execution patterns
        process_pattern_anomalies = []
        process_total = process_agg.get("doc_count", 0)
        
        if process_total > 0:
            unusual_processes = []
            for bucket in process_agg.get("process_execution_times", {}).get("buckets", []):
                process = bucket["key"]
                execution_count = bucket["doc_count"]
                
                # Check for execution bursts
                execution_bursts = []
                for time_bucket in bucket.get("execution_timeline", {}).get("buckets", []):
                    if time_bucket["doc_count"] > (execution_count / 24 * 3):  # 300% of average
                        execution_bursts.append({
                            "time": time_bucket["key_as_string"],
                            "execution_count": time_bucket["doc_count"]
                        })
                
                if execution_bursts or execution_count > 100:
                    unusual_processes.append({
                        "process": process,
                        "total_executions": execution_count,
                        "execution_bursts": execution_bursts[:3]
                    })
            
            if unusual_processes:
                process_pattern_anomalies.append({
                    "pattern_type": "unusual_process_execution",
                    "total_process_events": process_total,
                    "unusual_processes": unusual_processes[:10],
                    "risk_level": "Medium"
                })
        
        # Build result
        result = {
            "total_alerts": total_alerts,
            "analysis_period": timeframe,
            "pattern_analysis": {
                "temporal_anomalies": temporal_anomalies,
                "host_pattern_anomalies": host_pattern_anomalies[:limit],
                "user_pattern_anomalies": user_pattern_anomalies[:limit],
                "rule_pattern_anomalies": rule_pattern_anomalies[:limit],
                "network_pattern_anomalies": network_pattern_anomalies,
                "process_pattern_anomalies": process_pattern_anomalies
            },
            "summary": {
                "total_pattern_anomalies": (
                    len(temporal_anomalies) + len(host_pattern_anomalies) + 
                    len(user_pattern_anomalies) + len(rule_pattern_anomalies) +
                    len(network_pattern_anomalies) + len(process_pattern_anomalies)
                ),
                "hosts_with_anomalies": len(host_pattern_anomalies),
                "users_with_anomalies": len(user_pattern_anomalies),
                "rules_with_anomalies": len(rule_pattern_anomalies),
                "temporal_anomalies": len(temporal_anomalies),
                "network_anomalies": len(network_pattern_anomalies),
                "process_anomalies": len(process_pattern_anomalies),
                "highest_risk_pattern": "temporal" if temporal_anomalies else "host" if host_pattern_anomalies else "user" if user_pattern_anomalies else "none",
                "risk_assessment": "High" if any([host_pattern_anomalies, user_pattern_anomalies, network_pattern_anomalies]) else "Medium" if any([temporal_anomalies, rule_pattern_anomalies, process_pattern_anomalies]) else "Low"
            }
        }
        
        logger.info("Pattern anomaly detection completed", 
                   total_alerts=total_alerts,
                   pattern_anomalies=result["summary"]["total_pattern_anomalies"])
        
        return result
        
    except Exception as e:
        logger.error("Pattern anomaly detection failed", error=str(e))
        raise Exception(f"Failed to detect pattern anomalies: {str(e)}")
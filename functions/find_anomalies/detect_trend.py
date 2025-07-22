"""
Detect trend-based anomalies in Wazuh alerts by analyzing temporal patterns and changes over time
"""
from typing import Dict, Any, List
import structlog
from datetime import datetime, timedelta
import statistics

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detect trend-based anomalies by analyzing temporal patterns and changes over time
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including timeframe, trend_type, metric, baseline
        
    Returns:
        Trend anomaly results with increasing/decreasing patterns, trend analysis, and predictions
    """
    try:
        # Extract parameters
        timeframe = params.get("timeframe", "24h")
        trend_type = params.get("trend_type", "increasing")  # increasing, decreasing, both
        metric = params.get("metric", "alert_volume")
        baseline = params.get("baseline", "7d")  # Baseline period for trend comparison
        sensitivity = params.get("sensitivity", "medium")  # low, medium, high
        limit = params.get("limit", 20)
        
        logger.info("Detecting trend anomalies", 
                   timeframe=timeframe,
                   trend_type=trend_type,
                   metric=metric,
                   baseline=baseline,
                   sensitivity=sensitivity)
        
        # Build base query for trend analysis
        query = {
            "query": {
                "bool": {
                    "must": [opensearch_client.build_time_range_filter(timeframe)]
                }
            },
            "size": 0,
            "aggs": {
                "time_series": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "interval": "1h",
                        "order": {"_key": "asc"}
                    },
                    "aggs": {
                        "host_count": {
                            "cardinality": {
                                "field": "agent.name"
                            }
                        },
                        "user_count": {
                            "cardinality": {
                                "field": "data.win.eventdata.targetUserName"
                            }
                        },
                        "rule_diversity": {
                            "cardinality": {
                                "field": "rule.id"
                            }
                        },
                        "severity_weighted": {
                            "sum": {
                                "field": "rule.level"
                            }
                        },
                        "high_severity_count": {
                            "filter": {
                                "range": {
                                    "rule.level": {"gte": 8}
                                }
                            }
                        }
                    }
                },
                "host_trends": {
                    "terms": {
                        "field": "agent.name",
                        "size": 50
                    },
                    "aggs": {
                        "time_series": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "2h"
                            }
                        },
                        "severity_trend": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "2h"
                            },
                            "aggs": {
                                "avg_severity": {
                                    "avg": {
                                        "field": "rule.level"
                                    }
                                }
                            }
                        }
                    }
                },
                "user_trends": {
                    "terms": {
                        "field": "data.win.eventdata.targetUserName",
                        "size": 30
                    },
                    "aggs": {
                        "time_series": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "2h"
                            }
                        }
                    }
                },
                "rule_trends": {
                    "terms": {
                        "field": "rule.id",
                        "size": 30
                    },
                    "aggs": {
                        "time_series": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "1h"
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
                "failed_login_trends": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"wildcard": {"rule.description": "*failed*"}},
                                {"wildcard": {"rule.description": "*authentication*failure*"}},
                                {"terms": {"rule.groups": ["authentication_failed", "authentication_failures"]}}
                            ]
                        }
                    },
                    "aggs": {
                        "time_series": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "interval": "1h"
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
        
        # Process time series data
        time_series_agg = response.get("aggregations", {}).get("time_series", {})
        hosts_agg = response.get("aggregations", {}).get("host_trends", {})
        users_agg = response.get("aggregations", {}).get("user_trends", {})
        rules_agg = response.get("aggregations", {}).get("rule_trends", {})
        failed_logins_agg = response.get("aggregations", {}).get("failed_login_trends", {})
        
        # Set sensitivity thresholds
        trend_thresholds = {
            "low": {"slope": 0.1, "variance": 0.3, "correlation": 0.6},
            "medium": {"slope": 0.05, "variance": 0.2, "correlation": 0.7},
            "high": {"slope": 0.02, "variance": 0.1, "correlation": 0.8}
        }
        threshold = trend_thresholds.get(sensitivity, trend_thresholds["medium"])
        
        # Analyze overall alert volume trends
        alert_volume_trend = []
        time_points = []
        alert_counts = []
        
        for i, bucket in enumerate(time_series_agg.get("buckets", [])):
            timestamp = bucket["key_as_string"]
            count = bucket["doc_count"]
            host_count = bucket.get("host_count", {}).get("value", 0)
            user_count = bucket.get("user_count", {}).get("value", 0)
            rule_diversity = bucket.get("rule_diversity", {}).get("value", 0)
            severity_weighted = bucket.get("severity_weighted", {}).get("value", 0)
            high_severity = bucket.get("high_severity_count", {}).get("doc_count", 0)
            
            time_points.append(i)
            alert_counts.append(count)
            
            alert_volume_trend.append({
                "timestamp": timestamp,
                "alert_count": count,
                "host_count": host_count,
                "user_count": user_count,
                "rule_diversity": rule_diversity,
                "severity_weighted": severity_weighted,
                "high_severity_count": high_severity
            })
        
        # Calculate trend statistics for overall volume
        overall_trends = {}
        if len(time_points) >= 3:
            # Calculate linear regression slope
            n = len(time_points)
            sum_x = sum(time_points)
            sum_y = sum(alert_counts)
            sum_xy = sum(x * y for x, y in zip(time_points, alert_counts))
            sum_x2 = sum(x * x for x in time_points)
            
            if n * sum_x2 - sum_x * sum_x != 0:
                slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
                
                # Calculate correlation coefficient
                mean_x = statistics.mean(time_points)
                mean_y = statistics.mean(alert_counts)
                
                numerator = sum((x - mean_x) * (y - mean_y) for x, y in zip(time_points, alert_counts))
                denom_x = sum((x - mean_x) ** 2 for x in time_points)
                denom_y = sum((y - mean_y) ** 2 for y in alert_counts)
                
                correlation = numerator / (denom_x * denom_y) ** 0.5 if denom_x * denom_y > 0 else 0
                
                # Calculate variance
                variance = statistics.variance(alert_counts) if len(alert_counts) > 1 else 0
                variance_coefficient = (variance ** 0.5) / mean_y if mean_y > 0 else 0
                
                overall_trends = {
                    "slope": round(slope, 4),
                    "correlation": round(correlation, 3),
                    "variance_coefficient": round(variance_coefficient, 3),
                    "mean_alerts_per_hour": round(mean_y, 2),
                    "trend_direction": "increasing" if slope > threshold["slope"] else "decreasing" if slope < -threshold["slope"] else "stable",
                    "trend_strength": "strong" if abs(correlation) > threshold["correlation"] else "moderate" if abs(correlation) > 0.5 else "weak",
                    "volatility": "high" if variance_coefficient > threshold["variance"] else "medium" if variance_coefficient > 0.1 else "low"
                }
        
        # Analyze host-specific trends
        host_trend_anomalies = []
        for bucket in hosts_agg.get("buckets", []):
            host = bucket["key"]
            total_alerts = bucket["doc_count"]
            
            if total_alerts < 5:  # Skip hosts with too few alerts
                continue
            
            # Extract time series data for this host
            host_time_points = []
            host_alert_counts = []
            host_severity_trend = []
            
            for i, time_bucket in enumerate(bucket.get("time_series", {}).get("buckets", [])):
                host_time_points.append(i)
                host_alert_counts.append(time_bucket["doc_count"])
            
            for sev_bucket in bucket.get("severity_trend", {}).get("buckets", []):
                avg_sev = sev_bucket.get("avg_severity", {}).get("value", 0)
                host_severity_trend.append(avg_sev if avg_sev else 0)
            
            # Calculate host trend statistics
            if len(host_time_points) >= 3:
                n = len(host_time_points)
                sum_x = sum(host_time_points)
                sum_y = sum(host_alert_counts)
                sum_xy = sum(x * y for x, y in zip(host_time_points, host_alert_counts))
                sum_x2 = sum(x * x for x in host_time_points)
                
                if n * sum_x2 - sum_x * sum_x != 0:
                    host_slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
                    
                    # Check for trend anomalies
                    is_anomaly = False
                    anomaly_reasons = []
                    
                    if trend_type in ["increasing", "both"] and host_slope > threshold["slope"] * 2:
                        is_anomaly = True
                        anomaly_reasons.append(f"Rapidly increasing alert trend (slope: {host_slope:.3f})")
                    
                    if trend_type in ["decreasing", "both"] and host_slope < -threshold["slope"] * 2:
                        is_anomaly = True
                        anomaly_reasons.append(f"Rapidly decreasing alert trend (slope: {host_slope:.3f})")
                    
                    # Check severity trend
                    if len(host_severity_trend) >= 3:
                        severity_slope = statistics.linear_regression(range(len(host_severity_trend)), host_severity_trend).slope
                        if severity_slope > 0.5:
                            is_anomaly = True
                            anomaly_reasons.append(f"Increasing severity trend (slope: {severity_slope:.3f})")
                    
                    if is_anomaly:
                        host_trend_anomalies.append({
                            "host": host,
                            "total_alerts": total_alerts,
                            "trend_slope": round(host_slope, 4),
                            "trend_direction": "increasing" if host_slope > 0 else "decreasing",
                            "anomaly_score": min(100, abs(host_slope) * 1000),
                            "anomaly_reasons": anomaly_reasons,
                            "time_series": [{"period": i, "count": count} for i, count in enumerate(host_alert_counts)],
                            "risk_level": "High" if abs(host_slope) > threshold["slope"] * 5 else "Medium"
                        })
        
        # Analyze user activity trends
        user_trend_anomalies = []
        for bucket in users_agg.get("buckets", []):
            user = bucket["key"]
            total_activity = bucket["doc_count"]
            
            if total_activity < 3:  # Skip users with too little activity
                continue
            
            # Extract time series data for this user
            user_time_points = []
            user_activity_counts = []
            
            for i, time_bucket in enumerate(bucket.get("time_series", {}).get("buckets", [])):
                user_time_points.append(i)
                user_activity_counts.append(time_bucket["doc_count"])
            
            # Calculate user trend statistics
            if len(user_time_points) >= 3:
                try:
                    slope = statistics.linear_regression(user_time_points, user_activity_counts).slope
                    
                    # Check for significant trends
                    if abs(slope) > threshold["slope"]:
                        user_trend_anomalies.append({
                            "user": user,
                            "total_activity": total_activity,
                            "trend_slope": round(slope, 4),
                            "trend_direction": "increasing" if slope > 0 else "decreasing",
                            "anomaly_score": min(100, abs(slope) * 500),
                            "anomaly_reason": f"{'Increasing' if slope > 0 else 'Decreasing'} user activity trend",
                            "time_series": [{"period": i, "count": count} for i, count in enumerate(user_activity_counts)],
                            "risk_level": "Medium" if abs(slope) > threshold["slope"] * 2 else "Low"
                        })
                except:
                    continue  # Skip if regression fails
        
        # Analyze rule firing trends
        rule_trend_anomalies = []
        for bucket in rules_agg.get("buckets", []):
            rule_id = bucket["key"]
            total_fires = bucket["doc_count"]
            
            # Get rule description
            rule_description = "Unknown"
            desc_buckets = bucket.get("rule_description", {}).get("buckets", [])
            if desc_buckets:
                rule_description = desc_buckets[0]["key"]
            
            if total_fires < 5:  # Skip rules with too few fires
                continue
            
            # Extract time series data for this rule
            rule_time_points = []
            rule_fire_counts = []
            
            for i, time_bucket in enumerate(bucket.get("time_series", {}).get("buckets", [])):
                rule_time_points.append(i)
                rule_fire_counts.append(time_bucket["doc_count"])
            
            # Calculate rule trend statistics
            if len(rule_time_points) >= 3:
                try:
                    slope = statistics.linear_regression(rule_time_points, rule_fire_counts).slope
                    
                    # Check for significant trends
                    if abs(slope) > threshold["slope"] * 1.5:
                        rule_trend_anomalies.append({
                            "rule_id": rule_id,
                            "rule_description": rule_description,
                            "total_fires": total_fires,
                            "trend_slope": round(slope, 4),
                            "trend_direction": "increasing" if slope > 0 else "decreasing",
                            "anomaly_score": min(100, abs(slope) * 300),
                            "anomaly_reason": f"{'Increasing' if slope > 0 else 'Decreasing'} rule firing trend",
                            "time_series": [{"period": i, "count": count} for i, count in enumerate(rule_fire_counts)],
                            "risk_level": "High" if abs(slope) > threshold["slope"] * 3 else "Medium"
                        })
                except:
                    continue  # Skip if regression fails
        
        # Analyze failed login trends
        failed_login_trends = []
        failed_login_time_points = []
        failed_login_counts = []
        
        for i, bucket in enumerate(failed_logins_agg.get("time_series", {}).get("buckets", [])):
            failed_login_time_points.append(i)
            failed_login_counts.append(bucket["doc_count"])
            
            failed_login_trends.append({
                "timestamp": bucket["key_as_string"],
                "failed_attempts": bucket["doc_count"]
            })
        
        # Calculate failed login trend statistics
        failed_login_anomaly = None
        if len(failed_login_time_points) >= 3 and sum(failed_login_counts) > 0:
            try:
                slope = statistics.linear_regression(failed_login_time_points, failed_login_counts).slope
                total_failures = sum(failed_login_counts)
                
                if abs(slope) > threshold["slope"] and total_failures > 5:
                    failed_login_anomaly = {
                        "trend_slope": round(slope, 4),
                        "trend_direction": "increasing" if slope > 0 else "decreasing",
                        "total_failures": total_failures,
                        "anomaly_score": min(100, abs(slope) * 400),
                        "anomaly_reason": f"{'Increasing' if slope > 0 else 'Decreasing'} failed login trend",
                        "time_series": failed_login_trends,
                        "risk_level": "Critical" if slope > threshold["slope"] * 3 else "High"
                    }
            except:
                pass  # Skip if regression fails
        
        # Sort anomalies by score
        host_trend_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        user_trend_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        rule_trend_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        
        # Build result
        result = {
            "total_alerts": total_alerts,
            "analysis_period": timeframe,
            "trend_settings": {
                "trend_type": trend_type,
                "sensitivity": sensitivity,
                "thresholds": threshold
            },
            "overall_trends": overall_trends,
            "alert_volume_timeline": alert_volume_trend,
            "trend_analysis": {
                "host_trend_anomalies": host_trend_anomalies[:limit],
                "user_trend_anomalies": user_trend_anomalies[:limit],
                "rule_trend_anomalies": rule_trend_anomalies[:limit],
                "failed_login_trend": failed_login_anomaly
            },
            "summary": {
                "total_trend_anomalies": len(host_trend_anomalies) + len(user_trend_anomalies) + len(rule_trend_anomalies),
                "hosts_with_trends": len(host_trend_anomalies),
                "users_with_trends": len(user_trend_anomalies),
                "rules_with_trends": len(rule_trend_anomalies),
                "overall_trend_direction": overall_trends.get("trend_direction", "stable"),
                "overall_trend_strength": overall_trends.get("trend_strength", "weak"),
                "highest_anomaly_score": max([a["anomaly_score"] for a in host_trend_anomalies + user_trend_anomalies + rule_trend_anomalies]) if (host_trend_anomalies or user_trend_anomalies or rule_trend_anomalies) else 0,
                "critical_trends": len([a for a in host_trend_anomalies + user_trend_anomalies + rule_trend_anomalies if a.get("risk_level") == "Critical"]),
                "risk_assessment": "Critical" if failed_login_anomaly and failed_login_anomaly.get("risk_level") == "Critical" else "High" if host_trend_anomalies or user_trend_anomalies or rule_trend_anomalies else "Low"
            }
        }
        
        logger.info("Trend anomaly detection completed", 
                   total_alerts=total_alerts,
                   trend_anomalies=result["summary"]["total_trend_anomalies"],
                   overall_trend=result["summary"]["overall_trend_direction"])
        
        return result
        
    except Exception as e:
        logger.error("Trend anomaly detection failed", error=str(e))
        raise Exception(f"Failed to detect trend anomalies: {str(e)}")
"""
Analyze access patterns and behaviors between entities using OpenSearch aggregations
"""
from typing import Dict, Any, List, Optional
import structlog
from datetime import datetime

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze access patterns using aggregation-based approach
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including source_type, source_id, target_type, timeframe
        
    Returns:
        Access patterns analysis with behavioral insights and anomaly detection
    """
    try:
        # Extract parameters
        source_type = params.get("source_type")
        source_id = params.get("source_id")
        target_type = params.get("target_type")
        timeframe = params.get("timeframe", "24h")
        
        logger.info("Executing aggregated access patterns analysis", 
                   source_type=source_type,
                   source_id=source_id,
                   target_type=target_type,
                   timeframe=timeframe)
        
        # Build time range filter
        time_filter = opensearch_client.build_time_range_filter(timeframe)
        
        # Build aggregation-based query
        query = _build_access_patterns_aggregation_query(source_type, source_id, target_type, time_filter)
        
        # Execute search with aggregations
        response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=query,
            size=0  # Only aggregations needed
        )
        
        # Process aggregation results
        total_alerts = response["hits"]["total"]["value"] if isinstance(response["hits"]["total"], dict) else response["hits"]["total"]
        aggregations = response.get("aggregations", {})
        
        logger.info("Retrieved aggregated access patterns data", total_alerts=total_alerts)
        
        # Process access patterns from aggregations
        access_events = []
        pattern_summary = {
            "source_entity": {"type": source_type, "id": source_id},
            "total_access_events": total_alerts,
            "timeframe": timeframe,
            "unique_access_targets": set(),
            "access_methods": set(),
            "time_period_distribution": {},
            "behavioral_patterns": {}
        }
        
        # Process access pattern analysis
        if "access_pattern_analysis" in aggregations:
            for source_bucket in aggregations["access_pattern_analysis"]["buckets"]:
                source_entity = source_bucket["key"]
                
                # Process temporal access patterns
                if "access_timeline" in source_bucket:
                    for time_bucket in source_bucket["access_timeline"]["buckets"]:
                        timestamp = time_bucket["key_as_string"]
                        access_count = time_bucket["doc_count"]
                        
                        # Get access methods used in this time window
                        access_methods = [b["key"] for b in time_bucket.get("access_methods", {}).get("buckets", [])]
                        
                        # Get target diversity for this time window
                        target_diversity = time_bucket.get("target_diversity", {}).get("value", 0)
                        
                        access_event = {
                            "timestamp": timestamp,
                            "source_entity": source_entity,
                            "access_count": access_count,
                            "access_methods": access_methods,
                            "target_diversity": target_diversity,
                            "access_density": access_count / max(1, target_diversity),  # Access concentration
                            "risk_indicators": _assess_access_risk(access_count, access_methods, target_diversity)
                        }
                        
                        access_events.append(access_event)
                        pattern_summary["access_methods"].update(access_methods)
                
                # Process behavioral pattern analysis
                if "behavioral_patterns" in source_bucket:
                    business_hours_access = source_bucket["behavioral_patterns"]["filters"]["buckets"]["business_hours"]["doc_count"]
                    after_hours_access = source_bucket["behavioral_patterns"]["filters"]["buckets"]["after_hours"]["doc_count"]
                    
                    pattern_summary["behavioral_patterns"][source_entity] = {
                        "business_hours_access": business_hours_access,
                        "after_hours_access": after_hours_access,
                        "after_hours_ratio": (after_hours_access / max(1, business_hours_access + after_hours_access)) * 100,
                        "total_access": business_hours_access + after_hours_access
                    }
                
                # Process anomalous access detection
                if "anomalous_access" in source_bucket:
                    for anomaly_bucket in source_bucket["anomalous_access"]["buckets"]:
                        unusual_target = anomaly_bucket["key"]
                        significance_score = anomaly_bucket["score"]
                        
                        pattern_summary["unique_access_targets"].add(unusual_target)
        
        # Process network access patterns
        network_access_patterns = []
        if "network_access_analysis" in aggregations:
            for ip_bucket in aggregations["network_access_analysis"]["buckets"]:
                source_ip = ip_bucket["key"]
                connection_count = ip_bucket["doc_count"]
                
                # Get destination diversity
                dest_diversity = ip_bucket.get("destination_diversity", {}).get("value", 0)
                
                # Get connection types
                connection_types = [b["key"] for b in ip_bucket.get("connection_types", {}).get("buckets", [])]
                
                # Get temporal distribution
                temporal_pattern = []
                if "temporal_distribution" in ip_bucket:
                    temporal_pattern = [
                        {"hour": b["key"], "connections": b["doc_count"]}
                        for b in ip_bucket["temporal_distribution"]["buckets"]
                    ]
                
                network_pattern = {
                    "source_ip": source_ip,
                    "connection_count": connection_count,
                    "destination_diversity": dest_diversity,
                    "connection_types": connection_types,
                    "temporal_pattern": temporal_pattern,
                    "network_risk_score": _calculate_network_risk(connection_count, dest_diversity, connection_types)
                }
                
                network_access_patterns.append(network_pattern)
        
        # Process authentication access patterns
        auth_patterns = []
        if "authentication_analysis" in aggregations:
            for user_bucket in aggregations["authentication_analysis"]["buckets"]:
                username = user_bucket["key"]
                auth_count = user_bucket["doc_count"]
                
                # Get host diversity for this user
                host_diversity = user_bucket.get("host_diversity", {}).get("value", 0)
                
                # Get success/failure breakdown
                success_count = user_bucket.get("auth_success", {}).get("doc_count", 0)
                failure_count = user_bucket.get("auth_failures", {}).get("doc_count", 0)
                
                # Get geographic pattern
                geographic_diversity = user_bucket.get("geographic_diversity", {}).get("value", 0)
                
                auth_pattern = {
                    "username": username,
                    "auth_attempts": auth_count,
                    "host_diversity": host_diversity,
                    "success_count": success_count,
                    "failure_count": failure_count,
                    "failure_rate": (failure_count / max(1, auth_count)) * 100,
                    "geographic_diversity": geographic_diversity,
                    "auth_risk_assessment": _assess_auth_risk(failure_count, host_diversity, geographic_diversity)
                }
                
                auth_patterns.append(auth_pattern)
        
        # Convert sets to lists and finalize summary
        pattern_summary["access_methods"] = list(pattern_summary["access_methods"])
        pattern_summary["unique_access_targets"] = list(pattern_summary["unique_access_targets"])
        pattern_summary["unique_target_count"] = len(pattern_summary["unique_access_targets"])
        pattern_summary["unique_access_methods"] = len(pattern_summary["access_methods"])
        
        # Generate comprehensive analysis
        patterns_analysis = _analyze_aggregated_access_patterns(
            access_events, network_access_patterns, auth_patterns, aggregations
        )
        
        # Build result
        result = {
            "relationship_type": "access_patterns",
            "search_parameters": {
                "source_type": source_type,
                "source_id": source_id,
                "target_type": target_type,
                "timeframe": timeframe,
                "data_source": "opensearch_alerts"
            },
            "pattern_summary": pattern_summary,
            "access_events": access_events,
            "network_access_patterns": network_access_patterns,
            "authentication_patterns": auth_patterns,
            "patterns_analysis": patterns_analysis,
            "behavioral_insights": _generate_behavioral_insights(access_events, patterns_analysis),
            "recommendations": _generate_access_recommendations(patterns_analysis)
        }
        
        logger.info("Aggregated access patterns analysis completed", 
                   total_events=len(access_events),
                   unique_targets=len(pattern_summary["unique_access_targets"]),
                   network_patterns=len(network_access_patterns),
                   auth_patterns=len(auth_patterns))
        
        return result
        
    except Exception as e:
        logger.error("Aggregated access patterns analysis failed", error=str(e))
        raise Exception(f"Failed to analyze access patterns: {str(e)}")


def _build_access_patterns_aggregation_query(source_type: str, source_id: str, target_type: Optional[str], time_filter: Dict[str, Any]) -> Dict[str, Any]:
    """Build aggregation query for access patterns analysis"""
    
    # Build source entity filter if specified
    must_conditions = [time_filter]
    if source_id:
        source_filters = _get_entity_filters(source_type, source_id)
        must_conditions.extend(source_filters)
    
    query = {
        "query": {
            "bool": {
                "must": must_conditions,
                "should": [
                    {"terms": {"rule.groups": ["authentication", "pam", "ssh", "login"]}},
                    {"terms": {"rule.groups": ["syscheck", "file_integrity", "audit"]}},
                    {"bool": {"must": [
                        {"terms": {"rule.groups": ["audit", "process"]}},
                        {"exists": {"field": "data.win.eventdata.commandLine"}}
                    ]}},
                    {"bool": {"must": [
                        {"exists": {"field": "data.srcip"}},
                        {"range": {"rule.level": {"gte": 3}}}
                    ]}},
                    {"bool": {"must": [
                        {"exists": {"field": "data.win.eventdata.targetUserName"}},
                        {"terms": {"rule.groups": ["windows", "logon"]}}
                    ]}}
                ],
                "minimum_should_match": 1
            }
        },
        "aggs": {
            "access_pattern_analysis": {
                "terms": {
                    "field": "agent.name",
                    "size": 100
                },
                "aggs": {
                    "access_timeline": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "interval": "1h",
                            "min_doc_count": 1
                        },
                        "aggs": {
                            "access_methods": {
                                "terms": {"field": "rule.groups", "size": 10}
                            },
                            "target_diversity": {
                                "cardinality": {"field": "data.win.eventdata.targetUserName"}
                            },
                            "severity_profile": {
                                "stats": {"field": "rule.level"}
                            }
                        }
                    },
                    "behavioral_patterns": {
                        "filters": {
                            "filters": {
                                "business_hours": {
                                    "script": {
                                        "source": "def hour = doc['@timestamp'].value.getHour(); return hour >= 8 && hour <= 18;"
                                    }
                                },
                                "after_hours": {
                                    "script": {
                                        "source": "def hour = doc['@timestamp'].value.getHour(); return hour < 8 || hour > 18;"
                                    }
                                }
                            }
                        },
                        "aggs": {
                            "access_frequency": {"value_count": {"field": "_id"}},
                            "unique_targets": {
                                "cardinality": {"field": "data.win.eventdata.targetUserName"}
                            }
                        }
                    },
                    "anomalous_access": {
                        "significant_terms": {
                            "field": "data.win.eventdata.targetUserName",
                            "background_filter": {
                                "range": {"@timestamp": {"gte": "now-30d", "lte": "now-1d"}}
                            },
                            "min_doc_count": 3
                        }
                    },
                    "access_velocity": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "interval": "5m"
                        },
                        "aggs": {
                            "access_burst_detection": {
                                "bucket_script": {
                                    "buckets_path": {"doc_count": "_count"},
                                    "script": "params.doc_count > 20 ? params.doc_count : 0"
                                }
                            }
                        }
                    }
                }
            },
            "network_access_analysis": {
                "terms": {
                    "field": "data.srcip",
                    "size": 50
                },
                "aggs": {
                    "destination_diversity": {
                        "cardinality": {"field": "data.dstip"}
                    },
                    "connection_types": {
                        "terms": {"field": "data.protocol", "size": 10}
                    },
                    "temporal_distribution": {
                        "histogram": {
                            "script": {
                                "source": "doc['@timestamp'].value.getHour()"
                            },
                            "interval": 1
                        }
                    },
                    "geographic_indicators": {
                        "terms": {"field": "agent.ip", "size": 20}
                    }
                }
            },
            "authentication_analysis": {
                "terms": {
                    "field": "data.win.eventdata.targetUserName",
                    "size": 50
                },
                "aggs": {
                    "host_diversity": {
                        "cardinality": {"field": "agent.name"}
                    },
                    "auth_success": {
                        "filter": {
                            "bool": {
                                "must_not": [
                                    {"wildcard": {"rule.description": "*failed*"}},
                                    {"wildcard": {"rule.description": "*denied*"}}
                                ]
                            }
                        }
                    },
                    "auth_failures": {
                        "filter": {
                            "bool": {
                                "should": [
                                    {"wildcard": {"rule.description": "*failed*"}},
                                    {"wildcard": {"rule.description": "*denied*"}},
                                    {"wildcard": {"rule.description": "*invalid*"}}
                                ]
                            }
                        }
                    },
                    "geographic_diversity": {
                        "cardinality": {"field": "agent.ip"}
                    },
                    "temporal_pattern": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "interval": "2h"
                        }
                    }
                }
            },
            "file_access_analysis": {
                "terms": {
                    "field": "data.win.eventdata.targetFilename",
                    "size": 30
                },
                "aggs": {
                    "access_frequency": {"value_count": {"field": "_id"}},
                    "accessing_users": {
                        "cardinality": {"field": "data.win.eventdata.targetUserName"}
                    },
                    "access_types": {
                        "terms": {"field": "rule.groups", "size": 5}
                    },
                    "recent_access": {
                        "top_hits": {
                            "size": 1,
                            "sort": [{"@timestamp": {"order": "desc"}}],
                            "_source": ["@timestamp", "data.win.eventdata.targetUserName", "rule.description"]
                        }
                    }
                }
            }
        }
    }
    
    return query


def _get_entity_filters(entity_type: str, entity_id: str) -> List[Dict[str, Any]]:
    """Get filters for specific entity type"""
    filters = []
    
    if entity_type.lower() == "host":
        filters.append({
            "bool": {
                "should": [
                    {"term": {"agent.name": entity_id}},
                    {"term": {"agent.ip": entity_id}},
                    {"wildcard": {"agent.name": f"*{entity_id}*"}}
                ]
            }
        })
    elif entity_type.lower() == "user":
        filters.append({
            "bool": {
                "should": [
                    {"wildcard": {"data.srcuser": f"*{entity_id}*"}},
                    {"wildcard": {"data.dstuser": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.targetUserName": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.subjectUserName": f"*{entity_id}*"}}
                ]
            }
        })
    
    return filters


def _assess_access_risk(access_count: int, access_methods: List[str], target_diversity: int) -> Dict[str, Any]:
    """Assess risk level of access patterns"""
    risk_score = 0
    risk_indicators = []
    
    # High access volume
    if access_count > 200:
        risk_score += 40
        risk_indicators.append("Very high access volume")
    elif access_count > 100:
        risk_score += 25
        risk_indicators.append("High access volume")
    elif access_count > 50:
        risk_score += 15
        risk_indicators.append("Elevated access volume")
    
    # High target diversity (potential lateral movement)
    if target_diversity > 50:
        risk_score += 35
        risk_indicators.append("Very high target diversity - potential scanning")
    elif target_diversity > 20:
        risk_score += 20
        risk_indicators.append("High target diversity")
    
    # Access concentration (high volume, low diversity = focused attack)
    if access_count > 50 and target_diversity < 5:
        risk_score += 30
        risk_indicators.append("High access concentration - potential brute force")
    
    # High-risk access methods
    high_risk_methods = ["authentication_failed", "privilege_escalation", "file_integrity"]
    if any(risk_method in " ".join(access_methods).lower() for risk_method in high_risk_methods):
        risk_score += 25
        risk_indicators.append("High-risk access methods detected")
    
    # Determine risk level
    if risk_score > 70:
        risk_level = "Critical"
    elif risk_score > 40:
        risk_level = "High"
    elif risk_score > 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_indicators": risk_indicators
    }


def _calculate_network_risk(connection_count: int, dest_diversity: int, connection_types: List[str]) -> int:
    """Calculate network access risk score"""
    risk_score = 0
    
    # Connection volume risk
    if connection_count > 1000:
        risk_score += 40
    elif connection_count > 500:
        risk_score += 25
    elif connection_count > 100:
        risk_score += 15
    
    # Destination diversity risk
    if dest_diversity > 100:
        risk_score += 35
    elif dest_diversity > 50:
        risk_score += 20
    
    # Suspicious protocols
    suspicious_protocols = ["tor", "proxy", "tunnel"]
    if any(proto in " ".join(connection_types).lower() for proto in suspicious_protocols):
        risk_score += 30
    
    return min(100, risk_score)


def _assess_auth_risk(failure_count: int, host_diversity: int, geographic_diversity: int) -> Dict[str, Any]:
    """Assess authentication risk level"""
    risk_score = 0
    risk_indicators = []
    
    # High failure count
    if failure_count > 100:
        risk_score += 40
        risk_indicators.append("Very high authentication failure count")
    elif failure_count > 50:
        risk_score += 25
        risk_indicators.append("High authentication failure count")
    elif failure_count > 20:
        risk_score += 15
        risk_indicators.append("Elevated authentication failures")
    
    # Host diversity (lateral movement indicator)
    if host_diversity > 20:
        risk_score += 30
        risk_indicators.append("Authentication attempts across many hosts")
    elif host_diversity > 10:
        risk_score += 20
        risk_indicators.append("Multi-host authentication activity")
    
    # Geographic diversity (potential account compromise)
    if geographic_diversity > 5:
        risk_score += 35
        risk_indicators.append("Authentication from multiple locations")
    elif geographic_diversity > 2:
        risk_score += 20
        risk_indicators.append("Multi-location authentication activity")
    
    # Determine risk level
    if risk_score > 70:
        risk_level = "Critical"
    elif risk_score > 40:
        risk_level = "High"
    elif risk_score > 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_indicators": risk_indicators
    }


def _analyze_aggregated_access_patterns(access_events: List[Dict], network_patterns: List[Dict], auth_patterns: List[Dict], aggregations: Dict) -> Dict[str, Any]:
    """Analyze access patterns using aggregated data"""
    analysis = {
        "temporal_analysis": {},
        "access_behavior_analysis": {},
        "network_analysis": {},
        "authentication_analysis": {},
        "risk_assessment": {}
    }
    
    if not access_events and not network_patterns and not auth_patterns:
        return {"message": "No access patterns found for analysis"}
    
    # Temporal analysis
    if access_events:
        hourly_distribution = {}
        for event in access_events:
            hour = datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00')).hour
            hourly_distribution[hour] = hourly_distribution.get(hour, 0) + event["access_count"]
        
        analysis["temporal_analysis"] = {
            "peak_access_hour": max(hourly_distribution.items(), key=lambda x: x[1]) if hourly_distribution else (0, 0),
            "total_time_periods": len(hourly_distribution),
            "night_access_percentage": sum(hourly_distribution.get(h, 0) for h in range(0, 6) + list(range(22, 24))) / sum(hourly_distribution.values()) * 100 if hourly_distribution else 0
        }
    
    # Network analysis
    if network_patterns:
        total_connections = sum(p["connection_count"] for p in network_patterns)
        avg_dest_diversity = sum(p["destination_diversity"] for p in network_patterns) / len(network_patterns)
        
        analysis["network_analysis"] = {
            "total_network_connections": total_connections,
            "avg_destination_diversity": round(avg_dest_diversity, 2),
            "high_risk_network_patterns": len([p for p in network_patterns if p["network_risk_score"] > 60])
        }
    
    # Authentication analysis
    if auth_patterns:
        total_failures = sum(p["failure_count"] for p in auth_patterns)
        avg_failure_rate = sum(p["failure_rate"] for p in auth_patterns) / len(auth_patterns)
        
        analysis["authentication_analysis"] = {
            "total_auth_failures": total_failures,
            "avg_failure_rate": round(avg_failure_rate, 2),
            "users_with_high_failures": len([p for p in auth_patterns if p["failure_rate"] > 50])
        }
    
    # Overall risk assessment
    high_risk_events = len([e for e in access_events if e.get("risk_indicators", {}).get("risk_level") in ["Critical", "High"]])
    total_events = len(access_events)
    
    analysis["risk_assessment"] = {
        "high_risk_access_events": high_risk_events,
        "risk_percentage": (high_risk_events / max(1, total_events)) * 100,
        "overall_risk_level": "High" if high_risk_events > total_events * 0.3 else "Medium" if high_risk_events > 0 else "Low"
    }
    
    return analysis


def _generate_behavioral_insights(access_events: List[Dict], analysis: Dict) -> List[str]:
    """Generate behavioral insights from access patterns"""
    insights = []
    
    if not access_events and not analysis:
        return ["No access events available for behavioral analysis"]
    
    # Temporal insights
    peak_hour, peak_count = analysis.get("temporal_analysis", {}).get("peak_access_hour", (0, 0))
    if peak_count > 0:
        insights.append(f"Peak access activity at hour {peak_hour} with {peak_count} total accesses")
    
    night_access_pct = analysis.get("temporal_analysis", {}).get("night_access_percentage", 0)
    if night_access_pct > 20:
        insights.append(f"Significant after-hours access activity: {night_access_pct:.1f}% of total access")
    
    # Network behavior insights
    high_risk_network = analysis.get("network_analysis", {}).get("high_risk_network_patterns", 0)
    if high_risk_network > 0:
        insights.append(f"Detected {high_risk_network} high-risk network access patterns")
    
    # Authentication insights
    high_failure_users = analysis.get("authentication_analysis", {}).get("users_with_high_failures", 0)
    if high_failure_users > 0:
        insights.append(f"Found {high_failure_users} users with high authentication failure rates")
    
    return insights


def _generate_access_recommendations(analysis: Dict) -> List[str]:
    """Generate recommendations based on access patterns analysis"""
    recommendations = []
    
    # Risk-based recommendations
    overall_risk = analysis.get("risk_assessment", {}).get("overall_risk_level", "Low")
    if overall_risk == "High":
        recommendations.append("Critical: High-risk access patterns detected - immediate security review required")
    elif overall_risk == "Medium":
        recommendations.append("Warning: Some risky access patterns detected - enhanced monitoring recommended")
    
    # Night access recommendations
    night_access_pct = analysis.get("temporal_analysis", {}).get("night_access_percentage", 0)
    if night_access_pct > 30:
        recommendations.append("High after-hours access detected - review business justification and implement additional controls")
    
    # Authentication recommendations
    high_failure_users = analysis.get("authentication_analysis", {}).get("users_with_high_failures", 0)
    if high_failure_users > 5:
        recommendations.append(f"Multiple users with high failure rates - investigate potential brute force attacks")
    
    # Network recommendations
    high_risk_network = analysis.get("network_analysis", {}).get("high_risk_network_patterns", 0)
    if high_risk_network > 3:
        recommendations.append("Multiple high-risk network patterns - review network access policies and monitoring")
    
    if not recommendations:
        recommendations.append("Access patterns appear normal based on aggregated analysis")
    
    return recommendations
"""
Correlate activities and behaviors across entities using OpenSearch aggregations
"""
from typing import Dict, Any, List, Optional
import structlog

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlate activities and behaviors using aggregation-based approach
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including source_type, source_id, target_type, timeframe
        
    Returns:
        Activity correlation analysis with temporal clustering and behavioral patterns
    """
    try:
        # Extract parameters
        source_type = params.get("source_type")
        source_id = params.get("source_id")
        target_type = params.get("target_type")
        timeframe = params.get("timeframe", "24h")
        
        logger.info("Executing aggregated activity correlation analysis", 
                   source_type=source_type,
                   source_id=source_id,
                   target_type=target_type,
                   timeframe=timeframe)
        
        # Build time range filter
        time_filter = opensearch_client.build_time_range_filter(timeframe)
        
        # Build aggregation-based query
        query = _build_correlation_aggregation_query(source_type, source_id, target_type, time_filter)
        
        # Execute search with aggregations
        response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=query,
            size=0  # Only aggregations needed
        )
        
        # Process aggregation results
        total_alerts = response["hits"]["total"]["value"] if isinstance(response["hits"]["total"], dict) else response["hits"]["total"]
        aggregations = response.get("aggregations", {})
        
        logger.info("Retrieved aggregated correlation data", total_alerts=total_alerts)
        
        # Process correlation results
        correlation_events = []
        correlation_summary = {
            "source_entity": {"type": source_type, "id": source_id},
            "total_correlated_activities": total_alerts,
            "timeframe": timeframe,
            "activity_types": set(),
            "correlated_entities": set(),
            "temporal_clusters": {},
            "correlation_strength": {}
        }
        
        # Process temporal correlation data
        if "temporal_correlation" in aggregations:
            for time_bucket in aggregations["temporal_correlation"]["buckets"]:
                timestamp = time_bucket["key_as_string"]
                activity_count = time_bucket["doc_count"]
                
                correlation_summary["temporal_clusters"][timestamp] = activity_count
                
                # Process entities active in this time window
                if "active_entities" in time_bucket:
                    for entity_bucket in time_bucket["active_entities"]["buckets"]:
                        entity_name = entity_bucket["key"]
                        entity_activity = entity_bucket["doc_count"]
                        
                        # Get activity types for this entity in this time window
                        activity_types = [b["key"] for b in entity_bucket.get("activity_types", {}).get("buckets", [])]
                        
                        # Get correlation significance
                        significance_score = entity_bucket.get("correlation_significance", {}).get("value", 0)
                        
                        # Check for unusual activity patterns
                        unusual_activities = []
                        if "unusual_activities" in entity_bucket:
                            unusual_activities = [
                                {"activity": b["key"], "score": b["score"]} 
                                for b in entity_bucket["unusual_activities"]["buckets"]
                            ]
                        
                        correlation_event = {
                            "timestamp": timestamp,
                            "entity": entity_name,
                            "entity_type": _infer_entity_type(entity_name),
                            "activity_count": entity_activity,
                            "activity_types": activity_types,
                            "correlation_significance": round(significance_score, 3),
                            "unusual_activities": unusual_activities,
                            "risk_indicators": _assess_correlation_risk(entity_activity, activity_types, unusual_activities)
                        }
                        
                        correlation_events.append(correlation_event)
                        correlation_summary["activity_types"].update(activity_types)
                        correlation_summary["correlated_entities"].add(entity_name)
        
        # Process cross-entity correlation analysis
        cross_entity_correlations = []
        if "cross_entity_correlation" in aggregations:
            for composite_bucket in aggregations["cross_entity_correlation"]["buckets"]:
                entity1 = composite_bucket["key"]["entity1"]
                entity2 = composite_bucket["key"]["entity2"]
                correlation_strength = composite_bucket["doc_count"]
                
                # Get temporal distribution of this correlation
                temporal_pattern = []
                if "correlation_timeline" in composite_bucket:
                    temporal_pattern = [
                        {"timestamp": b["key_as_string"], "activity": b["doc_count"]}
                        for b in composite_bucket["correlation_timeline"]["buckets"]
                    ]
                
                # Get shared activity analysis
                shared_activities = []
                if "shared_activities" in composite_bucket:
                    shared_activities = [
                        {"activity_type": b["key"], "frequency": b["doc_count"]}
                        for b in composite_bucket["shared_activities"]["buckets"]
                    ]
                
                cross_correlation = {
                    "entity1": entity1,
                    "entity2": entity2,
                    "correlation_strength": correlation_strength,
                    "temporal_pattern": temporal_pattern,
                    "shared_activities": shared_activities,
                    "correlation_score": min(100, correlation_strength * 2),  # Normalized score
                    "relationship_type": _determine_relationship_type(shared_activities)
                }
                
                cross_entity_correlations.append(cross_correlation)
        
        # Convert sets to lists and add summary statistics
        correlation_summary["activity_types"] = list(correlation_summary["activity_types"])
        correlation_summary["correlated_entities"] = list(correlation_summary["correlated_entities"])
        correlation_summary["unique_entities_count"] = len(correlation_summary["correlated_entities"])
        correlation_summary["unique_activity_types"] = len(correlation_summary["activity_types"])
        correlation_summary["cross_entity_correlations"] = len(cross_entity_correlations)
        
        # Generate enhanced correlation analysis
        correlation_analysis = _analyze_correlation_patterns(
            correlation_events, cross_entity_correlations, aggregations
        )
        
        # Build result
        result = {
            "relationship_type": "activity_correlation",
            "search_parameters": {
                "source_type": source_type,
                "source_id": source_id,
                "target_type": target_type,
                "timeframe": timeframe,
                "data_source": "opensearch_alerts"
            },
            "correlation_summary": correlation_summary,
            "correlation_events": correlation_events,
            "cross_entity_correlations": cross_entity_correlations,
            "correlation_analysis": correlation_analysis,
            "behavioral_insights": _generate_correlation_insights(correlation_events, correlation_analysis),
            "recommendations": _generate_correlation_recommendations(correlation_analysis)
        }
        
        logger.info("Aggregated activity correlation analysis completed", 
                   total_events=len(correlation_events),
                   unique_entities=len(correlation_summary["correlated_entities"]),
                   cross_correlations=len(cross_entity_correlations))
        
        return result
        
    except Exception as e:
        logger.error("Aggregated activity correlation analysis failed", error=str(e))
        raise Exception(f"Failed to analyze activity correlations: {str(e)}")


def _build_correlation_aggregation_query(source_type: str, source_id: str, target_type: Optional[str], time_filter: Dict[str, Any]) -> Dict[str, Any]:
    """Build aggregation query for correlation analysis"""
    
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
                    {"terms": {"rule.groups": ["audit", "system", "process", "network"]}},
                    {"terms": {"rule.groups": ["authentication", "pam", "ssh", "login", "logon"]}},
                    {"terms": {"rule.groups": ["syscheck", "file_integrity", "fim"]}},
                    {"bool": {"must": [
                        {"terms": {"rule.groups": ["windows", "security"]}},
                        {"exists": {"field": "data.win.eventdata"}}
                    ]}},
                    {"bool": {"must": [
                        {"exists": {"field": "data.srcip"}},
                        {"range": {"rule.level": {"gte": 2}}}
                    ]}}
                ],
                "minimum_should_match": 1
            }
        },
        "aggs": {
            "temporal_correlation": {
                "date_histogram": {
                    "field": "@timestamp",
                    "interval": "15m",
                    "min_doc_count": 1
                },
                "aggs": {
                    "active_entities": {
                        "terms": {
                            "field": "agent.name",
                            "size": 50
                        },
                        "aggs": {
                            "activity_types": {
                                "terms": {"field": "rule.groups", "size": 10}
                            },
                            "correlation_significance": {
                                "bucket_script": {
                                    "buckets_path": {"doc_count": "_count"},
                                    "script": "Math.log(params.doc_count + 1)"
                                }
                            },
                            "unusual_activities": {
                                "significant_terms": {
                                    "field": "rule.groups",
                                    "background_filter": {
                                        "range": {"@timestamp": {"gte": "now-7d/d"}}
                                    }
                                }
                            },
                            "severity_profile": {
                                "histogram": {"field": "rule.level", "interval": 1}
                            }
                        }
                    },
                    "activity_burst_detection": {
                        "bucket_script": {
                            "buckets_path": {"doc_count": "_count"},
                            "script": "params.doc_count > 50 ? params.doc_count : 0"
                        }
                    }
                }
            },
            "cross_entity_correlation": {
                "composite": {
                    "sources": [
                        {"entity1": {"terms": {"field": "agent.name"}}},
                        {"entity2": {"terms": {"field": "data.win.eventdata.targetUserName"}}}
                    ],
                    "size": 100
                },
                "aggs": {
                    "correlation_timeline": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "interval": "30m"
                        }
                    },
                    "shared_activities": {
                        "terms": {"field": "rule.groups", "size": 10}
                    },
                    "correlation_strength": {
                        "bucket_script": {
                            "buckets_path": {"doc_count": "_count"},
                            "script": "Math.sqrt(params.doc_count)"
                        }
                    }
                }
            },
            "behavioral_clustering": {
                "terms": {
                    "field": "data.win.eventdata.targetUserName",
                    "size": 30
                },
                "aggs": {
                    "host_diversity": {
                        "cardinality": {"field": "agent.name"}
                    },
                    "activity_pattern": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "interval": "1h"
                        }
                    },
                    "risk_indicators": {
                        "filters": {
                            "filters": {
                                "after_hours": {
                                    "script": {
                                        "script": {
                                            "source": "def hour = doc['@timestamp'].value.getHour(); return hour < 6 || hour > 20;",
                                            "lang": "painless"
                                        }
                                    }
                                },
                                "high_severity": {
                                    "range": {"rule.level": {"gte": 8}}
                                },
                                "failed_activities": {
                                    "wildcard": {"rule.description": "*failed*"}
                                }
                            }
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


def _infer_entity_type(entity_name: str) -> str:
    """Infer entity type from name patterns"""
    if "." in entity_name and len(entity_name.split(".")) > 1:
        return "user"
    elif "-" in entity_name or "server" in entity_name.lower():
        return "host"
    else:
        return "unknown"


def _assess_correlation_risk(activity_count: int, activity_types: List[str], unusual_activities: List[Dict]) -> Dict[str, Any]:
    """Assess risk level of correlated activities"""
    risk_score = 0
    risk_indicators = []
    
    # High activity volume
    if activity_count > 100:
        risk_score += 30
        risk_indicators.append("High activity volume")
    elif activity_count > 50:
        risk_score += 15
        risk_indicators.append("Elevated activity volume")
    
    # Unusual activity types
    if unusual_activities:
        risk_score += len(unusual_activities) * 10
        risk_indicators.append(f"Unusual activities detected: {len(unusual_activities)}")
    
    # High-risk activity types
    high_risk_activities = ["authentication_failed", "privilege_escalation", "malware", "attack", "exploit"]
    if any(risk_activity in " ".join(activity_types).lower() for risk_activity in high_risk_activities):
        risk_score += 40
        risk_indicators.append("High-risk activity types detected")
    
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


def _determine_relationship_type(shared_activities: List[Dict]) -> str:
    """Determine the type of relationship based on shared activities"""
    if not shared_activities:
        return "unknown"
    
    activity_names = [activity["activity_type"] for activity in shared_activities]
    activity_text = " ".join(activity_names).lower()
    
    if any(term in activity_text for term in ["authentication", "login", "logon"]):
        return "authentication_relationship"
    elif any(term in activity_text for term in ["file", "syscheck", "integrity"]):
        return "file_relationship"
    elif any(term in activity_text for term in ["process", "execution", "command"]):
        return "process_relationship"
    elif any(term in activity_text for term in ["network", "connection", "communication"]):
        return "network_relationship"
    else:
        return "general_activity_relationship"


def _analyze_correlation_patterns(correlation_events: List[Dict], cross_correlations: List[Dict], aggregations: Dict) -> Dict[str, Any]:
    """Analyze correlation patterns from aggregated data"""
    analysis = {
        "temporal_patterns": {},
        "entity_correlation_strength": {},
        "behavioral_anomalies": {},
        "risk_assessment": {}
    }
    
    if not correlation_events:
        return {"message": "No correlation events found for analysis"}
    
    # Analyze temporal clustering
    time_buckets = {}
    for event in correlation_events:
        timestamp = event["timestamp"]
        time_buckets[timestamp] = time_buckets.get(timestamp, 0) + event["activity_count"]
    
    analysis["temporal_patterns"] = {
        "peak_activity_time": max(time_buckets.items(), key=lambda x: x[1]) if time_buckets else ("N/A", 0),
        "total_time_windows": len(time_buckets),
        "avg_activity_per_window": sum(time_buckets.values()) / len(time_buckets) if time_buckets else 0
    }
    
    # Analyze correlation strength distribution
    if cross_correlations:
        strength_values = [c["correlation_strength"] for c in cross_correlations]
        analysis["entity_correlation_strength"] = {
            "max_correlation": max(strength_values),
            "avg_correlation": sum(strength_values) / len(strength_values),
            "strong_correlations": len([s for s in strength_values if s > 50])
        }
    
    # Risk assessment
    risk_levels = [event["risk_indicators"]["risk_level"] for event in correlation_events if "risk_indicators" in event]
    risk_counts = {level: risk_levels.count(level) for level in set(risk_levels)}
    
    analysis["risk_assessment"] = {
        "risk_distribution": risk_counts,
        "high_risk_correlations": len([r for r in risk_levels if r in ["Critical", "High"]]),
        "total_correlations_analyzed": len(correlation_events)
    }
    
    return analysis


def _generate_correlation_insights(correlation_events: List[Dict], analysis: Dict) -> List[str]:
    """Generate behavioral insights from correlation analysis"""
    insights = []
    
    if not correlation_events:
        return ["No correlation events available for behavioral analysis"]
    
    # Temporal insights
    peak_time, peak_count = analysis.get("temporal_patterns", {}).get("peak_activity_time", ("N/A", 0))
    if peak_count > 0:
        insights.append(f"Peak correlated activity occurred at {peak_time} with {peak_count} events")
    
    # Correlation strength insights
    strong_correlations = analysis.get("entity_correlation_strength", {}).get("strong_correlations", 0)
    if strong_correlations > 5:
        insights.append(f"Detected {strong_correlations} strong entity correlations - potential coordinated activity")
    
    # Risk insights
    high_risk_count = analysis.get("risk_assessment", {}).get("high_risk_correlations", 0)
    if high_risk_count > 0:
        insights.append(f"Identified {high_risk_count} high-risk correlation patterns requiring investigation")
    
    return insights


def _generate_correlation_recommendations(analysis: Dict) -> List[str]:
    """Generate recommendations based on correlation analysis"""
    recommendations = []
    
    # Risk-based recommendations
    high_risk_count = analysis.get("risk_assessment", {}).get("high_risk_correlations", 0)
    if high_risk_count > 10:
        recommendations.append("Critical: High number of risky correlations detected - immediate security review required")
    elif high_risk_count > 0:
        recommendations.append(f"Warning: {high_risk_count} high-risk correlations found - investigate coordination patterns")
    
    # Correlation strength recommendations
    strong_correlations = analysis.get("entity_correlation_strength", {}).get("strong_correlations", 0)
    if strong_correlations > 10:
        recommendations.append("Strong entity correlations detected - analyze for potential coordinated attacks or automation")
    
    if not recommendations:
        recommendations.append("Activity correlations appear normal based on aggregated analysis")
    
    return recommendations
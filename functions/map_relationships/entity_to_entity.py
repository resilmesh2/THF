"""
Map direct relationships between entities using OpenSearch aggregations
"""
from typing import Dict, Any, List, Optional
import structlog
from .relationship_types import infer_relationship_type, get_relationship_description

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map direct relationships between entities using aggregation-based approach
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including source_type, source_id, target_type, timeframe
        
    Returns:
        Direct entity relationships with connection strength and analysis
    """
    try:
        # Extract parameters
        source_type = params.get("source_type")
        source_id = params.get("source_id")
        target_type = params.get("target_type")
        filters = params.get("filters")
        timeframe = params.get("timeframe", "24h")

        # Ensure filters is a dict or None
        if filters is None:
            filters = {}
        elif not isinstance(filters, dict):
            logger.warning("filters parameter is not a dict, converting", filters=filters, type=type(filters))
            filters = {}

        logger.info("Executing aggregated entity-to-entity relationship mapping",
                   source_type=source_type,
                   source_id=source_id,
                   target_type=target_type,
                   filters=filters,
                   timeframe=timeframe)

        # Build time range filter
        time_filter = opensearch_client.build_single_time_filter(timeframe)

        # Build aggregation-based query
        query = _build_relationship_aggregation_query(source_type, source_id, target_type, time_filter, filters)
        
        # Execute search with aggregations
        response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=query,
            size=0  # Only aggregations needed
        )
        
        # Process aggregation results
        total_alerts = response["aggregations"]["total_count"]["value"]
        aggregations = response.get("aggregations", {})
        
        logger.info("Retrieved aggregated relationship data", total_alerts=total_alerts)
        
        # Process relationship network from aggregations
        relationships = []
        relationship_summary = {
            "source_entity": {"type": source_type, "id": source_id},
            "target_entity": {"type": target_type, "id": "multiple" if not target_type else "specified"},
            "total_connections": 0,
            "timeframe": timeframe,
            "connection_types": set(),
            "unique_targets": set(),
            "relationship_strength_distribution": {},
            "temporal_patterns": {}
        }
        
        # Process source entity aggregations
        if "source_entities" in aggregations:
            for source_bucket in aggregations["source_entities"]["buckets"]:
                source_entity_name = source_bucket["key"]
                
                # Process each target type
                target_mappings = {
                    "connected_users": "user",
                    "connected_hosts": "host", 
                    "connected_processes": "process",
                    "connected_files": "file"
                }
                
                for agg_name, target_entity_type in target_mappings.items():
                    if agg_name in source_bucket:
                        for target_bucket in source_bucket[agg_name]["buckets"]:
                            target_entity_name = target_bucket["key"]
                            connection_strength = target_bucket["doc_count"]
                            
                            # Extract connection types from rule groups
                            connection_types = [b["key"] for b in target_bucket.get("connection_types", {}).get("buckets", [])]
                            
                            # Get temporal pattern
                            temporal_pattern = []
                            if "temporal_distribution" in target_bucket:
                                temporal_pattern = [
                                    {"timestamp": b["key_as_string"], "count": b["doc_count"]} 
                                    for b in target_bucket["temporal_distribution"]["buckets"]
                                ]
                            
                            # Get latest connection example and infer relationship type
                            latest_connection = None
                            relationship_type_label = "connected_to"  # default

                            if target_bucket.get("latest_connection", {}).get("hits", {}).get("hits"):
                                latest_hit = target_bucket["latest_connection"]["hits"]["hits"][0]["_source"]
                                latest_connection = {
                                    "timestamp": latest_hit.get("@timestamp", ""),
                                    "rule_description": latest_hit.get("rule", {}).get("description", ""),
                                    "rule_level": latest_hit.get("rule", {}).get("level", 0),
                                    "rule_id": latest_hit.get("rule", {}).get("id", "")
                                }

                                # Infer relationship type from event data
                                relationship_type_label = infer_relationship_type(
                                    source_type=source_type,
                                    target_type=target_entity_type,
                                    event_data=latest_hit
                                )

                            # Calculate relationship metrics
                            avg_severity = target_bucket.get("avg_severity", {}).get("value", 0)
                            relationship_score = min(100, (connection_strength * avg_severity) / 10)

                            relationship_data = {
                                "source_entity": {"type": source_type, "id": source_entity_name},
                                "target_entity": {"type": target_entity_type, "id": target_entity_name},
                                "relationship_type": relationship_type_label,
                                "relationship_description": get_relationship_description(relationship_type_label),
                                "connection_strength": connection_strength,
                                "connection_types": connection_types,
                                "temporal_pattern": temporal_pattern,
                                "latest_connection": latest_connection,
                                "avg_severity": round(avg_severity, 2),
                                "relationship_score": round(relationship_score, 2),
                                "risk_assessment": _assess_relationship_risk(connection_strength, avg_severity, connection_types)
                            }

                            # Filter out self-referential relationships (same entity connected to itself)
                            if source_entity_name == target_entity_name:
                                logger.debug("Skipping self-referential relationship",
                                           entity=source_entity_name,
                                           source_type=source_type,
                                           target_type=target_entity_type)
                                continue

                            relationships.append(relationship_data)
                            relationship_summary["connection_types"].update(connection_types)
                            relationship_summary["unique_targets"].add(target_entity_name)
                            relationship_summary["total_connections"] += connection_strength
        
        # Convert sets to lists and add summary statistics
        relationship_summary["connection_types"] = list(relationship_summary["connection_types"])
        relationship_summary["unique_targets"] = list(relationship_summary["unique_targets"])
        relationship_summary["unique_target_count"] = len(relationship_summary["unique_targets"])
        relationship_summary["avg_connection_strength"] = (
            relationship_summary["total_connections"] / len(relationships) if relationships else 0
        )
        
        # Generate enhanced analysis
        analysis = _analyze_aggregated_relationships(relationships, aggregations)
        
        # Build result
        result = {
            "relationship_type": "entity_to_entity",
            "search_parameters": {
                "source_type": source_type,
                "source_id": source_id,
                "target_type": target_type,
                "timeframe": timeframe,
                "data_source": "opensearch_alerts"
            },
            "relationship_summary": relationship_summary,
            "relationships": relationships,
            "analysis": analysis,
            "recommendations": _generate_aggregated_recommendations(relationships, analysis)
        }
        
        logger.info("Aggregated entity-to-entity relationship mapping completed", 
                   total_relationships=len(relationships),
                   unique_targets=len(relationship_summary["unique_targets"]),
                   total_connections=relationship_summary["total_connections"])
        
        return result
        
    except Exception as e:
        logger.error("Aggregated entity-to-entity relationship mapping failed", error=str(e))
        raise Exception(f"Failed to map entity relationships: {str(e)}")


def _build_relationship_aggregation_query(source_type: str, source_id: Optional[str], target_type: Optional[str], time_filter: Dict[str, Any], filters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build aggregation query for relationship mapping"""

    # Build source entity filter (only if source_id is provided)
    source_filters = _get_entity_filters(source_type, source_id) if source_id else []

    # Build additional filters (e.g., host filter)
    additional_filters = []
    if filters:
        if "host" in filters:
            additional_filters.append({
                "bool": {
                    "should": [
                        {"term": {"agent.name": filters["host"]}},
                        {"wildcard": {"agent.name": f"*{filters['host']}*"}}
                    ]
                }
            })
        if "user" in filters:
            additional_filters.append({
                "bool": {
                    "should": [
                        {"wildcard": {"data.srcuser": f"*{filters['user']}*"}},
                        {"wildcard": {"data.dstuser": f"*{filters['user']}*"}},
                        {"wildcard": {"data.win.eventdata.targetUserName": f"*{filters['user']}*"}}
                    ]
                }
            })
    
    query = {
        "query": {
            "bool": {
                "must": [time_filter] + source_filters + additional_filters
            }
        },
        "aggs": {
            "total_count": {
                "value_count": {
                    "field": "_id"
                }
            },
            "source_entities": {
                "terms": {
                    "field": _get_entity_field(source_type),
                    "size": 100
                },
                "aggs": {
                    "connected_users": {
                        "terms": {
                            "field": "data.win.eventdata.targetUserName",
                            "size": 50
                        },
                        "aggs": {
                            "connection_types": {
                                "terms": {"field": "rule.groups", "size": 10}
                            },
                            "avg_severity": {
                                "avg": {"field": "rule.level"}
                            },
                            "temporal_distribution": {
                                "date_histogram": {
                                    "field": "@timestamp",
                                    "interval": "1h"
                                }
                            },
                            "latest_connection": {
                                "top_hits": {
                                    "size": 1,
                                    "sort": [{"@timestamp": {"order": "desc"}}],
                                    "_source": [
                                        "@timestamp", "rule.description", "rule.level", "rule.id",
                                        "rule.groups", "data.win.system.eventID",
                                        "data.win.eventdata", "data"
                                    ]
                                }
                            }
                        }
                    },
                    "connected_hosts": {
                        "terms": {
                            "field": "agent.name", 
                            "size": 50
                        },
                        "aggs": {
                            "connection_types": {
                                "terms": {"field": "rule.groups", "size": 10}
                            },
                            "avg_severity": {
                                "avg": {"field": "rule.level"}
                            },
                            "temporal_distribution": {
                                "date_histogram": {
                                    "field": "@timestamp",
                                    "interval": "1h"  
                                }
                            },
                            "latest_connection": {
                                "top_hits": {
                                    "size": 1,
                                    "sort": [{"@timestamp": {"order": "desc"}}],
                                    "_source": [
                                        "@timestamp", "rule.description", "rule.level", "rule.id",
                                        "rule.groups", "data.win.system.eventID",
                                        "data.win.eventdata", "data"
                                    ]
                                }
                            }
                        }
                    },
                    "connected_processes": {
                        "terms": {
                            "field": "data.win.eventdata.image",
                            "size": 30
                        },
                        "aggs": {
                            "connection_types": {
                                "terms": {"field": "rule.groups", "size": 10}
                            },
                            "avg_severity": {
                                "avg": {"field": "rule.level"}
                            },
                            "latest_connection": {
                                "top_hits": {
                                    "size": 1,
                                    "sort": [{"@timestamp": {"order": "desc"}}],
                                    "_source": [
                                        "@timestamp", "rule.description", "rule.level", "rule.id",
                                        "rule.groups", "data.win.system.eventID",
                                        "data.win.eventdata", "data"
                                    ]
                                }
                            }
                        }
                    },
                    "connected_files": {
                        "terms": {
                            "field": "data.win.eventdata.targetFilename",
                            "size": 30
                        },
                        "aggs": {
                            "connection_types": {
                                "terms": {"field": "rule.groups", "size": 10}
                            },
                            "avg_severity": {
                                "avg": {"field": "rule.level"}
                            },
                            "latest_connection": {
                                "top_hits": {
                                    "size": 1,
                                    "sort": [{"@timestamp": {"order": "desc"}}],
                                    "_source": [
                                        "@timestamp", "rule.description", "rule.level", "rule.id",
                                        "rule.groups", "data.win.system.eventID",
                                        "data.win.eventdata", "data"
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    return query


def _get_entity_filters(entity_type: str, entity_id: Optional[str]) -> List[Dict[str, Any]]:
    """Get filters for specific entity type"""
    filters = []

    # If no entity_id provided, return empty filters
    if not entity_id:
        return filters

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
    elif entity_type.lower() == "process":
        filters.append({
            "bool": {
                "should": [
                    {"wildcard": {"data.process": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.image": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.commandLine": f"*{entity_id}*"}}
                ]
            }
        })
    
    return filters


def _get_entity_field(entity_type: str) -> str:
    """Get the primary field for entity type"""
    field_mapping = {
        "host": "agent.name",
        "user": "data.win.eventdata.targetUserName", 
        "process": "data.win.eventdata.image",
        "file": "data.win.eventdata.targetFilename"
    }
    return field_mapping.get(entity_type.lower(), "agent.name")


def _assess_relationship_risk(connection_strength: int, avg_severity: float, connection_types: List[str]) -> str:
    """Assess risk level of relationship"""
    risk_score = 0
    
    # Factor in connection strength
    if connection_strength > 100:
        risk_score += 30
    elif connection_strength > 50:
        risk_score += 20
    elif connection_strength > 10:
        risk_score += 10
    
    # Factor in average severity
    if avg_severity > 8:
        risk_score += 40
    elif avg_severity > 5:
        risk_score += 25
    elif avg_severity > 3:
        risk_score += 10
    
    # Factor in connection types
    high_risk_types = ["authentication_failed", "privilege_escalation", "malware", "attack"]
    if any(risk_type in " ".join(connection_types).lower() for risk_type in high_risk_types):
        risk_score += 30
    
    if risk_score > 70:
        return "Critical"
    elif risk_score > 40:
        return "High"
    elif risk_score > 20:
        return "Medium"
    else:
        return "Low"


def _analyze_aggregated_relationships(relationships: List[Dict[str, Any]], aggregations: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze relationships using aggregation data"""
    if not relationships:
        return {"message": "No relationships found"}
    
    analysis = {
        "relationship_patterns": {},
        "strength_distribution": {},
        "risk_assessment": {},
        "temporal_analysis": {}
    }
    
    # Analyze relationship strength distribution
    strength_values = [r["connection_strength"] for r in relationships]
    analysis["strength_distribution"] = {
        "min_strength": min(strength_values),
        "max_strength": max(strength_values),
        "avg_strength": sum(strength_values) / len(strength_values),
        "total_connections": sum(strength_values)
    }
    
    # Risk assessment
    risk_counts = {}
    for r in relationships:
        risk_level = r["risk_assessment"]
        risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
    
    analysis["risk_assessment"] = {
        "risk_distribution": risk_counts,
        "high_risk_relationships": len([r for r in relationships if r["risk_assessment"] in ["Critical", "High"]]),
        "risk_percentage": (len([r for r in relationships if r["risk_assessment"] in ["Critical", "High"]]) / len(relationships)) * 100
    }
    
    return analysis


def _generate_aggregated_recommendations(relationships: List[Dict[str, Any]], analysis: Dict[str, Any]) -> List[str]:
    """Generate recommendations based on aggregated relationship analysis"""
    recommendations = []
    
    if not relationships:
        return ["No entity relationships found in the specified timeframe"]
    
    # High-risk relationship recommendations
    high_risk_count = analysis.get("risk_assessment", {}).get("high_risk_relationships", 0)
    if high_risk_count > 5:
        recommendations.append(f"Critical: {high_risk_count} high-risk relationships detected - immediate investigation required")
    elif high_risk_count > 0:
        recommendations.append(f"Warning: {high_risk_count} high-risk relationships found - review recommended")
    
    # Connection strength recommendations
    max_strength = analysis.get("strength_distribution", {}).get("max_strength", 0)
    if max_strength > 200:
        recommendations.append("Very high connection strength detected - investigate for potential automation or compromise")
    
    # General recommendations
    if len(relationships) > 100:
        recommendations.append("High relationship volume detected - consider narrowing timeframe for detailed analysis")
    
    if not recommendations:
        recommendations.append("Entity relationships appear normal based on aggregated analysis")
    
    return recommendations
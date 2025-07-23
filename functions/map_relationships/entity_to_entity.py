"""
Map direct relationships between two specific entities
"""
from typing import Dict, Any, List, Optional
import structlog
from datetime import datetime

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map direct relationships between two specific entities
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including source_type, source_id, target_type, timeframe
        
    Returns:
        Direct entity relationships with connection details
    """
    try:
        # Extract parameters
        source_type = params.get("source_type")
        source_id = params.get("source_id")
        target_type = params.get("target_type")
        timeframe = params.get("timeframe", "24h")
        
        logger.info("Executing entity-to-entity relationship mapping", 
                   source_type=source_type,
                   source_id=source_id,
                   target_type=target_type,
                   timeframe=timeframe)
        
        # Build time range filter
        time_filter = opensearch_client.build_time_range_filter(timeframe)
        
        # Build the search query based on entity types
        query = _build_entity_relationship_query(source_type, source_id, target_type, time_filter)
        
        # Execute search
        response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=query
        )
        
        # Process results
        hits = response.get("hits", {})
        total_alerts = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else hits.get("total", 0)
        events = hits.get("hits", [])
        
        logger.info("Retrieved events for entity relationship mapping", count=len(events), total=total_alerts)
        
        # Process relationships
        relationships = []
        relationship_summary = {
            "source_entity": {"type": source_type, "id": source_id},
            "target_entity": {"type": target_type, "id": "multiple" if not target_type else "specified"},
            "total_connections": len(events),
            "timeframe": timeframe,
            "connection_types": set(),
            "unique_targets": set()
        }
        
        for hit in events:
            source = hit.get("_source", {})
            relationship_data = _extract_relationship_data(source, source_type, source_id, target_type)
            if relationship_data:
                relationships.append(relationship_data)
                relationship_summary["connection_types"].add(relationship_data["connection_type"])
                relationship_summary["unique_targets"].add(relationship_data["target_entity"]["id"])
        
        # Convert sets to lists for JSON serialization
        relationship_summary["connection_types"] = list(relationship_summary["connection_types"])
        relationship_summary["unique_targets"] = list(relationship_summary["unique_targets"])
        relationship_summary["unique_target_count"] = len(relationship_summary["unique_targets"])
        
        # Generate relationship analysis
        analysis = _analyze_relationships(relationships, source_type, target_type)
        
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
            "recommendations": _generate_entity_recommendations(relationships, analysis)
        }
        
        logger.info("Entity-to-entity relationship mapping completed", 
                   total_relationships=len(relationships),
                   unique_targets=len(relationship_summary["unique_targets"]))
        
        return result
        
    except Exception as e:
        logger.error("Entity-to-entity relationship mapping failed", error=str(e))
        raise Exception(f"Failed to map entity relationships: {str(e)}")


def _build_entity_relationship_query(source_type: str, source_id: str, target_type: Optional[str], time_filter: Dict[str, Any]) -> Dict[str, Any]:
    """Build search query for entity relationships"""
    
    # Base query structure
    query = {
        "query": {
            "bool": {
                "must": [time_filter],
                "should": []
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 500,
        "_source": [
            "@timestamp", "rule.description", "rule.level", "rule.id",
            "agent.name", "agent.id", "agent.ip", "manager.name",
            "data.srcip", "data.dstip", "data.srcuser", "data.dstuser",
            "data.command", "data.process", "data.protocol",
            "data.win.eventdata.commandLine", "data.win.eventdata.image",
            "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName",
            "data.win.eventdata.targetFilename", "rule.groups", "location"
        ]
    }
    
    # Build source entity filters
    source_filters = _get_entity_filters(source_type, source_id)
    
    # Add target entity filters if specified
    if target_type:
        target_filters = _get_entity_filters(target_type, None)  # Will be filtered in post-processing
        # Combine source and target filters
        query["query"]["bool"]["should"] = [
            {"bool": {"must": source_filters}},
            {"bool": {"must": target_filters}}
        ]
        query["query"]["bool"]["minimum_should_match"] = 1
    else:
        # Only source entity filters
        query["query"]["bool"]["must"].extend(source_filters)
    
    return query


def _get_entity_filters(entity_type: str, entity_id: Optional[str]) -> List[Dict[str, Any]]:
    """Get filters for specific entity type"""
    filters = []
    
    if entity_type.lower() == "host":
        if entity_id:
            filters.extend([
                {"bool": {"should": [
                    {"term": {"agent.name": entity_id}},
                    {"term": {"agent.ip": entity_id}},
                    {"wildcard": {"agent.name": f"*{entity_id}*"}}
                ]}}
            ])
        else:
            filters.append({"exists": {"field": "agent.name"}})
            
    elif entity_type.lower() == "user":
        if entity_id:
            filters.extend([
                {"bool": {"should": [
                    {"wildcard": {"data.srcuser": f"*{entity_id}*"}},
                    {"wildcard": {"data.dstuser": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.targetUserName": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.subjectUserName": f"*{entity_id}*"}}
                ]}}
            ])
        else:
            filters.append({"bool": {"should": [
                {"exists": {"field": "data.srcuser"}},
                {"exists": {"field": "data.dstuser"}},
                {"exists": {"field": "data.win.eventdata.targetUserName"}}
            ]}})
            
    elif entity_type.lower() == "process":
        if entity_id:
            filters.extend([
                {"bool": {"should": [
                    {"wildcard": {"data.process": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.image": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.commandLine": f"*{entity_id}*"}}
                ]}}
            ])
        else:
            filters.append({"bool": {"should": [
                {"exists": {"field": "data.process"}},
                {"exists": {"field": "data.win.eventdata.image"}}
            ]}})
            
    elif entity_type.lower() == "file":
        if entity_id:
            filters.extend([
                {"bool": {"should": [
                    {"wildcard": {"data.path": f"*{entity_id}*"}},
                    {"wildcard": {"data.win.eventdata.targetFilename": f"*{entity_id}*"}}
                ]}}
            ])
        else:
            filters.append({"bool": {"should": [
                {"exists": {"field": "data.path"}},
                {"exists": {"field": "data.win.eventdata.targetFilename"}}
            ]}})
            
    elif entity_type.lower() == "ip":
        if entity_id:
            filters.extend([
                {"bool": {"should": [
                    {"term": {"data.srcip": entity_id}},
                    {"term": {"data.dstip": entity_id}},
                    {"term": {"agent.ip": entity_id}}
                ]}}
            ])
        else:
            filters.append({"bool": {"should": [
                {"exists": {"field": "data.srcip"}},
                {"exists": {"field": "data.dstip"}}
            ]}})
    
    return filters


def _extract_relationship_data(source: Dict[str, Any], source_type: str, source_id: str, target_type: Optional[str]) -> Optional[Dict[str, Any]]:
    """Extract relationship data from event source"""
    
    timestamp = source.get("@timestamp", "")
    agent_name = source.get("agent", {}).get("name", "")
    agent_ip = source.get("agent", {}).get("ip", "")
    
    # Extract relevant data fields
    data = source.get("data", {})
    win_eventdata = data.get("win", {}).get("eventdata", {})
    
    # Determine connection type based on available data
    connection_type = "unknown"
    target_entity = {"type": "unknown", "id": "unknown"}
    connection_details = {}
    
    # Host relationships
    if source_type.lower() == "host":
        if data.get("srcuser") or data.get("dstuser") or win_eventdata.get("targetUserName"):
            connection_type = "user_activity"
            target_entity = {
                "type": "user",
                "id": data.get("srcuser") or data.get("dstuser") or win_eventdata.get("targetUserName", "")
            }
        elif data.get("process") or win_eventdata.get("image"):
            connection_type = "process_execution"
            target_entity = {
                "type": "process", 
                "id": data.get("process") or win_eventdata.get("image", "")
            }
        elif data.get("srcip") or data.get("dstip"):
            connection_type = "network_connection"
            target_entity = {
                "type": "ip",
                "id": data.get("dstip") or data.get("srcip", "")
            }
    
    # User relationships
    elif source_type.lower() == "user":
        if agent_name and source_id.lower() in (data.get("srcuser", "").lower() or data.get("dstuser", "").lower() or win_eventdata.get("targetUserName", "").lower()):
            connection_type = "host_access"
            target_entity = {"type": "host", "id": agent_name}
        elif data.get("path") or win_eventdata.get("targetFilename"):
            connection_type = "file_access"
            target_entity = {
                "type": "file",
                "id": data.get("path") or win_eventdata.get("targetFilename", "")
            }
    
    # Process relationships
    elif source_type.lower() == "process":
        if data.get("srcip") or data.get("dstip"):
            connection_type = "network_activity"
            target_entity = {
                "type": "ip",
                "id": data.get("dstip") or data.get("srcip", "")
            }
        elif data.get("path") or win_eventdata.get("targetFilename"):
            connection_type = "file_interaction"
            target_entity = {
                "type": "file", 
                "id": data.get("path") or win_eventdata.get("targetFilename", "")
            }
    
    # Skip if no meaningful relationship found
    if target_entity["id"] in ["unknown", ""]:
        return None
    
    # Build connection details
    connection_details = {
        "rule_id": source.get("rule", {}).get("id", ""),
        "rule_description": source.get("rule", {}).get("description", ""),
        "rule_level": source.get("rule", {}).get("level", 0),
        "protocol": data.get("protocol", ""),
        "command": data.get("command") or win_eventdata.get("commandLine", ""),
        "location": source.get("location", "")
    }
    
    return {
        "timestamp": timestamp,
        "formatted_time": _format_timestamp(timestamp),
        "source_entity": {"type": source_type, "id": source_id},
        "target_entity": target_entity,
        "connection_type": connection_type,
        "connection_details": connection_details,
        "agent": {"name": agent_name, "ip": agent_ip}
    }


def _analyze_relationships(relationships: List[Dict[str, Any]], source_type: str, target_type: Optional[str]) -> Dict[str, Any]:
    """Analyze relationship patterns"""
    
    if not relationships:
        return {"message": "No relationships found"}
    
    analysis = {
        "connection_patterns": {},
        "temporal_distribution": {},
        "risk_assessment": {},
        "anomalies": []
    }
    
    # Analyze connection patterns
    connection_counts = {}
    target_counts = {}
    
    for rel in relationships:
        conn_type = rel["connection_type"]
        target_id = rel["target_entity"]["id"]
        
        connection_counts[conn_type] = connection_counts.get(conn_type, 0) + 1
        target_counts[target_id] = target_counts.get(target_id, 0) + 1
    
    analysis["connection_patterns"] = {
        "most_common_connection": max(connection_counts.items(), key=lambda x: x[1]) if connection_counts else ("none", 0),
        "connection_diversity": len(connection_counts),
        "target_diversity": len(target_counts),
        "most_active_target": max(target_counts.items(), key=lambda x: x[1]) if target_counts else ("none", 0)
    }
    
    # Risk assessment
    high_risk_connections = [r for r in relationships if r["connection_details"]["rule_level"] >= 7]
    analysis["risk_assessment"] = {
        "high_risk_connections": len(high_risk_connections),
        "risk_percentage": (len(high_risk_connections) / len(relationships)) * 100 if relationships else 0,
        "average_severity": sum([r["connection_details"]["rule_level"] for r in relationships]) / len(relationships)
    }
    
    # Identify anomalies
    if len(target_counts) > 10:
        analysis["anomalies"].append("High number of unique targets - possible lateral movement")
    
    if analysis["risk_assessment"]["risk_percentage"] > 30:
        analysis["anomalies"].append("High percentage of risky connections detected")
    
    return analysis


def _generate_entity_recommendations(relationships: List[Dict[str, Any]], analysis: Dict[str, Any]) -> List[str]:
    """Generate recommendations based on relationship analysis"""
    recommendations = []
    
    if not relationships:
        return ["No entity relationships found in the specified timeframe"]
    
    # Connection pattern recommendations
    if analysis.get("connection_patterns", {}).get("target_diversity", 0) > 20:
        recommendations.append("Investigate high target diversity - potential compromise or lateral movement")
    
    # Risk-based recommendations
    risk_pct = analysis.get("risk_assessment", {}).get("risk_percentage", 0)
    if risk_pct > 50:
        recommendations.append(f"Critical: {risk_pct:.1f}% of connections are high-risk - immediate investigation required")
    elif risk_pct > 20:
        recommendations.append(f"Warning: {risk_pct:.1f}% of connections are high-risk - review recommended")
    
    # Anomaly recommendations
    anomalies = analysis.get("anomalies", [])
    if anomalies:
        recommendations.extend([f"Investigate: {anomaly}" for anomaly in anomalies])
    
    # General recommendations
    if len(relationships) > 100:
        recommendations.append("High activity volume detected - consider narrowing timeframe for detailed analysis")
    
    if not recommendations:
        recommendations.append("Entity relationships appear normal - continue monitoring")
    
    return recommendations


def _format_timestamp(timestamp: str) -> str:
    """Format timestamp for display"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, AttributeError):
        return timestamp
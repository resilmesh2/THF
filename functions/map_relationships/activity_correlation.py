"""
Correlate activities and behaviors across multiple entities
"""
from typing import Dict, Any, List, Optional
import structlog
from datetime import datetime
from collections import defaultdict, Counter

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Correlate activities and behaviors across multiple entities
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including source_type, source_id, target_type, timeframe
        
    Returns:
        Activity correlation analysis with behavioral patterns
    """
    try:
        # Extract parameters
        source_type = params.get("source_type")
        source_id = params.get("source_id")
        target_type = params.get("target_type")
        timeframe = params.get("timeframe", "24h")
        
        logger.info("Executing activity correlation analysis", 
                   source_type=source_type,
                   source_id=source_id,
                   target_type=target_type,
                   timeframe=timeframe)
        
        # Build time range filter
        time_filter = opensearch_client.build_time_range_filter(timeframe)
        
        # Build the search query focused on correlated activities
        query = _build_activity_correlation_query(source_type, source_id, target_type, time_filter)
        
        # Execute search
        response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=query
        )
        
        # Process results
        hits = response.get("hits", {})
        total_alerts = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else hits.get("total", 0)
        events = hits.get("hits", [])
        
        logger.info("Retrieved events for activity correlation analysis", count=len(events), total=total_alerts)
        
        # Process activity correlations
        correlation_events = []
        correlation_summary = {
            "source_entity": {"type": source_type, "id": source_id},
            "total_correlated_activities": len(events),
            "timeframe": timeframe,
            "activity_types": set(),
            "correlated_entities": set(),
            "temporal_clusters": defaultdict(int)
        }
        
        for hit in events:
            source = hit.get("_source", {})
            activity_data = _extract_activity_data(source, source_type, source_id, target_type)
            if activity_data:
                correlation_events.append(activity_data)
                correlation_summary["activity_types"].add(activity_data["activity_type"])
                correlation_summary["correlated_entities"].add(f"{activity_data['correlated_entity']['type']}:{activity_data['correlated_entity']['id']}")
                
                # Group by time clusters (30-minute windows)
                try:
                    dt = datetime.fromisoformat(activity_data["timestamp"].replace('Z', '+00:00'))
                    time_cluster = dt.replace(minute=0 if dt.minute < 30 else 30, second=0, microsecond=0)
                    correlation_summary["temporal_clusters"][time_cluster.isoformat()] += 1
                except (ValueError, AttributeError):
                    pass
        
        # Convert sets to lists for JSON serialization
        correlation_summary["activity_types"] = list(correlation_summary["activity_types"])
        correlation_summary["correlated_entities"] = list(correlation_summary["correlated_entities"])
        correlation_summary["unique_entities_count"] = len(correlation_summary["correlated_entities"])
        correlation_summary["temporal_clusters"] = dict(correlation_summary["temporal_clusters"])
        
        # Analyze activity correlations
        correlation_analysis = await _analyze_activity_correlations(correlation_events, source_type)
        
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
            "correlation_analysis": correlation_analysis,
            "behavioral_insights": _generate_correlation_insights(correlation_events, correlation_analysis),
            "recommendations": _generate_correlation_recommendations(correlation_analysis)
        }
        
        logger.info("Activity correlation analysis completed", 
                   total_events=len(correlation_events),
                   unique_entities=len(correlation_summary["correlated_entities"]))
        
        return result
        
    except Exception as e:
        logger.error("Activity correlation analysis failed", error=str(e))
        raise Exception(f"Failed to analyze activity correlations: {str(e)}")


def _build_activity_correlation_query(source_type: str, source_id: str, target_type: Optional[str], time_filter: Dict[str, Any]) -> Dict[str, Any]:
    """Build search query focused on correlated activities"""
    
    query = {
        "query": {
            "bool": {
                "must": [time_filter],
                "should": [
                    # System activities
                    {"terms": {"rule.groups": ["audit", "system", "process", "network"]}},
                    # Authentication and access events
                    {"terms": {"rule.groups": ["authentication", "pam", "ssh", "login", "logon"]}},
                    # File system activities
                    {"terms": {"rule.groups": ["syscheck", "file_integrity", "fim"]}},
                    # Windows security events
                    {"bool": {"must": [
                        {"terms": {"rule.groups": ["windows", "security"]}},
                        {"exists": {"field": "data.win.eventdata"}}
                    ]}},
                    # Network connections and communications
                    {"bool": {"must": [
                        {"exists": {"field": "data.srcip"}},
                        {"range": {"rule.level": {"gte": 2}}}
                    ]}},
                    # Process execution and command line activity
                    {"bool": {"must": [
                        {"terms": {"rule.groups": ["process", "execution"]}},
                        {"exists": {"field": "data.win.eventdata.commandLine"}}
                    ]}}
                ],
                "minimum_should_match": 1
            }
        },
        "sort": [{"@timestamp": {"order": "asc"}}],
        "size": 800,
        "_source": [
            "@timestamp", "rule.description", "rule.level", "rule.id",
            "agent.name", "agent.id", "agent.ip",
            "data.srcip", "data.dstip", "data.srcuser", "data.dstuser",
            "data.command", "data.process", "data.protocol",
            "data.win.eventdata.commandLine", "data.win.eventdata.image",
            "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName",
            "data.win.eventdata.targetFilename", "data.win.eventdata.processId",
            "rule.groups", "location", "decoder.name"
        ]
    }
    
    # Add source entity filter
    source_filter = _get_source_entity_filter(source_type, source_id)
    if source_filter:
        query["query"]["bool"]["must"].append(source_filter)
    
    return query


def _get_source_entity_filter(source_type: str, source_id: str) -> Optional[Dict[str, Any]]:
    """Get filter for source entity"""
    
    if source_type.lower() == "host":
        return {"bool": {"should": [
            {"term": {"agent.name": source_id}},
            {"term": {"agent.ip": source_id}},
            {"wildcard": {"agent.name": f"*{source_id}*"}}
        ]}}
        
    elif source_type.lower() == "user":
        return {"bool": {"should": [
            {"wildcard": {"data.srcuser": f"*{source_id}*"}},
            {"wildcard": {"data.dstuser": f"*{source_id}*"}},
            {"wildcard": {"data.win.eventdata.targetUserName": f"*{source_id}*"}},
            {"wildcard": {"data.win.eventdata.subjectUserName": f"*{source_id}*"}}
        ]}}
        
    elif source_type.lower() == "process":
        return {"bool": {"should": [
            {"wildcard": {"data.process": f"*{source_id}*"}},
            {"wildcard": {"data.win.eventdata.image": f"*{source_id}*"}},
            {"wildcard": {"data.win.eventdata.commandLine": f"*{source_id}*"}}
        ]}}
        
    elif source_type.lower() == "ip":
        return {"bool": {"should": [
            {"term": {"data.srcip": source_id}},
            {"term": {"agent.ip": source_id}}
        ]}}
    
    return None


def _extract_activity_data(source: Dict[str, Any], source_type: str, source_id: str, target_type: Optional[str]) -> Optional[Dict[str, Any]]:
    """Extract activity correlation data from event source"""
    
    timestamp = source.get("@timestamp", "")
    agent_name = source.get("agent", {}).get("name", "")
    
    # Extract relevant data fields
    data = source.get("data", {})
    win_eventdata = data.get("win", {}).get("eventdata", {})
    rule_groups = source.get("rule", {}).get("groups", [])
    
    # Determine activity type and correlated entity
    activity_type = "unknown"
    correlated_entity = {"type": "unknown", "id": "unknown"}
    activity_details = {}
    
    # Process execution correlation
    if any(group in rule_groups for group in ["process", "execution", "audit"]) or win_eventdata.get("commandLine"):
        activity_type = "process_execution"
        process_name = data.get("process") or win_eventdata.get("image", "")
        if process_name:
            correlated_entity = {"type": "process", "id": process_name}
            activity_details = {
                "command_line": win_eventdata.get("commandLine", ""),
                "process_id": win_eventdata.get("processId", ""),
                "parent_process": win_eventdata.get("parentImage", "")
            }
    
    # Network activity correlation
    elif data.get("srcip") or data.get("dstip"):
        activity_type = "network_activity"
        target_ip = data.get("dstip") or data.get("srcip", "")
        if target_ip:
            correlated_entity = {"type": "ip", "id": target_ip}
            activity_details = {
                "protocol": data.get("protocol", ""),
                "source_ip": data.get("srcip", ""),
                "destination_ip": data.get("dstip", ""),
                "communication_type": "outbound" if data.get("dstip") else "inbound"
            }
    
    # File system activity correlation
    elif any(group in rule_groups for group in ["syscheck", "file_integrity", "fim"]):
        activity_type = "file_activity"
        file_path = data.get("path") or win_eventdata.get("targetFilename", "")
        if file_path:
            correlated_entity = {"type": "file", "id": file_path}
            activity_details = {
                "operation": "file_change",
                "file_type": _get_file_type(file_path),
                "user": data.get("srcuser") or win_eventdata.get("targetUserName", "")
            }
    
    # Authentication activity correlation
    elif any(group in rule_groups for group in ["authentication", "pam", "ssh", "login", "logon"]):
        activity_type = "authentication_activity"
        target_user = data.get("dstuser") or win_eventdata.get("targetUserName", "")
        if target_user:
            correlated_entity = {"type": "user", "id": target_user}
            activity_details = {
                "logon_type": win_eventdata.get("logonType", ""),
                "source_ip": data.get("srcip", ""),
                "authentication_result": "success" if source.get("rule", {}).get("level", 0) < 5 else "failure"
            }
    
    # Skip if no meaningful correlation found
    if correlated_entity["id"] in ["unknown", ""]:
        return None
    
    return {
        "timestamp": timestamp,
        "formatted_time": _format_timestamp(timestamp),
        "activity_type": activity_type,
        "correlated_entity": correlated_entity,
        "activity_details": activity_details,
        "rule_info": {
            "id": source.get("rule", {}).get("id", ""),
            "description": source.get("rule", {}).get("description", ""),
            "level": source.get("rule", {}).get("level", 0)
        },
        "agent": {"name": agent_name, "ip": source.get("agent", {}).get("ip", "")}
    }


async def _analyze_activity_correlations(correlation_events: List[Dict[str, Any]], source_type: str) -> Dict[str, Any]:
    """Analyze activity correlations for patterns and insights"""
    
    if not correlation_events:
        return {"message": "No correlated activities found for analysis"}
    
    analysis = {
        "activity_patterns": {},
        "temporal_analysis": {},
        "entity_interactions": {},
        "correlation_strength": {},
        "risk_indicators": {}
    }
    
    # Activity patterns analysis
    activity_counts = Counter([event["activity_type"] for event in correlation_events])
    entity_type_counts = Counter([event["correlated_entity"]["type"] for event in correlation_events])
    
    analysis["activity_patterns"] = {
        "most_common_activity": activity_counts.most_common(1)[0] if activity_counts else ("none", 0),
        "activity_distribution": dict(activity_counts),
        "entity_type_distribution": dict(entity_type_counts),
        "activity_diversity": len(activity_counts)
    }
    
    # Temporal analysis
    hourly_activity = defaultdict(int)
    activity_sequences = []
    
    for event in correlation_events:
        try:
            dt = datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00'))
            hourly_activity[dt.hour] += 1
            activity_sequences.append((dt, event["activity_type"]))
        except (ValueError, AttributeError):
            continue
    
    # Sort sequences by time
    activity_sequences.sort(key=lambda x: x[0])
    
    analysis["temporal_analysis"] = {
        "hourly_distribution": dict(hourly_activity),
        "peak_activity_hour": max(hourly_activity.items(), key=lambda x: x[1]) if hourly_activity else (0, 0),
        "activity_sequence": [seq[1] for seq in activity_sequences[:20]],  # First 20 activities
        "temporal_clustering": _detect_temporal_clusters(activity_sequences)
    }
    
    # Entity interactions analysis
    entity_interactions = defaultdict(list)
    for event in correlation_events:
        entity_key = f"{event['correlated_entity']['type']}:{event['correlated_entity']['id']}"
        entity_interactions[entity_key].append(event["activity_type"])
    
    analysis["entity_interactions"] = {
        "total_unique_entities": len(entity_interactions),
        "most_active_entity": max(entity_interactions.items(), key=lambda x: len(x[1])) if entity_interactions else ("none", []),
        "entity_activity_counts": {k: len(v) for k, v in entity_interactions.items()},
        "cross_entity_patterns": _analyze_cross_entity_patterns(entity_interactions)
    }
    
    # Correlation strength analysis
    total_events = len(correlation_events)
    unique_entities = len(entity_interactions)
    
    analysis["correlation_strength"] = {
        "correlation_density": unique_entities / total_events if total_events else 0,
        "activity_concentration": max(activity_counts.values()) / total_events if total_events else 0,
        "temporal_spread": len(hourly_activity),
        "strength_score": _calculate_correlation_strength(correlation_events, entity_interactions)
    }
    
    # Risk indicators
    high_risk_activities = [e for e in correlation_events if e["rule_info"]["level"] >= 7]
    suspicious_patterns = []
    
    # Check for rapid activity bursts
    if len(activity_sequences) > 10:
        time_diffs = [(activity_sequences[i+1][0] - activity_sequences[i][0]).total_seconds() 
                     for i in range(len(activity_sequences)-1)]
        avg_time_diff = sum(time_diffs) / len(time_diffs)
        if avg_time_diff < 60:  # Less than 1 minute between activities
            suspicious_patterns.append("Rapid activity burst detected - possible automated behavior")
    
    # Check for unusual entity diversity
    if unique_entities > 20:
        suspicious_patterns.append("High entity interaction diversity - possible lateral movement or reconnaissance")
    
    analysis["risk_indicators"] = {
        "high_risk_activities": len(high_risk_activities),
        "risk_percentage": (len(high_risk_activities) / total_events * 100) if total_events else 0,
        "suspicious_patterns": suspicious_patterns,
        "overall_risk_score": _calculate_correlation_risk_score(correlation_events, suspicious_patterns)
    }
    
    return analysis


def _detect_temporal_clusters(activity_sequences: List[tuple]) -> Dict[str, Any]:
    """Detect temporal clusters of activity"""
    if len(activity_sequences) < 2:
        return {"clusters_found": 0, "cluster_info": []}
    
    clusters = []
    current_cluster = [activity_sequences[0]]
    
    for i in range(1, len(activity_sequences)):
        time_diff = (activity_sequences[i][0] - activity_sequences[i-1][0]).total_seconds()
        
        if time_diff <= 300:  # 5 minutes threshold
            current_cluster.append(activity_sequences[i])
        else:
            if len(current_cluster) > 3:  # Cluster must have at least 4 activities
                clusters.append({
                    "start_time": current_cluster[0][0].isoformat(),
                    "end_time": current_cluster[-1][0].isoformat(),
                    "activity_count": len(current_cluster),
                    "activity_types": list(set([act[1] for act in current_cluster]))
                })
            current_cluster = [activity_sequences[i]]
    
    # Check final cluster
    if len(current_cluster) > 3:
        clusters.append({
            "start_time": current_cluster[0][0].isoformat(),
            "end_time": current_cluster[-1][0].isoformat(),
            "activity_count": len(current_cluster),
            "activity_types": list(set([act[1] for act in current_cluster]))
        })
    
    return {
        "clusters_found": len(clusters),
        "cluster_info": clusters[:5]  # Return top 5 clusters
    }


def _analyze_cross_entity_patterns(entity_interactions: Dict[str, List[str]]) -> Dict[str, Any]:
    """Analyze patterns across different entities"""
    patterns = {
        "common_activity_sequences": {},
        "entity_type_correlations": defaultdict(list),
        "activity_sharing": {}
    }
    
    # Group entities by type
    for entity_key, activities in entity_interactions.items():
        entity_type = entity_key.split(":")[0]
        patterns["entity_type_correlations"][entity_type].extend(activities)
    
    # Find common activity patterns
    all_activity_sets = [set(activities) for activities in entity_interactions.values()]
    if len(all_activity_sets) > 1:
        common_activities = set.intersection(*all_activity_sets)
        patterns["activity_sharing"] = {
            "shared_activities": list(common_activities),
            "sharing_percentage": len(common_activities) / len(set().union(*all_activity_sets)) * 100 if all_activity_sets else 0
        }
    
    return dict(patterns)


def _calculate_correlation_strength(correlation_events: List[Dict[str, Any]], entity_interactions: Dict[str, List[str]]) -> float:
    """Calculate overall correlation strength score"""
    if not correlation_events:
        return 0.0
    
    score = 0.0
    
    # Diversity bonus
    unique_activities = len(set([e["activity_type"] for e in correlation_events]))
    unique_entities = len(entity_interactions)
    
    score += min(30, unique_activities * 3)  # Up to 30 points for activity diversity
    score += min(25, unique_entities * 2)    # Up to 25 points for entity diversity
    
    # Temporal correlation bonus
    time_spans = []
    for activities in entity_interactions.values():
        if len(activities) > 1:
            score += 5  # Bonus for multi-activity entities
    
    # Event density bonus
    total_events = len(correlation_events)
    if total_events > 50:
        score += 20
    elif total_events > 20:
        score += 10
    
    return min(100.0, score)


def _calculate_correlation_risk_score(correlation_events: List[Dict[str, Any]], suspicious_patterns: List[str]) -> float:
    """Calculate risk score for correlated activities"""
    if not correlation_events:
        return 0.0
    
    risk_score = 0.0
    
    # Base risk from suspicious patterns
    risk_score += len(suspicious_patterns) * 20
    
    # Risk from high-severity events
    high_severity_count = len([e for e in correlation_events if e["rule_info"]["level"] >= 8])
    risk_score += (high_severity_count / len(correlation_events)) * 35
    
    # Risk from activity diversity (potential reconnaissance)
    unique_entities = len(set([f"{e['correlated_entity']['type']}:{e['correlated_entity']['id']}" for e in correlation_events]))
    if unique_entities > 30:
        risk_score += 25
    elif unique_entities > 15:
        risk_score += 15
    
    return min(100.0, risk_score)


def _get_file_type(file_path: str) -> str:
    """Determine file type from path"""
    if not file_path:
        return "unknown"
    
    file_path_lower = file_path.lower()
    if file_path_lower.endswith(('.exe', '.dll', '.sys')):
        return "executable"
    elif file_path_lower.endswith(('.txt', '.log', '.conf', '.cfg', '.ini')):
        return "configuration"
    elif file_path_lower.endswith(('.jpg', '.png', '.gif', '.bmp')):
        return "image"
    elif file_path_lower.endswith(('.doc', '.pdf', '.xls', '.ppt')):
        return "document"
    else:
        return "other"


def _generate_correlation_insights(correlation_events: List[Dict[str, Any]], analysis: Dict[str, Any]) -> List[str]:
    """Generate behavioral insights from activity correlation"""
    insights = []
    
    if not correlation_events:
        return ["No correlated activities available for analysis"]
    
    # Activity pattern insights
    patterns = analysis.get("activity_patterns", {})
    common_activity = patterns.get("most_common_activity", ("", 0))
    if common_activity[1] > 0:
        insights.append(f"Primary correlated activity: {common_activity[0]} ({common_activity[1]} occurrences)")
    
    # Temporal insights
    temporal = analysis.get("temporal_analysis", {})
    peak_hour = temporal.get("peak_activity_hour", (0, 0))
    if peak_hour[1] > 0:
        insights.append(f"Peak correlation activity at {peak_hour[0]:02d}:00 with {peak_hour[1]} events")
    
    clusters = temporal.get("temporal_clustering", {}).get("clusters_found", 0)
    if clusters > 0:
        insights.append(f"Detected {clusters} temporal activity clusters - possible coordinated behavior")
    
    # Entity interaction insights
    interactions = analysis.get("entity_interactions", {})
    unique_entities = interactions.get("total_unique_entities", 0)
    if unique_entities > 20:
        insights.append("High entity interaction diversity - investigate for potential lateral movement")
    elif unique_entities > 10:
        insights.append("Moderate entity interaction diversity - monitor for expansion patterns")
    
    # Risk insights
    risk = analysis.get("risk_indicators", {})
    risk_score = risk.get("overall_risk_score", 0)
    if risk_score > 70:
        insights.append("High-risk correlation patterns detected - immediate investigation recommended")
    elif risk_score > 40:
        insights.append("Moderate-risk correlation patterns - enhanced monitoring advised")
    else:
        insights.append("Correlation patterns appear within normal parameters")
    
    return insights


def _generate_correlation_recommendations(analysis: Dict[str, Any]) -> List[str]:
    """Generate recommendations based on activity correlation analysis"""
    recommendations = []
    
    # Risk-based recommendations
    risk = analysis.get("risk_indicators", {})
    suspicious_patterns = risk.get("suspicious_patterns", [])
    
    if suspicious_patterns:
        recommendations.extend([f"Investigate: {pattern}" for pattern in suspicious_patterns])
    
    risk_score = risk.get("overall_risk_score", 0)
    if risk_score > 70:
        recommendations.append("Critical: High-risk activity correlations - conduct immediate threat hunt")
    elif risk_score > 40:
        recommendations.append("Warning: Moderate-risk correlations - consider deeper analysis")
    
    # Entity interaction recommendations
    interactions = analysis.get("entity_interactions", {})
    unique_entities = interactions.get("total_unique_entities", 0)
    
    if unique_entities > 25:
        recommendations.append("Review access controls - entity may have excessive interaction scope")
    
    # Temporal recommendations
    temporal = analysis.get("temporal_analysis", {})
    clusters = temporal.get("temporal_clustering", {}).get("clusters_found", 0)
    
    if clusters > 3:
        recommendations.append("Analyze temporal clusters for automation or coordinated attack patterns")
    
    # Correlation strength recommendations
    correlation = analysis.get("correlation_strength", {})
    strength_score = correlation.get("strength_score", 0)
    
    if strength_score > 80:
        recommendations.append("Strong correlations detected - validate for legitimate business processes")
    
    if not recommendations:
        recommendations.append("Activity correlations appear normal - continue standard monitoring")
    
    return recommendations


def _format_timestamp(timestamp: str) -> str:
    """Format timestamp for display"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, AttributeError):
        return timestamp
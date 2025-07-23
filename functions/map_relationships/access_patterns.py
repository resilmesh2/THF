"""
Analyze access patterns and behaviors between entities
"""
from typing import Dict, Any, List, Optional
import structlog
from datetime import datetime
from collections import defaultdict, Counter

logger = structlog.get_logger()


async def execute(opensearch_client, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze access patterns and behaviors between entities
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including source_type, source_id, target_type, timeframe
        
    Returns:
        Access patterns analysis with behavioral insights
    """
    try:
        # Extract parameters
        source_type = params.get("source_type")
        source_id = params.get("source_id")
        target_type = params.get("target_type")
        timeframe = params.get("timeframe", "24h")
        
        logger.info("Executing access patterns analysis", 
                   source_type=source_type,
                   source_id=source_id,
                   target_type=target_type,
                   timeframe=timeframe)
        
        # Build time range filter
        time_filter = opensearch_client.build_time_range_filter(timeframe)
        
        # Build the search query focused on access events
        query = _build_access_patterns_query(source_type, source_id, target_type, time_filter)
        
        # Execute search
        response = await opensearch_client.search(
            index=opensearch_client.alerts_index,
            query=query
        )
        
        # Process results
        hits = response.get("hits", {})
        total_alerts = hits.get("total", {}).get("value", 0) if isinstance(hits.get("total"), dict) else hits.get("total", 0)
        events = hits.get("hits", [])
        
        logger.info("Retrieved events for access patterns analysis", count=len(events), total=total_alerts)
        
        # Process access patterns
        access_events = []
        pattern_summary = {
            "source_entity": {"type": source_type, "id": source_id},
            "total_access_events": len(events),
            "timeframe": timeframe,
            "unique_access_targets": set(),
            "access_methods": set(),
            "time_periods": defaultdict(int)
        }
        
        for hit in events:
            source = hit.get("_source", {})
            access_data = _extract_access_data(source, source_type, source_id, target_type)
            if access_data:
                access_events.append(access_data)
                pattern_summary["unique_access_targets"].add(access_data["target"])
                pattern_summary["access_methods"].add(access_data["access_method"])
                
                # Categorize by time period
                hour = datetime.fromisoformat(access_data["timestamp"].replace('Z', '+00:00')).hour
                if 6 <= hour < 12:
                    pattern_summary["time_periods"]["morning"] += 1
                elif 12 <= hour < 18:
                    pattern_summary["time_periods"]["afternoon"] += 1
                elif 18 <= hour < 22:
                    pattern_summary["time_periods"]["evening"] += 1
                else:
                    pattern_summary["time_periods"]["night"] += 1
        
        # Convert sets to lists for JSON serialization
        pattern_summary["unique_access_targets"] = list(pattern_summary["unique_access_targets"])
        pattern_summary["access_methods"] = list(pattern_summary["access_methods"])
        pattern_summary["unique_target_count"] = len(pattern_summary["unique_access_targets"])
        pattern_summary["time_periods"] = dict(pattern_summary["time_periods"])
        
        # Analyze access patterns
        patterns_analysis = await _analyze_access_patterns(access_events, source_type)
        
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
            "patterns_analysis": patterns_analysis,
            "behavioral_insights": _generate_behavioral_insights(access_events, patterns_analysis),
            "recommendations": _generate_access_recommendations(patterns_analysis)
        }
        
        logger.info("Access patterns analysis completed", 
                   total_events=len(access_events),
                   unique_targets=len(pattern_summary["unique_access_targets"]))
        
        return result
        
    except Exception as e:
        logger.error("Access patterns analysis failed", error=str(e))
        raise Exception(f"Failed to analyze access patterns: {str(e)}")


def _build_access_patterns_query(source_type: str, source_id: str, target_type: Optional[str], time_filter: Dict[str, Any]) -> Dict[str, Any]:
    """Build search query focused on access-related events"""
    
    query = {
        "query": {
            "bool": {
                "must": [time_filter],
                "should": [
                    # Authentication events
                    {"terms": {"rule.groups": ["authentication", "pam", "ssh", "login"]}},
                    # File access events
                    {"terms": {"rule.groups": ["syscheck", "file_integrity", "audit"]}},
                    # Process execution events
                    {"bool": {"must": [
                        {"terms": {"rule.groups": ["audit", "process"]}},
                        {"exists": {"field": "data.win.eventdata.commandLine"}}
                    ]}},
                    # Network access events
                    {"bool": {"must": [
                        {"exists": {"field": "data.srcip"}},
                        {"range": {"rule.level": {"gte": 3}}}
                    ]}},
                    # Windows logon events
                    {"bool": {"must": [
                        {"exists": {"field": "data.win.eventdata.targetUserName"}},
                        {"terms": {"rule.groups": ["windows", "logon"]}}
                    ]}}
                ],
                "minimum_should_match": 1
            }
        },
        "sort": [{"@timestamp": {"order": "asc"}}],
        "size": 1000,
        "_source": [
            "@timestamp", "rule.description", "rule.level", "rule.id",
            "agent.name", "agent.id", "agent.ip",
            "data.srcip", "data.dstip", "data.srcuser", "data.dstuser",
            "data.command", "data.process", "data.protocol"
            "data.win.eventdata.commandLine", "data.win.eventdata.image",
            "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName",
            "data.win.eventdata.targetFilename", "data.win.eventdata.logonType",
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


def _extract_access_data(source: Dict[str, Any], source_type: str, source_id: str, target_type: Optional[str]) -> Optional[Dict[str, Any]]:
    """Extract access-specific data from event source"""
    
    timestamp = source.get("@timestamp", "")
    agent_name = source.get("agent", {}).get("name", "")
    
    # Extract relevant data fields
    data = source.get("data", {})
    win_eventdata = data.get("win", {}).get("eventdata", {})
    rule_groups = source.get("rule", {}).get("groups", [])
    
    # Determine access method and target
    access_method = "unknown"
    target = "unknown"
    access_details = {}
    
    # Authentication access
    if any(group in rule_groups for group in ["authentication", "pam", "ssh", "login"]):
        access_method = "authentication"
        target = agent_name or data.get("dstip", "")
        access_details = {
            "logon_type": win_eventdata.get("logonType", ""),
            "source_ip": data.get("srcip", ""),
            "protocol": data.get("protocol", "")
        }
    
    # File access
    elif any(group in rule_groups for group in ["syscheck", "file_integrity", "audit"]):
        access_method = "file_access"
        target = data.get("path") or win_eventdata.get("targetFilename", "")
        access_details = {
            "operation": "file_modification" if "syscheck" in rule_groups else "file_audit",
            "user": data.get("srcuser") or win_eventdata.get("targetUserName", "")
        }
    
    # Process execution access
    elif "process" in rule_groups or win_eventdata.get("commandLine"):
        access_method = "process_execution"
        target = data.get("process") or win_eventdata.get("image", "")
        access_details = {
            "command_line": win_eventdata.get("commandLine", ""),
            "user": win_eventdata.get("targetUserName", data.get("srcuser", ""))
        }
    
    # Network access
    elif data.get("srcip") or data.get("dstip"):
        access_method = "network_access"
        target = data.get("dstip") or data.get("srcip", "")
        access_details = {
            "protocol": data.get("protocol", ""),
            "source_ip": data.get("srcip", ""),
            "destination_ip": data.get("dstip", "")
        }
    
    # Skip if no meaningful access found
    if target in ["unknown", ""]:
        return None
    
    return {
        "timestamp": timestamp,
        "formatted_time": _format_timestamp(timestamp),
        "access_method": access_method,
        "target": target,
        "access_details": access_details,
        "rule_info": {
            "id": source.get("rule", {}).get("id", ""),
            "description": source.get("rule", {}).get("description", ""),
            "level": source.get("rule", {}).get("level", 0)
        },
        "agent": {"name": agent_name, "ip": source.get("agent", {}).get("ip", "")}
    }


async def _analyze_access_patterns(access_events: List[Dict[str, Any]], source_type: str) -> Dict[str, Any]:
    """Analyze access patterns for behavioral insights"""
    
    if not access_events:
        return {"message": "No access events found for analysis"}
    
    analysis = {
        "temporal_patterns": {},
        "frequency_analysis": {},
        "access_diversity": {},
        "anomaly_detection": {},
        "behavioral_baseline": {}
    }
    
    # Temporal patterns analysis
    hourly_distribution = defaultdict(int)
    daily_pattern = defaultdict(int)
    
    for event in access_events:
        try:
            dt = datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00'))
            hourly_distribution[dt.hour] += 1
            daily_pattern[dt.strftime("%A")] += 1
        except (ValueError, AttributeError):
            continue
    
    analysis["temporal_patterns"] = {
        "hourly_distribution": dict(hourly_distribution),
        "daily_pattern": dict(daily_pattern),
        "peak_hour": max(hourly_distribution.items(), key=lambda x: x[1]) if hourly_distribution else (0, 0),
        "peak_day": max(daily_pattern.items(), key=lambda x: x[1]) if daily_pattern else ("", 0)
    }
    
    # Frequency analysis
    access_method_counts = Counter([event["access_method"] for event in access_events])
    target_counts = Counter([event["target"] for event in access_events])
    
    analysis["frequency_analysis"] = {
        "most_common_access_method": access_method_counts.most_common(1)[0] if access_method_counts else ("none", 0),
        "access_method_distribution": dict(access_method_counts),
        "most_accessed_target": target_counts.most_common(1)[0] if target_counts else ("none", 0),
        "access_frequency_per_target": dict(target_counts.most_common(10))
    }
    
    # Access diversity
    unique_targets = len(set([event["target"] for event in access_events]))
    unique_methods = len(set([event["access_method"] for event in access_events]))
    
    analysis["access_diversity"] = {
        "unique_targets": unique_targets,
        "unique_access_methods": unique_methods,
        "diversity_ratio": unique_targets / len(access_events) if access_events else 0,
        "method_diversity": unique_methods
    }
    
    # Anomaly detection
    anomalies = []
    
    # Check for unusual time patterns
    night_access = hourly_distribution.get(0, 0) + hourly_distribution.get(1, 0) + hourly_distribution.get(2, 0) + hourly_distribution.get(3, 0)
    total_access = sum(hourly_distribution.values())
    if night_access > 0.2 * total_access:
        anomalies.append("High night-time access activity detected")
    
    # Check for high diversity (potential lateral movement)
    if unique_targets > 50:
        anomalies.append("Extremely high target diversity - possible automated scanning or lateral movement")
    elif unique_targets > 20:
        anomalies.append("High target diversity detected - investigate for potential lateral movement")
    
    # Check for repeated failed access attempts
    high_severity_events = [e for e in access_events if e["rule_info"]["level"] >= 7]
    failed_access_ratio = len(high_severity_events) / len(access_events) if access_events else 0
    if failed_access_ratio > 0.3:
        anomalies.append("High ratio of failed access attempts - potential brute force or unauthorized access")
    
    analysis["anomaly_detection"] = {
        "anomalies_found": len(anomalies),
        "anomalies": anomalies,
        "night_access_percentage": (night_access / total_access * 100) if total_access else 0,
        "failed_access_ratio": failed_access_ratio * 100
    }
    
    # Behavioral baseline
    analysis["behavioral_baseline"] = {
        "average_access_per_hour": total_access / 24 if total_access else 0,
        "primary_access_method": access_method_counts.most_common(1)[0][0] if access_method_counts else "none",
        "access_consistency": _calculate_access_consistency(hourly_distribution),
        "risk_score": _calculate_access_risk_score(access_events, anomalies)
    }
    
    return analysis


def _calculate_access_consistency(hourly_distribution: Dict[int, int]) -> float:
    """Calculate consistency of access patterns (lower values = more consistent)"""
    if not hourly_distribution:
        return 0.0
    
    values = list(hourly_distribution.values())
    mean_val = sum(values) / len(values)
    variance = sum((x - mean_val) ** 2 for x in values) / len(values)
    
    # Normalize to 0-1 scale (0 = perfectly consistent, 1 = highly variable)
    return min(1.0, variance / (mean_val + 1))


def _calculate_access_risk_score(access_events: List[Dict[str, Any]], anomalies: List[str]) -> float:
    """Calculate overall risk score for access patterns"""
    if not access_events:
        return 0.0
    
    risk_score = 0.0
    
    # Base risk from anomalies
    risk_score += len(anomalies) * 15
    
    # Risk from high-severity events
    high_severity_count = len([e for e in access_events if e["rule_info"]["level"] >= 8])
    risk_score += (high_severity_count / len(access_events)) * 30
    
    # Risk from access diversity
    unique_targets = len(set([event["target"] for event in access_events]))
    if unique_targets > 30:
        risk_score += 20
    elif unique_targets > 10:
        risk_score += 10
    
    return min(100.0, risk_score)


def _generate_behavioral_insights(access_events: List[Dict[str, Any]], analysis: Dict[str, Any]) -> List[str]:
    """Generate behavioral insights from access patterns"""
    insights = []
    
    if not access_events:
        return ["No access events available for behavioral analysis"]
    
    # Temporal insights
    temporal = analysis.get("temporal_patterns", {})
    peak_hour = temporal.get("peak_hour", (0, 0))
    if peak_hour[1] > 0:
        insights.append(f"Peak access activity occurs at {peak_hour[0]:02d}:00 with {peak_hour[1]} events")
    
    # Frequency insights
    frequency = analysis.get("frequency_analysis", {})
    common_method = frequency.get("most_common_access_method", ("", 0))
    if common_method[1] > 0:
        insights.append(f"Primary access method: {common_method[0]} ({common_method[1]} occurrences)")
    
    # Diversity insights
    diversity = analysis.get("access_diversity", {})
    diversity_ratio = diversity.get("diversity_ratio", 0)
    if diversity_ratio > 0.8:
        insights.append("High access diversity - entity accesses many different targets")
    elif diversity_ratio < 0.2:
        insights.append("Low access diversity - entity focuses on specific targets")
    
    # Risk insights
    baseline = analysis.get("behavioral_baseline", {})
    risk_score = baseline.get("risk_score", 0)
    if risk_score > 70:
        insights.append("High-risk access behavior detected - immediate attention required")
    elif risk_score > 40:
        insights.append("Moderate-risk access behavior - monitoring recommended")
    else:
        insights.append("Access behavior appears normal")
    
    return insights


def _generate_access_recommendations(analysis: Dict[str, Any]) -> List[str]:
    """Generate recommendations based on access patterns analysis"""
    recommendations = []
    
    anomalies = analysis.get("anomaly_detection", {}).get("anomalies", [])
    risk_score = analysis.get("behavioral_baseline", {}).get("risk_score", 0)
    
    # Anomaly-based recommendations
    if anomalies:
        recommendations.extend([f"Investigate: {anomaly}" for anomaly in anomalies])
    
    # Risk-based recommendations
    if risk_score > 70:
        recommendations.append("Critical: High-risk access patterns detected - conduct immediate security review")
    elif risk_score > 40:
        recommendations.append("Warning: Moderate-risk access patterns - consider additional monitoring")
    
    # Specific pattern recommendations
    diversity = analysis.get("access_diversity", {})
    if diversity.get("unique_targets", 0) > 50:
        recommendations.append("Review access permissions - entity may have excessive privileges")
    
    night_access_pct = analysis.get("anomaly_detection", {}).get("night_access_percentage", 0)
    if night_access_pct > 20:
        recommendations.append("Monitor night-time access activity - unusual for typical business hours")
    
    if not recommendations:
        recommendations.append("Access patterns appear normal - continue standard monitoring")
    
    return recommendations


def _format_timestamp(timestamp: str) -> str:
    """Format timestamp for display"""
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, AttributeError):
        return timestamp
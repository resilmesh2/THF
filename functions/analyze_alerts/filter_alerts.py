"""
Filter alerts by specific criteria
"""
from typing import Dict, Any
import structlog
from .._shared.opensearch_client import WazuhOpenSearchClient, normalize_wazuh_array_fields

logger = structlog.get_logger()

def get_field_mapping() -> Dict[str, str]:
    """Get field mapping for user-friendly field names"""
    return {
        "severity": "rule.level",
        "host": "agent.name",
        "hosts": "agent.name",
        "rule": "rule.id",
        "rules": "rule.id",
        "rule_id": "rule.id",
        "rule_description": "rule.description",
        "user": "data.win.eventdata.user",
        "users": "data.win.eventdata.user",
        "target_user": "data.win.eventdata.targetUserName",
        "time": "@timestamp",
        "temporal": "@timestamp",
        "rule_groups": "rule.groups",
        "groups": "rule.groups",
        "rule_group": "rule.groups",
        "geographic": "agent.ip",
        "geo": "agent.ip",
        "location": "agent.ip",
        "locations": "agent.ip",
        "ip": "agent.ip",
        "process": "data.win.eventdata.originalFileName",
        "processes": "data.win.eventdata.originalFileName",
        "process_name": "data.win.eventdata.originalFileName",
        "command": "data.win.eventdata.commandLine",
        "command_line": "data.win.eventdata.commandLine",
        "parent_command": "data.win.eventdata.parentCommandLine",
        "parent_command_line": "data.win.eventdata.parentCommandLine",
        "image": "data.win.eventdata.image",
        "process_image": "data.win.eventdata.image",
        "executable": "data.win.eventdata.image",
        "process_id": "data.win.eventdata.processId",
        "pid": "data.win.eventdata.processId",
        "parent_process_id": "data.win.eventdata.parentProcessId",
        "parent_pid": "data.win.eventdata.parentProcessId",
        "parent_image": "data.win.eventdata.parentImage",
        "parent_user": "data.win.eventdata.parentUser",
        "integrity_level": "data.win.eventdata.integrityLevel",
        "logon_id": "data.win.eventdata.logonId",
        "current_directory": "data.win.eventdata.currentDirectory",
        "hashes": "data.win.eventdata.hashes"
    }

async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter alerts by specific criteria and return matching results
    
    Args:
        opensearch_client: OpenSearch client instance
        params: Parameters including filters, time_range, limit
        
    Returns:
        Filtered alerts with details and metadata
    """
    try:
        # Extract parameters
        time_range = params.get("time_range", "7d")
        filters = params.get("filters", {})
        limit = params.get("limit", 50)
        
        # Handle case where filters is None
        if filters is None:
            filters = {}
        
        # Handle separate time_start and time_end parameters from LLM
        time_start = filters.pop("time_start", None)
        time_end = filters.pop("time_end", None)
        
        # If we have separate start/end times, construct a time range
        if time_start and time_end:
            from datetime import date
            today = date.today().strftime("%Y-%m-%d")
            time_range = f"{time_start} until {time_end}"
            logger.info("Converting separate time parameters to range", 
                       time_start=time_start, time_end=time_end, time_range=time_range)
        
        # Handle time_range in filters (LLM sometimes puts it there instead of main params)
        filter_time_range = filters.pop("time_range", None)
        if filter_time_range:
            time_range = filter_time_range
            logger.info("Using time_range from filters", time_range=time_range)

        # Apply field mapping to convert user-friendly names to Wazuh field names
        field_mapping = get_field_mapping()
        mapped_filters = {}
        for key, value in filters.items():
            mapped_key = field_mapping.get(key, key)  # Use mapping if available, otherwise keep original
            mapped_filters[mapped_key] = value
        filters = mapped_filters

        # Convert string values to arrays for known Wazuh array fields
        filters = normalize_wazuh_array_fields(filters)

        logger.info("Filtering alerts",
                   time_range=time_range,
                   filters=filters,
                   limit=limit)
        
        # Build base query
        query = {
            "query": {
                "bool": {
                    "must": [
                        opensearch_client.build_time_range_filter(time_range)
                    ]
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ],
            "aggs": {
                "total_count": {
                    "value_count": {
                        "field": "_id"
                    }
                },
                "severity_summary": {
                    "terms": {
                        "field": "rule.level",
                        "size": 10,
                        "order": {"_key": "desc"}
                    }
                },
                "rule_summary": {
                    "terms": {
                        "field": "rule.id",
                        "size": 10,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "rule_details": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["rule.description", "rule.level", "rule.groups"]
                            }
                        }
                    }
                },
                "host_summary": {
                    "terms": {
                        "field": "agent.name",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                },
                "time_distribution": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "interval": "1h",
                        "format": "yyyy-MM-dd HH:mm"
                    }
                }
            }
        }
        
        # Add filters if provided
        if filters:
            filter_queries = opensearch_client.build_filters_query(filters)
            query["query"]["bool"]["must"].extend(filter_queries)
        
        # Execute query
        response = await opensearch_client.search(
            opensearch_client.alerts_index, 
            query, 
            size=limit
        )
        
        # Format results
        total_alerts = response["aggregations"]["total_count"]["value"]
        
        # Process filtered alerts
        filtered_alerts = []
        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            # Extract Windows event data for detailed process information
            win_eventdata = source.get("data", {}).get("win", {}).get("eventdata", {})

            alert = {
                "alert_id": hit["_id"],
                "timestamp": source.get("@timestamp", ""),
                "rule_id": source.get("rule", {}).get("id", ""),
                "rule_description": source.get("rule", {}).get("description", ""),
                "rule_level": source.get("rule", {}).get("level", 0),
                "rule_groups": source.get("rule", {}).get("groups", []),
                "agent_name": source.get("agent", {}).get("name", ""),
                "agent_ip": source.get("agent", {}).get("ip", ""),
                "source_ip": source.get("data", {}).get("srcip", ""),
                "source_user": source.get("data", {}).get("srcuser", ""),
                "destination_ip": source.get("data", {}).get("dstip", ""),
                # Process information with comprehensive Windows eventdata extraction
                "process_name": win_eventdata.get("originalFileName", win_eventdata.get("processName", "")),
                "process_image": win_eventdata.get("image", ""),
                "command_line": win_eventdata.get("commandLine", ""),
                "parent_command_line": win_eventdata.get("parentCommandLine", ""),
                "process_id": win_eventdata.get("processId", ""),
                "parent_process_id": win_eventdata.get("parentProcessId", ""),
                "parent_image": win_eventdata.get("parentImage", ""),
                "user": win_eventdata.get("user", ""),
                "parent_user": win_eventdata.get("parentUser", ""),
                "target_user": win_eventdata.get("targetUserName", ""),
                "target_filename": win_eventdata.get("targetFilename", ""),
                "current_directory": win_eventdata.get("currentDirectory", ""),
                "integrity_level": win_eventdata.get("integrityLevel", ""),
                "logon_id": win_eventdata.get("logonId", ""),
                "hashes": win_eventdata.get("hashes", ""),
                "process_guid": win_eventdata.get("processGuid", ""),
                "parent_process_guid": win_eventdata.get("parentProcessGuid", ""),
                "utc_time": win_eventdata.get("utcTime", ""),
                "terminal_session_id": win_eventdata.get("terminalSessionId", ""),
                # MITRE ATT&CK information
                "mitre_technique": source.get("rule", {}).get("mitre", {}).get("technique", []),
                "mitre_tactic": source.get("rule", {}).get("mitre", {}).get("tactic", []),
                "mitre_id": source.get("rule", {}).get("mitre", {}).get("id", []),
                "full_log": source.get("full_log", "")[:200] + "..." if len(source.get("full_log", "")) > 200 else source.get("full_log", "")
            }
            filtered_alerts.append(alert)
        
        # Process severity summary
        severity_summary = {}
        for bucket in response["aggregations"]["severity_summary"]["buckets"]:
            level = bucket["key"]
            severity_summary[str(level)] = {
                "count": bucket["doc_count"],
                "severity_name": get_severity_name(level)
            }
        
        # Process rule summary
        rule_summary = []
        for bucket in response["aggregations"]["rule_summary"]["buckets"]:
            rule_data = {
                "rule_id": bucket["key"],
                "count": bucket["doc_count"]
            }
            
            # Get rule details
            if bucket["rule_details"]["hits"]["hits"]:
                rule_source = bucket["rule_details"]["hits"]["hits"][0]["_source"]
                rule_data["description"] = rule_source.get("rule", {}).get("description", "")
                rule_data["level"] = rule_source.get("rule", {}).get("level", 0)
                rule_data["groups"] = rule_source.get("rule", {}).get("groups", [])
            
            rule_summary.append(rule_data)
        
        # Process host summary
        host_summary = []
        for bucket in response["aggregations"]["host_summary"]["buckets"]:
            host_summary.append({
                "host_name": bucket["key"],
                "count": bucket["doc_count"]
            })
        
        # Process time distribution
        time_distribution = []
        for bucket in response["aggregations"]["time_distribution"]["buckets"]:
            time_distribution.append({
                "timestamp": bucket["key_as_string"],
                "count": bucket["doc_count"]
            })
        
        result = {
            "total_matching_alerts": total_alerts,
            "returned_alerts": len(filtered_alerts),
            "time_range": time_range,
            "filters_applied": filters,
            "filtered_alerts": filtered_alerts,
            "severity_summary": severity_summary,
            "rule_summary": rule_summary,
            "host_summary": host_summary,
            "time_distribution": time_distribution,
            "query_info": {
                "limit": limit,
                "filters_count": len(filters) if filters else 0
            }
        }
        
        logger.info("Alert filtering completed", 
                   total_matching=total_alerts,
                   returned=len(filtered_alerts),
                   time_range=time_range)
        
        return result
        
    except Exception as e:
        logger.error("Alert filtering failed", 
                    error=str(e), 
                    params=params)
        raise Exception(f"Failed to filter alerts: {str(e)}")

def get_severity_name(level: int) -> str:
    """
    Convert Wazuh alert level to severity name
    
    Args:
        level: Alert level number
        
    Returns:
        Severity name string
    """
    if level >= 12:
        return "Critical"
    elif level >= 8:
        return "High"
    elif level >= 5:
        return "Medium"
    elif level >= 3:
        return "Low"
    else:
        return "Informational"
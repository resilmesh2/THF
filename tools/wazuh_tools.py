"""
LangChain tools for Wazuh SIEM functions
"""
from langchain.tools import BaseTool
from langchain.callbacks.manager import AsyncCallbackManagerForToolRun
from typing import Type
import structlog
from schemas.wazuh_schemas import *

logger = structlog.get_logger()


class WazuhBaseTool(BaseTool):
    """Base class for all Wazuh tools"""
    
    def __init__(self, opensearch_client):
        super().__init__()
        # Store opensearch_client as a private attribute to avoid Pydantic validation
        self._opensearch_client = opensearch_client
    
    @property
    def opensearch_client(self):
        """Get the OpenSearch client"""
        return self._opensearch_client


class AnalyzeAlertsTool(WazuhBaseTool):
    """Tool for analyzing Wazuh alerts"""
    name: str = "analyze_alerts"
    description: str = "Analyze and aggregate alerts for statistical analysis, trends, rankings, and distributions. Actions: 'ranking' (rank by frequency), 'counting' (count alerts with breakdowns), 'filtering' (filter by criteria), 'distribution' (analyze patterns)."
    args_schema: Type[AnalyzeAlertsSchema] = AnalyzeAlertsSchema
    
    def _run(
        self,
        action: str,
        group_by: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        time_range: str = "7d",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for alert analysis"""
        import asyncio
        return asyncio.run(self._arun(action, group_by, filters, limit, time_range, run_manager))

    async def _arun(
        self,
        action: str,
        group_by: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 10,
        time_range: str = "7d",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute alert analysis"""
        try:
            # Route to specific sub-function
            if action == "ranking":
                from functions.analyze_alerts.rank_alerts import execute
            elif action == "counting":
                from functions.analyze_alerts.count_alerts import execute
            elif action == "filtering":
                from functions.analyze_alerts.filter_alerts import execute
            elif action == "distribution":
                from functions.analyze_alerts.distribution_alerts import execute
            else:
                raise ValueError(f"Unknown action: {action}")
            
            params = {
                "group_by": group_by,
                "filters": filters,
                "limit": limit,
                "time_range": time_range
            }
            
            result = await execute(self.opensearch_client, params)
            
            logger.info("Alert analysis completed", 
                       action=action, 
                       results_count=result.get("total_alerts", 0))
            
            return result
            
        except Exception as e:
            logger.error("Alert analysis failed", action=action, error=str(e))
            raise Exception(f"Alert analysis failed: {str(e)}")


class InvestigateEntityTool(WazuhBaseTool):
    """Tool for investigating specific entities"""
    name: str = "investigate_entity"
    description: str = "Get alerts, activity, status, or details for a specific entity (host, user, process, file, ip). Use this when querying about a specifically identified entity."
    args_schema: Type[InvestigateEntitySchema] = InvestigateEntitySchema
    
    def _run(
        self,
        entity_type: str,
        entity_id: str,
        query_type: str,
        time_range: str = "24h",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for entity investigation"""
        import asyncio
        return asyncio.run(self._arun(entity_type, entity_id, query_type, time_range, run_manager))

    async def _arun(
        self,
        entity_type: str,
        entity_id: str,
        query_type: str,
        time_range: str = "24h",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute entity investigation"""
        try:
            # Route to specific sub-function based on query_type
            # Handle both string and enum values
            query_value = query_type.value if hasattr(query_type, 'value') else query_type
            
            if query_value == "alerts":
                from functions.investigate_entity.get_alerts_for_entity import execute
            elif query_value == "details":
                from functions.investigate_entity.get_entity_details import execute
            elif query_value == "activity":
                from functions.investigate_entity.get_entity_activity import execute
            elif query_value == "status":
                from functions.investigate_entity.get_entity_status import execute
            else:
                raise ValueError(f"Unknown query_type: {query_value}. Supported types: alerts, details, activity, status")
            
            params = {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "time_range": time_range
            }
            
            result = await execute(self.opensearch_client, params)
            
            logger.info("Entity investigation completed",
                        entity_type=entity_type,
                        entity_id=entity_id,
                        query_type=query_type,
                        total_alerts=result.get("total_alerts", 0))
            
            return result
            
        except Exception as e:
            logger.error("Entity investigation failed",
                         entity_type=entity_type,
                         entity_id=entity_id,
                         error=str(e))
            raise Exception(f"Entity investigation failed: {str(e)}")


class MapRelationshipsTool(WazuhBaseTool):
    """Tool for mapping relationships between entities"""
    name: str = "map_relationships"
    description: str = "Explore relationships between users, hosts, files, alerts, or other entities"
    args_schema: Type[MapRelationshipsSchema] = MapRelationshipsSchema
    
    def _run(
        self,
        source_type: str,
        source_id: str,
        relationship_type: str,
        target_type: Optional[str] = None,
        timeframe: str = "24h",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for relationship mapping"""
        import asyncio
        return asyncio.run(self._arun(source_type, source_id, relationship_type, target_type, timeframe, run_manager))

    async def _arun(
        self,
        source_type: str,
        source_id: str,
        relationship_type: str,
        target_type: Optional[str] = None,
        timeframe: str = "24h",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute relationship mapping"""
        try:
            # For now, return a placeholder response
            # TODO: Implement actual relationship mapping functions
            result = {
                "source_type": source_type,
                "source_id": source_id,
                "relationship_type": relationship_type,
                "target_type": target_type,
                "timeframe": timeframe,
                "message": "Relationship mapping not yet implemented",
                "relationships": []
            }
            
            logger.info("Relationship mapping completed",
                        source_type=source_type,
                        source_id=source_id,
                        relationship_type=relationship_type)
            
            return result
            
        except Exception as e:
            logger.error("Relationship mapping failed",
                         source_type=source_type,
                         source_id=source_id,
                         error=str(e))
            raise Exception(f"Relationship mapping failed: {str(e)}")


class DetectThreatsTool(WazuhBaseTool):
    """Tool for detecting threats and MITRE ATT&CK techniques"""
    name: str = "detect_threats"
    description: str = "Identify MITRE ATT&CK tactics, techniques, threat actors, indicator of compromises or activity patterns"
    args_schema: Type[DetectThreatsSchema] = DetectThreatsSchema
    
    def _run(
        self,
        threat_type: str,
        technique_id: Optional[str] = None,
        tactic_name: Optional[str] = None,
        actor_name: Optional[str] = None,
        timeframe: str = "7d",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for threat detection"""
        import asyncio
        return asyncio.run(self._arun(threat_type, technique_id, tactic_name, actor_name, timeframe, run_manager))

    async def _arun(
        self,
        threat_type: str,
        technique_id: Optional[str] = None,
        tactic_name: Optional[str] = None,
        actor_name: Optional[str] = None,
        timeframe: str = "7d",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute threat detection"""
        try:
            # Handle both string and enum values
            threat_value = threat_type.value if hasattr(threat_type, 'value') else threat_type
            
            # Normalize to lowercase for case-insensitive matching
            threat_value_lower = threat_value.lower()
            
            # Route to specific sub-function based on threat_type
            if threat_value_lower == "technique":
                from functions.detect_threats.find_technique import execute
            elif threat_value_lower == "tactic":
                from functions.detect_threats.find_tactic import execute
            elif threat_value_lower in ["threat_actor", "actor"]:
                from functions.detect_threats.find_threat_actor import execute
            elif threat_value_lower in ["indicators", "iocs", "indicators of compromise"]:
                from functions.detect_threats.find_indicators import execute
            elif threat_value_lower == "chains":
                from functions.detect_threats.find_chains import execute
            else:
                raise ValueError(f"Unknown threat_type: {threat_value}. Supported types: technique, tactic, threat_actor/actor, indicators/ioc, chains")
            
            # Build parameters
            params = {
                "technique_id": technique_id,
                "tactic_name": tactic_name,
                "actor_name": actor_name,
                "timeframe": timeframe
            }
            
            # Execute the detection
            result = await execute(self.opensearch_client, params)
            
            logger.info("Threat detection completed",
                        threat_type=threat_value,
                        total_results=result.get("total_alerts", 0))
            
            return result
            
        except Exception as e:
            logger.error("Threat detection failed",
                         threat_type=threat_type,
                         error=str(e))
            raise Exception(f"Threat detection failed: {str(e)}")


class FindAnomaliesTool(WazuhBaseTool):
    """Tool for finding anomalies in security data using various detection methods"""
    name: str = "find_anomalies"
    description: str = "Detect security anomalies using different analysis types: 'threshold' (entities exceeding limits), 'pattern' (unusual temporal/behavioral patterns), 'behavioral' (deviations from historical baselines), 'trend' (increasing/decreasing patterns over time)"
    args_schema: Type[FindAnomaliesSchema] = FindAnomaliesSchema
    
    def _run(
        self,
        anomaly_type: str,
        metric: Optional[str] = None,
        timeframe: str = "24h",
        threshold: Optional[float] = None,
        baseline: Optional[str] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for anomaly detection"""
        import asyncio
        return asyncio.run(self._arun(anomaly_type, metric, timeframe, threshold, baseline, run_manager))

    async def _arun(
        self,
        anomaly_type: str,
        metric: Optional[str] = None,
        timeframe: str = "24h",
        threshold: Optional[float] = None,
        baseline: Optional[str] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute anomaly detection"""
        try:
            # Build parameters for the anomaly detection function
            params = {
                "metric": metric,
                "timeframe": timeframe,
                "threshold": threshold,
                "baseline": baseline
            }
            
            # Remove None values
            params = {k: v for k, v in params.items() if v is not None}
            
            logger.info("Executing anomaly detection", 
                       anomaly_type=anomaly_type,
                       params=params)
            
            # Route to appropriate anomaly detection function based on type
            anomaly_type_lower = anomaly_type.lower()
            
            # Handle common variations and map them to correct types
            if anomaly_type_lower in ["threshold", "thresholds"]:
                from functions.find_anomalies.detect_threshold import execute
                result = await execute(self.opensearch_client, params)
                
            elif anomaly_type_lower in ["pattern", "patterns", "temporal", "time_pattern", "time_patterns"]:
                from functions.find_anomalies.detect_pattern import execute
                result = await execute(self.opensearch_client, params)
                
            elif anomaly_type_lower in ["behavioral", "behaviour", "behavior", "user_behavior", "host_behavior", "baseline", "baseline_comparison"]:
                from functions.find_anomalies.detect_behavioral import execute
                result = await execute(self.opensearch_client, params)
                
            elif anomaly_type_lower in ["trend", "trends", "trending", "time_trend", "temporal_trend"]:
                from functions.find_anomalies.detect_trend import execute
                result = await execute(self.opensearch_client, params)
                
            elif anomaly_type_lower in ["all", "comprehensive"]:
                # For comprehensive analysis, default to behavioral as it provides the most comprehensive view
                logger.info("Comprehensive anomaly request, using behavioral detection", 
                           anomaly_type=anomaly_type)
                from functions.find_anomalies.detect_behavioral import execute
                result = await execute(self.opensearch_client, params)
                
            else:
                # Default to behavioral detection for user-focused queries, threshold for others
                if any(keyword in anomaly_type_lower for keyword in ["user", "host", "entity", "activity"]):
                    logger.info("Mapping user/host/activity query to behavioral detection", 
                               anomaly_type=anomaly_type)
                    from functions.find_anomalies.detect_behavioral import execute
                    result = await execute(self.opensearch_client, params)
                else:
                    logger.warning("Unknown anomaly type, defaulting to threshold", 
                                 anomaly_type=anomaly_type)
                    from functions.find_anomalies.detect_threshold import execute
                    result = await execute(self.opensearch_client, params)
            
            logger.info("Anomaly detection completed", 
                       anomaly_type=anomaly_type,
                       total_anomalies=result.get("summary", {}).get("total_anomalies", result.get("summary", {}).get("total_threshold_anomalies", result.get("summary", {}).get("total_pattern_anomalies", result.get("summary", {}).get("total_behavioral_anomalies", result.get("summary", {}).get("total_trend_anomalies", 0))))))
            
            return result
            
        except Exception as e:
            logger.error("Anomaly detection failed", 
                        anomaly_type=anomaly_type, 
                        error=str(e))
            raise Exception(f"Anomaly detection failed: {str(e)}")


class TraceTimelineTool(WazuhBaseTool):
    """Tool for reconstructing event timelines"""
    name: str = "trace_timeline"
    description: str = "Reconstruct chronological view of events for entities or incidents"
    args_schema: Type[TraceTimelineSchema] = TraceTimelineSchema
    
    def _run(
        self,
        start_time: str,
        end_time: str,
        view_type: str,
        entity: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for timeline reconstruction"""
        import asyncio
        return asyncio.run(self._arun(start_time, end_time, view_type, entity, event_types, run_manager))

    async def _arun(
        self,
        start_time: str,
        end_time: str,
        view_type: str,
        entity: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute timeline reconstruction"""
        try:
            # For now, return a placeholder response
            # TODO: Implement actual timeline reconstruction functions
            result = {
                "start_time": start_time,
                "end_time": end_time,
                "view_type": view_type,
                "entity": entity,
                "event_types": event_types,
                "message": "Timeline reconstruction not yet implemented",
                "timeline": []
            }
            
            logger.info("Timeline reconstruction completed", 
                       start_time=start_time,
                       end_time=end_time,
                       view_type=view_type)
            
            return result
            
        except Exception as e:
            logger.error("Timeline reconstruction failed", 
                        start_time=start_time, 
                        end_time=end_time, 
                        error=str(e))
            raise Exception(f"Timeline reconstruction failed: {str(e)}")


class CheckVulnerabilitiesTool(WazuhBaseTool):
    """Tool for checking vulnerabilities using various analysis methods"""
    name: str = "check_vulnerabilities"
    description: str = "Check vulnerabilities using different actions: 'list_by_entity' (list vulnerabilities by host/entity), 'check_cve' (analyze specific CVE references), 'check_patches' (check patch status and Windows updates)"
    args_schema: Type[CheckVulnerabilitiesSchema] = CheckVulnerabilitiesSchema
    
    def _run(
        self,
        action: str,
        entity_filter: Optional[str] = None,
        cve_id: Optional[str] = None,
        severity: Optional[str] = None,
        patch_status: Optional[str] = None,
        timeframe: str = "30d",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for vulnerability checking"""
        import asyncio
        return asyncio.run(self._arun(action, entity_filter, cve_id, severity, patch_status, timeframe, run_manager))

    async def _arun(
        self,
        action: str,
        entity_filter: Optional[str] = None,
        cve_id: Optional[str] = None,
        severity: Optional[str] = None,
        patch_status: Optional[str] = None,
        timeframe: str = "30d",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute vulnerability checking"""
        try:
            # Build parameters for the vulnerability checking function
            params = {
                "entity_filter": entity_filter,
                "cve_id": cve_id,
                "severity": severity,
                "patch_status": patch_status,
                "timeframe": timeframe
            }
            
            # Remove None values
            params = {k: v for k, v in params.items() if v is not None}
            
            logger.info("Executing vulnerability checking", 
                       action=action,
                       params=params)
            
            # Handle both string and enum values
            action_value = action.value if hasattr(action, 'value') else action
            action_lower = action_value.lower()
            
            # Route to appropriate vulnerability checking function based on action
            if action_lower == "list_by_entity":
                from functions.check_vulnerabilities.list_by_entity import execute
                result = await execute(self.opensearch_client, params)
                
            elif action_lower == "check_cve":
                from functions.check_vulnerabilities.check_cve import execute
                result = await execute(self.opensearch_client, params)
                
            elif action_lower == "check_patches":
                from functions.check_vulnerabilities.check_patches import execute
                result = await execute(self.opensearch_client, params)
                
            else:
                # Default to list_by_entity for unknown actions
                logger.warning("Unknown vulnerability action, defaulting to list_by_entity", 
                             action=action)
                from functions.check_vulnerabilities.list_by_entity import execute
                result = await execute(self.opensearch_client, params)
            
            logger.info("Vulnerability checking completed", 
                       action=action,
                       total_results=result.get("total_vulnerability_alerts", result.get("total_cve_alerts", result.get("total_patch_events", 0))))
            
            return result
            
        except Exception as e:
            logger.error("Vulnerability checking failed", 
                        action=action,
                        error=str(e))
            raise Exception(f"Vulnerability checking failed: {str(e)}")


class MonitorAgentsTool(WazuhBaseTool):
    """Tool for monitoring Wazuh agents"""
    name: str = "monitor_agents"
    description: str = "Check agent connectivity, versions, and operational status"
    args_schema: Type[MonitorAgentsSchema] = MonitorAgentsSchema
    
    def _run(
        self,
        agent_id: Optional[str] = None,
        status_filter: Optional[str] = None,
        version_requirements: Optional[str] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for agent monitoring"""
        import asyncio
        return asyncio.run(self._arun(agent_id, status_filter, version_requirements, run_manager))

    async def _arun(
        self,
        agent_id: Optional[str] = None,
        status_filter: Optional[str] = None,
        version_requirements: Optional[str] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> Dict[str, Any]:
        """Execute agent monitoring"""
        try:
            # For now, return a placeholder response
            # TODO: Implement actual agent monitoring functions
            result = {
                "agent_id": agent_id,
                "status_filter": status_filter,
                "version_requirements": version_requirements,
                "message": "Agent monitoring not yet implemented",
                "agents": []
            }
            
            logger.info("Agent monitoring completed")
            
            return result
            
        except Exception as e:
            logger.error("Agent monitoring failed", error=str(e))
            raise Exception(f"Agent monitoring failed: {str(e)}")


def get_all_tools(opensearch_client):
    """
    Get all available Wazuh tools
    
    Args:
        opensearch_client: OpenSearch client instance
        
    Returns:
        List of all tool instances
    """
    return [
        AnalyzeAlertsTool(opensearch_client),
        InvestigateEntityTool(opensearch_client),
        MapRelationshipsTool(opensearch_client),
        DetectThreatsTool(opensearch_client),
        FindAnomaliesTool(opensearch_client),
        TraceTimelineTool(opensearch_client),
        CheckVulnerabilitiesTool(opensearch_client),
        MonitorAgentsTool(opensearch_client)
    ]

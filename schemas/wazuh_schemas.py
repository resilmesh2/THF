"""
Pydantic schemas for Wazuh function parameters
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum


class AlertAction(str, Enum):
    """Actions for alert analysis"""
    RANKING = "ranking"
    FILTERING = "filtering" 
    COUNTING = "counting"
    DISTRIBUTION = "distribution"


class EntityType(str, Enum):
    """Types of entities to investigate"""
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    FILE = "file"
    IP = "ip"


class QueryType(str, Enum):
    """Types of entity queries"""
    ALERTS = "alerts"
    DETAILS = "details"
    ACTIVITY = "activity"
    STATUS = "status"


class ThreatType(str, Enum):
    """Types of threat detection"""
    TECHNIQUE = "technique"
    TACTIC = "tactic"
    THREAT_ACTOR = "threat_actor"
    INDICATORS = "indicators"
    CHAINS = "chains"


class AnomalyType(str, Enum):
    """Types of anomaly detection"""
    THRESHOLD = "threshold"
    PATTERN = "pattern"
    BEHAVIORAL = "behavioral"
    TREND = "trend"


class ViewType(str, Enum):
    """Types of timeline views"""
    SEQUENCE = "sequence"
    PROGRESSION = "progression"
    TEMPORAL = "temporal"


class RelationshipType(str, Enum):
    """Types of relationship mapping"""
    ENTITY_TO_ENTITY = "entity_to_entity"
    ACCESS_PATTERNS = "access_patterns"
    ACTIVITY_CORRELATION = "activity_correlation"


class VulnerabilityAction(str, Enum):
    """Types of vulnerability checking actions"""
    LIST_BY_ENTITY = "list_by_entity"
    CHECK_CVE = "check_cve"
    CHECK_PATCHES = "check_patches"


class AgentMonitorAction(str, Enum):
    """Types of agent monitoring actions"""
    STATUS_CHECK = "status_check"
    VERSION_CHECK = "version_check"
    HEALTH_CHECK = "health_check"


class AnalyzeAlertsSchema(BaseModel):
    """Schema for analyze_alerts function"""
    action: AlertAction = Field(description="Type of analysis to perform")
    group_by: Optional[str] = Field(default=None, description="Field to group results by")
    filters: Optional[Dict[str, Any]] = Field(default=None, description="Filters to apply")
    limit: Optional[int] = Field(default=10, description="Maximum number of results")
    time_range: Optional[str] = Field(default="7d", description="Time range for analysis")


class InvestigateEntitySchema(BaseModel):
    """Schema for investigate_entity function"""
    entity_type: EntityType = Field(description="Type of entity to investigate")
    entity_id: str = Field(description="ID or name of the entity")
    query_type: QueryType = Field(description="Type of information to retrieve")
    time_range: Optional[str] = Field(default="24h", description="Time range for investigation")


class MapRelationshipsSchema(BaseModel):
    """Schema for map_relationships function"""
    source_type: EntityType = Field(description="Type of source entity")
    source_id: str = Field(description="ID of source entity")
    target_type: Optional[EntityType] = Field(default=None, description="Type of target entity")
    relationship_type: RelationshipType = Field(description="Type of relationship to explore")
    timeframe: Optional[str] = Field(default="24h", description="Time frame for relationship mapping")


class DetectThreatsSchema(BaseModel):
    """Schema for detect_threats function"""
    threat_type: ThreatType = Field(description="Type of threat to detect")
    technique_id: Optional[str] = Field(default=None, description="MITRE ATT&CK technique ID")
    tactic_name: Optional[str] = Field(default=None, description="MITRE ATT&CK tactic name")
    actor_name: Optional[str] = Field(default=None, description="Threat actor name")
    timeframe: Optional[str] = Field(default="7d", description="Time frame for threat detection")


class FindAnomaliesSchema(BaseModel):
    """Schema for find_anomalies function"""
    anomaly_type: AnomalyType = Field(description="Type of anomaly detection: 'threshold' (entities exceeding limits), 'pattern' (unusual time/activity patterns), 'behavioral' (deviations from baselines), 'trend' (increasing/decreasing over time), or 'all' for comprehensive analysis")
    metric: Optional[str] = Field(default=None, description="Specific metric to analyze (e.g., 'alert_count', 'severity')")
    timeframe: Optional[str] = Field(default="24h", description="Time frame for anomaly detection (e.g., '24h', '7d')")
    threshold: Optional[float] = Field(default=None, description="Threshold value for anomaly detection")
    baseline: Optional[str] = Field(default=None, description="Baseline period for comparison (e.g., '7d', '30d')")


class TraceTimelineSchema(BaseModel):
    """Schema for trace_timeline function"""
    start_time: str = Field(description="Start time for timeline")
    end_time: str = Field(description="End time for timeline")
    entity: Optional[str] = Field(default=None, description="Entity to focus timeline on")
    view_type: ViewType = Field(description="Type of timeline view")
    event_types: Optional[List[str]] = Field(default=None, description="Types of events to include")


class CheckVulnerabilitiesSchema(BaseModel):
    """Schema for check_vulnerabilities function"""
    action: VulnerabilityAction = Field(description="Type of vulnerability check to perform: 'list_by_entity', 'check_cve', or 'check_patches'")
    entity_filter: Optional[str] = Field(default=None, description="Filter by entity name or pattern")
    cve_id: Optional[str] = Field(default=None, description="Specific CVE ID to check (for check_cve action)")
    severity: Optional[str] = Field(default=None, description="Vulnerability severity level (low, medium, high, critical)")
    patch_status: Optional[str] = Field(default=None, description="Patch status filter (installed, missing, failed)")
    timeframe: Optional[str] = Field(default="30d", description="Time frame for vulnerability analysis (e.g., '30d', '7d')")


class MonitorAgentsSchema(BaseModel):
    """Schema for monitor_agents function"""
    action: AgentMonitorAction = Field(description="Type of agent monitoring to perform: 'status_check', 'version_check', or 'health_check'")
    agent_id: Optional[str] = Field(default=None, description="Specific agent ID, name, or IP address")
    status_filter: Optional[str] = Field(default=None, description="Filter by agent status (active, inactive, disconnected)")
    version_requirements: Optional[str] = Field(default=None, description="Version requirements (e.g., '>=4.5.0')")
    timeframe: Optional[str] = Field(default="24h", description="Time frame for analysis (e.g., '24h', '7d')")
    health_threshold: Optional[float] = Field(default=70.0, description="Health score threshold for health_check action")

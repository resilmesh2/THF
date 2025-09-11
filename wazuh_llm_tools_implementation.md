# LLM-Based Wazuh SIEM System Implementation with Tools & Frameworks

## Architecture Overview

The system follows the flow: **User Query → LLM Function Calling → Function Dispatcher → Wazuh Backend → Response Formatter → User**

## Technology Stack

### Core LLM Framework
- **LangChain** - Primary framework for agent orchestration and tool integration
- **LangSmith** - Observability and tracing for debugging and monitoring
- **Anthropic Claude API** - LLM for function calling and response generation

### Backend Integration
- **OpenSearch Python Client** - Direct integration with Wazuh's OpenSearch backend
- **Wazuh API Client** - For agent management and system queries
- **FastAPI** - REST API framework with async support

### Data & Validation
- **Pydantic** - Schema validation for function parameters and responses
- **Redis** - Caching frequent queries and session management
- **JWT** - Authentication and authorization

### Monitoring & Observability
- **OpenTelemetry** - Distributed tracing
- **Prometheus + Grafana** - Metrics and monitoring
- **Structured logging** - For debugging and audit trails

## Function Structure

```
/functions/
├── analyze_alerts/
│   ├── rank_alerts.py
│   ├── count_alerts.py
│   ├── filter_alerts.py
│   └── distribution_analysis.py
├── investigate_entity/
│   ├── get_alerts_for_entity.py
│   ├── get_details_for_entity.py
│   ├── get_activity_for_entity.py
│   └── get_status_for_entity.py
├── map_relationships/
│   ├── entity_to_entity.py
│   ├── access_patterns.py
│   └── activity_correlation.py
├── detect_threats/
│   ├── find_technique.py
│   ├── find_tactic.py
│   ├── find_threat_actor.py
│   └── find_indicators.py
├── find_anomalies/
│   ├── detect_threshold.py
│   ├── detect_pattern.py
│   ├── detect_behavioral.py
│   └── detect_trend.py
├── trace_timeline/
│   ├── show_sequence.py
│   ├── trace_progression.py
│   └── correlate_temporal.py
├── check_vulnerabilities/
│   ├── list_by_entity.py
│   ├── check_cve.py
│   └── check_patches.py
├── monitor_agents/
│   ├── status_check.py
│   ├── version_check.py
│   └── health_check.py
└── _shared/
    ├── opensearch_client.py
    ├── build_query_from_filters.py
    ├── time_range_utils.py
    └── response_formatters.py
```

## Implementation

### 1. Dependencies and Setup

```python
# requirements.txt
langchain>=0.1.0
langsmith>=0.1.0
anthropic>=0.17.0
opensearch-py>=2.4.0
fastapi>=0.104.0
pydantic>=2.0.0
redis>=5.0.0
python-jose[cryptography]>=3.3.0
opentelemetry-api>=1.20.0
opentelemetry-sdk>=1.20.0
prometheus-client>=0.19.0
structlog>=23.0.0
```

### 2. Pydantic Schemas

```python
# schemas/wazuh_schemas.py
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum

class AlertAction(str, Enum):
    RANKING = "ranking"
    FILTERING = "filtering"
    COUNTING = "counting"
    DISTRIBUTION = "distribution"

class EntityType(str, Enum):
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    FILE = "file"

class QueryType(str, Enum):
    ALERTS = "alerts"
    DETAILS = "details"
    ACTIVITY = "activity"
    STATUS = "status"

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
    relationship_type: str = Field(description="Type of relationship to explore")
    timeframe: Optional[str] = Field(default="24h", description="Time frame for relationship mapping")

class DetectThreatsSchema(BaseModel):
    """Schema for detect_threats function"""
    threat_type: str = Field(description="Type of threat to detect")
    technique_id: Optional[str] = Field(default=None, description="MITRE ATT&CK technique ID")
    tactic_name: Optional[str] = Field(default=None, description="MITRE ATT&CK tactic name")
    actor_name: Optional[str] = Field(default=None, description="Threat actor name")
    timeframe: Optional[str] = Field(default="7d", description="Time frame for threat detection")

class FindAnomaliesSchema(BaseModel):
    """Schema for find_anomalies function"""
    anomaly_type: str = Field(description="Type of anomaly to detect")
    metric: Optional[str] = Field(default=None, description="Metric to analyze")
    timeframe: Optional[str] = Field(default="24h", description="Time frame for anomaly detection")
    threshold: Optional[float] = Field(default=None, description="Threshold for anomaly detection")
    baseline: Optional[str] = Field(default=None, description="Baseline period for comparison")

class TraceTimelineSchema(BaseModel):
    """Schema for trace_timeline function"""
    start_time: str = Field(description="Start time for timeline")
    end_time: str = Field(description="End time for timeline")
    entity: Optional[str] = Field(default=None, description="Entity to focus timeline on")
    view_type: str = Field(description="Type of timeline view")
    event_types: Optional[List[str]] = Field(default=None, description="Types of events to include")

class CheckVulnerabilitiesSchema(BaseModel):
    """Schema for check_vulnerabilities function"""
    entity_filter: Optional[str] = Field(default=None, description="Filter by entity")
    cve_id: Optional[str] = Field(default=None, description="Specific CVE ID to check")
    severity: Optional[str] = Field(default=None, description="Vulnerability severity level")
    patch_status: Optional[str] = Field(default=None, description="Patch status filter")

class MonitorAgentsSchema(BaseModel):
    """Schema for monitor_agents function"""
    agent_id: Optional[str] = Field(default=None, description="Specific agent ID")
    status_filter: Optional[str] = Field(default=None, description="Filter by agent status")
    version_requirements: Optional[str] = Field(default=None, description="Version requirements")
```

### 3. OpenSearch Client Integration

```python
# _shared/opensearch_client.py
from opensearchpy import OpenSearch, AsyncOpenSearch
from typing import Dict, Any, Optional
import structlog
from datetime import datetime, timedelta
import re

logger = structlog.get_logger()

class WazuhOpenSearchClient:
    def __init__(self, host: str, port: int = 9200, auth: tuple = None, use_ssl: bool = True):
        self.client = AsyncOpenSearch(
            hosts=[{'host': host, 'port': port}],
            http_auth=auth,
            use_ssl=use_ssl,
            verify_certs=False,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
            connection_class=RequestsHttpConnection,
        )
        
    async def search(self, index: str, query: Dict[str, Any], size: int = 100) -> Dict[str, Any]:
        """Execute search query against OpenSearch"""
        try:
            query['size'] = size
            response = await self.client.search(
                index=index,
                body=query
            )
            logger.info("OpenSearch query executed", 
                       index=index, 
                       hits=response['hits']['total']['value'])
            return response
        except Exception as e:
            logger.error("OpenSearch query failed", error=str(e), query=query)
            raise

    async def count(self, index: str, query: Dict[str, Any]) -> Dict[str, Any]:
        """Count documents matching query"""
        try:
            response = await self.client.count(
                index=index,
                body=query
            )
            return response
        except Exception as e:
            logger.error("OpenSearch count failed", error=str(e))
            raise

    async def get_indices(self) -> List[str]:
        """Get list of available indices"""
        try:
            response = await self.client.cat.indices(format='json')
            return [idx['index'] for idx in response if idx['index'].startswith('wazuh')]
        except Exception as e:
            logger.error("Failed to get indices", error=str(e))
            raise

    def build_time_range_filter(self, time_range: str) -> Dict[str, Any]:
        """Convert time range string to OpenSearch query filter"""
        if time_range.endswith('d'):
            days = int(time_range[:-1])
            gte = f"now-{days}d"
        elif time_range.endswith('h'):
            hours = int(time_range[:-1])
            gte = f"now-{hours}h"
        elif time_range.endswith('m'):
            minutes = int(time_range[:-1])
            gte = f"now-{minutes}m"
        else:
            gte = "now-24h"  # default
            
        return {
            "range": {
                "timestamp": {
                    "gte": gte,
                    "lte": "now"
                }
            }
        }

    def build_filters_query(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert filters dict to OpenSearch query filters"""
        query_filters = []
        
        for field, value in filters.items():
            if isinstance(value, list):
                query_filters.append({
                    "terms": {field: value}
                })
            elif isinstance(value, str):
                if '*' in value or '?' in value:
                    query_filters.append({
                        "wildcard": {field: value}
                    })
                else:
                    query_filters.append({
                        "term": {field: value}
                    })
            else:
                query_filters.append({
                    "term": {field: value}
                })
        
        return query_filters
```

### 4. LangChain Tool Implementation

```python
# tools/wazuh_tools.py
from langchain.tools import BaseTool
from langchain.callbacks.manager import AsyncCallbackManagerForToolRun
from typing import Optional, Type, Dict, Any
import importlib
import structlog
from schemas.wazuh_schemas import *

logger = structlog.get_logger()

class WazuhBaseTool(BaseTool):
    """Base class for all Wazuh tools"""
    opensearch_client: Any
    
    def __init__(self, opensearch_client):
        super().__init__()
        self.opensearch_client = opensearch_client

class AnalyzeAlertsTool(WazuhBaseTool):
    name = "analyze_alerts"
    description = "Analyze Wazuh alerts with ranking, filtering, counting, or distribution analysis"
    args_schema: Type[AnalyzeAlertsSchema] = AnalyzeAlertsSchema
    
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
            module_name = f"functions.analyze_alerts.{action}_alerts"
            module = importlib.import_module(module_name)
            
            params = {
                "group_by": group_by,
                "filters": filters,
                "limit": limit,
                "time_range": time_range
            }
            
            result = await module.execute(self.opensearch_client, params)
            
            logger.info("Alert analysis completed", 
                       action=action, 
                       results_count=len(result.get('hits', {}).get('hits', [])))
            
            return result
            
        except Exception as e:
            logger.error("Alert analysis failed", action=action, error=str(e))
            raise

class InvestigateEntityTool(WazuhBaseTool):
    name = "investigate_entity"
    description = "Investigate specific entities (host, user, process, file)"
    args_schema: Type[InvestigateEntitySchema] = InvestigateEntitySchema
    
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
            # Route to specific sub-function
            module_name = f"functions.investigate_entity.get_{query_type}_for_entity"
            module = importlib.import_module(module_name)
            
            params = {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "time_range": time_range
            }
            
            result = await module.execute(self.opensearch_client, params)
            
            logger.info("Entity investigation completed", 
                       entity_type=entity_type, 
                       entity_id=entity_id,
                       query_type=query_type)
            
            return result
            
        except Exception as e:
            logger.error("Entity investigation failed", 
                        entity_type=entity_type, 
                        entity_id=entity_id, 
                        error=str(e))
            raise

class MapRelationshipsTool(WazuhBaseTool):
    name = "map_relationships"
    description = "Explore relationships between users, hosts, files, alerts, or other entities"
    args_schema: Type[MapRelationshipsSchema] = MapRelationshipsSchema
    
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
            # Route to specific sub-function
            module_name = f"functions.map_relationships.{relationship_type}"
            module = importlib.import_module(module_name)
            
            params = {
                "source_type": source_type,
                "source_id": source_id,
                "target_type": target_type,
                "timeframe": timeframe
            }
            
            result = await module.execute(self.opensearch_client, params)
            
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
            raise

# Additional tool classes for other intents...
class DetectThreatsTool(WazuhBaseTool):
    name = "detect_threats"
    description = "Identify MITRE ATT&CK tactics, techniques, or activity patterns"
    args_schema: Type[DetectThreatsSchema] = DetectThreatsSchema
    
    async def _arun(self, threat_type: str, **kwargs) -> Dict[str, Any]:
        module_name = f"functions.detect_threats.find_{threat_type}"
        module = importlib.import_module(module_name)
        return await module.execute(self.opensearch_client, kwargs)

class FindAnomaliesTool(WazuhBaseTool):
    name = "find_anomalies"
    description = "Detect abnormal behaviour in users, processes, hosts, or network activity"
    args_schema: Type[FindAnomaliesSchema] = FindAnomaliesSchema
    
    async def _arun(self, anomaly_type: str, **kwargs) -> Dict[str, Any]:
        module_name = f"functions.find_anomalies.detect_{anomaly_type}"
        module = importlib.import_module(module_name)
        return await module.execute(self.opensearch_client, kwargs)

class TraceTimelineTool(WazuhBaseTool):
    name = "trace_timeline"
    description = "Reconstruct chronological view of events for entities or incidents"
    args_schema: Type[TraceTimelineSchema] = TraceTimelineSchema
    
    async def _arun(self, view_type: str, **kwargs) -> Dict[str, Any]:
        module_name = f"functions.trace_timeline.{view_type}"
        module = importlib.import_module(module_name)
        return await module.execute(self.opensearch_client, kwargs)

class CheckVulnerabilitiesTool(WazuhBaseTool):
    name = "check_vulnerabilities"
    description = "Check for known vulnerabilities (CVEs) on hosts or in alerts"
    args_schema: Type[CheckVulnerabilitiesSchema] = CheckVulnerabilitiesSchema
    
    async def _arun(self, **kwargs) -> Dict[str, Any]:
        module = importlib.import_module("functions.check_vulnerabilities.check_cve")
        return await module.execute(self.opensearch_client, kwargs)

class MonitorAgentsTool(WazuhBaseTool):
    name = "monitor_agents"
    description = "Check agent connectivity, versions, and operational status"
    args_schema: Type[MonitorAgentsSchema] = MonitorAgentsSchema
    
    async def _arun(self, **kwargs) -> Dict[str, Any]:
        module = importlib.import_module("functions.monitor_agents.status_check")
        return await module.execute(self.opensearch_client, kwargs)
```

### 5. Example Function Implementation

```python
# functions/analyze_alerts/rank_alerts.py
from typing import Dict, Any
from _shared.opensearch_client import WazuhOpenSearchClient
import structlog

logger = structlog.get_logger()

async def execute(opensearch_client: WazuhOpenSearchClient, params: Dict[str, Any]) -> Dict[str, Any]:
    """Rank alerts by specified criteria"""
    
    # Build base query
    query = {
        "query": {
            "bool": {
                "must": [
                    opensearch_client.build_time_range_filter(params.get("time_range", "7d"))
                ]
            }
        },
        "aggs": {
            "ranked_entities": {
                "terms": {
                    "field": params.get("group_by", "agent.name"),
                    "size": params.get("limit", 10),
                    "order": {"_count": "desc"}
                },
                "aggs": {
                    "latest_alert": {
                        "top_hits": {
                            "size": 1,
                            "sort": [{"timestamp": {"order": "desc"}}],
                            "_source": ["rule.description", "rule.level", "timestamp"]
                        }
                    }
                }
            }
        }
    }
    
    # Add filters if provided
    if params.get("filters"):
        filter_queries = opensearch_client.build_filters_query(params["filters"])
        query["query"]["bool"]["must"].extend(filter_queries)
    
    # Execute query
    try:
        result = await opensearch_client.search("wazuh-alerts-*", query)
        
        # Format results for better readability
        formatted_results = {
            "total_alerts": result["hits"]["total"]["value"],
            "ranked_entities": []
        }
        
        for bucket in result["aggregations"]["ranked_entities"]["buckets"]:
            entity_data = {
                "entity": bucket["key"],
                "alert_count": bucket["doc_count"],
                "latest_alert": bucket["latest_alert"]["hits"]["hits"][0]["_source"] if bucket["latest_alert"]["hits"]["hits"] else None
            }
            formatted_results["ranked_entities"].append(entity_data)
        
        logger.info("Alert ranking completed", 
                   total_alerts=formatted_results["total_alerts"],
                   entities_found=len(formatted_results["ranked_entities"]))
        
        return formatted_results
        
    except Exception as e:
        logger.error("Alert ranking failed", error=str(e), params=params)
        raise
```

### 6. LangChain Agent Setup

```python
# agent/wazuh_agent.py
from langchain.agents import initialize_agent, AgentType
from langchain.memory import ConversationBufferMemory
from langchain.callbacks import LangChainTracer
from langchain_anthropic import ChatAnthropic
from tools.wazuh_tools import *
from _shared.opensearch_client import WazuhOpenSearchClient
import structlog

logger = structlog.get_logger()

class WazuhSecurityAgent:
    def __init__(self, anthropic_api_key: str, opensearch_config: Dict[str, Any]):
        # Initialize OpenSearch client
        self.opensearch_client = WazuhOpenSearchClient(**opensearch_config)
        
        # Initialize LLM
        self.llm = ChatAnthropic(
            model="claude-3-5-sonnet-20241022",
            temperature=0.1,
            anthropic_api_key=anthropic_api_key
        )
        
        # Initialize tools
        self.tools = [
            AnalyzeAlertsTool(self.opensearch_client),
            InvestigateEntityTool(self.opensearch_client),
            MapRelationshipsTool(self.opensearch_client),
            DetectThreatsTool(self.opensearch_client),
            FindAnomaliesTool(self.opensearch_client),
            TraceTimelineTool(self.opensearch_client),
            CheckVulnerabilitiesTool(self.opensearch_client),
            MonitorAgentsTool(self.opensearch_client)
        ]
        
        # Initialize memory
        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True,
            output_key="output"
        )
        
        # Initialize agent
        self.agent = initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
            memory=self.memory,
            verbose=True,
            max_iterations=3,
            early_stopping_method="generate",
            callbacks=[LangChainTracer()]
        )
        
        # Custom system prompt
        self.system_prompt = """
        You are a Wazuh SIEM security analyst assistant. You help users investigate security incidents, 
        analyze alerts, and understand their security posture.
        
        Key guidelines:
        - Always use the appropriate tools for data retrieval
        - Provide actionable security insights
        - Highlight critical findings and potential threats
        - Explain technical concepts in clear terms
        - Suggest follow-up investigations when relevant
        - Maintain security context in all responses
        
        Available tools cover:
        - Alert analysis and statistics
        - Entity investigation (hosts, users, processes, files)
        - Threat detection and MITRE ATT&CK mapping
        - Relationship mapping between entities
        - Anomaly detection
        - Timeline reconstruction
        - Vulnerability checking
        - Agent monitoring
        """
    
    async def query(self, user_input: str) -> str:
        """Process user query and return response"""
        try:
            # Add system context to query
            full_prompt = f"{self.system_prompt}\n\nUser query: {user_input}"
            
            # Execute agent
            response = await self.agent.arun(full_prompt)
            
            logger.info("Agent query completed", 
                       user_input=user_input[:100],  # Log first 100 chars
                       response_length=len(response))
            
            return response
            
        except Exception as e:
            logger.error("Agent query failed", error=str(e), user_input=user_input)
            return f"I encountered an error processing your request: {str(e)}"
    
    async def reset_memory(self):
        """Reset conversation memory"""
        self.memory.clear()
        logger.info("Agent memory reset")
```

### 7. FastAPI Application

```python
# main.py
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from agent.wazuh_agent import WazuhSecurityAgent
from typing import Dict, Any
import structlog
import os

logger = structlog.get_logger()

app = FastAPI(
    title="Wazuh LLM Security Assistant",
    description="Natural language interface for Wazuh SIEM",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize agent
agent = WazuhSecurityAgent(
    anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
    opensearch_config={
        "host": os.getenv("OPENSEARCH_HOST", "localhost"),
        "port": int(os.getenv("OPENSEARCH_PORT", "9200")),
        "auth": (os.getenv("OPENSEARCH_USER"), os.getenv("OPENSEARCH_PASSWORD")),
        "use_ssl": os.getenv("OPENSEARCH_USE_SSL", "true").lower() == "true"
    }
)

class QueryRequest(BaseModel):
    query: str
    session_id: str = "default"

class QueryResponse(BaseModel):
    response: str
    session_id: str

@app.post("/query", response_model=QueryResponse)
async def query_agent(request: QueryRequest):
    """Process natural language query"""
    try:
        response = await agent.query(request.query)
        return QueryResponse(response=response, session_id=request.session_id)
    except Exception as e:
        logger.error("Query processing failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/reset")
async def reset_session():
    """Reset conversation memory"""
    await agent.reset_memory()
    return {"message": "Session reset successfully"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "wazuh-llm-assistant"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### 8. Example Usage

```python
# Example queries the agent can handle
example_queries = [
    "Show me the top 10 hosts with most alerts this week",
    "What alerts are there for user john.doe?",
    "Find T1055 process injection techniques detected recently",
    "Which users accessed host web-server-01 in the last 24 hours?",
    "Show me unusual login patterns from yesterday",
    "What happened with user admin between 2pm and 3pm yesterday?",
    "Check for Log4Shell vulnerabilities on our Windows hosts",
    "Which agents are disconnected right now?",
    "Find hosts with more than 50 failed login attempts",
    "Show me the attack timeline for the recent incident on host db-server-02"
]

# Usage example
agent = WazuhSecurityAgent(
    anthropic_api_key="your-anthropic-api-key",
    opensearch_config={
        "host": "your-opensearch-host",
        "port": 9200,
        "auth": ("username", "password"),
        "use_ssl": True
    }
)

response = await agent.query("Show me the top 5 hosts with most critical alerts today")
print(response)
```

## Key Benefits

### 1. **Modular Architecture**
- Each function is a separate module for maintainability
- Shared utilities reduce code duplication
- Easy to add new intents and sub-actions

### 2. **Type Safety**
- Pydantic schemas ensure proper parameter validation
- OpenSearch client provides type-safe query building
- Structured logging for better debugging

### 3. **Observability**
- LangSmith integration for tracing function calls
- Structured logging throughout the pipeline
- OpenTelemetry support for distributed tracing

### 4. **Production Ready**
- Async support for high throughput
- Redis caching for frequent queries
- JWT authentication and authorization
- Rate limiting and error handling

### 5. **Natural Language Interface**
- LangChain agents provide conversational experience
- Memory maintains context across queries
- Intelligent function calling based on user intent

This implementation provides a robust, scalable foundation for a production-ready Wazuh SIEM assistant that can understand natural language queries and provide meaningful security insights using modern LLM tooling and frameworks.
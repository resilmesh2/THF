# THF (Threat Hunting Framework)

An AI-powered natural language interface for Wazuh SIEM using LangChain and Anthropic Claude.

## Overview

THF (Threat Hunting Framework) is a sophisticated AI-powered security analysis platform that provides a conversational interface to Wazuh SIEM data. The system leverages Claude AI (Anthropic's Claude Sonnet 4) through LangChain to enable security analysts to investigate security incidents, analyze alerts, and understand their security posture using natural language queries.

The framework converts user queries into structured function calls, executes them against the Wazuh OpenSearch backend and Wazuh API, and returns actionable security insights with full context preservation across multi-turn conversations.

## Installation Instructions & Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/resilmesh2/THF.git
   cd THF/
   ```
   
2. Install required dependencies
   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment variables
   ```bash
   cp .env.example .env
   ```

## Environment Variables

### Edit .env and configure your API keys

The following environment variables must be configured in your `.env` file:

**Anthropic Configuration:**
- `ANTHROPIC_API_KEY` - Your Anthropic API key for Claude AI access

**OpenSearch Configuration:**
- `OPENSEARCH_HOST` - Your OpenSearch host address
- `OPENSEARCH_PORT` - OpenSearch port (default: 9200)
- `OPENSEARCH_USER` - OpenSearch username (default: admin)
- `OPENSEARCH_PASSWORD` - OpenSearch password
- `OPENSEARCH_USE_SSL` - Enable SSL for OpenSearch connection (true/false)

**Wazuh API Configuration:**
- `WAZUH_API_HOST` - Wazuh API host address (default: localhost)
- `WAZUH_API_PORT` - Wazuh API port (default: 55000)
- `WAZUH_API_USERNAME` - Wazuh API username
- `WAZUH_API_PASSWORD` - Wazuh API password
- `WAZUH_API_USE_SSL` - Enable SSL for Wazuh API (true/false)
- `WAZUH_API_VERIFY_CERTS` - Verify SSL certificates (true/false)

**Redis Configuration (optional):**
- `REDIS_HOST` - Redis host address (default: localhost)
- `REDIS_PORT` - Redis port (default: 6379)
- `REDIS_PASSWORD` - Redis password (leave empty if not required)

**Application Configuration:**
- `LOG_LEVEL` - Logging level (INFO, DEBUG, WARNING, ERROR)
- `API_HOST` - FastAPI host binding (default: 0.0.0.0)
- `API_PORT` - FastAPI port (default: 8000)

## Running the Application

Once dependencies are installed, you need to start the FastAPI backend and the Streamlit frontend UI.

1. First, start the FastAPI backend server:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```

2. Then in a new terminal, start the Streamlit UI:
   ```bash
   streamlit run ./streamlit_ui.py
   ```

The backend will be available at `http://localhost:8000` and the UI at `http://localhost:8501` by default.

3. Access the Streamlit UI and start threat hunting:
   - Open your browser and navigate to `http://localhost:8501`
   - Enter a natural language security query in the text input field
   - Press Enter or click outside the input field to submit

   Example queries to try:
   ```
   Show me the top 10 hosts with most alerts this week
   What alerts are there for user admin?
   Find hosts with more than 50 failed login attempts
   Which agents are disconnected?
   ```

## Application Architecture

```
User Query → Context Processor → LangChain Agent → Tool Selection → Function Execution → OpenSearch/Wazuh API → Response Generation → User
     ↓                                                    ↓
Session Memory                                   Function Dispatcher
```

### Core Components

#### 1. WazuhSecurityAgent (`agent/wazuh_agent.py`)
The central orchestrator that manages the entire query processing lifecycle:

- **LLM Model**: Claude Sonnet 4
- **Agent Type**: STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION
- **Session Management**: Unique session IDs for isolated conversation contexts
- **Memory System**: ConversationSummaryBufferMemory (1500 token limit per session)
- **Max Iterations**: 3 with early stopping to optimize API usage
- **Timeout**: 30 seconds per API call with exponential backoff retry logic
- **Key Features**:
  - Session-based conversation memory prevents context bleed between users
  - Automatic retry on API overload (529 errors) with 2s, 4s backoff
  - Context preservation across multi-turn conversations
  - Real-time agent state management

#### 2. ConversationContextProcessor (`agent/context_processor.py`)
Intelligent context analysis and preservation system:

- **Context Detection**: Identifies contextual references ("these alerts", "that host", "this process")
- **Entity Extraction**: Extracts hosts, users, processes, files, IPs from conversation history
- **Temporal Context**: Preserves time ranges across queries
- **Query Enrichment**: Automatically applies previous filters to follow-up queries
- **Detection Strategies**:
  - Explicit keyword matching
  - Numerical reference tracking
  - Definite article patterns
  - Entity reference extraction

#### 3. Security Function Modules (`functions/`)
8 specialized modules with 30+ sub-actions for comprehensive security analysis:

- **analyze_alerts**: Alert ranking, filtering, counting, distribution analysis
- **investigate_entity**: Deep-dive investigation (host, user, process, file, IP)
- **detect_threats**: MITRE ATT&CK techniques, tactics, threat actors, IoCs
- **map_relationships**: Entity relationship mapping with behavioral correlation
- **find_anomalies**: Threshold, behavioral, trend detection with RCF baselines
- **trace_timeline**: Chronological event reconstruction and attack progression
- **check_vulnerabilities**: CVE checking, patch status, vulnerability assessment
- **monitor_agents**: Agent status, health, connectivity monitoring

#### 4. Data Integration Layer (`functions/_shared/`)

**WazuhOpenSearchClient**:
- Async OpenSearch connectivity with SSL support
- Intelligent field mapping (auto-detects agent.id vs agent.name)
- Smart query building with wildcard and term queries
- Natural language time range parsing ("3 days ago", "yesterday 6am-11am")
- Wazuh array field normalization

**WazuhAPIClient**:
- JWT authentication with token caching
- Agent status monitoring (active, disconnected, never_connected)
- Agent search and summary statistics
- Comprehensive agent information retrieval

#### 5. Web Interface

**FastAPI Backend** (`main.py`):
- Async REST API with WebSocket support
- Session management endpoints
- Health checks and monitoring
- CORS configuration for production

**Streamlit UI** (`streamlit_ui.py`):
- Real-time conversation interface
- Session management (create, reset, view info)
- Example query suggestions
- API health status indicator
- Conversation history with timestamps

#### 6. Type Safety & Validation (`schemas/`)
- Pydantic schemas for all function parameters
- Enum-based action/type selection
- Automatic JSON serialization
- Request/response validation

## Features

### 8 Core Security Intents

1. **analyze_alerts** - Alert analysis with ranking, filtering, counting, distribution
2. **investigate_entity** - Entity investigation (host, user, process, file)
3. **detect_threats** - MITRE ATT&CK techniques, tactics, threat actors
4. **map_relationships** - Entity relationships, activity correlation
5. **find_anomalies** - Threshold, behavioral, trend detection
6. **trace_timeline** - Chronological event reconstruction
7. **check_vulnerabilities** - CVE checking and vulnerability assessment
8. **monitor_agents** - Agent status, health, and connectivity monitoring

### Example Queries

- "Show me the top 10 hosts with most alerts this week."
- "What alerts are there for user SYSTEM?"
- "Find T1055 process injection techniques detected recently."
- "Which users accessed host win10-01 in the last 24 hours?"
- "Show me unusual login patterns from yesterday."
- "Check for Log4Shell vulnerabilities on our Windows hosts."
- "Which agents are disconnected right now?"

## Technology Stack

### Core Framework & AI
- **Anthropic Claude API** (v0.57.1+) - Claude Sonnet 4 for LLM orchestration
- **LangChain** (v0.3.26+) - Agent framework and tool integration
- **LangChain-Anthropic** (v0.3.17+) - Anthropic integration for LangChain
- **LangSmith** (v0.4.5+) - Observability and agent tracing

### Backend & APIs
- **FastAPI** (v0.116.1+) - Async REST API with auto-documentation
- **Uvicorn** (v0.35.0+) - ASGI server with WebSocket support
- **HTTPX** (v0.28.1+) - Async HTTP client
- **Aiohttp** (v3.12.14+) - Async HTTP framework

### Data Integration
- **OpenSearch-py** (v2.4.0+) - Direct Wazuh OpenSearch backend integration
- **Wazuh API Client** (custom) - Agent management and system queries
- **Redis** (v6.2.0+) - Query caching and session storage

### Frontend
- **Streamlit** (v1.46.1+) - Interactive web UI framework
- **Python-multipart** (v0.0.20+) - File upload handling

### Data Validation & Serialization
- **Pydantic** (v2.10.6+) - Schema validation and type safety
- **Pydantic-settings** (v2.8.1+) - Environment configuration management

### Observability & Monitoring
- **OpenTelemetry-api** (v1.35.0+) - Distributed tracing
- **OpenTelemetry-sdk** (v1.35.0+) - Telemetry implementation
- **OpenTelemetry-exporter-prometheus** (v0.56b0) - Metrics export
- **Prometheus-client** (v0.22.1+) - Metrics collection
- **Structlog** (v25.4.0+) - Structured JSON logging
- **Colorama** (v0.4.6+) - Colored terminal output

### Security & Authentication
- **Python-jose[cryptography]** (v3.5.0+) - JWT token handling

### Utilities
- **Python-dotenv** (v1.1.0+) - Environment variable loading
- **Python-dateutil** (v2.8.2+) - Date parsing and manipulation
- **Pytz** (v2023.3+) - Timezone handling
- **Aiofiles** (v24.1.0+) - Async file operations

### Development & Testing
- **Pytest** (v7.4.0+) - Testing framework
- **Pytest-asyncio** (v0.21.0+) - Async test support
- **Pytest-cov** (v4.1.0+) - Coverage reporting
- **Black** (v23.0.0+) - Code formatting
- **Mypy** (v1.5.0+) - Static type checking

## Usage

### REST API

Start the FastAPI server:
```bash
python main.py
```

Query the assistant:
```bash
curl -X POST "http://localhost:8000/query" \
  -H "Content-Type: application/json" \
  -d '{"query": "Show me critical alerts from the last hour"}'
```

### Python SDK Example

```python
from agent.wazuh_agent import WazuhSecurityAgent

agent = WazuhSecurityAgent(
    opensearch_config={
        "host": "your-opensearch-host",
        "port": 9200,
        "auth": ("username", "password"),
        "use_ssl": True
    }
)

response = await agent.query("Show me the top 5 hosts with most alerts today")
print(response)
```

## Development

### Project Structure

```
THF/
├── agent/                         # Core LLM agent implementation
│   ├── wazuh_agent.py             # Main LangChain agent orchestrator
│   ├── context_processor.py       # Conversation context analysis
│   └── __init__.py
├── functions/                      # Security analysis function modules
│   ├── analyze_alerts/            # Alert ranking, filtering, counting, distribution
│   ├── investigate_entity/        # Host, user, process, file investigation
│   ├── map_relationships/         # Entity relationship mapping and correlation
│   ├── detect_threats/            # MITRE ATT&CK detection, threat actors, IoCs
│   ├── find_anomalies/            # Threshold, behavioral, trend anomaly detection
│   ├── trace_timeline/            # Event timeline reconstruction
│   ├── check_vulnerabilities/     # CVE checking, vulnerability assessment
│   ├── monitor_agents/            # Agent status, health, version monitoring
│   ├── smart_routing/             # Intelligent query routing
│   └── _shared/                   # Shared utilities
│       ├── opensearch_client.py   # OpenSearch integration
│       ├── wazuh_api_client.py    # Wazuh API integration
│       ├── time_parser.py         # Natural language time parsing
│       └── utils.py               # Common utilities
├── tools/                         # LangChain tool wrappers
├── schemas/                       # Pydantic validation schemas
├── assets/                        # Static assets (logos, images)
├── tests/                         # Test suite
├── docs/                          # Documentation
├── main.py                        # FastAPI backend server
├── streamlit_ui.py                # Streamlit web UI
├── demo_server.py                 # Demo/testing server
├── start_ui.py                    # UI launcher script
├── requirements.txt               # Python dependencies
├── README.md                      # This file
└── .env                           # Environment configuration
```

### Key Architectural Features

#### Session-Based Memory Management
- **Isolated Contexts**: Each user session maintains separate conversation memory
- **Prevents Memory Bleed**: Concurrent users don't interfere with each other
- **Context-Aware Follow-ups**: System remembers entities, filters, and time ranges from previous queries
- **Token Optimization**: ConversationSummaryBufferMemory with 1500 token limit

#### Intelligent Context Preservation
The `ConversationContextProcessor` (agent/context_processor.py:1) analyzes conversations to:
- Detect contextual references ("these alerts", "that host")
- Extract entities from previous responses
- Preserve temporal context across queries
- Enrich follow-up queries with relevant filters

#### Smart Routing & Field Detection
- **Automatic Field Mapping**: Detects whether to use agent.id or agent.name
- **Process Intelligence**: Searches across originalFileName, image, commandLine
- **Multi-field Search**: Comprehensive coverage for hosts, processes, files
- **Natural Language Time Parsing**: Supports "3 days ago", "yesterday 6am-11am"

#### Retry Logic with Exponential Backoff
The agent (`agent/wazuh_agent.py:214`) handles API overload gracefully:
- Detects 529 (overload) errors automatically
- Exponential backoff: 2s, 4s intervals
- User-friendly error messages
- Maintains conversation state during retries

#### Type Safety & Validation
- **Pydantic Schemas**: All function parameters are validated
- **Enum-Based Selection**: Action and entity types use enums
- **Automatic Serialization**: JSON conversion handled automatically
- **Request Validation**: FastAPI validates all API requests

### Adding New Functions

1. Create a new module in the appropriate `functions/` subdirectory
2. Implement the `execute()` function with proper parameters
3. Add Pydantic schema for parameter validation
4. Add the function to the corresponding LangChain tool in `tools/`
5. Update documentation and add tests

### Testing

Run the test suite:
```bash
pytest tests/
```

Run with coverage:
```bash
pytest --cov=. tests/
```

## Monitoring

### Observability

- **LangSmith**: Trace agent interactions and function calls
- **Structured Logging**: JSON-formatted logs with context
- **OpenTelemetry**: Distributed tracing support
- **Prometheus**: Metrics collection (optional)

### Health Checks

```bash
curl http://localhost:8000/health
```

## Security

### Best Practices

- Store API keys securely using environment variables
- Use HTTPS in production
- Implement rate limiting
- Validate all inputs through Pydantic schemas
- Monitor for unusual query patterns

### Authentication

The system supports JWT-based authentication. Configure your authentication provider in the environment variables.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Code Style

- Follow PEP 8
- Use type hints
- Write docstrings for all functions
- Add structured logging to new functions

## License

MIT License - see LICENSE file for details

## Support

For issues and questions:
- Create an issue on GitHub
- Check the documentation in `docs/`
- Review the example queries and use cases

## API Endpoints

The FastAPI backend provides the following endpoints:

### Query Endpoint
```bash
POST /query
Content-Type: application/json

{
  "query": "Show me critical alerts from the last hour",
  "session_id": "optional-session-id"
}
```

### Session Management
```bash
# Reset session memory
POST /reset?session_id=your-session-id

# Get session information
GET /session/{session_id}

# List all active sessions
GET /sessions
```

### Health & System Info
```bash
# Health check
GET /health

# API information
GET /
```

### Agent Methods (Python SDK)
The `WazuhSecurityAgent` class provides these key methods:

```python
# Process natural language query with session context
await agent.query(user_input="Show me alerts", session_id="user-123")

# Reset conversation memory
await agent.reset_memory(session_id="user-123")

# Get session information
agent.get_session_info(session_id="user-123")

# Test OpenSearch connection
await agent.test_connection()

# Get available Wazuh indices
await agent.get_available_indices()

# Get tool descriptions
agent.get_tool_descriptions()

# Get system information
agent.get_system_info()

# Close connections
await agent.close()
```

## Roadmap

### Completed Features ✓
- [x] Natural language interface with Claude Sonnet 4
- [x] Session-based conversation memory
- [x] Context preservation across queries
- [x] 8 core security analysis intents with 30+ sub-actions
- [x] Streamlit web interface
- [x] FastAPI REST API
- [x] OpenSearch and Wazuh API integration
- [x] Smart routing and field detection
- [x] Natural language time parsing
- [x] MITRE ATT&CK threat detection
- [x] Entity relationship mapping
- [x] Anomaly detection with RCF baselines
- [x] Comprehensive logging and tracing

### Planned Features
- [ ] Support for custom Wazuh rules and decoders
- [ ] Integration with external threat intelligence feeds
- [ ] Multi-tenant support with role-based access control
- [ ] Advanced visualization capabilities and dashboards
- [ ] Query result caching with Redis
- [ ] Automated report generation
- [ ] Scheduled threat hunting queries
- [ ] Integration with ticketing systems (Jira, ServiceNow)
- [ ] Mobile app interface
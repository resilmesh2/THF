# Query Timing Measurements

This document describes the comprehensive timing measurement system implemented for the Wazuh LLM Assistant.

## Overview

The timing system tracks execution time from when a query is submitted in the frontend until the response is displayed, with detailed breakdowns of each phase of execution.

## Features

### 1. **End-to-End Timing**
- Measures total time from frontend query submission to response display
- Displayed in Streamlit UI as "Total Frontend Time"

### 2. **Detailed Backend Breakdown**
The system tracks and reports:

- **Total Execution Time**: Complete backend processing time
- **LLM Processing Time**: Time spent in Claude API calls (thinking, reasoning, response generation)
- **Tool Execution Time**: Time spent executing security functions (OpenSearch queries, data processing)
- **Orchestration Time**: Time spent on agent logic, planning, and coordination
- **Agent Iterations**: Number of ReAct reasoning cycles

### 3. **Granular Execution Details**

#### LLM Call Tracking
- Individual timing for each Claude API call
- Iteration number for each call
- Total number of LLM invocations

#### Tool Call Tracking
- Individual timing for each security function execution
- Tool name identification
- Execution order and iteration context

### 4. **Terminal Output**

When running the FastAPI backend (`python main.py`), detailed timing information is printed to the terminal after each query:

```
================================================================================
⏱️  QUERY EXECUTION TIMING SUMMARY
================================================================================
🕐 Total Time: 12.345 seconds
🔄 Agent Iterations: 2
--------------------------------------------------------------------------------

📊 Time Breakdown:
  🤖 LLM Processing:     8.123s (65.8%)
  🔧 Tool Execution:     3.456s (28.0%)
  ⚙️  Other (orchestration): 0.766s (6.2%)

🤖 LLM Calls Detail (3 calls):
  Call 1 (Iteration 0): 2.345s
  Call 2 (Iteration 1): 3.456s
  Call 3 (Iteration 2): 2.322s

🔧 Tool Calls Detail (2 calls):
  1. analyze_alerts_tool: 2.123s (Iteration 1)
  2. investigate_entity_tool: 1.333s (Iteration 2)
================================================================================
```

### 5. **Streamlit UI Display**

In the web interface, timing information is available for each assistant response:
- Click the "⏱️ Timing Information" expander below any response
- View metrics for:
  - Total Frontend Time (end-to-end)
  - Backend execution breakdown
  - Individual LLM and tool calls

## Implementation Details

### Components

1. **`agent/timing_callback.py`**
   - Custom LangChain callback handler (`TimingCallbackHandler`)
   - Tracks LLM start/end, tool start/end, agent actions
   - Generates detailed timing reports

2. **`agent/wazuh_agent.py`**
   - Modified `query()` method to use timing callback
   - Returns dict with both response and timing data
   - Handles timing across retries

3. **`main.py`**
   - Updated FastAPI endpoint to handle timing data
   - Returns timing in API response
   - Prints summary to terminal

4. **`streamlit_ui.py`**
   - Measures frontend-to-frontend time
   - Displays timing metrics in UI
   - Shows detailed breakdown in expandable section

## Usage

### Running the System

1. **Start the FastAPI backend:**
   ```bash
   python main.py
   ```
   Timing information will be printed to this terminal after each query.

2. **Start the Streamlit UI:**
   ```bash
   streamlit run streamlit_ui.py
   ```

3. **Submit a query** through the web interface

4. **View timing data:**
   - Terminal: Check the FastAPI terminal for detailed breakdown
   - Logs: Check structured logs for JSON timing data
   - UI: Expand "⏱️ Timing Information" below the response

### Example Query Flow

**User submits:** "Show me critical alerts from the last hour"

**Terminal Output (FastAPI):**
```
⏱️  Starting query execution timing
🔄 Agent iteration starting: iteration=1
🤖 LLM starting: iteration=1
✅ LLM completed: duration_seconds=2.345 iteration=1
🎯 Agent action selected: tool=analyze_alerts_tool iteration=1
🔧 Tool starting: tool=analyze_alerts_tool iteration=1
✅ Tool completed: tool=analyze_alerts_tool duration_seconds=1.234 iteration=1
🏁 Agent finished: total_iterations=1

================================================================================
⏱️  QUERY EXECUTION TIMING SUMMARY
================================================================================
🕐 Total Time: 4.567 seconds
🔄 Agent Iterations: 1
[... detailed breakdown ...]
```

### Analyzing Performance

Use the timing data to:

1. **Identify bottlenecks**: See if LLM or tool execution is slower
2. **Optimize queries**: Understand which operations take longest
3. **Monitor iterations**: Track ReAct reasoning cycles
4. **Debug issues**: Correlate slow queries with specific tools or patterns

## Timing Metrics Explained

### LLM Processing Time
Time Claude spends:
- Understanding the query
- Planning tool usage (ReAct reasoning)
- Generating natural language responses
- Summarizing results

### Tool Execution Time
Time spent:
- Querying OpenSearch
- Processing security data
- Analyzing alerts/entities
- Formatting results

### Orchestration Time
Time for:
- LangChain agent logic
- Memory operations
- Context processing
- Parameter validation
- Response formatting

### Agent Iterations
Number of reasoning cycles in the ReAct pattern:
- Iteration 0: Initial query understanding
- Iteration 1+: Tool selection, execution, and reasoning
- More iterations = more complex queries

## Logging

Structured logs include timing data:

```json
{
  "event": "Query execution completed",
  "total_duration": 12.345,
  "total_llm_time": 8.123,
  "total_tool_time": 3.456,
  "llm_calls": 3,
  "tool_calls": 2,
  "iterations": 2,
  "timestamp": "2025-01-15T10:30:45.123Z"
}
```

## Performance Tips

1. **Specific queries** tend to execute faster (fewer iterations)
2. **Context-aware follow-ups** may be faster (cached context)
3. **Complex investigations** may require multiple iterations
4. **API rate limits** can affect LLM processing time

## Troubleshooting

**Q: Timing shows 0 seconds for everything**
- A: Ensure the timing callback is properly initialized. Check for errors in agent initialization.

**Q: Terminal doesn't show timing summary**
- A: Make sure you're running `python main.py` directly (not through a process manager that might suppress stdout)

**Q: UI doesn't show timing expander**
- A: The timing expander only appears for assistant messages (not errors). Verify the query completed successfully.

**Q: Timing seems incorrect**
- A: Check system clock, ensure callbacks are firing (look for log messages)

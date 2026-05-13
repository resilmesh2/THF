# Quick Start: Timing Measurements

## Fixed Issue
The callback error has been resolved. The timing callback is now properly integrated without conflicting with existing callbacks.

## How to Use

### Option 1: Using the Web Interface (Recommended)

1. **Start the FastAPI backend** (this terminal will show timing data):
   ```bash
   python main.py
   ```

2. **Start the Streamlit UI** (in a separate terminal):
   ```bash
   streamlit run streamlit_ui.py
   ```

3. **Submit a query** in the web interface

4. **View timing data:**
   - **Backend Terminal**: Detailed timing summary is printed after each query
   - **Frontend UI**: Click "⏱️ Timing Information" expander below responses

### Option 2: Test Script

Run the test script to verify timing is working:
```bash
python test_timing.py
```

This will:
- Initialize the agent
- Run a test query
- Display timing metrics in the terminal
- Verify the timing system is functioning

### Option 3: Direct Python Usage

```python
import asyncio
from agent.wazuh_agent import WazuhSecurityAgent

async def main():
    agent = WazuhSecurityAgent(...)
    result = await agent.query("Show me critical alerts", session_id="test")

    print(f"Response: {result['response']}")
    print(f"Timing: {result['timing']}")

asyncio.run(main())
```

## What You'll See

### Terminal Output (FastAPI backend)
```
================================================================================
⏱️  QUERY EXECUTION TIMING SUMMARY
================================================================================
🕐 Total Time: 8.234 seconds
🔄 Agent Iterations: 2
--------------------------------------------------------------------------------

📊 Time Breakdown:
  🤖 LLM Processing:     5.123s (62.2%)
  🔧 Tool Execution:     2.456s (29.8%)
  ⚙️  Other (orchestration): 0.655s (8.0%)

🤖 LLM Calls Detail (2 calls):
  Call 1 (Iteration 0): 2.345s
  Call 2 (Iteration 1): 2.778s

🔧 Tool Calls Detail (1 calls):
  1. analyze_alerts_tool: 2.456s (Iteration 1)
================================================================================
```

### Streamlit UI
- Expand "⏱️ Timing Information" below any assistant response
- View metrics cards showing:
  - Total Frontend Time (end-to-end)
  - Total Execution (backend)
  - LLM Processing time
  - Tool Execution time
  - Agent Iterations count
  - Orchestration time
- Detailed lists of individual LLM and tool calls

## Metrics Explained

| Metric | Description |
|--------|-------------|
| **Total Frontend Time** | Complete time from UI query submission to response display |
| **Total Execution** | Backend processing time (agent execution) |
| **LLM Processing** | Time Claude spends thinking, reasoning, and generating responses |
| **Tool Execution** | Time executing security functions (OpenSearch queries, data analysis) |
| **Orchestration** | Agent coordination, memory, context processing |
| **Agent Iterations** | Number of ReAct reasoning cycles (thought → action → observation) |

## Troubleshooting

**Error: "got multiple values for keyword argument 'callbacks'"**
- This has been fixed. If you still see it, restart the FastAPI server.

**No timing data appears / All time shows as "orchestration"**
- **FIXED**: Callbacks now use `config` parameter to properly propagate
- Restart the FastAPI server: `python main.py`
- You should now see callback log messages like "🤖 LLM starting" in the terminal
- If still not working, check for import errors in the terminal

**Terminal doesn't show timing summary**
- Ensure you're running `python main.py` (not uvicorn directly)
- Check stdout isn't being suppressed

**Very long execution times**
- Complex queries naturally take longer
- Check OpenSearch connection speed
- Review which tools are being called (some are slower than others)

## Recent Fixes

**v2 (Current)**: Fixed callback propagation issue
- Changed from `self.agent.callbacks = [...]` to `config={"callbacks": [...]}`
- Callbacks now properly propagate to LLM and tool executions
- LLM and Tool timing is now accurately captured

## Performance Tips

1. **Specific queries** execute faster (fewer iterations needed)
2. **Context-aware follow-ups** can be quicker (reuses context)
3. **Critical alert queries** are usually fast (simple filters)
4. **Complex investigations** may require multiple iterations and tools

## Next Steps

- Review `TIMING_MEASUREMENTS.md` for comprehensive documentation
- Check structured logs for JSON timing data
- Use timing data to optimize query patterns
- Identify performance bottlenecks in your queries

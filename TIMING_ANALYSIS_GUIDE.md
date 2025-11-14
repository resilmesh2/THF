# Timing Analysis Guide

## Understanding Your Query Performance

This guide helps you interpret the timing data and understand where time is spent during threat hunting queries.

## Sample Analysis

### Your Query: "Show me an alert breakdown on host U209-PC-BLEE for the past 5 hours"

**Total Time: 24.688 seconds**

```
📊 Time Breakdown:
  🤖 LLM Processing:     24.204s (98.0%)
  🔧 Tool Execution:     0.238s (1.0%)
  ⚙️  Other (orchestration): 0.246s (1.0%)

🤖 LLM Calls Detail (2 calls):
  Call 1 (Iteration 0): 5.669s
  Call 2 (Iteration 0): 18.535s

🔧 Tool Calls Detail (1 calls):
  1. analyze_alerts_tool: 0.238s (Iteration 0)
```

### What This Means:

#### Call 1: Initial Planning (5.669s)
Claude is:
- Understanding your query
- Identifying you want alert breakdown for a specific host
- Parsing the time range ("past 5 hours")
- Deciding which tool to use (`analyze_alerts_tool`)
- Planning the tool parameters (host filter, time range, action type)

#### Tool Execution: Data Retrieval (0.238s)
The `analyze_alerts_tool`:
- Queries OpenSearch/Wazuh backend
- Filters alerts for host "U209-PC-BLEE"
- Applies 5-hour time range
- Aggregates alerts by severity/rule groups
- Returns structured data

**Why so fast?** OpenSearch is highly optimized for these queries!

#### Call 2: Response Generation (18.535s)
Claude is:
- Processing the tool's returned data
- Analyzing alert patterns
- Organizing information by severity levels
- Identifying top rule groups
- Generating natural language explanation
- Formatting the response for readability
- Adding security context and recommendations

**Why so long?** This is the most complex step - Claude is:
1. Synthesizing multiple data points
2. Creating a coherent narrative
3. Providing security insights
4. Formatting detailed breakdowns

### Is This Normal?

**Yes!** For complex analytical queries:
- **LLM dominates timing** (85-98%) - Claude does the heavy thinking
- **Tool execution is fast** (<1-5%) - Databases are optimized
- **Orchestration is minimal** (<5%) - Agent overhead is low

## Performance Patterns

### Fast Queries (5-10 seconds)
**Examples:**
- "Show me critical alerts from the last hour"
- "How many alerts are there?"
- "Which agents are disconnected?"

**Characteristics:**
- Simple aggregations
- Single tool call
- Brief responses
- Less analysis needed

**Timing Profile:**
- LLM: 60-70% (planning + simple response)
- Tool: 5-10% (quick query)
- Orchestration: 20-30%

### Medium Queries (10-20 seconds)
**Examples:**
- "Show me alert breakdown by severity"
- "What alerts does user admin have?"
- "Find authentication failures on host X"

**Characteristics:**
- Moderate data analysis
- 1-2 tool calls
- Structured responses
- Some pattern analysis

**Timing Profile:**
- LLM: 75-85% (analysis + formatting)
- Tool: 5-15% (filtering + aggregation)
- Orchestration: 5-10%

### Complex Queries (20-40+ seconds)
**Examples:**
- "Show me an alert breakdown on host X for the past 5 hours" (your query)
- "Investigate suspicious activity on host Y"
- "What's the relationship between these alerts and user Z?"

**Characteristics:**
- Deep data analysis
- Multiple aggregations
- Detailed explanations
- Security insights
- Recommendations

**Timing Profile:**
- LLM: 85-98% (complex analysis + comprehensive response)
- Tool: 1-5% (even complex queries are fast)
- Orchestration: 1-10%

## Optimization Tips

### When LLM Time is High (>80%)

**This is usually normal**, but you can try:

1. **Simplify the ask:**
   - Instead of: "Give me a detailed breakdown..."
   - Try: "Count alerts by severity for host X"

2. **Break into smaller queries:**
   - Query 1: "How many alerts on host X?"
   - Query 2: "What are the top rule groups?"

3. **Be specific:**
   - Good: "Show alerts for host U209-PC-BLEE in last 5 hours"
   - Better: "Count critical alerts for host U209-PC-BLEE in last 5 hours"

### When Tool Time is High (>20%)

**This is rare** but indicates:
- Large dataset processing
- Complex OpenSearch queries
- Multiple time-range scans
- Heavy aggregations

**Solutions:**
- Narrow the time range
- Add more specific filters
- Check OpenSearch performance
- Verify index optimization

### When Orchestration is High (>20%)

**This is unusual** and may indicate:
- Memory operations taking too long
- Context processing bottlenecks
- Agent iteration overhead
- System resource constraints

**Solutions:**
- Reset the session to clear memory
- Check system resources (CPU, RAM)
- Restart the backend
- Review agent configuration

## Reading the Iteration Count

### Iteration 0: Initial Planning
- All queries start here
- Claude plans the approach
- Single-iteration queries finish here

### Iteration 1+: Follow-up Actions
- Multiple tool calls needed
- ReAct reasoning cycle
- More complex analysis

**Your query had 0 iterations** which means:
- Single thought-action-response cycle
- Claude knew exactly what to do
- No need for additional reasoning steps
- Efficient execution path

## Comparing Query Performance

### Your Query Performance Matrix

| Aspect | Value | Rating |
|--------|-------|--------|
| Total Time | 24.688s | ⚠️ Slow |
| Tool Efficiency | 0.238s | ✅ Excellent |
| LLM Efficiency | 24.204s | ⚠️ Detailed Analysis |
| Iterations | 0 | ✅ Optimal |
| Tool Calls | 1 | ✅ Optimal |

### Why "Slow" Can Be Good

The 24.7 seconds wasn't wasted:
- ✅ Comprehensive alert analysis
- ✅ Breakdown by multiple dimensions
- ✅ Security context provided
- ✅ Clear, formatted response
- ✅ Actionable insights

**Trade-off:** Speed vs. Detail
- Fast queries (5s): Basic counts, simple answers
- Your query (25s): Detailed breakdown, analysis, insights

## Advanced: Multi-Iteration Queries

When you see multiple iterations (1, 2, 3+):

```
🔄 Agent Iterations: 3

🤖 LLM Calls Detail (4 calls):
  Call 1 (Iteration 0): 3.2s   # Initial planning
  Call 2 (Iteration 1): 2.8s   # After first tool result
  Call 3 (Iteration 2): 3.1s   # After second tool result
  Call 4 (Iteration 3): 5.4s   # Final synthesis

🔧 Tool Calls Detail (3 calls):
  1. analyze_alerts: 0.5s (Iteration 0)
  2. investigate_entity: 1.2s (Iteration 1)
  3. map_relationships: 0.8s (Iteration 2)
```

**This is the ReAct pattern:**
1. **Thought** (LLM): What should I do?
2. **Action** (Tool): Execute security function
3. **Observation** (LLM): What did I learn?
4. **Repeat** until answer is complete

## Benchmarking Your Queries

### Typical Performance Ranges

| Query Type | Expected Time | Your Query |
|------------|--------------|------------|
| Simple count | 3-8s | - |
| Basic filter | 5-12s | - |
| Breakdown/aggregation | 15-30s | ✅ 24.7s |
| Deep investigation | 30-60s | - |
| Multi-entity correlation | 45-90s | - |

Your query falls within the expected range for breakdown queries!

## Summary

**Your Query Performance:**
- ✅ Tool execution: Excellent (0.238s)
- ✅ Iterations: Optimal (single pass)
- ⚠️ LLM time: Long but justified (detailed analysis)
- ✅ Overall: Normal for this query complexity

**Key Takeaway:**
The 98% LLM time reflects Claude doing sophisticated analysis to provide you with a comprehensive, well-formatted alert breakdown with security insights. This is **working as designed** for complex analytical queries.

**When to Worry:**
- Tool execution >5 seconds
- Multiple iterations for simple queries
- Orchestration >20%
- Total time doubles for similar queries

**When NOT to Worry:**
- High LLM percentage (this is normal)
- Long time for complex breakdown queries
- Detailed responses taking 20-30 seconds

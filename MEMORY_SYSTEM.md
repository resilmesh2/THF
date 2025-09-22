# LangChain Memory System Implementation

## Overview

This implementation adds sophisticated conversation context preservation to the Wazuh LLM Assistant using LangChain's memory components. The system now maintains conversation history across queries and can intelligently handle contextual references.

## Key Features

### 1. Session-Based Memory Management
- **Isolated Sessions**: Each session ID maintains its own conversation context
- **Memory Type**: Uses `ConversationSummaryBufferMemory` for efficient long-term context preservation
- **Automatic Context Switching**: Agent automatically switches to the appropriate session context

### 2. Context-Aware Query Processing
- **Contextual Reference Detection**: Identifies when users refer to previous results
- **Context Extraction**: Extracts hosts, users, timeframes, IPs, and alert types from conversation history
- **Intelligent Prompt Enhancement**: Adds relevant context to queries automatically

### 3. Enhanced System Prompting
- **Context Preservation Instructions**: Explicitly instructs the AI to maintain conversation context
- **Parameter Inheritance**: Maintains search parameters from previous queries unless explicitly changed
- **Reference Resolution**: Resolves contextual references like "those alerts", "that host", etc.

## Implementation Details

### WazuhSecurityAgent Changes

#### Session Memory Storage
```python
# Session-based memory storage
self.session_memories = defaultdict(lambda: self._create_session_memory())
self.current_session_id = None
```

#### Context Analysis
The system analyzes queries for contextual keywords:
- "those", "these", "that", "this"
- "the critical ones", "from there"
- "more details", "same host"
- "previously mentioned", "earlier"

#### Memory Types
- **ConversationSummaryBufferMemory**: Automatically summarizes older conversations while keeping recent messages detailed
- **Token Limit**: 2000 tokens to balance context preservation with performance
- **Auto-summarization**: Older context gets summarized to preserve memory

### API Enhancements

#### New Endpoints
- `POST /query` - Now accepts `session_id` parameter
- `POST /reset?session_id=<id>` - Reset specific session or all sessions
- `GET /session/{session_id}` - Get session information
- `GET /sessions` - Get all active sessions info

#### Session Information Response
```json
{
  "session_id": "session_123",
  "message_count": 8,
  "exists": true
}
```

### UI Improvements

#### Streamlit Interface
- **Session Management**: Visual session info and reset functionality
- **Query Types**: Separate examples for initial vs follow-up queries
- **Context Display**: Shows session state and message count
- **Enhanced Examples**: Context-aware query examples

## Usage Examples

### Context Preservation in Action

**Initial Query:**
```
User: "Show me all alerts for host 192.168.1.100 in the last 24 hours"
Assistant: [Returns alerts for host 192.168.1.100 from last 24 hours]
```

**Follow-up Query (maintains context):**
```
User: "Give me more information on the critical alerts from that host"
Assistant: [Analyzes CRITICAL alerts specifically for 192.168.1.100 in the same 24-hour timeframe]
```

**Another Follow-up:**
```
User: "What about authentication failures on the same host?"
Assistant: [Looks for authentication failures on 192.168.1.100 in the same timeframe]
```

### Context Extraction

The system extracts and tracks:
- **Hosts**: server names, IP addresses, agent names
- **Users**: usernames, accounts mentioned
- **Timeframes**: "last 24 hours", "this week", "yesterday"
- **Alert Types**: "critical", "authentication failures", "high priority"
- **IP Addresses**: Automatic regex extraction

## Configuration

### Environment Variables
```bash
# Required for basic functionality
ANTHROPIC_API_KEY=your_anthropic_key
OPENSEARCH_HOST=localhost
OPENSEARCH_PORT=9200
OPENSEARCH_USER=admin
OPENSEARCH_PASSWORD=admin

# Optional for enhanced tracing
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=your_langsmith_key
```

### Memory Configuration
```python
# Adjustable parameters in _create_session_memory()
max_token_limit=2000    # Context window size
memory_key="chat_history"  # Memory key for agent
return_messages=True    # Return as message objects
```

## Testing

### Automated Tests
Run the memory test script:
```bash
python test_memory.py
```

Tests include:
1. **Context Preservation**: Verify follow-up queries maintain context
2. **Session Isolation**: Ensure different sessions don't share context
3. **Context Extraction**: Test automatic parameter extraction
4. **Memory Reset**: Verify session reset functionality
5. **Multi-session Management**: Test concurrent session handling

### Manual Testing
1. Start the application: `python main.py`
2. Open Streamlit UI: `streamlit run streamlit_ui.py`
3. Test context preservation with follow-up queries
4. Use session management features
5. Test different session isolation

## Troubleshooting

### Common Issues

**Memory Not Preserving:**
- Check session_id is being passed consistently
- Verify agent memory initialization
- Check for session resets between queries

**Context Not Extracted:**
- Review context extraction regex patterns
- Check conversation history format
- Verify contextual keywords detection

**Performance Issues:**
- Adjust `max_token_limit` in memory configuration
- Monitor conversation length and auto-summarization
- Consider clearing old sessions periodically

### Debug Information

Enable verbose logging to see:
- Session creation and switching
- Context extraction results
- Memory state changes
- Prompt enhancement details

```python
logger.info("Session memory updated", session_id=session_id)
logger.info("Context extracted", context=context)
```

## Future Enhancements

### Potential Improvements
1. **Persistent Memory**: Store sessions in database for cross-restart persistence
2. **Advanced Context**: Extract more sophisticated security context patterns
3. **Memory Optimization**: More intelligent summarization strategies
4. **Session Management**: Automatic session cleanup and archiving
5. **Context Visualization**: UI showing extracted context and memory state

### Configuration Options
- Configurable memory types per session
- Adjustable context extraction patterns
- Custom summarization prompts
- Session timeout and cleanup policies

## Best Practices

### For Users
1. **Be Explicit**: When starting new topics, be explicit about changing context
2. **Use References**: Leverage contextual references like "that host", "those alerts"
3. **Session Management**: Use session reset when switching to unrelated topics
4. **Follow-up Queries**: Take advantage of context preservation for deeper analysis

### For Developers
1. **Session IDs**: Always pass session_id from UI to API
2. **Memory Limits**: Monitor and adjust token limits based on usage patterns
3. **Context Patterns**: Extend regex patterns for domain-specific entities
4. **Error Handling**: Implement graceful degradation when memory fails
5. **Testing**: Regular testing of context preservation across query types

This implementation solves the original issue where the agent would "forget" previous context and treat each query independently, providing a much more natural conversational experience for security analysts.
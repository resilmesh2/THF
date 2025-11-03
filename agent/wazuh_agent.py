"""
Wazuh Security Agent using LangChain
"""
from langchain.agents import initialize_agent, AgentType
from langchain.memory import ConversationSummaryBufferMemory, ConversationBufferWindowMemory
from langchain.callbacks import LangChainTracer
from langchain_anthropic import ChatAnthropic
from typing import Dict, Any, List
import structlog
import os
import asyncio
from collections import defaultdict
import hashlib
import time

from functions._shared.opensearch_client import WazuhOpenSearchClient
from tools.wazuh_tools import get_all_tools
from .context_processor import ConversationContextProcessor

logger = structlog.get_logger()

class WazuhSecurityAgent:
    """
    LangChain-based security agent for Wazuh SIEM
    """
    
    def __init__(self, anthropic_api_key: str, opensearch_config: Dict[str, Any]):
        """
        Initialize the Wazuh security agent
        
        Args:
            anthropic_api_key: Anthropic API key
            opensearch_config: OpenSearch connection configuration
        """
        self.anthropic_api_key = anthropic_api_key
        self.opensearch_config = opensearch_config
        
        # Initialize OpenSearch client
        self.opensearch_client = WazuhOpenSearchClient(**opensearch_config)

        # Initialize query response cache (2-minute TTL for repeated queries)
        self.query_cache = {}
        self.cache_ttl = 120  # 2 minutes

        # Initialize FAST LLM for reasoning/tool selection (Claude Haiku 4.5)
        # This model is 2-3x faster and cheaper for quick decision-making
        self.llm_fast = ChatAnthropic(
            model="claude-3-5-haiku-20241022",
            temperature=0.1,
            anthropic_api_key=anthropic_api_key,
            max_tokens=1000,  # Lower for faster reasoning
            timeout=15,
            streaming=True  # Enable streaming for better perceived performance
        )

        # Initialize MAIN LLM for final response generation (Claude Sonnet 4)
        # This model provides higher quality, comprehensive responses
        self.llm = ChatAnthropic(
            model="claude-sonnet-4-20250514",
            temperature=0.1,
            anthropic_api_key=anthropic_api_key,
            max_tokens=1500,  # Reduced from 3000 for faster responses
            timeout=30,
            streaming=True  # Enable streaming for better perceived performance
        )
        
        # Initialize tools
        self.tools = get_all_tools(self.opensearch_client, self)
        
        # Initialize session-based memory storage
        self.session_memories = defaultdict(lambda: self._create_session_memory())
        self.current_session_id = None

        # Initialize default memory for backwards compatibility
        self.memory = self._create_session_memory()

        # Initialize context processor
        self.context_processor = ConversationContextProcessor()

        # Enhanced system prompt with context preservation instructions
        # MUST be defined before agent initialization
        self.system_prompt = """You are a Wazuh SIEM security analyst assistant.

EFFICIENCY RULE - READ CAREFULLY:
- Call each tool ONLY ONCE with appropriate parameters
- Tools return COMPLETE ANALYZED DATA - do NOT call again to "analyze" what you already have
- After receiving tool results, IMMEDIATELY provide your Final Answer
- Do NOT make redundant calls with the same parameters

RESPONSE FORMAT:
Put your FULL DETAILED ANALYSIS in the Final Answer action_input field (not just a summary).
Include all severity distributions, alert types, timelines, and security insights.

CONTEXT PRESERVATION:
When users reference "these alerts", "this host", "that process", etc., use parameters from previous queries.
"""

        # Initialize callbacks
        callbacks = []
        # Only enable LangSmith tracing if properly configured
        try:
            if os.getenv("LANGCHAIN_TRACING_V2") == "true" and os.getenv("LANGCHAIN_API_KEY"):
                callbacks.append(LangChainTracer())
                logger.info("LangSmith tracing enabled")
        except Exception as e:
            logger.warning("Failed to initialize LangSmith tracing", error=str(e))

        # Initialize agent with FAST model for reasoning
        # Use Haiku for tool selection (faster), Sonnet generates final response
        self.agent = initialize_agent(
            tools=self.tools,
            llm=self.llm_fast,  # Use fast model for reasoning/tool selection
            agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
            memory=self.memory,
            verbose=True,
            max_iterations=3,  # Strict limit: 1 tool call + 1 final answer = 2 iterations max
            early_stopping_method="force",  # Force stop to prevent excessive iterations
            callbacks=callbacks,
            handle_parsing_errors=True,
            agent_kwargs={
                "prefix": self.system_prompt,
                "format_instructions": "After ONE successful tool call, immediately provide your complete Final Answer. Do NOT call tools multiple times."
            }
        )

        logger.info("Wazuh Security Agent initialized",
                   tools_count=len(self.tools),
                   reasoning_model="claude-haiku-3.5",
                   response_model="claude-sonnet-4",
                   streaming_enabled=True,
                   cache_enabled=True,
                   max_iterations=3)

    def _create_session_memory(self):
        """
        Create a new memory instance for a session

        Uses ConversationBufferWindowMemory instead of ConversationSummaryBufferMemory
        to avoid LLM calls for memory summarization (saves 2-3 seconds per query)
        """
        return ConversationBufferWindowMemory(
            k=7,  # Keep last 7 message pairs (no LLM summarization needed)
            memory_key="chat_history",
            return_messages=True,
            output_key="output"
        )

    def _get_session_memory(self, session_id: str):
        """Get or create memory for a specific session"""
        if session_id not in self.session_memories:
            logger.info("Creating new session memory", session_id=session_id)
        return self.session_memories[session_id]

    def _update_agent_memory(self, session_id: str):
        """Update the agent's memory to use the session-specific memory"""
        if self.current_session_id != session_id:
            self.current_session_id = session_id
            session_memory = self._get_session_memory(session_id)

            # Re-initialize agent with session-specific memory
            callbacks = []
            try:
                if os.getenv("LANGCHAIN_TRACING_V2") == "true" and os.getenv("LANGCHAIN_API_KEY"):
                    callbacks.append(LangChainTracer())
            except Exception as e:
                logger.warning("Failed to initialize LangSmith tracing", error=str(e))

            self.agent = initialize_agent(
                tools=self.tools,
                llm=self.llm_fast,  # Use fast model for reasoning/tool selection
                agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
                memory=session_memory,
                verbose=True,
                max_iterations=3,  # Strict limit: 1 tool call + 1 final answer = 2 iterations max
                early_stopping_method="force",  # Force stop to prevent excessive iterations
                callbacks=callbacks,
                handle_parsing_errors=True,
                agent_kwargs={
                    "prefix": self.system_prompt,
                    "format_instructions": "After ONE successful tool call, immediately provide your complete Final Answer. Do NOT call tools multiple times."
                }
            )

            logger.info("Agent memory updated for session", session_id=session_id)

    async def query(self, user_input: str, session_id: str = "default") -> str:
        """
        Process user query and return response with session-based context

        Implements query caching with 2-minute TTL for repeated queries

        Args:
            user_input: User's natural language query
            session_id: Unique session identifier for conversation context

        Returns:
            Agent's response
        """
        try:
            # Check cache for repeated queries (2-minute TTL)
            cache_key = self._generate_cache_key(user_input, session_id)
            cached_response = self._get_from_cache(cache_key)
            if cached_response:
                logger.info("Returning cached response",
                           query_preview=user_input[:100],
                           session_id=session_id,
                           cache_hit=True)
                return cached_response

            # Update agent memory for this session
            self._update_agent_memory(session_id)

            # Get conversation history for context analysis
            session_memory = self._get_session_memory(session_id)
            chat_history = session_memory.chat_memory.messages if hasattr(session_memory, 'chat_memory') else []

            # Process context separately from LLM prompt
            context_result = self.context_processor.process_query_with_context(user_input, chat_history)

            logger.info("Processing agent query with session context",
                       query_preview=user_input[:100],
                       session_id=session_id,
                       history_length=len(chat_history),
                       context_applied=context_result["context_applied"],
                       reasoning=context_result["reasoning"],
                       cache_hit=False)

            # Create enriched input with context for LLM when context is applied
            enriched_input = user_input
            if context_result["context_applied"]:
                enriched_input = self._create_context_enriched_input(user_input, context_result)

            # Execute agent with context-aware input
            response = await self._execute_with_retry(enriched_input, context_result)

            # Cache the response for 2 minutes
            self._add_to_cache(cache_key, response)

            logger.info("Agent query completed with context",
                       query_preview=user_input[:100],
                       session_id=session_id,
                       response_length=len(response))

            return response

        except Exception as e:
            logger.error("Agent query failed",
                        error=str(e),
                        query_preview=user_input[:100],
                        session_id=session_id)
            return f"I encountered an error processing your request: {str(e)}"

    async def _execute_with_retry(self, user_input: str, context_result: Dict[str, Any], max_retries: int = 2) -> str:
        """Execute agent with retry logic for API overload"""
        # Store context result for tool execution
        self._current_context_result = context_result

        for attempt in range(max_retries + 1):
            try:
                # Agent expects input as dict with "input" key for STRUCTURED_CHAT type
                response = await self.agent.ainvoke({"input": user_input})

                # Extract the output from the response dict
                # Check if response contains intermediate_steps (full agent reasoning)
                output = response.get("output", "")

                # If the output is too short (likely just a summary), try to extract full reasoning
                if len(output) < 100 and "intermediate_steps" in response:
                    # Try to extract the full agent scratchpad/reasoning
                    logger.debug("Output seems truncated, checking intermediate steps",
                               output_length=len(output),
                               has_intermediate=True)

                    # For STRUCTURED_CHAT agents, the full response might be in the intermediate_steps
                    # or we need to reconstruct it from the agent's reasoning
                    # For now, fallback to the output field
                    pass

                return output if output else str(response)
            except Exception as e:
                error_str = str(e)
                error_type = type(e).__name__

                # Log detailed error information for debugging
                logger.error("Agent execution error",
                           error_type=error_type,
                           error_message=error_str,
                           user_input_preview=user_input[:200],
                           context_filters=context_result.get("suggested_filters", {}),
                           attempt=attempt + 1)

                if "overloaded" in error_str.lower() or "529" in error_str:
                    if attempt < max_retries:
                        wait_time = (2 ** attempt) * 2  # Exponential backoff: 2s, 4s
                        logger.warning(f"API overloaded, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries + 1})")
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        return "I apologize, but the system is currently experiencing high load. Please try your query again in a few moments, or try a more specific question to reduce processing requirements."
                elif "500" in error_str or "api_error" in error_str.lower():
                    # API 500 errors - provide helpful context
                    return f"The AI service encountered an error processing your query. This may be due to: (1) ambiguous entity references - try being more specific (e.g., use full process path instead of just name), (2) complex contextual queries - try rephrasing with explicit parameters, or (3) temporary API issues. Original error: {error_str}"
                else:
                    # Non-overload error, don't retry
                    raise e

        return "Unable to process request due to system overload."

    def _create_context_enriched_input(self, user_input: str, context_result: Dict[str, Any]) -> str:
        """
        Create enriched input that includes context information for the LLM

        Args:
            user_input: Original user input
            context_result: Result from context processor

        Returns:
            Enriched input with context guidance
        """
        suggested_filters = context_result.get("suggested_filters", {})
        suggested_time_range = context_result.get("suggested_time_range")

        # Build context hints
        context_parts = []

        if "host" in suggested_filters:
            context_parts.append(f'host {suggested_filters["host"]} (use "host": "{suggested_filters["host"]}")')

        if suggested_time_range:
            context_parts.append(f"timeframe {suggested_time_range}")

        if "rule.level" in suggested_filters:
            level_filter = suggested_filters["rule.level"]
            if isinstance(level_filter, dict) and "gte" in level_filter:
                if level_filter["gte"] == 12:
                    context_parts.append('critical alerts (use "rule.level": {"gte": 12})')
                elif level_filter["gte"] == 8:
                    context_parts.append('high severity alerts (use "rule.level": {"gte": 8})')

        if "rule.groups" in suggested_filters:
            groups = suggested_filters["rule.groups"]
            if isinstance(groups, list):
                context_parts.append(f"rule groups {', '.join(groups)}")

        # Create enriched input
        if context_parts:
            context_hint = f"[Context from previous query: {', '.join(context_parts)}] "
            enriched_input = context_hint + user_input

            logger.info("Created context-enriched input",
                       original=user_input,
                       context_parts=context_parts,
                       enriched_preview=enriched_input[:150])

            return enriched_input

        return user_input

    def _generate_cache_key(self, user_input: str, session_id: str) -> str:
        """
        Generate cache key for query caching

        Args:
            user_input: User query
            session_id: Session identifier

        Returns:
            Hash-based cache key
        """
        cache_string = f"{session_id}:{user_input}"
        return hashlib.md5(cache_string.encode()).hexdigest()

    def _get_from_cache(self, cache_key: str) -> str:
        """
        Retrieve cached response if available and not expired

        Args:
            cache_key: Cache key

        Returns:
            Cached response or None if expired/not found
        """
        if cache_key in self.query_cache:
            cached_data = self.query_cache[cache_key]
            # Check if cache entry has expired (2-minute TTL)
            if time.time() - cached_data["timestamp"] < self.cache_ttl:
                return cached_data["response"]
            else:
                # Remove expired entry
                del self.query_cache[cache_key]
        return None

    def _add_to_cache(self, cache_key: str, response: str):
        """
        Add response to cache with timestamp

        Args:
            cache_key: Cache key
            response: Response to cache
        """
        self.query_cache[cache_key] = {
            "response": response,
            "timestamp": time.time()
        }

        # Clean up expired cache entries (keep cache size under control)
        current_time = time.time()
        expired_keys = [
            key for key, data in self.query_cache.items()
            if current_time - data["timestamp"] >= self.cache_ttl
        ]
        for key in expired_keys:
            del self.query_cache[key]

        logger.debug("Response cached",
                    cache_key=cache_key,
                    cache_size=len(self.query_cache))

    async def reset_memory(self, session_id: str = None):
        """Reset conversation memory and cache for a session or all sessions"""
        try:
            if session_id:
                # Reset specific session
                if session_id in self.session_memories:
                    self.session_memories[session_id].clear()
                    logger.info("Session memory reset", session_id=session_id)
                else:
                    logger.info("Session not found for reset", session_id=session_id)

                # Clear cache entries for this session
                session_cache_keys = [
                    key for key in self.query_cache.keys()
                    if key.startswith(hashlib.md5(f"{session_id}:".encode()).hexdigest()[:8])
                ]
                for key in session_cache_keys:
                    del self.query_cache[key]
            else:
                # Reset all sessions
                self.session_memories.clear()
                self.current_session_id = None
                self.memory.clear()
                self.query_cache.clear()  # Clear all cache
                logger.info("All session memories and cache reset")
        except Exception as e:
            logger.error("Failed to reset memory", error=str(e), session_id=session_id)
            raise

    def get_session_info(self, session_id: str = None) -> dict:
        """Get information about active sessions"""
        if session_id:
            session_memory = self.session_memories.get(session_id)
            if session_memory and hasattr(session_memory, 'chat_memory'):
                return {
                    "session_id": session_id,
                    "message_count": len(session_memory.chat_memory.messages),
                    "exists": True
                }
            return {"session_id": session_id, "exists": False}
        else:
            return {
                "total_sessions": len(self.session_memories),
                "active_sessions": list(self.session_memories.keys()),
                "current_session": self.current_session_id
            }

    async def test_connection(self) -> bool:
        """
        Test connection to OpenSearch
        
        Returns:
            True if connection successful
        """
        try:
            return await self.opensearch_client.test_connection()
        except Exception as e:
            logger.error("Connection test failed", error=str(e))
            return False
    
    async def get_available_indices(self) -> List[str]:
        """
        Get list of available Wazuh indices
        
        Returns:
            List of index names
        """
        try:
            return await self.opensearch_client.get_indices()
        except Exception as e:
            logger.error("Failed to get indices", error=str(e))
            return []
    
    async def close(self):
        """Close connections and cleanup"""
        try:
            await self.opensearch_client.close()
            logger.info("Agent connections closed")
        except Exception as e:
            logger.error("Error closing agent connections", error=str(e))
    
    def get_tool_descriptions(self) -> Dict[str, str]:
        """
        Get descriptions of available tools
        
        Returns:
            Dictionary mapping tool names to descriptions
        """
        return {tool.name: tool.description for tool in self.tools}
    
    def get_system_info(self) -> Dict[str, Any]:
        """
        Get system information
        
        Returns:
            Dictionary with system information
        """
        return {
            "reasoning_model": "claude-haiku-3.5 (fast)",
            "response_model": "claude-sonnet-4 (high-quality)",
            "streaming_enabled": True,
            "cache_enabled": True,
            "cache_ttl_seconds": self.cache_ttl,
            "cached_queries": len(self.query_cache),
            "tools_available": len(self.tools),
            "tool_names": [tool.name for tool in self.tools],
            "opensearch_host": self.opensearch_config.get("host"),
            "opensearch_port": self.opensearch_config.get("port"),
            "memory_type": "ConversationBufferWindowMemory (k=7, session-based)",
            "active_sessions": len(self.session_memories),
            "max_iterations": 3,
            "agent_type": "Structured Chat Zero Shot React Description"
        }
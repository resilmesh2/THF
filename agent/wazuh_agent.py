"""
Wazuh Security Agent using LangChain
"""
from langchain.agents import initialize_agent, AgentType
from langchain.memory import ConversationBufferWindowMemory, ConversationSummaryBufferMemory
from langchain.callbacks import LangChainTracer
from langchain_anthropic import ChatAnthropic
from typing import Dict, Any, Optional, List
import structlog
import os
import asyncio
from collections import defaultdict

from functions._shared.opensearch_client import WazuhOpenSearchClient
from tools.wazuh_tools import get_all_tools

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
        
        # Initialize LLM
        self.llm = ChatAnthropic(
            model="claude-3-5-sonnet-20241022",
            temperature=0.1,
            anthropic_api_key=anthropic_api_key,
            max_tokens=3000,  # Reduced to help prevent API overload
            timeout=30  # Add timeout for overload handling
        )
        
        # Initialize tools
        self.tools = get_all_tools(self.opensearch_client)
        
        # Initialize session-based memory storage
        self.session_memories = defaultdict(lambda: self._create_session_memory())
        self.current_session_id = None

        # Initialize default memory for backwards compatibility
        self.memory = self._create_session_memory()
        
        # Initialize callbacks
        callbacks = []
        # Only enable LangSmith tracing if properly configured
        try:
            if os.getenv("LANGCHAIN_TRACING_V2") == "true" and os.getenv("LANGCHAIN_API_KEY"):
                callbacks.append(LangChainTracer())
                logger.info("LangSmith tracing enabled")
        except Exception as e:
            logger.warning("Failed to initialize LangSmith tracing", error=str(e))
        
        # Initialize agent
        self.agent = initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
            memory=self.memory,
            verbose=True,
            max_iterations=3,  # Reduced to save API calls
            early_stopping_method="generate",  # Generate response instead of force stopping
            callbacks=callbacks,
            handle_parsing_errors="Check your output and make sure it conforms to the expected format! Continue with the task."
        )
        
        # Enhanced system prompt with context preservation instructions
        self.system_prompt = """
        You are a Wazuh SIEM security analyst assistant. You help users investigate security incidents,
        analyze alerts, and understand their security posture.

        IMPORTANT CONTEXT PRESERVATION:
        - Always consider the full conversation history when responding to queries
        - When users refer to previous results (using words like "those alerts", "the critical ones", "from there", "that host"),
          maintain the same filters, timeframes, and host specifications from the previous query unless explicitly told otherwise
        - If a user asks for "more details" or "critical alerts", apply those filters to the SAME context from the previous query
        - Track the current active context: host names, IP addresses, time ranges, alert types, etc.
        - Inherit and maintain search parameters from previous queries in the conversation
        - CRITICAL: When specific tool usage instructions are provided in context, you MUST follow them exactly

        Key guidelines:
        - Always use the appropriate tools for data retrieval
        - Provide actionable security insights
        - Highlight critical findings and potential threats
        - Explain technical concepts in clear terms
        - Suggest follow-up investigations when relevant
        - Maintain security context in all responses
        - Focus on the most important security information
        - If a tool returns placeholder data, acknowledge it's not yet implemented

        Available tools cover:
        - Entity investigation for specific hosts, users, processes, files, IPs (investigate_entity)
        - Alert analysis and statistics across multiple alerts (analyze_alerts)
        - Threat detection and MITRE ATT&CK mapping (detect_threats)
        - Relationship mapping between entities (map_relationships)
        - Anomaly detection (find_anomalies)
        - Timeline reconstruction (trace_timeline)
        - Vulnerability checking (check_vulnerabilities)
        - Agent monitoring (monitor_agents)

        TOOL USAGE EXAMPLES:
        For PowerShell process investigation on a specific host, use:
        analyze_alerts with action="filtering", filters={"agent.id": "[host_id]", "process.name": "powershell.exe"}

        For PowerShell process investigation globally, use:
        investigate_entity with entity_type="process", entity_id="powershell.exe", query_type="alerts"

        For specific host investigation, use:
        investigate_entity with entity_type="host", entity_id="[host_id]", query_type="alerts"

        IMPORTANT: When investigating processes on a specific host, always use analyze_alerts with host filters to maintain context.

        Always provide context about what the data means from a security perspective.
        """
        
        logger.info("Wazuh Security Agent initialized",
                   tools_count=len(self.tools),
                   model="claude-3-5-sonnet")

    def _create_session_memory(self):
        """Create a new memory instance for a session"""
        # Use ConversationSummaryBufferMemory for better context management
        return ConversationSummaryBufferMemory(
            llm=self.llm,
            max_token_limit=1500,  # Reduced to prevent API overload
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
                llm=self.llm,
                agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
                memory=session_memory,
                verbose=True,
                max_iterations=5,
                early_stopping_method="force",
                callbacks=callbacks,
                handle_parsing_errors="Check your output and make sure it conforms to the expected format! Continue with the task."
            )

            logger.info("Agent memory updated for session", session_id=session_id)
    
    async def query(self, user_input: str, session_id: str = "default") -> str:
        """
        Process user query and return response with session-based context

        Args:
            user_input: User's natural language query
            session_id: Unique session identifier for conversation context

        Returns:
            Agent's response
        """
        try:
            # Update agent memory for this session
            self._update_agent_memory(session_id)

            # Get conversation history for context analysis
            session_memory = self._get_session_memory(session_id)
            chat_history = session_memory.chat_memory.messages if hasattr(session_memory, 'chat_memory') else []

            # Analyze the query for contextual references
            context_aware_prompt = self._enhance_prompt_with_context(user_input, chat_history)

            logger.info("Processing agent query with session context",
                       query_preview=user_input[:100],
                       session_id=session_id,
                       history_length=len(chat_history))

            # Execute agent with context-aware prompt and retry logic
            response = await self._execute_with_retry(context_aware_prompt)

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

    async def _execute_with_retry(self, prompt: str, max_retries: int = 2) -> str:
        """Execute agent with retry logic for API overload"""
        for attempt in range(max_retries + 1):
            try:
                response = await self.agent.arun(prompt)
                return response
            except Exception as e:
                error_str = str(e)
                if "overloaded" in error_str.lower() or "529" in error_str:
                    if attempt < max_retries:
                        wait_time = (2 ** attempt) * 2  # Exponential backoff: 2s, 4s
                        logger.warning(f"API overloaded, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries + 1})")
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        return "I apologize, but the system is currently experiencing high load. Please try your query again in a few moments, or try a more specific question to reduce processing requirements."
                else:
                    # Non-overload error, don't retry
                    raise e

        return "Unable to process request due to system overload."

    def _enhance_prompt_with_context(self, user_input: str, chat_history: list) -> str:
        """
        Enhance the user prompt with context analysis and previous conversation context

        Args:
            user_input: Current user query
            chat_history: Previous conversation messages

        Returns:
            Enhanced prompt with context instructions
        """
        # Check for contextual references in the query
        contextual_keywords = [
            "those", "these", "that", "this", "the critical ones", "the high priority",
            "from there", "on that host", "for that user", "more details", "more information",
            "same host", "same user", "same timeframe", "same period", "those alerts",
            "critical alerts", "high severity", "from before", "previously mentioned",
            "the ones", "earlier", "above", "mentioned", "said alerts", "said events",
            "these alerts", "these events", "those processes", "these processes"
        ]

        has_contextual_reference = any(keyword in user_input.lower() for keyword in contextual_keywords)

        # Extract previous context if available
        previous_context = self._extract_previous_context(chat_history) if chat_history else {}

        # Build enhanced prompt - put context at the very beginning for maximum visibility
        enhanced_prompt = ""

        if has_contextual_reference and previous_context:
            enhanced_prompt += "*** IMMEDIATE CONTEXT INSTRUCTIONS ***\n"

            # Check if it's a PowerShell-related query
            if "powershell" in user_input.lower():
                time_range = "10h" if any("10 hour" in tf for tf in previous_context.get("timeframes", [])) else "24h"

                if previous_context.get("hosts"):
                    host_id = previous_context["hosts"][0]
                    enhanced_prompt += f"MANDATORY: Use analyze_alerts with action='filtering', filters={{'agent.id': '{host_id}', 'process.name': 'powershell.exe'}}, time_range='{time_range}'\n"
                    enhanced_prompt += f"HOST ID MUST BE: '{host_id}' (NOT 'specifications' or any other value!)\n"
                else:
                    enhanced_prompt += f"MANDATORY: Use investigate_entity with entity_type='process', entity_id='powershell.exe', query_type='alerts', time_range='{time_range}'\n"

            enhanced_prompt += f"CONTEXT: {previous_context}\n"
            enhanced_prompt += "The user is referring to previous results. Maintain these exact parameters.\n\n"

        if has_contextual_reference and not previous_context:
            enhanced_prompt += "WARNING: The user appears to be referencing previous information, but no prior context was found. Ask for clarification if needed.\n\n"

        enhanced_prompt += f"{self.system_prompt}\n\n"
        enhanced_prompt += f"Current user query: {user_input}"

        return enhanced_prompt

    def _extract_previous_context(self, chat_history: list) -> dict:
        """
        Extract relevant context from previous conversation messages

        Args:
            chat_history: List of previous conversation messages

        Returns:
            Dictionary containing extracted context
        """
        context = {
            "hosts": [],
            "users": [],
            "timeframes": [],
            "alert_types": [],
            "ip_addresses": [],
            "last_query_type": None
        }

        # Look at recent messages (last 4-6 messages)
        recent_messages = chat_history[-6:] if len(chat_history) > 6 else chat_history

        for message in recent_messages:
            if hasattr(message, 'content'):
                content = message.content.lower()

                # Extract hosts (looking for patterns like "host 123", "server-name", etc.)
                import re
                host_patterns = [
                    r'\bhost\s+(\d+)\b',  # Matches "host 012", "host 123" with word boundaries
                    r'\bon\s+host\s+(\d+)\b',  # Matches "on host 012"
                    r'\bfor\s+host\s+(\d+)\b',  # Matches "for host 012"
                    r'\bfrom\s+host\s+(\d+)\b',  # Matches "from host 012"
                    r'\bthat\s+host\b.*?\b(\d{3})\b',  # "that host" followed by 3-digit number
                ]
                for pattern in host_patterns:
                    matches = re.findall(pattern, content)
                    context["hosts"].extend(matches)

                # Extract IP addresses
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ip_matches = re.findall(ip_pattern, content)
                context["ip_addresses"].extend(ip_matches)

                # Extract users
                user_patterns = [
                    r'\buser\s+([a-zA-Z][a-zA-Z0-9_.-]+)\b',  # User followed by valid username
                    r'\busername\s+([a-zA-Z][a-zA-Z0-9_.-]+)\b',
                    r'\baccount\s+([a-zA-Z][a-zA-Z0-9_.-]+)\b'
                ]
                for pattern in user_patterns:
                    matches = re.findall(pattern, content)
                    context["users"].extend(matches)

                # Extract timeframes
                time_patterns = [
                    r'(last \d+ \w+)',
                    r'(past \d+ \w+)',
                    r'(over the (?:past|last) \d+ \w+)',  # "over the past 10 hours"
                    r'(\d+ hours?)',
                    r'(\d+ days?)',
                    r'(this week)',
                    r'(today)',
                    r'(yesterday)'
                ]
                for pattern in time_patterns:
                    matches = re.findall(pattern, content)
                    context["timeframes"].extend(matches)

                # Extract alert types
                if "critical" in content:
                    context["alert_types"].append("critical")
                if "high" in content:
                    context["alert_types"].append("high")
                if "failed login" in content or "authentication fail" in content:
                    context["alert_types"].append("authentication_failed")

        # Remove duplicates and clean up
        for key in context:
            if isinstance(context[key], list):
                context[key] = list(set(context[key]))

        # Prioritize numeric hosts (like "012") over text matches
        if context["hosts"]:
            numeric_hosts = [h for h in context["hosts"] if h.isdigit()]
            if numeric_hosts:
                # Put numeric hosts first
                context["hosts"] = numeric_hosts + [h for h in context["hosts"] if not h.isdigit()]

        return context
    
    async def reset_memory(self, session_id: str = None):
        """Reset conversation memory for a session or all sessions"""
        try:
            if session_id:
                # Reset specific session
                if session_id in self.session_memories:
                    self.session_memories[session_id].clear()
                    logger.info("Session memory reset", session_id=session_id)
                else:
                    logger.info("Session not found for reset", session_id=session_id)
            else:
                # Reset all sessions
                self.session_memories.clear()
                self.current_session_id = None
                self.memory.clear()
                logger.info("All session memories reset")
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
            "model": "claude-3-5-sonnet",
            "tools_available": len(self.tools),
            "tool_names": [tool.name for tool in self.tools],
            "opensearch_host": self.opensearch_config.get("host"),
            "opensearch_port": self.opensearch_config.get("port"),
            "memory_type": "ConversationSummaryBufferMemory (Session-based)",
            "active_sessions": len(self.session_memories),
            "agent_type": "Structured Chat Zero Shot React Description"
        }
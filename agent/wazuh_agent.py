"""
Wazuh Security Agent using LangChain
"""
from langchain.agents import initialize_agent, AgentType
from langchain.memory import ConversationBufferMemory
from langchain.callbacks import LangChainTracer
from langchain_anthropic import ChatAnthropic
from typing import Dict, Any, Optional, List
import structlog
import os

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
            max_tokens=4000
        )
        
        # Initialize tools
        self.tools = get_all_tools(self.opensearch_client)
        
        # Initialize memory
        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True,
            output_key="output"
        )
        
        # Initialize callbacks
        callbacks = []
        if os.getenv("LANGCHAIN_TRACING_V2") == "true":
            callbacks.append(LangChainTracer())
        
        # Initialize agent
        self.agent = initialize_agent(
            tools=self.tools,
            llm=self.llm,
            agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION,
            memory=self.memory,
            verbose=True,
            max_iterations=3,
            early_stopping_method="generate",
            callbacks=callbacks,
            handle_parsing_errors=True
        )
        
        # System prompt for security context
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
        
        Always provide context about what the data means from a security perspective.
        """
        
        logger.info("Wazuh Security Agent initialized", 
                   tools_count=len(self.tools),
                   model="claude-3-5-sonnet")
    
    async def query(self, user_input: str) -> str:
        """
        Process user query and return response
        
        Args:
            user_input: User's natural language query
            
        Returns:
            Agent's response
        """
        try:
            # Add system context to query
            full_prompt = f"{self.system_prompt}\n\nUser query: {user_input}"
            
            logger.info("Processing agent query", 
                       query_preview=user_input[:100])
            
            # Execute agent
            response = await self.agent.arun(full_prompt)
            
            logger.info("Agent query completed", 
                       query_preview=user_input[:100],
                       response_length=len(response))
            
            return response
            
        except Exception as e:
            logger.error("Agent query failed", 
                        error=str(e), 
                        query_preview=user_input[:100])
            return f"I encountered an error processing your request: {str(e)}"
    
    async def reset_memory(self):
        """Reset conversation memory"""
        try:
            self.memory.clear()
            logger.info("Agent memory reset")
        except Exception as e:
            logger.error("Failed to reset memory", error=str(e))
            raise
    
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
            "memory_type": "ConversationBufferMemory",
            "agent_type": "Structured Chat Zero Shot React Description"
        }
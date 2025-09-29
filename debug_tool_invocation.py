#!/usr/bin/env python3
"""
Debug script to test tool invocation and identify the root cause
of the "Missing some input keys" error.
"""
import asyncio
import os
import sys
import traceback
import logging
from typing import Dict, Any

# Configure logging to capture all details
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Import the required modules
sys.path.append('.')

async def test_direct_tool_invocation():
    """Test tools directly without the agent to isolate the issue"""
    print("=== Testing Direct Tool Invocation ===")

    try:
        # Import required modules
        from functions._shared.opensearch_client import WazuhOpenSearchClient
        from tools.wazuh_tools import AnalyzeAlertsTool, InvestigateEntityTool

        # Create a mock OpenSearch client (since we're testing tool structure)
        class MockOpenSearchClient:
            def __init__(self):
                pass

        mock_client = MockOpenSearchClient()

        # Test AnalyzeAlertsTool
        print("\n--- Testing AnalyzeAlertsTool ---")
        analyze_tool = AnalyzeAlertsTool(mock_client, None)

        print(f"Tool name: {analyze_tool.name}")
        print(f"Tool schema: {analyze_tool.args_schema}")
        print(f"Schema fields: {list(analyze_tool.args_schema.model_fields.keys())}")

        # Test with kwargs that should work
        test_kwargs = {
            'action': 'counting',
            'group_by': 'host',
            'time_range': '6h'
        }

        print(f"Testing with kwargs: {test_kwargs}")

        try:
            # This will fail because we don't have real OpenSearch, but should show parameter validation
            result = analyze_tool._run(**test_kwargs)
            print(f"Tool result: {result}")
        except Exception as e:
            print(f"Tool execution error (expected): {str(e)}")
            print(f"Error type: {type(e)}")
            traceback.print_exc()

        # Test InvestigateEntityTool
        print("\n--- Testing InvestigateEntityTool ---")
        investigate_tool = InvestigateEntityTool(mock_client, None)

        print(f"Tool name: {investigate_tool.name}")
        print(f"Tool schema: {investigate_tool.args_schema}")
        print(f"Schema fields: {list(investigate_tool.args_schema.model_fields.keys())}")

        test_kwargs2 = {
            'entity_type': 'host',
            'entity_id': 'U209-PC-BLEE',
            'query_type': 'status'
        }

        print(f"Testing with kwargs: {test_kwargs2}")

        try:
            result = investigate_tool._run(**test_kwargs2)
            print(f"Tool result: {result}")
        except Exception as e:
            print(f"Tool execution error (expected): {str(e)}")
            print(f"Error type: {type(e)}")
            traceback.print_exc()

    except Exception as e:
        print(f"Direct tool test failed: {str(e)}")
        traceback.print_exc()

async def test_langchain_tool_integration():
    """Test tools through LangChain's tool system"""
    print("\n=== Testing LangChain Tool Integration ===")

    try:
        from functions._shared.opensearch_client import WazuhOpenSearchClient
        from tools.wazuh_tools import get_all_tools
        from langchain.schema import AgentAction
        from pydantic import ValidationError

        # Create mock client
        class MockOpenSearchClient:
            def __init__(self):
                pass

        mock_client = MockOpenSearchClient()

        # Get all tools
        tools = get_all_tools(mock_client, None)
        print(f"Available tools: {[tool.name for tool in tools]}")

        # Test each tool's schema validation
        for tool in tools:
            print(f"\n--- Testing {tool.name} ---")
            print(f"Schema: {tool.args_schema}")

            # Test with LangChain's tool.run() method
            try:
                if tool.name == "analyze_alerts":
                    test_input = {
                        "action": "counting",
                        "group_by": "host",
                        "time_range": "6h"
                    }
                elif tool.name == "investigate_entity":
                    test_input = {
                        "entity_type": "host",
                        "entity_id": "U209-PC-BLEE",
                        "query_type": "status"
                    }
                else:
                    continue  # Skip other tools for now

                print(f"Testing {tool.name} with input: {test_input}")

                # Test schema validation first
                try:
                    validated_input = tool.args_schema(**test_input)
                    print(f"Schema validation passed: {validated_input}")
                except ValidationError as ve:
                    print(f"Schema validation failed: {ve}")
                    continue

                # Test tool.run()
                try:
                    result = tool.run(test_input)
                    print(f"Tool.run() result: {result}")
                except Exception as re:
                    print(f"Tool.run() error (expected): {str(re)}")
                    print(f"Error type: {type(re)}")

            except Exception as e:
                print(f"Tool test error: {str(e)}")
                traceback.print_exc()

    except Exception as e:
        print(f"LangChain integration test failed: {str(e)}")
        traceback.print_exc()

async def test_agent_execution():
    """Test the actual agent execution with real configuration"""
    print("\n=== Testing Agent Execution ===")

    try:
        # Check if we have environment variables
        anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        if not anthropic_key:
            print("WARNING: ANTHROPIC_API_KEY not found in environment")
            return

        # Import agent
        from agent.wazuh_agent import WazuhSecurityAgent

        # Mock OpenSearch config
        opensearch_config = {
            "host": "localhost",
            "port": 9200,
            "username": "admin",
            "password": "admin",
            "use_ssl": False,
            "verify_certs": False
        }

        # Create agent
        agent = WazuhSecurityAgent(anthropic_key, opensearch_config)

        # Test queries
        test_queries = [
            "Count alerts for each agent over the past six hours.",
            "Show a status report on the host U209-PC-BLEE since 6AM this morning."
        ]

        for query in test_queries:
            print(f"\n--- Testing Query: {query} ---")
            try:
                # Use a test session ID
                result = await agent.query(query, "debug_session_123")
                print(f"Agent result: {result}")
            except Exception as e:
                print(f"Agent query error: {str(e)}")
                print(f"Error type: {type(e)}")
                traceback.print_exc()

    except Exception as e:
        print(f"Agent execution test failed: {str(e)}")
        traceback.print_exc()

async def main():
    """Run all tests"""
    print("Starting comprehensive tool debugging...")
    print("=" * 60)

    # Test 1: Direct tool invocation
    await test_direct_tool_invocation()

    # Test 2: LangChain integration
    await test_langchain_tool_integration()

    # Test 3: Agent execution (if API key available)
    await test_agent_execution()

    print("\n" + "=" * 60)
    print("Debugging complete!")

if __name__ == "__main__":
    asyncio.run(main())
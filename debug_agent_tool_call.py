#!/usr/bin/env python3
"""
Debug script to test the actual agent tool calling mechanism
"""
import os
import sys
import json
import logging
from typing import Dict, Any

# Configure logging to capture all details
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

sys.path.append('.')

def test_tool_call_direct():
    """Test what happens when we manually call a tool the way LangChain does"""
    print("=== Testing Direct Tool Call (LangChain Style) ===")

    try:
        from functions._shared.opensearch_client import WazuhOpenSearchClient
        from tools.wazuh_tools import AnalyzeAlertsTool, InvestigateEntityTool

        # Create a mock client
        class MockOpenSearchClient:
            def __init__(self):
                pass

        mock_client = MockOpenSearchClient()

        # Test AnalyzeAlertsTool with the exact parameters from your query
        print("\n--- Testing AnalyzeAlertsTool ---")
        tool = AnalyzeAlertsTool(mock_client, None)

        # Try different parameter combinations that might be causing the issue
        test_cases = [
            {
                'name': 'Simple counting query',
                'params': {'action': 'counting', 'group_by': 'host', 'time_range': '6h'}
            },
            {
                'name': 'Query with host filter',
                'params': {'action': 'filtering', 'filters': {'host': 'U209-PC-BLEE'}, 'time_range': '6h'}
            },
            {
                'name': 'LLM might pass host at top level (wrong)',
                'params': {'action': 'filtering', 'host': 'U209-PC-BLEE', 'time_range': '6h'}
            }
        ]

        for test_case in test_cases:
            print(f"\nTesting: {test_case['name']}")
            print(f"Parameters: {test_case['params']}")

            try:
                # First test schema validation
                validated = tool.args_schema(**test_case['params'])
                print(f"✅ Schema validation passed: {validated}")
            except Exception as e:
                print(f"❌ Schema validation failed: {str(e)}")
                print(f"   Error type: {type(e)}")
                continue

            try:
                # Test tool.run() (this is what LangChain calls)
                # We'll catch the async error but see what parameters are passed
                result = tool.run(test_case['params'])
                print(f"✅ Tool.run() succeeded: {result}")
            except Exception as e:
                print(f"⚠️ Tool.run() error (expected): {str(e)}")
                print(f"   Error type: {type(e)}")

        # Test InvestigateEntityTool
        print("\n--- Testing InvestigateEntityTool ---")
        tool2 = InvestigateEntityTool(mock_client, None)

        test_cases2 = [
            {
                'name': 'Host status query',
                'params': {'entity_type': 'host', 'entity_id': 'U209-PC-BLEE', 'query_type': 'status'}
            },
            {
                'name': 'LLM might pass host at top level (wrong)',
                'params': {'entity_type': 'host', 'entity_id': 'U209-PC-BLEE', 'query_type': 'status', 'host': 'U209-PC-BLEE'}
            }
        ]

        for test_case in test_cases2:
            print(f"\nTesting: {test_case['name']}")
            print(f"Parameters: {test_case['params']}")

            try:
                # Test schema validation
                validated = tool2.args_schema(**test_case['params'])
                print(f"✅ Schema validation passed: {validated}")
            except Exception as e:
                print(f"❌ Schema validation failed: {str(e)}")
                print(f"   Error type: {type(e)}")
                continue

    except Exception as e:
        print(f"Test failed: {str(e)}")
        import traceback
        traceback.print_exc()

def debug_langchain_tool_calling():
    """Debug LangChain's tool calling mechanism"""
    print("\n=== Debugging LangChain Tool Calling Mechanism ===")

    try:
        from langchain.tools import BaseTool
        from langchain.schema import AgentAction
        from functions._shared.opensearch_client import WazuhOpenSearchClient
        from tools.wazuh_tools import AnalyzeAlertsTool

        # Create tool
        mock_client = type('MockClient', (), {})()
        tool = AnalyzeAlertsTool(mock_client, None)

        print(f"Tool name: {tool.name}")
        print(f"Tool description: {tool.description}")
        print(f"Tool args_schema: {tool.args_schema}")

        # Check the tool's input schema
        print(f"Tool input schema: {tool.get_input_schema()}")

        # Try to create an agent action (this is what LangChain does internally)
        action = AgentAction(
            tool='analyze_alerts',
            tool_input={'action': 'counting', 'group_by': 'host', 'time_range': '6h'},
            log='Testing action'
        )

        print(f"AgentAction created: {action}")

        # Test the tool's invoke method directly
        try:
            # This should show us what parameters LangChain expects
            schema_dict = tool.get_input_schema().schema()
            print(f"Tool input schema dict: {json.dumps(schema_dict, indent=2)}")
        except Exception as e:
            print(f"Schema introspection error: {str(e)}")

    except Exception as e:
        print(f"LangChain debugging failed: {str(e)}")
        import traceback
        traceback.print_exc()

def check_environment_and_imports():
    """Check the environment and imports for any issues"""
    print("\n=== Environment Check ===")

    try:
        # Check Python version
        print(f"Python version: {sys.version}")

        # Check key packages
        import langchain
        print(f"LangChain version: {langchain.__version__}")

        import pydantic
        print(f"Pydantic version: {pydantic.__version__}")

        # Check if environment variables are set
        print(f"ANTHROPIC_API_KEY set: {'Yes' if os.getenv('ANTHROPIC_API_KEY') else 'No'}")

        # Check current working directory
        print(f"Current working directory: {os.getcwd()}")

        # Check if we can import all required modules
        print("\nImporting modules...")
        from agent.wazuh_agent import WazuhSecurityAgent
        print("✅ WazuhSecurityAgent imported")

        from tools.wazuh_tools import get_all_tools
        print("✅ get_all_tools imported")

        from schemas.wazuh_schemas import AnalyzeAlertsSchema
        print("✅ AnalyzeAlertsSchema imported")

    except Exception as e:
        print(f"Environment check failed: {str(e)}")
        import traceback
        traceback.print_exc()

def main():
    """Run all debugging tests"""
    print("Starting detailed agent tool call debugging...")
    print("=" * 70)

    check_environment_and_imports()
    test_tool_call_direct()
    debug_langchain_tool_calling()

    print("\n" + "=" * 70)
    print("Debugging complete!")

if __name__ == "__main__":
    main()
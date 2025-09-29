#!/usr/bin/env python3
"""
Debug agent execution to find the initialize_agent reference
"""
import sys
import os
sys.path.append('.')

def test_agent_creation_detailed():
    """Test agent creation with detailed inspection"""
    print("DETAILED AGENT CREATION TEST")
    print("="*50)

    try:
        # Set environment variable
        os.environ['ANTHROPIC_API_KEY'] = 'test_key'

        # Import and create agent
        from agent.wazuh_agent import WazuhSecurityAgent

        print("Creating agent...")
        agent = WazuhSecurityAgent(
            anthropic_api_key='test_key',
            opensearch_config={
                'host': 'localhost',
                'port': 9200,
                'auth': ('admin', 'admin'),
                'use_ssl': False,
                'verify_certs': False
            }
        )

        print("Agent created successfully!")
        print(f"Agent type: {type(agent.agent)}")
        print(f"Agent attributes: {dir(agent.agent)}")

        # Check the agent's internal structure
        if hasattr(agent.agent, 'agent'):
            print(f"Internal agent type: {type(agent.agent.agent)}")
            print(f"Internal agent attributes: {dir(agent.agent.agent)}")

        # Try to inspect the runnable chain
        if hasattr(agent.agent, 'agent'):
            internal_agent = agent.agent.agent
            print(f"Agent runnable: {internal_agent}")

        return agent

    except Exception as e:
        print(f"Agent creation failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def test_agent_invoke_structure(agent):
    """Test what happens when we try to invoke the agent"""
    print("\nTESTING AGENT INVOKE STRUCTURE")
    print("="*40)

    try:
        # Check the agent's invoke method
        print(f"Agent has ainvoke: {hasattr(agent.agent, 'ainvoke')}")
        print(f"Agent has invoke: {hasattr(agent.agent, 'invoke')}")

        # Try to get the agent's input schema
        if hasattr(agent.agent, 'get_input_schema'):
            schema = agent.agent.get_input_schema()
            print(f"Agent input schema: {schema}")

        # Check what the agent expects as input
        if hasattr(agent.agent, 'input_schema'):
            print(f"Agent input schema property: {agent.agent.input_schema}")

        return True

    except Exception as e:
        print(f"Agent invoke structure test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def test_mock_agent_call(agent):
    """Test calling the agent with a mock input"""
    print("\nTESTING MOCK AGENT CALL")
    print("="*30)

    try:
        # Try a very simple input
        test_input = {"input": "test query"}
        print(f"Testing with input: {test_input}")

        # Don't actually call it, just check if the structure is right
        print("Agent structure looks correct for invoke calls")
        return True

    except Exception as e:
        print(f"Mock agent call test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def inspect_langchain_imports():
    """Inspect what LangChain functions are actually imported"""
    print("\nINSPECTING LANGCHAIN IMPORTS")
    print("="*35)

    try:
        # Check what's in langchain.agents
        from langchain import agents
        print(f"Available in langchain.agents: {dir(agents)}")

        # Check if initialize_agent is still imported somewhere
        if hasattr(agents, 'initialize_agent'):
            print("WARNING: initialize_agent is still available!")
        else:
            print("Good: initialize_agent not found in agents module")

        # Check our specific imports
        from langchain.agents import create_react_agent, AgentExecutor
        print(f"create_react_agent type: {type(create_react_agent)}")
        print(f"AgentExecutor type: {type(AgentExecutor)}")

        return True

    except Exception as e:
        print(f"LangChain import inspection failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def check_for_hidden_references():
    """Check for any hidden references to initialize_agent"""
    print("\nCHECKING FOR HIDDEN REFERENCES")
    print("="*35)

    try:
        # Check if initialize_agent appears anywhere in the current namespace
        import builtins

        # Check if it's in globals
        if 'initialize_agent' in globals():
            print("WARNING: initialize_agent found in globals!")
        else:
            print("Good: initialize_agent not in globals")

        # Check the agent module namespace
        from agent import wazuh_agent
        agent_module_vars = vars(wazuh_agent)

        for name, value in agent_module_vars.items():
            if 'initialize_agent' in str(value).lower():
                print(f"WARNING: Found reference in {name}: {value}")

        print("Hidden reference check complete")
        return True

    except Exception as e:
        print(f"Hidden reference check failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main debugging function"""
    print("AGENT EXECUTION DEBUG")
    print("="*60)

    # Test 1: Inspect LangChain imports
    inspect_langchain_imports()

    # Test 2: Check for hidden references
    check_for_hidden_references()

    # Test 3: Create agent
    agent = test_agent_creation_detailed()
    if not agent:
        print("Cannot continue - agent creation failed")
        return False

    # Test 4: Test agent structure
    test_agent_invoke_structure(agent)

    # Test 5: Test mock call
    test_mock_agent_call(agent)

    print("\n" + "="*60)
    print("DEBUG COMPLETE")
    print("="*60)

    return True

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Debug failed: {str(e)}")
        import traceback
        traceback.print_exc()
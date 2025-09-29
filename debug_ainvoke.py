#!/usr/bin/env python3
"""
Debug the ainvoke call specifically
"""
import sys
import os
import asyncio
sys.path.append('.')

async def test_ainvoke_directly():
    """Test calling ainvoke directly on the agent"""
    print("TESTING AINVOKE DIRECTLY")
    print("="*40)

    try:
        # Set up environment
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

        # Test the ainvoke call directly
        print("\nTesting ainvoke with simple input...")

        try:
            result = await agent.agent.ainvoke({"input": "hello"})
            print("SUCCESS: ainvoke worked!")
            print(f"Result type: {type(result)}")
            print(f"Result: {result}")

        except Exception as e:
            print(f"FAILED: ainvoke error - {str(e)}")
            print(f"Error type: {type(e)}")

            # Check for initialize_agent
            if "initialize_agent" in str(e):
                print("*** FOUND initialize_agent error in direct ainvoke! ***")
                import traceback
                print("Full traceback:")
                traceback.print_exc()
            else:
                print("Different error - not initialize_agent related")

        return True

    except Exception as e:
        print(f"Agent creation or setup failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

async def test_agent_query_method():
    """Test the agent.query method specifically"""
    print("\n" + "="*50)
    print("TESTING AGENT.QUERY METHOD")
    print("="*50)

    try:
        # Set up environment
        os.environ['ANTHROPIC_API_KEY'] = 'test_key'

        # Import and create agent
        from agent.wazuh_agent import WazuhSecurityAgent

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

        print("Testing agent.query method...")

        try:
            result = await agent.query("hello", "debug_session")
            print("SUCCESS: agent.query worked!")
            print(f"Result: {result}")

        except Exception as e:
            print(f"FAILED: agent.query error - {str(e)}")

            if "initialize_agent" in str(e):
                print("*** FOUND initialize_agent error in agent.query! ***")
                import traceback
                print("Full traceback:")
                traceback.print_exc()

        return True

    except Exception as e:
        print(f"Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Main debug function"""
    print("DEBUGGING AINVOKE AND AGENT QUERY")
    print("="*60)

    # Test direct ainvoke
    await test_ainvoke_directly()

    # Test agent.query method
    await test_agent_query_method()

    print("\n" + "="*60)
    print("DEBUG COMPLETE")
    print("="*60)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"Debug failed: {str(e)}")
        import traceback
        traceback.print_exc()
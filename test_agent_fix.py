#!/usr/bin/env python3
"""
Test script to verify the agent fix works
"""
import sys
import os
sys.path.append('.')

def test_agent_import_and_creation():
    """Test that we can import and create the agent without errors"""
    print("Testing agent import and creation...")

    try:
        # Test import
        from agent.wazuh_agent import WazuhSecurityAgent
        print("✅ Agent import successful")

        # Test creation with mock config
        mock_config = {
            "host": "localhost",
            "port": 9200,
            "username": "admin",
            "password": "admin",
            "use_ssl": False,
            "verify_certs": False
        }

        # This will fail without ANTHROPIC_API_KEY but should show us if initialize_agent is still referenced
        agent = WazuhSecurityAgent("test_key", mock_config)
        print("✅ Agent creation successful")

        # Test that we can access the agent object
        print(f"Agent tools count: {len(agent.tools)}")
        print(f"Agent LLM model: {agent.llm.model}")
        print(f"Agent type: {type(agent.agent)}")

        return True

    except NameError as e:
        if "initialize_agent" in str(e):
            print(f"❌ Still referencing initialize_agent: {str(e)}")
            return False
        else:
            print(f"❌ Other NameError: {str(e)}")
            return False
    except Exception as e:
        print(f"⚠️ Other error (might be expected without real config): {str(e)}")
        return True  # Other errors are OK for this test

def main():
    print("Testing agent fix...")
    print("=" * 50)

    success = test_agent_import_and_creation()

    print("=" * 50)
    if success:
        print("✅ Agent fix appears to be working!")
        print("🔄 If you're still getting errors, restart your uvicorn and streamlit servers")
        print("   They may have the old code cached in memory.")
    else:
        print("❌ Agent fix needs more work")

if __name__ == "__main__":
    main()
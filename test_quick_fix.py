"""
Quick test to verify the memory fix works
"""
import asyncio
import os
from dotenv import load_dotenv

# Force reload the module
import importlib
import sys
if 'agent.wazuh_agent' in sys.modules:
    importlib.reload(sys.modules['agent.wazuh_agent'])

from agent.wazuh_agent import WazuhSecurityAgent

load_dotenv()

async def test_quick_query():
    """Quick test of a simple query"""

    print("Testing the memory fix...")

    try:
        # Create agent
        agent = WazuhSecurityAgent(
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            opensearch_config={
                "host": os.getenv("OPENSEARCH_HOST", "localhost"),
                "port": int(os.getenv("OPENSEARCH_PORT", "9200")),
                "auth": (
                    os.getenv("OPENSEARCH_USER", "admin"),
                    os.getenv("OPENSEARCH_PASSWORD", "admin")
                ),
                "use_ssl": os.getenv("OPENSEARCH_USE_SSL", "false").lower() == "true",
                "verify_certs": os.getenv("OPENSEARCH_VERIFY_CERTS", "false").lower() == "true"
            }
        )

        print("SUCCESS: Agent created successfully")

        # Test the problematic query
        query = "Show me alerts on host 012 over the last ten hours."
        session_id = "test_session"

        print(f"Testing query: {query}")

        response = await agent.query(query, session_id)

        print("SUCCESS: Query executed successfully!")
        print(f"Response length: {len(response)} characters")
        print(f"Response preview: {response[:200]}...")

        await agent.close()

    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_quick_query())
"""
Debug script to mimic exactly what FastAPI does
"""
import os
import sys
from dotenv import load_dotenv

# Load environment variables exactly like main.py
load_dotenv()

# Import exactly like main.py startup event
from agent.wazuh_agent import WazuhSecurityAgent

print("Python version:", sys.version)
print("Python path:", sys.path[:3])
print("Working directory:", os.getcwd())

# Initialize agent exactly like main.py
try:
    agent = WazuhSecurityAgent(
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        opensearch_config={
            "host": os.getenv("OPENSEARCH_HOST", "localhost"),
            "port": int(os.getenv("OPENSEARCH_PORT", "9200")),
            "auth": (
                os.getenv("OPENSEARCH_USER", "admin"),
                os.getenv("OPENSEARCH_PASSWORD", "admin")
            ),
            "use_ssl": os.getenv("OPENSEARCH_USE_SSL", "true").lower() == "true",
            "verify_certs": os.getenv("OPENSEARCH_VERIFY_CERTS", "false").lower() == "true"
        }
    )
    print("Agent created successfully")

    # Check all methods
    print("Available methods starting with _enhance:", [m for m in dir(agent) if '_enhance' in m])
    print("Available methods starting with _extract:", [m for m in dir(agent) if '_extract' in m])

    # Test the exact call that's failing
    print("Testing query method...")
    import asyncio

    async def test_query():
        try:
            result = await agent.query("Show me all alerts on host 012 over the past 10 hours.", "default")
            print("Query successful! Response length:", len(result))
            return True
        except Exception as e:
            print("Query failed with error:", str(e))
            import traceback
            traceback.print_exc()
            return False

    success = asyncio.run(test_query())
    print("Test result:", "SUCCESS" if success else "FAILED")

except Exception as e:
    print("Agent creation failed:", str(e))
    import traceback
    traceback.print_exc()
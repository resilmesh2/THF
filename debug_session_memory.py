"""
Debug what's actually in the session memory
"""
import os
import asyncio
from dotenv import load_dotenv
from agent.wazuh_agent import WazuhSecurityAgent

load_dotenv()

async def debug_session_memory():
    """Debug session memory to see what conversation history is stored"""

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

    session_id = "test_debug_session"

    print("=== DEBUGGING SESSION MEMORY ===")

    # Simulate the first query
    print("\n1. First query: 'Show me all alerts on host 012 over the past 10 hours.'")
    response1 = await agent.query("Show me all alerts on host 012 over the past 10 hours.", session_id)
    print(f"Response length: {len(response1)} characters")

    # Check what's in session memory after first query
    print("\n2. Checking session memory after first query...")
    session_memory = agent._get_session_memory(session_id)

    if hasattr(session_memory, 'chat_memory'):
        messages = session_memory.chat_memory.messages
        print(f"Messages in memory: {len(messages)}")

        for i, msg in enumerate(messages):
            print(f"Message {i}:")
            print(f"  Type: {type(msg)}")
            print(f"  Content preview: {str(msg)[:200]}...")
            if hasattr(msg, 'content'):
                print(f"  Content attribute: {msg.content[:200]}...")
            print()
    else:
        print("No chat_memory attribute found!")

    # Test context extraction with actual messages
    print("\n3. Testing context extraction with actual session messages...")
    if hasattr(session_memory, 'chat_memory'):
        context = agent._extract_previous_context(session_memory.chat_memory.messages)
        print("Extracted context:")
        for key, value in context.items():
            print(f"  {key}: {value}")

    # Now test the second query
    print("\n4. Second query: 'Show me details of which PowerShell processes created executable files on that host.'")

    # Get the enhanced prompt without executing
    if hasattr(session_memory, 'chat_memory'):
        enhanced_prompt = agent._enhance_prompt_with_context(
            "Show me details of which PowerShell processes created executable files on that host.",
            session_memory.chat_memory.messages
        )

        print("\n5. Enhanced prompt analysis:")
        lines = enhanced_prompt.split('\n')
        for i, line in enumerate(lines[:10]):  # First 10 lines
            print(f"Line {i}: {line}")

        # Look for the critical instructions
        if "MANDATORY" in enhanced_prompt:
            print("\n6. Found MANDATORY instructions - YES")
        else:
            print("\n6. NO MANDATORY instructions found")

        if "'012'" in enhanced_prompt:
            print("7. Found host 012 reference - YES")
        else:
            print("7. NO host 012 reference found")

    await agent.close()

if __name__ == "__main__":
    asyncio.run(debug_session_memory())
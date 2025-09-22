"""
Test script for LangChain memory functionality
"""
import asyncio
import os
from dotenv import load_dotenv
from agent.wazuh_agent import WazuhSecurityAgent

# Load environment variables
load_dotenv()

async def test_memory_preservation():
    """Test that conversation context is preserved across queries"""

    # Initialize agent
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

    session_id = "test_session_001"

    print("=" * 60)
    print("Testing LangChain Memory Preservation")
    print("=" * 60)

    # Test 1: Initial query about specific host
    print("\n1. Initial Query (establishing context):")
    query1 = "Show me all alerts for host 192.168.1.100 in the last 24 hours"
    print(f"Query: {query1}")

    response1 = await agent.query(query1, session_id)
    print(f"Response: {response1[:200]}...")

    # Test 2: Contextual follow-up query
    print("\n2. Contextual Follow-up Query:")
    query2 = "Give me more information on the critical alerts from that host"
    print(f"Query: {query2}")

    response2 = await agent.query(query2, session_id)
    print(f"Response: {response2[:200]}...")

    # Test 3: Another contextual query
    print("\n3. Another Contextual Query:")
    query3 = "What about authentication failures on the same host?"
    print(f"Query: {query3}")

    response3 = await agent.query(query3, session_id)
    print(f"Response: {response3[:200]}...")

    # Test 4: Check session info
    print("\n4. Session Information:")
    session_info = agent.get_session_info(session_id)
    print(f"Session Info: {session_info}")

    # Test 5: Test different session
    print("\n5. Testing Different Session (should not have context):")
    different_session = "test_session_002"
    query4 = "Show me the critical alerts we discussed"
    print(f"Query: {query4}")

    response4 = await agent.query(query4, different_session)
    print(f"Response: {response4[:200]}...")

    # Test 6: Check all sessions
    print("\n6. All Sessions Information:")
    all_sessions = agent.get_session_info()
    print(f"All Sessions: {all_sessions}")

    # Test 7: Reset specific session
    print("\n7. Resetting First Session:")
    await agent.reset_memory(session_id)

    # Test 8: Query after reset (should not have context)
    print("\n8. Query After Reset (should not have context):")
    query5 = "Give me more details on those critical alerts"
    print(f"Query: {query5}")

    response5 = await agent.query(query5, session_id)
    print(f"Response: {response5[:200]}...")

    print("\n" + "=" * 60)
    print("Memory Test Complete")
    print("=" * 60)

    await agent.close()

async def test_context_extraction():
    """Test context extraction functionality"""

    print("\n" + "=" * 60)
    print("Testing Context Extraction")
    print("=" * 60)

    # Mock chat history for testing
    class MockMessage:
        def __init__(self, content):
            self.content = content

    chat_history = [
        MockMessage("Show me alerts for host server-01 in the last 2 hours"),
        MockMessage("I found 15 alerts for host server-01 in the last 2 hours, including 3 critical authentication failures."),
        MockMessage("What about user admin on that host?"),
        MockMessage("User admin had 7 failed login attempts on server-01 during this period.")
    ]

    # Initialize agent (we just need the context extraction method)
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

    # Test context extraction
    context = agent._extract_previous_context(chat_history)
    print("Extracted Context:")
    for key, value in context.items():
        print(f"  {key}: {value}")

    # Test prompt enhancement
    test_query = "Show me the critical alerts from there"
    enhanced_prompt = agent._enhance_prompt_with_context(test_query, chat_history)
    print(f"\nOriginal Query: {test_query}")
    print(f"Enhanced Prompt Length: {len(enhanced_prompt)} characters")
    print(f"Enhanced Prompt Preview: {enhanced_prompt[:300]}...")

    await agent.close()

if __name__ == "__main__":
    print("Starting Memory Tests...")

    # Run context extraction test first
    asyncio.run(test_context_extraction())

    # Run full memory preservation test
    asyncio.run(test_memory_preservation())

    print("\nAll tests completed!")
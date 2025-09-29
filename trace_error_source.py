#!/usr/bin/env python3
"""
Trace the exact source of the initialize_agent error
"""
import requests
import json
import time
import sys

def test_with_different_queries():
    """Test with different types of queries to see if the error is consistent"""
    print("TESTING DIFFERENT QUERY TYPES")
    print("="*50)

    queries = [
        "Hello, how are you?",
        "What is 2 + 2?",
        "List all available tools",
        "Count alerts for each agent over the past six hours.",
        "Show me agent status"
    ]

    for i, query in enumerate(queries, 1):
        print(f"\n--- Test {i}: {query} ---")

        try:
            payload = {
                "query": query,
                "session_id": f"trace_session_{int(time.time())}_{i}"
            }

            response = requests.post(
                "http://localhost:8000/query",
                json=payload,
                timeout=30
            )

            print(f"Status: {response.status_code}")

            if response.status_code == 200:
                result = response.json()
                response_text = result.get('response', 'No response')
                print(f"Response: {response_text[:200]}...")

                # Check for the specific error
                if "initialize_agent" in response_text:
                    print("*** FOUND initialize_agent ERROR ***")
                else:
                    print("No initialize_agent error in this response")
            else:
                print(f"HTTP Error: {response.text}")

        except Exception as e:
            print(f"Request failed: {str(e)}")

        time.sleep(1)

def test_api_directly():
    """Test the API with minimal queries to isolate the issue"""
    print("\n" + "="*60)
    print("TESTING API DIRECTLY")
    print("="*60)

    # Test health first
    try:
        health_response = requests.get("http://localhost:8000/health", timeout=5)
        print(f"Health check: {health_response.status_code}")

        if health_response.status_code == 200:
            health_data = health_response.json()
            print(f"Agent initialized: {health_data.get('agent_initialized')}")

    except Exception as e:
        print(f"Health check failed: {str(e)}")
        return False

    # Test a very simple query
    print("\nTesting simple query...")
    try:
        simple_payload = {
            "query": "hello",
            "session_id": "trace_simple"
        }

        response = requests.post(
            "http://localhost:8000/query",
            json=simple_payload,
            timeout=30
        )

        print(f"Simple query status: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            response_text = result.get('response', '')
            print(f"Simple query response: {response_text}")

            if "initialize_agent" in response_text:
                print("ERROR: initialize_agent appears even in simple query!")
                return True
            else:
                print("Simple query works - error might be query-specific")

        return False

    except Exception as e:
        print(f"Simple query failed: {str(e)}")
        return False

def check_server_logs():
    """Instructions for checking server logs"""
    print("\n" + "="*60)
    print("SERVER LOG CHECKING INSTRUCTIONS")
    print("="*60)
    print("Please check the uvicorn terminal window for:")
    print("1. Any 'Agent execution error details' log entries")
    print("2. Any 'Initialize agent error - full traceback' entries")
    print("3. Any Python exception stack traces")
    print("4. Any other error messages")
    print()
    print("If you see detailed error logs, please share them!")
    print("If you don't see any error logs, the issue might be:")
    print("- The error is being handled differently than expected")
    print("- The error is coming from the LLM response, not Python code")
    print("- There's a different execution path being taken")

def main():
    """Main tracing function"""
    print("INITIALIZE_AGENT ERROR SOURCE TRACING")
    print("="*60)

    # Test if simple queries work
    simple_error = test_api_directly()

    if simple_error:
        print("\n🚨 ERROR: initialize_agent appears even in simple queries!")
        print("This suggests the error is in the basic agent execution path.")
    else:
        print("\n✅ Simple queries work - testing more complex ones...")
        test_with_different_queries()

    # Instructions for manual log checking
    check_server_logs()

    print("\n" + "="*60)
    print("TRACE COMPLETE")
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTracing interrupted")
    except Exception as e:
        print(f"Tracing failed: {str(e)}")
        import traceback
        traceback.print_exc()
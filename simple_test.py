#!/usr/bin/env python3
"""
Enhanced test script with detailed server logging and trace capture
"""
import requests
import json
import time
import sys

def test_health():
    """Test server health"""
    print("Testing server health...")

    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            print("SUCCESS: Uvicorn is healthy")
            print(f"Health data: {health_data}")

            if health_data.get("agent_initialized"):
                print("SUCCESS: Agent is initialized")
                return True
            else:
                print("FAILED: Agent is NOT initialized")
                return False
        else:
            print(f"FAILED: Uvicorn unhealthy - status {response.status_code}")
            return False
    except Exception as e:
        print(f"FAILED: Cannot connect to uvicorn - {str(e)}")
        return False

def check_server_logs():
    """Instructions for checking server logs"""
    print("\n" + "="*60)
    print("SERVER LOG MONITORING INSTRUCTIONS")
    print("="*60)
    print("IMPORTANT: While this test runs, please check your uvicorn terminal for:")
    print("1. Any error messages containing 'initialize_agent'")
    print("2. Any Python exceptions or tracebacks")
    print("3. Any 'Agent execution error details' messages")
    print("4. Any import errors or module loading issues")
    print("5. Any messages about agent initialization")
    print()
    print("Look for lines that start with:")
    print("- ERROR:")
    print("- Traceback:")
    print("- ImportError:")
    print("- NameError:")
    print("- Agent execution error details")
    print()
    print("If you see ANY error messages, please copy them!")
    print("="*60)

def test_query_with_details():
    """Test the threat hunting query with detailed analysis"""
    print("\n" + "="*60)
    print("TESTING THREAT HUNTING QUERY WITH DETAILED LOGGING")
    print("="*60)

    query = "Count alerts for each agent over the past six hours."
    session_id = f"debug_session_{int(time.time())}"

    print(f"Query: {query}")
    print(f"Session ID: {session_id}")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        payload = {
            "query": query,
            "session_id": session_id
        }

        print(f"Payload: {json.dumps(payload, indent=2)}")
        print("Sending request to API...")
        print("CHECK YOUR UVICORN TERMINAL NOW FOR ERROR MESSAGES!")

        start_time = time.time()

        response = requests.post(
            "http://localhost:8000/query",
            json=payload,
            timeout=120,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
        )

        duration = time.time() - start_time
        print(f"Response time: {duration:.2f} seconds")
        print(f"Status code: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")

        if response.status_code == 200:
            try:
                result = response.json()
                print("SUCCESS: Query processed successfully!")

                # Analyze the response structure
                print("Response structure analysis:")
                print(f"- Response type: {type(result)}")
                print(f"- Response keys: {list(result.keys()) if isinstance(result, dict) else 'Not a dict'}")

                response_text = result.get('response', 'No response field')
                print("Response preview:")
                print(response_text)

                # Check for the specific error
                if "initialize_agent" in response_text:
                    print("\n*** CRITICAL: initialize_agent error found in response! ***")
                    print("This means the error is happening during LLM execution,")
                    print("not during agent creation or HTTP handling.")

                    # Try to extract more details
                    if "Traceback" in response_text or "Error" in response_text:
                        print("Response contains error details:")
                        print(response_text)

                return "initialize_agent" not in response_text

            except json.JSONDecodeError:
                print("FAILED: Response is not valid JSON")
                print(f"Raw response: {response.text}")
                return False
        else:
            print(f"FAILED: HTTP {response.status_code}")
            print(f"Error response: {response.text}")
            return False

    except requests.exceptions.Timeout:
        print("FAILED: Request timed out after 120 seconds")
        print("This suggests the server is hanging during execution")
        return False
    except Exception as e:
        print(f"FAILED: Request error - {str(e)}")
        return False

def test_simple_query():
    """Test with a very simple query to isolate the issue"""
    print("\n" + "="*60)
    print("TESTING SIMPLE QUERY")
    print("="*60)

    simple_queries = [
        "hello",
        "what is 2 plus 2",
        "list available tools"
    ]

    for query in simple_queries:
        print(f"\nTesting: {query}")

        payload = {
            "query": query,
            "session_id": f"simple_test_{int(time.time())}"
        }

        try:
            response = requests.post(
                "http://localhost:8000/query",
                json=payload,
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                response_text = result.get('response', '')

                if "initialize_agent" in response_text:
                    print(f"  ERROR: initialize_agent found in simple query '{query}'")
                    return False
                else:
                    print(f"  OK: No initialize_agent error")
            else:
                print(f"  HTTP Error: {response.status_code}")

        except Exception as e:
            print(f"  Exception: {str(e)}")

    return True

def main():
    """Main test function with enhanced debugging"""
    print("ENHANCED THREAT HUNTING TEST WITH SERVER LOG MONITORING")
    print("="*70)

    # Test server health
    if not test_health():
        print("\nServers not ready. Please start them manually:")
        print("1. uvicorn main:app --host 0.0.0.0 --port 8000 --reload")
        print("2. streamlit run streamlit_ui.py")
        return False

    # Show server log monitoring instructions
    check_server_logs()

    # Wait for user to be ready to monitor logs
    input("\nPress ENTER when you're ready to run the test and monitor the uvicorn terminal...")

    # Test simple queries first
    print("Step 1: Testing simple queries...")
    simple_success = test_simple_query()

    # Test the complex query with detailed analysis
    print("\nStep 2: Testing complex query with full analysis...")
    complex_success = test_query_with_details()

    print("\n" + "="*70)
    print("TEST COMPLETE - RESULTS SUMMARY")
    print("="*70)

    print(f"Simple queries: {'PASSED' if simple_success else 'FAILED'}")
    print(f"Complex query: {'PASSED' if complex_success else 'FAILED'}")

    if simple_success and complex_success:
        print("OVERALL RESULT: SUCCESS - All tests passed!")
        return True
    elif not simple_success:
        print("OVERALL RESULT: FAILED - Even simple queries have initialize_agent error")
        print("This indicates a fundamental issue with agent execution")
        return False
    else:
        print("OVERALL RESULT: PARTIAL - Simple queries work but complex query fails")
        print("This indicates the error is query-specific or tool-specific")
        return False

if __name__ == "__main__":
    try:
        success = main()
        if not success:
            exit(1)
    except KeyboardInterrupt:
        print("\nTest interrupted")
        exit(1)
    except Exception as e:
        print(f"Test failed: {str(e)}")
        exit(1)
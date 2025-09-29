#!/usr/bin/env python3
"""
Simple test script without Unicode characters
"""
import requests
import json
import time

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

def test_query():
    """Test the threat hunting query"""
    print("\n" + "="*60)
    print("TESTING THREAT HUNTING QUERY")
    print("="*60)

    query = "Count alerts for each agent over the past six hours."
    print(f"Query: {query}")

    try:
        payload = {
            "query": query,
            "session_id": "test_session_" + str(int(time.time()))
        }

        print("Sending request to API...")
        start_time = time.time()

        response = requests.post(
            "http://localhost:8000/query",
            json=payload,
            timeout=120
        )

        duration = time.time() - start_time
        print(f"Response time: {duration:.2f} seconds")
        print(f"Status code: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            print("SUCCESS: Query processed successfully!")
            print("Response preview:")
            response_text = result.get('response', 'No response field')
            print(response_text[:500] + "..." if len(response_text) > 500 else response_text)
            return True
        else:
            print(f"FAILED: HTTP {response.status_code}")
            print(f"Error response: {response.text}")

            # Check for specific errors
            if "initialize_agent" in response.text:
                print("ERROR FOUND: initialize_agent reference still exists!")
            return False

    except requests.exceptions.Timeout:
        print("FAILED: Request timed out after 120 seconds")
        return False
    except Exception as e:
        print(f"FAILED: Request error - {str(e)}")
        return False

def main():
    """Main test function"""
    print("SIMPLE THREAT HUNTING TEST")
    print("="*50)

    # Test server health
    if not test_health():
        print("\nServers not ready. Please start them manually:")
        print("1. uvicorn main:app --host 0.0.0.0 --port 8000 --reload")
        print("2. streamlit run streamlit_ui.py")
        return False

    # Test the query
    success = test_query()

    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)

    if success:
        print("RESULT: SUCCESS - Threat hunting query worked!")
    else:
        print("RESULT: FAILED - Check errors above")

    return success

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
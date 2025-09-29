#!/usr/bin/env python3
"""
Direct test of the threat hunting query against running servers
"""
import requests
import json
import time
import sys

def test_server_health():
    """Test if servers are healthy"""
    print("Testing server health...")

    # Test uvicorn
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            health_data = response.json()
            print(f"✅ Uvicorn healthy: {health_data}")

            # Check if agent is initialized
            if health_data.get("agent_initialized"):
                print("✅ Agent is initialized")
            else:
                print("❌ Agent is NOT initialized")
                return False
        else:
            print(f"❌ Uvicorn unhealthy: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Uvicorn connection failed: {str(e)}")
        return False

    # Test streamlit
    try:
        response = requests.get("http://localhost:8501", timeout=5)
        if response.status_code == 200:
            print("✅ Streamlit healthy")
        else:
            print(f"⚠️ Streamlit status: {response.status_code}")
    except Exception as e:
        print(f"⚠️ Streamlit connection issue: {str(e)}")

    return True

def test_threat_hunting_queries():
    """Test multiple threat hunting queries"""
    queries = [
        "Count alerts for each agent over the past six hours.",
        "Show a status report on the host U209-PC-BLEE since 6AM this morning.",
        "Filter any alerts on host win10-01 with severity level 15 for the past 12 hours."
    ]

    results = []

    for i, query in enumerate(queries, 1):
        print(f"\n{'='*60}")
        print(f"TEST {i}: {query}")
        print('='*60)

        try:
            payload = {
                "query": query,
                "session_id": f"test_session_{int(time.time())}"
            }

            print("Sending request...")
            start_time = time.time()

            response = requests.post(
                "http://localhost:8000/query",
                json=payload,
                timeout=120  # Longer timeout for complex queries
            )

            duration = time.time() - start_time
            print(f"Response time: {duration:.2f} seconds")
            print(f"Status code: {response.status_code}")

            if response.status_code == 200:
                result = response.json()
                print("✅ SUCCESS!")
                print(f"Response preview: {result.get('response', 'No response')[:300]}...")
                results.append({"query": query, "status": "success", "duration": duration})
            else:
                print(f"❌ FAILED - HTTP {response.status_code}")
                print(f"Error: {response.text}")
                results.append({"query": query, "status": "failed", "error": response.text})

        except requests.exceptions.Timeout:
            print("❌ FAILED - Request timeout")
            results.append({"query": query, "status": "timeout"})
        except Exception as e:
            print(f"❌ FAILED - {str(e)}")
            results.append({"query": query, "status": "error", "error": str(e)})

        # Small delay between queries
        time.sleep(2)

    return results

def print_summary(results):
    """Print test summary"""
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print('='*60)

    successful = sum(1 for r in results if r["status"] == "success")
    total = len(results)

    print(f"Total tests: {total}")
    print(f"Successful: {successful}")
    print(f"Failed: {total - successful}")
    print(f"Success rate: {(successful/total)*100:.1f}%" if total > 0 else "No tests")

    for i, result in enumerate(results, 1):
        status_icon = "✅" if result["status"] == "success" else "❌"
        print(f"{status_icon} Test {i}: {result['status']}")
        if "error" in result:
            print(f"   Error: {result['error'][:100]}...")

def main():
    """Main test function"""
    print("THREAT HUNTING QUERY TEST")
    print("="*60)

    # Check server health first
    if not test_server_health():
        print("\n❌ Servers are not healthy. Please start them first.")
        print("Run: python start_servers.py")
        return False

    print("\n🚀 Starting threat hunting tests...")

    # Run the tests
    results = test_threat_hunting_queries()

    # Print summary
    print_summary(results)

    # Check if any tests passed
    success_count = sum(1 for r in results if r["status"] == "success")
    return success_count > 0

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
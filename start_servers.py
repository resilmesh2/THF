#!/usr/bin/env python3
"""
Script to start both servers in order and test the threat hunting query
"""
import subprocess
import time
import requests
import json
import sys
import os
from pathlib import Path

def clear_cache():
    """Clear Python cache files"""
    print("Clearing Python cache files...")

    # Clear __pycache__ directories
    for cache_dir in Path(".").rglob("__pycache__"):
        if cache_dir.is_dir():
            print(f"Removing {cache_dir}")
            try:
                import shutil
                shutil.rmtree(cache_dir)
            except Exception as e:
                print(f"Warning: Could not remove {cache_dir}: {e}")

    # Clear .pyc files
    for pyc_file in Path(".").rglob("*.pyc"):
        if pyc_file.is_file():
            print(f"Removing {pyc_file}")
            try:
                pyc_file.unlink()
            except Exception as e:
                print(f"Warning: Could not remove {pyc_file}: {e}")

    print("Cache cleared!")

def start_uvicorn():
    """Start uvicorn server"""
    print("Starting uvicorn server...")

    # Start uvicorn in background
    process = subprocess.Popen(
        ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        bufsize=1
    )

    # Wait for server to start and capture initial logs
    print("Waiting for uvicorn to start...")
    startup_timeout = 30
    start_time = time.time()

    while time.time() - start_time < startup_timeout:
        # Check if process is still running
        if process.poll() is not None:
            print("ERROR: Uvicorn process died!")
            output = process.stdout.read()
            print("Uvicorn output:")
            print(output)
            return None

        # Try to connect to health endpoint
        try:
            response = requests.get("http://localhost:8000/health", timeout=2)
            if response.status_code == 200:
                print("✅ Uvicorn server is running!")
                health_data = response.json()
                print(f"Health check: {health_data}")
                return process
        except requests.exceptions.RequestException:
            pass

        time.sleep(1)

    print("ERROR: Uvicorn failed to start within timeout")
    process.terminate()
    return None

def start_streamlit():
    """Start streamlit server"""
    print("Starting streamlit server...")

    # Start streamlit in background
    process = subprocess.Popen(
        ["python", "-m", "streamlit", "run", "streamlit_ui.py", "--server.port", "8501"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        bufsize=1
    )

    # Wait for streamlit to start
    print("Waiting for streamlit to start...")
    startup_timeout = 30
    start_time = time.time()

    while time.time() - start_time < startup_timeout:
        # Check if process is still running
        if process.poll() is not None:
            print("ERROR: Streamlit process died!")
            output = process.stdout.read()
            print("Streamlit output:")
            print(output)
            return None

        # Try to connect to streamlit
        try:
            response = requests.get("http://localhost:8501", timeout=2)
            if response.status_code == 200:
                print("✅ Streamlit server is running!")
                return process
        except requests.exceptions.RequestException:
            pass

        time.sleep(1)

    print("ERROR: Streamlit failed to start within timeout")
    process.terminate()
    return None

def test_threat_hunting_query():
    """Test the threat hunting query"""
    print("\n" + "="*60)
    print("TESTING THREAT HUNTING QUERY")
    print("="*60)

    query = "Count alerts for each agent over the past six hours."
    print(f"Testing query: {query}")

    # Test the API directly
    try:
        payload = {
            "query": query,
            "session_id": "test_session_123"
        }

        print("Sending request to API...")
        response = requests.post(
            "http://localhost:8000/query",
            json=payload,
            timeout=60
        )

        print(f"Response status: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")

        if response.status_code == 200:
            result = response.json()
            print("✅ SUCCESS: Query processed successfully!")
            print(f"Response: {result.get('response', 'No response field')[:200]}...")
            return True
        else:
            print(f"❌ FAILED: HTTP {response.status_code}")
            print(f"Response text: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"❌ FAILED: Request error - {str(e)}")
        return False
    except Exception as e:
        print(f"❌ FAILED: Unexpected error - {str(e)}")
        return False

def monitor_server_logs(uvicorn_process, duration=10):
    """Monitor server logs for a short duration"""
    print(f"\nMonitoring server logs for {duration} seconds...")

    start_time = time.time()
    while time.time() - start_time < duration:
        # Check uvicorn logs
        if uvicorn_process and uvicorn_process.poll() is None:
            try:
                # Non-blocking read
                line = uvicorn_process.stdout.readline()
                if line:
                    print(f"[UVICORN] {line.strip()}")
            except:
                pass

        time.sleep(0.1)

def main():
    """Main function"""
    print("THREAT HUNTING SYSTEM STARTUP AND TEST")
    print("="*60)

    # Check working directory
    print(f"Working directory: {os.getcwd()}")

    # Check required files exist
    required_files = ["main.py", "streamlit_ui.py", "agent/wazuh_agent.py"]
    for file in required_files:
        if not os.path.exists(file):
            print(f"ERROR: Required file {file} not found!")
            return False

    # Clear cache first
    clear_cache()

    # Start uvicorn server
    uvicorn_process = start_uvicorn()
    if not uvicorn_process:
        print("Failed to start uvicorn server")
        return False

    # Start streamlit server
    streamlit_process = start_streamlit()
    if not streamlit_process:
        print("Failed to start streamlit server")
        uvicorn_process.terminate()
        return False

    print("\n✅ Both servers are running!")
    print("Uvicorn: http://localhost:8000")
    print("Streamlit: http://localhost:8501")

    # Monitor logs briefly
    monitor_server_logs(uvicorn_process, 5)

    # Test the threat hunting query
    success = test_threat_hunting_query()

    # Keep servers running for manual testing
    if success:
        print("\n🎉 SUCCESS! Servers are ready for manual testing.")
        print("Press Ctrl+C to stop both servers...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down servers...")
    else:
        print("\n❌ FAILED! Check the logs above for errors.")
        print("Shutting down servers...")

    # Cleanup
    uvicorn_process.terminate()
    streamlit_process.terminate()

    # Wait for processes to end
    uvicorn_process.wait(timeout=5)
    streamlit_process.wait(timeout=5)

    print("Servers stopped.")
    return success

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
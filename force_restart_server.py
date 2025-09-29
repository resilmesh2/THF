#!/usr/bin/env python3
"""
Force restart server with complete module reload
"""
import os
import sys
import time
import subprocess
import shutil
from pathlib import Path

def kill_all_python_processes():
    """Kill all Python processes"""
    print("Killing all Python processes...")
    try:
        # Kill python processes
        subprocess.run(["taskkill", "/f", "/im", "python.exe"],
                      capture_output=True, text=True)
        subprocess.run(["taskkill", "/f", "/im", "uvicorn.exe"],
                      capture_output=True, text=True)
        subprocess.run(["taskkill", "/f", "/im", "streamlit.exe"],
                      capture_output=True, text=True)
        print("Python processes killed")
    except Exception as e:
        print(f"Error killing processes: {e}")

def clear_all_cache():
    """Clear all Python cache thoroughly"""
    print("Clearing ALL Python cache...")

    cache_count = 0

    # Clear __pycache__ directories
    for cache_dir in Path(".").rglob("__pycache__"):
        if cache_dir.is_dir():
            try:
                shutil.rmtree(cache_dir)
                cache_count += 1
            except Exception as e:
                print(f"Warning: Could not remove {cache_dir}: {e}")

    # Clear .pyc files
    for pyc_file in Path(".").rglob("*.pyc"):
        try:
            pyc_file.unlink()
            cache_count += 1
        except Exception as e:
            print(f"Warning: Could not remove {pyc_file}: {e}")

    print(f"Cleared {cache_count} cache files")

def verify_code_changes():
    """Verify our code changes are in place"""
    print("Verifying code changes...")

    try:
        with open("agent/wazuh_agent.py", "r") as f:
            content = f.read()

        if "create_react_agent" in content and "initialize_agent" not in content:
            print("✓ Code changes verified - create_react_agent found, initialize_agent removed")
            return True
        else:
            print("✗ Code changes NOT found - still has old initialize_agent code")
            return False

    except Exception as e:
        print(f"Error checking code: {e}")
        return False

def restart_servers():
    """Restart servers with fresh processes"""
    print("Starting fresh server processes...")

    # Start uvicorn in a new process
    print("Starting uvicorn...")
    uvicorn_cmd = [
        "python", "-m", "uvicorn",
        "main:app",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--reload"
    ]

    uvicorn_process = subprocess.Popen(
        uvicorn_cmd,
        cwd=os.getcwd(),
        env=os.environ.copy()
    )

    # Wait for uvicorn to start
    print("Waiting for uvicorn to start...")
    time.sleep(10)

    # Start streamlit
    print("Starting streamlit...")
    streamlit_cmd = [
        "python", "-m", "streamlit",
        "run",
        "streamlit_ui.py"
    ]

    streamlit_process = subprocess.Popen(
        streamlit_cmd,
        cwd=os.getcwd(),
        env=os.environ.copy()
    )

    print("Both servers started!")
    print("Uvicorn PID:", uvicorn_process.pid)
    print("Streamlit PID:", streamlit_process.pid)

    return uvicorn_process, streamlit_process

def main():
    """Main restart function"""
    print("FORCE SERVER RESTART WITH MODULE RELOAD")
    print("="*50)

    # Step 1: Verify code changes
    if not verify_code_changes():
        print("ERROR: Code changes not found! Check if you're on the right branch.")
        return False

    # Step 2: Kill all processes
    kill_all_python_processes()

    # Step 3: Clear cache
    clear_all_cache()

    # Step 4: Wait for cleanup
    print("Waiting for cleanup...")
    time.sleep(5)

    # Step 5: Restart servers
    try:
        uvicorn_proc, streamlit_proc = restart_servers()

        print("\n" + "="*50)
        print("RESTART COMPLETE!")
        print("="*50)
        print("Servers should now be running with fresh code.")
        print("Wait 15 seconds, then test with: python simple_test.py")
        print("Press Ctrl+C to stop this script (servers will keep running)")

        # Keep script alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nScript stopped. Servers are still running.")

        return True

    except Exception as e:
        print(f"Error restarting servers: {e}")
        return False

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nRestart interrupted")
    except Exception as e:
        print(f"Restart failed: {e}")
        import traceback
        traceback.print_exc()
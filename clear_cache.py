#!/usr/bin/env python3
"""
Comprehensive cache clearing script
"""
import os
import sys
import shutil
from pathlib import Path

def clear_python_cache():
    """Clear Python cache files and directories"""
    print("Clearing Python cache files...")

    cache_cleared = 0

    # Clear __pycache__ directories
    for cache_dir in Path(".").rglob("__pycache__"):
        if cache_dir.is_dir():
            print(f"  Removing {cache_dir}")
            try:
                shutil.rmtree(cache_dir)
                cache_cleared += 1
            except Exception as e:
                print(f"    Warning: Could not remove {cache_dir}: {e}")

    # Clear .pyc files
    for pyc_file in Path(".").rglob("*.pyc"):
        if pyc_file.is_file():
            print(f"  Removing {pyc_file}")
            try:
                pyc_file.unlink()
                cache_cleared += 1
            except Exception as e:
                print(f"    Warning: Could not remove {pyc_file}: {e}")

    # Clear .pyo files (optimized bytecode)
    for pyo_file in Path(".").rglob("*.pyo"):
        if pyo_file.is_file():
            print(f"  Removing {pyo_file}")
            try:
                pyo_file.unlink()
                cache_cleared += 1
            except Exception as e:
                print(f"    Warning: Could not remove {pyo_file}: {e}")

    print(f"Cleared {cache_cleared} cache files/directories")
    return cache_cleared

def clear_import_cache():
    """Clear Python import cache"""
    print("Clearing Python import cache...")

    # Clear sys.modules for our project files
    project_modules = [module for module in sys.modules.keys()
                      if any(part in module for part in ['agent', 'tools', 'functions', 'schemas'])]

    cleared_modules = 0
    for module in project_modules:
        try:
            del sys.modules[module]
            cleared_modules += 1
            print(f"  Cleared module: {module}")
        except KeyError:
            pass

    print(f"Cleared {cleared_modules} modules from import cache")
    return cleared_modules

def check_running_processes():
    """Check for running Python processes that might be using cached code"""
    print("Checking for running Python processes...")

    try:
        import psutil
        python_processes = []

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['name'] and 'python' in proc.info['name'].lower():
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    if any(keyword in cmdline.lower() for keyword in ['uvicorn', 'streamlit', 'main.py', 'streamlit_ui.py']):
                        python_processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cmdline': cmdline[:100] + '...' if len(cmdline) > 100 else cmdline
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if python_processes:
            print("Found running Python processes:")
            for proc in python_processes:
                print(f"  PID {proc['pid']}: {proc['name']} - {proc['cmdline']}")
            print("\n⚠️  WARNING: You may need to stop these processes for cache clearing to be effective!")
        else:
            print("✅ No relevant Python processes found running")

        return len(python_processes)

    except ImportError:
        print("psutil not available, skipping process check")
        return 0

def verify_key_files():
    """Verify that key files exist and check their modification times"""
    print("Verifying key files...")

    key_files = [
        "agent/wazuh_agent.py",
        "tools/wazuh_tools.py",
        "main.py",
        "streamlit_ui.py"
    ]

    for file_path in key_files:
        if os.path.exists(file_path):
            mtime = os.path.getmtime(file_path)
            mtime_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
            print(f"  ✅ {file_path} (modified: {mtime_str})")
        else:
            print(f"  ❌ {file_path} - NOT FOUND!")

def main():
    """Main cache clearing function"""
    import time

    print("COMPREHENSIVE CACHE CLEARING")
    print("="*50)
    print(f"Working directory: {os.getcwd()}")
    print(f"Python version: {sys.version}")
    print()

    # Check for running processes first
    running_processes = check_running_processes()
    print()

    # Clear Python cache
    cache_files_cleared = clear_python_cache()
    print()

    # Clear import cache
    modules_cleared = clear_import_cache()
    print()

    # Verify key files
    verify_key_files()
    print()

    # Summary
    print("CACHE CLEARING SUMMARY")
    print("="*30)
    print(f"Cache files cleared: {cache_files_cleared}")
    print(f"Modules cleared: {modules_cleared}")
    print(f"Running processes: {running_processes}")

    if running_processes > 0:
        print("\n⚠️  RECOMMENDATION: Stop all server processes and restart them")
        print("   This ensures they pick up the code changes without cached imports")
    else:
        print("\n✅ Cache clearing complete! Safe to start servers now.")

    return True

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Cache clearing failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
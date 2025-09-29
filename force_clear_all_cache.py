#!/usr/bin/env python3
"""
Force clear all cache layers - Python, browser, server
"""
import os
import sys
import shutil
import time
from pathlib import Path

def clear_python_cache_thorough():
    """Thoroughly clear all Python cache"""
    print("CLEARING PYTHON CACHE (THOROUGH)")
    print("="*40)

    cache_cleared = 0

    # Clear __pycache__ directories
    for cache_dir in Path(".").rglob("__pycache__"):
        if cache_dir.is_dir():
            try:
                shutil.rmtree(cache_dir)
                cache_cleared += 1
                print(f"  Removed: {cache_dir}")
            except Exception as e:
                print(f"  Warning: Could not remove {cache_dir}: {e}")

    # Clear .pyc files
    for pyc_file in Path(".").rglob("*.pyc"):
        try:
            pyc_file.unlink()
            cache_cleared += 1
        except Exception as e:
            print(f"  Warning: Could not remove {pyc_file}: {e}")

    # Clear .pyo files
    for pyo_file in Path(".").rglob("*.pyo"):
        try:
            pyo_file.unlink()
            cache_cleared += 1
        except Exception as e:
            print(f"  Warning: Could not remove {pyo_file}: {e}")

    print(f"Cleared {cache_cleared} Python cache files/directories")

def clear_sys_modules():
    """Clear sys.modules for project modules"""
    print("\nCLEARING SYS.MODULES")
    print("="*20)

    # Clear our project modules from sys.modules
    modules_to_clear = []
    for module_name in list(sys.modules.keys()):
        if any(part in module_name for part in ['agent', 'tools', 'functions', 'schemas', 'main']):
            modules_to_clear.append(module_name)

    cleared_count = 0
    for module_name in modules_to_clear:
        try:
            del sys.modules[module_name]
            cleared_count += 1
            print(f"  Cleared: {module_name}")
        except KeyError:
            pass

    print(f"Cleared {cleared_count} modules from sys.modules")

def kill_python_processes():
    """Instructions to kill Python processes"""
    print("\nKILL PYTHON PROCESSES")
    print("="*25)
    print("Please do these steps manually:")
    print("1. Stop uvicorn server (Ctrl+C)")
    print("2. Stop streamlit server (Ctrl+C)")
    print("3. Wait 5 seconds for processes to fully terminate")
    print("4. Check Task Manager (Ctrl+Shift+Esc) for any remaining:")
    print("   - python.exe processes")
    print("   - uvicorn processes")
    print("   - streamlit processes")
    print("5. End any remaining Python processes manually")

def browser_cache_instructions():
    """Instructions for clearing browser cache"""
    print("\nBROWSER CACHE CLEARING")
    print("="*25)
    print("For Firefox:")
    print("1. Press Ctrl+Shift+Del")
    print("2. Select 'Everything' for Time range")
    print("3. Check all boxes including:")
    print("   - Browsing & download history")
    print("   - Cookies and site data")
    print("   - Cached web content")
    print("4. Click 'Clear Now'")
    print()
    print("Alternative Firefox method:")
    print("1. Press F12 to open Developer Tools")
    print("2. Right-click the refresh button")
    print("3. Select 'Empty Cache and Hard Reload'")
    print()
    print("For Chrome/Edge:")
    print("1. Press Ctrl+Shift+Del")
    print("2. Select 'All time' for Time range")
    print("3. Check all boxes")
    print("4. Click 'Clear data'")

def create_fresh_start_script():
    """Create a script for fresh restart"""
    print("\nCREATING FRESH START SCRIPT")
    print("="*30)

    script_content = '''@echo off
echo FRESH SERVER START
echo ==================

echo Step 1: Clearing Python cache...
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d"
del /s /q *.pyc >nul 2>&1
del /s /q *.pyo >nul 2>&1

echo Step 2: Killing any remaining Python processes...
taskkill /f /im python.exe >nul 2>&1
taskkill /f /im uvicorn.exe >nul 2>&1
taskkill /f /im streamlit.exe >nul 2>&1

echo Step 3: Waiting for cleanup...
timeout /t 3 /nobreak >nul

echo Step 4: Starting uvicorn server...
start "Uvicorn-Fresh" cmd /k "uvicorn main:app --host 0.0.0.0 --port 8000 --reload"

echo Step 5: Waiting for uvicorn startup...
timeout /t 10 /nobreak >nul

echo Step 6: Starting streamlit server...
start "Streamlit-Fresh" cmd /k "streamlit run streamlit_ui.py"

echo.
echo FRESH START COMPLETE!
echo Both servers should be starting with clean cache.
echo.
pause
'''

    with open('fresh_start.bat', 'w') as f:
        f.write(script_content)

    print("Created fresh_start.bat script")
    print("You can run this script to do a complete clean restart")

def main():
    """Main cache clearing function"""
    print("COMPREHENSIVE CACHE CLEARING")
    print("="*50)
    print("This will clear ALL cache layers that might retain old code")
    print()

    # Clear Python cache
    clear_python_cache_thorough()

    # Clear sys.modules (for current Python session only)
    clear_sys_modules()

    # Create fresh start script
    create_fresh_start_script()

    # Instructions for manual steps
    kill_python_processes()
    browser_cache_instructions()

    print("\n" + "="*60)
    print("CACHE CLEARING COMPLETE")
    print("="*60)
    print("NEXT STEPS:")
    print("1. Follow the manual process steps above")
    print("2. Clear your browser cache")
    print("3. Run fresh_start.bat OR manually restart servers")
    print("4. Test with: python simple_test.py")
    print()
    print("If the error persists after ALL these steps,")
    print("then we have a different issue to investigate.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Cache clearing failed: {str(e)}")
        import traceback
        traceback.print_exc()
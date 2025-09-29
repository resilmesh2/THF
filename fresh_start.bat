@echo off
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

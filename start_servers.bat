@echo off
echo THREAT HUNTING SYSTEM STARTUP
echo ===============================
echo.

echo Clearing Python cache...
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d"
del /s /q *.pyc >nul 2>&1

echo.
echo Starting Uvicorn server...
start "Uvicorn Server" cmd /k "uvicorn main:app --host 0.0.0.0 --port 8000 --reload"

echo.
echo Waiting 10 seconds for Uvicorn to start...
timeout /t 10 /nobreak >nul

echo.
echo Starting Streamlit server...
start "Streamlit Server" cmd /k "streamlit run streamlit_ui.py"

echo.
echo Waiting 10 seconds for Streamlit to start...
timeout /t 10 /nobreak >nul

echo.
echo Both servers should now be running!
echo Uvicorn: http://localhost:8000
echo Streamlit: http://localhost:8501
echo.
echo Testing the system...
python start_servers.py

pause
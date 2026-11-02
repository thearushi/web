@echo off
title VigilSec Cyber Security Web Scanner
cls
echo ============================================================
echo      VIGILSEC CYBER SECURITY WEB VULNERABILITY SCANNER
echo ============================================================
echo.
echo   [1] Launch Modern Cyber HUD Web Application (Recommended)
echo   [2] Launch Streamlit Legacy Dashboard
echo.
echo ============================================================
set /p choice="Select launcher option [1 or 2, default is 1]: "

if "%choice%"=="2" goto launch_streamlit

:launch_modern
echo.
echo [*] Starting VigilSec Cyber HUD Server (http://127.0.0.1:5000)...
python server.py
pause
exit

:launch_streamlit
echo.
echo [*] Starting Streamlit Dashboard...
streamlit run app.py --server.headless=true --browser.gatherUsageStats=false
pause
exit

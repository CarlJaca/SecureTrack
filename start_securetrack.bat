@echo off
echo ==================================================
echo   SecureTrack - Startup Script
echo ==================================================

echo [1] Checking MySQL Database...
tasklist /FI "IMAGENAME eq mysqld.exe" 2>NUL | find /I /N "mysqld.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo     MySQL is already running.
) else (
    echo     Starting XAMPP MySQL...
    start /B "" "C:\xampp\mysql\bin\mysqld.exe" --defaults-file="C:\xampp\mysql\bin\my.ini" --standalone
    timeout /t 3 /nobreak > NUL
)

echo.
echo [2] Starting SecureTrack Application...
echo     Please keep this window open to keep the server running.
echo     Access the system at: http://127.0.0.1:5000
echo ==================================================
echo.

python app.py
pause

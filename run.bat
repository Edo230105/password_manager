@echo off
echo 🔐 Starting Secure Password Manager...

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed. Please install Python 3.8 or higher.
    pause
    exit /b 1
)

REM Install dependencies if requirements.txt exists
if exist requirements.txt (
    echo 📦 Installing dependencies...
    pip install -r requirements.txt
)

REM Check which version to run
if "%1"=="--enhanced" (
    echo 🚀 Starting Enhanced Password Manager with Browser Extension support...
    python enhanced_password_manager.py
) else (
    echo 🚀 Starting Basic Password Manager...
    python password_manager.py
)

pause

#!/bin/bash

# Secure Password Manager Launcher
echo "🔐 Starting Secure Password Manager..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Please install pip."
    exit 1
fi

# Install dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "📦 Installing dependencies..."
    pip3 install -r requirements.txt
fi

# Check which version to run
if [ "$1" = "--enhanced" ]; then
    echo "🚀 Starting Enhanced Password Manager with Browser Extension support..."
    python3 enhanced_password_manager.py
else
    echo "🚀 Starting Basic Password Manager..."
    python3 password_manager.py
fi

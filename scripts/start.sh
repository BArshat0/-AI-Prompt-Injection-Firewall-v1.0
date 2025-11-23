#!/bin/bash

set -e

echo "🚀 Starting AI Prompt Injection Firewall"
echo "========================================"

# Check if virtual environment exists
if [ ! -d "aipif-env" ]; then
    echo "❌ Virtual environment not found. Please run install.sh first."
    exit 1
fi

# Activate virtual environment
source aipif-env/bin/activate

# Check if backend directory exists
if [ ! -d "backend" ]; then
    echo "❌ Backend directory not found. Please check your installation."
    exit 1
fi

# Start the FastAPI server
echo "🌐 Starting backend server..."
cd backend

# Check if port 8000 is available
if lsof -Pi :8000 -sTCP:LISTEN -t >/dev/null ; then
    echo "⚠️  Port 8000 is already in use. Attempting to use port 8001..."
    uvicorn main:app --host 0.0.0.0 --port 8001 --reload &
else
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
fi

SERVER_PID=$!

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down AIPIF..."
    kill $SERVER_PID 2>/dev/null
    exit 0
}

trap cleanup INT TERM

echo ""
echo "✅ AIPIF is now running!"
echo "📊 Dashboard: http://localhost:8000"
echo "📚 API Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop the server"

# Wait for server process
wait $SERVER_PID
#!/bin/bash

set -e

echo "🛡️  AI Prompt Injection Firewall - Installation Script"
echo "======================================================"

# Check if Python 3.8+ is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "✓ Python $PYTHON_VERSION detected"

# Create virtual environment
echo "📦 Setting up virtual environment..."
python3 -m venv aipif-env
source aipif-env/bin/activate

# Install Python dependencies
echo "📥 Installing Python dependencies..."
cd backend
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
echo "📁 Creating project structure..."
mkdir -p logs
mkdir -p model

# Install frontend dependencies (if using any build process)
echo "🌐 Setting up frontend..."
cd ../frontend

# Check if Node.js is available for potential frontend build
if command -v npm &> /dev/null; then
    echo "✓ Node.js detected - frontend ready"
else
    echo "⚠️  Node.js not found - using pre-built frontend"
fi

# Make scripts executable
echo "🔧 Making scripts executable..."
cd ../scripts
chmod +x *.sh

# Create log file
echo "📝 Initializing log file..."
touch ../backend/aipif_logs.jsonl

echo ""
echo "🎉 Installation completed successfully!"
echo ""
echo "Next steps:"
echo "1. Start the system: ./scripts/start.sh"
echo "2. Open http://localhost:8000 in your browser"
echo "3. Check system health: ./scripts/health_check.sh"
echo ""
echo "To run on system boot:"
echo "sudo cp service/aipif.service /etc/systemd/system/"
echo "sudo systemctl enable aipif.service"
echo "sudo systemctl start aipif.service"
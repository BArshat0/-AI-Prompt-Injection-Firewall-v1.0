#!/bin/bash

set -e

echo "❤️  AIPIF Health Check"
echo "===================="

# Check if backend is running
echo "🔍 Checking backend service..."

# Try to connect to the API health endpoint
if curl -f -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "✅ Backend API is responding"

    # Get detailed health info
    HEALTH_JSON=$(curl -s http://localhost:8000/health)
    echo "📊 System status: $(echo $HEALTH_JSON | python3 -c "import sys, json; print(json.load(sys.stdin)['status'])")"

    # Check components
    COMPONENTS=$(echo $HEALTH_JSON | python3 -c "import sys, json; comps = json.load(sys.stdin)['components']; [print(f'✅ {comp}: {status}') for comp, status in comps.items()]")
    echo "$COMPONENTS"

else
    echo "❌ Backend API is not responding"
    echo "💡 Try starting the service: ./scripts/start.sh"
    exit 1
fi

# Check log file
echo ""
echo "📝 Checking log file..."
LOG_FILE="backend/aipif_logs.jsonl"
if [ -f "$LOG_FILE" ]; then
    LOG_SIZE=$(du -h "$LOG_FILE" | cut -f1)
    LOG_LINES=$(wc -l < "$LOG_FILE" 2>/dev/null || echo "0")
    echo "✅ Log file exists: $LOG_SIZE, $LOG_LINES lines"
else
    echo "⚠️  Log file not found"
fi

# Check disk space
echo ""
echo "💾 Checking disk space..."
DISK_INFO=$(df -h . | tail -1)
DISK_USAGE=$(echo $DISK_INFO | awk '{print $5}')
DISK_AVAILABLE=$(echo $DISK_INFO | awk '{print $4}')
echo "📊 Disk usage: $DISK_USAGE, Available: $DISK_AVAILABLE"

# Check memory usage
echo ""
echo "🧠 Checking memory usage..."
MEM_INFO=$(free -h | grep Mem:)
TOTAL_MEM=$(echo $MEM_INFO | awk '{print $2}')
USED_MEM=$(echo $MEM_INFO | awk '{print $3}')
echo "📊 Memory: $USED_MEM used of $TOTAL_MEM"

echo ""
echo "🎉 Health check completed successfully!"
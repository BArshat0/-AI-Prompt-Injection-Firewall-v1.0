#!/bin/bash

set -e

echo "📁 Rotating AIPIF Logs"
echo "======================"

LOG_FILE="backend/aipif_logs.jsonl"
BACKUP_DIR="backend/logs/backups"
DATE_SUFFIX=$(date +%Y-%m-%d)

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Check if log file exists and has content
if [ ! -f "$LOG_FILE" ] || [ ! -s "$LOG_FILE" ]; then
    echo "ℹ️  No logs to rotate"
    exit 0
fi

# Create compressed backup
BACKUP_FILE="$BACKUP_DIR/aipif_logs_$DATE_SUFFIX.jsonl.gz"
echo "📦 Creating backup: $BACKUP_FILE"
gzip -c "$LOG_FILE" > "$BACKUP_FILE"

# Verify backup was created successfully
if [ $? -eq 0 ] && [ -f "$BACKUP_FILE" ]; then
    # Clear current log file
    > "$LOG_FILE"
    echo "✅ Logs rotated successfully"
    echo "📊 Original size: $(du -h "$LOG_FILE" | cut -f1) (now cleared)"
    echo "💾 Backup size: $(du -h "$BACKUP_FILE" | cut -f1)"

    # Remove backups older than 30 days
    echo "🧹 Cleaning up old backups..."
    find "$BACKUP_DIR" -name "aipif_logs_*.jsonl.gz" -mtime +30 -delete
else
    echo "❌ Failed to create backup. Logs not rotated."
    exit 1
fi

echo ""
echo "🎉 Log rotation completed!"
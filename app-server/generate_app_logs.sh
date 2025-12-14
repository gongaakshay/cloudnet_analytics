#!/bin/bash
LOG_DIR="<PATH>/logs"
LOG_FILE="$LOG_DIR/app.log"

mkdir -p "$LOG_DIR"

if [ ! -w "$LOG_DIR" ]; then
    echo "Error: Cannot write to $LOG_DIR" >&2
    exit 1
fi

# Define arrays for more realistic log generation
USERS=("admin" "support" "developer" "user" "guest")
ACTIONS=("LOGIN" "LOGOUT" "CREATE" "UPDATE" "DELETE" "ERROR" "ACCESS_DENIED")

while true; do
    USER=${USERS[$((RANDOM % 5))]}
    ACTION=${ACTIONS[$((RANDOM % 7))]}
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') - User: $USER$((RANDOM % 1000)) - Action: $ACTION" >> "$LOG_FILE"
    sleep 15
done

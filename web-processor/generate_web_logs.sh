#!/bin/bash
LOG_DIR="<PATH>/logs"
LOG_FILE="$LOG_DIR/web.log"

mkdir -p "$LOG_DIR"

if [ ! -w "$LOG_DIR" ]; then
    echo "Error: Cannot write to $LOG_DIR. Check permissions." >&2
    exit 1
fi

while true; do
    # More realistic HTTP methods and endpoints
    METHODS=("GET" "POST" "PUT" "DELETE")
    METHOD=${METHODS[$((RANDOM % 4))]}
    
    # More varied endpoints
    ENDPOINTS=("/api/users" "/dashboard" "/products" "/orders" "/page/$((RANDOM % 100))")
    ENDPOINT=${ENDPOINTS[$((RANDOM % 5))]}
    
    # Generate more realistic IP addresses
    IP="$((RANDOM % 192)).$((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 255))"
    
    # More varied status codes
    STATUS_CODES=(200 201 204 400 401 403 404 500 502 503)
    STATUS=${STATUS_CODES[$((RANDOM % 10))]}
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $METHOD $ENDPOINT - IP: $IP - Status: $STATUS" >> "$LOG_FILE"
    sleep 15
done

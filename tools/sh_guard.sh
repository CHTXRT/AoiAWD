#!/bin/bash
# sh_guard.sh - Bash-based File & Process Monitor for AWD-Defender
# Usage: ./sh_guard.sh <SERVER_IP> <SERVER_PORT>

SERVER_IP=$1
PORT=$2
WATCH_DIR="/var/www/html"
INTERVAL=2

# Helper to send log to TCP Server
send_log() {
    # JSON payload passed as argument $1
    PAYLOAD="$1"
    # echo "Sending: $PAYLOAD"
    # Use /dev/tcp (Bash built-in)
    if >/dev/tcp/$SERVER_IP/$PORT; then
        echo "$PAYLOAD" >/dev/tcp/$SERVER_IP/$PORT
    fi
}

# --- PROCESS MONITOR ---
get_pids() {
    ls /proc | grep -E '^[0-9]+$' | sort
}

# Init Process State
get_pids > /tmp/.wd_pids_old

check_processes() {
    get_pids > /tmp/.wd_pids_new
    # Find new PIDs
    NEW_PIDS=$(comm -13 /tmp/.wd_pids_old /tmp/.wd_pids_new)
    
    if [ ! -z "$NEW_PIDS" ]; then
        for PID in $NEW_PIDS; do
            if [ -f "/proc/$PID/cmdline" ]; then
                # Read cmdline (null delimited) and replace with spaces
                CMD=$(cat /proc/$PID/cmdline | tr '\0' ' ')
                UID_VAL=$(awk '/^Uid:/{print $2}' /proc/$PID/status 2>/dev/null)
                
                # Manual JSON construction
                # simple escaping for quotes
                CMD_ESC=$(echo "$CMD" | sed 's/"/\\"/g')
                
                JSON="{\"type\":\"process\",\"data\":{\"pid\":$PID,\"uid\":\"$UID_VAL\",\"cmd\":\"$CMD_ESC\"}}"
                send_log "$JSON"
            fi
        done
        mv /tmp/.wd_pids_new /tmp/.wd_pids_old
    fi
}

# --- FILE MONITOR ---
# Since inotifywait might not be installed, we use find (polling) efficiently
# Check for modified files in last X minutes
# We use a marker file to track "last check time"
touch /tmp/.wd_last_check

check_files() {
    # Find files modified/created significantly recently (since last check ideally)
    # Using -newer /tmp/.wd_last_check
    
    # Files changed
    CHANGED=$(find $WATCH_DIR -type f -newer /tmp/.wd_last_check 2>/dev/null)
    
    # Update marker immediately
    touch /tmp/.wd_last_check
    
    if [ ! -z "$CHANGED" ]; then
        for F in $CHANGED; do
             # JSON
             F_ESC=$(echo "$F" | sed 's/"/\\"/g')
             JSON="{\"type\":\"file\",\"data\":{\"path\":\"$F_ESC\",\"event\":\"MODIFY/CREATE\"}}"
             send_log "$JSON"
        done
    fi
}

echo "Starting Shell Guard..."
send_log "{\"type\":\"info\",\"data\":{\"msg\":\"Shell Guard Started\"}}"

while true; do
    check_processes
    check_files
    sleep $INTERVAL
done

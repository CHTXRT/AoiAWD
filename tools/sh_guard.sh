#!/bin/bash
# sh_guard.sh - Bash-based File & Process Monitor for AWD-Defender
# Usage: ./sh_guard.sh <SERVER_IP> <SERVER_PORT>

SERVER_IP=${1:-"127.0.0.1"}
SERVER_PORT=${2:-8024}
WATCH_DIR="/var/www/html"
INTERVAL=1
RESOLVED_IP=""

# --- Network Helper ---
get_gateway_ip() {
    # Parse /proc/net/route to find the default gateway
    # Gateway is in the 3rd column (index 2), hex format
    local route_info=$(grep -P '^\w+\t00000000' /proc/net/route | head -n 1)
    if [ -n "$route_info" ]; then
        local hex_gw=$(echo "$route_info" | awk '{print $3}')
        # Convert hex to IP (little endian)
        local ip1=$((16#${hex_gw:6:2}))
        local ip2=$((16#${hex_gw:4:2}))
        local ip3=$((16#${hex_gw:2:2}))
        local ip4=$((16#${hex_gw:0:2}))
        echo "${ip1}.${ip2}.${ip3}.${ip4}"
    fi
}

resolve_and_check() {
    local host=$1
    local port=$2
    # Simple check using timeout and /dev/tcp
    if timeout 1 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
        echo "$host"
        return 0
    fi
    return 1
}

get_working_server_ip() {
    local initial=$1
    local port=$2
    
    # Try initial
    if [ -n "$initial" ]; then
        RES=$(resolve_and_check "$initial" "$port")
        if [ $? -eq 0 ]; then echo "$RES"; return 0; fi
    fi
    
    # Try host.docker.internal
    RES=$(resolve_and_check "host.docker.internal" "$port")
    if [ $? -eq 0 ]; then echo "$RES"; return 0; fi
    
    # Try Gateway
    local gw=$(get_gateway_ip)
    if [ -n "$gw" ]; then
        RES=$(resolve_and_check "$gw" "$port")
        if [ $? -eq 0 ]; then echo "$RES"; return 0; fi
    fi
    
    echo "$initial"
}

send_log() {
    local log_type=$1
    local data=$2
    
    if [ -z "$RESOLVED_IP" ]; then
        RESOLVED_IP=$(get_working_server_ip "$SERVER_IP" "$SERVER_PORT")
    fi
    
    # Construct final JSON
    local payload="{\"type\":\"$log_type\",\"data\":$data}"
    
    # Send via /dev/tcp
    if ! timeout 2 bash -c "echo '$payload' > /dev/tcp/$RESOLVED_IP/$SERVER_PORT" 2>/dev/null; then
        # Reset IP to force re-resolve next time if failed
        RESOLVED_IP=""
    fi
}

# --- PROCESS MONITOR ---
get_pids() {
    ls /proc | grep -E '^[0-9]+$' | sort -n
}

# Init process state
get_pids > /tmp/.wd_pids_old

check_processes() {
    get_pids > /tmp/.wd_pids_new
    local new_pids=$(comm -13 /tmp/.wd_pids_old /tmp/.wd_pids_new)
    
    if [ -n "$new_pids" ]; then
        for pid in $new_pids; do
            if [ -f "/proc/$pid/status" ]; then
                local uid=$(awk '/^Uid:/{print $2}' "/proc/$pid/status")
                # Filter for www-data (UID 33)
                if [ "$uid" == "33" ]; then
                    local cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' | sed 's/"/\\"/g')
                    local now=$(date +%s)
                    local data="{\"pid\":$pid,\"uid\":\"$uid\",\"cmd\":\"$cmd\",\"time\":$now}"
                    send_log "process" "$data"
                fi
            fi
        done
        mv /tmp/.wd_pids_new /tmp/.wd_pids_old
    fi
}

# --- FILE MONITOR ---
touch /tmp/.wd_last_check

check_files() {
    local changed=$(find "$WATCH_DIR" -type f -newer /tmp/.wd_last_check 2>/dev/null)
    touch /tmp/.wd_last_check
    
    if [ -n "$changed" ]; then
        for f in $changed; do
            local f_esc=$(echo "$f" | sed 's/"/\\"/g')
            local now=$(date +%s)
            local content=""
            
            # Read small files (< 4KB)
            if [ -f "$f" ] && [ $(stat -c%s "$f") -lt 4096 ]; then
                content=$(cat "$f" | tr -d '\0' | sed 's/\\/\\\\/g; s/"/\\"/g; s/\$/\\$/g' | awk '{printf "%s\\n", $0}' ORS="")
            fi
            
            local data="{\"path\":\"$f_esc\",\"event\":\"MODIFY/CREATE\",\"time\":$now"
            if [ -n "$content" ]; then
                data="$data,\"content\":\"$content\""
            fi
            data="$data}"
            send_log "file" "$data"
        done
    fi
}

# --- MAIN ---
RESOLVED_IP=$(get_working_server_ip "$SERVER_IP" "$SERVER_PORT")
echo "Starting Shell Guard... Server: $RESOLVED_IP:$SERVER_PORT"

# Async Heartbeat
(
    while true; do
        now=$(date +%s)
        send_log "heartbeat" "{\"time\":$now}"
        sleep 30
    done
) &

while true; do
    check_processes
    check_files
    sleep "$INTERVAL"
done

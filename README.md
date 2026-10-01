# Real-time-Monitor
#!/usr/bin/env bash

set -u

INTERFACE="${1:-$(ip route | awk '/default/ {print $5; exit}')}"
LOGFILE="$HOME/network-security.log"

# Ports that deserve an alert when seen on the network.
SUSPICIOUS_PORTS="21 23 25 110 139 445 1433 1521 3306 3389 4444 5900 6667"

# SYN threshold from one source within the time window.
SYN_THRESHOLD=30
WINDOW=60

declare -A SYN_COUNT
declare -A SYN_TIME

log_alert() {
    local message="$1"

    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    echo "[$timestamp] $message" | tee -a "$LOGFILE"

    notify-send \
        -u critical \
        -t 8000 \
        "🚨 Network Security Alert" \
        "$message"
}

echo "=============================================="
echo "        Bash Network Security Monitor"
echo "=============================================="
echo "Interface : $INTERFACE"
echo "Log file  : $LOGFILE"
echo "Started   : $(date)"
echo "Press Ctrl+C to stop."
echo "=============================================="

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Monitor started on $INTERFACE" >> "$LOGFILE"

sudo tcpdump \
    -l \
    -nn \
    -i "$INTERFACE" \
    -s 0 \
    -A \
    'tcp or udp' |
while IFS= read -r line; do

    # ---------------------------------------------------------
    # Extract IP:PORT -> IP:PORT from tcpdump packet headers
    # ---------------------------------------------------------

    if [[ "$line" =~ IP[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)[[:space:]]+\>[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+) ]]; then

        SRC_IP="${BASH_REMATCH[1]}"
        SRC_PORT="${BASH_REMATCH[2]}"
        DST_IP="${BASH_REMATCH[3]}"
        DST_PORT="${BASH_REMATCH[4]}"

        # -----------------------------------------------------
        # HTTP traffic
        # -----------------------------------------------------

        if [[ "$DST_PORT" == "80" ]]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] HTTP $SRC_IP:$SRC_PORT -> $DST_IP:$DST_PORT" \
                >> "$LOGFILE"

            notify-send \
                -u normal \
                -t 4000 \
                "🌐 HTTP Traffic" \
                "$SRC_IP → $DST_IP:80"
        fi

        # -----------------------------------------------------
        # HTTPS traffic
        # -----------------------------------------------------

        if [[ "$DST_PORT" == "443" ]]; then
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] HTTPS $SRC_IP:$SRC_PORT -> $DST_IP:$DST_PORT" \
                >> "$LOGFILE"
        fi

        # -----------------------------------------------------
        # Suspicious destination ports
        # -----------------------------------------------------

        for PORT in $SUSPICIOUS_PORTS; do
            if [[ "$DST_PORT" == "$PORT" ]]; then

                log_alert \
                    "Suspicious port detected\nSource: $SRC_IP:$SRC_PORT\nDestination: $DST_IP:$DST_PORT"

                break
            fi
        done

        # -----------------------------------------------------
        # Detect SYN packets
        # -----------------------------------------------------

        if [[ "$line" == *"Flags [S]"* ]]; then

            NOW=$(date +%s)

            if [[ -z "${SYN_TIME[$SRC_IP]:-}" ||
                  $((NOW - SYN_TIME[$SRC_IP])) -ge $WINDOW ]]; then

                SYN_TIME[$SRC_IP]=$NOW
                SYN_COUNT[$SRC_IP]=0
            fi

            SYN_COUNT[$SRC_IP]=$((SYN_COUNT[$SRC_IP] + 1))

            if (( SYN_COUNT[$SRC_IP] == SYN_THRESHOLD )); then

                log_alert \
                    "High SYN activity detected\nSource IP: $SRC_IP\nConnections: ${SYN_COUNT[$SRC_IP]} in ${WINDOW}s"
            fi
        fi
    fi

    # ---------------------------------------------------------
    # Detect common HTTP methods in packet payload
    # ---------------------------------------------------------

    if [[ "$line" =~ ^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)[[:space:]] ]]; then

        METHOD="${BASH_REMATCH[1]}"

        log_alert \
            "HTTP request detected\nMethod: $METHOD\nPacket: $line"
    fi

done
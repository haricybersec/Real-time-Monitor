#!/bin/bash

echo "================================="
echo "        CYBER SECURITY"
echo "================================="
echo
echo "   ██╗  ██╗██████╗ "
echo "   ██║  ██║██╔══██╗"
echo "   ███████║██████╔╝"
echo "   ██╔══██║██╔══██╗"
echo "   ██║  ██║██║  ██║"
echo "   ╚═╝  ╚═╝╚═╝  ╚═╝"
echo
echo "        SYSTEM MONITOR"
echo "================================="

set -u

INTERFACE="${1:-$(ip route | awk '/default/ {print $5; exit}')}"
LOGFILE="$HOME/network-security.log"
SSH_LOGFILE="$HOME/ssh-command.log"

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

    echo -e "[$timestamp] $message" | tee -a "$LOGFILE"

    notify-send \
        -u critical \
        -t 8000 \
        "🚨 Network Security Alert" \
        "$message" 2>/dev/null || true
}

log_event() {
    local message="$1"

    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    echo -e "[$timestamp] $message" >> "$LOGFILE"
}

echo "=============================================="
echo "       Bash Network Security Monitor"
echo "=============================================="
echo "Interface     : $INTERFACE"
echo "Network log   : $LOGFILE"
echo "SSH command log: $SSH_LOGFILE"
echo "Started       : $(date)"
echo "Press Ctrl+C to stop."
echo "=============================================="

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Monitor started on $INTERFACE" \
    >> "$LOGFILE"


# =========================================================
# SSH COMMAND LOGGER
# =========================================================
#
# This function is intended to be called from an SSH shell.
# It records commands executed in that SSH session.
#
# It uses SSH_CONNECTION to determine that the shell is
# associated with an SSH connection.
#
# =========================================================

ssh_command_logger() {

    # Only activate inside an SSH session.
    [[ -z "${SSH_CONNECTION:-}" ]] && return

    local command="$BASH_COMMAND"

    # Ignore internal shell commands.
    [[ "$command" == "ssh_command_logger" ]] && return
    [[ "$command" == "_ssh_debug_trap" ]] && return

    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    local source_ip
    source_ip="$(echo "$SSH_CONNECTION" | awk '{print $1}')"

    local source_port
    source_port="$(echo "$SSH_CONNECTION" | awk '{print $2}')"

    local local_ip
    local_ip="$(echo "$SSH_CONNECTION" | awk '{print $3}')"

    local local_port
    local_port="$(echo "$SSH_CONNECTION" | awk '{print $4}')"

    echo "[$timestamp] SSH_COMMAND user=$USER source=$source_ip:$source_port destination=$local_ip:$local_port command=$command" \
        >> "$SSH_LOGFILE"

    echo "[$timestamp] SSH_COMMAND user=$USER source=$source_ip:$source_port command=$command" \
        >> "$LOGFILE"
}


# =========================================================
# INSTALL SSH COMMAND LOGGING FOR CURRENT USER
# =========================================================
#
# Add a DEBUG trap to ~/.bashrc.
#
# It only records commands when SSH_CONNECTION exists.
#
# =========================================================

SSH_MARKER="# --- Bash Network Security SSH Command Logger ---"

if [[ -f "$HOME/.bashrc" ]]; then

    if ! grep -qF "$SSH_MARKER" "$HOME/.bashrc" 2>/dev/null; then

        cat >> "$HOME/.bashrc" <<'EOF'

# --- Bash Network Security SSH Command Logger ---

_ssh_debug_trap() {

    [[ -z "${SSH_CONNECTION:-}" ]] && return

    local cmd="$BASH_COMMAND"

    # Ignore the trap itself.
    [[ "$cmd" == "_ssh_debug_trap" ]] && return

    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    local source_ip
    source_ip="$(echo "$SSH_CONNECTION" | awk '{print $1}')"

    local source_port
    source_port="$(echo "$SSH_CONNECTION" | awk '{print $2}')"

    local destination_ip
    destination_ip="$(echo "$SSH_CONNECTION" | awk '{print $3}')"

    local destination_port
    destination_port="$(echo "$SSH_CONNECTION" | awk '{print $4}')"

    echo "[$timestamp] SSH_COMMAND user=$USER source=$source_ip:$source_port destination=$destination_ip:$destination_port command=$cmd" \
        >> "$HOME/ssh-command.log"

    echo "[$timestamp] SSH_COMMAND user=$USER source=$source_ip:$source_port command=$cmd" \
        >> "$HOME/network-security.log"
}

if [[ -n "${SSH_CONNECTION:-}" ]]; then
    trap '_ssh_debug_trap' DEBUG
fi

# --- End Bash Network Security SSH Command Logger ---

EOF

        echo "[+] SSH command logging added to ~/.bashrc"
    fi
fi


# =========================================================
# SSH CONNECTION MONITOR
# =========================================================

monitor_ssh_connections() {

    declare -A SEEN_SSH

    while true; do

        # Find current TCP connections involving SSH port 22.
        while read -r proto state local remote; do

            [[ -z "$remote" ]] && continue

            # Extract remote IP and port.
            remote_ip="${remote%:*}"
            remote_port="${remote##*:}"

            # Handle IPv4 format.
            [[ "$remote_port" == "22" ]] || continue

            connection_id="$remote_ip:$remote -> $local"

            if [[ -z "${SEEN_SSH[$connection_id]:-}" ]]; then

                SEEN_SSH[$connection_id]=1

                timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

                message="SSH connection detected
Remote: $remote
Local: $local"

                echo "[$timestamp] $message" >> "$LOGFILE"

                notify-send \
                    -u normal \
                    -t 5000 \
                    "🔐 SSH Connection" \
                    "Remote: $remote_ip" \
                    2>/dev/null || true
            fi

        done < <(
            ss -tnH 2>/dev/null |
            awk '$4 ~ /:22$/ || $5 ~ /:22$/ {print $1, $2, $4, $5}'
        )

        sleep 2
    done
}


# =========================================================
# START SSH CONNECTION MONITOR
# =========================================================

monitor_ssh_connections &

SSH_MONITOR_PID=$!

trap 'kill "$SSH_MONITOR_PID" 2>/dev/null || true' EXIT


# =========================================================
# TCPDUMP NETWORK MONITOR
# =========================================================

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
        # SSH traffic
        # -----------------------------------------------------

        if [[ "$DST_PORT" == "22" ]]; then

            log_event \
                "SSH TRAFFIC $SRC_IP:$SRC_PORT -> $DST_IP:$DST_PORT"

        fi


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
                "$SRC_IP → $DST_IP:80" \
                2>/dev/null || true
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
                    "Suspicious port detected
Source: $SRC_IP:$SRC_PORT
Destination: $DST_IP:$DST_PORT"

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
                    "High SYN activity detected
Source IP: $SRC_IP
Connections: ${SYN_COUNT[$SRC_IP]} in ${WINDOW}s"

            fi

        fi

    fi


    # ---------------------------------------------------------
    # Detect common HTTP methods in packet payload
    # ---------------------------------------------------------

    if [[ "$line" =~ ^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)[[:space:]] ]]; then

        METHOD="${BASH_REMATCH[1]}"

        log_alert \
            "HTTP request detected
Method: $METHOD
Packet: $line"

    fi

done
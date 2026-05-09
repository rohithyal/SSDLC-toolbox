#!/usr/bin/env bash
# Structured threat hunt against local log files.
# Covers: brute force, lateral movement, privilege escalation,
#         C2 beaconing, persistence, and data exfiltration indicators.
#
# Usage: ./siem_hunt.sh [log_dir]
#        Defaults to /var/log if no argument given.
#
# Run as root or with read access to auth.log / syslog / journal.

set -euo pipefail

LOG_DIR="${1:-/var/log}"
REPORT="hunt_$(date +%Y%m%d_%H%M).log"
HIT_COUNT=0

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$REPORT"; }
hit() { log "HIT [$1] $2"; HIT_COUNT=$((HIT_COUNT + 1)); }

hunt_brute_force() {
    log "--- Brute Force: SSH failures > 10 attempts (same minute) ---"
    [[ -f "$LOG_DIR/auth.log" ]] || { log "SKIP: $LOG_DIR/auth.log not found"; return; }
    awk '/Failed password/{print $1,$2,$3}' "$LOG_DIR/auth.log" \
    | sort | uniq -c | sort -rn \
    | awk '$1 > 10 {print "count="$1, $2, $3, $4}' \
    | while read -r line; do hit "BRUTE_FORCE" "$line"; done
}

hunt_successful_after_failures() {
    log "--- Auth: successful login from IP that had failures ---"
    [[ -f "$LOG_DIR/auth.log" ]] || return
    failed_ips=$(grep "Failed password" "$LOG_DIR/auth.log" \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
    for ip in $failed_ips; do
        if grep -q "Accepted.*$ip" "$LOG_DIR/auth.log" 2>/dev/null; then
            hit "SUCCESS_AFTER_FAIL" "IP $ip had failures then succeeded"
        fi
    done
}

hunt_lateral_movement() {
    log "--- Lateral Movement: SSH from non-standard accounts ---"
    [[ -f "$LOG_DIR/auth.log" ]] || return
    grep "Accepted publickey" "$LOG_DIR/auth.log" \
    | grep -Ev "root|admin|ec2-user|ubuntu|deploy" \
    | tail -20 \
    | while read -r line; do hit "LATERAL_MOVE" "$line"; done
}

hunt_privesc() {
    log "--- Privilege Escalation: sudo to root by non-standard users ---"
    [[ -f "$LOG_DIR/auth.log" ]] || return
    grep "sudo:.*COMMAND" "$LOG_DIR/auth.log" \
    | grep "USER=root" \
    | grep -Ev "TTY=.*; PWD=.*;.*COMMAND=(/usr/bin/(apt|yum|systemctl|journalctl))" \
    | tail -20 \
    | while read -r line; do hit "PRIVESC" "$line"; done
}

hunt_c2_beaconing() {
    log "--- C2 Beaconing: high-frequency DNS to external hosts ---"
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u systemd-resolved --since "2 hours ago" 2>/dev/null \
        | grep -oE '([a-zA-Z0-9_-]+\.){2,}[a-zA-Z]{2,}' \
        | grep -Ev '(amazonaws|google|microsoft|cloudflare|ubuntu|debian)\.com$' \
        | sort | uniq -c | sort -rn \
        | awk '$1 > 60 {print "count="$1, "domain="$2}' \
        | while read -r line; do hit "C2_BEACON_CANDIDATE" "$line"; done
    else
        log "SKIP: journalctl not available"
    fi
}

hunt_new_persistence() {
    log "--- Persistence: cron/systemd units modified in last 24h ---"
    find /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron \
         /etc/systemd/system /lib/systemd/system \
         -newer /etc/passwd -type f 2>/dev/null \
    | grep -Ev "\.dpkg-|\.bak$" \
    | while read -r f; do hit "NEW_PERSISTENCE" "$f"; done
}

hunt_suid_changes() {
    log "--- Persistence: new SUID/SGID binaries (modified < 7 days) ---"
    find /usr /bin /sbin /tmp /var/tmp \
        -type f \( -perm -4000 -o -perm -2000 \) \
        -newer /etc/passwd 2>/dev/null \
    | while read -r f; do hit "SUID_NEW" "$f"; done
}

hunt_exfil_indicators() {
    log "--- Exfil: large data transfers logged (> 100 MB) ---"
    [[ -f "$LOG_DIR/syslog" ]] || return
    grep -iE "bytes|sent|transferred" "$LOG_DIR/syslog" 2>/dev/null \
    | awk '{
        for(i=1;i<=NF;i++) {
            if($i+0 > 104857600) print "LARGE_TRANSFER bytes="$i,$0
        }
    }' | head -20 \
    | while read -r line; do hit "EXFIL" "$line"; done
}

log "=== Threat Hunt | log_dir: $LOG_DIR | $(date) ==="
hunt_brute_force
hunt_successful_after_failures
hunt_lateral_movement
hunt_privesc
hunt_c2_beaconing
hunt_new_persistence
hunt_suid_changes
hunt_exfil_indicators
log "=== Hunt complete. Hits: $HIT_COUNT | Report: $REPORT ==="

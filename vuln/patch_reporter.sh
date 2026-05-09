#!/usr/bin/env bash
# Patch status reporter for the local Linux host.
# Reports: available security updates, kernel version, last upgrade time,
#          reboot-required state, and status of key security daemons.
#
# Run locally or push via SSH:
#   ssh host "bash -s" < patch_reporter.sh
#   for h in host1 host2; do ssh "$h" "bash -s" < patch_reporter.sh; done

set -euo pipefail

HOST=$(hostname -f)
REPORT="patch_${HOST}_$(date +%Y%m%d).txt"

log()  { echo "$*" | tee -a "$REPORT"; }
sep()  { log ""; log "--- $* ---"; }

log "=== Patch Report | host: $HOST | $(date) ==="
log "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
log "Kernel: $(uname -r)"

sep "Uptime & Load"
uptime | tee -a "$REPORT"

sep "Security updates available"
if command -v apt >/dev/null 2>&1; then
    count=$(apt-get -s upgrade 2>/dev/null \
        | grep "^Inst" | grep -i security \
        | tee -a "$REPORT" | wc -l)
    log "$count security package(s) pending"

    sep "Last upgrade timestamp"
    grep -E "^(Start-Date|Commandline:.*upgrade)" /var/log/apt/history.log 2>/dev/null \
    | tail -6 | tee -a "$REPORT"

    sep "Reboot required"
    [[ -f /var/run/reboot-required ]] \
        && log "REBOOT REQUIRED" \
        || log "No reboot pending"

elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
    mgr="yum"; command -v dnf >/dev/null 2>&1 && mgr="dnf"
    $mgr check-update --security 2>/dev/null | tee -a "$REPORT" || true
else
    log "Unknown package manager — check manually"
fi

sep "Security daemon status"
DAEMONS=(fail2ban ufw firewalld auditd aide ossec wazuh-agent crowdstrike)
for d in "${DAEMONS[@]}"; do
    if systemctl is-active "$d" >/dev/null 2>&1; then
        log "  $d: running"
    elif command -v "$d" >/dev/null 2>&1; then
        log "  $d: installed but NOT running"
    fi
done

sep "Open listening ports"
ss -lntp | tee -a "$REPORT"

sep "Recent auth failures (last 20)"
grep "authentication failure\|Failed password" /var/log/auth.log 2>/dev/null \
| tail -20 | tee -a "$REPORT" || true

log ""
log "=== Done: $REPORT ==="

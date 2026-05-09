#!/usr/bin/env bash
# Incident Response: volatile evidence collection for triage.
# Run this FIRST on a suspected compromised host — before anything else changes.
# Collects: network state, processes, users, persistence, logs, file changes.
# Packages everything into a timestamped tar.gz with SHA-256 checksums
# for chain-of-custody integrity.
#
# Usage: sudo ./ir_collect.sh
#        Transfer: scp ir_<host>_<ts>.tar.gz analyst@ir-server:/evidence/

set -euo pipefail

HOST=$(hostname -s)
TS=$(date +%Y%m%d_%H%M%S)
OUT="ir_${HOST}_${TS}"
mkdir -p "$OUT"

log()     { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/collection.log"; }
collect() {
    local label="$1"; shift
    log ">> $label"
    "$@" > "$OUT/${label}.txt" 2>&1 || true
}

log "=== IR Collection | host: $HOST | $(date) ==="
log "Kernel: $(uname -r) | Uptime: $(uptime -p 2>/dev/null || uptime)"

# ---- Network state (most volatile — grab first) ----
collect "net_connections"    ss -antp
collect "net_listening"      ss -lntp
collect "net_arp"            arp -n
collect "net_routes"         ip route show
collect "net_interfaces"     ip addr show
collect "net_dns"            cat /etc/resolv.conf

# ---- Active sessions ----
collect "users_active"       who
collect "users_history"      last -n 100
collect "users_failed"       lastb -n 100 2>/dev/null

# ---- Process state ----
collect "procs_full"         ps auxf
collect "procs_tree"         pstree -palc 2>/dev/null
collect "procs_env"          cat /proc/*/environ 2>/dev/null | tr '\0' '\n'

# ---- Open files & handles ----
collect "open_files"         lsof -n -P 2>/dev/null

# ---- Persistence mechanisms ----
log ">> persistence_cron"
{
    echo "=== crontab -l (current user) ==="
    crontab -l 2>/dev/null || echo "(none)"
    for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /var/spool/cron; do
        [[ -d "$d" ]] && echo "=== $d ===" && ls -la "$d" && cat "$d"/* 2>/dev/null || true
    done
} > "$OUT/persistence_cron.txt"

collect "persistence_systemd"  systemctl list-units --type=service --state=running --no-pager
collect "persistence_rc_local" cat /etc/rc.local 2>/dev/null
collect "persistence_bashrc"   cat /root/.bashrc /root/.bash_profile /root/.profile 2>/dev/null

# ---- Filesystem anomalies ----
log ">> files_modified_1h (this may take a moment)"
find / -newer /tmp \
    -not -path "/proc/*" -not -path "/sys/*" \
    -not -path "/run/*"  -not -path "/dev/*" \
    -type f -mmin -60 2>/dev/null \
> "$OUT/files_modified_1h.txt"

collect "files_suid_sgid" \
    find / -type f \( -perm -4000 -o -perm -2000 \) -not -path "/proc/*" 2>/dev/null

collect "files_tmp_exec" \
    find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null

# ---- System state ----
collect "kernel_modules"     lsmod
collect "iptables_rules"     iptables -L -n -v 2>/dev/null
collect "hosts_file"         cat /etc/hosts
collect "env_vars"           env
collect "dmesg_tail"         dmesg | tail -200

# ---- Credentials / shadow (for integrity check, not exfil) ----
collect "passwd"             cat /etc/passwd
collect "shadow_users"       awk -F: '$2 !~ /^[!*x]/ {print $1}' /etc/shadow 2>/dev/null

# ---- Logs ----
log ">> copying logs"
for f in /var/log/auth.log /var/log/syslog /var/log/secure /var/log/messages; do
    [[ -f "$f" ]] && cp "$f" "$OUT/$(basename "$f")" || true
done
journalctl --since "12 hours ago" --no-pager > "$OUT/journal_12h.log" 2>/dev/null || true

# ---- Integrity: hash all collected files ----
log ">> computing checksums"
find "$OUT" -type f | sort | xargs sha256sum > "$OUT/CHECKSUMS.sha256"

# ---- Package ----
tar czf "${OUT}.tar.gz" "$OUT/"
rm -rf "${OUT:?}/"

log "=== Collection complete: ${OUT}.tar.gz ==="
echo ""
echo "Transfer command:"
echo "  scp ${OUT}.tar.gz analyst@ir-server:/evidence/"

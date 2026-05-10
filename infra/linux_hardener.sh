#!/usr/bin/env bash
# Linux hardening audit — CIS Benchmark Level 1 inspired.
# Checks current system state against hardening baselines.
# READ-ONLY: reports gaps, does not modify configuration.
#
# Run with --apply to write recommended sysctl and SSH settings.
# Always review output before applying on production systems.
#
# Usage:
#   sudo ./linux_hardener.sh           # audit only
#   sudo ./linux_hardener.sh --apply   # audit + apply safe defaults

set -euo pipefail

APPLY="${1:-}"
REPORT="hardening_$(hostname -s)_$(date +%Y%m%d_%H%M).log"
FAIL=0
WARN=0

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$REPORT"; }
pass() { log "PASS  $*"; }
fail() { log "FAIL  $*"; FAIL=$((FAIL + 1)); }
warn() { log "WARN  $*"; WARN=$((WARN + 1)); }
section() { log ""; log "=== $* ==="; }

# ── SSH hardening ─────────────────────────────────────────────────────────────

check_ssh() {
    section "SSH Configuration"
    [[ -f /etc/ssh/sshd_config ]] || { warn "sshd_config not found"; return; }

    ssh_check() {
        local key="$1" want="$2"
        local val
        val=$(grep -E "^\s*${key}\s" /etc/ssh/sshd_config 2>/dev/null \
              | awk '{print $2}' | tail -1)
        if [[ -z "$val" ]]; then
            warn "SSH $key: not set (default may be unsafe)"
        elif [[ "${val,,}" == "${want,,}" ]]; then
            pass "SSH $key: $val"
        else
            fail "SSH $key: $val (want: $want)"
        fi
    }

    ssh_check "PermitRootLogin"            "no"
    ssh_check "PasswordAuthentication"     "no"
    ssh_check "PermitEmptyPasswords"       "no"
    ssh_check "ChallengeResponseAuthentication" "no"
    ssh_check "X11Forwarding"             "no"
    ssh_check "MaxAuthTries"              "4"
    ssh_check "Protocol"                  "2"
    ssh_check "AllowAgentForwarding"      "no"
    ssh_check "AllowTcpForwarding"        "no"

    # check for idle timeout
    timeout_val=$(grep -E "^\s*ClientAliveInterval\s" /etc/ssh/sshd_config \
        | awk '{print $2}' | tail -1 || echo "0")
    if [[ "${timeout_val:-0}" -gt 0 && "${timeout_val:-0}" -le 300 ]]; then
        pass "SSH ClientAliveInterval: $timeout_val"
    else
        fail "SSH ClientAliveInterval not set or > 300s — idle sessions not timed out"
    fi

    if [[ "$APPLY" == "--apply" ]]; then
        log "Applying SSH hardening..."
        cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%Y%m%d)"
        {
            grep -Ev "^(PermitRootLogin|PasswordAuthentication|X11Forwarding|MaxAuthTries|ClientAliveInterval|ClientAliveCountMax)" \
                /etc/ssh/sshd_config
            echo "PermitRootLogin no"
            echo "PasswordAuthentication no"
            echo "X11Forwarding no"
            echo "MaxAuthTries 4"
            echo "ClientAliveInterval 300"
            echo "ClientAliveCountMax 2"
        } > /tmp/sshd_config_new
        mv /tmp/sshd_config_new /etc/ssh/sshd_config
        systemctl reload sshd 2>/dev/null || service sshd reload 2>/dev/null || true
        log "SSH hardening applied and sshd reloaded"
    fi
}

# ── Kernel parameters (sysctl) ────────────────────────────────────────────────

check_sysctl() {
    section "Kernel Parameters (sysctl)"

    sysctl_check() {
        local key="$1" want="$2"
        local val
        val=$(sysctl -n "$key" 2>/dev/null || echo "MISSING")
        if [[ "$val" == "MISSING" ]]; then
            warn "sysctl $key: not available on this kernel"
        elif [[ "$val" == "$want" ]]; then
            pass "sysctl $key: $val"
        else
            fail "sysctl $key: $val (want: $want)"
        fi
    }

    # Network hardening
    sysctl_check "net.ipv4.ip_forward"                     "0"
    sysctl_check "net.ipv4.conf.all.send_redirects"        "0"
    sysctl_check "net.ipv4.conf.default.send_redirects"    "0"
    sysctl_check "net.ipv4.conf.all.accept_redirects"      "0"
    sysctl_check "net.ipv4.conf.all.accept_source_route"   "0"
    sysctl_check "net.ipv4.conf.all.log_martians"          "1"
    sysctl_check "net.ipv4.icmp_echo_ignore_broadcasts"    "1"
    sysctl_check "net.ipv4.icmp_ignore_bogus_error_responses" "1"
    sysctl_check "net.ipv4.tcp_syncookies"                 "1"
    sysctl_check "net.ipv6.conf.all.disable_ipv6"          "1"

    # Memory protection
    sysctl_check "kernel.randomize_va_space"               "2"
    sysctl_check "kernel.dmesg_restrict"                   "1"
    sysctl_check "kernel.kptr_restrict"                    "2"
    sysctl_check "kernel.yama.ptrace_scope"                "1"
    sysctl_check "fs.protected_hardlinks"                  "1"
    sysctl_check "fs.protected_symlinks"                   "1"
    sysctl_check "fs.suid_dumpable"                        "0"

    if [[ "$APPLY" == "--apply" ]]; then
        log "Applying sysctl hardening..."
        cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.disable_ipv6 = 1
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF
        sysctl --system >/dev/null
        log "sysctl hardening applied"
    fi
}

# ── File permissions ──────────────────────────────────────────────────────────

check_file_perms() {
    section "File Permissions"

    perm_check() {
        local file="$1" want_max="$2"
        [[ -f "$file" ]] || { warn "$file: not found"; return; }
        local perms
        perms=$(stat -c "%a" "$file")
        if [[ "$perms" -le "$want_max" ]]; then
            pass "$file: $perms"
        else
            fail "$file: $perms (want <= $want_max)"
        fi
    }

    perm_check "/etc/passwd"  644
    perm_check "/etc/shadow"  640
    perm_check "/etc/group"   644
    perm_check "/etc/gshadow" 640
    perm_check "/etc/ssh/sshd_config" 600
    perm_check "/boot/grub/grub.cfg"  600

    # world-writable files outside /tmp
    log "Checking for world-writable files outside /tmp..."
    ww=$(find / -xdev -type f -perm -o+w \
        -not -path "/tmp/*" -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null \
        | head -10)
    if [[ -n "$ww" ]]; then
        while IFS= read -r f; do fail "World-writable: $f"; done <<< "$ww"
    else
        pass "No world-writable files outside /tmp"
    fi
}

# ── Service minimisation ──────────────────────────────────────────────────────

check_services() {
    section "Running Services"

    UNNECESSARY=(
        telnet ftp rsh rlogin rexec
        nis ypbind tftp talk ntalk
        chargen daytime discard echo time
        xinetd inetd
    )

    for svc in "${UNNECESSARY[@]}"; do
        if systemctl is-active "$svc" >/dev/null 2>&1; then
            fail "Unnecessary service running: $svc"
        fi
    done
    pass "No legacy/unnecessary services detected"

    # check for listening services that shouldn't be exposed
    log "Listening on all interfaces (0.0.0.0 / ::):"
    ss -lntp 2>/dev/null | grep -E "0\.0\.0\.0|::" \
        | grep -Ev "127\.|::1" | tee -a "$REPORT" || true
}

# ── Auditd ────────────────────────────────────────────────────────────────────

check_auditd() {
    section "Auditd"
    if systemctl is-active auditd >/dev/null 2>&1; then
        pass "auditd: running"
        rule_count=$(auditctl -l 2>/dev/null | grep -c "^-" || echo 0)
        [[ "$rule_count" -gt 0 ]] \
            && pass "auditd: $rule_count rules loaded" \
            || warn "auditd: no rules loaded — add rules for logins, privilege use, file access"
    else
        fail "auditd: not running — no kernel audit trail"
    fi
}

# ── Users and passwords ───────────────────────────────────────────────────────

check_users() {
    section "User Accounts"

    # accounts with no password
    awk -F: '($2 == "" || $2 == "!") && $1 != "nologin" { print "NO_PASSWORD:", $1 }' \
        /etc/shadow 2>/dev/null \
    | while read -r line; do warn "$line"; done

    # UID 0 accounts other than root
    awk -F: '$3 == 0 && $1 != "root" { print "UID_ZERO:", $1 }' /etc/passwd \
    | while read -r line; do fail "$line"; done

    # users with login shell who are not in sudoers
    log "Users with login shells:"
    grep -E "(/bash|/sh|/zsh|/fish)$" /etc/passwd | awk -F: '{print "  "$1}' | tee -a "$REPORT"
}

# ── Fail2ban ──────────────────────────────────────────────────────────────────

check_fail2ban() {
    section "Brute Force Protection"
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        pass "fail2ban: running"
        fail2ban-client status 2>/dev/null | grep "Jail list" | tee -a "$REPORT" || true
    else
        fail "fail2ban: not running — no brute force protection"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

[[ "$(id -u)" -ne 0 ]] && { echo "Run as root"; exit 1; }

log "=== Linux Hardening Audit | host: $(hostname -f) | $(date) ==="
[[ "$APPLY" == "--apply" ]] && log "Mode: AUDIT + APPLY" || log "Mode: AUDIT ONLY"

check_ssh
check_sysctl
check_file_perms
check_services
check_auditd
check_users
check_fail2ban

log ""
log "=== Done. Failures: $FAIL | Warnings: $WARN | Report: $REPORT ==="
[[ $FAIL -gt 0 ]] && exit 1 || exit 0

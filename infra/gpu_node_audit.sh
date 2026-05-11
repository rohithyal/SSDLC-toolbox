#!/usr/bin/env bash
# Security audit for on-premise GPU nodes.
# Checks: driver CVE exposure, unauthorised processes on GPUs,
#         network isolation, remote management exposure,
#         GPU node access controls, and resource monitoring.
#
# Designed for bare-metal or on-prem servers running NVIDIA GPUs
# for inference or training workloads.
#
# Prerequisites: nvidia-smi, ss, ps, awk
# Usage: sudo ./gpu_node_audit.sh

set -euo pipefail

HOST=$(hostname -s)
REPORT="gpu_audit_${HOST}_$(date +%Y%m%d_%H%M).log"
FAIL=0
WARN=0

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$REPORT"; }
pass() { log "PASS  $*"; }
fail() { log "FAIL  $*"; FAIL=$((FAIL + 1)); }
warn() { log "WARN  $*"; WARN=$((WARN + 1)); }
section() { log ""; log "=== $* ==="; }

check_deps() {
    command -v nvidia-smi >/dev/null || { echo "nvidia-smi required"; exit 1; }
}

# ── Driver and firmware ───────────────────────────────────────────────────────

check_driver() {
    section "GPU Driver"
    driver_ver=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -1)
    log "Driver version: $driver_ver"

    # NVIDIA driver branches — flag anything below current stable branch
    # Update this when NVIDIA publishes new stable branch (check https://www.nvidia.com/drivers)
    MINIMUM_DRIVER="535.0"
    if awk "BEGIN {exit !($driver_ver < $MINIMUM_DRIVER)}"; then
        warn "Driver $driver_ver may be below current stable branch $MINIMUM_DRIVER — check NVIDIA security bulletins"
    else
        pass "Driver $driver_ver: within expected range"
    fi

    # CUDA version
    cuda_ver=$(nvidia-smi | grep "CUDA Version" | awk '{print $NF}' || echo "unknown")
    log "CUDA version: $cuda_ver"
}

# ── GPU process audit ─────────────────────────────────────────────────────────

check_gpu_processes() {
    section "GPU Process Audit"

    # who is running compute on the GPUs right now
    log "Current GPU compute processes:"
    nvidia-smi --query-compute-apps=gpu_uuid,pid,used_memory,process_name \
        --format=csv,noheader 2>/dev/null \
    | while IFS=',' read -r gpu pid mem procname; do
        procname=$(echo "$procname" | xargs)
        pid=$(echo "$pid" | xargs)
        owner=$(ps -o user= -p "$pid" 2>/dev/null | xargs || echo "unknown")
        log "  GPU=$gpu PID=$pid user=$owner mem=$mem proc=$procname"

        # flag unexpected process names
        if echo "$procname" | grep -qE "^(/tmp|/dev/shm|/var/tmp)"; then
            fail "GPU process running from temp path: $procname (PID $pid, user $owner)"
        fi

        # flag processes owned by non-service users
        if echo "$owner" | grep -qvE "^(root|nvidia|gpu|mlops|inference|training|nobody)$"; then
            warn "GPU process owned by non-standard user: $owner (PID $pid, $procname)"
        fi
    done

    # total GPU count and utilisation
    log "GPU utilisation:"
    nvidia-smi --query-gpu=index,name,utilization.gpu,temperature.gpu,memory.used,memory.total \
        --format=csv,noheader | tee -a "$REPORT"
}

# ── Network exposure ──────────────────────────────────────────────────────────

check_network() {
    section "Network Exposure"

    # GPU nodes should not be directly internet-accessible
    # Check for unexpected listening services
    log "Listening ports:"
    ss -lntp 2>/dev/null | tee -a "$REPORT"

    # Specific dangerous ports for ML infrastructure
    DANGEROUS_PORTS=(
        "8888:Jupyter notebook (no auth by default)"
        "8080:Common ML serving port"
        "6006:TensorBoard"
        "5000:Flask default — often dev model servers"
        "8000:Common FastAPI/uvicorn serving port"
        "2375:Docker daemon (unencrypted)"
        "2376:Docker daemon"
        "4040:Spark UI"
        "8265:Ray dashboard"
        "8787:Dask dashboard"
    )

    for entry in "${DANGEROUS_PORTS[@]}"; do
        port="${entry%%:*}"
        desc="${entry#*:}"
        if ss -lntp 2>/dev/null | grep -q ":${port}\b"; then
            # check if bound to all interfaces
            if ss -lntp 2>/dev/null | grep ":${port}\b" | grep -qE "0\.0\.0\.0|:::"; then
                fail "Port $port open on all interfaces: $desc"
            else
                warn "Port $port listening (loopback only): $desc — verify access control"
            fi
        fi
    done

    # NVIDIA fabric manager port (used in multi-GPU setups)
    if ss -lntp 2>/dev/null | grep -q ":59100\b"; then
        log "NVIDIA Fabric Manager: listening on 59100 (expected for NVLink)"
    fi
}

# ── Remote management ─────────────────────────────────────────────────────────

check_remote_mgmt() {
    section "Remote Management"

    # IPMI / BMC exposure
    if command -v ipmitool >/dev/null 2>&1; then
        log "IPMI: ipmitool found"
        # check if IPMI is using default credentials
        if ipmitool -I lanplus -H 127.0.0.1 -U ADMIN -P ADMIN chassis status \
            >/dev/null 2>&1; then
            fail "IPMI: default credentials (ADMIN/ADMIN) accepted — change immediately"
        else
            pass "IPMI: default credentials rejected"
        fi
    fi

    # check for NVIDIA DCGM (Data Center GPU Manager) — good for monitoring but needs auth
    if systemctl is-active nv-hostengine >/dev/null 2>&1; then
        pass "NVIDIA DCGM host engine: running"
    else
        warn "NVIDIA DCGM: not running — consider enabling for GPU health monitoring"
    fi

    # SSH key-only auth check (repeated from linux_hardener but critical for GPU nodes)
    passwd_auth=$(grep -E "^\s*PasswordAuthentication\s" /etc/ssh/sshd_config \
        | awk '{print $2}' | tail -1 || echo "unset")
    [[ "${passwd_auth,,}" == "no" ]] \
        && pass "SSH password auth: disabled" \
        || fail "SSH password auth: enabled — GPU nodes must use key auth only"
}

# ── GPU node access control ───────────────────────────────────────────────────

check_access_control() {
    section "Access Control"

    # check who has sudo on this node
    log "Sudoers with unrestricted access:"
    grep -E "ALL\s*=\s*(\(ALL\)|ALL)" /etc/sudoers /etc/sudoers.d/* 2>/dev/null \
    | grep -v "^#" \
    | tee -a "$REPORT"

    # GPU device permissions
    log "GPU device permissions:"
    ls -la /dev/nvidia* 2>/dev/null | tee -a "$REPORT" || warn "/dev/nvidia* not found"

    # check that GPU devices are not world-readable
    if find /dev -maxdepth 1 -name "nvidia*" -print0 2>/dev/null \
        | xargs -0 stat -c "%a %n" 2>/dev/null \
        | awk '$1 ~ /7$/ {print "WORLD_ACCESSIBLE:", $2}' \
        | grep -q "WORLD"; then
        fail "GPU device nodes are world-accessible — restrict to gpu group"
    else
        pass "GPU device permissions: restricted"
    fi

    # verify nvidia group exists and is populated
    if getent group nvidia >/dev/null 2>&1 || getent group gpu >/dev/null 2>&1; then
        pass "GPU user group exists"
    else
        warn "No 'nvidia' or 'gpu' group — consider group-based GPU access control"
    fi
}

# ── Persistent monitoring health ──────────────────────────────────────────────

check_monitoring() {
    section "Monitoring Health"

    # DCGM exporter for Prometheus
    if systemctl is-active dcgm-exporter >/dev/null 2>&1; then
        pass "DCGM Prometheus exporter: running"
    else
        warn "DCGM exporter: not running — GPU metrics not exported to Prometheus"
    fi

    # node exporter
    if systemctl is-active node_exporter >/dev/null 2>&1; then
        pass "Node exporter: running"
    else
        warn "Node exporter: not running"
    fi

    # check for thermal throttling (sustained high temp = cooling issue = availability risk)
    log "GPU thermal state:"
    nvidia-smi --query-gpu=index,temperature.gpu,clocks_throttle_reasons.sw_thermal_slowdown \
        --format=csv,noheader 2>/dev/null \
    | while IFS=',' read -r idx temp throttled; do
        temp=$(echo "$temp" | xargs)
        throttled=$(echo "$throttled" | xargs)
        if [[ "$throttled" == "Active" ]]; then
            fail "GPU $idx: thermal throttling ACTIVE (${temp}C) — cooling issue"
        elif [[ "${temp:-0}" -gt 85 ]]; then
            warn "GPU $idx: temperature high (${temp}C) — monitor closely"
        else
            pass "GPU $idx: temperature OK (${temp}C)"
        fi
    done
}

check_deps
log "=== GPU Node Security Audit | host: $HOST | $(date) ==="
check_driver
check_gpu_processes
check_network
check_remote_mgmt
check_access_control
check_monitoring
log ""
log "=== Done. Failures: $FAIL | Warnings: $WARN | Report: $REPORT ==="
[[ $FAIL -gt 0 ]] && exit 1 || exit 0

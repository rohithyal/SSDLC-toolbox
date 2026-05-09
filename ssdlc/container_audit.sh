#!/usr/bin/env bash
# Docker container security audit.
# Checks Dockerfiles for best-practice violations and
# inspects running containers for runtime misconfigurations.
# Runs Trivy image scans if installed.
#
# Usage: ./container_audit.sh [path_to_search]
#        Defaults to current directory.

set -euo pipefail

TARGET="${1:-.}"
REPORT="container_audit_$(date +%Y%m%d_%H%M).log"
FAIL=0
WARN=0

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$REPORT"; }
fail() { log "FAIL  $*"; FAIL=$((FAIL + 1)); }
pass() { log "PASS  $*"; }
warn() { log "WARN  $*"; WARN=$((WARN + 1)); }

check_deps() {
    command -v docker >/dev/null || { echo "docker required"; exit 1; }
}

audit_dockerfile() {
    local df="$1"
    log "--- Dockerfile: $df ---"

    # non-root USER required
    if grep -qE "^USER\s+([^r]|r[^o]|ro[^o]|roo[^t])" "$df" 2>/dev/null || \
       grep -qE "^USER\s+[0-9]{4,}" "$df" 2>/dev/null; then
        pass "$df: non-root USER set"
    else
        fail "$df: no non-root USER directive — container will run as root"
    fi

    # pinned base image
    if grep -qE "^FROM .+:latest(\s|$)" "$df"; then
        fail "$df: FROM uses :latest — pin to a specific digest"
    elif grep -qE "^FROM .+@sha256:[a-f0-9]{64}" "$df"; then
        pass "$df: base image pinned to digest"
    else
        pass "$df: base image tag is not :latest"
    fi

    # ADD vs COPY
    if grep -qE "^ADD\s" "$df"; then
        warn "$df: ADD used — prefer COPY unless extracting a tar archive"
    fi

    # secrets in ENV
    if grep -qE "^ENV\s.*(PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL)\s*=" "$df"; then
        fail "$df: secret-like ENV variable — use --mount=type=secret at build time"
    fi

    # curl | sh install pattern
    if grep -qE "curl.+\|.+(ba)?sh|wget.+\|.+(ba)?sh" "$df"; then
        fail "$df: curl-pipe-shell install pattern — verify checksums instead"
    fi

    # privileged: no in Dockerfile, but check for --privileged hints
    if grep -qiE "privileged|cap_add.*ALL" "$df"; then
        fail "$df: privileged or CAP_ADD ALL found"
    fi

    # HEALTHCHECK
    if ! grep -q "^HEALTHCHECK" "$df"; then
        warn "$df: no HEALTHCHECK — container restarts blindly on failure"
    else
        pass "$df: HEALTHCHECK present"
    fi

    # secrets in COPY/ADD source
    if grep -qE "^(COPY|ADD)\s.*(\.(pem|key|p12|pfx|env))" "$df"; then
        fail "$df: private key or .env file copied into image"
    fi
}

audit_running_containers() {
    log "--- Running containers ---"
    local ids
    ids=$(docker ps -q 2>/dev/null)
    [[ -z "$ids" ]] && { log "  no containers running"; return; }

    for id in $ids; do
        name=$(docker inspect "$id" --format '{{.Name}}' | tr -d '/')
        image=$(docker inspect "$id" --format '{{.Config.Image}}')
        log "Container: $name ($id) | image: $image"

        # privileged
        priv=$(docker inspect "$id" --format '{{.HostConfig.Privileged}}')
        [[ "$priv" == "true" ]] \
            && fail "$name: privileged mode — full host access" \
            || pass "$name: not privileged"

        # root user
        user=$(docker inspect "$id" --format '{{.Config.User}}')
        [[ -z "$user" || "$user" == "root" || "$user" == "0" ]] \
            && fail "$name: running as root" \
            || pass "$name: user=$user"

        # host network
        net=$(docker inspect "$id" --format '{{.HostConfig.NetworkMode}}')
        [[ "$net" == "host" ]] \
            && fail "$name: host network mode — bypasses isolation" \
            || pass "$name: network mode=$net"

        # read-only root fs
        ro=$(docker inspect "$id" --format '{{.HostConfig.ReadonlyRootfs}}')
        [[ "$ro" == "true" ]] \
            && pass "$name: read-only root filesystem" \
            || warn "$name: writable root filesystem"

        # extra capabilities
        caps=$(docker inspect "$id" --format '{{.HostConfig.CapAdd}}')
        [[ "$caps" != "[]" && -n "$caps" ]] \
            && warn "$name: added capabilities: $caps"

        # mounts — flag bind mounts of sensitive host paths
        docker inspect "$id" --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}} {{end}}{{end}}' \
        | tr ' ' '\n' | grep -E "^/(etc|root|var/run/docker.sock|proc|sys)" \
        | while read -r mount; do
            fail "$name: sensitive host path mounted: $mount"
        done
    done
}

run_trivy() {
    command -v trivy >/dev/null 2>&1 || return
    log "--- Trivy: image vulnerability scan ---"
    docker ps --format '{{.Image}}' | sort -u \
    | while read -r image; do
        log "  Scanning: $image"
        trivy image --severity HIGH,CRITICAL --quiet "$image" 2>&1 | tee -a "$REPORT" || true
    done
}

check_deps
log "=== Container Audit | target: $TARGET | $(date) ==="

find "$TARGET" -name "Dockerfile*" -not -path "*/.git/*" 2>/dev/null \
| while read -r df; do audit_dockerfile "$df"; done

audit_running_containers
run_trivy

log "=== Done. Failures: $FAIL | Warnings: $WARN | Report: $REPORT ==="
[[ $FAIL -gt 0 ]] && exit 1 || exit 0

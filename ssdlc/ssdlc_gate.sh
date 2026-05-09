#!/usr/bin/env bash
# SSDLC Pipeline Security Gate
# Blocks merges/deploys when any critical security check fails.
# Designed to run in GitHub Actions, GitLab CI, or Jenkins.
#
# Gates (uses whatever tools are available in CI):
#   1. Secret scanning   — gitleaks or trufflehog
#   2. SAST              — semgrep or bandit
#   3. Dependency audit  — safety (Python), npm audit, or trivy fs
#   4. IaC scanning      — checkov
#   5. Container audit   — trivy image
#
# Exit code 0 = all gates passed. Non-zero = pipeline should be blocked.
#
# Usage: ./ssdlc_gate.sh
#        In CI: add as a step before build/deploy stages.

set -euo pipefail

REPORT="ssdlc_gate_$(date +%Y%m%d_%H%M).log"
PASS=0
FAIL=0

log()       { echo "[$(date +%H:%M:%S)] $*" | tee -a "$REPORT"; }
gate_pass() { log "GATE PASS: $*"; PASS=$((PASS + 1)); }
gate_fail() { log "GATE FAIL: $*"; FAIL=$((FAIL + 1)); }
skip()      { log "GATE SKIP: $* (tool not found)"; }

# ---- Gate 1: Secret Scanning ----
gate_secrets() {
    log "=== Gate 1: Secret Scanning ==="
    if command -v gitleaks >/dev/null 2>&1; then
        if gitleaks detect --source . --no-banner 2>&1 | tee -a "$REPORT"; then
            gate_pass "gitleaks: no secrets in history"
        else
            gate_fail "gitleaks: secrets detected — rotate before merging"
        fi
    elif command -v trufflehog >/dev/null 2>&1; then
        if trufflehog git file://. --only-verified --no-update 2>&1 | tee -a "$REPORT"; then
            gate_pass "trufflehog: no verified secrets"
        else
            gate_fail "trufflehog: verified secrets found"
        fi
    else
        skip "secret scanner (install gitleaks: brew install gitleaks)"
    fi
}

# ---- Gate 2: SAST ----
gate_sast() {
    log "=== Gate 2: SAST ==="
    if command -v semgrep >/dev/null 2>&1; then
        if semgrep --config=auto --severity ERROR --quiet --no-git-ignore 2>&1 \
            | tee -a "$REPORT"; then
            gate_pass "semgrep: no ERROR-level findings"
        else
            gate_fail "semgrep: ERROR findings block merge"
        fi
    elif command -v bandit >/dev/null 2>&1; then
        py_files=$(find . -name "*.py" -not -path "./.git/*" 2>/dev/null | head -1)
        if [[ -n "$py_files" ]]; then
            if bandit -r . -l -q 2>&1 | tee -a "$REPORT"; then
                gate_pass "bandit: no high-severity issues"
            else
                gate_fail "bandit: high-severity Python issues found"
            fi
        else
            gate_pass "bandit: no Python files to scan"
        fi
    else
        skip "SAST (install semgrep: pip install semgrep)"
    fi
}

# ---- Gate 3: Dependency Vulnerability Check ----
gate_deps() {
    log "=== Gate 3: Dependency Audit ==="
    checked=0

    if [[ -f requirements.txt ]] && command -v safety >/dev/null 2>&1; then
        if safety check -r requirements.txt --short-report 2>&1 | tee -a "$REPORT"; then
            gate_pass "safety: Python deps clean"
        else
            gate_fail "safety: vulnerable Python packages found"
        fi
        checked=1
    fi

    if [[ -f package.json ]] && command -v npm >/dev/null 2>&1; then
        if npm audit --audit-level=high 2>&1 | tee -a "$REPORT"; then
            gate_pass "npm audit: no high/critical vulns"
        else
            gate_fail "npm audit: high or critical vulns found"
        fi
        checked=1
    fi

    if command -v trivy >/dev/null 2>&1; then
        if trivy fs --severity HIGH,CRITICAL --quiet --exit-code 1 . 2>&1 \
            | tee -a "$REPORT"; then
            gate_pass "trivy fs: no HIGH/CRITICAL in dependencies"
        else
            gate_fail "trivy fs: HIGH/CRITICAL dependency vulns found"
        fi
        checked=1
    fi

    [[ $checked -eq 0 ]] && skip "dependency audit (install trivy or safety)"
}

# ---- Gate 4: IaC Security ----
gate_iac() {
    log "=== Gate 4: IaC Security ==="
    iac_files=$(find . \( -name "*.tf" -o -name "*.yaml" \
        -o -name "docker-compose*.yml" -o -name "docker-compose*.yaml" \) \
        -not -path "./.git/*" 2>/dev/null | head -1)

    if [[ -z "$iac_files" ]]; then
        log "GATE SKIP: IaC (no .tf / docker-compose / .yaml files found)"
        return
    fi

    if command -v checkov >/dev/null 2>&1; then
        if checkov -d . --quiet --compact --soft-fail-on MEDIUM,LOW 2>&1 \
            | tee -a "$REPORT"; then
            gate_pass "checkov: no HIGH/CRITICAL IaC issues"
        else
            gate_fail "checkov: HIGH/CRITICAL IaC misconfigurations found"
        fi
    else
        skip "IaC scanner (install checkov: pip install checkov)"
    fi
}

# ---- Gate 5: Container Image Scan ----
gate_container() {
    log "=== Gate 5: Container Image Scan ==="
    dockerfiles=$(find . -name "Dockerfile*" -not -path "./.git/*" 2>/dev/null | head -1)
    [[ -z "$dockerfiles" ]] && { log "GATE SKIP: container (no Dockerfiles found)"; return; }

    if command -v trivy >/dev/null 2>&1; then
        # scan any locally tagged images
        images=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null \
            | grep -v "<none>" | head -5)
        if [[ -n "$images" ]]; then
            for img in $images; do
                if trivy image --severity HIGH,CRITICAL --quiet --exit-code 1 \
                    "$img" 2>&1 | tee -a "$REPORT"; then
                    gate_pass "trivy image: $img clean"
                else
                    gate_fail "trivy image: HIGH/CRITICAL vulns in $img"
                fi
            done
        else
            log "GATE SKIP: container images (no local images found — build first)"
        fi
    else
        skip "container scanner (install trivy)"
    fi
}

log "=== SSDLC Security Gate | $(date) ==="
gate_secrets
gate_sast
gate_deps
gate_iac
gate_container
log "=== Gate Summary: PASS=$PASS FAIL=$FAIL | Report: $REPORT ==="

if [[ $FAIL -gt 0 ]]; then
    log "PIPELINE BLOCKED — $FAIL gate(s) failed. Fix issues above before merging."
    exit 1
fi

log "All gates passed. Safe to proceed."
exit 0

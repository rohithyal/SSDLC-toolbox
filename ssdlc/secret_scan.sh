#!/usr/bin/env bash
# Pre-merge secret scanner for git repositories.
# Uses gitleaks if installed; falls back to regex pattern matching via git log -p.
# Scans full git history, not just the working tree.
# Exits non-zero if secrets are found — wire into CI to block merges.
#
# Usage: ./secret_scan.sh [repo_path]
#        Defaults to current directory.

set -euo pipefail

TARGET="${1:-.}"
REPORT="secrets_$(date +%Y%m%d_%H%M).log"
SARIF="gitleaks_$(date +%Y%m%d).sarif"
FOUND=0

log()   { echo "[$(date +%H:%M:%S)] $*" | tee -a "$REPORT"; }
found() { log "SECRET [$1]: $2"; FOUND=$((FOUND + 1)); }

# patterns: (label, regex)
declare -a PATTERNS=(
    "AWS_AKID:AKIA[0-9A-Z]{16}"
    "PRIVATE_KEY:-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY"
    "GH_TOKEN:['\"]ghp_[0-9a-zA-Z]{36}['\"]"
    "GENERIC_PASSWORD:(?i)password\s*=\s*['\"][^'\"]{8,}['\"]"
    "GENERIC_SECRET:(?i)secret\s*=\s*['\"][^'\"]{8,}['\"]"
    "API_KEY:(?i)api[_-]?key\s*[=:]\s*['\"][^'\"]{16,}['\"]"
    "DB_URL:(?i)(postgres|mysql|mongodb)\+?://[^:]+:[^@]+@"
    "SLACK_TOKEN:xox[baprs]-[0-9]{10}-[0-9]{10,}-[a-zA-Z0-9]{24}"
    "STRIPE_KEY:sk_(live|test)_[0-9a-zA-Z]{24,}"
    "GCP_SA_KEY:\"type\":\s*\"service_account\""
)

run_gitleaks() {
    log "--- Using gitleaks ---"
    if gitleaks detect \
        --source "$TARGET" \
        --report-format sarif \
        --report-path "$SARIF" \
        --no-banner 2>&1 | tee -a "$REPORT"; then
        log "gitleaks: no secrets detected"
        return 0
    else
        log "gitleaks: secrets found — see $SARIF"
        FOUND=$((FOUND + 1))
        return 1
    fi
}

run_pattern_scan() {
    log "--- Pattern scan (gitleaks not found) ---"
    for entry in "${PATTERNS[@]}"; do
        label="${entry%%:*}"
        pattern="${entry#*:}"
        while IFS= read -r line; do
            [[ -n "$line" ]] && found "$label" "$line"
        done < <(
            git -C "$TARGET" log --all -p 2>/dev/null \
            | grep -P "$pattern" \
            | grep -Ev "^\+\+\+|^---|example|test|spec|mock|fake|placeholder" \
            | head -5
        )
    done
}

scan_committed_env_files() {
    log "--- Checking for committed .env files ---"
    git -C "$TARGET" log --all --name-only --format="" 2>/dev/null \
    | grep -E "^\.env$|^\.env\." \
    | sort -u \
    | while read -r f; do found "ENV_FILE_IN_HISTORY" "$f"; done
}

scan_large_files() {
    log "--- Files > 10 MB in git history (potential data exfil) ---"
    git -C "$TARGET" rev-list --objects --all 2>/dev/null \
    | git -C "$TARGET" cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' \
    | awk '$1=="blob" && $3>10485760 {print $4, int($3/1048576)"MB"}' \
    | while read -r line; do found "LARGE_FILE" "$line"; done
}

log "=== Secret Scan | target: $TARGET | $(date) ==="

if command -v gitleaks >/dev/null 2>&1; then
    run_gitleaks
else
    run_pattern_scan
fi

scan_committed_env_files
scan_large_files

log "=== Done. Secrets found: $FOUND | Report: $REPORT ==="
[[ $FOUND -gt 0 ]] && exit 1 || exit 0

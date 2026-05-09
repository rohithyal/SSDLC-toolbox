#!/usr/bin/env bash
# Vulnerability triage: reads scanner CSV output and assigns remediation priority.
#
# Priority logic:
#   CVSS >= 9.0 -> P1   CVSS >= 7.0 -> P2   CVSS >= 4.0 -> P3   else P4
#   Asset tagged as "critical" or "prod" or "payment" -> bumped one level higher
#
# Expected CSV columns (with header row):
#   host, cve, cvss, severity, plugin_name, asset_tag
#
# Usage:
#   ./vuln_triage.sh findings.csv
#   ./vuln_triage.sh findings.csv | grep "^P1"

set -euo pipefail

INPUT="${1:-}"

if [[ -z "$INPUT" || ! -f "$INPUT" ]]; then
    echo "Usage: $0 <findings.csv>"
    echo ""
    echo "Expected CSV columns (first row = header):"
    echo "  host, cve, cvss, severity, plugin_name, asset_tag"
    exit 1
fi

REPORT="vuln_triage_$(date +%Y%m%d_%H%M).csv"

log() { echo "[$(date +%H:%M:%S)] $*"; }

log "=== Vulnerability Triage | input: $INPUT | $(date) ==="

echo "priority,host,cve,cvss,severity,asset_tag,plugin_name" > "$REPORT"

awk -F',' '
NR == 1 { next }
{
    host    = $1
    cve     = $2
    cvss    = $3 + 0
    sev     = $4
    plugin  = $5
    asset   = $6

    # strip whitespace
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", asset)

    # base priority
    if      (cvss >= 9.0) p = 1
    else if (cvss >= 7.0) p = 2
    else if (cvss >= 4.0) p = 3
    else                  p = 4

    # asset criticality bump (max P1)
    if (asset ~ /critical|prod|payment|auth|finance|pci/ && p > 1)
        p = p - 1

    printf "%s,%s,%s,%.1f,%s,%s,%s\n", p, host, cve, cvss, sev, asset, plugin
}' "$INPUT" \
| sort -t',' -k1,1n -k4,4rn \
>> "$REPORT"

log "--- P1 Critical (immediate action) ---"
p1=$(awk -F',' 'NR>1 && $1==1' "$REPORT")
[[ -n "$p1" ]] && echo "$p1" | head -20 | column -t -s',' || log "  none"

log "--- P2 High (< 7 days) ---"
p2=$(awk -F',' 'NR>1 && $1==2' "$REPORT")
[[ -n "$p2" ]] && echo "$p2" | head -15 | column -t -s',' || log "  none"

log "--- Summary ---"
for p in 1 2 3 4; do
    n=$(awk -F',' -v p="$p" 'NR>1 && $1==p' "$REPORT" | wc -l | tr -d ' ')
    label=("" "Critical (P1 - immediate)" "High (P2 - 7 days)" "Medium (P3 - 30 days)" "Low (P4 - 90 days)")
    log "  ${label[$p]}: $n findings"
done

log "=== Done. Full report: $REPORT ==="

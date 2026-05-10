#!/usr/bin/env bash
# Observability stack health check.
# Validates Prometheus, Grafana, and Alertmanager are healthy,
# targets are being scraped, alert rules are loaded,
# and the dead man's switch (watchdog alert) is firing.
#
# Prerequisites: curl, jq
# Usage:
#   ./observability_check.sh
#   PROM_URL=http://prometheus:9090 GRAFANA_URL=http://grafana:3000 ./observability_check.sh

set -euo pipefail

PROM_URL="${PROM_URL:-http://localhost:9090}"
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
ALERTMANAGER_URL="${ALERTMANAGER_URL:-http://localhost:9093}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASS="${GRAFANA_PASS:-admin}"

REPORT="observability_$(date +%Y%m%d_%H%M).log"
FAIL=0
WARN=0

log()    { echo "[$(date +%H:%M:%S)] $*" | tee -a "$REPORT"; }
pass()   { log "PASS  $*"; }
fail()   { log "FAIL  $*"; FAIL=$((FAIL + 1)); }
warn()   { log "WARN  $*"; WARN=$((WARN + 1)); }
section(){ log ""; log "=== $* ==="; }

api() {
    curl -sf --max-time 5 "$@" 2>/dev/null
}

# ── Prometheus ────────────────────────────────────────────────────────────────

check_prometheus() {
    section "Prometheus"

    # health endpoint
    if api "${PROM_URL}/-/healthy" | grep -q "Prometheus"; then
        pass "Prometheus: healthy"
    else
        fail "Prometheus: health check failed at $PROM_URL"
        return
    fi

    # readiness
    if api "${PROM_URL}/-/ready" | grep -q "ready"; then
        pass "Prometheus: ready"
    else
        warn "Prometheus: not ready (may be loading)"
    fi

    # target scrape health
    targets=$(api "${PROM_URL}/api/v1/targets" | jq -r '.data.activeTargets[]')
    total=$(echo "$targets" | jq -s 'length')
    down=$(api "${PROM_URL}/api/v1/targets" \
        | jq '[.data.activeTargets[] | select(.health=="down")] | length')

    log "Prometheus targets: $total total, $down down"
    [[ "$down" -gt 0 ]] \
        && fail "Prometheus: $down target(s) DOWN" \
        || pass "Prometheus: all $total targets healthy"

    # list down targets
    if [[ "$down" -gt 0 ]]; then
        api "${PROM_URL}/api/v1/targets" \
        | jq -r '.data.activeTargets[] | select(.health=="down") | .labels.job + " -> " + .scrapeUrl' \
        | while read -r t; do log "  DOWN: $t"; done
    fi

    # alert rules loaded
    rule_count=$(api "${PROM_URL}/api/v1/rules" \
        | jq '[.data.groups[].rules[]] | length' 2>/dev/null || echo 0)
    [[ "$rule_count" -gt 0 ]] \
        && pass "Prometheus: $rule_count alert rule(s) loaded" \
        || fail "Prometheus: no alert rules loaded — alerting is blind"

    # firing alerts
    firing=$(api "${PROM_URL}/api/v1/alerts" \
        | jq '[.data.alerts[] | select(.state=="firing")] | length' 2>/dev/null || echo 0)
    critical_firing=$(api "${PROM_URL}/api/v1/alerts" \
        | jq '[.data.alerts[] | select(.state=="firing" and .labels.severity=="critical")] | length' \
        2>/dev/null || echo 0)

    log "Firing alerts: $firing total, $critical_firing critical"
    [[ "$critical_firing" -gt 0 ]] \
        && fail "Prometheus: $critical_firing CRITICAL alert(s) firing — investigate immediately" \
        || pass "Prometheus: no critical alerts firing"

    # dead man's switch / watchdog
    watchdog=$(api "${PROM_URL}/api/v1/alerts" \
        | jq -r '[.data.alerts[] | select(.labels.alertname == "Watchdog" or .labels.alertname == "DeadMansSwitch")] | length' \
        2>/dev/null || echo 0)
    [[ "$watchdog" -gt 0 ]] \
        && pass "Prometheus: watchdog/dead man's switch is firing (expected)" \
        || fail "Prometheus: watchdog alert NOT firing — alerting pipeline may be broken"

    # TSDB storage usage
    tsdb_size=$(api "${PROM_URL}/api/v1/query?query=prometheus_tsdb_storage_blocks_bytes" \
        | jq -r '.data.result[0].value[1]' 2>/dev/null || echo 0)
    tsdb_gb=$(awk "BEGIN {printf \"%.1f\", $tsdb_size/1073741824}" 2>/dev/null || echo "?")
    log "Prometheus TSDB: ~${tsdb_gb} GB"
}

# ── Alertmanager ──────────────────────────────────────────────────────────────

check_alertmanager() {
    section "Alertmanager"

    if api "${ALERTMANAGER_URL}/-/healthy" | grep -q "OK"; then
        pass "Alertmanager: healthy"
    else
        fail "Alertmanager: health check failed at $ALERTMANAGER_URL"
        return
    fi

    # check it has receivers configured
    receivers=$(api "${ALERTMANAGER_URL}/api/v2/receivers" \
        | jq 'length' 2>/dev/null || echo 0)
    [[ "$receivers" -gt 0 ]] \
        && pass "Alertmanager: $receivers receiver(s) configured" \
        || fail "Alertmanager: no receivers — alerts will be silently dropped"

    # silenced alerts — flag if too many are silenced (potential suppression abuse)
    silences=$(api "${ALERTMANAGER_URL}/api/v2/silences" \
        | jq '[.[] | select(.status.state=="active")] | length' 2>/dev/null || echo 0)
    log "Active silences: $silences"
    [[ "$silences" -gt 5 ]] \
        && warn "Alertmanager: $silences active silences — verify none are masking real incidents" \
        || pass "Alertmanager: $silences silence(s) active (acceptable)"
}

# ── Grafana ───────────────────────────────────────────────────────────────────

check_grafana() {
    section "Grafana"

    if api "${GRAFANA_URL}/api/health" | jq -e '.database == "ok"' >/dev/null 2>&1; then
        pass "Grafana: healthy (database ok)"
    else
        fail "Grafana: health check failed at $GRAFANA_URL"
        return
    fi

    # datasource health
    ds_count=$(api -u "${GRAFANA_USER}:${GRAFANA_PASS}" \
        "${GRAFANA_URL}/api/datasources" | jq 'length' 2>/dev/null || echo "?")
    log "Grafana datasources: $ds_count"

    # test each datasource
    api -u "${GRAFANA_USER}:${GRAFANA_PASS}" "${GRAFANA_URL}/api/datasources" \
    | jq -r '.[] | "\(.id) \(.name) \(.type)"' 2>/dev/null \
    | while read -r ds_id ds_name ds_type; do
        result=$(api -u "${GRAFANA_USER}:${GRAFANA_PASS}" \
            -X POST "${GRAFANA_URL}/api/datasources/${ds_id}/health" \
            | jq -r '.status' 2>/dev/null || echo "unknown")
        [[ "$result" == "OK" ]] \
            && pass "Grafana datasource '$ds_name' ($ds_type): healthy" \
            || fail "Grafana datasource '$ds_name' ($ds_type): $result"
    done

    # check admin password not default
    if api -u "admin:admin" "${GRAFANA_URL}/api/auth/keys" >/dev/null 2>&1; then
        fail "Grafana: default admin/admin credentials still active"
    else
        pass "Grafana: default credentials rejected"
    fi

    # dashboard count
    dash_count=$(api -u "${GRAFANA_USER}:${GRAFANA_PASS}" \
        "${GRAFANA_URL}/api/search?type=dash-db" | jq 'length' 2>/dev/null || echo "?")
    log "Grafana dashboards: $dash_count"
}

# ── Key metric freshness ──────────────────────────────────────────────────────

check_metric_freshness() {
    section "Critical Metric Freshness"

    check_metric() {
        local name="$1" query="$2"
        result=$(api "${PROM_URL}/api/v1/query?query=$(python3 -c \
            "import urllib.parse; print(urllib.parse.quote('$query'))" 2>/dev/null || echo "$query")" \
            | jq -r '.data.result | length' 2>/dev/null || echo 0)
        [[ "$result" -gt 0 ]] \
            && pass "Metric present: $name" \
            || fail "Metric missing: $name — scrape may have stopped"
    }

    check_metric "node CPU"           "node_cpu_seconds_total"
    check_metric "node memory"        "node_memory_MemAvailable_bytes"
    check_metric "node disk"          "node_filesystem_avail_bytes"
    check_metric "GPU utilisation"    "DCGM_FI_DEV_GPU_UTIL"
    check_metric "container CPU"      "container_cpu_usage_seconds_total"
}

command -v curl >/dev/null || { echo "curl required"; exit 1; }
command -v jq   >/dev/null || { echo "jq required";   exit 1; }

log "=== Observability Stack Health | $(date) ==="
log "Prometheus:    $PROM_URL"
log "Alertmanager:  $ALERTMANAGER_URL"
log "Grafana:       $GRAFANA_URL"

check_prometheus
check_alertmanager
check_grafana
check_metric_freshness

log ""
log "=== Done. Failures: $FAIL | Warnings: $WARN | Report: $REPORT ==="
[[ $FAIL -gt 0 ]] && exit 1 || exit 0

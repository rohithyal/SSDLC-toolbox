#!/usr/bin/env bash
# Finds AWS Security Groups with unrestricted inbound access (0.0.0.0/0 or ::/0)
# on sensitive ports: SSH, RDP, DB, cache, ES, SMB, and common admin ports.
#
# Prerequisites: aws-cli, jq
# Usage: AWS_PROFILE=prod AWS_DEFAULT_REGION=eu-central-1 ./sg_audit.sh

set -euo pipefail

LOG="sg_audit_$(date +%Y%m%d_%H%M).log"
PROFILE="${AWS_PROFILE:-default}"
REGION="${AWS_DEFAULT_REGION:-eu-central-1}"

# ports that should never be 0.0.0.0/0
RISKY_PORTS=(22 3389 5432 3306 27017 6379 9200 9300 445 1433 2375 2376 11211)

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
open() { log "OPEN: SG $1 ($2) port $3 -> $4"; }

check_deps() {
    command -v aws >/dev/null || { echo "aws-cli required"; exit 1; }
    command -v jq  >/dev/null || { echo "jq required";      exit 1; }
}

audit_sgs() {
    log "--- Security Groups with unrestricted inbound ---"
    aws ec2 describe-security-groups \
        --profile "$PROFILE" --region "$REGION" --output json \
    | jq -r '
        .SecurityGroups[] |
        .GroupId as $gid |
        .GroupName as $gname |
        .IpPermissions[] |
        . as $perm |
        (
          ($perm.IpRanges[]   | select(.CidrIp   == "0.0.0.0/0") |
            [$gid, $gname,
             ($perm.FromPort // "ALL" | tostring),
             ($perm.ToPort   // "ALL" | tostring),
             .CidrIp] | @tsv),
          ($perm.Ipv6Ranges[] | select(.CidrIpv6 == "::/0") |
            [$gid, $gname,
             ($perm.FromPort // "ALL" | tostring),
             ($perm.ToPort   // "ALL" | tostring),
             .CidrIpv6] | @tsv)
        )
    ' 2>/dev/null \
    | while IFS=$'\t' read -r gid gname from_port to_port cidr; do
        for port in "${RISKY_PORTS[@]}"; do
            if [[ "$from_port" == "ALL" ]] || \
               { [[ "$from_port" =~ ^[0-9]+$ && "$to_port" =~ ^[0-9]+$ ]] && \
                 [[ "$from_port" -le "$port" && "$to_port" -ge "$port" ]]; }; then
                open "$gid" "$gname" "$port" "$cidr"
            fi
        done
    done
}

list_default_sgs() {
    log "--- Default SGs with non-empty inbound rules ---"
    aws ec2 describe-security-groups \
        --profile "$PROFILE" --region "$REGION" \
        --filters "Name=group-name,Values=default" \
        --output json \
    | jq -r '
        .SecurityGroups[] |
        select(.IpPermissions | length > 0) |
        "DEFAULT_SG_HAS_RULES: \(.GroupId) vpc=\(.VpcId)"
    ' | while read -r line; do log "WARN: $line"; done
}

check_deps
log "=== Security Group Audit | profile: $PROFILE | region: $REGION | $(date) ==="
audit_sgs
list_default_sgs
log "=== Done. Report: $LOG ==="

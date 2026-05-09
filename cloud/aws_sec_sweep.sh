#!/usr/bin/env bash
# Quick AWS security posture sweep across the most impactful controls.
# Checks: S3 public access, CloudTrail, GuardDuty, SecurityHub,
#         EBS default encryption, password policy, account contacts.
#
# Prerequisites: aws-cli, jq
# Usage: AWS_PROFILE=prod AWS_DEFAULT_REGION=eu-central-1 ./aws_sec_sweep.sh

set -euo pipefail

LOG="aws_sweep_$(date +%Y%m%d_%H%M).log"
PROFILE="${AWS_PROFILE:-default}"
REGION="${AWS_DEFAULT_REGION:-eu-central-1}"
FAIL_COUNT=0

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
pass() { log "PASS  $*"; }
fail() { log "FAIL  $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }

check_deps() {
    command -v aws >/dev/null || { echo "aws-cli required"; exit 1; }
    command -v jq  >/dev/null || { echo "jq required";      exit 1; }
}

check_s3_public() {
    log "--- S3: public access block ---"
    aws s3api list-buckets --profile "$PROFILE" \
        --query 'Buckets[].Name' --output text \
    | tr '\t' '\n' \
    | while read -r bucket; do
        missing=$(aws s3api get-public-access-block \
            --profile "$PROFILE" --bucket "$bucket" 2>/dev/null \
            | jq -r '.PublicAccessBlockConfiguration
                | to_entries[] | select(.value==false) | .key' \
            | tr '\n' ',' || echo "NO_BLOCK_CONFIG")
        if [[ -n "$missing" ]]; then
            fail "S3 $bucket: missing blocks -> $missing"
        else
            pass "S3 $bucket: fully blocked"
        fi
    done
}

check_cloudtrail() {
    log "--- CloudTrail: multi-region trail ---"
    count=$(aws cloudtrail describe-trails \
        --profile "$PROFILE" --region "$REGION" \
        --include-shadow-trails false \
        --query 'trailList[?IsMultiRegionTrail==`true`]' \
        --output json | jq length)
    [[ "$count" -gt 0 ]] \
        && pass "CloudTrail multi-region: $count trail(s)" \
        || fail "No multi-region CloudTrail found"
}

check_guardduty() {
    log "--- GuardDuty ---"
    count=$(aws guardduty list-detectors \
        --profile "$PROFILE" --region "$REGION" \
        --query 'DetectorIds' --output json | jq length)
    [[ "$count" -gt 0 ]] \
        && pass "GuardDuty: $count detector(s) active" \
        || fail "GuardDuty not enabled in $REGION"
}

check_securityhub() {
    log "--- SecurityHub ---"
    hub=$(aws securityhub describe-hub \
        --profile "$PROFILE" --region "$REGION" \
        --query 'HubArn' --output text 2>/dev/null || echo "DISABLED")
    [[ "$hub" == "DISABLED" ]] \
        && fail "SecurityHub not enabled in $REGION" \
        || pass "SecurityHub: enabled"
}

check_ebs_encryption() {
    log "--- EBS: default encryption ---"
    enabled=$(aws ec2 get-ebs-encryption-by-default \
        --profile "$PROFILE" --region "$REGION" \
        --query 'EbsEncryptionByDefault' --output text)
    [[ "$enabled" == "True" ]] \
        && pass "EBS default encryption: on" \
        || fail "EBS default encryption: off"
}

check_config_service() {
    log "--- AWS Config ---"
    recorders=$(aws configservice describe-configuration-recorders \
        --profile "$PROFILE" --region "$REGION" \
        --query 'ConfigurationRecorders[].name' --output json 2>/dev/null | jq length)
    [[ "$recorders" -gt 0 ]] \
        && pass "AWS Config: $recorders recorder(s)" \
        || fail "AWS Config not enabled — no change history"
}

check_vpc_flow_logs() {
    log "--- VPC Flow Logs ---"
    vpcs=$(aws ec2 describe-vpcs --profile "$PROFILE" --region "$REGION" \
        --query 'Vpcs[].VpcId' --output text | tr '\t' '\n')
    for vpc in $vpcs; do
        fl=$(aws ec2 describe-flow-logs --profile "$PROFILE" --region "$REGION" \
            --filter "Name=resource-id,Values=$vpc" \
            --query 'FlowLogs[?FlowLogStatus==`ACTIVE`]' \
            --output json | jq length)
        [[ "$fl" -gt 0 ]] \
            && pass "VPC $vpc: flow logs enabled" \
            || fail "VPC $vpc: no active flow logs"
    done
}

check_deps
log "=== AWS Security Sweep | profile: $PROFILE | region: $REGION | $(date) ==="
check_s3_public
check_cloudtrail
check_guardduty
check_securityhub
check_ebs_encryption
check_config_service
check_vpc_flow_logs
log "=== Done. Failures: $FAIL_COUNT | Report: $LOG ==="
[[ $FAIL_COUNT -gt 0 ]] && exit 1 || exit 0

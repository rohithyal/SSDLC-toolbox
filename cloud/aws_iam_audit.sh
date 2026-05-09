#!/usr/bin/env bash
# Audits AWS IAM for common misconfigurations:
#   - console users with no MFA
#   - access keys unused > 90 days
#   - customer-managed policies granting full admin (*:*)
#   - root account MFA state
#
# Prerequisites: aws-cli, jq
# Usage: AWS_PROFILE=myprofile ./aws_iam_audit.sh

set -euo pipefail

LOG="iam_audit_$(date +%Y%m%d_%H%M).log"
PROFILE="${AWS_PROFILE:-default}"

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
issue(){ log "ISSUE: $*"; }
ok()   { log "OK:    $*"; }

check_deps() {
    command -v aws >/dev/null || { echo "aws-cli required"; exit 1; }
    command -v jq  >/dev/null || { echo "jq required";      exit 1; }
}

check_mfa() {
    log "--- Console users without MFA ---"
    aws iam generate-credential-report --profile "$PROFILE" >/dev/null 2>&1 || true
    sleep 3
    aws iam get-credential-report --profile "$PROFILE" \
        --query 'Content' --output text \
    | base64 -d \
    | awk -F',' 'NR>1 && $4=="true" && $8=="false" { print "NO_MFA:", $1 }' \
    | while read -r line; do issue "$line"; done
}

check_unused_keys() {
    log "--- Access keys unused > 90 days ---"
    cutoff=$(date -d "-90 days" +%Y-%m-%d 2>/dev/null || date -v-90d +%Y-%m-%d)
    aws iam list-users --profile "$PROFILE" \
        --query 'Users[].UserName' --output text \
    | tr '\t' '\n' \
    | while read -r user; do
        aws iam list-access-keys --profile "$PROFILE" --user-name "$user" \
            --query 'AccessKeyMetadata[?Status==`Active`].[UserName,AccessKeyId,CreateDate]' \
            --output text \
        | while read -r uname keyid created; do
            key_date="${created:0:10}"
            [[ "$key_date" < "$cutoff" ]] && issue "STALE_KEY $uname $keyid (created $key_date)"
        done
    done
}

check_admin_policies() {
    log "--- Customer-managed policies with full admin (*:*) ---"
    aws iam list-policies --profile "$PROFILE" --scope Local \
        --query 'Policies[].Arn' --output text \
    | tr '\t' '\n' \
    | while read -r arn; do
        ver=$(aws iam get-policy --profile "$PROFILE" --policy-arn "$arn" \
            --query 'Policy.DefaultVersionId' --output text)
        doc=$(aws iam get-policy-version --profile "$PROFILE" \
            --policy-arn "$arn" --version-id "$ver" \
            --query 'PolicyVersion.Document' --output json)
        if echo "$doc" | jq -e \
            '.Statement[] | select(.Effect=="Allow" and .Action=="*" and .Resource=="*")' \
            >/dev/null 2>&1; then
            issue "WILDCARD_ADMIN: $arn"
        else
            ok "policy $arn"
        fi
    done
}

check_root_mfa() {
    log "--- Root account MFA ---"
    mfa=$(aws iam get-account-summary --profile "$PROFILE" \
        --query 'SummaryMap.AccountMFAEnabled' --output text)
    [[ "$mfa" == "1" ]] && ok "Root MFA enabled" || issue "CRITICAL: Root account has no MFA"
}

check_password_policy() {
    log "--- IAM password policy ---"
    policy=$(aws iam get-account-password-policy --profile "$PROFILE" \
        --query 'PasswordPolicy' --output json 2>/dev/null || echo "{}")
    min=$(echo "$policy" | jq -r '.MinimumPasswordLength // 0')
    reuse=$(echo "$policy" | jq -r '.PasswordReusePrevention // 0')
    [[ "$min" -ge 14 ]] && ok "Min length: $min" || issue "Weak min length: $min (need >=14)"
    [[ "$reuse" -ge 10 ]] && ok "Reuse prevention: $reuse" \
        || issue "Reuse prevention too low: $reuse (need >=10)"
}

check_deps
log "=== IAM Audit | profile: $PROFILE | $(date) ==="
check_mfa
check_unused_keys
check_admin_policies
check_root_mfa
check_password_policy
log "=== Done. Report: $LOG ==="

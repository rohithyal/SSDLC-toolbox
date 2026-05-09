#!/usr/bin/env python3
"""
ISO 27001:2022 compliance gap mapper.

Two modes:
  1. Interactive: walks you through a checklist of common security findings
     and maps each "yes" to the affected ISO 27001:2022 controls.
  2. File input: accepts a JSON list of finding keys and maps them directly.

Output: JSON gap report + console summary grouped by control domain.

Usage:
    # interactive checklist
    python3 compliance_map.py

    # from scanner findings
    python3 compliance_map.py -f findings.json

    # findings.json format: ["no_mfa", "public_s3", "no_cloudtrail", ...]
"""

import json
import sys
import argparse
from datetime import datetime

# ISO 27001:2022 controls referenced in this script
CONTROLS: dict[str, str] = {
    "A.5.1":  "Policies for information security",
    "A.5.2":  "Roles and responsibilities",
    "A.5.7":  "Threat intelligence",
    "A.5.10": "Acceptable use of information and assets",
    "A.5.23": "Information security for cloud services",
    "A.5.24": "Incident management planning and preparation",
    "A.5.26": "Response to information security incidents",
    "A.5.29": "Information security during disruption",
    "A.6.3":  "Information security awareness, education and training",
    "A.8.2":  "Privileged access rights",
    "A.8.3":  "Information access restriction",
    "A.8.5":  "Secure authentication",
    "A.8.7":  "Protection against malware",
    "A.8.8":  "Management of technical vulnerabilities",
    "A.8.9":  "Configuration management",
    "A.8.12": "Data leakage prevention",
    "A.8.15": "Logging",
    "A.8.16": "Monitoring activities",
    "A.8.20": "Network security",
    "A.8.22": "Segregation of networks",
    "A.8.24": "Use of cryptography",
    "A.8.25": "Secure development life cycle",
    "A.8.26": "Application security requirements",
    "A.8.27": "Secure system architecture and engineering",
    "A.8.28": "Secure coding",
    "A.8.29": "Security testing in development and acceptance",
    "A.8.32": "Change management",
}

# finding key -> affected ISO 27001 controls
FINDING_MAP: dict[str, list[str]] = {
    "no_mfa":                    ["A.8.5", "A.8.2"],
    "wildcard_admin_policy":     ["A.8.2", "A.8.3"],
    "unused_access_keys":        ["A.8.2", "A.5.10"],
    "no_root_mfa":               ["A.8.5", "A.8.2"],
    "weak_password_policy":      ["A.8.5"],
    "public_s3":                 ["A.8.20", "A.8.12"],
    "no_cloudtrail":             ["A.8.15", "A.8.16"],
    "no_guardduty":              ["A.8.16", "A.5.7"],
    "no_securityhub":            ["A.8.16", "A.5.7"],
    "no_vpc_flow_logs":          ["A.8.15", "A.8.20"],
    "ebs_unencrypted":           ["A.8.24"],
    "no_aws_config":             ["A.8.9", "A.8.16"],
    "open_ssh_sg":               ["A.8.20", "A.8.22"],
    "open_rdp_sg":               ["A.8.20", "A.8.22"],
    "open_db_sg":                ["A.8.20", "A.8.22"],
    "unpatched_critical":        ["A.8.8"],
    "unpatched_high":            ["A.8.8"],
    "secret_in_code":            ["A.8.28", "A.8.24"],
    "env_file_committed":        ["A.8.28", "A.8.24"],
    "privileged_container":      ["A.8.9", "A.8.27"],
    "container_root_user":       ["A.8.27", "A.8.9"],
    "host_network_container":    ["A.8.22", "A.8.27"],
    "no_ssdlc":                  ["A.8.25", "A.8.26", "A.8.29"],
    "no_sast_in_pipeline":       ["A.8.28", "A.8.29"],
    "no_dep_scanning":           ["A.8.8", "A.8.29"],
    "no_incident_plan":          ["A.5.24", "A.5.26"],
    "no_security_training":      ["A.6.3", "A.5.1"],
    "no_threat_modeling":        ["A.8.25", "A.8.26"],
    "no_pen_test":               ["A.8.29"],
    "malicious_ip_active":       ["A.8.7", "A.8.16"],
    "malicious_domain_active":   ["A.8.7", "A.8.16"],
}

# human-readable checklist questions per finding key
CHECKLIST: list[tuple[str, str]] = [
    ("no_mfa",                 "Are there IAM/console user accounts without MFA?"),
    ("wildcard_admin_policy",  "Are there policies granting full admin (*:*) permissions?"),
    ("unused_access_keys",     "Are there access keys unused for more than 90 days?"),
    ("no_root_mfa",            "Does the root account lack MFA?"),
    ("weak_password_policy",   "Does the password policy allow passwords shorter than 14 chars?"),
    ("public_s3",              "Are any S3 buckets or storage containers publicly accessible?"),
    ("no_cloudtrail",          "Is API/audit logging (CloudTrail or equivalent) disabled/missing?"),
    ("no_guardduty",           "Is threat detection (GuardDuty or IDS) not enabled?"),
    ("no_securityhub",         "Is centralised security posture management missing?"),
    ("no_vpc_flow_logs",       "Are VPC/network flow logs disabled?"),
    ("ebs_unencrypted",        "Is data at rest stored without encryption?"),
    ("open_ssh_sg",            "Is SSH (port 22) open to 0.0.0.0/0?"),
    ("open_rdp_sg",            "Is RDP (port 3389) open to 0.0.0.0/0?"),
    ("open_db_sg",             "Are database ports open to the public internet?"),
    ("unpatched_critical",     "Are there unpatched vulnerabilities with CVSS >= 9.0?"),
    ("unpatched_high",         "Are there unpatched vulnerabilities with CVSS >= 7.0?"),
    ("secret_in_code",         "Were secrets or credentials found in source code or git history?"),
    ("env_file_committed",     "Has a .env file been committed to any git repository?"),
    ("privileged_container",   "Are any containers running in privileged mode?"),
    ("container_root_user",    "Are any containers running as root with no USER directive?"),
    ("host_network_container", "Are any containers using host network mode?"),
    ("no_ssdlc",               "Is there no formal secure development lifecycle (SSDLC) process?"),
    ("no_sast_in_pipeline",    "Is SAST absent from the CI/CD pipeline?"),
    ("no_dep_scanning",        "Is dependency vulnerability scanning not performed?"),
    ("no_incident_plan",       "Is there no documented incident response plan?"),
    ("no_security_training",   "Have developers not received security awareness training?"),
    ("no_threat_modeling",     "Is threat modeling (STRIDE/PASTA) not performed for new features?"),
    ("no_pen_test",            "Has no penetration test been conducted in the last 12 months?"),
]

REMEDIATION: dict[str, str] = {
    "no_mfa":                "Enforce MFA via IAM policy condition aws:MultiFactorAuthPresent",
    "wildcard_admin_policy": "Replace *:* with least-privilege; use IAM Access Analyzer",
    "unused_access_keys":    "Rotate or deactivate keys via aws iam update-access-key",
    "no_root_mfa":           "Enable virtual/hardware MFA on root immediately",
    "weak_password_policy":  "Set MinimumPasswordLength=14, RequireSymbols=true",
    "public_s3":             "Enable S3 Block Public Access at account and bucket level",
    "no_cloudtrail":         "Create multi-region trail, log to immutable S3 bucket",
    "no_guardduty":          "Enable GuardDuty in all active regions",
    "no_securityhub":        "Enable SecurityHub, activate FSBP and CIS standards",
    "no_vpc_flow_logs":      "Enable VPC flow logs to S3 or CloudWatch Logs",
    "ebs_unencrypted":       "Enable EBS default encryption; use AWS KMS CMK",
    "open_ssh_sg":           "Restrict port 22 to known CIDR ranges; use SSM Session Manager",
    "open_rdp_sg":           "Restrict port 3389; use Bastion or VPN gateway",
    "open_db_sg":            "Place DBs in private subnets; restrict to app-tier SGs only",
    "unpatched_critical":    "Patch within 24-72h; track via vuln management platform",
    "unpatched_high":        "Patch within 7 days; automate with AWS Systems Manager Patch Manager",
    "secret_in_code":        "Rotate exposed secret immediately; use AWS Secrets Manager",
    "env_file_committed":    "Remove from history with git-filter-repo; add .env to .gitignore",
    "privileged_container":  "Remove --privileged; grant only specific capabilities needed",
    "container_root_user":   "Add USER nonroot (UID 1000+) in Dockerfile",
    "host_network_container":"Use bridge/overlay networks; host network bypasses all isolation",
    "no_ssdlc":              "Adopt OWASP SAMM; integrate security at each SDL phase",
    "no_sast_in_pipeline":   "Add semgrep or bandit step in CI; block merge on ERROR",
    "no_dep_scanning":       "Add trivy or safety to CI; fail on HIGH/CRITICAL",
    "no_incident_plan":      "Draft IR playbook covering: detect, contain, eradicate, recover",
    "no_security_training":  "Run OWASP Top 10 training; track completion in HRMS",
    "no_threat_modeling":    "Run STRIDE per feature; log threats in risk register",
    "no_pen_test":           "Commission annual external pen test + quarterly internal scan",
    "malicious_ip_active":   "Block at WAF/SG; investigate endpoint; check for lateral movement",
    "malicious_domain_active":"Block at DNS/proxy; investigate DNS client; check for C2 activity",
}


def map_findings(findings: list[str]) -> dict[str, list[str]]:
    gaps: dict[str, list[str]] = {}
    for f in findings:
        for ctrl in FINDING_MAP.get(f, []):
            gaps.setdefault(ctrl, []).append(f)
    return gaps


def interactive_checklist() -> list[str]:
    print("\n=== ISO 27001:2022 Compliance Checklist ===")
    print("Answer 'y' if the issue EXISTS in your environment.\n")
    issues: list[str] = []
    for key, question in CHECKLIST:
        try:
            ans = input(f"  [?] {question} (y/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if ans == "y":
            issues.append(key)
    return issues


def generate_report(findings: list[str], gaps: dict[str, list[str]]) -> dict:
    return {
        "generated":              datetime.now().strftime("%Y-%m-%d %H:%M"),
        "findings_count":         len(findings),
        "controls_affected":      len(gaps),
        "gaps_by_control":        {
            ctrl: {
                "control_name":  CONTROLS.get(ctrl, "Unknown"),
                "findings":      gap_findings,
                "remediation":   [REMEDIATION.get(f, "See ISO 27001 guidance") for f in gap_findings],
            }
            for ctrl, gap_findings in sorted(gaps.items())
        },
        "all_findings_remediation": {
            f: REMEDIATION.get(f, "See ISO 27001 guidance") for f in findings
        },
    }


def print_report(report: dict):
    print(f"\n{'='*60}")
    print(f"ISO 27001:2022 Gap Report  |  {report['generated']}")
    print(f"{'='*60}")
    print(f"Findings assessed:      {report['findings_count']}")
    print(f"Controls affected:      {report['controls_affected']}\n")

    if not report["gaps_by_control"]:
        print("No gaps identified.\n")
        return

    for ctrl, data in report["gaps_by_control"].items():
        print(f"  {ctrl}  {data['control_name']}")
        for finding in data["findings"]:
            rem = REMEDIATION.get(finding, "")
            print(f"    - {finding}")
            if rem:
                print(f"      Fix: {rem}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="ISO 27001:2022 compliance gap mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-f", "--findings",
        help='JSON file containing a list of finding keys, e.g. ["no_mfa", "public_s3"]',
    )
    parser.add_argument(
        "-o", "--output",
        default=f"compliance_{datetime.now().strftime('%Y%m%d')}.json",
        help="Output JSON report path (default: compliance_YYYYMMDD.json)",
    )
    parser.add_argument(
        "--list-findings",
        action="store_true",
        help="Print all supported finding keys and exit",
    )
    args = parser.parse_args()

    if args.list_findings:
        print("Supported finding keys:")
        for k in sorted(FINDING_MAP):
            print(f"  {k}")
        sys.exit(0)

    if args.findings:
        with open(args.findings) as fh:
            findings = json.load(fh)
        if not isinstance(findings, list):
            print("Error: findings file must be a JSON array of strings")
            sys.exit(1)
    else:
        findings = interactive_checklist()

    if not findings:
        print("No findings to map.")
        sys.exit(0)

    gaps   = map_findings(findings)
    report = generate_report(findings, gaps)

    print_report(report)

    with open(args.output, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"[+] Report saved: {args.output}")


if __name__ == "__main__":
    main()

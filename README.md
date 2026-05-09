# Security Scripts

![Lint](https://github.com/rohithyal/SSDLC-toolbox/actions/workflows/lint.yml/badge.svg)

Practical automation for daily security engineering work.
Cloud security, SOC operations, vulnerability management, SSDLC, and compliance.

Read [MASTERMIND.md](MASTERMIND.md) for the full reference on every script.

---

## Quick Reference

### Cloud

| Script | What it does | Run as |
|---|---|---|
| `cloud/aws_iam_audit.sh` | IAM: MFA, stale keys, wildcard policies, root | `AWS_PROFILE=prod ./aws_iam_audit.sh` |
| `cloud/aws_sec_sweep.sh` | S3, CloudTrail, GuardDuty, SecurityHub, EBS | `AWS_PROFILE=prod ./aws_sec_sweep.sh` |
| `cloud/sg_audit.sh` | Security groups open to 0.0.0.0/0 | `AWS_PROFILE=prod ./sg_audit.sh` |

### SOC / Incident Response

| Script | What it does | Run as |
|---|---|---|
| `soc/siem_hunt.sh` | Threat hunting against local log files | `sudo ./siem_hunt.sh` |
| `soc/ioc_check.py` | Bulk IOC reputation (VT + AbuseIPDB) | `python3 ioc_check.py 1.2.3.4 evil.ru` |
| `soc/ir_collect.sh` | Volatile evidence collection for IR | `sudo ./ir_collect.sh` |

### Vulnerability Management

| Script | What it does | Run as |
|---|---|---|
| `vuln/vuln_triage.sh` | Prioritise scanner CSV by CVSS + asset tag | `./vuln_triage.sh findings.csv` |
| `vuln/patch_reporter.sh` | Patch status: pending updates, reboot needed | `sudo ./patch_reporter.sh` |

### SSDLC / DevSecOps

| Script | What it does | Run as |
|---|---|---|
| `ssdlc/secret_scan.sh` | Git history secret scanning | `./secret_scan.sh` |
| `ssdlc/container_audit.sh` | Dockerfile best practices + runtime checks | `./container_audit.sh` |
| `ssdlc/ssdlc_gate.sh` | CI/CD security gate (blocks on failure) | `./ssdlc_gate.sh` |

### Compliance

| Script | What it does | Run as |
|---|---|---|
| `compliance/compliance_map.py` | Map findings → ISO 27001:2022 controls | `python3 compliance_map.py` |

---

## Setup

```bash
# Make all shell scripts executable
chmod +x cloud/*.sh soc/*.sh vuln/*.sh ssdlc/*.sh

# Required tools
apt install jq awscli          # core
pip install semgrep safety checkov   # SSDLC tools

# Optional but recommended
# Trivy: https://aquasecurity.github.io/trivy
# Gitleaks: https://github.com/gitleaks/gitleaks
```

## IOC Checker API keys

```bash
export VT_API_KEY=your_virustotal_key
export ABUSEIPDB_KEY=your_abuseipdb_key
```

## CI

Every push to `main` runs two automated lint checks via GitHub Actions:

- **ShellCheck** — static analysis on all `.sh` scripts, catches syntax errors, unsafe patterns, and POSIX issues
- **Ruff** — fast Python linter on all `.py` scripts, flags errors and style violations

See [`.github/workflows/lint.yml`](.github/workflows/lint.yml).

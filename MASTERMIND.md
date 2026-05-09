# MASTERMIND — Security Engineering Script Reference

A comprehensive reference for every script in this collection.
Written from the perspective of a working security engineer: what each
script does, why it exists, how to read its output, and what to do next.

---

## Table of Contents

1. [Philosophy](#philosophy)
2. [CI — GitHub Actions](#ci--github-actions)
3. [Cloud Security](#cloud-security)
   - [aws_iam_audit.sh](#aws_iam_auditsh)
   - [aws_sec_sweep.sh](#aws_sec_sweepsh)
   - [sg_audit.sh](#sg_auditsh)
4. [SOC & Incident Response](#soc--incident-response)
   - [siem_hunt.sh](#siem_huntsh)
   - [ioc_check.py](#ioc_checkpy)
   - [ir_collect.sh](#ir_collectsh)
5. [Vulnerability Management](#vulnerability-management)
   - [vuln_triage.sh](#vuln_triagesh)
   - [patch_reporter.sh](#patch_reportersh)
5. [SSDLC & DevSecOps](#ssdlc--devsecops)
   - [secret_scan.sh](#secret_scansh)
   - [container_audit.sh](#container_auditsh)
   - [ssdlc_gate.sh](#ssdlc_gatesh)
6. [Compliance](#compliance)
   - [compliance_map.py](#compliance_mappy)
7. [Tool Dependencies at a Glance](#tool-dependencies-at-a-glance)
8. [Connecting the Workflow](#connecting-the-workflow)

---

## CI — GitHub Actions

Every push to `main` automatically runs two lint jobs defined in
[`.github/workflows/lint.yml`](.github/workflows/lint.yml).

### ShellCheck

Runs `shellcheck --severity=warning` against every `.sh` file in the repo.
ShellCheck is a static analyser for shell scripts — it catches things that
are syntactically valid but dangerous:

- Unquoted variables that break on filenames with spaces (`$f` vs `"$f"`)
- `[ $x == y ]` instead of `[[ $x == y ]]` — the former splits on whitespace
- Useless `cat file | grep` — should be `grep file` directly
- Missing `|| true` on commands inside `set -e` scripts that are expected to fail
- Uninitialized variables, array misuse, and deprecated syntax

All scripts in this collection pass ShellCheck at `--severity=warning`.
If you add a new script, it must pass before merging.

### Ruff

Runs `ruff check --select=E,F,W` against every `.py` file.
Ruff is a fast Python linter (written in Rust) that covers the same rules
as Flake8. The selected rule sets:

- `E` — PEP8 style errors (line length, indentation, whitespace)
- `F` — Pyflakes (unused imports, undefined names, unreachable code)
- `W` — warnings (deprecated constructs, bad practices)

### Why lint and not test?

These scripts interact with live systems — AWS APIs, Docker daemons,
real log files. Meaningful tests would require mocking entire cloud
environments, which adds complexity without adding confidence.

Linting catches the class of bugs that actually matters here: syntax
errors and unsafe shell patterns that would silently produce wrong output
or fail in unexpected ways on a production host. That is the right
trade-off for an ops toolbox.

---

## Philosophy

These scripts were built around one rule: **run fast, output clearly,
block nothing you don't mean to block**. Every script:

- Logs to a timestamped file AND prints to the terminal simultaneously
- Exits non-zero only when findings genuinely need to block a pipeline
- Degrades gracefully — if a tool isn't installed, it skips and says so
- Respects the read-only principle — no script modifies cloud resources or
  system state, only reads and reports

The pattern is intentionally low-abstraction. A shell script you can read
in two minutes is worth more than a framework you have to understand first.

---

## Cloud Security

### aws_iam_audit.sh

**Location:** `cloud/aws_iam_audit.sh`

**What it does**

Connects to AWS and audits IAM for the four most common, highest-impact
misconfigurations. It uses the AWS CLI credential report (a built-in
IAM feature) plus direct API calls for policy inspection.

**Checks performed**

| Check | Why it matters |
|---|---|
| Console users without MFA | Single-factor credentials are the #1 initial access vector. If an attacker phishes or leaks a password, no MFA = full account access. |
| Access keys unused > 90 days | Stale keys are forgotten keys. Developers leave, keys stay. They don't appear in any alerting because they're never used — until they are. |
| Customer-managed policies with `*:*` | Wildcard admin policies are the "break glass" that never gets put back. One compromised account with this policy = full account compromise. |
| Root account MFA | Root bypasses all IAM restrictions. No MFA on root is a single point of catastrophic failure. |
| Password policy | Weak password policies enable credential stuffing and brute force against console logins. |

**How to run**

```bash
# Using default profile
./aws_iam_audit.sh

# Targeting a specific account/profile
AWS_PROFILE=prod-account ./aws_iam_audit.sh
```

**Reading the output**

Lines prefixed `ISSUE:` need remediation. Lines prefixed `OK:` are passing.
The log file (`iam_audit_YYYYMMDD_HHMM.log`) is your audit trail.

```
[09:14:22] === IAM Audit | profile: prod | 2026-05-09 ===
[09:14:31] --- Console users without MFA ---
[09:14:33] ISSUE: NO_MFA: john.doe
[09:14:33] ISSUE: NO_MFA: svc-deploy
[09:14:35] --- Access keys unused > 90 days ---
[09:14:41] ISSUE: STALE_KEY john.doe AKIAIOSFODNN7EXAMPLE (created 2025-11-12)
[09:14:50] --- Customer-managed policies with full admin (*:*) ---
[09:14:52] ISSUE: WILDCARD_ADMIN: arn:aws:iam::123456789012:policy/DevOpsFullAccess
```

**What to do with findings**

- `NO_MFA` → enforce MFA via a policy condition:
  `"Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "true"}}`
- `STALE_KEY` → deactivate via `aws iam update-access-key --status Inactive`
- `WILDCARD_ADMIN` → open IAM Access Analyzer, review what the policy actually
  needs, and scope it to specific actions and resources
- Root no MFA → enable hardware MFA immediately, this is a critical finding

**Caveats**

The credential report takes 2–4 seconds to generate if it hasn't been
recently created. The script sleeps 3 seconds to account for this.
In large organisations with hundreds of users, `check_unused_keys` will
make many API calls — add `--max-items 100` if you're hitting rate limits.

---

### aws_sec_sweep.sh

**Location:** `cloud/aws_sec_sweep.sh`

**What it does**

A broad AWS security posture check covering seven controls. Think of it as
a lightweight alternative to AWS Security Hub for a quick sanity check —
or a complement to it for a second opinion.

**Checks performed**

| Check | FAIL condition | Compliance mapping |
|---|---|---|
| S3 public access block | Any bucket missing any of the 4 block settings | A.8.12, A.8.20 |
| CloudTrail multi-region | No multi-region trail exists | A.8.15, A.8.16 |
| GuardDuty | No detector in the target region | A.8.16, A.5.7 |
| SecurityHub | Not enabled | A.8.16 |
| EBS default encryption | Default encryption is off | A.8.24 |
| AWS Config | No recorder in target region | A.8.9, A.8.16 |
| VPC flow logs | Any VPC without active flow logs | A.8.15, A.8.20 |

**How to run**

```bash
# Set your environment first
export AWS_PROFILE=prod
export AWS_DEFAULT_REGION=eu-central-1

./aws_sec_sweep.sh
```

**Reading the output**

```
[10:22:11] PASS  S3 my-app-assets: fully blocked
[10:22:13] FAIL  S3 old-backup-bucket-2023: missing blocks -> BlockPublicAcls,BlockPublicPolicy,
[10:22:15] PASS  CloudTrail multi-region: 1 trail(s)
[10:22:16] FAIL  GuardDuty not enabled in eu-central-1
```

The script exits non-zero if any check fails, making it easy to wire
into monitoring or a scheduled CI check.

**Key concept: why these seven?**

These are the controls that, when missing, lead to real incidents:

- **S3 public access** — thousands of breaches have happened because someone
  created a bucket, disabled the block "temporarily", and forgot.
- **CloudTrail** — without it, you have no forensic trail. You cannot
  answer "what happened?" after an incident.
- **GuardDuty** — ML-based threat detection that works on your CloudTrail
  and VPC logs. Costs pennies per GB. Not having it is negligence.
- **EBS encryption** — default off means every new volume is unencrypted
  unless explicitly set. One misconfigured volume in a snapshot = data exposure.
- **VPC flow logs** — your network forensics. Without it, you cannot trace
  lateral movement or C2 communication inside your VPC.

---

### sg_audit.sh

**Location:** `cloud/sg_audit.sh`

**What it does**

Scans every Security Group in the target region and flags any that allow
inbound traffic from `0.0.0.0/0` (all IPv4) or `::/0` (all IPv6) on
a list of sensitive ports.

**Why this is important**

Misconfigured Security Groups are one of the most common findings in
cloud security assessments. Developers open ports for testing and
forget to close them. A `0.0.0.0/0` rule on port 22 (SSH) means your
server is being continuously probed by every internet scanner alive.

**Sensitive ports checked**

| Port | Service | Risk |
|---|---|---|
| 22 | SSH | Direct shell access |
| 3389 | RDP | Windows remote desktop |
| 5432 | PostgreSQL | DB credential brute force, data theft |
| 3306 | MySQL/MariaDB | Same |
| 27017 | MongoDB | Notorious for unauthenticated public instances |
| 6379 | Redis | Unauthenticated by default, command execution |
| 9200/9300 | Elasticsearch | Data leakage, often no auth by default |
| 445 | SMB | EternalBlue, ransomware pivot path |
| 1433 | MSSQL | DB access |
| 2375/2376 | Docker daemon | Full host compromise via Docker API |
| 11211 | Memcached | Amplification attacks, data exposure |

**How to run**

```bash
AWS_PROFILE=prod AWS_DEFAULT_REGION=eu-central-1 ./sg_audit.sh
```

**Reading the output**

```
[11:05:33] OPEN: SG sg-0abc123 (allow-all-ssh) port 22 -> 0.0.0.0/0
[11:05:33] WARN: DEFAULT_SG_HAS_RULES: sg-0def456 vpc=vpc-0123abc
```

The `DEFAULT_SG_HAS_RULES` warning is significant. AWS best practice
is to leave the default SG with no rules and create explicit SGs for
each workload. Resources that accidentally get assigned the default SG
shouldn't gain any access.

**Remediation approach**

For each `OPEN` finding:
1. Identify what service uses that SG
2. Check if the open port is intentional (public-facing load balancer) or a mistake
3. Replace `0.0.0.0/0` with the specific CIDR of your corporate VPN or
   the specific application-tier SG
4. For SSH: migrate to AWS Systems Manager Session Manager — eliminates
   the need for port 22 entirely

---

## SOC & Incident Response

### siem_hunt.sh

**Location:** `soc/siem_hunt.sh`

**What it does**

Runs a set of structured threat hunting queries against local system
log files. This is not a replacement for a full SIEM (QRadar, Suricata,
Splunk) — it's what you run when you need answers fast from a single
host, or when you're hunting without a centralised log platform.

**Hunt hypotheses and logic**

**1. Brute Force Detection**

Counts `Failed password` entries in `auth.log` grouped by time.
More than 10 failures in the same minute = brute force signature.

What to look for next: IP of the attacker. Check `ioc_check.py` on that IP.
Check if any subsequent `Accepted` login came from the same IP.

**2. Success After Failures**

Correlates failed auth IPs against successful auths. This is the
"they guessed the password" scenario. A hit here means the brute force
worked — treat this as an active incident.

**3. Lateral Movement**

Looks for SSH `Accepted publickey` from non-standard usernames. Legitimate
automation uses `ec2-user`, `ubuntu`, `deploy`. Anything else is unusual
and worth investigating — especially if the destination host isn't
where that user normally logs in from.

**4. Privilege Escalation**

Searches for `sudo` to root from non-standard commands. Legitimate admins
run `apt`, `systemctl`, `journalctl` as root. Someone running
`sudo python3 -c 'import os; os.system("/bin/bash")'` is not legitimate.

**5. C2 Beaconing**

High-frequency DNS queries to non-CDN external domains.
Malware beacons home at regular intervals — this creates an unusually high
query count to a single domain. The script checks the last 2 hours of
`systemd-resolved` logs and flags any domain with > 60 queries.

Real C2 indicators: randomised subdomains (DGA), unusual TLDs,
domains registered in the last 30 days. Run flagged domains through
`ioc_check.py` for reputation context.

**6. Persistence**

Files modified more recently than `/etc/passwd` in known persistence
locations. `/etc/passwd` is rarely touched after initial OS setup —
using it as a reference timestamp is a practical trick. Any cron file
or systemd unit modified after `/etc/passwd` deserves examination.

**7. SUID/SGID Changes**

New SUID binaries in `/usr`, `/bin`, `/sbin` are red flags.
Attackers plant SUID shells (`cp /bin/bash /tmp/.hidden_bash; chmod 4755 /tmp/.hidden_bash`)
for persistent root escalation. Anything in `/tmp` with SUID is always suspicious.

**8. Exfiltration Indicators**

Looks for transfer sizes > 100 MB in syslog. Legitimate transfers can
be this large, but combined with other indicators (C2 beacon, unusual
user), large transfers are a key exfiltration signal.

**How to run**

```bash
# Local logs
sudo ./siem_hunt.sh

# Remote host
ssh user@host "sudo bash -s" < siem_hunt.sh

# Different log directory (e.g., imported logs)
./siem_hunt.sh /mnt/evidence/var/log
```

**Workflow integration**

Run this script first during a suspicious-host investigation, before
`ir_collect.sh`. It takes seconds and may immediately confirm or rule out
compromise, helping you decide whether a full collection is warranted.

---

### ioc_check.py

**Location:** `soc/ioc_check.py`

**What it does**

Bulk checks Indicators of Compromise (IPs, domains, file hashes) against
VirusTotal and AbuseIPDB APIs. Produces a per-IOC verdict
(CLEAN / SUSPICIOUS / MALICIOUS) and saves a structured JSON report.

**Setup**

```bash
export VT_API_KEY=your_virustotal_api_key
export ABUSEIPDB_KEY=your_abuseipdb_api_key
```

Both free tiers are sufficient for most SOC work.
VirusTotal free: 4 lookups/minute, 500/day.
AbuseIPDB free: 1000 checks/day.

**IOC type auto-detection**

The script determines the type from the value itself:
- Looks like an IP address → `ip`
- 32 hex chars (MD5), 40 (SHA1), or 64 (SHA256) → `hash`
- Contains a dot, doesn't start with `http` → `domain`
- Everything else → skipped with a warning

**Verdict logic**

| Source | MALICIOUS | SUSPICIOUS | CLEAN |
|---|---|---|---|
| VirusTotal | > 3 engines flagged | 1–3 engines flagged | 0 engines flagged |
| AbuseIPDB | Confidence score > 75 | Score 25–75 | Score < 25 |

Overall verdict = worst of the two sources.

**How to run**

```bash
# Inline IOCs
python3 ioc_check.py 185.220.101.34 malware.ru d41d8cd98f00b204e9800998ecf8427e

# From a file (one IOC per line, # for comments)
python3 ioc_check.py -f suspicious_iocs.txt
```

**Reading the output**

```
[*] IP: 185.220.101.34
    VT: 12/94 engines | MALICIOUS
    AbuseIPDB: score=98 | 847 reports | DE | MALICIOUS
[*] DOMAIN: malware.ru
    VT: 45/94 engines | MALICIOUS
[*] HASH: d41d8cd98f00b204e9800998ecf8427e
    VT: 0/72 engines | CLEAN

[+] Summary: {'MALICIOUS': 2, 'SUSPICIOUS': 0, 'CLEAN': 1, 'UNKNOWN': 0}
[+] Report saved: ioc_results_20260509_1122.json
```

**Practical use in SOC**

1. `siem_hunt.sh` finds a suspicious IP or domain
2. Paste it into `ioc_check.py` for instant reputation context
3. If MALICIOUS: escalate, contain, then check for lateral movement
4. If SUSPICIOUS: monitor, correlate with other signals, low-and-slow response
5. If CLEAN but still behaving oddly: check domain age, WHOIS, certificate
   transparency logs — new domains evade reputation for weeks

---

### ir_collect.sh

**Location:** `soc/ir_collect.sh`

**What it does**

First-responder evidence collection. Run this on a suspected compromised
host as the very first action — before rebooting, before disconnecting,
before running antivirus. Volatile data (network connections, running
processes, logged-in users) disappears the moment the system changes state.

The script collects everything important, packages it into a timestamped
`tar.gz`, and computes SHA-256 checksums of every file for chain-of-custody
integrity.

**Collection phases (in order of volatility)**

| Phase | What | Why first |
|---|---|---|
| Network state | `ss`, `arp`, `ip route` | Disappears on reboot or network change |
| Sessions | `who`, `last`, `lastb` | Active logins may log off |
| Processes | `ps`, `pstree`, `/proc/*/environ` | Killed on next reboot |
| Open files | `lsof` | File handles close when processes exit |
| Persistence | cron, systemd, rc.local | Attacker may cover tracks remotely |
| Filesystem | modified files, SUID binaries, /tmp | Time-sensitive if attacker is active |
| System state | kernel modules, iptables, env | Stable but worth capturing |
| Logs | auth.log, syslog, journal | Rotate by time |

**Why SHA-256 checksums matter**

In a legal or HR proceeding, you may need to prove the evidence wasn't
tampered with after collection. The `CHECKSUMS.sha256` file inside the
archive lets you verify integrity at any point:

```bash
cd ir_hostname_20260509_142233/
sha256sum -c CHECKSUMS.sha256
```

**How to run**

```bash
# Must be root to read shadow, lsof -n, etc.
sudo ./ir_collect.sh

# Output: ir_hostname_YYYYMMDD_HHMMSS.tar.gz
```

**Transfer to analyst workstation**

```bash
scp ir_hostname_20260509_142233.tar.gz analyst@ir-server:/evidence/
```

**What to look for first**

After collecting, start analysis with:
1. `net_connections.txt` — any unexpected outbound connections?
2. `users_active.txt` — anyone logged in who shouldn't be?
3. `files_modified_1h.txt` — what changed recently?
4. `files_suid_sgid.txt` — any unexpected SUID binaries?
5. `files_tmp_exec.txt` — any executables in /tmp?
6. `persistence_cron.txt` — any unknown cron jobs?

**Important caveat**

Running `find /` in `files_modified_1h.txt` takes time — on a
busy system with many inodes, this may take 2–5 minutes. The other
collections complete in seconds. Plan for this when time is critical.

---

## Vulnerability Management

### vuln_triage.sh

**Location:** `vuln/vuln_triage.sh`

**What it does**

Takes CSV output from vulnerability scanners (Nessus, Qualys, Tenable,
OpenVAS) and assigns a remediation priority to each finding based on
CVSS score and asset criticality. Produces a sorted, prioritised output
that feeds directly into your ticketing system.

**Input format**

```csv
host,cve,cvss,severity,plugin_name,asset_tag
web-prod-01,CVE-2024-1234,9.8,Critical,OpenSSL RCE,prod
db-dev-01,CVE-2023-5678,6.5,Medium,MySQL info disclosure,dev
payment-api,CVE-2024-2222,7.2,High,Log4j variant,payment
```

**Priority algorithm**

```
Base priority from CVSS:
  CVSS >= 9.0  →  P1 (Critical)
  CVSS >= 7.0  →  P2 (High)
  CVSS >= 4.0  →  P3 (Medium)
  else         →  P4 (Low)

Asset criticality bump:
  asset_tag contains critical|prod|payment|auth|finance|pci
  AND base priority > P1  →  promote by one level
```

This reflects how real risk works. A CVSS 7.2 on your payment API
is more urgent than a CVSS 9.8 on a dev sandbox — it carries actual
business risk.

**SLA targets (recommended)**

| Priority | Fix deadline |
|---|---|
| P1 Critical | 24–72 hours |
| P2 High | 7 days |
| P3 Medium | 30 days |
| P4 Low | 90 days |

**How to run**

```bash
./vuln_triage.sh nessus_export.csv

# Filter just P1s for rapid response
./vuln_triage.sh nessus_export.csv | grep "^P1"
```

**Workflow**

1. Export CSV from your scanner after each scan cycle
2. Run `vuln_triage.sh` → get prioritised output
3. P1 findings → create emergency tickets immediately
4. P2 findings → create tickets, assign in current sprint
5. Track weekly: re-run script to measure remediation velocity
6. Feed into Tableau/Power BI dashboard using the output CSV

**Common gotcha**

Scanners use inconsistent column ordering. Check your CSV header row
before running — the script expects exactly:
`host, cve, cvss, severity, plugin_name, asset_tag`

If your export is different, adjust the `awk` column references (`$1`–`$6`).

---

### patch_reporter.sh

**Location:** `vuln/patch_reporter.sh`

**What it does**

Generates a patch status report for the local host. Covers available
security updates, kernel version, last upgrade timestamp, reboot-required
state, and status of key security daemons. Designed to be pushed via SSH
to collect fleet-wide patch status.

**How to run**

```bash
# Local
sudo ./patch_reporter.sh

# Across a fleet
for host in web-01 web-02 db-01 db-02; do
    ssh "$host" "sudo bash -s" < patch_reporter.sh \
    | tee "patch_${host}_$(date +%Y%m%d).txt"
done
```

**Key output sections**

- **Security updates available**: lists specific packages with security fixes
- **Last upgrade timestamp**: tells you how long since someone last ran patches
- **Reboot required**: critical — a kernel patch doesn't apply until reboot.
  A host can have "0 pending updates" but still need a reboot for a patch
  it already installed
- **Security daemon status**: checks for fail2ban, ufw, auditd, EDR agents

**Integrating into reporting**

Run this weekly across your fleet, collect the output, and track:
- How many hosts have > 0 security updates pending?
- How many have not been rebooted after kernel patches?
- Which hosts are missing fail2ban or auditd?

This feeds directly into KPI reporting for IT security controls.

---

## SSDLC & DevSecOps

### secret_scan.sh

**Location:** `ssdlc/secret_scan.sh`

**What it does**

Scans the full git history (not just the working tree) for secrets,
credentials, and sensitive data. This matters because developers often
commit secrets, then delete them in the next commit — the working tree
is clean but the history still contains the secret and it's still
accessible to anyone who can clone the repo.

**Two modes**

1. **gitleaks mode** (preferred): Uses gitleaks with its built-in rule set
   (400+ patterns), produces a SARIF file compatible with GitHub Code Scanning
   and other SAST tooling
2. **Pattern fallback**: 10 custom regex patterns covering the most common
   secret types when gitleaks isn't available

**Pattern coverage (fallback mode)**

| Pattern | What it catches |
|---|---|
| `AKIA[0-9A-Z]{16}` | AWS access key IDs |
| `-----BEGIN ... PRIVATE KEY` | RSA, EC, OpenSSH private keys |
| `ghp_...` | GitHub personal access tokens |
| `password = "..."` | Hardcoded passwords (case-insensitive) |
| `secret = "..."` | Generic secrets |
| `api_key = "..."` | API keys |
| `postgres://user:pass@` | Database connection strings |
| `xox[baprs]-...` | Slack tokens |
| `sk_live_...` | Stripe live API keys |
| `"type": "service_account"` | GCP service account JSON |

**How to run**

```bash
# Scan current repo
./secret_scan.sh

# Scan a specific path
./secret_scan.sh /path/to/repo

# Wire into CI (exits 1 if secrets found)
./secret_scan.sh && echo "Clean" || echo "Secrets found — blocked"
```

**What to do if secrets are found**

1. **Rotate immediately** — treat the secret as compromised regardless
   of whether anyone accessed it. Check cloud provider logs for suspicious
   usage before the rotation.
2. **Remove from history** — use `git-filter-repo` (not BFG, which is deprecated):
   ```bash
   git filter-repo --path-glob '*.env' --invert-paths
   # or for a specific string:
   git filter-repo --replace-text <(echo 'literal:AKIAEXAMPLEKEY==>REDACTED')
   ```
3. **Force-push all branches** — notify all collaborators to re-clone
4. **Add to .gitignore** — prevent re-occurrence

**Pre-commit hook integration**

Wire this into git hooks to prevent commits:

```bash
# .git/hooks/pre-commit
#!/bin/bash
./ssdlc/secret_scan.sh && exit 0 || { echo "Secret scan failed"; exit 1; }
```

---

### container_audit.sh

**Location:** `ssdlc/container_audit.sh`

**What it does**

Two-part Docker security audit: static analysis of Dockerfiles for
build-time misconfigurations, and runtime inspection of running containers
for dangerous configuration options. Optionally runs Trivy for CVE scanning.

**Dockerfile checks**

| Check | FAIL condition | Why it matters |
|---|---|---|
| Non-root user | No `USER` directive with non-root UID | Root in container = root on host if escape occurs |
| Pinned base image | `FROM ubuntu:latest` | Latest tag is a moving target — supply chain risk |
| ADD vs COPY | `ADD` used for local files | ADD expands URLs and archives, unexpected behaviour |
| Secrets in ENV | `ENV PASSWORD=...` | ENV vars appear in `docker inspect`, image layers, CI logs |
| curl-pipe-shell | `curl url \| bash` | Executes unverified remote code at build time |
| Private keys in COPY | `COPY *.pem` | Key burned into image, appears in every layer |
| HEALTHCHECK | Missing | Without it, orchestrators can't detect unhealthy containers |

**Runtime checks**

| Check | FAIL condition |
|---|---|
| Privileged mode | `--privileged` flag — full host device access |
| Root user | Empty `User` field in inspect output |
| Host network | `--network=host` — bypasses all network isolation |
| Writable root FS | `ReadonlyRootfs: false` (warning, not fail) |
| Extra capabilities | `CapAdd` is non-empty |
| Sensitive bind mounts | `/etc`, `/root`, `/var/run/docker.sock`, `/proc`, `/sys` |

Docker socket (`/var/run/docker.sock`) mounted in a container is
particularly dangerous — it gives that container full control of the
Docker daemon, which means full root on the host.

**How to run**

```bash
# Audit current directory's Dockerfiles + running containers
./container_audit.sh

# Target a specific project
./container_audit.sh /path/to/project
```

**Trivy integration**

If Trivy is installed, the script automatically scans all running images
for HIGH and CRITICAL CVEs. Install Trivy:

```bash
# macOS
brew install trivy
# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
```

---

### ssdlc_gate.sh

**Location:** `ssdlc/ssdlc_gate.sh`

**What it does**

A CI/CD pipeline security gate. Runs five sequential security checks and
exits non-zero if any critical check fails. Designed to be added as a
pipeline step before build, deploy, or merge — it blocks the pipeline
if the code isn't safe to proceed.

**Gates in order**

```
Gate 1: Secret scanning     — gitleaks or trufflehog
Gate 2: SAST                — semgrep or bandit  
Gate 3: Dependency audit    — safety, npm audit, or trivy fs
Gate 4: IaC scanning        — checkov
Gate 5: Container images    — trivy image
```

Each gate degrades gracefully: if the required tool isn't installed,
it logs `GATE SKIP` and continues rather than blocking (you don't want
an unfound tool to silently pass a gate).

**How to add to GitHub Actions**

```yaml
# .github/workflows/security.yml
name: Security Gate
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0    # full history for secret scanning

      - name: Install tools
        run: |
          pip install semgrep safety
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
          brew install gitleaks 2>/dev/null || curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz | tar xz

      - name: Run SSDLC Gate
        run: ./ssdlc/ssdlc_gate.sh
```

**How to add to GitLab CI**

```yaml
# .gitlab-ci.yml
security-gate:
  stage: test
  image: python:3.11
  before_script:
    - pip install semgrep safety
    - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
  script:
    - ./ssdlc/ssdlc_gate.sh
  allow_failure: false
```

**Gate pass/fail output**

```
[10:30:01] === SSDLC Security Gate | 2026-05-09 ===
[10:30:03] === Gate 1: Secret Scanning ===
[10:30:05] GATE PASS: gitleaks: no secrets in history
[10:30:05] === Gate 2: SAST ===
[10:30:11] GATE FAIL: semgrep: ERROR findings block merge
[10:30:11] === Gate 3: Dependency Audit ===
[10:30:14] GATE PASS: safety: Python deps clean
[10:30:15] GATE PASS: trivy fs: no HIGH/CRITICAL in dependencies
[10:30:15] === Gate 4: IaC Security ===
[10:30:18] GATE PASS: checkov: no HIGH/CRITICAL IaC issues
[10:30:18] === Gate 5: Container Image Scan ===
[10:30:22] GATE PASS: trivy image: myapp:latest clean
[10:30:22] === Gate Summary: PASS=4 FAIL=1 | Report: ssdlc_gate_20260509_1030.log ===
[10:30:22] PIPELINE BLOCKED — 1 gate(s) failed. Fix issues above before merging.
```

**Tuning gates for your environment**

The gate is intentionally strict. For brownfield projects with many
existing issues, start with:
- Gate 1 (secrets) — always keep blocking, no exceptions
- Gate 2 (SAST) — set `--severity ERROR` only, not WARNING
- Gate 3 (deps) — `--audit-level critical` for npm instead of high
- Gate 4 (IaC) — `--soft-fail-on MEDIUM,LOW,HIGH` to start, tighten over sprints

The goal is to make the gate trustworthy. A gate that always fires
gets disabled. Tune it to catch real issues only, then tighten each sprint.

---

## Compliance

### compliance_map.py

**Location:** `compliance/compliance_map.py`

**What it does**

Maps security findings to ISO 27001:2022 Annex A controls and generates
a gap report. Two modes: interactive checklist (for assessments where
you walk through questions) and file input (for automated output from
the other scripts in this collection).

**ISO 27001:2022 context**

ISO 27001:2022 restructured Annex A from 114 controls (2013 version) to
93 controls (2022 version) organised in four domains:
- **A.5** — Organizational controls (37 controls)
- **A.6** — People controls (8 controls)
- **A.7** — Physical controls (14 controls)
- **A.8** — Technology controls (34 controls)

This script covers A.5 and A.8 — the two domains most relevant to a
security engineer working in application and cloud security.

**Interactive mode**

```bash
python3 compliance_map.py
```

Walks you through 28 yes/no questions. Answer `y` if the issue EXISTS
(i.e., is a gap). On completion, produces the gap report.

**File input mode**

```bash
# findings.json: ["no_mfa", "public_s3", "unpatched_critical"]
python3 compliance_map.py -f findings.json -o gap_report_Q2.json
```

Combine with the other scripts: run `aws_iam_audit.sh`, note the findings,
translate them into finding keys, and map them here for your compliance report.

**Finding key → ISO 27001 control mapping (key selections)**

| Finding key | Controls | Logic |
|---|---|---|
| `no_mfa` | A.8.5, A.8.2 | Weak auth → secure authentication + privileged access |
| `wildcard_admin_policy` | A.8.2, A.8.3 | Over-privilege → privileged access + access restriction |
| `public_s3` | A.8.20, A.8.12 | Network exposure + data leakage prevention |
| `no_cloudtrail` | A.8.15, A.8.16 | Logging + monitoring |
| `secret_in_code` | A.8.28, A.8.24 | Secure coding + cryptography |
| `no_ssdlc` | A.8.25, A.8.26, A.8.29 | SDL + app sec requirements + security testing |
| `no_incident_plan` | A.5.24, A.5.26 | Incident planning + response |

**Reading the output**

```
============================================================
ISO 27001:2022 Gap Report  |  2026-05-09 14:30
============================================================
Findings assessed:      12
Controls affected:      9

  A.8.2  Privileged access rights
    - no_mfa
      Fix: Enforce MFA via IAM policy condition aws:MultiFactorAuthPresent
    - wildcard_admin_policy
      Fix: Replace *:* with least-privilege; use IAM Access Analyzer

  A.8.8  Management of technical vulnerabilities
    - unpatched_critical
      Fix: Patch within 24-72h; track via vuln management platform
```

**Using this for ISO 27001 audit preparation**

1. Run all scripts in this collection
2. Collect findings, translate to finding keys
3. Run `compliance_map.py` with those keys
4. The output = your Statement of Applicability gap evidence
5. Each finding + remediation = a corrective action you can track
6. Re-run quarterly to measure gap closure

The JSON output can be loaded into Power BI or Tableau to create an
executive compliance dashboard showing % controls addressed over time.

---

## Tool Dependencies at a Glance

| Script | Required | Optional (degrades gracefully) |
|---|---|---|
| `aws_iam_audit.sh` | `aws-cli`, `jq` | — |
| `aws_sec_sweep.sh` | `aws-cli`, `jq` | — |
| `sg_audit.sh` | `aws-cli`, `jq` | — |
| `siem_hunt.sh` | `bash`, `awk`, `grep` | `journalctl` |
| `ioc_check.py` | `python3` | `VT_API_KEY`, `ABUSEIPDB_KEY` env vars |
| `ir_collect.sh` | `bash` (as root) | `journalctl`, `lsof` |
| `vuln_triage.sh` | `bash`, `awk` | — |
| `patch_reporter.sh` | `bash`, `apt` or `yum` | `fail2ban`, `auditd`, `ss` |
| `secret_scan.sh` | `bash`, `git` | `gitleaks` (preferred) |
| `container_audit.sh` | `docker` | `trivy` |
| `ssdlc_gate.sh` | `bash` | `gitleaks`, `semgrep`, `safety`, `checkov`, `trivy` |
| `compliance_map.py` | `python3` | — |

**Quick install (Ubuntu/Debian)**

```bash
# Core
apt install jq awscli

# Security tools
pip install semgrep safety checkov

# Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Gitleaks
GITLEAKS_VER=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name)
curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER#v}_linux_x64.tar.gz" | tar xz -C /usr/local/bin
```

---

## Connecting the Workflow

These scripts are designed to chain together. Here is how they fit into
common security workflows:

### Weekly Security Operations Cycle

```
Monday morning:
  aws_sec_sweep.sh        → catch new cloud drift over the weekend
  patch_reporter.sh       → fleet-wide patch status check
  vuln_triage.sh          → process scanner output from Sunday's scan

During the week:
  siem_hunt.sh            → threat hunting on interesting hosts
  ioc_check.py            → reputation check on flagged IPs/domains

On pull requests (automated):
  ssdlc_gate.sh           → CI pipeline security gate (auto-blocks)
  secret_scan.sh          → pre-merge hook

Quarterly:
  aws_iam_audit.sh        → deep IAM review
  sg_audit.sh             → SG drift review
  container_audit.sh      → full container hardening check
  compliance_map.py       → ISO 27001 gap report for audit evidence
```

### Incident Response Workflow

```
Alert fires
    ↓
siem_hunt.sh             → quick hypothesis test (60 seconds)
    ↓ (if suspicious)
ioc_check.py             → reputation context for IPs/domains found
    ↓ (if confirmed)
ir_collect.sh            → volatile evidence capture (before anything else)
    ↓
Transfer to analyst workstation, begin forensic analysis
    ↓ (post-incident)
aws_iam_audit.sh         → check for persistent access or backdoors
sg_audit.sh              → check for new open ports
compliance_map.py        → map incident to ISO 27001 for incident report
```

### New SaaS/Cloud Application Onboarding

When a new cloud service or SaaS integration goes through your security
review (15+ per year as a security SME):

```
aws_sec_sweep.sh         → baseline posture of the new AWS account/environment
aws_iam_audit.sh         → check permissions granted to the integration
sg_audit.sh              → network exposure of any new infrastructure
container_audit.sh       → if containerised, check image and config
ssdlc_gate.sh            → wire into their CI/CD pipeline before go-live
compliance_map.py        → map gaps to controls for risk acceptance sign-off
```

---

*These scripts represent real automation built for real security work.
They are tools, not silver bullets. The output tells you where to look —
the judgment call on what to do is always yours.*

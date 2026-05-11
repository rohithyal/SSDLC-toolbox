#!/usr/bin/env python3
"""
AI agent scope and token permission auditor.

Reads an agent configuration file and checks each agent for:
  - Over-privileged scopes (write when only read is needed)
  - Missing token expiry or expiry too long
  - Dangerous permission combinations
  - Missing scope boundaries between agents
  - Agents with access to more resources than their stated purpose requires

Input format (JSON):
  {
    "agents": [
      {
        "name": "document-reader",
        "purpose": "Read customer documents for summarisation",
        "scopes": ["documents:read", "storage:read"],
        "token_expiry_minutes": 60,
        "can_call_agents": [],
        "resource_access": ["documents/*", "storage/docs/*"]
      }
    ]
  }

Usage:
    python3 agent_scope_auditor.py -f agents.json
    python3 agent_scope_auditor.py -f agents.json -o audit.json
"""

import json
import sys
import re
import argparse
from dataclasses import dataclass, field
from datetime import datetime


# ── Risk rules ───────────────────────────────────────────────────────────────

# Scopes considered dangerous on their own
DANGEROUS_SCOPES: dict[str, str] = {
    "admin":             "Full administrative access — should never be granted to an agent",
    "*":                 "Wildcard scope grants unrestricted access",
    "iam:write":         "Agent can modify identity and access policies",
    "iam:*":             "Agent has full IAM control",
    "secrets:write":     "Agent can create or overwrite secrets",
    "secrets:*":         "Agent has full secrets access including write",
    "execute:*":         "Agent can execute arbitrary code or commands",
    "network:write":     "Agent can modify network configuration",
    "users:write":       "Agent can create or modify user accounts",
    "users:delete":      "Agent can delete user accounts",
    "billing:write":     "Agent can modify billing configuration",
    "storage:delete":    "Agent can permanently delete stored data",
}

# Combinations that are dangerous together even if each is acceptable alone
DANGEROUS_COMBINATIONS: list[tuple[list[str], str]] = [
    (
        ["storage:read", "exfil:write"],
        "Agent can read storage and write externally — exfiltration path",
    ),
    (
        ["secrets:read", "http:post"],
        "Agent can read secrets and make outbound HTTP requests — exfiltration risk",
    ),
    (
        ["code:execute", "filesystem:write"],
        "Agent can execute code and write files — persistence and lateral movement risk",
    ),
    (
        ["users:read", "email:send"],
        "Agent can enumerate users and send emails — social engineering / phishing risk",
    ),
    (
        ["documents:read", "external:write"],
        "Agent can read internal documents and write externally — data leakage path",
    ),
    (
        ["logs:read", "external:post"],
        "Agent can read logs and post externally — credential and token leakage risk",
    ),
]

# Maximum acceptable token expiry in minutes per purpose keyword
EXPIRY_POLICY: dict[str, int] = {
    "default":     60,
    "read":        120,
    "summaris":    60,
    "analys":      60,
    "report":      120,
    "write":       30,
    "execute":     15,
    "admin":       10,
    "payment":     15,
    "credential":  10,
}

# Resource patterns that should trigger scrutiny
SENSITIVE_RESOURCE_PATTERNS: list[tuple[str, str]] = [
    (r"\*$",          "Wildcard resource access — scope not bounded to specific paths"),
    (r"secrets/",     "Direct access to secrets store"),
    (r"credentials/", "Direct access to credentials"),
    (r"/etc/",        "Access to system configuration directory"),
    (r"iam/",         "Access to IAM resources"),
    (r"billing/",     "Access to billing resources"),
    (r"users/.*\*",   "Wildcard access across user data"),
]


@dataclass
class AgentFinding:
    agent: str
    severity: str
    category: str
    description: str
    recommendation: str


@dataclass
class AgentAuditResult:
    name: str
    purpose: str
    risk_level: str = "LOW"
    risk_score: int = 0
    findings: list[AgentFinding] = field(default_factory=list)


SEVERITY_WEIGHT = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}


def score_to_level(score: int) -> str:
    if score >= 30:
        return "CRITICAL"
    if score >= 15:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    return "LOW"


def get_expiry_limit(purpose: str) -> int:
    purpose_lower = purpose.lower()
    for keyword, limit in EXPIRY_POLICY.items():
        if keyword in purpose_lower:
            return limit
    return EXPIRY_POLICY["default"]


# ── Audit checks ─────────────────────────────────────────────────────────────

def audit_scopes(agent: dict) -> list[AgentFinding]:
    findings = []
    name    = agent["name"]
    scopes  = agent.get("scopes", [])

    for scope in scopes:
        for dangerous, reason in DANGEROUS_SCOPES.items():
            if scope == dangerous or scope.endswith(":*") or scope == "*":
                findings.append(AgentFinding(
                    agent=name,
                    severity="CRITICAL" if "*" in scope or scope == "admin" else "HIGH",
                    category="dangerous_scope",
                    description=f"Scope '{scope}': {reason}",
                    recommendation=(
                        f"Replace '{scope}' with the minimum specific scope required. "
                        "Grant write only if the agent's stated purpose requires mutation."
                    ),
                ))
                break

    # write scopes without clear write purpose
    purpose = agent.get("purpose", "").lower()
    write_scopes = [s for s in scopes if s.endswith(":write") or s.endswith(":delete")]
    write_keywords = ["write", "creat", "updat", "delet", "modif"]
    if write_scopes and not any(w in purpose for w in write_keywords):
        findings.append(AgentFinding(
            agent=name,
            severity="HIGH",
            category="scope_purpose_mismatch",
            description=(
                f"Agent has write/delete scopes {write_scopes} but purpose "
                f"'{agent.get('purpose', '')}' suggests read-only operation"
            ),
            recommendation=(
                "Verify write access is genuinely required. If the agent only reads, "
                "remove all write and delete scopes."
            ),
        ))

    return findings


def audit_combinations(agent: dict) -> list[AgentFinding]:
    findings = []
    name   = agent["name"]
    scopes = set(agent.get("scopes", []))

    for combo, reason in DANGEROUS_COMBINATIONS:
        if all(s in scopes for s in combo):
            findings.append(AgentFinding(
                agent=name,
                severity="HIGH",
                category="dangerous_combination",
                description=f"Scope combination {combo}: {reason}",
                recommendation=(
                    "Decompose this agent into two separate agents with isolated scopes, "
                    "or remove one of the conflicting scopes if not required."
                ),
            ))

    return findings


def audit_token_expiry(agent: dict) -> list[AgentFinding]:
    findings = []
    name    = agent["name"]
    expiry  = agent.get("token_expiry_minutes")
    purpose = agent.get("purpose", "")

    if expiry is None:
        findings.append(AgentFinding(
            agent=name,
            severity="HIGH",
            category="no_token_expiry",
            description="No token expiry defined — token may be long-lived or permanent",
            recommendation="Set token_expiry_minutes. Default maximum: 60 minutes.",
        ))
        return findings

    limit = get_expiry_limit(purpose)
    if expiry > limit:
        findings.append(AgentFinding(
            agent=name,
            severity="MEDIUM",
            category="token_expiry_too_long",
            description=(
                f"Token expiry {expiry}min exceeds recommended {limit}min "
                f"for purpose: '{purpose}'"
            ),
            recommendation=(
                f"Reduce token_expiry_minutes to <= {limit}. "
                "Short-lived tokens limit blast radius if a token is leaked."
            ),
        ))

    return findings


def audit_resource_access(agent: dict) -> list[AgentFinding]:
    findings = []
    name      = agent["name"]
    resources = agent.get("resource_access", [])

    for resource in resources:
        for pattern, description in SENSITIVE_RESOURCE_PATTERNS:
            if re.search(pattern, resource):
                findings.append(AgentFinding(
                    agent=name,
                    severity="MEDIUM",
                    category="sensitive_resource",
                    description=f"Resource '{resource}': {description}",
                    recommendation=(
                        "Restrict resource path to the minimum required. "
                        "Replace wildcards with explicit resource identifiers where possible."
                    ),
                ))
                break

    return findings


def audit_agent_chaining(agents: list[dict]) -> list[AgentFinding]:
    findings = []
    agent_map = {a["name"]: a for a in agents}

    for agent in agents:
        called = agent.get("can_call_agents", [])
        for target_name in called:
            target = agent_map.get(target_name)
            if not target:
                findings.append(AgentFinding(
                    agent=agent["name"],
                    severity="LOW",
                    category="undefined_agent_target",
                    description=f"Agent calls undefined agent '{target_name}'",
                    recommendation="Define all agents in the config. Undefined targets bypass auditing.",
                ))
                continue

            # caller should not gain higher privilege through chaining
            caller_scopes = set(agent.get("scopes", []))
            target_scopes = set(target.get("scopes", []))
            privilege_gain = target_scopes - caller_scopes

            if any(
                s.endswith(":write") or s.endswith(":delete") or s == "admin"
                for s in privilege_gain
            ):
                findings.append(AgentFinding(
                    agent=agent["name"],
                    severity="HIGH",
                    category="privilege_escalation_via_chaining",
                    description=(
                        f"Agent '{agent['name']}' calls '{target_name}' which has "
                        f"higher-privilege scopes: {privilege_gain}. "
                        "Indirect privilege escalation path."
                    ),
                    recommendation=(
                        "Validate that agent chaining does not allow privilege escalation. "
                        "Consider a dedicated orchestrator with explicit scope grant per task."
                    ),
                ))

    return findings


# ── Main audit ────────────────────────────────────────────────────────────────

def audit_agent(agent: dict) -> AgentAuditResult:
    result = AgentAuditResult(
        name=agent.get("name", "unnamed"),
        purpose=agent.get("purpose", ""),
    )
    result.findings += audit_scopes(agent)
    result.findings += audit_combinations(agent)
    result.findings += audit_token_expiry(agent)
    result.findings += audit_resource_access(agent)
    result.risk_score = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in result.findings)
    result.risk_level = score_to_level(result.risk_score)
    return result


def print_results(results: list[AgentAuditResult], chain_findings: list[AgentFinding]):
    print(f"\n{'='*60}")
    print(f"Agent Scope Audit  |  {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*60}\n")

    for r in results:
        print(f"Agent:  {r.name}")
        print(f"Risk:   {r.risk_level} (score={r.risk_score})")
        print(f"Purpose: {r.purpose}")
        if not r.findings:
            print("  No issues found.\n")
            continue
        for f in r.findings:
            print(f"  [{f.severity}] {f.category}")
            print(f"    {f.description}")
            print(f"    Fix: {f.recommendation}")
        print()

    if chain_findings:
        print("--- Agent Chaining Risks ---")
        for f in chain_findings:
            print(f"  [{f.severity}] {f.agent}: {f.description}")
            print(f"    Fix: {f.recommendation}")
        print()

    critical = sum(1 for r in results if r.risk_level == "CRITICAL")
    high     = sum(1 for r in results if r.risk_level == "HIGH")
    print(f"Summary: {len(results)} agent(s) audited | CRITICAL={critical} HIGH={high}")


def main():
    parser = argparse.ArgumentParser(description="AI agent scope and token auditor")
    parser.add_argument("-f", "--file", required=True, help="Agent config JSON file")
    parser.add_argument("-o", "--output", help="Write JSON report to this path")
    args = parser.parse_args()

    with open(args.file) as fh:
        config = json.load(fh)

    agents = config.get("agents", config) if isinstance(config, dict) else config
    if not isinstance(agents, list):
        print("Error: config must contain an 'agents' list")
        sys.exit(1)

    results        = [audit_agent(a) for a in agents]
    chain_findings = audit_agent_chaining(agents)

    print_results(results, chain_findings)

    if args.output:
        report = {
            "generated":     datetime.now().strftime("%Y-%m-%d %H:%M"),
            "agents_audited": len(results),
            "results": [
                {
                    "name":       r.name,
                    "purpose":    r.purpose,
                    "risk_level": r.risk_level,
                    "risk_score": r.risk_score,
                    "findings": [
                        {
                            "severity":       f.severity,
                            "category":       f.category,
                            "description":    f.description,
                            "recommendation": f.recommendation,
                        }
                        for f in r.findings
                    ],
                }
                for r in results
            ],
            "chaining_findings": [
                {
                    "agent":          f.agent,
                    "severity":       f.severity,
                    "category":       f.category,
                    "description":    f.description,
                    "recommendation": f.recommendation,
                }
                for f in chain_findings
            ],
        }
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n[+] Report saved: {args.output}")

    any_high = any(r.risk_level in ("CRITICAL", "HIGH") for r in results)
    sys.exit(1 if any_high else 0)


if __name__ == "__main__":
    main()

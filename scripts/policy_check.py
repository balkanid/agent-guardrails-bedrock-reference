#!/usr/bin/env python3
"""Auto-deny checks that run before any BalkanID request or AWS change.

The core rule: a developer-created agent must never run as a developer (or any human, or an
admin role), and must never be granted broad managed policies. It gets its own scoped
execution role, approved in BalkanID, with an expiry.

  python3 scripts/policy_check.py                    # agent create, values from env
  python3 scripts/policy_check.py --grant BalkanIDAgentSecretsRead --minutes 30

Prints a JSON decision. Exit 0 = allowed, 1 = denied.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import balkanid_api as api

ROOT = Path(__file__).resolve().parent.parent
GUARDRAILS = ROOT / "policies" / "guardrails.json"


def load_guardrails(path: Path = GUARDRAILS) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def policy_names(raw: str) -> list[str]:
    names = []
    for item in re.split(r"[,\s]+", raw or ""):
        item = item.strip()
        if item:
            names.append(item.rsplit("/", 1)[-1])  # accept ARNs or bare names
    return names


def caller_role_arn() -> str:
    """Role behind the current AWS credentials, so we can refuse to reuse it for the agent."""
    aws = api.env_optional("AWS_CLI") or shutil.which("aws")
    if not aws:
        return ""
    try:
        proc = subprocess.run([aws, "sts", "get-caller-identity", "--output", "json"],
                              capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return json.loads(proc.stdout).get("Arn", "")


def _same_role(a: str, b: str) -> bool:
    """Compare an IAM role ARN with an assumed-role session ARN."""
    def role_name(arn: str) -> str:
        if ":assumed-role/" in arn:
            return arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
        return arn.rsplit("/", 1)[-1]
    return bool(a and b) and role_name(a) == role_name(b)


def check_create(g: dict, *, agent: str, policies: list[str], ttl_hours: int,
                 existing_role: str, caller_arn: str, parent: str, policy_arns: list[str] | None = None) -> list[str]:
    reasons: list[str] = []
    if policy_arns is not None:
        # Terraform attaches ARNs; BalkanID reviews names. They must be the same set, or the
        # approval would not cover what is actually attached.
        arn_names = sorted(a.rsplit("/", 1)[-1] for a in policy_arns)
        if arn_names != sorted(policies):
            reasons.append(
                f"AGENT_POLICY_ARNS {arn_names} must name exactly the reviewed AGENT_POLICY_NAMES {sorted(policies)}"
            )
        for arn in policy_arns:
            if not arn.startswith("arn:aws:iam::"):
                reasons.append(f"{arn!r} is not an IAM policy ARN")
    if not re.match(g.get("agent_name_pattern", "^.+$"), agent or ""):
        reasons.append(f"agent name {agent!r} does not match {g.get('agent_name_pattern')}")

    denied = {p.lower() for p in g.get("denied_policies", [])}
    for p in policies:
        if p.lower() in denied:
            reasons.append(f"policy {p!r} is too broad for an agent; request a scoped policy")

    if existing_role:
        role_reasons: list[str] = []
        for pattern in g.get("denied_execution_role_patterns", []):
            if re.search(pattern, existing_role):
                role_reasons.append(
                    f"execution role {existing_role!r} looks like a human, developer or admin role "
                    f"(matched {pattern!r}); agents get their own role"
                )
                break
        if caller_arn and _same_role(existing_role, caller_arn):
            role_reasons.append(
                "execution role is the role you are signed in as; an agent may not inherit its creator's permissions"
            )
        if not role_reasons:
            role_reasons.append(
                f"reusing execution role {existing_role!r} is not allowed; leave EXISTING_EXECUTION_ROLE_ARN "
                "empty and this workflow creates the agent's own BalkanID-approved role"
            )
        reasons.extend(role_reasons)

    ttl = g.get("ttl_hours", {})
    if ttl_hours <= 0 or ttl_hours > int(ttl.get("max", 72)):
        reasons.append(f"agent TTL {ttl_hours}h must be between 1 and {ttl.get('max', 72)} hours")

    if parent and parent == agent:
        reasons.append("an agent cannot be its own parent")
    return reasons


def check_grant(g: dict, *, grant: str, minutes: int) -> list[str]:
    rules = g.get("sensitive_grants", {})
    if grant not in rules:
        return [f"{grant!r} is not an approved sensitive grant; allowed: {sorted(rules)}"]
    limit = int(rules[grant].get("max_minutes", 60))
    if minutes <= 0 or minutes > limit:
        return [f"{grant} may be granted for 1 to {limit} minutes, not {minutes}"]
    return []


def expires_at(ttl_hours: int, now: dt.datetime | None = None) -> str:
    now = now or dt.datetime.now(dt.timezone.utc)
    return (now + dt.timedelta(hours=ttl_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BalkanID pre-request guardrails")
    parser.add_argument("--grant", default="", help="check a sensitive grant instead of an agent create")
    parser.add_argument("--minutes", type=int, default=30)
    parser.add_argument("--no-caller-check", action="store_true", help="skip sts get-caller-identity")
    args = parser.parse_args(argv)

    api.load_dotenv()
    g = load_guardrails()

    if args.grant:
        reasons = check_grant(g, grant=args.grant, minutes=args.minutes)
        decision = {"check": "grant", "grant": args.grant, "minutes": args.minutes}
    else:
        agent = api.env_optional("AGENT_NAME")
        ttl = int(api.env_optional("AGENT_TTL_HOURS", str(g.get("ttl_hours", {}).get("default", 8))))
        existing = api.env_optional("EXISTING_EXECUTION_ROLE_ARN")
        caller = "" if args.no_caller_check or not existing else caller_role_arn()
        arns = [a for a in re.split(r"[,\s]+", api.env_optional("AGENT_POLICY_ARNS")) if a]
        reasons = check_create(
            g, agent=agent, policies=policy_names(api.env_optional("AGENT_POLICY_NAMES")),
            ttl_hours=ttl, existing_role=existing, caller_arn=caller, parent=api.env_optional("PARENT_AGENT"),
            policy_arns=arns,
        )
        decision = {"check": "create", "agent": agent, "ttl_hours": ttl, "expires_at": expires_at(ttl)}

    decision["decision"] = "deny" if reasons else "allow"
    decision["reasons"] = reasons
    print(json.dumps(decision))
    for r in reasons:
        api.log_stderr(f"denied: {r}")
    return 1 if reasons else 0


if __name__ == "__main__":
    sys.exit(main())

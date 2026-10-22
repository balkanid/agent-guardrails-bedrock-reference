#!/usr/bin/env python3
"""Find agents past their BalkanID-approved expiry and (optionally) tear them down.

AWS is the source of truth: every agent role lives under /balkanid-agents/ and carries a
balkanid-expires-at tag set by Terraform from the approved expiry. Children are reaped with
(and before) their parent.

  python3 scripts/reap_expired.py                 # list expired agents as JSON
  python3 scripts/reap_expired.py --destroy       # run scripts/lifecycle.sh destroy for each

Run on a schedule (.github/workflows/reaper.yml).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import balkanid_api as api

ROOT = Path(__file__).resolve().parent.parent
ROLE_PATH = "/balkanid-agents/"


def aws_json(args: list[str]) -> dict:
    aws = api.env_optional("AWS_CLI") or shutil.which("aws")
    if not aws:
        raise SystemExit("aws CLI not found (set AWS_CLI)")
    proc = subprocess.run([aws, *args, "--output", "json"], capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise SystemExit(f"aws {' '.join(args[:2])} failed: {proc.stderr.strip()[:300]}")
    return json.loads(proc.stdout or "{}")


def agent_roles() -> list[dict]:
    roles = aws_json(["iam", "list-roles", "--path-prefix", ROLE_PATH]).get("Roles", [])
    out = []
    for role in roles:
        tags = {t["Key"]: t["Value"] for t in aws_json(["iam", "list-role-tags", "--role-name", role["RoleName"]]).get("Tags", [])}
        if "balkanid-agent" in tags:
            out.append({"role": role["RoleName"], "agent": tags["balkanid-agent"],
                        "expires_at": tags.get("balkanid-expires-at", ""), "parent": tags.get("balkanid-parent", "")})
    return out


def expired(agents: list[dict], now: dt.datetime) -> list[dict]:
    due: dict[str, dict] = {}
    for a in agents:
        try:
            when = dt.datetime.strptime(a["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        except ValueError:
            # No valid expiry tag is itself a violation: treat as expired so it gets attention.
            when = now
        if when <= now:
            due[a["agent"]] = {**a, "reason": "expired" if a["expires_at"] else "missing expiry"}
    # A child never outlives its parent.
    for a in agents:
        if a["parent"] and a["parent"] in due and a["agent"] not in due:
            due[a["agent"]] = {**a, "reason": f"parent {a['parent']} expired"}
    # Children first, so a parent's boundary is not deleted while a child still uses it.
    return sorted(due.values(), key=lambda a: 0 if a["parent"] else 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reap expired BalkanID-governed agents")
    parser.add_argument("--destroy", action="store_true")
    args = parser.parse_args(argv)
    api.load_dotenv()

    due = expired(agent_roles(), dt.datetime.now(dt.timezone.utc))
    print(json.dumps({"expired": due}))
    if not args.destroy:
        return 0
    failures = 0
    for a in due:
        api.log_stderr(f"reaping agent {a['agent']} ({a['reason']})")
        env = {**os.environ, "PARENT_AGENT": a["parent"]}
        proc = subprocess.run([str(ROOT / "scripts" / "lifecycle.sh"), "destroy", a["agent"]], env=env)
        failures += proc.returncode != 0
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

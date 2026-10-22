#!/usr/bin/env python3
"""Check env and tools before scripts/lifecycle.sh runs."""

from __future__ import annotations

import shutil
import sys

import balkanid_api as api
from policy_check import load_guardrails


def main() -> int:
    api.load_dotenv()
    errors: list[str] = []
    warnings: list[str] = []
    for name in ("BALKANID_PUBLIC_API_URL", "API_KEY_ID", "API_KEY_SECRET", "BALKANID_AGENT_OWNER_EMAIL",
                 "INTEGRATION_ID", "AWS_ACCOUNT_ID"):
        if not api.env_optional(name):
            errors.append(f"missing {name}")
    for tool in ("terraform", "aws"):
        if not shutil.which(tool):
            warnings.append(f"{tool} not found on PATH")
    if api.env_optional("EXISTING_EXECUTION_ROLE_ARN"):
        warnings.append("EXISTING_EXECUTION_ROLE_ARN is set; policy_check.py will refuse it")
    try:
        load_guardrails()
    except Exception as exc:  # noqa: BLE001
        errors.append(f"policies/guardrails.json invalid: {exc}")
    for m in warnings:
        api.log_stderr(f"warning: {m}")
    for m in errors:
        api.log_stderr(f"error: {m}")
    if errors:
        return 1
    api.log_stderr("preflight ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())

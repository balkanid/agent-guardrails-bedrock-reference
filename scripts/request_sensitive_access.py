#!/usr/bin/env python3
"""Time-bound sensitive access for an agent, approved in BalkanID with step-up MFA.

Raises SERVICE_ACCOUNT_ASSIGNMENT on the agent's own execution role, granting one of the
sensitive grant policies (terraform/grant-policies) for a limited number of minutes. Mark
those policies sensitive in BalkanID (custom insight with "Is Sensitive") so approvers must
complete step-up MFA. BalkanID attaches the policy on approval and removes it at expiry.

  python3 scripts/request_sensitive_access.py --agent payments-helper \
      --grant BalkanIDAgentSecretsRead --minutes 30 --reason "rotate staging DB creds"

Exit 0 when approved (and, with --wait-provisioning, attached). Fails closed otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys

import balkanid_api as api
from policy_check import check_grant, load_guardrails
from service_account_gate import role_name_for


def build_input(agent: str, identity_id: str, integration_id: str, grant: str, minutes: int, reason: str) -> dict:
    return {
        "requestType": "SERVICE_ACCOUNT_ASSIGNMENT",
        "reason": f"Agent {agent} needs {grant} for {minutes} min: {reason}",
        "duration": minutes * 60,
        "payload": {
            "entity": {
                "provisioningOption": "app",
                "integrationId": integration_id,
                "entity": identity_id,
                "scimPayload": {"grants": [{"type": "policy", "source_name": grant}], "revokes": []},
            }
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Request time-bound sensitive access for an agent")
    parser.add_argument("--agent", required=True)
    parser.add_argument("--grant", required=True, help="sensitive grant policy name, e.g. BalkanIDAgentSecretsRead")
    parser.add_argument("--minutes", type=int, default=30)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--wait-provisioning", action="store_true", help="also wait until BalkanID attaches the policy")
    args = parser.parse_args(argv)

    api.load_dotenv()
    reasons = check_grant(load_guardrails(), grant=args.grant, minutes=args.minutes)
    if reasons:
        for r in reasons:
            api.log_stderr(f"denied: {r}")
        print(json.dumps({"status": "denied", "reasons": reasons}))
        return 1

    integration_id = api.env("INTEGRATION_ID")
    url, key_id, secret = api.api_client_from_env()
    poll_s, timeout_s = api.poll_settings()

    identity = api.find_identity_id(url, key_id, secret, integration_id, role_name_for(args.agent),
                                    poll_s=poll_s, timeout_s=min(timeout_s, 120))
    inp = build_input(args.agent, identity["id"], integration_id, args.grant, args.minutes, args.reason)
    created = api.create_request_raw(url, key_id, secret, inp)
    if created.get("stepUpRequired"):
        api.log_stderr("BalkanID requires step-up verification from the requester: complete MFA in BalkanID, then retry")
        print(json.dumps({"status": "step_up_required"}))
        return 1
    request_id = created.get("id")
    if not created.get("success") or not request_id:
        raise SystemExit("createRequest failed for sensitive grant")
    api.log_stderr(f"request_id={request_id}; approver must complete step-up MFA if {args.grant} is marked sensitive")

    try:
        api.poll_request(url, key_id, secret, request_id, wait_provisioning=args.wait_provisioning,
                         poll_s=poll_s, timeout_s=timeout_s, label="SERVICE_ACCOUNT_ASSIGNMENT")
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        print(json.dumps({"request_id": request_id, "status": "denied" if code == 1 else "failed"}))
        return code or 1
    print(json.dumps({"request_id": request_id, "status": "approved", "grant": args.grant, "minutes": args.minutes}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

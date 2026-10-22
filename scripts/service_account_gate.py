#!/usr/bin/env python3
"""BalkanID approval for the agent's own execution role (CREATE_SERVICE_ACCOUNT).

This replaces "the agent runs as whoever created it" with a dedicated, scoped identity that
has a named owner and an expiry. Terraform creates the role after approval; this gate only
approves. Exit 0 only on approval.
"""

from __future__ import annotations

import json
import sys

import balkanid_api as api
from policy_check import expires_at, load_guardrails, policy_names

ROLE_PATH_PREFIX = "/balkanid-agents/"


def role_name_for(agent: str) -> str:
    return f"agent-{agent}"


def build_input(agent: str, owner: str, integration_id: str, policies: list[str], expiration: str) -> dict:
    scim_payload: dict = {
        "aws_service_role_name": role_name_for(agent),
        "aws_service_names": api.env_optional("SERVICE_ACCOUNT_AWS_SERVICE_NAMES", "bedrock-agentcore.amazonaws.com"),
        "description": f"Dedicated execution role for agent {agent}; never a developer or human role",
    }
    if policies:
        scim_payload["grants"] = [{"type": "policy", "source_name": p} for p in policies]
        scim_payload["revokes"] = []
    return {
        "requestType": "CREATE_SERVICE_ACCOUNT",
        "employeeEmail": owner,
        "reason": f"Own scoped identity for agent {agent} (expires {expiration})",
        "expirationDate": expiration,
        "payload": {
            "entity": {
                "provisioningOption": "app",
                "integrationId": integration_id,
                "sourceType": "aws service role",
                "identityType": "service account",
                "name": role_name_for(agent),
                "scimPayload": scim_payload,
            }
        },
    }


def main() -> int:
    api.load_dotenv()
    agent = api.env("AGENT_NAME")
    owner = api.env("BALKANID_AGENT_OWNER_EMAIL")
    integration_id = api.env("INTEGRATION_ID")
    g = load_guardrails()
    ttl = int(api.env_optional("AGENT_TTL_HOURS", str(g["ttl_hours"]["default"])))
    expiration = api.env_optional("AGENT_EXPIRES_AT") or expires_at(ttl)
    policies = policy_names(api.env_optional("AGENT_POLICY_NAMES"))

    url, key_id, secret = api.api_client_from_env()
    poll_s, timeout_s = api.poll_settings()
    api.log_stderr(f"requesting execution role {role_name_for(agent)!r} for agent {agent!r} until {expiration}")
    request_id = api.create_request(url, key_id, secret, build_input(agent, owner, integration_id, policies, expiration))
    api.log_stderr(f"request_id={request_id}; waiting for approval (fail closed on deny/timeout)")
    try:
        api.poll_request(url, key_id, secret, request_id, wait_provisioning=False,
                         poll_s=poll_s, timeout_s=timeout_s, label="CREATE_SERVICE_ACCOUNT")
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        print(json.dumps({"request_id": request_id, "status": "failed"}))
        return code or 1
    print(json.dumps({"request_id": request_id, "status": "approved", "role_name": role_name_for(agent),
                      "expires_at": expiration}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

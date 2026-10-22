#!/usr/bin/env python3
"""BalkanID approval for the agent itself (AGENT_ACCESS), before anything is provisioned.

Records the human owner, the developer who asked for it, its purpose, its parent (for
subagents), the execution role it will run as, and when it expires. Exit 0 only on approval.
"""

from __future__ import annotations

import getpass
import json
import sys

import balkanid_api as api
from policy_check import expires_at, load_guardrails, policy_names
from service_account_gate import ROLE_PATH_PREFIX, role_name_for


def purpose(agent: str) -> str:
    return api.env_optional("AGENT_PURPOSE") or f"Developer agent {agent}"


def build_input(agent: str, owner: str, expiration: str) -> dict:
    account = api.env_optional("AWS_ACCOUNT_ID")
    role_arn = f"arn:aws:iam::{account}:role{ROLE_PATH_PREFIX}{role_name_for(agent)}" if account else ""
    parent = api.env_optional("PARENT_AGENT")
    metadata = {
        "platform": "aws-bedrock-agentcore",
        "requested_by": api.env_optional("GITHUB_ACTOR") or api.env_optional("BALKANID_DEVELOPER_ID") or getpass.getuser(),
        "expires_at": expiration,
        "policies": policy_names(api.env_optional("AGENT_POLICY_NAMES")),
        "model": api.env_optional("FOUNDATION_MODEL", "amazon.nova-micro-v1:0"),
        "inherits_creator_permissions": False,
    }
    if parent:
        metadata["parent_agent"] = parent
    agent_access: dict = {
        "action": "CREATE",
        "name": agent,
        "agentType": "bedrock-agentcore",
        "description": purpose(agent),
        "metadata": metadata,
    }
    integration = api.env_optional("INTEGRATION_ID")
    if integration:
        agent_access["integrationId"] = integration
    if role_arn:
        agent_access["intendedIamRoleArn"] = role_arn
    return {
        "requestType": "AGENT_ACCESS",
        "employeeEmail": owner,
        "reason": purpose(agent),
        "expirationDate": expiration,
        "runAsync": False,
        "payload": {"agentAccess": agent_access},
    }


def main() -> int:
    api.load_dotenv()
    agent = api.env("AGENT_NAME")
    owner = api.env("BALKANID_AGENT_OWNER_EMAIL")
    g = load_guardrails()
    ttl = int(api.env_optional("AGENT_TTL_HOURS", str(g["ttl_hours"]["default"])))
    expiration = api.env_optional("AGENT_EXPIRES_AT") or expires_at(ttl)

    url, key_id, secret = api.api_client_from_env()
    poll_s, timeout_s = api.poll_settings()
    who = api.redact_identifier(owner) if api.ci_mode() else owner
    api.log_stderr(f"requesting agent {agent!r} owner={who} expires={expiration}")
    request_id = api.create_request(url, key_id, secret, build_input(agent, owner, expiration))
    api.log_stderr(f"request_id={request_id}; waiting for approval (fail closed on deny/timeout)")
    try:
        api.poll_request(url, key_id, secret, request_id, wait_provisioning=False,
                         poll_s=poll_s, timeout_s=timeout_s, label="AGENT_ACCESS")
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        print(json.dumps({"request_id": request_id, "status": "denied" if code == 1 else "failed"}))
        return code or 1
    print(json.dumps({"request_id": request_id, "status": "approved", "expires_at": expiration}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

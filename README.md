# BalkanID guardrails for developer-created Bedrock agents: reference

Reference implementation for the case where **developers create AWS Bedrock AgentCore agents and the agent inherits the developer's permissions**. With BalkanID, every agent gets its own approved identity, a named owner, a permissions ceiling, minutes-long grants for sensitive access with step-up MFA, and an expiry.

Builds on [agent-lifecycle-terraform-reference](https://github.com/balkanid/agent-lifecycle-terraform-reference), which gates agent creation on BalkanID approval. This repository adds the guardrails around the identity the agent runs as. The Kiro version of the same pattern is [agent-lifecycle-kiro-reference](https://github.com/balkanid/agent-lifecycle-kiro-reference).

## The control gap

| Without guardrails | With this reference |
|---|---|
| Agent runs as the developer's role, a CI role, or a role with `AdministratorAccess` | Agent runs as `agent-<name>`, its own role, approved in BalkanID. Reusing an existing role is refused. |
| No owner, no approval, no record | `AGENT_ACCESS` names owner, requester, purpose, parent and expiry before anything is created |
| Broad policies "to get it working" | Admin and `*FullAccess` policies auto-denied; a permissions boundary caps services and blocks IAM, STS role-hopping, Organizations and data destruction |
| Secrets and production reachable all the time | Time-bound `SERVICE_ACCOUNT_ASSIGNMENT` grants, step-up MFA for approvers |
| Subagents spawned with whatever is lying around | Children get their own role under the parent's boundary and are reaped with the parent |
| Agents live forever | Required expiry; an hourly reaper destroys expired agents, children first |

## Flow

```
scripts/lifecycle.sh apply payments-helper
  policy_check.py            auto-deny: admin policies, reused roles, caller's own role, TTL > max
  service_account_gate.py    BalkanID CREATE_SERVICE_ACCOUNT  agent-payments-helper, expiry      -> approved
  gate.py                    BalkanID AGENT_ACCESS  owner, requester, purpose, parent, expiry    -> approved
  terraform (workspace)      role + permissions boundary + AgentCore harness, tagged owner/expiry
  trigger_sync.py            BalkanID discovers agent and role

scripts/lifecycle.sh grant payments-helper BalkanIDAgentSecretsRead 30 "rotate staging creds"
  policy_check.py --grant    grant exists and is within its maximum length
  request_sensitive_access   BalkanID SERVICE_ACCOUNT_ASSIGNMENT, 30 minutes -> approver step-up MFA -> attached

reaper.yml (hourly)          destroy expired agents, children first, then sync
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and threat model, and [policies/BALKANID_POLICIES.md](policies/BALKANID_POLICIES.md) for the BalkanID request policies and step-up setup that mirror the local rules.

## Repository layout

```
policies/guardrails.json           Denied policies, denied role patterns, TTL limits, sensitive grant limits
policies/BALKANID_POLICIES.md      Matching BalkanID request policies and step-up configuration
scripts/
  lifecycle.sh                     apply | destroy | grant | reap
  policy_check.py                  Local auto-deny before any request
  service_account_gate.py          CREATE_SERVICE_ACCOUNT for the agent's own role
  gate.py                          AGENT_ACCESS for the agent
  request_sensitive_access.py      SERVICE_ACCOUNT_ASSIGNMENT time-bound grant
  reap_expired.py                  Find and destroy expired agents
  balkanid_api.py                  Shared Public API helpers (stdlib only)
  trigger_sync.py, preflight.py, verify_imports.py
terraform/
  agent/                           Execution role, permissions boundary, AgentCore harness (one workspace per agent)
  grant-policies/                  Sensitive grant policies (create once per account)
aws/agent-provisioner-iam-policy.json   Least-privilege policy for the principal that runs Terraform
.github/workflows/ci.yml, cd.yml (Agent lifecycle), reaper.yml
tests/                             Unit tests against a mock BalkanID API and a fake AWS CLI
```

## Prerequisites

**BalkanID**

- Agents (Early Access), agent access requests, and an AWS integration for the target account (`INTEGRATION_ID`).
- An employee API key that can call `createRequest`, `requests`, `identities` and `syncIntegration` ([Public API](https://docs.balkan.id/)).
- Request policies from [BALKANID_POLICIES.md](policies/BALKANID_POLICIES.md); Step-Up MFA with the grant policies marked sensitive.

**AWS and tools**

- Bedrock AgentCore in your region and model access (default Amazon Nova Micro).
- A Terraform principal with [`aws/agent-provisioner-iam-policy.json`](aws/agent-provisioner-iam-policy.json) (roles and policies only under `/balkanid-agents/`).
- Python 3.11+ (standard library only), Terraform 1.5+, AWS CLI v2. A remote backend for anything beyond a local demo.

## Quick start (local)

```bash
cp env.example .env
python3 scripts/preflight.py
(cd terraform/grant-policies && terraform init && terraform apply)   # once per account

scripts/lifecycle.sh apply payments-helper
scripts/lifecycle.sh grant payments-helper BalkanIDAgentSecretsRead 30 "rotate staging DB credentials"
scripts/lifecycle.sh destroy payments-helper
```

Subagent:

```bash
PARENT_AGENT=payments-helper scripts/lifecycle.sh apply payments-log-reader
```

See the guardrails refuse a request:

```bash
AGENT_POLICY_NAMES=AdministratorAccess python3 scripts/policy_check.py --no-caller-check
EXISTING_EXECUTION_ROLE_ARN=arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Developer_x \
  python3 scripts/policy_check.py
python3 scripts/policy_check.py --grant BalkanIDAgentSecretsRead --minutes 600
```

## GitHub Actions

1. Create environment **`agent-lifecycle`** with secrets `BALKANID_PUBLIC_API_URL`, `BALKANID_API_KEY_ID`, `BALKANID_API_KEY_SECRET`, `BALKANID_AGENT_OWNER_EMAIL`, `BALKANID_INTEGRATION_ID`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and variables `AWS_ACCOUNT_ID`, `AWS_REGION`, `AGENT_POLICY_NAMES`, `AGENT_POLICY_ARNS`.
2. Configure the S3 backend in `terraform/agent/versions.tf`.
3. **Actions → Agent lifecycle → Run workflow** to apply, destroy or grant. The job waits on BalkanID approvals and fails closed.
4. **Agent reaper** runs hourly.

## BalkanID Public API usage

| API | Used by |
|---|---|
| `createRequest` `CREATE_SERVICE_ACCOUNT` | `service_account_gate.py`: dedicated execution role with approved policies and `expirationDate` |
| `createRequest` `AGENT_ACCESS` | `gate.py`: owner, requester, purpose, parent, intended role ARN, `expirationDate` |
| `createRequest` `SERVICE_ACCOUNT_ASSIGNMENT` | `request_sensitive_access.py`: grant with `duration` |
| `requests` | Approval polling |
| `identities` | Resolve the agent role's BalkanID service account id |
| `syncIntegration` | After apply and destroy |

## Testing

```bash
python3 -m unittest discover -s tests -v
```

## Notes

- The policies Terraform attaches (`AGENT_POLICY_ARNS`) must name exactly the policies BalkanID reviewed (`AGENT_POLICY_NAMES`); otherwise `policy_check.py` refuses the run.
- The reaper treats an agent role with no `balkanid-expires-at` tag as expired. Only this workflow creates roles under `/balkanid-agents/`, and it always sets the tag. It confirms each role is really gone after `terraform destroy`, and fails loudly if it is not (for example, when no remote backend is configured).
- Teardown is recorded in BalkanID through `syncIntegration`; this reference does not raise a `DELETE_SERVICE_ACCOUNT` request, so expiry is not blocked on an approver.
- The workflows use static AWS keys for simplicity. In production, use GitHub OIDC with `aws-actions/configure-aws-credentials` and a role scoped to `aws/agent-provisioner-iam-policy.json`.
- This repository is a **reference**. Review the boundary, the denied policy list and the grant policies against your environment before production use.

## Security

See [SECURITY.md](SECURITY.md).

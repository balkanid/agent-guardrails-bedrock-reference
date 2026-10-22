# Security

## Reporting security issues

Per the [BalkanID Trust Center](https://trustcenter.balkan.id/), report security questions, incidents, or concerns to **[security@balkan.id](mailto:security@balkan.id)**.

For findings in this reference repository (sample code, docs, or workflows):

1. Email **security@balkan.id** with a description, reproduction steps, and impact.
2. Do **not** open a public GitHub issue for credential leaks, tenant-specific data, or exploitable vulnerabilities.
3. Do **not** test against BalkanID production systems or customer tenants without authorization.

For non-security bugs or documentation fixes, use GitHub Issues.

## Protecting credentials

| Location | Guidance |
|---|---|
| Git | Never commit `.env`, `*.tfvars` or Terraform state. |
| GitHub Actions | Store BalkanID and AWS credentials as **secrets** on the `agent-lifecycle` environment and require reviewers on it for production accounts. |
| AWS | Scope the Terraform principal to [`aws/agent-provisioner-iam-policy.json`](aws/agent-provisioner-iam-policy.json), which can only manage roles and policies under `/balkanid-agents/`, can only create roles that carry an agent permissions boundary, and cannot remove a boundary. |

## What the guardrails guarantee

The permissions boundary and the execution role are enforced by AWS and hold even if a pipeline is misconfigured. `policy_check.py` is a convenience that fails fast; the BalkanID request policies are the server-side equivalent. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#threat-model).

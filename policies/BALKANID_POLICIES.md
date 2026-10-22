# Recommended BalkanID policies

`scripts/policy_check.py` refuses obviously unsafe requests before they are raised. Configure the same intent as request policies in BalkanID (**Configure → Global Settings → Policies**, type **Request**) so it also holds for requests raised from the BalkanID UI, Slack, the MCP server or any other pipeline. Policies are evaluated top to bottom; the first matching clause wins. See [Policies](https://docs.balkan.id/lifecycle-management/policies).

The rules below are a starting point. Build each condition from the user, application, entitlement and request attributes available in your tenant, and start new policies as inactive.

| # | Applies to | Condition | Action | Why |
|---|---|---|---|---|
| 1 | `CREATE_SERVICE_ACCOUNT`, `SERVICE_ACCOUNT_ASSIGNMENT` | Grant includes `AdministratorAccess`, `PowerUserAccess`, `IAMFullAccess` or any `*FullAccess` policy | **Auto-deny** | Agents never get broad managed policies. |
| 2 | `SERVICE_ACCOUNT_ASSIGNMENT` | Grant is `BalkanIDAgentSecretsRead`, `BalkanIDAgentProductionReadOnly` or `BalkanIDAgentCustomerDataRead` | **Assign reviewer**: the agent owner's manager or the security group | Sensitive grants always get a human decision. |
| 3 | `AGENT_ACCESS` | Requester is not in an engineering department | **Auto-deny** | Only engineering creates developer agents. |
| 4 | `AGENT_ACCESS` | Owner in engineering (after rule 3) | **Auto-approve** | Low-risk, time-bound developer agents are self-service. Everything else above still applies to the identity they get. |
| 5 | `CREATE_SERVICE_ACCOUNT` | Grant is only Bedrock invoke or the team's scoped policies | **Auto-approve** | Scoped identities are cheap to approve and expire automatically. |

## Step-up MFA for sensitive grants

1. Enable **Require Step-Up MFA for Sensitive Requests** under **Access Requests → Settings**.
2. Create a custom insight whose filter matches the three `BalkanIDAgent*` grant policies and tick **Is Sensitive**.

Approving (or delegating) any request that touches those policies then requires a fresh TOTP or Okta Verify check. See [Step Up MFA for Sensitive Requests](https://docs.balkan.id/lifecycle-management/step-up-mfa-for-sensitive-requests).

## Natural-language policies through MCP

The same rules can be authored and tested through the [BalkanID MCP server](https://docs.balkan.id/balkanid-mcp/getting-started-with-mcp) from Claude, Copilot or Kiro, for example: "deny any service account request for an agent that includes a FullAccess policy". Review the generated policy in the BalkanID UI before activating it, and start new policies as inactive.

## Reviews

Include agent execution roles (path `/balkanid-agents/`) in your regular access review campaigns. Each role carries its owner and expiry as tags, and BalkanID shows the agent, its owner and its access together.

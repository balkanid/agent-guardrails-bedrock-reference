# Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `policy_check.py` denies with "too broad" | A denied managed policy in `AGENT_POLICY_NAMES` | Request a scoped policy; extend `denied_policies` only deliberately |
| "reusing execution role ... is not allowed" | `EXISTING_EXECUTION_ROLE_ARN` is set | Leave it empty; the workflow creates the agent's own role |
| Gate times out | Nobody approved within `POLL_TIMEOUT_SECONDS` | Approve in BalkanID and re-run; the open request can be approved later |
| `NoSuchEntity` for `agent-boundary-<parent>` | Applying a subagent before its parent exists | Apply the parent first |
| Sensitive grant: "timed out resolving identity" | BalkanID has not discovered the role yet | Run `scripts/trigger_sync.py`, wait for the sync, retry |
| Sensitive grant approved, AWS still denies | Policy not yet attached, or outside the boundary | Re-run with `--wait-provisioning`; keep grant services inside `allowed_services` |
| Reaper destroyed an agent unexpectedly | Its expiry passed, its parent expired, or the expiry tag was removed | Re-apply with a new TTL; do not edit tags by hand |
| `AccessDenied` creating roles or policies | Terraform principal policy out of date | Replace it with `aws/agent-provisioner-iam-policy.json` in full |

#!/usr/bin/env bash
# Developer-agent lifecycle with BalkanID guardrails.
#
#   scripts/lifecycle.sh apply   <agent>     policy check -> service account gate -> agent gate -> terraform -> sync
#   scripts/lifecycle.sh destroy <agent>     terraform destroy -> sync
#   scripts/lifecycle.sh grant   <agent> <grant-policy> <minutes> "<reason>"
#   scripts/lifecycle.sh reap                destroy every agent past its approved expiry
#
# Reads .env when present. Each agent has its own Terraform workspace in terraform/agent.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
# Load .env without overriding anything already set, so "PARENT_AGENT=x lifecycle.sh ..." works.
if [[ -f "$root/.env" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    [[ -n "${!key+x}" ]] && continue
    if [[ "$value" =~ ^\"(.*)\"$ || "$value" =~ ^\'(.*)\'$ ]]; then
      value="${BASH_REMATCH[1]}"
    fi
    export "$key=$value"
  done <"$root/.env"
fi

cmd="${1:-}"
agent="${2:-}"

require_agent() {
  if [[ -z "$agent" ]]; then
    echo "usage: $0 $cmd <agent>" >&2
    exit 2
  fi
  export AGENT_NAME="$agent"
}

tf() {
  terraform -chdir="$root/terraform/agent" "$@"
}

select_workspace() {
  tf init -input=false >/dev/null
  tf workspace select -or-create "$agent" >/dev/null
}

case "$cmd" in
  apply)
    require_agent
    echo "==> Guardrail pre-check" >&2
    decision="$(python3 "$root/scripts/policy_check.py")"
    expires_at="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["expires_at"])' "$decision")"
    export AGENT_EXPIRES_AT="$expires_at"

    echo "==> BalkanID: approve the agent's own execution role" >&2
    python3 "$root/scripts/service_account_gate.py"

    echo "==> BalkanID: approve the agent" >&2
    python3 "$root/scripts/gate.py"

    echo "==> Terraform (workspace $agent)" >&2
    select_workspace
    policy_arns="$(python3 - <<'PY'
import json, os
names = [n.strip() for n in os.environ.get("AGENT_POLICY_ARNS", "").replace(",", " ").split() if n.strip()]
print(json.dumps(names))
PY
)"
    tf apply -input=false -auto-approve \
      -var="aws_account_id=${AWS_ACCOUNT_ID:?AWS_ACCOUNT_ID is required}" \
      -var="aws_region=${AWS_REGION:-us-east-1}" \
      -var="agent_name=$agent" \
      -var="owner_email=${BALKANID_AGENT_OWNER_EMAIL:?}" \
      -var="expires_at=$expires_at" \
      -var="parent_agent_name=${PARENT_AGENT:-}" \
      -var="agent_policy_arns=$policy_arns" \
      -var="foundation_model=${FOUNDATION_MODEL:-amazon.nova-micro-v1:0}"

    if [[ -n "${INTEGRATION_ID:-}" ]]; then
      echo "==> BalkanID: sync so the agent and its role are discovered" >&2
      python3 "$root/scripts/trigger_sync.py"
    fi
    ;;

  destroy)
    require_agent
    select_workspace
    echo "==> Terraform destroy (workspace $agent)" >&2
    tf destroy -input=false -auto-approve \
      -var="aws_account_id=${AWS_ACCOUNT_ID:?AWS_ACCOUNT_ID is required}" \
      -var="aws_region=${AWS_REGION:-us-east-1}" \
      -var="agent_name=$agent" \
      -var="owner_email=${BALKANID_AGENT_OWNER_EMAIL:-unknown@example.com}" \
      -var="expires_at=1970-01-01T00:00:00Z" \
      -var="parent_agent_name=${PARENT_AGENT:-}"
    tf workspace select default >/dev/null
    tf workspace delete "$agent" >/dev/null || true
    if [[ -n "${INTEGRATION_ID:-}" ]]; then
      python3 "$root/scripts/trigger_sync.py"
    fi
    ;;

  grant)
    require_agent
    grant_policy="${3:?grant policy name required}"
    minutes="${4:?minutes required}"
    reason="${5:?reason required}"
    python3 "$root/scripts/request_sensitive_access.py" --agent "$agent" --grant "$grant_policy" \
      --minutes "$minutes" --reason "$reason" --wait-provisioning
    ;;

  reap)
    python3 "$root/scripts/reap_expired.py" --destroy
    ;;

  *)
    sed -n '2,10p' "$0" >&2
    exit 2
    ;;
esac

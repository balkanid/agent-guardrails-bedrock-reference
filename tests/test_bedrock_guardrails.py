"""Tests for the Bedrock developer-agent guardrails against a mock BalkanID API. Standard library only.

Run: python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import datetime as dt
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import gate  # noqa: E402
import policy_check  # noqa: E402
import reap_expired  # noqa: E402
import request_sensitive_access  # noqa: E402
import service_account_gate  # noqa: E402
from mock_balkanid import MockBalkanID  # noqa: E402

G = policy_check.load_guardrails()


def run(main, argv=None):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv) if argv is not None else main()
    return code, out.getvalue(), err.getvalue()


class PolicyCheckTests(unittest.TestCase):
    def check(self, **kw):
        base = dict(agent="payments-helper", policies=[], ttl_hours=8, existing_role="", caller_arn="", parent="")
        base.update(kw)
        return policy_check.check_create(G, **base)

    def test_scoped_agent_allowed(self):
        self.assertEqual(self.check(policies=["AmazonBedrockLimitedAccess"]), [])

    def test_broad_policies_denied(self):
        for p in ("AdministratorAccess", "arn:aws:iam::aws:policy/PowerUserAccess", "iamfullaccess"):
            with self.subTest(p=p):
                names = policy_check.policy_names(p)
                self.assertTrue(self.check(policies=names))

    def test_developer_sso_role_denied(self):
        r = self.check(existing_role="arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Developer_abc")
        self.assertTrue(any("human, developer or admin" in x for x in r))

    def test_creator_role_denied(self):
        r = self.check(existing_role="arn:aws:iam::123456789012:role/ci-builder",
                       caller_arn="arn:aws:sts::123456789012:assumed-role/ci-builder/session")
        self.assertTrue(any("signed in as" in x for x in r))

    def test_any_role_reuse_denied(self):
        r = self.check(existing_role="arn:aws:iam::123456789012:role/some-app-role")
        self.assertTrue(any("not allowed" in x for x in r))

    def test_ttl_bounds(self):
        self.assertTrue(self.check(ttl_hours=0))
        self.assertTrue(self.check(ttl_hours=G["ttl_hours"]["max"] + 1))
        self.assertEqual(self.check(ttl_hours=G["ttl_hours"]["max"]), [])

    def test_bad_name_and_self_parent(self):
        self.assertTrue(self.check(agent="Bad_Name"))
        self.assertTrue(self.check(parent="payments-helper"))

    def test_attached_arns_must_match_reviewed_names(self):
        ok = self.check(policies=["AmazonBedrockLimitedAccess"],
                        policy_arns=["arn:aws:iam::aws:policy/AmazonBedrockLimitedAccess"])
        self.assertEqual(ok, [])
        sneaky = self.check(policies=["AmazonBedrockLimitedAccess"],
                            policy_arns=["arn:aws:iam::aws:policy/AdministratorAccess"])
        self.assertTrue(any("must name exactly" in r for r in sneaky))
        extra = self.check(policies=["AmazonBedrockLimitedAccess"],
                           policy_arns=["arn:aws:iam::aws:policy/AmazonBedrockLimitedAccess",
                                        "arn:aws:iam::aws:policy/ReadOnlyAccess"])
        self.assertTrue(extra)

    def test_grant_limits(self):
        self.assertEqual(policy_check.check_grant(G, grant="BalkanIDAgentSecretsRead", minutes=30), [])
        self.assertTrue(policy_check.check_grant(G, grant="BalkanIDAgentSecretsRead", minutes=600))
        self.assertTrue(policy_check.check_grant(G, grant="AdministratorAccess", minutes=5))

    def test_cli_outputs_decision(self):
        env = {"BALKANID_SKIP_DOTENV": "1", "AGENT_NAME": "payments-helper", "AGENT_POLICY_NAMES": "AdministratorAccess",
               "AGENT_TTL_HOURS": "8", "EXISTING_EXECUTION_ROLE_ARN": ""}
        with mock.patch.dict(os.environ, env):
            code, out, _ = run(policy_check.main, ["--no-caller-check"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["decision"], "deny")


class ApiFlowTests(unittest.TestCase):
    def setUp(self):
        self.mock = MockBalkanID().__enter__()
        self.addCleanup(self.mock.__exit__, None, None, None)
        env = {
            "BALKANID_SKIP_DOTENV": "1", "BALKANID_PUBLIC_API_URL": self.mock.url, "API_KEY_ID": "test-key",
            "API_KEY_SECRET": "s", "BALKANID_AGENT_OWNER_EMAIL": "owner@example.com", "INTEGRATION_ID": "int-aws",
            "AWS_ACCOUNT_ID": "123456789012", "AGENT_NAME": "payments-helper", "AGENT_EXPIRES_AT": "2026-10-22T18:00:00Z",
            "AGENT_POLICY_NAMES": "AmazonBedrockLimitedAccess", "POLL_SECONDS": "1", "POLL_TIMEOUT_SECONDS": "5",
            "GQL_MAX_RETRIES": "1", "PARENT_AGENT": "",
        }
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)
        for k in ("CI", "GITHUB_ACTIONS"):
            os.environ.pop(k, None)

    def test_service_account_gate_approved(self):
        code, out, _ = run(service_account_gate.main)
        self.assertEqual(code, 0)
        sent = self.mock.created[0]
        self.assertEqual(sent["requestType"], "CREATE_SERVICE_ACCOUNT")
        self.assertEqual(sent["expirationDate"], "2026-10-22T18:00:00Z")
        self.assertEqual(sent["payload"]["entity"]["name"], "agent-payments-helper")
        self.assertEqual(sent["payload"]["entity"]["scimPayload"]["grants"][0]["source_name"], "AmazonBedrockLimitedAccess")

    def test_agent_gate_records_no_inheritance_and_parent(self):
        os.environ["PARENT_AGENT"] = "payments-orchestrator"
        code, out, _ = run(gate.main)
        self.assertEqual(code, 0)
        aa = self.mock.created[0]["payload"]["agentAccess"]
        self.assertEqual(aa["intendedIamRoleArn"], "arn:aws:iam::123456789012:role/balkanid-agents/agent-payments-helper")
        self.assertFalse(aa["metadata"]["inherits_creator_permissions"])
        self.assertEqual(aa["metadata"]["parent_agent"], "payments-orchestrator")

    def test_agent_gate_denied_fails_closed(self):
        self.mock.next_status = "denied"
        code, out, _ = run(gate.main)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["status"], "denied")

    def test_sensitive_grant_flow(self):
        self.mock.identities["agent-payments-helper"] = {"id": "ident-7", "sourceId": "", "handle": "agent-payments-helper",
                                                        "sourceType": "aws service role", "fullName": ""}
        code, out, err = run(request_sensitive_access.main, ["--agent", "payments-helper", "--grant",
                                                             "BalkanIDAgentSecretsRead", "--minutes", "30", "--reason", "rotate"])
        self.assertEqual(code, 0, err)
        sent = self.mock.created[0]
        self.assertEqual(sent["requestType"], "SERVICE_ACCOUNT_ASSIGNMENT")
        self.assertEqual(sent["duration"], 1800)
        self.assertEqual(sent["payload"]["entity"]["entity"], "ident-7")

    def test_sensitive_grant_over_limit_never_reaches_balkanid(self):
        code, _, _ = run(request_sensitive_access.main, ["--agent", "payments-helper", "--grant",
                                                         "BalkanIDAgentSecretsRead", "--minutes", "500", "--reason", "x"])
        self.assertEqual(code, 1)
        self.assertEqual(self.mock.calls, 0)

    def test_sensitive_grant_step_up(self):
        self.mock.identities["agent-payments-helper"] = {"id": "ident-7"}
        self.mock.step_up_required = True
        code, out, _ = run(request_sensitive_access.main, ["--agent", "payments-helper", "--grant",
                                                           "BalkanIDAgentSecretsRead", "--minutes", "10", "--reason", "x"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["status"], "step_up_required")


class ReaperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.roles = {
            "agent-old": {"balkanid-agent": "old", "balkanid-expires-at": "2026-01-01T00:00:00Z"},
            "agent-child": {"balkanid-agent": "child", "balkanid-expires-at": "2099-01-01T00:00:00Z", "balkanid-parent": "old"},
            "agent-live": {"balkanid-agent": "live", "balkanid-expires-at": "2099-01-01T00:00:00Z"},
            "agent-untagged": {"balkanid-agent": "untagged"},
            "agent-grandchild": {"balkanid-agent": "grandchild", "balkanid-expires-at": "2099-01-01T00:00:00Z",
                                 "balkanid-parent": "child"},
        }
        script = self.tmp / "aws"
        script.write_text(
            "#!/usr/bin/env python3\nimport json, sys\n"
            f"roles = {json.dumps(self.roles)}\n"
            "a = sys.argv[1:]\n"
            "if a[:2] == ['iam', 'list-roles']:\n"
            "    print(json.dumps({'Roles': [{'RoleName': r} for r in roles]}))\n"
            "elif a[:2] == ['iam', 'list-role-tags']:\n"
            "    t = roles[a[a.index('--role-name') + 1]]\n"
            "    print(json.dumps({'Tags': [{'Key': k, 'Value': v} for k, v in t.items()]}))\n"
            "elif a[:2] == ['iam', 'get-role']:\n"
            "    name = a[a.index('--role-name') + 1]\n"
            "    if name == 'agent-live':\n        print('{}')\n"
            "    else:\n        sys.stderr.write('An error occurred (NoSuchEntity)')\n        sys.exit(254)\n"
            "else:\n    sys.exit(3)\n"
        )
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        p = mock.patch.dict(os.environ, {"AWS_CLI": str(script), "BALKANID_SKIP_DOTENV": "1"})
        p.start()
        self.addCleanup(p.stop)

    def test_expired_children_and_untagged(self):
        due = reap_expired.expired(reap_expired.agent_roles(), dt.datetime(2026, 10, 22, tzinfo=dt.timezone.utc))
        names = [d["agent"] for d in due]
        self.assertEqual(set(names), {"old", "child", "grandchild", "untagged"})
        self.assertLess(names.index("grandchild"), names.index("child"))  # deepest first
        self.assertLess(names.index("child"), names.index("old"))
        self.assertEqual({d["agent"]: d["reason"] for d in due}["untagged"], "missing expiry")

    def test_role_exists_distinguishes_gone_from_present(self):
        self.assertTrue(reap_expired.role_exists("agent-live"))
        self.assertFalse(reap_expired.role_exists("agent-old"))


if __name__ == "__main__":
    unittest.main()

"""End-to-end run of scripts/lifecycle.sh with a mock BalkanID API and fake terraform/aws binaries."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mock_balkanid import MockBalkanID  # noqa: E402

FAKE_TF = """#!/usr/bin/env python3
import json, os, sys
with open(os.environ["FAKE_LOG"], "a") as fh:
    fh.write(json.dumps(["terraform"] + sys.argv[1:]) + "\\n")
"""


@unittest.skipUnless(shutil.which("bash"), "bash required")
class LifecycleScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        tf = bin_dir / "terraform"
        tf.write_text(FAKE_TF)
        tf.chmod(tf.stat().st_mode | stat.S_IEXEC)
        self.log = self.tmp / "calls.jsonl"
        self.mock = MockBalkanID().__enter__()
        self.addCleanup(self.mock.__exit__, None, None, None)
        self.env = {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "FAKE_LOG": str(self.log),
            "BALKANID_SKIP_DOTENV": "1",
            "BALKANID_PUBLIC_API_URL": self.mock.url,
            "API_KEY_ID": "test-key",
            "API_KEY_SECRET": "s",
            "BALKANID_AGENT_OWNER_EMAIL": "owner@example.com",
            "INTEGRATION_ID": "int-aws",
            "AWS_ACCOUNT_ID": "123456789012",
            "AGENT_POLICY_NAMES": "AmazonBedrockLimitedAccess",
            "AGENT_POLICY_ARNS": "arn:aws:iam::aws:policy/AmazonBedrockLimitedAccess",
            "AGENT_TTL_HOURS": "4",
            "POLL_SECONDS": "1",
            "POLL_TIMEOUT_SECONDS": "5",
            "GQL_MAX_RETRIES": "1",
        }

    def run_sh(self, *args, **extra):
        env = {**self.env, **extra}
        return subprocess.run([str(ROOT / "scripts" / "lifecycle.sh"), *args], env=env,
                              capture_output=True, text=True, timeout=60)

    def tf_calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_apply_runs_checks_gates_terraform_sync_in_order(self):
        proc = self.run_sh("apply", "payments-helper")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        types = [c["requestType"] for c in self.mock.created]
        self.assertEqual(types, ["CREATE_SERVICE_ACCOUNT", "AGENT_ACCESS"])
        self.assertEqual(self.mock.created[0]["expirationDate"], self.mock.created[1]["expirationDate"])
        apply = [c for c in self.tf_calls() if "apply" in c][0]
        self.assertIn("-var=agent_name=payments-helper", apply)
        self.assertIn('-var=agent_policy_arns=["arn:aws:iam::aws:policy/AmazonBedrockLimitedAccess"]', apply)
        self.assertIn(f"-var=expires_at={self.mock.created[0]['expirationDate']}", apply)
        self.assertTrue(any("workspace" in c and "payments-helper" in c for c in self.tf_calls()))

    def test_apply_refuses_admin_policy_before_any_request(self):
        proc = self.run_sh("apply", "payments-helper", AGENT_POLICY_NAMES="AdministratorAccess")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.mock.created, [])
        self.assertEqual(self.tf_calls(), [])

    def test_apply_refuses_unreviewed_policy_arn(self):
        proc = self.run_sh("apply", "payments-helper",
                           AGENT_POLICY_ARNS="arn:aws:iam::aws:policy/AdministratorAccess")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.mock.created, [])
        self.assertEqual(self.tf_calls(), [])

    def test_denied_agent_never_reaches_terraform(self):
        self.mock.next_status = "denied"
        proc = self.run_sh("apply", "payments-helper")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.tf_calls(), [])

    def test_destroy(self):
        proc = self.run_sh("destroy", "payments-helper")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(any("destroy" in c for c in self.tf_calls()))


if __name__ == "__main__":
    unittest.main()

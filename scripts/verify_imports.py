#!/usr/bin/env python3
"""Import every script module to catch broken cross-module imports (py_compile misses these)."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

MODULES = (
    "balkanid_api",
    "policy_check",
    "service_account_gate",
    "gate",
    "request_sensitive_access",
    "reap_expired",
    "trigger_sync",
    "preflight",
)


def main() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    for name in MODULES:
        importlib.import_module(name)
    print(f"imported {len(MODULES)} modules ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

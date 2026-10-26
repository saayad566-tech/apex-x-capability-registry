#!/usr/bin/env python3
"""Fail the run when any capability is in the `failed` state.

Used by CI after a live re-verification: a demotion must turn the pipeline red
so it cannot be missed, and must never be silently re-labelled as verified.

Usage
  python3 scripts/check_failed.py [--registry capability-registry.json]
"""
from __future__ import annotations

import argparse
import json
import sys


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Fail when a capability is in `failed`")
    p.add_argument("--registry", default="capability-registry.json")
    args = p.parse_args(argv)

    try:
        with open(args.registry, "r", encoding="utf-8") as fh:
            registry = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read registry: {exc}", file=sys.stderr)
        return 2

    failed = sorted(name for name, entry in registry.get("capabilities", {}).items()
                    if entry.get("status") == "failed")
    if failed:
        print("failed capabilities: " + ", ".join(failed))
        for name in failed:
            reason = registry["capabilities"][name].get("failure_reason", "")
            print(f"  - {name}: {reason}")
        return 1
    print("no capability is in the failed state")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Dependency and licence inventory - with its own coverage limits stated.

This never claims "zero vulnerabilities". It reports what it could actually
see: the manifests in the repository, the distributions installed in the
current interpreter, the licence each one declares, and whether an advisory
feed was reachable at all. If no feed answered, the honest conclusion is
"coverage unknown", not "clean".

Usage
  python3 scripts/deps_inventory.py                      # JSON to stdout
  python3 scripts/deps_inventory.py --markdown out.md    # markdown report
"""
from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import os
import re
import sys
import urllib.error
import urllib.request

MANIFEST_NAMES = (
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "pyproject.toml", "setup.cfg", "setup.py", "Pipfile",
    "package.json", "go.mod", "Cargo.toml", "Gemfile",
)
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".progress",
             "build", "dist", ".mypy_cache", ".pytest_cache"}
ADVISORY_ENDPOINTS = (
    ("osv.dev", "https://api.osv.dev/v1/query"),
    ("pypi.org", "https://pypi.org/pypi/pip/json"),
)


def find_manifests(root: str) -> list[str]:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name in MANIFEST_NAMES or (name.startswith("requirements")
                                           and name.endswith(".txt")):
                found.append(os.path.relpath(os.path.join(dirpath, name), root))
    return sorted(found)


def parse_requirements(path: str) -> list[dict]:
    deps = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("-r", "-e", "--", "http:", "https:", "git+")):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*([<>=!~].*)?$", line)
            if m:
                deps.append({"name": m.group(1), "spec": (m.group(2) or "").strip()})
    return deps


def parse_pyproject(path: str) -> list[dict]:
    try:
        import tomllib
    except ModuleNotFoundError:
        return []
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError):
        return []
    out = []
    for spec in (data.get("project", {}).get("dependencies") or []):
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*([<>=!~].*)?$", str(spec))
        if m:
            out.append({"name": m.group(1), "spec": (m.group(2) or "").strip()})
    return out


def installed_distributions() -> list[dict]:
    rows = []
    for dist in md.distributions():
        try:
            name = dist.metadata["Name"]
            version = dist.version
        except (KeyError, TypeError):
            continue
        if not name:
            continue
        license_field = ""
        try:
            license_field = (dist.metadata.get("License-Expression")
                             or dist.metadata.get("License") or "")
        except TypeError:
            license_field = ""
        license_field = (license_field or "").strip()
        if not license_field or len(license_field) > 120:
            classifiers = dist.metadata.get_all("Classifier") or []
            for c in classifiers:
                if c.startswith("License ::"):
                    license_field = c.split("::")[-1].strip()
                    break
        requires = []
        try:
            requires = [r.split(";")[0].strip() for r in (dist.requires or [])]
        except Exception:  # noqa: BLE001 - metadata can be malformed
            requires = []
        rows.append({"name": name, "version": version,
                     "license": license_field or "UNDECLARED",
                     "requires": requires})
    return sorted(rows, key=lambda r: r["name"].lower())


def advisory_feed_status(timeout: float = 6.0) -> list[dict]:
    """Probe each advisory endpoint. A probe is not an audit - it is reachability."""
    results = []
    for label, url in ADVISORY_ENDPOINTS:
        status = {"feed": label, "url": url, "reachable": False, "detail": ""}
        try:
            req = urllib.request.Request(url, method="GET",
                                         headers={"User-Agent": "apex-x-deps-inventory"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status["reachable"] = 200 <= resp.status < 400
                status["detail"] = f"HTTP {resp.status}"
        except urllib.error.HTTPError as exc:
            status["detail"] = f"HTTP {exc.code}"
            status["reachable"] = exc.code < 500
        except Exception as exc:  # noqa: BLE001 - offline, DNS, TLS, timeout
            status["detail"] = f"{type(exc).__name__}: {exc}"
        results.append(status)
    return results


def build_inventory(root: str = ".", probe_feeds: bool = True) -> dict:
    manifests = find_manifests(root)
    direct: list[dict] = []
    for rel in manifests:
        path = os.path.join(root, rel)
        if rel.endswith(".txt") and "requirement" in os.path.basename(rel):
            direct.extend([{**d, "manifest": rel} for d in parse_requirements(path)])
        elif rel.endswith("pyproject.toml"):
            direct.extend([{**d, "manifest": rel} for d in parse_pyproject(path)])

    dists = installed_distributions()
    feeds = advisory_feed_status() if probe_feeds else []
    feeds_ok = any(f["reachable"] for f in feeds)

    limitations: list[str] = []
    if not manifests:
        limitations.append(
            "No dependency manifest exists in this repository, so there is no "
            "declared dependency surface to audit.")
    if not direct:
        limitations.append(
            "No third-party runtime dependencies are declared: every script here "
            "uses the Python standard library only.")
    if probe_feeds and not feeds_ok:
        limitations.append(
            "No advisory feed was reachable from this environment. Absence of "
            "reported vulnerabilities here means COVERAGE UNKNOWN, not zero "
            "vulnerabilities.")
    if not probe_feeds:
        limitations.append("Advisory feed probing was disabled for this run; "
                           "vulnerability coverage is unknown.")
    limitations.append(
        "Installed distributions are those of the *running interpreter*, not a "
        "declared lockfile; a different environment can differ.")
    limitations.append(
        "Licence strings come from package metadata and can be absent or "
        "imprecise; a licence obligation is not cleared by this report.")

    return {
        "root": os.path.abspath(root),
        "manifests": manifests,
        "direct_dependencies": direct,
        "installed_distributions": len(dists),
        "installed": dists,
        "licences": {d["name"]: d["license"] for d in dists},
        "advisory_feeds": feeds,
        "vulnerability_coverage": "unknown" if not feeds_ok else "feed-reachable (audit not run by this script)",
        "limitations": limitations,
    }


def to_markdown(inv: dict) -> str:
    lines = ["# Dependency and licence inventory", ""]
    lines.append(f"- Repository root: `{inv['root']}`")
    lines.append(f"- Manifests found: {len(inv['manifests'])}"
                 + (": " + ", ".join(f"`{m}`" for m in inv["manifests"])
                    if inv["manifests"] else ""))
    lines.append(f"- Declared direct dependencies: {len(inv['direct_dependencies'])}")
    lines.append(f"- Distributions installed in this interpreter: "
                 f"{inv['installed_distributions']}")
    lines.append(f"- Vulnerability coverage: **{inv['vulnerability_coverage']}**")
    lines += ["", "## Advisory feeds", ""]
    if not inv["advisory_feeds"]:
        lines.append("Probing disabled for this run.")
    for f in inv["advisory_feeds"]:
        state = "reachable" if f["reachable"] else "UNREACHABLE"
        lines.append(f"- {f['feed']}: {state} ({f['detail']})")
    lines += ["", "## Declared dependencies", ""]
    if inv["direct_dependencies"]:
        lines.append("| name | spec | manifest |")
        lines.append("|---|---|---|")
        for d in inv["direct_dependencies"]:
            lines.append(f"| {d['name']} | `{d['spec'] or '-'}` | {d['manifest']} |")
    else:
        lines.append("None declared.")
    undeclared = [d for d in inv["installed"] if d["license"] == "UNDECLARED"]
    lines += ["", "## Licence coverage", "",
              f"- Distributions with a declared licence: "
              f"{inv['installed_distributions'] - len(undeclared)}",
              f"- Distributions with NO declared licence: {len(undeclared)}"]
    if undeclared:
        lines.append("- Unresolved: " + ", ".join(d["name"] for d in undeclared[:40]))
    lines += ["", "## Limitations (read these before trusting the numbers)", ""]
    lines += [f"- {l}" for l in inv["limitations"]]
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Dependency and licence inventory")
    p.add_argument("--root", default=".")
    p.add_argument("--no-probe", action="store_true",
                   help="skip advisory-feed reachability probes")
    p.add_argument("--markdown", default="", help="also write a markdown report here")
    p.add_argument("--json", action="store_true", help="print JSON to stdout")
    args = p.parse_args(argv)

    inv = build_inventory(args.root, probe_feeds=not args.no_probe)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(inv))
    if args.json or not args.markdown:
        print(json.dumps(inv, indent=2, sort_keys=True))
    else:
        print(f"wrote {args.markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

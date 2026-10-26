#!/usr/bin/env bash
# Seed capabilities through the documented lifecycle. Every step is the real CLI.
set -euo pipefail
R="--registry capability-registry.json"
S="scripts/capability_registry.py"   # run from the repo root
REPO="https://github.com/saayad566-tech/apex-x-capability-registry"
APPROVER="akshya"
REF="Instruction 2026-10-26: proceed with upgrades A (durable registry), B (supply chain), C (verification freshness)"
PY=python3

seed () {
  local name="$1" artifact="$2" purpose="$3" rollback="$4" deps="$5" testjson="$6" license="$7" source="$8" trusted="${9:-}"
  local sha; sha=$(sha256sum "$artifact" | cut -d' ' -f1)
  echo "== $name (sha256 ${sha:0:12}...) =="
  $PY "$S" $R add --name "$name" --kind tool --purpose "$purpose" \
     --artifact "$artifact" --sha256 "$sha" --license "$license" \
     --source "$source" --risk low ${deps:+--dependencies "$deps"} $trusted >/dev/null
  $PY "$S" $R transition --name "$name" --to assessed >/dev/null
  $PY "$S" $R transition --name "$name" --to approved \
     --approval-by "$APPROVER" --approval-ref "$REF" >/dev/null
  $PY "$S" $R transition --name "$name" --to installed --rollback "$rollback" >/dev/null
  $PY "$S" $R verify --name "$name" --command "$testjson" >/dev/null
  $PY "$S" $R show --name "$name" | $PY -c 'import json,sys; e=json.load(sys.stdin); print("   status:", e["status"], "| exit:", e["verify_result"]["exit_code"], "| sha256 matches artifact:", e["sha256"]==__import__("hashlib").sha256(open(e["artifact"],"rb").read()).hexdigest())'
}

seed capability-registry scripts/capability_registry.py \
  "Registry, audit chain and lifecycle guards for capability claims" \
  "rm scripts/capability_registry.py" "" \
  '["python3","-m","unittest","discover","-s","tests","-p","test_registry.py"]' \
  "internal" "$REPO#scripts/capability_registry.py"

seed preflight-gate scripts/preflight.py \
  "Fail-closed preflight: missing/tampered state exits 2, dishonest state exits 1" \
  "rm scripts/preflight.py" "capability-registry" \
  '["python3","-m","unittest","discover","-s","tests","-p","test_preflight.py"]' \
  "internal" "$REPO#scripts/preflight.py"

seed reverify-engine scripts/reverify.py \
  "Scheduled re-verification that demotes stale evidence through audited transitions" \
  "rm scripts/reverify.py" "capability-registry" \
  '["python3","-m","unittest","discover","-s","tests","-p","test_reverify.py"]' \
  "internal" "$REPO#scripts/reverify.py"

seed dependency-inventory scripts/deps_inventory.py \
  "Dependency, licence and advisory-coverage inventory with stated limitations" \
  "rm scripts/deps_inventory.py" "capability-registry" \
  '["python3","scripts/deps_inventory.py","--no-probe","--json"]' \
  "internal" "$REPO#scripts/deps_inventory.py"

# pip-audit: the checksum is the digest PyPI publishes (trusted), not one we computed.
seed pip-audit vendor/pip_audit-2.10.1-py3-none-any.whl \
  "Vulnerability audit of installed distributions against OSV/PyPI advisory data" \
  "python3 -m pip uninstall -y pip-audit" "" \
  '["python3","-m","pip_audit","--local"]' \
  "Apache-2.0" "https://pypi.org/project/pip-audit/2.10.1/" "--sha256-trusted"

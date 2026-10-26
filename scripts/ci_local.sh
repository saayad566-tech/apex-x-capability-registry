#!/usr/bin/env bash
# Run the exact gates the CI workflow runs - locally, in this order.
#
# Why this exists: GitHub Actions could not start the jobs on this account
# (jobs are created and fail in ~2 seconds with no runner assigned, no steps
# executed and no logs produced - see the weekly report). Rather than call the
# pipeline "working" without a run, this script reproduces the same gates where
# they can actually execute, and exits non-zero on the first failure.
#
# Usage (from the repository root):
#   bash scripts/ci_local.sh
set -uo pipefail

fail=0
step () {
  local label="$1"; shift
  echo
  echo "=== $label ==="
  echo "\$ $*"
  if "$@"; then
    echo "--- ok"
  else
    local code=$?
    echo "--- FAILED (exit $code)"
    fail=1
  fi
}

step "unit tests (stdlib only)" python -m unittest discover -s tests -v
step "preflight (fail-closed)" python scripts/preflight.py --registry capability-registry.json --max-evidence-days 90
step "registry self-check" python scripts/capability_registry.py check --max-age-days 120
step "audit hash chain" python scripts/capability_registry.py verify-audit
step "re-verification (dry run)" python scripts/reverify.py --registry capability-registry.json --max-age-days 90 --dry-run
step "dependency and licence inventory" python scripts/deps_inventory.py --markdown deps-inventory.md
step "failed-state gate" python scripts/check_failed.py --registry capability-registry.json

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL GATES PASSED"
else
  echo "ONE OR MORE GATES FAILED"
fi
exit "$fail"

# APEX-X capability registry

A durable, tamper-evident record of what APEX-X can actually do — and the gates
that refuse to let it claim more than the evidence supports.

The problem this repository solves: the agent's sandbox is recycled between
sessions, so any capability claim that lived only in a session vanished. The
weekly review of 26 October 2026 found no registry at all. This repository is
the durable home: the registry, its hash-chained audit log, the tooling that
writes them, and the tests that prove the tooling refuses dishonest state.

## What is in here

| Path | Role |
|---|---|
| `capability-registry.json` | The registry: every capability, its lifecycle state, approval, rollback, evidence and checksums |
| `capability-registry.json.audit.jsonl` | Append-only, hash-chained audit log of every action |
| `scripts/capability_registry.py` | The v3 registry, audit log, integrity and lessons store |
| `scripts/preflight.py` | Fail-closed gate: is the state complete, untampered and honest? |
| `scripts/reverify.py` | Scheduled re-verification; demotes stale or failing evidence |
| `scripts/deps_inventory.py` | Dependency, licence and advisory coverage — with its limits stated |
| `scripts/weekly_report.py` | Composes the weekly report from live execution only |
| `scripts/check_failed.py` | CI gate: red build while any capability is `failed` |
| `scripts/ci_local.sh` | Runs every CI gate locally, in the same order, and exits non-zero on the first failure |
| `tests/` | 40 stdlib tests over the lifecycle, the gates and the audit chain |
| `vendor/` | The one pinned third-party artifact (`pip-audit` wheel), checksum-matched to PyPI |

Runtime dependencies: **none**. Everything uses the Python standard library, so
`requirements.txt` is deliberately empty of packages. The only third-party code
is the audit tool in `requirements-dev.txt`, pinned with its PyPI digest.

## Reproduce every result

Run from the repository root. Python 3.10+ (CI uses 3.12).

```bash
# 1. the test suite - no installs, no network
python -m unittest discover -s tests -v

# 2. the fail-closed preflight (0 clean, 1 dishonest state, 2 missing/tampered)
python scripts/preflight.py --registry capability-registry.json --max-evidence-days 90

# 3. registry self-check: obsolete / incompatible / missing rollback / stale
python scripts/capability_registry.py check --max-age-days 120

# 4. the audit chain
python scripts/capability_registry.py verify-audit

# 5. re-verification - dry run, then live
python scripts/reverify.py --registry capability-registry.json --max-age-days 90 --dry-run
python scripts/reverify.py --registry capability-registry.json --max-age-days 90

# 6. dependency, licence and advisory coverage
python scripts/deps_inventory.py --markdown deps-inventory.md

# 7. the weekly report, built from the commands above
python scripts/weekly_report.py --out weekly-report.md --max-evidence-days 90

# 8. CI gate
python scripts/check_failed.py --registry capability-registry.json
```

### Exit codes

`preflight.py` is deliberately split, because "the state is missing" and "the
state is lying" are different failures:

- **0** — clean.
- **1** — integrity problems: a `verified` claim without an executed test, an
  artifact whose checksum changed, stale evidence, a missing rollback, a stale
  approval, an unmet dependency, a status that is not the last audited
  transition.
- **2** — state missing or tampered with: registry absent, unparseable,
  structurally invalid, audit log absent, or the audit hash chain broken.
  Exit 2 outranks exit 1 — if the trail cannot be trusted, findings cannot be.

## The lifecycle, and what it refuses

```
discovered -> assessed -> approved -> installed -> verified
                                  \-> failed -> assessed (recovery)
verified -> failed          (scheduled re-verification demotes)
```

The registry refuses, by construction:

- `approved` without a recorded approver; a **protected** capability (external
  kind, or high/critical risk) also needs a `plan_hash`, and the approver must
  differ from the executing identity.
- `installed` without an approval, a non-empty **rollback**, a passing
  compatibility check, satisfied dependencies, and an artifact checksum that
  still matches the approved one.
- `verified` without evidence and a test command; and a declaration alone is
  caught by `check` and `preflight` as *"declaration only"*.
- `failed` without a `failure_reason`.

A capability earns `verified` only through `verify`, which **executes** the real
test as an argument list (no shell), records exit code, output and environment,
and marks `failed` on a non-zero exit.

## Current state (as committed)

| capability | kind | status | evidence |
|---|---|---|---|
| `capability-registry` | tool | verified | `test_registry.py` executed, exit 0 |
| `preflight-gate` | tool | verified | `test_preflight.py` executed, exit 0 |
| `reverify-engine` | tool | verified | `test_reverify.py` executed, exit 0 |
| `dependency-inventory` | tool | verified | `deps_inventory.py --json` executed, exit 0 |
| `pip-audit` | tool | verified | `pip_audit --local` executed, exit 0 |

Every entry carries the sha256 of its artifact; `preflight.py` recomputes those
digests from the working tree on every run, so a changed file breaks the gate
until it is re-approved. The `pip-audit` digest is the one **PyPI publishes** for
wheel `pip_audit-2.10.1-py3-none-any.whl`, matched against the downloaded wheel
(`sha256_trusted: true`); the others are digests of files in this repository.

## Coverage limitations (read before trusting any "clean" result)

- The repository has **no third-party runtime dependencies**, so the
  vulnerability surface audited here is the tooling, not an application.
- `pip-audit --local` audits the *running interpreter's* installed
  distributions against OSV/PyPI advisory data. A different environment can
  differ, and an unreachable advisory feed means **coverage unknown**, not zero
  vulnerabilities. `deps_inventory.py` records feed reachability explicitly and
  says so when it could not reach one.
- Licence strings come from package metadata; they can be missing or imprecise,
  and this report does not clear a licence obligation.
- The audit log is tamper-**evident**, not tamper-proof: hash chaining detects
  edits and deletions, but a privileged attacker who rewrote the entire log
  could recompute the chain. The defence is that the log is committed, so a
  rewritten history shows up as a changed commit.
- Nothing here is verified on hardware other than Linux x86_64 / Python 3.12.

## CI status — read this before assuming the pipeline is green

The workflow `.github/workflows/ci.yml` is committed and passes the CI linter
(invalid YAML, unpinned actions, missing permissions/concurrency/timeout,
incomplete echo-only steps, hardcoded secrets: none found).

**It has not been observed running successfully.** Both runs triggered on
2026-10-26 (run `40287140816`, attempt 1 and attempt 2) failed at job startup:
the jobs were created and reported `failure` after roughly two seconds, with
`runner_name` empty, **zero steps executed** and no logs produced. That is a
rejection before a runner was assigned, not a failing test — the gates
contained in the workflow never executed.

Because a pipeline must not be called working without a run, the same gates are
executed by `scripts/ci_local.sh` and were run here: all passed. The registry and
its audit chain were additionally restored from this repository into a fresh
directory and re-validated in a new process (40 tests OK, preflight exit 0,
audit chain intact). The remaining unknown is GitHub-side runner allocation on
this account; nothing in the repository can fix that, and it is reported rather
than papered over.

## Weekly cadence

`.github/workflows/ci.yml` is written to run the gates on every push and pull
request, and on a schedule (Mondays 04:00 UTC = 09:30 IST) to run **live**
re-verification, upload the registry plus the weekly report, and fail the run if
any capability was demoted — so a stale claim cannot sit green until someone
notices. Until GitHub allocates a runner for this account (see *CI status*
above), the equivalent weekly job is:

```bash
bash scripts/ci_local.sh
python scripts/reverify.py --registry capability-registry.json --max-age-days 90
python scripts/weekly_report.py --out weekly-report.md
```

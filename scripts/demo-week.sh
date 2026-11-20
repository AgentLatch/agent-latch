#!/usr/bin/env bash
# Demo of the ALR05 / ALR10 follow-ups, all local and synthetic (no network).
# Run from the repo root with the project installed:  bash scripts/demo-week.sh
# Set DEMO_PAUSE=1 to wait for Enter between steps (for a live walk-through).
set -euo pipefail

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; [ "${DEMO_PAUSE:-0}" = 1 ] && read -r _ || true; }
say() { printf '%s\n' "$*"; }

step "1. ALR05: an injected tool result is flagged (monitor only, never blocks)"
agent-latch-runtime demo --scenario poisoned-output --dir "$work/poison" >/dev/null 2>&1 || true
agent-latch --runtime-result "$work/poison/gate-results.csv" --plain --fail-on none 2>&1 | grep -E "ALR05|ALR04" | head -8 || true

step "2. ALR10: a secret crossing the tool boundary (values stay masked)"
agent-latch-runtime demo --scenario secret-leak --dir "$work/leak" >/dev/null 2>&1 || true
agent-latch --runtime-result "$work/leak/gate-results.csv" --plain --fail-on none 2>&1 | grep -E "ALR10" | head -6 || true
say "payloads.jsonl holds [REDACTED] and masked locations only:"
grep -c "REDACTED" "$work/leak/payloads.jsonl" | sed 's/^/  masked records: /'

step "3. One operator policy file mutes one ALR05 rule (the file is operator config)"
cat > "$work/policy.yaml" <<'YAML'
suppressions:
  ALR05-R03: reviewed with the weather vendor
YAML
rm -f "$work/poison"/{gate-results.csv,events.csv,normalized.jsonl}
agent-latch-runtime import-logs --dir "$work/poison" --once --quiet --policy "$work/policy.yaml"
python3 -I - "$work/poison/gate-results.csv" <<'PY'
import csv, json, sys
for row in csv.DictReader(open(sys.argv[1], newline="")):
    for f in json.loads(row["result_json"])["findings"]:
        if f.get("rule_id", "").startswith("ALR05-R0"):
            print(f"  {f['rule_id']}: is_finding={f['is_finding']} suppressed={f['suppressed']}")
PY

step "4. A mistyped policy key is reported instead of silently ignored"
printf 'allowed_secret_tool: []\n' > "$work/typo.yaml"
rm -f "$work/poison"/{gate-results.csv,events.csv,normalized.jsonl}
agent-latch-runtime import-logs --dir "$work/poison" --once --quiet --policy "$work/typo.yaml" 2>&1 | grep warning || true

step "5. Measured precision (small synthetic sets, same authors as the gates)"
python3 tests/test_alr05_eval.py | tail -3
python3 -I - <<'PY'
import sys
sys.path.insert(0, "tests")
import test_alr10_heldout as h
for side in ("request", "response"):
    recall, fp, missed, fps = h._rates(side)
    print(f"ALR10 {side}: recall {recall:.0%}, false positives {fp:.0%}; misses {len(missed)}, known false positives {len(fps)}")
PY

step "6. Tests and lint"
python -m pytest -q 2>&1 | tail -2
ruff check . | tail -1
say ""
say "A clean result is not a security guarantee; these gates are previews."

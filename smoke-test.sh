#!/usr/bin/env bash
#
# Squawk — end-to-end smoke test against real targets with known properties.
#
#   ./smoke-test.sh            # dogfood against Squawk's own repo (works anywhere)
#   ./smoke-test.sh --targets  # also clone and scan known-vulnerable targets
#
# Why this exists, separate from the unit tests. Unit tests check functions
# against fixtures the author wrote, and a fixture the author wrote is the
# author's idea of the format, which is exactly how checkov's real list-form
# output reported 477 findings as zero for a while, because every fixture used
# the single-dict form. This runs the whole app against real code and checks the
# result is what a security engineer would expect, which is the only test that
# catches "the fixture did not match reality".
#
# It skips gracefully: a scanner that is not installed is a skipped stage, not a
# failure, the same stance the tool itself takes. So it does something useful on
# a laptop with three scanners and everything on a full Kali box.
#
# Expectations are deliberately coarse ("checkov finds many on a repo built to
# trip checkov", not "checkov finds exactly 477"), because an exact count is
# hostage to every scanner's next release. The shape of the answer is stable;
# the number is not.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
EV="$(mktemp -d)"
WITH_TARGETS=0
PASS=0; FAIL=0
[ "${1:-}" = "--targets" ] && WITH_TARGETS=1

say()  { printf '%s\n' "$*"; }
check() { # description  actual-condition(0/1)
  if [ "$2" -eq 0 ]; then printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1))
  else printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); fi
}

run() { python3 "$HERE/squawk.py" "$@" --evidence "$EV" 2>&1; }
latest_run() { ls -dt "$EV"/*/ 2>/dev/null | head -1; }
findings_count() { # scanner
  python3 - "$1" "$(latest_run)" <<'PY'
import json,sys,os
scanner,d=sys.argv[1],sys.argv[2]
try:
    f=json.load(open(os.path.join(d,"findings.json")))
    print(sum(1 for x in f if x.get("scanner")==scanner))
except Exception: print(-1)
PY
}
manifest_field() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]+'/manifest.json')).get(sys.argv[2],''))" "$(latest_run)" "$1" 2>/dev/null; }

say "Squawk smoke test"
say "evidence: $EV"
say

# --- 1. Dogfood: Squawk scans its own repo. Always available. -----------------
say "1. Dogfood — Squawk on its own source (a real, mostly-clean Python tree)"
out="$(run --run preflight --repo "$HERE")"
rundir="$(latest_run)"
check "a run directory was written" "$([ -n "$rundir" ] && [ -d "$rundir" ]; echo $?)"
check "the manifest records a ledger" "$(python3 -c "import json,sys; m=json.load(open(sys.argv[1]+'/manifest.json')); sys.exit(0 if m.get('ledger') else 1)" "$rundir" 2>/dev/null; echo $?)"
check "findings carry stable identities (no ../ traversal, no absolute paths)" \
  "$(python3 -c "
import json,sys
f=json.load(open(sys.argv[1]+'/findings.json'))
bad=[x for x in f if '../' in x['identity'] or x['path'].startswith('/')]
sys.exit(1 if bad else 0)" "$rundir" 2>/dev/null; echo $?)"
check "every stage recorded a status (ok/skipped/error/gap)" \
  "$(python3 -c "
import json,sys
m=json.load(open(sys.argv[1]+'/manifest.json'))
ok=all(r.get('status') in ('ok','skipped','error','gap') for r in m['ledger'])
sys.exit(0 if ok else 1)" "$rundir" 2>/dev/null; echo $?)"

# --- 2. The empty-denominator gate fires on an empty tree ---------------------
say
say "2. Empty target — a scan of nothing must be a gap, not a clean zero"
empty="$(mktemp -d)"; mkdir -p "$empty/.git"
out="$(run --run preflight --repo "$empty")"
gate_fired=1
echo "$out" | grep -qE 'examined 0|gap|7600' && gate_fired=0
check "an empty tree produces a gap / 7600, not a silent pass" "$gate_fired"
rm -rf "$empty"

# --- 3. Known-vulnerable targets (opt-in; needs network) ----------------------
if [ "$WITH_TARGETS" -eq 1 ]; then
  say
  say "3. Known targets — output checked against documented expectation"
  tmp="$(mktemp -d)"
  if git clone --depth 1 -q https://github.com/bridgecrewio/terragoat.git "$tmp/terragoat" 2>/dev/null; then
    run --run compliance --repo "$tmp/terragoat" >/dev/null
    ck="$(findings_count checkov)"
    # TerraGoat is built by checkov's authors to be full of findings.
    check "checkov finds many on TerraGoat (got $ck, expect >100)" "$([ "$ck" -gt 100 ] 2>/dev/null; echo $?)"
  else
    say "  -- skipped TerraGoat (no network)"
  fi
  rm -rf "$tmp"
fi

say
say "$PASS passed, $FAIL failed"
rm -rf "$EV"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0

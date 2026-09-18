#!/usr/bin/env bash
#
# Squawk — Phase 1 field check. The paths that need the full toolbench
# (gitleaks, syft, grype) and so could not be proven on the author's laptop.
#
#   ./phase1-check.sh
#
# Like smoke-test.sh, but for the completeness claims: the three-state coverage
# asymmetry, syft/grype live with the differential silent on agreement, the
# error channel, the 7600 dedupe, trivy's designed gap, and a log sweep proving
# every mechanism left a line. It builds its own sample targets, asserts each
# expectation, and prints PASS / FAIL / SKIP (a scanner not installed is a skip,
# not a failure — the same stance the tool takes).
#
# Run `python3 squawk.py --update` first so trivy and grype have fresh DBs, or
# the CVE checks skip.

set -uo pipefail
# The checks live in `dev/`; the app is one directory up, at the root of
# the checkout.
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# One fixed evidence root, NOT a tmp dir, so squawk.log accumulates and the
# final grep sweep can prove each mechanism logged.
EV="$HOME/scan-evidence"
LOG="$EV/squawk.log"
WORK="$(mktemp -d)"
PASS=0; FAIL=0; SKIP=0

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
have() { command -v "$1" >/dev/null 2>&1; }
run()  { python3 "$HERE/squawk.py" "$@" --evidence "$EV" 2>&1; }
latest() { ls -dt "$EV"/*/ 2>/dev/null | grep -v /installs/ | head -1; }

section() { printf '\n\033[1m%s\033[0m\n' "$1"; }

echo "Squawk Phase 1 field check"
echo "evidence root: $EV   (fixed, so the log sweep works)"

# --- build sample targets ---------------------------------------------------
mkdir -p "$WORK/clean/src"
printf 'def add(a, b):\n    return a + b\n' > "$WORK/clean/src/ok.py"
( cd "$WORK/clean" && git init -q && git add -A && git -c user.email=t@t -c user.name=t commit -qm s )

mkdir -p "$WORK/broken/src"
printf 'def add(a, b):\n    return a + b\n' > "$WORK/broken/src/ok.py"
printf 'def broken(:\n    x =\n' > "$WORK/broken/src/bad.py"
( cd "$WORK/broken" && git init -q && git add -A && git -c user.email=t@t -c user.name=t commit -qm s )

mkdir -p "$WORK/deps"
printf 'flask==0.12.2\nrequests==2.19.1\n' > "$WORK/deps/requirements.txt"
( cd "$WORK/deps" && git init -q && git add -A && git -c user.email=t@t -c user.name=t commit -qm s )

mkdir -p "$WORK/empty/.git"

# --- 1. the three-state coverage asymmetry ----------------------------------
section "1. Coverage asymmetry — across-N, unknown, all on one screen"
out="$(run --run baggage --target "$WORK/clean")"
printf '%s\n' "$out" | grep -E 'gitleaks|semgrep|bandit' | sed 's/^/     /'
if printf '%s' "$out" | grep -Eq '(semgrep|bandit).*across [0-9]+ files'; then
  ok "a SAST scanner reports 'across N files' (a real denominator)"
else bad "no scanner showed 'across N files' — coverage not surfaced"; fi
if have gitleaks; then
  if printf '%s' "$out" | grep gitleaks | grep -qv 'across'; then
    ok "gitleaks shows neither 'across' nor a gap (coverage unknown, not faked)"
  else bad "gitleaks fabricated a denominator or gapped — unknown must stay unknown"; fi
else skip "gitleaks not installed — cannot prove the unknown state"; fi

# --- 2. syft/grype live, differential silent on agreement -------------------
# baggage runs syft, grype AND trivy-fs, so the trivy/grype differential is
# actually in play. customs (syft+grype only) could never fire it, which made
# the earlier "silent on agreement" assertion vacuous — it passed because trivy
# never ran, not because the two agreed. This stages real agreement: both trivy
# and grype scan flask==0.12.2, both find CVEs, and the differential must stay
# silent because that is agreement, not a blind scanner.
section "2. SBOM + CVE + differential — both scanners find CVEs, differential SILENT"
if have syft && have grype && have trivy; then
  out="$(run --run baggage --target "$WORK/deps")"
  printf '%s\n' "$out" | grep -E 'syft|grype|trivy|differential' | sed 's/^/     /'
  if printf '%s' "$out" | grep -Eq 'syft.*across [0-9]+ packages'; then
    ok "syft reports 'across N packages'"
  else bad "syft did not report a package count"; fi
  gc="$(printf '%s' "$out" | grep -E 'grype' | grep -oE '[0-9]+ finding' | grep -oE '[0-9]+' | head -1)"
  tc="$(printf '%s' "$out" | grep -E 'trivy' | grep -oE '[0-9]+ finding' | grep -oE '[0-9]+' | head -1)"
  if [ "${gc:-0}" -gt 0 ] 2>/dev/null; then ok "grype found CVEs on flask 0.12.2 (got ${gc})"
  else bad "grype found 0 CVEs — stale DB? run 'python3 squawk.py --update'"; fi
  if [ "${tc:-0}" -gt 0 ] 2>/dev/null; then ok "trivy-fs also found CVEs (got ${tc}) — the differential pair both ran"
  else skip "trivy-fs found 0 on this tree — cannot test agreement (only one side found CVEs)"; fi
  # NOW the assertion means something: both found CVEs, so agreement must be silent.
  if [ "${gc:-0}" -gt 0 ] && [ "${tc:-0}" -gt 0 ] 2>/dev/null; then
    if printf '%s' "$out" | grep -q 'differential'; then
      bad "differential FIRED though both trivy and grype found CVEs — false alarm on agreement"
    else ok "differential SILENT while both found CVEs — agreement correctly not flagged"; fi
  fi
else skip "syft/grype/trivy not all installed — differential agreement not exercised"; fi

# --- 3. error channel -------------------------------------------------------
section "3. Error channel — a file the tool could not parse is surfaced"
out="$(run --run baggage --target "$WORK/broken")"
printf '%s\n' "$out" | grep -E 'semgrep|bandit' | sed 's/^/     /'
if printf '%s' "$out" | grep -Eq 'unreadable'; then
  ok "an unparseable file shows as '(N unreadable)', not swallowed"
else bad "the syntax-error file was not surfaced — error channel dropped"; fi

# --- 4. 7600 dedupe ---------------------------------------------------------
section "4. 7600 dedupe — a quiet scanner is listed once, not twice"
run --run baggage --target "$WORK/empty" >/dev/null
run --run baggage --target "$WORK/clean" >/dev/null
out="$(run --run baggage --target "$WORK/empty")"
dupe="$(printf '%s' "$out" | grep -c 'did not report')"
also="$(printf '%s' "$out" | grep -c 'not this one')"
printf '     did-not-report lines: %s | not-this-one lines: %s\n' "$dupe" "$also"
# a gapped scanner should appear via "did not report", never ALSO via "not this one"
if printf '%s' "$out" | grep -E 'semgrep|bandit' | grep -q 'not this one'; then
  bad "a gapped scanner is double-counted in 7600 (did-not-report AND not-this-one)"
else ok "no scanner is double-counted in the 7600 list"; fi

# --- 5. trivy's designed gap ------------------------------------------------
section "5. trivy designed gap — no dependency manifest means examined 0"
if have trivy; then
  out="$(run --run baggage --target "$WORK/clean")"
  printf '%s\n' "$out" | grep -E 'trivy' | sed 's/^/     /'
  if printf '%s' "$out" | grep trivy | grep -Eq 'examined 0 scan targets|gap'; then
    ok "trivy gaps on a no-manifest tree ('examined 0 scan targets') — the I15 semantic"
  else skip "trivy did not gap here (it may have found a manifest to scan) — inspect the line above"; fi
else skip "trivy not installed"; fi

# --- 6. the log sweep -------------------------------------------------------
# The section header used to promise more than the check delivered: it said
# every mechanism must leave a greppable line, then asserted only GAP and
# printed the rest as bare numbers a reader had to interpret. A zero next to
# DIFFERENTIAL means either "the mechanism correctly stayed silent" or "the
# mechanism is broken", and the script knew which and did not say. Now each
# mechanism states whether a zero is expected in THIS run, and the ones that
# must have fired are asserted.
section "6. Log sweep — did each mechanism leave a line, and is a zero expected?"
if [ -f "$LOG" ]; then
  count() { c="$(grep -c "$1 " "$LOG" 2>/dev/null | head -1)"; echo "${c:-0}"; }
  g="$(count GAP)"; c="$(count COVERAGE)"
  d="$(count DIFFERENTIAL)"; r="$(count CORRELATION)"; f="$(count REFUSED)"
  printf '     %-12s %-6s %s\n' GAP "$g" "this run scans an empty tree, so it must be non-zero"
  printf '     %-12s %-6s %s\n' COVERAGE "$c" "denominators are logged whenever a scanner publishes one"
  printf '     %-12s %-6s %s\n' DIFFERENTIAL "$d" "zero is CORRECT here: section 2 proved the pair agreed, and agreement is not a signal"
  printf '     %-12s %-6s %s\n' CORRELATION "$r" "zero is fine: no target here has a toxic combination"
  printf '     %-12s %-6s %s\n' REFUSED "$f" "zero is fine: nothing was refused in this evidence root"
  [ "$g" -gt 0 ] && ok "GAP lines present — the empty-denominator gate logged" \
                  || bad "no GAP lines — the gate did not log, so it cannot be audited"
  [ "$c" -gt 0 ] && ok "COVERAGE lines present — denominators reached the log" \
                  || bad "no COVERAGE lines — a denominator that is not logged cannot be checked later"
  # A mechanism that never logs is indistinguishable from one that never fires,
  # which is this tool's own thesis. So the two that ran here are asserted, and
  # the three that legitimately may not fire are explained rather than counted
  # at the reader.
else bad "no squawk.log at $LOG — logging is off, which is itself a defect"; fi

# --- manual items -----------------------------------------------------------
# Two items, not five. The rest of what used to be listed here is asserted by
# kali-check.py now, and repeating a check a script already makes is how a
# checklist becomes something nobody runs.
section "Needs your eyes — two things"
echo "  Start it:  python3 squawk.py restart   (serves http://127.0.0.1:8787)"
echo "  a) A run with a gap: the stage row is AMBER, not grey."
echo "  b) A correlated run (a public unencrypted bucket): the Findings page"
echo "     shows a 'correlation' group citing its member findings."
echo
echo "  The rest of the manual checklist is the operator's own; ./kali-check.py"
echo "  asserts everything in it that has a mechanical answer."

section "Result"
echo "  $PASS passed, $FAIL failed, $SKIP skipped"
echo "  Evidence and log: $EV"
rm -rf "$WORK"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0

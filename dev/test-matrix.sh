#!/usr/bin/env bash
#
# Squawk — run the installer and the host self-audit across Unix images.
#
#   ./test-matrix.sh                 # detection + self-audit on the default set
#   ./test-matrix.sh --full          # also run a real install (slow, pulls a lot)
#   ./test-matrix.sh --images "debian:stable-slim alpine:latest"
#
# Why this exists. The installer and the self-audit are the two parts of Squawk
# that talk to the operating system, and they were written against one: Kali.
# Everything else is Python that runs anywhere. Claiming portability without
# running it on anything else is a claim, not a control.
#
# Containers are not virtual machines and this does not pretend otherwise. They
# run as root by default, usually have no sudo, and have no systemd, which makes
# them an unusually hostile environment for an installer — three conditions that
# each broke the original script. What they cannot exercise is the systemd side:
# `clock-sync` and `journal-persistent` answer "not determined" here, and only a
# real VM makes them answer properly. That gap is stated rather than papered
# over.
#
# Needs Docker. Nothing is installed on the host running this.

set -uo pipefail

FULL=0
# archlinux is published for amd64 only, so it is not in the default set on an
# arm64 host. Pass it with --images to test it where the architecture matches.
IMAGES="debian:stable-slim ubuntu:24.04 fedora:latest alpine:latest opensuse/tumbleweed kalilinux/kali-rolling"
while [ $# -gt 0 ]; do
  case "$1" in
    --full)   FULL=1; shift ;;
    --images) IMAGES="$2"; shift 2 ;;
    *) echo "usage: $0 [--full] [--images \"img1 img2\"]"; exit 2 ;;
  esac
done

# The checks live in `dev/`; the app is one directory up, at the root of
# the checkout.
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; FAIL=0; SKIP=0
RESULTS=""

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running. Start it and try again."
  exit 2
fi

# python3 is not in every base image, and how you add it differs. Kept here
# rather than in install-tools.sh because installing an interpreter to run the
# installer is a test-harness concern, not the installer's job.
# Alpine ships neither python3 nor bash, so both are bootstrapped. bash is a
# real requirement of the installer rather than an accident of the harness, and
# squawk.py now says so plainly instead of failing inside Popen.
# The bootstrap output is kept, not discarded. A distribution that could not
# install python3 — stale repo metadata on a rolling image, a slow mirror — used
# to produce the same bare "no findings file produced" as a genuine break in the
# tool, and the reason was thrown away by the >/dev/null on the end of it.
python_bootstrap() {
  case "$1" in
    alpine*)      echo 'apk add --no-cache python3 bash 2>&1' ;;
    debian*|ubuntu*|kali*) echo 'apt-get update -qq 2>&1 && apt-get install -y -qq python3 2>&1' ;;
    fedora*)      echo 'dnf install -y -q python3 2>&1' ;;
    tumbleweed*|opensuse*|leap*) echo 'zypper --non-interactive refresh 2>&1 && zypper --non-interactive install python3 2>&1' ;;
    archlinux*)   echo 'pacman -Sy --noconfirm python 2>&1' ;;
    *)            echo 'true' ;;
  esac
}

# bash alone, for the detect probe, which runs before the python bootstrap.
bash_bootstrap() {
  case "$1" in
    alpine*)    echo 'apk add --no-cache bash >/dev/null 2>&1' ;;
    archlinux*) echo 'true' ;;
    *)          echo 'true' ;;
  esac
}

record() { # image  check  status  detail
  printf '%-26s %-12s %-6s %s\n' "$1" "$2" "$3" "$4"
  RESULTS="${RESULTS}$1|$2|$3|$4"$'\n'
  # Three states, not two. An image that will not download proves nothing about
  # portability either way, and counting it as a failure says the tool broke on
  # a distribution it was never run on. It is a skip, and the summary says so
  # loudly, because a skip is not a pass.
  case "$3" in
    ok)   PASS=$((PASS+1)) ;;
    skip) SKIP=$((SKIP+1)) ;;
    *)    FAIL=$((FAIL+1)) ;;
  esac
}

echo "Squawk portability matrix"
echo "images: $IMAGES"
echo "mode:   $([ "$FULL" = 1 ] && echo 'full install' || echo 'detect + self-audit')"
echo
printf '%-26s %-12s %-6s %s\n' IMAGE CHECK STATUS DETAIL
printf '%s\n' "----------------------------------------------------------------------------"

for img in $IMAGES; do
  short="${img##*/}"
  if ! pull_err="$(docker pull -q "$img" 2>&1)"; then
    record "$img" pull skip "not pulled, so nothing was proved: $(printf '%s' "$pull_err" | tail -1 | cut -c1-70)"
    continue
  fi
  boot="$(python_bootstrap "$short")"

  # 1. Does the installer recognise this system at all?
  bboot="$(bash_bootstrap "$short")"
  out="$(docker run --rm -v "$HERE":/w:ro -w /w "$img" \
        sh -c "$bboot; bash install-tools.sh --detect 2>&1" 2>&1)"
  pm="$(printf '%s' "$out" | awk '/^  packages/{print $2}')"
  priv="$(printf '%s' "$out" | awk '/^  privilege/{print $2" "$3}')"
  if [ -n "$pm" ] && [ "$pm" != none ]; then
    record "$img" detect ok "manager=$pm privilege=$priv"
  else
    record "$img" detect fail "no package manager recognised"
  fi

  # 2. Does the host self-audit run, and does it reach a verdict?
  # The titles live in findings.json, not on stdout — stdout prints a count.
  # Grepping the summary line for a finding title passed nothing and failed
  # everything, which is a harness that cannot tell working from broken.
  # Each finding is printed with a FINDING tag and only tagged lines are
  # counted. Counting every line of output meant that on an image without
  # python3 the shell's "command not found" was counted as one finding — a
  # tool that did not run reading as a tool that found something, which is the
  # failure this whole project exists to prevent, in its own test harness.
  read_titles='python3 -c "
import json,glob,sys
d=sorted(glob.glob(\"/tmp/ev/*-host\"))
if not d: sys.exit(1)
for x in json.load(open(d[-1]+\"/findings.json\")): print(\"FINDING\", x[\"severity\"], x[\"title\"])
"'
  # The run's own output is kept. It used to be sent to /dev/null, so a failure
  # here reported "no findings file produced" and destroyed the reason: a
  # harness that knew why and did not say, which is the defect this project is
  # about, in the harness that checks for it.
  out="$(docker run --rm -v "$HERE":/w:ro -w /tmp "$img" sh -c \
        "$boot; echo BOOT_RC=\$?; python3 /w/squawk.py --run selfaudit --evidence /tmp/ev 2>&1; echo RUN_RC=\$?; $read_titles" 2>&1)"
  count="$(printf '%s' "$out" | grep -c '^FINDING ')"
  boot_rc="$(printf '%s' "$out" | grep -o 'BOOT_RC=[0-9]*' | tail -1 | cut -d= -f2)"
  run_rc="$(printf '%s' "$out" | grep -o 'RUN_RC=[0-9]*' | tail -1 | cut -d= -f2)"
  if [ "$count" -gt 0 ]; then
    record "$img" selfaudit ok "$count finding(s)"
  elif [ "${boot_rc:-1}" != 0 ] || ! printf '%s' "$out" | grep -q 'RUN_RC='; then
    # python3 never arrived, so the tool was never run on this image. That is
    # an environment result, not a portability one.
    record "$img" selfaudit skip "python3 could not be installed: $(printf '%s' "$out" | grep -iv '^FINDING' | grep -iE 'error|fail|not found|no provider' | tail -1 | cut -c1-64)"
  else
    record "$img" selfaudit fail "ran but produced no findings (rc=${run_rc:-?}): $(printf '%s' "$out" | grep -iE 'error|traceback|no such' | tail -1 | cut -c1-64)"
  fi

  # 3. Does it catch a root run? Containers run as root by default, which is the
  #    one condition a developer laptop never reproduces.
  if printf '%s' "$out" | grep -qi 'running as root'; then
    record "$img" root-check ok "flagged running as root (high)"
  elif [ "$count" -eq 0 ]; then
    record "$img" root-check skip "the self-audit did not run here"
  else
    record "$img" root-check fail "did not flag root"
  fi

  if [ "$FULL" = 1 ]; then
    out="$(docker run --rm -v "$HERE":/w:ro -w /tmp "$img" sh -c \
          'cp -r /w /work && cd /work && bash install-tools.sh 2>&1; echo "RC=$?"' 2>&1)"
    rc="$(printf '%s' "$out" | grep -o 'RC=[0-9]*' | tail -1 | cut -d= -f2)"
    landed="$(printf '%s' "$out" | grep -c 'ok  ')"
    if [ "${rc:-1}" = 0 ]; then
      record "$img" install ok "$landed tool(s) reported ok"
    else
      record "$img" install partial "exit $rc, $landed ok — see detail"
    fi
  fi
done

echo
echo "$PASS passed, $FAIL failed, $SKIP skipped"
if [ "$SKIP" -gt 0 ]; then
  echo
  echo "A skip is not a pass. It means the image did not download or python3"
  echo "could not be installed on it, so this run proved nothing about that"
  echo "distribution either way. Re-run it when the network or the mirror is"
  echo "behaving, and treat the matrix as incomplete until it comes back clean."
fi
echo
echo "Not covered by containers: clock-sync and journal-persistent need systemd"
echo "and answer 'not determined' here. Those two need a real VM."
[ "$FAIL" -gt 0 ] && exit 1
exit 0

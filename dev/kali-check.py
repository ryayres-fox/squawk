#!/usr/bin/env python3
"""Squawk — the field check for everything that does not need your eyes.

This used to be a checklist a person worked through by hand: start the
server, mark a triage row, rescan, look for a date, disable a scanner, check
nothing reads as fixed. Each of those has an exact expected answer, so each of
them belongs here, and what is left for a person is only what a person can
judge: does it look right, does it read right, does it survive a reboot.

    ./kali-check.py            # about a minute; builds its own targets
    ./kali-check.py --keep     # leave the evidence root behind to poke at

Every line prints PASS, FAIL or SKIP with the value it actually saw, so a
failure is a report you can paste rather than a thing to reproduce. A scanner
that is not installed is a SKIP, never a FAIL: absence is a gap, not an error,
which is the same stance the tool takes. Exit 0 when nothing failed.

What it covers, and the manual step each one replaces:

  1  lifecycle          start, status, healthz, restart, stop, status again
  2  subcommands        every verb, the old flags, and a bare `run`
  3  aborted run        an unfinished run is recorded, not lost
  4  decisions          a mark survives the browser and shows on the next run
  5  remediation        a fix gets a date; putting it back is a regression
  6  silent scanner     a scanner that stops running resolves nothing
  7  refusals           a vanished target, and a cross-origin write
  8  scan page          each tile lists its targets; no built-in probe is missing
  9  overview           a vanished target is folded away and not counted
 10  feeds              with no feeds, the pages say so and never show a zero
 11  tamper evidence    a real run verifies; every way of editing it is named
 12  other servers      a server this check did not start is left running
 13  stop               the ZAP container this check started dies with the server; others do not
 14  profiles           printed before the run, in argv and the manifest; refused when unsafe
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

# The checks live in `dev/`; the app is one directory up, at the root of
# the checkout.
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRY = os.path.join(HERE, "squawk.py")
sys.path.insert(0, HERE)

PASS = FAIL = SKIP = 0
FAILURES = []


def ok(msg, detail=""):
    global PASS
    PASS += 1
    print("  \033[32mPASS\033[0m %s%s" % (msg, ("  ·  " + detail) if detail else ""))


def bad(msg, detail=""):
    global FAIL
    FAIL += 1
    FAILURES.append("%s%s" % (msg, ("  ·  " + detail) if detail else ""))
    print("  \033[31mFAIL\033[0m %s%s" % (msg, ("  ·  " + detail) if detail else ""))


def skip(msg, why):
    global SKIP
    SKIP += 1
    print("  \033[33mSKIP\033[0m %s  ·  %s" % (msg, why))


def check(msg, condition, detail=""):
    (ok if condition else bad)(msg, detail)
    return bool(condition)


def section(title):
    print("\n\033[1m%s\033[0m" % title)


def cli(*args, **kw):
    """Run the real entry point and return (rc, combined output)."""
    res = subprocess.run([sys.executable, ENTRY, *args],
                         capture_output=True, text=True,
                         timeout=kw.get("timeout", 600))
    return res.returncode, res.stdout + res.stderr


# The servers THIS check started, by pid. The clean-up used to `pkill -f
# "squawk.py serve"`, which killed every Squawk on the host — including the one
# you had just started yourself, with whatever scan it was running —
# and the "left behind" check counted that server as a leak and FAILED. A check
# that fails on the instruction it is paired with, then destroys the thing under
# test, is the defect this file exists to catch. Only what it started is its
# to stop.
STARTED_PIDS = set()


def _alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def start_daemon(ev, port):
    """`serve --daemon` on this evidence root and port; remember its pid."""
    rc, out = cli("serve", "--daemon", "--evidence", ev, "--port", str(port))
    health = wait_healthz("http://127.0.0.1:%d" % port) if rc == 0 else None
    if health and health.get("pid"):
        STARTED_PIDS.add(int(health["pid"]))
    return rc, out, health


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def get(base, path, timeout=30):
    try:
        with urllib.request.urlopen(base + path, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:
        return 0, str(exc)


def post(base, path, fields, origin=None, timeout=60):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        base + path, data=data,
        headers={"Origin": origin if origin is not None else base})

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        r = opener.open(req, timeout=timeout)
        return r.status, r.headers.get("Location", ""), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Location", ""), exc.read().decode("utf-8", "replace")
    except Exception as exc:
        return 0, "", str(exc)


def wait_healthz(base, tries=80):
    for _ in range(tries):
        code, body = get(base, "/healthz", timeout=2)
        if code == 200:
            try:
                return json.loads(body)
            except ValueError:
                return {}
        time.sleep(0.25)
    return None


def scan(ev, service, target, extra=()):
    """One headless run. The pause keeps run ids (second resolution) distinct
    so the checks below can tell them apart by name; the engine itself no
    longer needs it — a same-second run takes the next suffix."""
    rc, out = cli("run", service, "--target", target, "--evidence", ev, *extra)
    time.sleep(1.1)
    return rc, out


# --------------------------------------------------------------------------- #
# the targets this builds for itself
# --------------------------------------------------------------------------- #

# One file bandit flags deterministically (B602, shell=True). It is a target
# for a scanner, not a thing that runs, so nothing here executes.
RISKY = 'import subprocess\n\n\ndef go(cmd):\n    return subprocess.call(cmd, shell=True)\n'
CLEAN = 'def add(a, b):\n    return a + b\n'


def build_target(work, name, risky=True):
    d = os.path.join(work, name)
    os.makedirs(os.path.join(d, "src"), exist_ok=True)
    with open(os.path.join(d, "src", "ok.py"), "w") as fh:
        fh.write(CLEAN)
    if risky:
        with open(os.path.join(d, "src", "risky.py"), "w") as fh:
            fh.write(RISKY)
    elif os.path.exists(os.path.join(d, "src", "risky.py")):
        os.remove(os.path.join(d, "src", "risky.py"))
    return d


def bandit_findings(ev):
    import squawk
    runs = squawk.list_runs(ev)
    if not runs:
        return []
    return [f for f in squawk.load_findings(runs[0]["_dir"])
            if f.get("scanner") == "bandit"]


# --------------------------------------------------------------------------- #
# 1 · lifecycle
# --------------------------------------------------------------------------- #

def check_lifecycle(ev, port):
    section("1 · Lifecycle — start, status, health, restart, stop")
    base = "http://127.0.0.1:%d" % port
    rc, out = cli("status", "--evidence", ev)
    check("status with no server exits 1 and says so", rc == 1 and "not running" in out,
          "rc=%d" % rc)
    rc, out, health = start_daemon(ev, port)
    if not check("serve --daemon starts and prints the URL, pid and log",
                 rc == 0 and "URL" in out and "PID" in out, "rc=%d" % rc):
        return base, None
    check("/healthz answers with ok, version and a run count",
          bool(health) and health.get("ok") and health.get("version"),
          "version=%s runs=%s" % ((health or {}).get("version"), (health or {}).get("runs")))
    rc, out = cli("status", "--evidence", ev)
    check("status finds it running", rc == 0 and "running" in out.lower(), "rc=%d" % rc)
    first_pid = (health or {}).get("pid")
    rc, out = cli("restart", "--evidence", ev, "--port", str(port))
    health2 = wait_healthz(base)
    if health2 and health2.get("pid"):
        STARTED_PIDS.add(int(health2["pid"]))
    check("restart stops the old server and starts a new one with a new pid",
          rc == 0 and bool(health2) and health2.get("pid") != first_pid,
          "%s -> %s" % (first_pid, (health2 or {}).get("pid")))
    check("restart prints one Stopped line, not two",
          out.count("Stopped Squawk") == 1, "%d line(s)" % out.count("Stopped Squawk"))
    return base, health2


def check_stop(ev, base):
    section("Lifecycle — stop")
    rc, out = cli("stop", "--evidence", ev)
    check("stop reports the pid it stopped", rc == 0 and "Stopped" in out, "rc=%d" % rc)
    time.sleep(1)
    code, _b = get(base, "/healthz", timeout=2)
    check("the port is closed afterwards", code == 0, "healthz -> %s" % code)
    rc, _out = cli("status", "--evidence", ev)
    check("status exits 1 again once it is stopped", rc == 1, "rc=%d" % rc)
    left = sorted(p for p in STARTED_PIDS if _alive(p))
    check("no server this check started is left behind", not left,
          " ".join(str(p) for p in left) or "none of %d" % len(STARTED_PIDS))


# --------------------------------------------------------------------------- #
# 2 · subcommands
# --------------------------------------------------------------------------- #

def check_subcommands(work):
    section("2 · Subcommands — every verb, the old flags, and a bare run")
    ev = tempfile.mkdtemp(dir=work, prefix="sub-")
    rc, out = cli("version")
    ver = out.strip()
    check("version prints one version line", rc == 0 and ver.startswith("squawk "), ver)
    rc, out2 = cli("--version")
    check("the old --version flag still works and agrees", rc == 0 and out2.strip() == ver,
          out2.strip())
    res = subprocess.run([sys.executable, "-m", "squawk", "--version"],
                         capture_output=True, text=True, cwd=HERE, timeout=120)
    check("python3 -m squawk --version agrees",
          res.returncode == 0 and (res.stdout + res.stderr).strip() == ver,
          (res.stdout + res.stderr).strip())
    rc, out = cli("services")
    check("services lists the kiosk services", rc == 0 and "preflight" in out, "rc=%d" % rc)
    rc, out = cli("--list-services")
    check("the old --list-services flag still works", rc == 0 and "preflight" in out,
          "rc=%d" % rc)
    rc, out = cli("doctor", "--evidence", ev)
    check("doctor exits 0 with no traceback",
          rc == 0 and "Traceback" not in out, "rc=%d" % rc)
    rc, out = cli("run", "nosuch", "--evidence", ev)
    check("an unknown service exits 2 and lists the real ones",
          rc == 2 and "Unknown service" in out, "rc=%d" % rc)
    ev2 = tempfile.mkdtemp(dir=work, prefix="bare-")
    rc, out = cli("run", "--evidence", ev2, timeout=60)
    served = "is up" in out
    check("a bare run exits 2 with a usage line and does not start the server",
          rc == 2 and "needs a service" in out and not served,
          "rc=%d served=%s" % (rc, served))
    dirs = [n for n in os.listdir(ev2) if os.path.isdir(os.path.join(ev2, n))]
    check("a bare run writes no run directory", dirs == [], str(dirs))


# --------------------------------------------------------------------------- #
# 3 · an unfinished run is recorded, not lost
# --------------------------------------------------------------------------- #

def check_aborted(work, port):
    section("3 · An interrupted run is recorded as aborted, never lost")
    import squawk
    ev = tempfile.mkdtemp(dir=work, prefix="abort-")
    rid = "20260101T000000Z-dir"
    d = os.path.join(ev, rid)
    os.makedirs(os.path.join(d, "raw"))
    started = os.path.join(d, "started.json")
    with open(started, "w") as fh:
        json.dump({"run_id": rid, "service": "baggage", "service_label": "Baggage check",
                   "scope": "dir", "target": work, "started_at": "20260101T000000Z"}, fh)
    old = time.time() - (squawk.ABORT_SWEEP_AGE + 600)
    os.utime(started, (old, old))
    start_daemon(ev, port)
    base = "http://127.0.0.1:%d" % port
    wait_healthz(base)
    # --daemon forks, so the note lands in the server's own log, not in the
    # parent's stdout. Read it where it actually goes.
    log = os.path.join(ev, "squawk-serve.log")
    note = open(log, encoding="utf-8", errors="replace").read() if os.path.exists(log) else ""
    check("the server records an unfinished run as aborted on the way up",
          "never finished" in note and rid in note,
          (note.strip().splitlines() or ["log empty"])[-1][:90])
    runs = squawk.list_runs(ev)
    man = runs[0] if runs else {}
    check("the aborted run keeps its target, so it lands under the right one",
          man.get("aborted") is True and man.get("target") == work,
          "target=%s" % man.get("target"))
    code, html = get(base, "/findings?run=%s" % rid)
    check("its Findings page says it was aborted, never clean",
          code == 200 and "This run was aborted" in html
          and "clean result only because it looked" not in html, "HTTP %s" % code)
    code, html = get(base, "/")
    check("the Overview shows it as an aborted run with the gap marker",
          code == 200 and "aborted" in html.lower(), "HTTP %s" % code)
    cli("stop", "--evidence", ev)
    time.sleep(0.6)


# --------------------------------------------------------------------------- #
# 4-7 · decisions, remediation, silence, refusals — one target, five states
# --------------------------------------------------------------------------- #

def check_evidence_features(work, port):
    """One directory scanned four times: with the risky file, without it, with
    it again, and once with bandit hidden. That sequence is every claim the
    manual checklist used to ask for by hand."""
    import squawk
    section("4 · Decisions live in the evidence store, not a browser")
    if not shutil.which("bandit"):
        skip("decisions, remediation, silence and refusals", "bandit is not installed")
        return
    ev = tempfile.mkdtemp(dir=work, prefix="ev-")
    target = build_target(work, "app", risky=True)
    other = build_target(work, "other", risky=True)

    rc, _out = scan(ev, "baggage", target)
    finds = bandit_findings(ev)
    if not check("a scan of a file with shell=True produces a bandit finding",
                 rc == 0 and len(finds) >= 1, "rc=%d findings=%d" % (rc, len(finds))):
        return
    scan(ev, "baggage", other)
    ident = finds[0]["identity"]
    rule = ident.split(":")[0]

    base = "http://127.0.0.1:%d" % port
    start_daemon(ev, port)
    if not wait_healthz(base):
        bad("the server did not come up for the decision checks")
        return
    try:
        run1 = squawk.list_runs(ev)
        r_target = next(m["run_id"] for m in run1 if m.get("target") == target)
        r_other = next(m["run_id"] for m in run1 if m.get("target") == other)

        code, _loc, body = post(base, "/decide", {
            "run": r_target, "scanner": "bandit", "rule": rule, "status": "reviewed",
            "note": "field check", "ids": json.dumps([ident])})
        j = json.loads(body) if body.startswith("{") else {}
        check("marking a row records a decision and answers with the new state",
              code == 200 and j.get("ok") and j.get("state", {}).get("status") == "reviewed",
              "HTTP %s state=%s" % (code, j.get("state", {}).get("status")))
        who = j.get("event", {}).get("who", "")
        ledger = os.path.join(ev, "decisions", "ledger.jsonl")
        lines = open(ledger).read().strip().splitlines() if os.path.exists(ledger) else []
        check("the ledger holds one line, owner-only, with who and why",
              len(lines) == 1 and oct(os.stat(ledger).st_mode & 0o777) == "0o600"
              and "field check" in lines[0],
              "%d line(s) mode=%s who=%s" % (len(lines),
                                             oct(os.stat(ledger).st_mode & 0o777)
                                             if lines else "-", who))
        code, _l, body = post(base, "/decide", {
            "run": r_target, "scanner": "bandit", "rule": rule, "status": "reviewed",
            "ids": json.dumps(["bandit:nosuch.py:1"])})
        check("a decision on an identity the run never recorded is refused",
              code == 400 and "did not record" in body, "HTTP %s" % code)
        code, _l, body = post(base, "/decide", {
            "run": r_target, "scanner": "bandit", "rule": rule, "status": "reviewed",
            "ids": json.dumps([ident])}, origin="http://evil.example")
        check("a cross-origin decision is refused like a cross-origin run",
              code == 403, "HTTP %s" % code)

        code, html = get(base, "/triage?run=%s" % r_other)
        check("the decision does not leak to another target",
              code == 200 and "field check" not in html, "HTTP %s" % code)

        scan(ev, "baggage", target)                      # rescan, nothing changed
        newest = squawk.list_runs(ev)[0]["run_id"]
        code, html = get(base, "/triage?run=%s" % newest)
        check("the mark made on the earlier run shows on the next run of the target",
              code == 200 and "field check" in html, "HTTP %s" % code)
        code, html = get(base, "/findings?run=%s" % newest)
        check("Findings shows it on the group row with who marked it",
              code == 200 and "dchip dec" in html and "field check" in html,
              "HTTP %s" % code)

        section("5 · A fix gets a date; putting it back is a regression")
        build_target(work, "app", risky=False)          # the fix
        scan(ev, "baggage", target)
        newest = squawk.list_runs(ev)[0]["run_id"]
        code, html = get(base, "/findings?run=%s" % newest)
        check("the run that fixed everything lists what it fixed, with dates",
              code == 200 and "Resolved before this run" in html and ident in html,
              "HTTP %s" % code)
        check("and it does not read as a target that never had anything",
              "were resolved before it" in html,
              "plain clean page" if "clean result only because it looked" in html
              and "resolved before it" not in html else "names the fixes")

        build_target(work, "app", risky=True)           # put it back
        scan(ev, "baggage", target)
        newest = squawk.list_runs(ev)[0]["run_id"]
        code, html = get(base, "/findings?run=%s" % newest)
        check("its row reads regressed, with the date it was resolved and the date it came back",
              code == 200 and "regressed &middot; resolved" in html and "back " in html,
              "HTTP %s" % code)
        check("the summary line counts the regression, before any row",
              "regressed</span>" in html.split("<details")[0],
              "in summary" if "regressed</span>" in html.split("<details")[0] else "missing")
        code, html = get(base, "/history")
        check("History shows open, resolved and regressed for the target",
              code == 200 and "open</span>" in html and "resolved</span>" in html
              and "regressed</span>" in html, "HTTP %s" % code)

        section("6 · A scanner that stops running resolves nothing")
        shim = os.path.join(work, "noshim")
        os.makedirs(shim, exist_ok=True)
        with open(os.path.join(shim, "bandit"), "w") as fh:
            fh.write("#!/bin/sh\nexit 127\n")       # present but broken: a stage error
        env_path = os.environ.get("PATH", "")
        hidden = os.pathsep.join(
            p for p in env_path.split(os.pathsep)
            if not os.path.exists(os.path.join(p, "bandit")))
        res = subprocess.run(
            [sys.executable, ENTRY, "run", "baggage", "--target", target,
             "--evidence", ev],
            capture_output=True, text=True, timeout=600,
            env=dict(os.environ, PATH=hidden))
        time.sleep(1.1)
        check("a run with bandit off the PATH still completes", res.returncode == 0,
              "rc=%d" % res.returncode)
        newest = squawk.list_runs(ev)[0]
        tl = squawk.remediation_timeline(ev, newest)
        state = (tl.get(("bandit", ident)) or {}).get("status")
        check("the finding it can no longer see is NOT resolved",
              state != "resolved", "state=%s" % state)
        code, html = get(base, "/compare?run=%s" % newest["run_id"])
        check("Compare puts it under Silent scanners, never Remediated",
              code == 200 and "Silent scanners" in html
              and "bandit" in html.split("Silent scanners")[-1][:400],
              "HTTP %s" % code)
        # A scanner that is not installed is a GAP in the ledger, and the run
        # is incomplete everywhere that reads it. Before 2026-09-07 it was
        # "skipped", which every reader treated as neutral: a run with no
        # working scanner drew a blue "clean" pill on the Overview.
        row = next((r for r in newest.get("ledger", []) if r.get("tool") == "bandit"), {})
        check("the missing scanner is a gap in the ledger, not a skip",
              row.get("status") == "gap" and "not installed" in row.get("detail", ""),
              "%s — %s" % (row.get("status"), row.get("detail")))
        check("the run reads as incomplete", squawk._run_incomplete(newest),
              "incomplete=%s" % squawk._run_incomplete(newest))
        code, html = get(base, "/")
        check("the Overview flags a coverage gap for it, never clean",
              code == 200 and "with a coverage gap" in html, "HTTP %s" % code)

        section("7 · Refusals — a vanished target, and the scan page")
        gone = build_target(work, "gone", risky=True)
        scan(ev, "baggage", gone)
        shutil.rmtree(gone)
        before = len([n for n in os.listdir(ev) if os.path.isdir(os.path.join(ev, n))])
        code, _l, body = post(base, "/run", {"service": "baggage", "target": gone})
        after = len([n for n in os.listdir(ev) if os.path.isdir(os.path.join(ev, n))])
        check("rescanning a target that is gone is refused, and writes no run",
              code == 400 and "no longer exists" in body and after == before,
              "HTTP %s runs %d -> %d" % (code, before, after))

        section("8 · The scan page: each tile is the picker")
        code, html = get(base, "/scan")
        check("a directory tile offers a list, not an empty box",
              code == 200 and "<select name='target' data-scope='dir'" in html,
              "HTTP %s" % code)
        check("the target that vanished is offered as gone and cannot be chosen",
              "(gone)" in html and "disabled" in html)
        check("Other path is the last resort, not the default",
              "value='__other__'" in html)
        check("the self-audit tile asks for nothing and names this machine",
              "name='target' value='host'" in html and "this machine" in html
              and "class='fixed'" in html and socket.gethostname()[:12] in html)
        check("no probe built into Squawk is listed as missing",
              "missing: selfaudit" not in html and "missing: recon" not in html)

        section("9 · The Overview counts what is there and folds what is not")
        code, html = get(base, "/")
        check("the vanished target is under a fold, named, and not a live row",
              code == 200 and "vanished" in html.lower(), "HTTP %s" % code)

        section("10 · With no feeds fetched, nothing reads as zero")
        code, html = get(base, "/priority")
        check("Priority says the feeds are not fetched rather than showing a zero",
              code == 200 and ("not fetched" in html or "feeds" in html.lower()),
              "HTTP %s" % code)
        code, html = get(base, "/")
        check("the Overview's exploited tile says the same",
              "feeds not fetched" in html or "&mdash;" in html, "HTTP %s" % code)
    finally:
        cli("stop", "--evidence", ev)
        time.sleep(0.6)


# --------------------------------------------------------------------------- #
# 11 · the evidence proves it was not edited after the fact
# --------------------------------------------------------------------------- #

def check_tamper_evidence(work, port):
    section("11 · Tamper-evident evidence — a real run, then every way of editing it")
    ev = tempfile.mkdtemp(dir=work, prefix="verify-")
    target = build_target(work, "verify-target")
    scan(ev, "customs", target)
    runs = sorted(n for n in os.listdir(ev)
                  if os.path.isdir(os.path.join(ev, n)) and n[:2].isdigit())
    if not runs:
        skip("a run to verify", "the scan wrote no run directory")
        return
    run_dir = os.path.join(ev, runs[-1])

    rc, out = cli("verify", "--evidence", ev)
    check("a fresh evidence root verifies and exits 0",
          rc == 0 and "verified unaltered" in out, "rc=%d" % rc)
    check("the command says what the chain does not prove",
          "does not prove" in out, "no honesty line in the output")
    rec = os.path.join(ev, "verify.json")
    check("the result is recorded where the Overview reads it",
          os.path.exists(rec), rec)

    digest = json.load(open(os.path.join(run_dir, "digest.json")))
    on_disk = set()
    for cur, _dirs, files in os.walk(run_dir):
        for name in files:
            rel = os.path.relpath(os.path.join(cur, name), run_dir).replace(os.sep, "/")
            if rel != "digest.json":
                on_disk.add(rel)
    check("the digest covers every file in the run but itself",
          set(digest.get("files") or {}) == on_disk,
          "digest %d, on disk %d" % (len(digest.get("files") or {}), len(on_disk)))

    modes = set()
    for cur, _dirs, files in os.walk(run_dir):
        for name in files:
            modes.add(os.stat(os.path.join(cur, name)).st_mode & 0o777)
    check("a finished run is sealed read-only (0400)", modes == {0o400},
          " ".join(oct(m) for m in sorted(modes)))

    victim = os.path.join(run_dir, "findings.json")
    os.chmod(victim, 0o600)
    with open(victim, "a") as fh:
        fh.write(" ")
    rc, out = cli("verify", "--evidence", ev)
    check("one edited byte is named and exits 1",
          rc == 1 and "altered" in out and "findings.json" in out, "rc=%d" % rc)

    # Put it back, byte for byte, and it verifies again: the check is on the
    # content, not on a timestamp or a file that was merely touched.
    with open(victim) as fh:
        blob = fh.read()
    with open(victim, "w") as fh:
        fh.write(blob[:-1])
    rc, _out = cli("verify", "--evidence", ev)
    check("restoring the exact bytes verifies again", rc == 0, "rc=%d" % rc)

    raws = [n for n in os.listdir(os.path.join(run_dir, "raw"))]
    if raws:
        os.remove(os.path.join(run_dir, "raw", raws[0]))
        rc, out = cli("verify", "--evidence", ev)
        check("a deleted raw report is missing, not quietly ignored",
              rc == 1 and "missing" in out and raws[0] in out, "rc=%d" % rc)
    else:
        skip("a deleted raw report is reported", "this run wrote no raw output")

    ev2 = tempfile.mkdtemp(dir=work, prefix="ledger-")
    import squawk
    for i in range(3):
        squawk.record_decision(ev2, "r", "/t", "customs", "trivy", "R%d" % i,
                               "reviewed", ["trivy:R%d" % i], by="field-check")
    led = squawk.ledger_path(ev2)
    lines = open(led).read().splitlines()
    check("the decisions ledger chains, and says so",
          squawk.verify_ledger(ev2)["state"] == "ok", "3 decisions")
    edited = json.loads(lines[1])
    edited["status"] = "skipped"
    lines[1] = json.dumps(edited, sort_keys=True)
    open(led, "w").write("\n".join(lines) + "\n")
    out = squawk.verify_ledger(ev2)
    check("an edited decision is caught and the changed line is named",
          out["state"] == "broken" and "line 2 was changed" in out["detail"],
          out["detail"])

    # The second pass: every way the first version of verify could be fooled,
    # each reproduced on 2026-09-06 with exit 0 before it was closed.
    import shutil as _sh
    ev3 = tempfile.mkdtemp(dir=work, prefix="fool-")
    for _i in range(3):
        scan(ev3, "selfaudit", "host")
    runs3 = sorted(n for n in os.listdir(ev3) if os.path.isdir(os.path.join(ev3, n))
                   and n[:2].isdigit())
    if len(runs3) < 3:
        skip("the second-pass cases", "needed three runs, got %d" % len(runs3))
        return
    mid, newest = runs3[1], runs3[-1]
    rc, out = cli("verify", "--evidence", ev3)
    check("three runs verify clean and the first verify is recorded",
          rc == 0 and os.path.exists(os.path.join(ev3, "verify.json")), "rc=%d" % rc)

    man = os.path.join(ev3, mid, "manifest.json")
    os.chmod(man, 0o600)
    os.remove(man)
    rc, out = cli("verify", "--evidence", ev3)
    check("a run whose manifest was deleted is missing, not gone (was: exit 0, 2 runs)",
          rc == 1 and "missing" in out and mid in out and "manifest.json" in out,
          "rc=%d" % rc)
    _sh.rmtree(os.path.join(ev3, mid))
    rc, out = cli("verify", "--evidence", ev3)
    check("a run deleted outright is remembered from the previous verify",
          rc == 1 and "nothing records its removal" in out, "rc=%d" % rc)

    d = os.path.join(ev3, newest)
    for name in ("findings.json", "digest.json"):
        os.chmod(os.path.join(d, name), 0o600)
    with open(os.path.join(d, "findings.json")) as fh:
        blob = fh.read()
    with open(os.path.join(d, "findings.json"), "w") as fh:
        fh.write(blob + " ")
    dg = json.load(open(os.path.join(d, "digest.json")))
    dg["files"] = squawk.hash_run_files(d)
    with open(os.path.join(d, "digest.json"), "w") as fh:
        json.dump(dg, fh, indent=2, sort_keys=True)
    rc, out = cli("verify", "--evidence", ev3)
    check("the newest run edited and its digest rewritten to match is still caught",
          rc == 1 and "rewritten after the verify" in out, "rc=%d" % rc)

    ev4 = tempfile.mkdtemp(dir=work, prefix="prune-")
    for _i in range(2):
        scan(ev4, "selfaudit", "host")
    runs4 = sorted(n for n in os.listdir(ev4) if os.path.isdir(os.path.join(ev4, n))
                   and n[:2].isdigit())
    if len(runs4) == 2:
        d = os.path.join(ev4, runs4[0])
        os.chmod(os.path.join(d, "findings.json"), 0o600)
        os.remove(os.path.join(d, "findings.json"))
        with open(os.path.join(d, "pruned.json"), "w") as fh:
            json.dump({"schema": 1, "removed": ["findings.json"], "at": "x", "by": "x"}, fh)
        rc, out = cli("verify", "--evidence", ev4)
        check("a forged pruned.json hides nothing: the file is missing, not pruned",
              rc == 1 and "missing" in out and "findings.json" in out, "rc=%d" % rc)
    else:
        skip("a forged pruned.json hides nothing", "needed two runs, got %d" % len(runs4))


# --------------------------------------------------------------------------- #
# 13 · stop stops the scanner — the container, not only the client
# --------------------------------------------------------------------------- #

def _zap_containers():
    """Every running ZAP container Squawk names, by name."""
    out = subprocess.run(["docker", "ps", "--format", "{{.Names}}"],
                         capture_output=True, text=True).stdout.split()
    return {n for n in out if n.startswith("squawk-zap-")}


def check_stop_kills_the_scanner(work):
    section("13 · stop stops the scanner: the ZAP container, not only the docker client")
    import squawk
    code, _b = get("http://127.0.0.1:3000", "/", timeout=3)
    if code != 200:
        skip("a live probe is started and stopped",
             "nothing answers on 127.0.0.1:3000 — start Juice Shop to exercise this")
        return
    if subprocess.run(["docker", "info"], capture_output=True, timeout=60).returncode != 0:
        skip("a live probe is started and stopped", "docker is not answering")
        return
    ev = tempfile.mkdtemp(dir=work, prefix="stop-")
    port = free_port()
    rc, _out, health = start_daemon(ev, port)
    if not check("a server for the probe starts", rc == 0 and bool(health), "rc=%d" % rc):
        return
    base = "http://127.0.0.1:%d" % port
    code, _loc, _b = post(base, "/run", {"service": "liveprobe",
                                          "target": "http://127.0.0.1:3000"})
    check("a live probe is started through the server", code in (200, 303), "HTTP %s" % code)
    # Only the container THIS check started. Taking the first `squawk-zap-
    # baseline-*` on the host picked up the operator's own probe on 2026-09-07 and
    # then failed because stop had — correctly — left it alone: two red lines
    # from a working product. Section 12 holds this rule for servers; a
    # container is no different.
    before = _zap_containers()
    name = ""
    for _ in range(120):
        new = _zap_containers() - before
        if new:
            name = sorted(new)[0]
            break
        time.sleep(1)
    check("the ZAP container is up and carries Squawk's name", bool(name), name or "none in 120s")
    if before:
        print("       (%d ZAP container(s) already running, left alone: %s)"
              % (len(before), ", ".join(sorted(before))))
    rc, _stop_out = cli("stop", "--evidence", ev, timeout=120)
    check("stop returns 0 without giving up on the server", rc == 0, "rc=%d" % rc)
    gone = False
    left = before
    for _ in range(20):
        left = _zap_containers()
        if name not in left:
            gone = True
            break
        time.sleep(0.5)
    check("the container is gone within ten seconds of stop (was: still attacking)",
          gone, "still listed" if not gone else "gone")
    survived = before & left
    check("a ZAP container this check did not start is left running",
          survived == before,
          "%d of %d still up" % (len(survived), len(before)) if before
          else "none were running to leave alone")
    try:
        log = open(os.path.join(ev, "squawk-serve.log")).read()
    except OSError:
        log = ""
    check("the serve log says the container was killed, by name",
          ("killed container %s" % name) in log,
          " / ".join(log.strip().splitlines()[-2:]) if log else "no log")
    newest = squawk.list_runs(ev)
    check("the interrupted probe is recorded as aborted, never lost",
          bool(newest) and newest[0].get("aborted") is True,
          "aborted=%s" % (newest[0].get("aborted") if newest else "no run"))


def check_profiles(work):
    """A profile (squawk.toml) is printed before the run, reaches the command,
    is recorded in the manifest, and is refused — before any stage runs — when
    it carries a destructive option or a credential."""
    section("14 · A profile is printed, applied and refused")
    if not shutil.which("bandit"):
        skip("profiles", "bandit is not installed")
        return
    ev = tempfile.mkdtemp(dir=work, prefix="ev-")
    target = build_target(work, "prof", risky=True)
    toml = os.path.join(ev, "squawk.toml")
    good = ('# the field check\'s profile\n[services.baggage]\nstage_timeout = 123\n'
            '[scanners.bandit]\nextra_args = ["-ll"]\n')
    with open(toml, "w") as fh:
        fh.write(good)
    rc, out = scan(ev, "baggage", target)
    check("the run prints the profile it ran under, before it runs",
          rc == 0 and ("Profile : %s" % toml) in out and "differ from the built-in" in out,
          next((ln.strip() for ln in out.splitlines() if ln.startswith("Profile :")), out[-200:]))
    import squawk
    runs = squawk.list_runs(ev)
    man = runs[0] if runs else {}
    rows = {r["tool"]: r for r in man.get("ledger", [])}
    bandit = (rows.get("bandit") or {}).get("ran") or {}
    check("bandit's command carries the profile's extra_args, appended",
          (bandit.get("command") or [""])[-1] == "-ll" and bandit.get("extra_args") == ["-ll"],
          " ".join(bandit.get("command") or ["no command recorded"]))
    ran = [r["ran"] for r in rows.values() if r.get("ran")]
    check("every stage that ran did so under the profile's timeout, and says where from",
          ran and all(r["timeout"] == 123 and r["timeout_from"] == "[services.baggage]"
                      for r in ran),
          "%d stage(s): %s" % (len(ran), ", ".join("%s<-%s" % (r["timeout"], r["timeout_from"])
                                                    for r in ran)))
    prof = man.get("profile") or {}
    check("the manifest names the file, each changed value and its section",
          prof.get("path") == toml and prof.get("source") == "evidence root"
          and all(c["section"] == "[services.baggage]" and c["builtin"] != 123
                  for c in prof.get("changed", []))
          and prof.get("extra_args", {}).get("bandit") == ["-ll"],
          "%d changed, extra_args %s" % (len(prof.get("changed", [])), prof.get("extra_args")))
    check("the finding is still found with the option applied",
          len(bandit_findings(ev)) >= 1, "%d bandit finding(s)" % len(bandit_findings(ev)))
    n_runs = len(runs)
    with open(toml, "w") as fh:
        fh.write('[scanners.bandit]\nextra_args = ["--delete"]\n')
    rc, out = scan(ev, "baggage", target)
    check("a destructive option is refused before any stage runs, and no run is written",
          rc == 2 and "--delete" in out and "read-only" in out
          and len(squawk.list_runs(ev)) == n_runs,
          "rc=%d runs %d -> %d" % (rc, n_runs, len(squawk.list_runs(ev))))
    with open(toml, "w") as fh:
        fh.write('[scanners.bandit]\napi_token = "ghp_%s"\n' % ("q" * 30))
    rc, out = scan(ev, "baggage", target)
    check("a credential-shaped value is refused by key, and the value is never printed",
          rc == 2 and "api_token" in out and "ghp_" not in out and "rule 1" in out,
          "rc=%d" % rc)
    try:
        log = open(os.path.join(ev, "squawk.log")).read()
    except OSError:
        log = ""
    check("both refusals are in the log", log.count("REFUSED run: profile") >= 2,
          "%d refusal line(s)" % log.count("REFUSED run: profile"))
    with open(toml, "w") as fh:
        fh.write(good)
    rc, out = cli("config", "show", "baggage", target, "--evidence", ev)
    check("config show names where each value came from, without running",
          rc == 0 and "[services.baggage]" in out and "built-in" in out
          and "Nothing was run" in out and len(squawk.list_runs(ev)) == n_runs,
          "rc=%d runs %d" % (rc, len(squawk.list_runs(ev))))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", action="store_true",
                    help="leave the working directory behind")
    args = ap.parse_args(argv)

    print("Squawk field check · %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    _rc, ver = cli("version")
    print("version: %s · python %s" % (ver.strip(), sys.version.split()[0]))
    work = tempfile.mkdtemp(prefix="squawk-field-")
    port = free_port()
    ev = tempfile.mkdtemp(dir=work, prefix="life-")
    # A server this check did NOT start, standing in for the one you run. It
    # must be untouched when this is over: the earlier clean-up killed it.
    other_ev = tempfile.mkdtemp(dir=work, prefix="yours-")
    other_port = free_port()
    _rc, _out, other = start_daemon(other_ev, other_port)
    other_pid = int((other or {}).get("pid") or 0)
    STARTED_PIDS.discard(other_pid)          # ours to stop at the end, not to reap
    try:
        base, _health = check_lifecycle(ev, port)
        check_stop(ev, base)
        check_subcommands(work)
        check_aborted(work, port)
        check_evidence_features(work, port)
        check_tamper_evidence(work, port)
        check_profiles(work)
        check_stop_kills_the_scanner(work)
        section("12 · A server this check did not start is left alone")
        check("the other server is still up when this is over",
              other_pid and _alive(other_pid)
              and (wait_healthz("http://127.0.0.1:%d" % other_port, tries=4) or {}).get("ok"),
              "pid %s on port %d" % (other_pid or "?", other_port))
        rc, _out = cli("stop", "--evidence", other_ev)
        check("...and stops cleanly when asked", rc == 0, "rc=%d" % rc)
    finally:
        import signal
        for pid in sorted(STARTED_PIDS):
            if _alive(pid):
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
        if other_pid and _alive(other_pid):
            try:
                os.kill(other_pid, signal.SIGTERM)
            except OSError:
                pass
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("\nworking directory kept: %s" % work)

    section("Result")
    print("  %d passed, %d failed, %d skipped" % (PASS, FAIL, SKIP))
    if FAILURES:
        print("\n  Paste these back:")
        for f in FAILURES:
            print("   - %s" % f)
    print("""
Still yours, because a script cannot judge them:
  a) Light and dark on a populated Findings and Overview page. Text legible on
     both grounds, severity distinguishable by shape as well as colour.
  b) `python3 squawk.py install-service`, then the four commands it prints.
     `systemctl --user status squawk` is active; reboot; it is back.
  c) `python3 squawk-dashboard.py <newest run>` and open the page it names: the
     same palette and the same light and dark as the app.
  d) Does the Scan page read as one thing? Does the Overview answer "what is
     the state of my estate" in five seconds?""")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

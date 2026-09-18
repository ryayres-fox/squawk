#!/usr/bin/env python3
"""Prove the running server serves what the source says it routes.

Squawk's rule is that a control in source but not enforced on the running
system is not a control. The same applies to its own pages: a route added to
the handler and never fetched is a page nobody has seen fail. So this reads
the route table out of `squawk/web.py`, starts a real daemon on a free port
against a throwaway evidence root, fetches every route it found, and fails on
any non-200, any traceback in a body, any traceback in the server log, or a
server still listening after stop.

    python3 live-check.py            # against a fresh, empty evidence root
    python3 live-check.py --runs 2   # write N real self-audit runs first, so
                                     # the pages have findings and history

Exit 0 when every route answered and the server stopped. Exit 1 otherwise,
with the failures listed. It never leaves a process behind: the stop is in a
finally block and the last thing it does is check the port is closed.
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ENTRY = os.path.join(HERE, "squawk.py")
WEB = os.path.join(HERE, "squawk", "web.py")

# Routes that need a run id or a job id in the path are not fetched blind; the
# ones listed here are fetched with whatever the evidence root holds.
SKIP_PREFIXES = ("/job/",)


def routes_from_source():
    """Every GET path the handler dispatches on, read from the source rather
    than kept in a list here. A route added to the handler and not fetched by
    this script would otherwise be a page that is never checked.

    Only `_route` is scanned. `do_POST` dispatches on its own paths, and those
    correctly answer 404 to a GET, so reading the whole file listed them as
    routes and then failed them. The first version of this script did exactly
    that, which is the point of deriving the list rather than trusting one."""
    src = open(WEB, encoding="utf-8").read()
    start = src.index("def _route(self)")
    end = src.index("def _origin_ok(self)", start)
    found = []
    for m in re.finditer(r"path (?:==|in) (\([^)]*\)|\"[^\"]+\")", src[start:end]):
        for path in re.findall(r"\"(/[^\"]*)\"", m.group(1)):
            if path not in found and not path.startswith(SKIP_PREFIXES):
                found.append(path)
    if not found:
        raise SystemExit("live-check: no routes found in _route; the handler "
                         "was restructured and this scan needs updating")
    return found


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_up(base, tries=60):
    for _ in range(tries):
        try:
            with urllib.request.urlopen(base + "/healthz", timeout=2) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception:
            time.sleep(0.25)
    return None


def fetch(base, path):
    """(status, bytes, has_traceback) for one route; an HTTP error is a status
    like any other, because a 404 from /nosuchpage is the correct answer."""
    try:
        with urllib.request.urlopen(base + path, timeout=30) as r:
            body = r.read()
            return r.status, len(body), b"Traceback" in body
    except urllib.error.HTTPError as exc:
        body = exc.read()
        return exc.code, len(body), b"Traceback" in body
    except Exception as exc:                      # a refused socket, a timeout
        print("  %-14s ERROR %s" % (path, exc))
        return 0, 0, False


def find_browser():
    """A headless-capable Chrome or Chromium, or None."""
    import shutil
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
                 "chrome"):
        p = shutil.which(name)
        if p:
            return p
    mac = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    return mac if os.path.exists(mac) else None


def measure_widths(base, paths, widths=(1240, 1000, 800, 640)):
    """[(path, width, scrollWidth, clientWidth)] for every route at every
    width, or None when no browser is available. The page is saved and a
    script appended that writes the two numbers into the title; the browser
    renders the file and dumps the DOM, so the numbers come from a real layout
    engine, not from reading the CSS."""
    import re
    import tempfile
    import urllib.request
    browser = find_browser()
    if not browser:
        return None
    out = []
    probe = ("<script>%s</script>" % (
        'window.addEventListener("load",function(){var m=0;'
        'document.querySelectorAll(".card").forEach(function(c){'
        'm=Math.max(m,c.scrollWidth-c.clientWidth)});'
        'document.title="SW="+document.documentElement.scrollWidth+"/CW="'
        '+document.documentElement.clientWidth+"/CARD="+m});'))
    with tempfile.TemporaryDirectory(prefix="squawk-widths-") as d:
        for path in paths:
            try:
                with urllib.request.urlopen(base + path, timeout=30) as r:
                    html = r.read().decode("utf-8", "replace")
            except Exception as exc:
                # Said, not swallowed: a route that could not be fetched is a
                # route that was not measured, and the caller's count must
                # not read as if it had been.
                print("  %-14s widths not measured: %s" % (path, exc))
                continue
            f = os.path.join(d, "page.html")
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(html + probe)
            for w in widths:
                res = subprocess.run(
                    [browser, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                     "--window-size=%d,900" % w, "--virtual-time-budget=2000",
                     "--dump-dom", "file://" + f],
                    capture_output=True, text=True, timeout=120)
                m = re.search(r"SW=(\d+)/CW=(\d+)/CARD=(\d+)", res.stdout)
                if m:
                    out.append((path, w, int(m.group(1)), int(m.group(2)),
                                int(m.group(3))))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--runs", type=int, default=0,
                    help="write N real self-audit runs before serving")
    ap.add_argument("--port", type=int, default=0, help="default: a free port")
    args = ap.parse_args(argv)

    ev = tempfile.mkdtemp(prefix="squawk-live-")
    port = args.port or free_port()
    base = "http://127.0.0.1:%d" % port
    failures = []

    for i in range(args.runs):
        res = subprocess.run([sys.executable, ENTRY, "run", "selfaudit",
                              "--evidence", ev],
                             capture_output=True, text=True, timeout=600)
        both = res.stdout + res.stderr
        print("run %d/%d rc=%d tracebacks=%d" % (i + 1, args.runs,
                                                 res.returncode,
                                                 both.count("Traceback")))
        if res.returncode != 0 or "Traceback" in both:
            failures.append("self-audit run %d" % (i + 1))
        time.sleep(1.1)          # run ids are second-resolution

    started = subprocess.run([sys.executable, ENTRY, "serve", "--daemon",
                              "--evidence", ev, "--port", str(port)],
                             capture_output=True, text=True, timeout=120)
    if started.returncode != 0:
        print((started.stdout + started.stderr).strip()[:400])
        print("FAIL: the server did not start")
        return 1

    try:
        health = wait_up(base)
        if not health:
            failures.append("/healthz never answered")
        else:
            print("healthz ok · version %s · runs %s"
                  % (health.get("version"), health.get("runs")))
        paths = [*routes_from_source(), "/nosuchpage"]
        print("routes read from web.py: %d" % (len(paths) - 1))
        for path in paths:
            status, size, tb = fetch(base, path)
            want = 404 if path == "/nosuchpage" else 200
            ok = status == want and not tb
            print("  %-14s %s %7d bytes  traceback=%s  %s"
                  % (path, status, size, tb, "ok" if ok else "FAIL"))
            if not ok:
                failures.append("%s -> %s%s" % (path, status,
                                                " with a traceback" if tb else ""))
        # No page may scroll sideways: the Overview needed 1412px at any width
        # and the owner, at 170% zoom, scrolled left and right to read it. A
        # headless browser measures scrollWidth against clientWidth at four
        # widths; without one this prints that it was not measured, which is
        # not a pass.
        wide = measure_widths(base, [p for p in paths if p != "/nosuchpage"])
        if wide is None:
            print("widths: not measured (no headless Chrome or Chromium on this machine)")
        else:
            bad = [w for w in wide if w[2] > w[3]]
            # A card may scroll its own table at phone widths; at 1000px and
            # up that is a layout that did not shrink, which the Overview did
            # at the owner's zoom with two columns cut off at the edge.
            clipped = [w for w in wide if w[4] > 0 and w[1] >= 1000]
            narrow = [w for w in wide if w[4] > 0 and w[1] < 1000]
            print("widths: %d route(s) x 4 width(s); %s; %s"
                  % (len(paths) - 1,
                     "none scroll sideways" if not bad else
                     "%d scroll sideways" % len(bad),
                     "no card clips its content at 1000px or wider" if not clipped else
                     "%d card(s) clip at 1000px or wider" % len(clipped)))
            for path, w, sw, cw, _c in bad:
                print("  %-14s at %4dpx scrolls sideways by %dpx" % (path, w, sw - cw))
                failures.append("%s scrolls sideways at %dpx (%d > %d)" % (path, w, sw, cw))
            for path, w, _sw, _cw, c in clipped:
                print("  %-14s at %4dpx a card clips %dpx of its content" % (path, w, c))
                failures.append("%s: a card clips %dpx at %dpx" % (path, c, w))
            for path, w, _sw, _cw, c in narrow:
                print("  %-14s at %4dpx a card scrolls %dpx inside itself (allowed below 1000px)"
                      % (path, w, c))
    finally:
        stopped = subprocess.run([sys.executable, ENTRY, "stop",
                                  "--evidence", ev],
                                 capture_output=True, text=True, timeout=120)
        print("stop rc=%d · %s" % (stopped.returncode,
                                   (stopped.stdout + stopped.stderr).strip()[:80]))
        if stopped.returncode != 0:
            failures.append("stop rc=%d" % stopped.returncode)
        time.sleep(1)
        if wait_up(base, tries=2) is not None:
            failures.append("the server is still listening after stop")

    log_path = os.path.join(ev, "squawk-serve.log")
    if os.path.exists(log_path):
        log = open(log_path, encoding="utf-8", errors="replace").read()
        print("serve.log: %d bytes, %d traceback(s)" % (len(log), log.count("Traceback")))
        if "Traceback" in log:
            failures.append("the server log holds a traceback")

    if failures:
        print("\nFAIL (%d):" % len(failures))
        for f in failures:
            print("  " + f)
        return 1
    print("\nevery route answered and the server stopped · evidence %s" % ev)
    return 0


if __name__ == "__main__":
    sys.exit(main())

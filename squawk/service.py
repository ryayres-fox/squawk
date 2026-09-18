"""The server's lifecycle: serve, daemonize, status, stop, and the systemd unit."""

import argparse
import errno
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import ThreadingHTTPServer
from typing import Optional, Tuple

from squawk.core import (
    ABORT_SWEEP_AGE,
    DEFAULT_EVIDENCE,
    ENTRY_PATH,
    LOG,
    SERVE_LOG,
    STOP_REQUESTED,
    __version__,
    _report,
    env,
    evidence_writable,
    resolve_repo,
    run_cmd,
    terminate_children,
    tool_path,
)
from squawk.evidence import list_runs, record_aborted_run, record_aborted_runs
from squawk.runtime import (
    JOBS,
    _alive,
    _drain_jobs,
    _pid_path,
    read_pid_file,
    remove_pid_file,
    write_pid_file,
)
from squawk.web import make_handler


def _systemd_present() -> bool:
    return os.path.isdir("/run/systemd/system")


def unit_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".config", "systemd", "user",
                        "squawk.service")


def _service_state() -> Optional[str]:
    """What systemd thinks of the unit Squawk generated, or None when there is
    no unit or no systemd. Reported from the field: after a reboot, `status`
    said only "stale pid file" while an installed unit sat there not running.
    A tool that generates a service and then cannot see it is asking the
    operator to remember what the tool itself wrote."""
    if not os.path.exists(unit_path()) or not tool_path("systemctl"):
        return None
    parts = []
    for prop in ("ActiveState", "UnitFileState"):
        code, out, _err = run_cmd(
            ["systemctl", "--user", "show", "squawk.service",
             "--property=" + prop, "--value"], None, 10)
        parts.append(out.strip() if code == 0 else "unknown")
    return "%s, %s at boot" % (parts[0] or "unknown", parts[1] or "unknown")


def _service_note(prefix: str = "") -> str:
    state = _service_state()
    if state is None:
        return ""
    if state.startswith("active"):
        return "%sThe systemd user unit is %s." % (prefix, state)
    return ("%sA systemd user unit is installed and is %s.\n"
            "  Start it : systemctl --user start squawk\n"
            "  At boot  : systemctl --user enable squawk  ·  "
            "loginctl enable-linger %s"
            % (prefix, state, os.environ.get("USER", "$USER")))


def cmd_status(root: str) -> int:
    """Is a server up, and is it answering? 0 running, 1 not running, 2 the
    record is stale or the process is not answering."""
    rec = read_pid_file(root)
    if rec is None:
        print("Squawk is not running (no pid file at %s)." % _pid_path(root))
        note = _service_note("")
        if note:
            print(note)
        return 1
    pid = int(rec.get("pid", 0))
    if not _alive(pid):
        print("Stale pid file: process %d is gone. Removing it." % pid)
        remove_pid_file(root)
        note = _service_note("")
        if note:
            print(note)
        return 2
    url = str(rec.get("url", ""))
    try:
        with urllib.request.urlopen(url + "healthz", timeout=3) as resp:
            health = _report(resp.read().decode("utf-8", "replace"), dict)
    except (OSError, ValueError) as exc:
        print("Process %d is alive but %shealthz is not answering: %s" % (pid, url, exc))
        return 2
    started = str(rec.get("started_at", ""))
    up = ""
    try:
        import calendar
        secs = time.time() - calendar.timegm(time.strptime(started, "%Y%m%dT%H%M%SZ"))
        up = "%dh %02dm" % (secs // 3600, (secs % 3600) // 60)
    except (ValueError, OverflowError):
        pass
    print("Squawk %s is running." % health.get("version", rec.get("version", "")))
    print("  URL      : %s" % url)
    print("  PID      : %d" % pid)
    state = _service_state()
    if state:
        print("  Service  : %s" % state)
    print("  Since    : %s%s" % (started, " (up %s)" % up if up else ""))
    print("  Runs     : %s on disk, %s scan(s) in progress"
          % (health.get("runs", "?"), health.get("jobs_running", "?")))
    print("  Evidence : %s" % rec.get("evidence", root))
    print("  Log      : %s" % (rec.get("log") or "-"))
    return 0


# The server's own shutdown budget: drain 5 s, then up to 5 s grace + 1 s kill
# per scanner, then a container kill checked for up to 10 s. `stop` waits past
# that; it used to give up at 10 s and report the server still running while
# the server was three seconds from done.
STOP_WAIT_SECONDS = 30.0


def cmd_stop(root: str, wait: float = STOP_WAIT_SECONDS) -> int:
    """Stop the server recorded in the pid file with SIGTERM and wait for it
    to go. It records any scan in progress as aborted on the way out, and
    stops the scanner — process and container — before it goes."""
    import signal
    rec = read_pid_file(root)
    if rec is None:
        print("Squawk is not running (no pid file at %s)." % _pid_path(root))
        return 1
    pid = int(rec.get("pid", 0))
    if not _alive(pid):
        print("Stale pid file: process %d is already gone. Removing it." % pid)
        remove_pid_file(root)
        return 1
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        print("Could not signal process %d: %s" % (pid, exc))
        return 2
    deadline = time.time() + wait
    said = False
    while time.time() < deadline and _alive(pid):
        if not said and time.time() > deadline - wait + 3:
            print("  waiting for the server to stop its scanner…", flush=True)
            said = True
        time.sleep(0.1)
    if _alive(pid):
        print("Process %d is still running after %.0f s; it may be finishing a scan. "
              "Run --stop again, or kill -9 %d to force." % (pid, wait, pid))
        return 2
    remove_pid_file(root)
    print("Stopped Squawk (pid %d)." % pid)
    LOG.info("server stopped by --stop: pid=%d", pid)
    return 0


def report_no_start(log_path: str) -> None:
    """Say the child did not come up, and show its own last words.

    It bound a moment ago and still did not come up, so the child said why on
    its way out. Show it rather than sending the reader to a file. A function
    rather than a block inside the fork, because the only test it had searched
    start_daemon's SOURCE for the print() call -- which a comment satisfies,
    and which says nothing about what reaches the terminal (review R-17)."""
    print("Squawk did not come up within 6 s.")
    try:
        with open(log_path, encoding="utf-8") as fh:
            tail = [ln.rstrip() for ln in fh.read().splitlines()
                    if ln.strip()][-6:]
    except OSError:
        tail = []
    for line in tail:
        print("  %s" % line)
    print("  Full log : %s" % log_path)


def start_daemon(args: argparse.Namespace, root: str) -> int:
    """Start the server in the background: double-fork, detach, send its
    output to the serve log, and only report 'up' once the child has bound
    its port and written the pid file."""
    if not hasattr(os, "fork"):
        print("Background mode needs a POSIX system; run without --daemon.")
        return 2
    rec = read_pid_file(root)
    if rec and _alive(int(rec.get("pid", 0))):
        print("Squawk is already running (pid %s). Use --restart." % rec["pid"])
        return 1
    if rec:
        remove_pid_file(root)
    if not evidence_writable(root):
        print("Evidence root not writable: %s" % root)
        return 1
    # Before the fork, so the reason lands in this terminal rather than in a
    # log the operator has no reason to open.
    free, why = port_is_free(args.host, args.port)
    if not free:
        print("Squawk cannot start: %s" % why)
        LOG.error("daemon start refused: %s", why)
        return 1
    log_path = os.path.join(root, SERVE_LOG)
    # Flush before forking: anything still buffered (a "Stopped ..." line from
    # --restart, say) would otherwise be inherited by the child and written a
    # second time when it flushes on its way to the log.
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid > 0:
        for _ in range(60):                 # up to six seconds to bind
            time.sleep(0.1)
            rec = read_pid_file(root)
            if rec and rec.get("pid") != os.getpid() and _alive(int(rec["pid"])):
                print("Squawk is up in the background.")
                print("  URL      : %s" % rec.get("url", ""))
                print("  PID      : %s" % rec["pid"])
                print("  Log      : %s" % log_path)
                print("  Stop     : squawk.py --stop   ·   Status: squawk.py --status")
                if args.open:
                    webbrowser.open(str(rec.get("url", "")))
                return 0
        # It bound a moment ago and still did not come up, so the child said
        # why on its way out. Show it rather than sending the reader to a file.
        report_no_start(log_path)
        return 1
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    sys.stdout.flush()
    sys.stderr.flush()
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    # Rebind stdout and stderr line-buffered. Writing to a file rather than a
    # terminal makes Python block-buffer, and this process ends with os._exit,
    # which does not flush, so every line the daemon printed was discarded: the
    # startup banner, the note that a run was recorded as aborted, and any
    # traceback. The log the startup message points at was empty by
    # construction. Line buffering plus the flush below is the fix; squawk.log
    # was always fine because logging flushes each record.
    sys.stdout = os.fdopen(1, "w", buffering=1)
    sys.stderr = os.fdopen(2, "w", buffering=1)
    args.open = False
    try:
        rc = serve_web(args)
    finally:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except (OSError, ValueError):
            pass
    os._exit(rc)


def cmd_install_service(args: argparse.Namespace, root: str) -> int:
    """Write a systemd user unit so Squawk starts at login and restarts on
    failure. The unit is generated, not described; enabling it is left to you
    and printed, because that changes what runs on your machine."""
    if not _systemd_present():
        print("This needs systemd (Kali has it). Here, run it in the background with "
              "--daemon; a launchd plist is not generated.")
        return 2
    unit = unit_path()
    os.makedirs(os.path.dirname(unit), exist_ok=True)
    script = ENTRY_PATH
    body = ("[Unit]\nDescription=Squawk, a loopback-only security instrument\n"
            "After=network.target\n\n"
            "[Service]\nType=simple\n"
            "ExecStart=%s %s --host %s --port %d --evidence %s\n"
            "Restart=on-failure\nRestartSec=3\nEnvironment=PYTHONUNBUFFERED=1\n\n"
            "[Install]\nWantedBy=default.target\n"
            % (sys.executable, script, args.host, args.port, root))
    with open(unit, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(unit, 0o600)
    print("Wrote %s" % unit)
    print("Next, in your shell:")
    print("  systemctl --user daemon-reload")
    print("  systemctl --user enable --now squawk")
    print("  systemctl --user status squawk")
    print("  loginctl enable-linger %s     # keep it running when you log out"
          % os.environ.get("USER", "$USER"))
    print("Then: python3 %s --status" % script)
    return 0


def port_is_free(host: str, port: int) -> Tuple[bool, str]:
    """Can the server bind here? A busy port is the most ordinary startup
    failure there is, and it used to answer with a socketserver traceback
    while the foreground said only "did not come up within 6 s" — naming
    neither the port nor the reason (the operator, 2026-09-08). Tested before
    forking, so the reason arrives in the terminal the operator is looking
    at."""
    probe = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET,
                          socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
        return True, ""
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            return False, ("port %d is already in use on %s — something else is "
                           "listening there. Find it with `lsof -nP -iTCP:%d "
                           "-sTCP:LISTEN`, or pick another: --port %d"
                           % (port, host, port, port + 12))
        return False, ("cannot bind %s:%d — %s"
                       % (host, port, exc.strerror or exc.__class__.__name__))
    finally:
        probe.close()


def serve_web(args: argparse.Namespace) -> int:
    root = args.evidence or env("EVIDENCE") or DEFAULT_EVIDENCE
    if not evidence_writable(root):
        print("Evidence root not writable: %s" % root)
        return 1
    repo = resolve_repo(args.repo or env("REPO"))
    host, port = args.host, args.port
    free, why = port_is_free(host, port)
    if not free:
        print("Squawk cannot start: %s" % why)
        LOG.error("server start refused: %s", why)
        return 1
    httpd = ThreadingHTTPServer((host, port), make_handler(root, repo))
    shown = "[::1]" if host == "::1" else host
    url = "http://%s:%d/" % (shown, port)
    LOG.info("server start: version=%s url=%s evidence=%s repo=%s pid=%d",
             __version__, url, root, repo or "-", os.getpid())
    started_at = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    write_pid_file(root, {"pid": os.getpid(), "host": host, "port": port, "url": url,
                          "started_at": started_at, "version": __version__,
                          "evidence": root, "log": getattr(LOG, "_squawk_path", None)})
    print("Squawk %s is up." % __version__)
    print("  URL      : %s" % url)
    print("  Evidence : %s" % root)
    print("  Repo     : %s" % (repo or "none resolved (pick a target on the Scan page)"))
    print("  Runs     : %d on disk" % len(list_runs(root)))
    try:
        for name in record_aborted_runs(root, "found unfinished at server start",
                                        older_than=ABORT_SWEEP_AGE):
            print("  Note     : run %s never finished; recorded as aborted" % name)
    except Exception as exc:  # the sweep is housekeeping; it must not take the server down
        LOG.error("abort sweep failed at start: %s", exc)
        print("  Note     : could not sweep for unfinished runs (%s); "
              "see `squawk verify`" % exc)
    print("Ctrl-C to stop; or from another shell: squawk.py --stop | --status | --restart")
    # SIGTERM (from --stop, systemd, or a kill) ends the serve loop cleanly.
    # shutdown() must run on a thread other than the one in serve_forever().
    if threading.current_thread() is threading.main_thread():
        import signal

        def _on_term(signum, _frame):
            LOG.info("server signal %d: shutting down", signum)
            threading.Thread(target=httpd.shutdown, daemon=True).start()
        signal.signal(signal.SIGTERM, _on_term)
    if args.open:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping.")
    finally:
        # A scan still running when the server goes is not lost quietly: it is
        # written up as aborted under its target (charter I1, over the lifecycle).
        # And its scanner is stopped first. "Recorded as aborted" used to be a
        # claim about a file while the scanner — an active DAST probe, say —
        # kept attacking the target for up to ninety minutes more.
        # Say we are stopping BEFORE anything is killed, so a stage that dies
        # is recorded as aborted for that reason, not as an ordinary error.
        STOP_REQUESTED.set()
        still = _drain_jobs(2.0)
        for rec in terminate_children():
            if rec["container"] is None:
                print("  stopped scanner pid=%s (%s)" % (rec["pid"], rec["cmd"]))
            elif rec["container_stopped"]:
                print("  stopped scanner pid=%s and killed container %s"
                      % (rec["pid"], rec["container"]))
            else:
                # Loud, because "stopped" here is a claim about attack traffic
                # ending, and it has not.
                print("  STOPPED scanner pid=%s BUT container %s is still running: %s"
                      % (rec["pid"], rec["container"], rec["detail"]))
        _drain_jobs(3.0)               # let the job threads write their abort records
        for job in list(JOBS.values()):
            if job.status == "running" and job.run_dir:
                if record_aborted_run(job.run_dir, "server stopped mid-run"):
                    print("  run %s was in progress; recorded as aborted"
                          % os.path.basename(job.run_dir))
        httpd.server_close()
        remove_pid_file(root, os.getpid())
        LOG.info("server stop: pid=%d aborted_in_flight=%d", os.getpid(), still)
        print("stopped.")
    return 0


__all__ = [
    'STOP_WAIT_SECONDS',
    '_service_note',
    '_service_state',
    '_systemd_present',
    'cmd_install_service',
    'cmd_status',
    'cmd_stop',
    'port_is_free',
    'report_no_start',
    'serve_web',
    'start_daemon',
    'unit_path',
]

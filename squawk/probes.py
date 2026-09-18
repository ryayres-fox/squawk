"""Squawk's own probes that run in-process: target recon, the skill audit, the host self-audit."""

import configparser
import fnmatch
import hashlib
import io
import json
import logging
import logging.handlers
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, NamedTuple, Optional, Tuple, Union
from urllib.parse import urlparse

from squawk.core import (
    DB_STALE_DAYS,
    FEEDS_DIRNAME,
    INSTALL_DIRNAME,
    LOG,
    LOG_KEEP,
    LOG_MAX_BYTES,
    PROFILE_KEYS,
    RunContext,
    _mode_of,
    _report,
    _rows,
    app_sources,
    env,
    evidence_writable,
    is_contaminated,
    mask_account,
    mask_email,
    redact_identifiers,
    run_cmd,
    tool_path,
    vuln_db_ages,
)

# --------------------------------------------------------------------------- #
# Target recon — the discovery step. Given a host, find the reachable web apps
# so the kiosk knows what to point DAST at, instead of the operator needing to
# know that Metasploitable serves DVWA at /dvwa and Mutillidae at /mutillidae.
# Stdlib only (socket + urllib), so it runs on a bare machine with no extra
# install. It sends active traffic, so it runs only under the url scope, behind
# the same private-target rail as DAST.
# --------------------------------------------------------------------------- #

RECON_PORTS = (("http", 80), ("https", 443), ("http", 8080), ("http", 8000),
               ("https", 8443), ("http", 3000), ("http", 8888), ("http", 8081),
               ("http", 9000), ("http", 5000))

# Curated paths: the deliberately-vulnerable apps common test targets ship,
# plus generic entry points. A hit here is a scan target the kiosk can offer.
RECON_PATHS = ("/", "/dvwa/", "/mutillidae/", "/mutillidae/index.php",
               "/phpMyAdmin/", "/phpmyadmin/", "/twiki/", "/tikiwiki/",
               "/dav/", "/webdav/", "/test/", "/cgi-bin/", "/admin/",
               "/api/", "/rest/", "/#/")

_KNOWN_APPS = {"dvwa": "DVWA", "mutillidae": "Mutillidae",
               "phpmyadmin": "phpMyAdmin", "twiki": "TWiki",
               "tikiwiki": "TikiWiki", "webdav": "WebDAV", "dav": "WebDAV",
               "rest": "Juice Shop (likely)", "cgi-bin": "CGI"}

# A path nothing serves on purpose. A server that answers it is a catch-all —
# a single-page app, a wildcard rewrite — and every curated path after it
# would "exist" with the same page. Probed first, per port, so the labeled
# apps are only reported where the page differs from the catch-all page.
CALIBRATION_PATH = "/squawk-recon-%s/"


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_probe(url: str, timeout: float = 4.0) -> Optional[dict]:
    ctx = ssl._create_unverified_context()  # test targets use self-signed certs
    req = urllib.request.Request(url, headers={"User-Agent": "Squawk-recon"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        status, headers = resp.getcode(), resp.headers
        body = resp.read(4096).decode("latin-1", "replace")
    except urllib.error.HTTPError as exc:
        status, headers, body = exc.code, exc.headers, ""
    except (urllib.error.URLError, OSError, ValueError):
        return None
    title = ""
    lo = body.lower()
    if "<title>" in lo:
        i = lo.index("<title>") + 7
        j = lo.find("</title>", i)
        if j > i:
            title = body[i:j].strip()[:80]
    return {"status": status,
            "server": (headers.get("Server", "") if headers else "")[:60],
            "title": title,
            # status plus a hash of the page, so two paths that return the
            # same page can be told from two apps
            "fingerprint": "%s:%s" % (status, hashlib.sha256(
                body.encode("latin-1", "replace")).hexdigest()[:16])}


def recon_probe(ctx: "RunContext") -> "Union[str, Tuple[str, str, str]]":
    """Discover reachable web endpoints on the target host. Returns JSON:
    {"host": ..., "endpoints": [{"url","status","server","title","app"}]}."""
    parsed = urlparse(ctx.target if "://" in ctx.target else "http://" + ctx.target)
    host = parsed.hostname or ctx.target
    if parsed.port:
        candidates = [(parsed.scheme or "http", parsed.port)]
    else:
        candidates = list(RECON_PORTS)
    open_web = [(scheme, port) for scheme, port in candidates
                if _port_open(host, port)]

    seen, endpoints = set(), []
    catch_all: Dict[str, dict] = {}
    # What this run actually probed. Without it the stage published no
    # denominator at all -- `COVERAGE` had no entry for recon, so a sweep of
    # ten ports and sixteen paths and a run that reached one port printed the
    # same "N finding(s)". Counted here rather than taken from RECON_PORTS,
    # because a target given with an explicit port probes one candidate, not
    # ten, and the constant would overstate every such run (I15/I16).
    tried = answered = 0
    for scheme, port in open_web:
        base = "%s://%s:%d" % (scheme, host, port)
        # Calibrate before the curated paths. Without this Juice Shop, which
        # serves its index for any path, reported DVWA, phpMyAdmin and TWiki
        # at paths it does not serve (measured 2026-09-07: fifteen endpoints,
        # one real). ffuf and dirbuster call the same step auto-calibration.
        nonce = _http_probe(base + CALIBRATION_PATH % secrets.token_hex(6))
        tried += 1
        answered += 1 if nonce is not None else 0
        wild = ""
        if nonce is not None and nonce["status"] not in (0, 404):
            wild = nonce["fingerprint"]
            catch_all[str(port)] = {"url": base + "/", "status": nonce["status"]}
        for path in RECON_PATHS:
            info = _http_probe(base + path)
            tried += 1
            answered += 1 if info is not None else 0
            if not info or info["status"] in (0, 404):
                continue
            if wild and path != "/" and info["fingerprint"] == wild:
                continue                 # the catch-all page, not an app here
            app = ""
            for token, label in _KNOWN_APPS.items():
                if token in path.lower() or token in info["title"].lower():
                    app = label
                    break
            key = (port, urlparse(base + path).path)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append({"url": base + path, "status": info["status"],
                              "server": info["server"], "title": info["title"],
                              "app": app})
    payload = json.dumps({"host": host, "open_ports": [p for _s, p in open_web],
                          "ports_probed": len(candidates),
                          "requests": tried, "requests_answered": answered,
                          "catch_all": catch_all, "endpoints": endpoints},
                         indent=2)
    if not open_web:
        # Nothing answered, so nothing was examined. Reporting this as "0
        # findings" would be the substitution this whole tool exists to prevent:
        # a scanner that could not look must never read like one that looked and
        # found nothing.
        return (payload, "error",
                "no reachable port on %s — nothing was scanned" % host)
    return payload


# --------------------------------------------------------------------------- #
# Skill audit — static checks on agent skills and MCP server configs against the
# OWASP Agentic Skills Top 10 (AST10, v1.0 2026). AST08 in that list is "Poor
# Scanning", so a scanner that audits skills is Squawk mitigating an AST10 risk
# directly. Stdlib only (an internal stage, like recon). Static and heuristic:
# it reads manifests, it does not execute skills, so it covers the checkable
# risks (metadata, privilege, external-instruction and supply-chain patterns,
# governance) and names the ones it cannot see statically.
# --------------------------------------------------------------------------- #

AST10 = {
    "AST01": ("Malicious Skills", "critical"),
    "AST02": ("Supply Chain Compromise", "critical"),
    "AST03": ("Over-Privileged Skills", "high"),
    "AST04": ("Insecure Metadata", "high"),
    "AST05": ("Untrusted External Instructions", "high"),
    "AST06": ("Weak Isolation", "high"),
    "AST07": ("Update Drift", "medium"),
    "AST08": ("Poor Scanning", "medium"),
    "AST09": ("No Governance", "medium"),
    "AST10": ("Cross-Platform Reuse", "medium"),
}


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _frontmatter(text: str) -> Tuple[Dict[str, str], str]:
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    fm: Dict[str, str] = {}
    for line in text[3:end].splitlines():
        if ":" in line and not line.strip().startswith("#"):
            k, v = line.split(":", 1)
            fm[k.strip().lower()] = v.strip()
    return fm, text[end + 4:]


def _hit(findings: List[dict], ast: str, rel: str, marker: str, detail: str) -> None:
    findings.append({"ast": ast, "path": rel, "marker": marker, "detail": detail})


def _audit_skill_md(text: str, rel: str, findings: List[dict]) -> None:
    fm, body = _frontmatter(text)
    low = body.lower()
    missing = [k for k in ("name", "description") if not fm.get(k)]
    if missing:
        _hit(findings, "AST04", rel, "meta", "missing %s in frontmatter"
             % " and ".join(missing))
    if not any(k in fm for k in ("version", "owner", "author", "maintainer")):
        _hit(findings, "AST09", rel, "gov", "no version or owner declared")
    tools = fm.get("allowed-tools") or fm.get("allowed_tools") or fm.get("tools")
    if tools is None:
        _hit(findings, "AST03", rel, "priv-all",
             "no allowed-tools — the skill inherits every tool")
    elif "*" in tools or re.search(r"\bbash\b", tools, re.I):
        _hit(findings, "AST03", rel, "priv-broad",
             "grants broad tool access (%s)" % tools[:50])
    if re.search(r"(curl|wget)[^\n|]*\|\s*(bash|sh)\b", low):
        _hit(findings, "AST02", rel, "curlbash",
             "pipes a remote script straight into a shell")
    if re.search(r"https?://\S+", body) and re.search(
            r"\b(download and run|fetch and|execute|run this|install from)\b", low):
        _hit(findings, "AST05", rel, "extinstr",
             "instructs the agent to fetch or run remote content")
    if re.search(r"git clone https?://\S+", low) and "@" not in low.split("clone")[1][:80]:
        _hit(findings, "AST07", rel, "drift", "clones a repo without pinning a ref")


def _audit_mcp(data: dict, rel: str, findings: List[dict]) -> None:
    servers = data.get("mcpServers") or data.get("mcp_servers") or {}
    if not isinstance(servers, dict):
        return
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command", ""))
        argstr = " ".join(str(a) for a in (cfg.get("args") or []))
        blob = cmd + " " + argstr
        if not cfg.get("description"):
            _hit(findings, "AST04", rel, "mcp-meta-" + name,
                 "server '%s' has no description" % name)
        if re.search(r"\b(npx|uvx|pipx)\b", blob) and "@" not in argstr:
            _hit(findings, "AST02", rel, "mcp-unpin-" + name,
                 "server '%s' runs an unpinned package" % name)
        if re.search(r"\b(bash|sh)\s+-c\b", blob) or "curl" in blob:
            _hit(findings, "AST01", rel, "mcp-shell-" + name,
                 "server '%s' shells out arbitrarily" % name)
        if re.search(r"(--allow-all|--yolo|\s/\s|\$HOME|/Users/|/home/|~/)", argstr):
            _hit(findings, "AST03", rel, "mcp-fs-" + name,
                 "server '%s' is granted broad filesystem access" % name)


def skill_audit(ctx: "RunContext") -> str:
    """Walk the target tree, find agent skills (SKILL.md) and MCP configs, and
    audit each against AST10. Returns JSON {scanned, findings}."""
    root = ctx.target
    findings: List[dict] = []
    scanned = 0
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs
                   if d not in (".git", "node_modules") and not is_contaminated(d)]
        for fn in files:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            low = fn.lower()
            if low == "skill.md" or low.endswith(".skill.md"):
                _audit_skill_md(_read_text(full), rel, findings)
                scanned += 1
            elif low in ("mcp.json", ".mcp.json", "plugin.json") or (
                    low.endswith(".json") and "mcpServers" in _read_text(full)):
                try:
                    data = json.loads(_read_text(full))
                except (json.JSONDecodeError, OSError):
                    continue
                if isinstance(data, dict) and (
                        "mcpServers" in data or "mcp_servers" in data):
                    _audit_mcp(data, rel, findings)
                    scanned += 1
    return json.dumps({"scanned": scanned, "findings": findings}, indent=2)


# --------------------------------------------------------------------------- #
# Host self-audit: the room the autopsy happens in
#
# Squawk's output is only worth what the machine producing it is worth. A
# finding written to a world-readable directory has leaked. A timestamp from an
# unsynchronised clock cannot order two runs. A scanner resolved from a
# world-writable PATH entry is whatever the last writer wanted it to be. None of
# that shows up in a scan of the target, because none of it is wrong with the
# target. It is wrong with the instrument.
#
# So these checks point at the host, and they carry the same rule as everything
# else here: a check that could not run reports "unknown" and never "ok". The
# three states are kept apart deliberately. "ok" is a verified pass, "gap" is a
# verified problem, and "unknown" is an admission, which is the honest answer on
# a platform where the probe does not exist.
# --------------------------------------------------------------------------- #

SELF_AUDIT_AREAS = ("logging", "evidence", "time", "trail", "privilege",
                    "integrity", "freshness")

# Free space below this on the evidence volume and a long run can truncate the
# very artifacts it exists to keep.
EVIDENCE_FREE_WARN = 1 * 1024 * 1024 * 1024      # 1 GiB
EVIDENCE_FREE_CRIT = 100 * 1024 * 1024           # 100 MiB


def _chk(key, area, status, severity, title, detail, fix=""):
    return {"check": key, "area": area, "status": status, "severity": severity,
            "title": title, "detail": detail, "fix": fix}


def _in_git_worktree(path: str) -> Optional[str]:
    """The .git directory governing `path`, or None. Walks up rather than
    shelling out, so it works whether or not git is installed."""
    cur = os.path.abspath(path)
    while True:
        if os.path.exists(os.path.join(cur, ".git")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def _audit_logging(root: str, out: List[dict]) -> None:
    log_path = getattr(LOG, "_squawk_path", None)
    if not log_path or not LOG.handlers:
        out.append(_chk(
            "log-enabled", "logging", "gap", "critical",
            "Logging is off",
            "No log handler is attached, so refusals, runs and errors are not "
            "being recorded and cannot be audited later.",
            "Point --evidence at a writable directory and re-run."))
        return
    out.append(_chk("log-enabled", "logging", "ok", "info",
                    "Logging is on", "Writing to %s" % log_path))

    rotating = any(isinstance(h, logging.handlers.RotatingFileHandler)
                   for h in LOG.handlers)
    if rotating:
        out.append(_chk("log-rotation", "logging", "ok", "info",
                        "Log rotation is configured",
                        "%d files of %d bytes." % (LOG_KEEP, LOG_MAX_BYTES)))
    else:
        out.append(_chk(
            "log-rotation", "logging", "gap", "medium",
            "Log rotation is not configured",
            "The log can grow until it fills the evidence volume, at which "
            "point writing evidence starts failing.",
            "Use the built-in handler rather than redirecting output to a file."))

    mode = _mode_of(log_path)
    if mode is None:
        out.append(_chk("log-perms", "logging", "unknown", "low",
                        "Log permissions not readable",
                        "Could not stat %s." % log_path))
    elif mode & 0o077:
        out.append(_chk(
            "log-perms", "logging", "gap", "medium",
            "The log is readable by other local users",
            "Mode %04o on %s. It records every target scanned and every "
            "refusal, which is a map of what this machine looks at."
            % (mode, log_path),
            "chmod 600 %s" % log_path))
    else:
        out.append(_chk("log-perms", "logging", "ok", "info",
                        "Log is owner-only", "Mode %04o." % mode))


def _audit_evidence(root: str, out: List[dict]) -> None:
    if not os.path.isdir(root):
        out.append(_chk("evidence-exists", "evidence", "gap", "high",
                        "Evidence root does not exist",
                        "%s is missing, so nothing is being kept." % root,
                        "Create it, or pass --evidence."))
        return
    if not evidence_writable(root):
        # The check was right and the fix line was not. It named ownership,
        # which is the least likely cause on a single-user box, and said
        # nothing about the two that actually produce this: a filesystem
        # remounted read-only after an error, and a full disk. A finding whose
        # remediation points at the wrong thing costs the reader the time the
        # finding saved them.
        free = ""
        try:
            free = " %.2f GiB free." % (shutil.disk_usage(root).free / float(1024 ** 3))
        except OSError:
            pass
        out.append(_chk("evidence-writable", "evidence", "gap", "critical",
                        "Evidence root is not writable",
                        "A write probe in %s failed, so runs cannot leave "
                        "proof.%s Usually the filesystem is mounted read-only "
                        "after an error, or the disk is full; ownership is the "
                        "third possibility." % (root, free),
                        "mount | grep ' / '   (ro means read-only; dmesg says why)\n"
                        "        df -h %s     (100%% means full)\n"
                        "        ls -ld %s    (ownership, if the first two are fine)"
                        % (root, root)))
    else:
        out.append(_chk("evidence-writable", "evidence", "ok", "info",
                        "Evidence root is writable", root))

    mode = _mode_of(root)
    if mode is None:
        out.append(_chk("evidence-perms", "evidence", "unknown", "low",
                        "Evidence permissions not readable",
                        "Could not stat %s." % root))
    elif mode & 0o077:
        out.append(_chk(
            "evidence-perms", "evidence", "gap", "high",
            "Findings are readable by other local users",
            "Mode %04o on %s. Run evidence carries hostnames, paths, secret "
            "match context and the full finding set — the inventory an "
            "attacker on this box would otherwise have to build."
            % (mode, root),
            "chmod 700 %s" % root))
    else:
        out.append(_chk("evidence-perms", "evidence", "ok", "info",
                        "Evidence is owner-only", "Mode %04o." % mode))

    try:
        usage = shutil.disk_usage(root)
        free_bytes = usage.free
        gib = free_bytes / float(1024 ** 3)
        if free_bytes < EVIDENCE_FREE_CRIT:
            out.append(_chk("evidence-space", "evidence", "gap", "high",
                            "Almost no space left for evidence",
                            "%.2f GiB free on the evidence volume. A run can "
                            "fail part-written, which reads as a short scan "
                            "rather than a full one." % gib,
                            "Free space, or move --evidence to a larger volume."))
        elif free_bytes < EVIDENCE_FREE_WARN:
            out.append(_chk("evidence-space", "evidence", "gap", "medium",
                            "Low space for evidence", "%.2f GiB free." % gib,
                            "Prune old runs or move the evidence root."))
        else:
            out.append(_chk("evidence-space", "evidence", "ok", "info",
                            "Evidence volume has room", "%.2f GiB free." % gib))
    except OSError as exc:
        out.append(_chk("evidence-space", "evidence", "unknown", "low",
                        "Could not read free space", str(exc)))

    # The root being 0700 is not the whole answer: the run directories inside it
    # carry the findings, and they were being created with the ambient umask.
    loose = []
    try:
        for name in sorted(os.listdir(root)):
            full = os.path.join(root, name)
            if not os.path.isdir(full) or name in (INSTALL_DIRNAME, FEEDS_DIRNAME):
                continue
            mode = _mode_of(full)
            if mode is not None and mode & 0o077:
                loose.append("%s (%04o)" % (name, mode))
    except OSError:
        loose = []
    if loose:
        out.append(_chk(
            "run-perms", "evidence", "gap", "high",
            "Some run directories are readable by other local users",
            "%d of them, including %s. The root being owner-only is not enough "
            "on its own: these hold the findings, and a directory left "
            "group- or world-writable is evidence somebody else can edit."
            % (len(loose), ", ".join(loose[:3])),
            "chmod 700 %s/*/" % root))
    else:
        out.append(_chk("run-perms", "evidence", "ok", "info",
                        "Run directories are owner-only", root))

    worktree = _in_git_worktree(root)
    if worktree:
        out.append(_chk(
            "evidence-in-git", "evidence", "gap", "high",
            "Evidence root sits inside a git working tree",
            "%s is under %s. Run evidence carries account ids, resource names "
            "and finding detail, and a stray `git add -A` publishes all of it."
            % (root, worktree),
            "Move the evidence root outside any repository, or confirm it is "
            "ignored and never force-added."))
    else:
        out.append(_chk("evidence-in-git", "evidence", "ok", "info",
                        "Evidence root is outside any git working tree", root))


def _audit_time(out: List[dict]) -> None:
    """Clock sync, which underwrites every timestamp this tool writes.

    Worth its own check because the failure is invisible: findings still get
    written, runs still diff, and nothing looks wrong until two runs sort into
    the wrong order or a database age comes out negative."""
    if not tool_path("timedatectl"):
        out.append(_chk("clock-sync", "time", "unknown", "medium",
                        "Clock synchronisation not determined",
                        "timedatectl is not present, so NTP state could not be "
                        "read. Every run id, finding timestamp and database-age "
                        "calculation assumes this clock is right.",
                        "Check time sync by whatever means this platform uses."))
        return
    _c, out_s, _e = run_cmd(["timedatectl", "show", "-p", "NTPSynchronized",
                             "--value"], None, 10)
    val = (out_s or "").strip().lower()
    if val == "yes":
        out.append(_chk("clock-sync", "time", "ok", "info",
                        "Clock is synchronised", "NTPSynchronized=yes"))
    elif val == "no":
        out.append(_chk(
            "clock-sync", "time", "gap", "high",
            "Clock is not synchronised",
            "NTPSynchronized=no. Run ids are UTC timestamps and history is "
            "ordered by them, so an unsynchronised clock can order two runs "
            "wrongly and skew every database-age reading.",
            "Enable time sync: sudo timedatectl set-ntp true"))
    else:
        out.append(_chk("clock-sync", "time", "unknown", "medium",
                        "Clock synchronisation not determined",
                        "timedatectl returned %r." % val,
                        "Check time sync manually."))


def _audit_trail(out: List[dict]) -> None:
    """The host's own record. Squawk logging its own actions is not the same as
    the machine keeping a record of everything else that happened to it."""
    # /run/systemd/system is the documented "systemd is running" test. Without
    # it the journal questions are meaningless rather than failing, which is a
    # different answer: this platform does not have the thing being asked about.
    if not os.path.isdir("/run/systemd/system"):
        out.append(_chk("journal-persistent", "trail", "unknown", "low",
                        "Host log persistence not determined",
                        "systemd is not running here, so there is no journal to "
                        "check. Whatever this platform uses for host logs has "
                        "not been examined.",
                        "Confirm host logging by this platform's own means."))
    elif os.path.isdir("/var/log/journal"):
        out.append(_chk("journal-persistent", "trail", "ok", "info",
                        "systemd journal is persistent",
                        "/var/log/journal exists, so host logs survive a reboot."))
    else:
        out.append(_chk(
            "journal-persistent", "trail", "gap", "medium",
            "systemd journal is volatile",
            "/var/log/journal is absent, so the journal lives in /run and is "
            "lost on every reboot. Anything that happened to this machine "
            "before the last boot cannot be reviewed.",
            "sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create "
            "--prefix /var/log/journal && sudo systemctl restart systemd-journald"))

    if tool_path("auditd") or os.path.exists("/sbin/auditd"):
        out.append(_chk("auditd", "trail", "ok", "info",
                        "auditd is installed",
                        "Kernel-level audit records are available."))
    else:
        out.append(_chk(
            "auditd", "trail", "gap", "low",
            "auditd is not installed",
            "No kernel audit trail, so file and privilege events on the host "
            "running the scans are not recorded independently of Squawk.",
            "sudo apt-get install auditd  (optional; useful on a shared box)"))


def _audit_privilege(out: List[dict]) -> None:
    try:
        euid = os.geteuid()
    except AttributeError:
        out.append(_chk("not-root", "privilege", "unknown", "low",
                        "Effective user not determined",
                        "No geteuid on this platform."))
        return
    if euid == 0:
        out.append(_chk(
            "not-root", "privilege", "gap", "high",
            "Squawk is running as root",
            "Scanners parse untrusted input — repositories, images, HTTP "
            "responses from a target. Running that parsing as root means a "
            "parser bug is a root compromise of the analysis host.",
            "Run as an ordinary user; the installer is the only part needing sudo."))
    else:
        out.append(_chk("not-root", "privilege", "ok", "info",
                        "Not running as root", "euid=%d" % euid))

    try:
        import grp
        names = set()
        for gid in os.getgroups():
            try:
                names.add(grp.getgrgid(gid).gr_name)
            except KeyError:
                continue
        if "docker" in names:
            out.append(_chk(
                "docker-group", "privilege", "gap", "medium",
                "This user is in the docker group",
                "Membership of the docker group is equivalent to root on this "
                "host, because a container can mount the root filesystem. It "
                "is what lets Squawk run ZAP and image scans without sudo, so "
                "this is a trade rather than a mistake — but it should be a "
                "known one.",
                "Accept it deliberately, or use rootless Docker."))
        else:
            out.append(_chk("docker-group", "privilege", "ok", "info",
                            "Not in the docker group",
                            "Image and DAST stages will need another route."))
    except (ImportError, OSError) as exc:
        out.append(_chk("docker-group", "privilege", "unknown", "low",
                        "Group membership not determined", str(exc)))


def _audit_integrity(out: List[dict]) -> None:
    """Whether the instrument is what it claims to be."""
    bad_dirs = []
    unknown_dirs = 0
    for entry in (os.environ.get("PATH") or "").split(os.pathsep):
        if not entry:
            continue
        mode = _mode_of(entry)
        if mode is None:
            unknown_dirs += 1
            continue
        if mode & 0o002:                      # world-writable
            bad_dirs.append("%s (%04o)" % (entry, mode))
    if bad_dirs:
        out.append(_chk(
            "path-writable", "integrity", "gap", "high",
            "A world-writable directory is on PATH",
            "Squawk resolves every scanner through PATH, so any local user can "
            "place a binary that runs instead: %s" % ", ".join(bad_dirs),
            "Remove the entry from PATH, or chmod go-w it."))
    else:
        out.append(_chk("path-writable", "integrity", "ok", "info",
                        "No world-writable directory on PATH",
                        "%d entries checked, %d unreadable."
                        % (len((os.environ.get("PATH") or "").split(os.pathsep)),
                           unknown_dirs)))

    # The app is a package: check every source file, report the loosest.
    me, mode = "", None
    for cand in app_sources() or [os.path.abspath(__file__)]:
        cm = _mode_of(cand)
        if cm is not None and (mode is None or (cm & 0o022) > (mode & 0o022)):
            me, mode = cand, cm
    if mode is None:
        out.append(_chk("self-perms", "integrity", "unknown", "low",
                        "Own file permissions not readable", me))
    elif mode & 0o022:
        out.append(_chk(
            "self-perms", "integrity", "gap", "high",
            "Squawk's own file is writable by others",
            "Mode %04o on %s. Anything that can rewrite the auditor decides "
            "what the audit says." % (mode, me),
            "chmod go-w %s" % me))
    else:
        out.append(_chk("self-perms", "integrity", "ok", "info",
                        "Squawk's own file is not group- or world-writable",
                        "Mode %04o." % mode))

    here = os.path.dirname(me)
    if not tool_path("git") or not _in_git_worktree(here):
        out.append(_chk("self-integrity", "integrity", "unknown", "low",
                        "Cannot tell whether the running code matches source control",
                        "git is unavailable or this is not a checkout.",
                        "Run from a git checkout to make this checkable."))
        return
    code, out_s, _e = run_cmd(["git", "-C", here, "status", "--porcelain"], None, 15)
    if code != 0:
        out.append(_chk("self-integrity", "integrity", "unknown", "low",
                        "git status failed", "exit %d" % code))
    elif out_s.strip():
        n = len([ln for ln in out_s.splitlines() if ln.strip()])
        out.append(_chk(
            "self-integrity", "integrity", "gap", "medium",
            "The running code has uncommitted changes",
            "%d modified path(s) in the checkout. Findings produced now cannot "
            "be reproduced from any commit, so 'which version found this' has "
            "no answer." % n,
            "Commit or stash before a run whose output you intend to keep."))
    else:
        out.append(_chk("self-integrity", "integrity", "ok", "info",
                        "Checkout is clean",
                        "The running code matches source control."))


def _audit_freshness(out: List[dict]) -> None:
    ages = vuln_db_ages()
    if not ages:
        out.append(_chk("vuln-db", "freshness", "unknown", "medium",
                        "No vulnerability database could be checked",
                        "Neither trivy nor grype is installed, so CVE stages "
                        "cannot run at all.",
                        "python3 squawk.py --install"))
        return
    for name, age, detail in ages:
        if age is None:
            out.append(_chk("vuln-db-%s" % name, "freshness", "gap", "high",
                            "%s has no usable vulnerability database" % name,
                            detail or "No database date could be read.",
                            "python3 squawk.py --update"))
        elif age > DB_STALE_DAYS:
            out.append(_chk("vuln-db-%s" % name, "freshness", "gap", "medium",
                            "%s vulnerability database is %d days old"
                            % (name, age),
                            "Vulnerability data is published daily. A stale "
                            "database reports fewer CVEs and still looks clean.",
                            "python3 squawk.py --update"))
        else:
            out.append(_chk("vuln-db-%s" % name, "freshness", "ok", "info",
                            "%s database is current" % name,
                            "%d day(s) old." % age))


def self_audit_checks(evidence_root: str) -> List[dict]:
    """Run every host check and return one record each, pass or fail."""
    out: List[dict] = []
    _audit_logging(evidence_root, out)
    _audit_evidence(evidence_root, out)
    _audit_time(out)
    _audit_trail(out)
    _audit_privilege(out)
    _audit_integrity(out)
    _audit_freshness(out)
    return out


def self_audit(ctx: "RunContext") -> str:
    """Stage entry point. The target of this scanner is the host, so it ignores
    ctx.target and audits the evidence root it was pointed at."""
    checks = self_audit_checks(ctx.evidence_root)
    counts = {"ok": 0, "gap": 0, "unknown": 0}
    for c in checks:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    LOG.info("self-audit: %d ok, %d gap, %d unknown",
             counts["ok"], counts["gap"], counts["unknown"])
    return json.dumps({"counts": counts, "checks": checks}, indent=2)



# --------------------------------------------------------------------------- #
# AWS inventory — the account's own resources, read through the provider API.
#
# Everything Squawk could say about a cloud account used to be a re-reading of
# what Security Hub had already decided. An account with Security Hub off got
# silence, which is the one outcome this tool exists to prevent. This reads the
# resources themselves: what exists, and how it connects.
#
# An internal stage, because one answer needs many calls. Every call is a
# `describe-*`: read-only, no credential on argv (the CLI resolves its own
# chain), and nothing is installed in the account.
#
# Bounded, and it says where the bound fell. Regions are read one after another
# until the budget is gone; the ones that were not reached are named, because
# "no public instances" over four of seventeen regions is not the same claim as
# "no public instances".
# --------------------------------------------------------------------------- #

# read key -> (argv after `aws`, the response key holding the rows)
INVENTORY_READS: Tuple[Tuple[str, Tuple[str, ...], str], ...] = (
    ("vpcs", ("ec2", "describe-vpcs"), "Vpcs"),
    ("subnets", ("ec2", "describe-subnets"), "Subnets"),
    ("route-tables", ("ec2", "describe-route-tables"), "RouteTables"),
    ("internet-gateways", ("ec2", "describe-internet-gateways"), "InternetGateways"),
    ("security-groups", ("ec2", "describe-security-groups"), "SecurityGroups"),
    ("network-interfaces", ("ec2", "describe-network-interfaces"), "NetworkInterfaces"),
    ("instances", ("ec2", "describe-instances"), "Reservations"),
    ("vpc-peering", ("ec2", "describe-vpc-peering-connections"),
     "VpcPeeringConnections"),
)


def _keep(row: dict, *fields: str) -> dict:
    """One resource reduced to the fields the rules actually read.

    The whole `describe-instances` response is far more than the graph needs,
    and evidence that keeps everything keeps tags too — free-text an operator
    never chose to hand us. Projecting at the point of read means the evidence
    holds what the reasoning used and nothing else, which is also what makes it
    reviewable."""
    out: Dict[str, object] = {}
    for f in fields:
        if f in row:
            out[f] = row[f]
    return out


def _project(kind: str, rows: List[dict]) -> List[dict]:
    """Project one read's rows down to the graph's fields."""
    out: List[dict] = []
    if kind == "vpcs":
        for r in rows:
            out.append(_keep(r, "VpcId", "CidrBlock", "IsDefault"))
    elif kind == "subnets":
        for r in rows:
            out.append(_keep(r, "SubnetId", "VpcId", "AvailabilityZone",
                             "CidrBlock", "MapPublicIpOnLaunch"))
    elif kind == "route-tables":
        for r in rows:
            out.append({
                "RouteTableId": r.get("RouteTableId", ""),
                "VpcId": r.get("VpcId", ""),
                "Associations": [_keep(a, "SubnetId", "Main")
                                 for a in _rows(r.get("Associations"))],
                "Routes": [_keep(x, "DestinationCidrBlock", "DestinationIpv6CidrBlock",
                                 "GatewayId", "NatGatewayId", "State")
                           for x in _rows(r.get("Routes"))]})
    elif kind == "internet-gateways":
        for r in rows:
            out.append({
                "InternetGatewayId": r.get("InternetGatewayId", ""),
                "Attachments": [_keep(a, "VpcId", "State")
                                for a in _rows(r.get("Attachments"))]})
    elif kind == "security-groups":
        for r in rows:
            out.append({
                "GroupId": r.get("GroupId", ""),
                "GroupName": r.get("GroupName", ""),
                "VpcId": r.get("VpcId", ""),
                "IpPermissions": [{
                    "IpProtocol": p.get("IpProtocol", ""),
                    "FromPort": p.get("FromPort"),
                    "ToPort": p.get("ToPort"),
                    "IpRanges": [a.get("CidrIp", "") for a in _rows(p.get("IpRanges"))],
                    "Ipv6Ranges": [a.get("CidrIpv6", "")
                                   for a in _rows(p.get("Ipv6Ranges"))],
                } for p in _rows(r.get("IpPermissions"))]})
    elif kind == "network-interfaces":
        for r in rows:
            assoc = r.get("Association") or {}
            att = r.get("Attachment") or {}
            out.append({
                "NetworkInterfaceId": r.get("NetworkInterfaceId", ""),
                "SubnetId": r.get("SubnetId", ""),
                "VpcId": r.get("VpcId", ""),
                "PublicIp": (assoc or {}).get("PublicIp", ""),
                "InstanceId": (att or {}).get("InstanceId", ""),
                # What OWNS this interface. A hundred and three interfaces
                # against seven instances is the largest unexplained number an
                # operator can be shown, and the answer was already in the
                # response: the type and description say whether it belongs to
                # a load balancer, a Lambda, an ECS task or a VPC endpoint.
                "InterfaceType": r.get("InterfaceType", ""),
                "Description": r.get("Description", ""),
                "Groups": [g.get("GroupId", "") for g in _rows(r.get("Groups"))]})
    elif kind == "vpc-peering":
        for r in rows:
            acc = r.get("AccepterVpcInfo") or {}
            req = r.get("RequesterVpcInfo") or {}
            out.append({
                "VpcPeeringConnectionId": r.get("VpcPeeringConnectionId", ""),
                "Status": (r.get("Status") or {}).get("Code", ""),
                "AccepterVpcId": acc.get("VpcId", ""),
                "AccepterOwnerId": acc.get("OwnerId", ""),
                "AccepterRegion": acc.get("Region", ""),
                "RequesterVpcId": req.get("VpcId", ""),
                "RequesterOwnerId": req.get("OwnerId", ""),
                "RequesterRegion": req.get("Region", "")})
    elif kind == "instances":
        # describe-instances nests: Reservations[].Instances[].
        for res in rows:
            for r in _rows(res.get("Instances")):
                prof = r.get("IamInstanceProfile") or {}
                out.append({
                    "InstanceId": r.get("InstanceId", ""),
                    "State": (r.get("State") or {}).get("Name", ""),
                    "SubnetId": r.get("SubnetId", ""),
                    "VpcId": r.get("VpcId", ""),
                    "PublicIpAddress": r.get("PublicIpAddress", ""),
                    "InstanceProfileArn": (prof or {}).get("Arn", ""),
                    "SecurityGroups": [g.get("GroupId", "")
                                       for g in _rows(r.get("SecurityGroups"))]})
    return out


# Every call one reading cost. A snapshot that says "439 read-only API calls"
# is telling the reader what it did and what a re-read would cost, instead of
# presenting numbers that could have come from anywhere. Module-level and reset
# per run: a probe runs one at a time, in-process, by design.
# The API-call counter for the stage running RIGHT NOW, per thread.
#
# It was one module-level dict. Jobs run in threads (runtime.py starts one per
# job), so two runs overlapping shared the counter: each stage resets it to
# zero at its start, so a second run beginning mid-flight zeroed the first
# one's count and the page reported a number that belonged to neither (review
# R-15). Thread-local is the smallest fix that is actually a fix -- a counter
# passed through forty call sites would be the same guarantee with more places
# to forget it.
class _CallCounter(threading.local):
    def __init__(self) -> None:
        self.n = 0

    def __getitem__(self, _key: str) -> int:
        return self.n

    def __setitem__(self, _key: str, value: int) -> None:
        self.n = value


_CALLS = _CallCounter()


def _aws_json(argv: List[str], timeout: int) -> Tuple[Optional[dict], str]:
    """One read-only AWS call, parsed. Returns (data, "") or (None, why).

    A failure is a *state*, never an empty result: the caller records it per
    read, and any rule that needed it reports unknown rather than clean."""
    _CALLS["n"] += 1
    code, out, err = run_cmd(["aws", *argv, "--output", "json"], None, timeout)
    if code != 0:
        # Redacted HERE, not at the point it is printed. An AccessDenied
        # message carries the caller ARN, and under SSO that ARN carries the
        # operator's email address and the account id -- so an unredacted
        # error becomes the read's `detail`, is written into the manifest and
        # the evidence, and outlives the run (review R-3). PRODUCT rule 6 asks
        # that evidence never hold it in the first place, and the only way to
        # keep that promise is to never put it there.
        lines = (err or out or "call failed").strip().splitlines()
        text = lines[-1] if lines else "call failed"
        return None, redact_identifiers(text)[:240]
    data = _report(out, dict)
    if not isinstance(data, dict):
        return None, "unreadable response"
    return data, ""


# The words a stage writes when its own clock, not AWS, ended a read. They are
# matched, not just printed: a region that was ENTERED and not finished is a
# different answer from one never reached, and from one read to the end. The
# review found the edge stage putting the same region in regions_read and
# regions_unread at once, because breaking out of an inner loop recorded the
# region as never read while its partial results were kept (R-13).
BUDGET_MARK = "budget ran out"


def _ran_out(value: object) -> bool:
    """Whether anything in one region's record says the clock ended it.

    The stages record it in two shapes -- a reason in an `unreadable` list, or
    a `detail` on the individual read that stopped -- so this reads both rather
    than making every stage adopt one. What matters is that the answer is
    derived from the evidence and not tracked beside it, where a stage could
    write the reason and forget the bookkeeping."""
    if isinstance(value, str):
        return BUDGET_MARK in value
    if isinstance(value, dict):
        return any(_ran_out(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(_ran_out(v) for v in value)
    return False


def _partial_regions(regional: Dict[str, dict]) -> List[str]:
    """Regions the stage entered and did not finish."""
    return sorted(region for region, per in regional.items()
                  if _ran_out(per))


def _enabled_regions(timeout: int) -> Tuple[List[str], str]:
    """Every region this account has enabled — the denominator for every count
    the inventory reports. Without it a scan of one region reads as a scan of
    the account, which is the silent cap this tool refuses (I12)."""
    data, why = _aws_json(["ec2", "describe-regions",
                           "--filters", "Name=opt-in-status,Values=opt-in-not-required,opted-in"],
                          timeout)
    if data is None:
        return [], why
    names = sorted(str(r.get("RegionName", "")) for r in _rows(data.get("Regions"))
                   if r.get("RegionName"))
    return [n for n in names if n], ""


# AWS-managed policies whose NAME alone settles it. `*FullAccess` is matched by
# suffix so a new service's full-access policy is caught the day AWS ships it.
# This shortcut is only sound for policies AWS itself publishes and names; a
# customer-managed policy called "ReadOnlyish" means nothing, so those are read.
BROAD_POLICIES = ("AdministratorAccess", "PowerUserAccess")

# An AWS-managed policy ARN. Anything else under iam::<account>:policy/ is the
# customer's, and its name is not evidence about what it allows.
AWS_MANAGED = ":iam::aws:policy/"


def _policy_is_broad(name: str) -> bool:
    return name in BROAD_POLICIES or name.endswith("FullAccess")


def _as_policy_doc(value: object) -> Optional[dict]:
    """A policy document from the CLI, as a dict.

    The API returns these URL-encoded (RFC 3986) and botocore registers
    `json_decode_policies` on `after-call.iam`, so through the CLI they arrive
    already decoded and parsed. Both shapes are accepted anyway: a tool that
    reports on permissions must not start silently reporting nothing because a
    vendor moved a response handler."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(urllib.parse.unquote(value))
        except ValueError:
            return None
    return None


def _broad_reasons(doc: object, label: str) -> List[str]:
    """Why this policy document grants more than reading, in words.

    Only wildcards are called out, and deliberately so. `Action: "*"` and
    `service:*` on `Resource: "*"` are not judgement calls -- they are the
    policy saying "everything" in its own words. Enumerating individual write
    actions would be a much larger claim resting on a list this tool would have
    to keep current, and a stale list would produce exactly the confident wrong
    answer it is trying to avoid."""
    data = _as_policy_doc(doc)
    if not data:
        return []
    statements = data.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    out = []
    for st in _rows(statements):
        if str(st.get("Effect", "")).lower() != "allow":
            continue
        resources = _string_values(st.get("Resource"))
        wide_resource = any(r == "*" for r in resources)

        # An allow written as NotAction grants everything it does not name.
        # This is how PowerUserAccess is written, and reading only `Action`
        # meant such a policy came back with nothing to say (review R-4).
        #
        # It then came back with nothing to say for a DIFFERENT reason: the
        # branch reported breadth only when the exclusions failed to cover the
        # permission-granting actions, which is the ESCALATION question. Allow
        # everything except iam, organizations and account is far more than
        # read, and "far more than read" is what the four-leg rule asks about.
        # AWS's own PowerUserAccess was caught by name and a customer's
        # hand-written equivalent was not, under a caveat reading "none grants
        # a wildcard action. That is a real negative" (review 2, R-31).
        not_actions = _string_values(st.get("NotAction"))
        if not_actions:
            if wide_resource:
                out.append(
                    "%s allows every action except %s, on every resource%s"
                    % (label, _brief(not_actions),
                       " — far more than read, and not a path to MORE "
                       "permission, because the exclusions keep the "
                       "permission-granting actions out"
                       if _excludes_escalation(not_actions) else ""))
            continue

        for action in _string_values(st.get("Action")):
            low = action.lower()
            if low == "*":
                # On a single resource this is every action on THAT thing --
                # a large grant and not an account-wide one. Calling it
                # "allows every action" made `*` on one bucket the fourth leg
                # of a CRITICAL rule about the whole account.
                if wide_resource:
                    out.append("%s allows every action" % label)
                    break
                continue
            if low.endswith(":*") and (
                    wide_resource
                    or any(_everything_arn(r, low[:-2]) for r in resources)):
                out.append("%s allows %s on every resource" % (label, action))
                break
    return out


def _read_policy_document(arn: str, timeout: int) -> Tuple[object, str]:
    """A customer-managed policy's default version, or (None, why)."""
    meta, why = _aws_json(["iam", "get-policy", "--policy-arn", arn], timeout)
    if meta is None:
        return None, why
    version = str((meta.get("Policy") or {}).get("DefaultVersionId", ""))
    if not version:
        return None, "no default version on %s" % arn
    data, why = _aws_json(["iam", "get-policy-version", "--policy-arn", arn,
                           "--version-id", version], timeout)
    if data is None:
        return None, why
    return (data.get("PolicyVersion") or {}).get("Document"), ""


def _role_breadth(role_name: str, timeout: int) -> dict:
    """What one role can actually do, with the evidence for saying so.

    The first version judged this from the NAMES of attached managed policies
    and nothing else. Against a real account it reported "0 roles carrying more
    than read" over six roles -- a number that had never looked at an inline
    policy or opened a customer-managed one, presented as a fact. A role with
    an inline `"Action": "*"` would have counted as fine.

    So this reads them: AWS-managed policies are judged by AWS's own naming,
    which is reliable because AWS controls it; customer-managed policies and
    inline policies are fetched and read. Anything that could not be read is
    listed in `unevaluated`, and a role with an unevaluated policy is never
    reported as limited -- it is reported as not fully known."""
    out: Dict[str, object] = {"status": "ok", "detail": "", "policies": [],
                              "inline": [], "broad": [], "unevaluated": []}
    broad: List[str] = []
    unevaluated: List[str] = []

    data, why = _aws_json(["iam", "list-attached-role-policies",
                           "--role-name", role_name], timeout)
    if data is None:
        return {"status": "unknown", "detail": why, "policies": [],
                "inline": [], "broad": [], "unevaluated": ["every policy"]}
    attached = _rows(data.get("AttachedPolicies"))
    out["policies"] = [str(p.get("PolicyName", "")) for p in attached]
    for policy in attached:
        name = str(policy.get("PolicyName", ""))
        arn = str(policy.get("PolicyArn", ""))
        if AWS_MANAGED in arn:
            if _policy_is_broad(name):
                broad.append("%s (AWS-managed)" % name)
            continue
        doc, why_doc = _read_policy_document(arn, timeout)
        if doc is None:
            unevaluated.append("%s (customer-managed: %s)" % (name, why_doc))
            continue
        broad.extend(_broad_reasons(doc, "customer policy %s" % name))

    listed, why_inline = _aws_json(["iam", "list-role-policies",
                                    "--role-name", role_name], timeout)
    if listed is None:
        unevaluated.append("inline policies (%s)" % why_inline)
    else:
        names = [str(n) for n in (listed.get("PolicyNames") or [])
                 if isinstance(n, str)]
        out["inline"] = names
        for name in names:
            doc, why_doc = _aws_json(["iam", "get-role-policy",
                                      "--role-name", role_name,
                                      "--policy-name", name], timeout)
            if doc is None:
                unevaluated.append("inline %s (%s)" % (name, why_doc))
                continue
            broad.extend(_broad_reasons(doc.get("PolicyDocument"),
                                        "inline policy %s" % name))

    out["broad"] = broad
    out["unevaluated"] = unevaluated
    return out


def _profile_role(profile_arn: str, timeout: int) -> Tuple[str, str]:
    """The role name behind an instance profile ARN, or ("", why).

    An instance profile ARN carries the profile's name, not the role's, and
    they are frequently different — so this is a real lookup, not a parse."""
    name = profile_arn.rsplit("/", 1)[-1]
    if not name:
        return "", "no instance profile name in %s" % profile_arn
    data, why = _aws_json(["iam", "get-instance-profile",
                           "--instance-profile-name", name], timeout)
    if data is None:
        return "", why
    roles = _rows((data.get("InstanceProfile") or {}).get("Roles"))
    if not roles:
        return "", "instance profile %s carries no role" % name
    return str(roles[0].get("RoleName", "")), ""


# Every budget and every elapsed in this file is measured with `time.monotonic`,
# not the wall clock. A deadline on the wall clock counts the time a laptop
# spends asleep against a scan that was not running, so a machine that slept
# mid-read would wake and mark the rest of its regions unread. The stamps that
# say WHEN a reading was taken stay on the wall clock, because those are dates a
# person reads (2026-09-14).
def _budget(ctx: "RunContext", key: str, floor: int) -> int:
    """One profile knob as a positive whole number of seconds.

    `Knob.builtin` is optional (the stage timeout has none), a profile value
    arrives as whatever the TOML held, and this stage's own deadline arithmetic
    is what keeps the run bounded. A knob that came back None or a string would
    have crashed the stage or, worse, turned the deadline into something that
    never fires — so the fall-back is explicit and non-zero rather than
    whatever the table happens to say."""
    value = PROFILE_KEYS[key].builtin
    prof = getattr(ctx, "profile", None)
    if prof is not None:
        value = prof.setting(getattr(ctx, "service", ""),
                             getattr(ctx, "target", ""), "awscli", key, value).value
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return floor
    return value


def aws_inventory(ctx: "RunContext") -> "Union[str, Tuple[str, str, str]]":
    """Read the account's networking and compute inventory, region by region.

    Returns the JSON the graph rules are built from: what was read, what could
    not be read, and which regions were never reached. The three are kept
    apart on purpose — a rule may only say "nothing found" over data it
    actually has."""
    if not tool_path("aws"):
        return (json.dumps({"reads": {}, "resources": {}}, indent=2), "error",
                "aws CLI not installed — nothing was read")

    _CALLS["n"] = 0
    started = time.monotonic()
    budget = _budget(ctx, "cloud_inventory_budget", 600)
    call_timeout = _budget(ctx, "cloud_call_timeout", 30)
    deadline = time.monotonic() + budget

    # Who we are, before anything is read as us. Asked here with the same
    # read-only call `doctor` uses rather than imported from stages, because
    # stages imports this module and a cycle between them would be a worse
    # problem than four lines.
    ident, why = _aws_json(["sts", "get-caller-identity"], call_timeout)
    if ident is None or not ident.get("Account"):
        return (json.dumps({"reads": {}, "resources": {}}, indent=2), "error",
                "could not resolve an AWS identity: %s — nothing was read"
                % (why or "no Account in the response"))
    account = str(ident["Account"])

    regions, region_why = _enabled_regions(call_timeout)
    if not regions:
        return (json.dumps({"account": account, "reads": {}, "resources": {}},
                           indent=2),
                "error",
                "could not list the account's regions: %s — a per-region count "
                "with no denominator would be a guess" % (region_why or "none returned"))

    resources: Dict[str, Dict[str, List[dict]]] = {}
    reads: Dict[str, Dict[str, dict]] = {}
    unread: List[str] = []
    for region in regions:
        if time.monotonic() >= deadline:
            unread.append(region)
            continue
        per_read: Dict[str, dict] = {}
        per_res: Dict[str, List[dict]] = {}
        for key, argv, rows_key in INVENTORY_READS:
            if time.monotonic() >= deadline:
                per_read[key] = {"status": "unread",
                                 "detail": "the %ds budget ran out first" % budget,
                                 "count": 0}
                continue
            data, err = _aws_json([*argv, "--region", region], call_timeout)
            if data is None:
                per_read[key] = {"status": "error", "detail": err, "count": 0}
                per_res[key] = []
                LOG.warning("INVENTORY %s %s could not be read: %s", region, key, err)
                continue
            projected = _project(key, _rows(data.get(rows_key)))
            per_read[key] = {"status": "ok", "detail": "", "count": len(projected)}
            per_res[key] = projected
        reads[region] = per_read
        resources[region] = per_res

    # Only now, and only for the instances that are actually exposed, ask what
    # their role can do. Reading every role in the account is step 2's job and
    # a much larger call; this is the bounded lookup that lets the reachability
    # rule state its fourth leg instead of leaving it unknown.
    roles: Dict[str, dict] = {}
    profiles: Dict[str, dict] = {}
    for _region, per_res in resources.items():
        for inst in per_res.get("instances", []):
            arn = inst.get("InstanceProfileArn", "")
            if not arn or arn in profiles:
                continue
            if time.monotonic() >= deadline:
                profiles[arn] = {"status": "unknown", "detail":
                                 "the %ds budget ran out first" % budget, "role": ""}
                continue
            role_name, why_role = _profile_role(arn, call_timeout)
            profiles[arn] = {"status": "ok" if role_name else "unknown",
                             "detail": why_role, "role": role_name}
            if role_name and role_name not in roles:
                roles[role_name] = _role_breadth(role_name, call_timeout)

    payload = {
        "account": account,
        # The provenance of the reading, kept WITH it. A number on a page is
        # worth what the reader knows about where it came from: which identity
        # took it, when, and what it cost to take. Read back on every page load
        # so the page dates itself rather than implying it is live.
        # The ARN, with the ADDRESS out of it. Attribution needs the
        # account id and keeps it; nothing needs the operator's email,
        # and evidence outlives the run (PRODUCT rule 6, review R-3).
        "read_as": mask_email(ident.get("Arn", "")),
        "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api_calls": _CALLS["n"],
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "regions_enabled": regions,
        "regions_read": sorted(set(reads) - set(_partial_regions(reads))),
        "regions_partial": _partial_regions(reads),
        "regions_unread": sorted(unread),
        "budget_seconds": budget,
        "reads": reads,
        "resources": resources,
        "instance_profiles": profiles,
        "roles": roles,
    }
    # This stage recorded every refused read faithfully — per_read[key] carries
    # status "error" and the reason — and then returned a bare string, so the
    # ledger row said `ok` and the Cloud page counted whatever came back. A
    # denied `describe-security-groups` in one region meant that region
    # contributed zero groups to "groups open to the world", and nothing on the
    # green row said the zero was a refusal (denial sweep, 2026-09-12). The
    # evidence was right and the verdict was wrong, which is the exact split
    # `_partial` exists to close.
    refused = ["%s in %s (%s)" % (key, region, per[key].get("detail") or "refused")
               for region, per in sorted(reads.items())
               for key in sorted(per)
               if per[key].get("status") == "error"]
    # A role or instance profile that could not be opened is the same failure
    # one layer in: the reachability rule's fourth leg goes unknown, and the
    # roles tile counts over a set it could not finish reading.
    refused += ["instance profile %s (%s)" % (arn, info.get("detail") or "refused")
                for arn, info in sorted(profiles.items())
                if info.get("status") != "ok"]
    refused += ["role %s (%s)" % (name, info.get("detail") or "refused")
                for name, info in sorted(roles.items())
                if info.get("status") != "ok"]
    # A role whose attached policies opened but whose inline list did not comes
    # back `ok` with an `unevaluated` entry. The roles tile already prints that
    # as a floor; the ledger row did not, so the Scan page showed a green
    # stage for a run that had been refused a policy read.
    refused += ["role %s: %s" % (name, why)
                for name, info in sorted(roles.items())
                for why in (info.get("unevaluated") or [])
                if info.get("status") == "ok"]
    return _partial(json.dumps(payload, indent=2, sort_keys=True),
                    refused, "inventory read(s)")



# --------------------------------------------------------------------------- #
# What is watching this account, and where.
#
# The inventory says what exists. This says whether anything would notice if
# something happened to it — and it exists because an account with GuardDuty
# off in sixteen of seventeen regions looks, to every tool that reads Security
# Hub, exactly like an account with nothing wrong in sixteen regions.
#
# Four states per service, never two. ON, OFF, PARTIAL (on somewhere and not
# everywhere, with the count), and UNKNOWN (the identity could not tell). OFF
# and UNKNOWN are different answers about different things: one is a fact about
# the account, the other is a fact about the reading.
# --------------------------------------------------------------------------- #

ON, OFF, PARTIAL, UNKNOWN = "on", "off", "partial", "unknown"


def _guardduty(region: str, timeout: int) -> dict:
    data, why = _aws_json(["guardduty", "list-detectors", "--region", region],
                          timeout)
    if data is None:
        return {"state": UNKNOWN, "detail": why}
    ids = [str(d) for d in (data.get("DetectorIds") or []) if isinstance(d, str)]
    if not ids:
        return {"state": OFF, "detail": "no detector in this region"}
    got, why = _aws_json(["guardduty", "get-detector", "--detector-id", ids[0],
                          "--region", region], timeout)
    if got is None:
        return {"state": UNKNOWN, "detail": why}
    status = str(got.get("Status", "")).upper()
    features = _rows(got.get("Features"))
    on = [str(f.get("Name", "")) for f in features
          if str(f.get("Status", "")).upper() == "ENABLED"]
    off = [str(f.get("Name", "")) for f in features
           if str(f.get("Status", "")).upper() != "ENABLED"]
    return {"state": ON if status == "ENABLED" else OFF,
            "detail": "%d of %d feature(s) on" % (len(on), len(features))
                      if features else status.lower(),
            "features_on": sorted(on), "features_off": sorted(off)}


def _config(region: str, timeout: int) -> dict:
    data, why = _aws_json(["configservice", "describe-configuration-recorder-status",
                           "--region", region], timeout)
    if data is None:
        return {"state": UNKNOWN, "detail": why}
    rows = _rows(data.get("ConfigurationRecordersStatus"))
    if not rows:
        return {"state": OFF, "detail": "no configuration recorder"}
    recording = [r for r in rows if r.get("recording")]
    return {"state": ON if recording else OFF,
            "detail": "%d of %d recorder(s) recording" % (len(recording), len(rows))}


def _securityhub(region: str, timeout: int) -> dict:
    data, why = _aws_json(["securityhub", "describe-hub", "--region", region],
                          timeout)
    if data is None:
        # The API raises rather than answering when the hub is not enabled, so
        # the error text is the answer. Distinguished from a permissions
        # failure, which is genuinely unknown -- reporting "off" for "you may
        # not look" would be the tool inventing a fact about the account.
        low = why.lower()
        if "invalidaccess" in low or "not subscribed" in low or "resourcenotfound" in low:
            return {"state": OFF, "detail": "not enabled in this region"}
        return {"state": UNKNOWN, "detail": why}
    std, why = _aws_json(["securityhub", "get-enabled-standards",
                          "--region", region], timeout)
    if std is None:
        # The hub IS on -- describe-hub answered. Only the standards count is
        # missing, and reporting "0 standard(s) enabled" would be a number
        # nobody read.
        #
        # `state` stays ON because that is the answer to the question this row
        # asks, so the UNKNOWN sweep below never saw it and the stage reported
        # `ok` over a refused read. `unreadable` is the second fact the row was
        # keeping to itself (denial sweep, 2026-09-12).
        return {"state": ON, "detail": "enabled; standards count unreadable "
                                       "(%s)" % why,
                "unreadable": "standards count (%s)" % why}
    count = len(_rows(std.get("StandardsSubscriptions")))
    return {"state": ON, "detail": "%d standard(s) enabled" % count}


def _inspector(region: str, timeout: int) -> dict:
    data, why = _aws_json(["inspector2", "batch-get-account-status",
                           "--region", region], timeout)
    if data is None:
        return {"state": UNKNOWN, "detail": why}
    rows = _rows(data.get("accounts"))
    if not rows:
        return {"state": UNKNOWN, "detail": "no account status returned"}
    status = str(((rows[0].get("state") or {}).get("status") or "")).upper()
    res = rows[0].get("resourceState") or {}
    on = [k for k, v in res.items()
          if isinstance(v, dict) and str(v.get("status", "")).upper() == "ENABLED"]
    if status == "ENABLED":
        return {"state": ON if len(on) == len(res) else PARTIAL,
                "detail": "%d of %d resource type(s) scanned" % (len(on), len(res))}
    return {"state": OFF, "detail": status.lower() or "not enabled"}


def _access_analyzer(region: str, timeout: int) -> dict:
    data, why = _aws_json(["accessanalyzer", "list-analyzers", "--region", region],
                          timeout)
    if data is None:
        return {"state": UNKNOWN, "detail": why}
    rows = _rows(data.get("analyzers"))
    active = [r for r in rows if str(r.get("status", "")).upper() == "ACTIVE"]
    if not active:
        return {"state": OFF, "detail": "no active analyzer"}
    kinds = sorted({str(r.get("type", "")) for r in active})
    return {"state": ON, "detail": ", ".join(kinds) or "%d active" % len(active)}


REGIONAL_SERVICES = (
    ("guardduty", "GuardDuty", _guardduty,
     "watches for attacks in progress"),
    ("config", "AWS Config", _config,
     "records what the account looked like, and when it changed"),
    ("securityhub", "Security Hub", _securityhub,
     "aggregates control findings"),
    ("inspector", "Inspector", _inspector,
     "scans workloads and images for known vulnerabilities"),
    ("accessanalyzer", "Access Analyzer", _access_analyzer,
     "finds resources shared outside the account"),
)


def _cloudtrail(timeout: int) -> dict:
    """A trail is account-wide when it is multi-region, so this is asked once."""
    data, why = _aws_json(["cloudtrail", "describe-trails"], timeout)
    if data is None:
        return {"state": UNKNOWN, "detail": why}
    trails = _rows(data.get("trailList"))
    multi = [t for t in trails if t.get("IsMultiRegionTrail")]
    if not trails:
        return {"state": OFF, "detail": "no trail — API calls are not recorded"}
    validated = [t for t in multi if t.get("LogFileValidationEnabled")]
    if not multi:
        return {"state": PARTIAL,
                "detail": "%d trail(s), none multi-region" % len(trails)}
    return {"state": ON,
            "detail": "%d multi-region trail(s), %d with log file validation"
                      % (len(multi), len(validated))}


def _root_account(timeout: int) -> dict:
    data, why = _aws_json(["iam", "get-account-summary"], timeout)
    if data is None:
        return {"state": UNKNOWN, "detail": why}
    summary = data.get("SummaryMap") or {}
    mfa = summary.get("AccountMFAEnabled")
    keys = summary.get("AccountAccessKeysPresent")
    if mfa is None:
        return {"state": UNKNOWN, "detail": "summary did not report root MFA"}
    bits = ["root MFA %s" % ("on" if mfa else "OFF")]
    if keys is not None:
        bits.append("%s root access key(s)" % ("no" if not keys else keys))
    return {"state": ON if (mfa and not keys) else OFF, "detail": ", ".join(bits)}


def _s3_account_block(account: str, timeout: int) -> dict:
    """The ACCOUNT-wide S3 public access block, which is a different call on a
    different service from the per-bucket one, and needs the account id."""
    data, why = _aws_json(["s3control", "get-public-access-block",
                           "--account-id", account], timeout)
    if data is None:
        low = why.lower()
        if "nosuchpublicaccessblock" in low or "not exist" in low:
            return {"state": OFF, "detail": "no account-wide block configured"}
        return {"state": UNKNOWN, "detail": why}
    conf = data.get("PublicAccessBlockConfiguration") or {}
    on = [k for k, v in conf.items() if v is True]
    return {"state": ON if len(on) == 4 else (OFF if not on else PARTIAL),
            "detail": "%d of 4 settings on" % len(on)}


def _password_policy(timeout: int) -> dict:
    data, why = _aws_json(["iam", "get-account-password-policy"], timeout)
    if data is None:
        low = why.lower()
        if "nosuchentity" in low or "cannot be found" in low:
            return {"state": OFF, "detail": "no password policy set"}
        return {"state": UNKNOWN, "detail": why}
    policy = data.get("PasswordPolicy") or {}
    length = policy.get("MinimumPasswordLength")
    return {"state": ON, "detail": "minimum length %s" % (length or "unset")}


def aws_enablement(ctx: "RunContext") -> "Union[str, Tuple[str, str, str]]":
    """Which security services are on, per region, and which are not.

    The companion to the inventory: that one says what exists, this one says
    whether anything would notice if something happened to it. Read separately
    so a failure here cannot take the inventory down with it, and so each has
    its own status on the run."""
    if not tool_path("aws"):
        return (json.dumps({"regional": {}, "account": {}}, indent=2), "error",
                "aws CLI not installed — nothing was read")
    _CALLS["n"] = 0
    started = time.monotonic()
    budget = _budget(ctx, "cloud_inventory_budget", 600)
    call_timeout = _budget(ctx, "cloud_call_timeout", 30)
    deadline = time.monotonic() + budget

    ident, why = _aws_json(["sts", "get-caller-identity"], call_timeout)
    if ident is None or not ident.get("Account"):
        return (json.dumps({"regional": {}, "account": {}}, indent=2), "error",
                "could not resolve an AWS identity: %s — nothing was read"
                % (why or "no Account in the response"))
    account = str(ident["Account"])

    regions, region_why = _enabled_regions(call_timeout)
    if not regions:
        return (json.dumps({"account_id": account, "regional": {}, "account": {}},
                           indent=2), "error",
                "could not list the account's regions: %s — a per-region answer "
                "with no denominator would be a guess"
                % (region_why or "none returned"))

    regional: Dict[str, Dict[str, dict]] = {}
    unread: List[str] = []
    for region in regions:
        if time.monotonic() >= deadline:
            unread.append(region)
            continue
        per: Dict[str, dict] = {}
        for key, _label, probe, _what in REGIONAL_SERVICES:
            if time.monotonic() >= deadline:
                per[key] = {"state": UNKNOWN,
                            "detail": "the %ds budget ran out first" % budget}
                continue
            per[key] = probe(region, call_timeout)
        regional[region] = per

    account_level = {
        "cloudtrail": _cloudtrail(call_timeout),
        "root": _root_account(call_timeout),
        "s3block": _s3_account_block(account, call_timeout),
        "password": _password_policy(call_timeout),
    }
    # A service check that came back UNKNOWN is a question this stage could not
    # answer. The page has always shown it as "could not tell", but the ledger
    # said `ok`, so a run summary and a scan history both read as complete
    # (review R-2). The other cloud stages degrade on an unreadable read and
    # this one now does too.
    could_not_tell = ["%s in %s (%s)" % (key, region,
                                         (row or {}).get("detail") or "unknown")
                      for region, per in sorted(regional.items())
                      for key, row in sorted(per.items())
                      if isinstance(row, dict) and row.get("state") == UNKNOWN]
    could_not_tell += ["%s account-wide (%s)" % (key,
                                                 (row or {}).get("detail") or "unknown")
                       for key, row in sorted(account_level.items())
                       if isinstance(row, dict) and row.get("state") == UNKNOWN]
    # A probe that answered its own question and was refused a sub-read says so
    # in `unreadable`. Its state is a real answer, so the UNKNOWN sweep above
    # cannot see it, and without this the stage reported `ok`.
    could_not_tell += ["%s in %s: %s" % (key, region, row["unreadable"])
                       for region, per in sorted(regional.items())
                       for key, row in sorted(per.items())
                       if isinstance(row, dict) and row.get("unreadable")]
    could_not_tell += ["%s account-wide: %s" % (key, row["unreadable"])
                       for key, row in sorted(account_level.items())
                       if isinstance(row, dict) and row.get("unreadable")]
    payload = {
        "account_id": account,
        # The ARN, with the ADDRESS out of it. Attribution needs the
        # account id and keeps it; nothing needs the operator's email,
        # and evidence outlives the run (PRODUCT rule 6, review R-3).
        "read_as": mask_email(ident.get("Arn", "")),
        "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api_calls": _CALLS["n"],
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "regions_enabled": regions,
        "regions_read": sorted(set(regional) - set(_partial_regions(regional))),
        "regions_partial": _partial_regions(regional),
        "regions_unread": sorted(unread),
        "regional": regional,
        "account": account_level,
    }
    return _partial(json.dumps(payload, indent=2, sort_keys=True),
                    could_not_tell, "service check(s)")



# --------------------------------------------------------------------------- #
# The IAM graph — who exists, and what they can become.
#
# `get-account-authorization-details` returns, in the API's own words, "all IAM
# users, groups, roles, and policies in your account, including their
# relationships to one another". One call is the whole permission model, which
# is why this reads it rather than walking the account principal by principal.
#
# What this deliberately does NOT do: call `generate-credential-report`. That
# report carries MFA and key-age per principal and would be convenient, and
# generating one is a WRITE -- it creates something in the account that was not
# there before. Harmless, and still a write, and I3 says this tool does not
# write. So MFA and key age come from `list-mfa-devices` and `list-access-keys`
# instead, which are reads and give the same facts.
# --------------------------------------------------------------------------- #

# Actions that let a principal grant itself more than it has. Each is here with
# the sentence that says why, because "iam:CreatePolicyVersion is dangerous" is
# a claim a reader cannot check and "can rewrite a policy already attached to
# it" is one they can.
ESCALATION_ACTIONS = {
    "iam:createpolicyversion":
        "can rewrite a policy already attached to it",
    "iam:setdefaultpolicyversion":
        "can switch an attached policy to an older, wider version",
    "iam:attachuserpolicy":
        "can attach any policy, including AdministratorAccess, to itself",
    "iam:attachrolepolicy":
        "can attach any policy to a role it can then assume",
    "iam:attachgrouppolicy":
        "can attach any policy to a group it belongs to",
    "iam:putuserpolicy":
        "can write itself an inline policy allowing anything",
    "iam:putrolepolicy":
        "can write an inline policy onto a role it can assume",
    "iam:putgrouppolicy":
        "can write an inline policy onto a group it belongs to",
    "iam:createaccesskey":
        "can mint long-lived keys for any user, including more privileged ones",
    "iam:createloginprofile":
        "can give a console password to a user that had none",
    "iam:updateloginprofile":
        "can reset another user's console password",
    "iam:updateassumerolepolicy":
        "can make itself trusted by a role it does not currently hold",
    "iam:passrole":
        "can hand an existing role to a service it starts, inheriting its power",
    "iam:createuser":
        "can create a principal and grant it whatever it likes",
    "iam:createrole":
        "can create a role and grant it whatever it likes",
    "iam:addusertogroup":
        "can put a user into a group that already holds more than it does",
    "sts:assumerole":
        "can become any role that trusts it, and inherit what that role holds "
        "— the trust policies are the other half, and are read in the section "
        "above",
}

# The actions AWS's own self-service policy grants: managing the credentials of
# the user making the call. On `user/${aws:username}` these are genuinely not a
# path to more -- rotating your own key leaves you where you were.
#
# Everything else in the table above is a path even on your own user.
# `iam:AttachUserPolicy` on yourself is one call from AdministratorAccess, and
# the shortcut filed it beside "rotate my own access key" (review 2, R-19).
SELF_SERVICE_ACTIONS = frozenset({
    "iam:createaccesskey", "iam:updateaccesskey", "iam:deleteaccesskey",
    "iam:createloginprofile", "iam:updateloginprofile", "iam:changepassword",
    "iam:createvirtualmfadevice", "iam:enablemfadevice",
    "iam:resyncmfadevice", "iam:deactivatemfadevice",
})

# Actions whose Resource names a ROLE rather than a user, so the "limited to"
# branch looks for role ARNs.
ROLE_TARGET_ACTIONS = frozenset({"iam:passrole", "sts:assumerole"})


class PolicyRead(NamedTuple):
    """What one policy says, sorted by what a reader would do about it.

    The first version returned one list, because it matched action names and
    read nothing else in the statement. That made AWS's own "let users manage
    their own credentials" policy -- CreateAccessKey and UpdateLoginProfile
    scoped to `user/${aws:username}` -- three privilege-escalation paths, and
    a deploy role's `iam:PassRole` on one named role a fourth (review R-4,
    reproduction 2). The Resource is what separates them, so the reader keeps
    the separation instead of collapsing it."""

    escalation: List[str]     # can become more than it is
    self_service: List[str]   # can only act on its own credentials
    scoped: List[str]         # an escalation action pinned to named targets
    notes: List[str]          # true, and not a finding by itself


def _string_values(value: object) -> List[str]:
    """A policy element that is a string or a list of them.

    Anything else is nothing, not a crash. A policy document arrives from
    outside and can hold any JSON at all: the earlier version iterated
    whatever it was given, so an `Action` of `5` raised TypeError out of the
    reader and took the stage with it (I14 -- a reading this tool cannot parse
    is a gap, never an exception)."""
    if isinstance(value, str):
        return [value]
    if not isinstance(value, (list, tuple)):
        return []
    return [v for v in value if isinstance(v, str)]


def _escalation_matches(action: str) -> List[Tuple[str, str]]:
    """The escalation actions one Action element grants.

    Matched with fnmatch, because `iam:Attach*` and `iam:*Policy*` grant the
    same permissions as naming them and the old exact lookup found neither.
    A wildcard that covers three escalation actions is three ways, and is
    reported as three."""
    if "*" in action or "?" in action:
        return [(key, why) for key, why in sorted(ESCALATION_ACTIONS.items())
                if fnmatch.fnmatchcase(key, action)]
    why = ESCALATION_ACTIONS.get(action)
    return [(action, why)] if why else []


def _excludes_escalation(patterns: List[str]) -> bool:
    """Whether a NotAction list keeps the permission-GRANTING actions out.

    This is how PowerUserAccess is written: allow everything except `iam:*`,
    `organizations:*` and `account:*`. Broad, and not a path to more
    permissions, which are different sentences.

    Only the `iam:` actions count here. `sts:AssumeRole` is in the escalation
    table and is not a permission-granting action -- it does nothing without a
    role that trusts the caller -- so requiring a NotAction to exclude it as
    well would make PowerUserAccess read as a path to more, which it is not."""
    lows = [p.lower() for p in patterns]
    return all(any(fnmatch.fnmatchcase(key, pattern) for pattern in lows)
               for key in ESCALATION_ACTIONS if key.startswith("iam:"))


def _only_own_user(resources: List[str]) -> bool:
    """Every resource is the caller's own user, by policy variable."""
    return bool(resources) and all("${aws:username}" in r for r in resources)


def _named_targets(resources: List[str], kind: str) -> List[str]:
    """The names this statement is pinned to, for `user` or `role`.

    Empty when any resource is a wildcard, another kind, or carries a `*` in
    the name itself -- `arn:aws:iam::*:role/*` pins nothing."""
    marker = ":%s/" % kind
    names = []
    for resource in resources:
        if not resource.startswith("arn:") or marker not in resource:
            return []
        name = resource.split(marker, 1)[1]
        if not name or "*" in name or "?" in name or "${" in name:
            return []
        names.append(name)
    return names


def _everything_arn(resource: str, service: str) -> bool:
    """`arn:aws:s3:::*` is every bucket, said the long way.

    `s3:*` on that resource is as broad as `s3:*` on `*`, and the old check
    compared the resource to the bare `*` and so missed it."""
    parts = resource.split(":")
    if len(parts) < 6 or parts[0] != "arn" or parts[2].lower() != service:
        return False
    return all(part in ("", "*") for part in parts[3:])


def _brief(resources: List[str]) -> str:
    return ", ".join(resources[:2]) + (" and %d more" % (len(resources) - 2)
                                       if len(resources) > 2 else "")


def _unique(values: List[str]) -> List[str]:
    """Same sentence from two statements in one policy is one sentence."""
    seen, out = set(), []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def read_policy(doc: object, label: str) -> PolicyRead:
    """What a policy document grants, with the Resource and Condition read.

    Deny statements are skipped: a policy that forbids something is not a
    grant. An MFA condition is recorded beside the reason rather than removing
    it -- it is a guard on the path, not the absence of one."""
    data = _as_policy_doc(doc)
    empty = PolicyRead([], [], [], [])
    if not data:
        return empty
    statements = data.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    escalation: List[str] = []
    self_service: List[str] = []
    scoped: List[str] = []
    notes: List[str] = []
    for st in _rows(statements):
        if str(st.get("Effect", "")).lower() != "allow":
            continue
        resources = _string_values(st.get("Resource"))
        wide = any(r == "*" for r in resources)
        conditions = _condition_keys(st.get("Condition"))
        guard = (" (only with MFA present)"
                 if "aws:multifactorauthpresent" in conditions else "")

        not_actions = _string_values(st.get("NotAction"))
        if not_actions:
            if not wide:
                notes.append("%s allows every action except %s, on %s"
                             % (label, _brief(not_actions), _brief(resources)))
            elif _excludes_escalation(not_actions):
                notes.append("%s allows every action except %s, which keeps "
                             "the permission-granting IAM actions out"
                             % (label, _brief(not_actions)))
            else:
                escalation.append("%s allows every action except %s%s"
                                  % (label, _brief(not_actions), guard))
            continue

        own = _only_own_user(resources)
        for action in _string_values(st.get("Action")):
            low = action.lower()
            if low == "*":
                if wide:
                    escalation.append("%s allows every action%s" % (label, guard))
                else:
                    notes.append("%s allows every action on %s"
                                 % (label, _brief(resources)))
                break
            if low == "iam:*":
                if own:
                    self_service.append("%s allows every IAM action, on its "
                                        "own user only" % label)
                else:
                    escalation.append("%s allows every IAM action%s"
                                      % (label, guard))
                break
            for key, why in _escalation_matches(low):
                named = (action if low == key
                         else "%s (through %s)" % (key, action))
                if key in ROLE_TARGET_ACTIONS:
                    roles = _named_targets(resources, "role")
                    if roles:
                        scoped.append("%s allows %s, limited to %s — a named "
                                      "role, not any role"
                                      % (label, named, _brief(roles)))
                        continue
                # The own-user shortcut is for CREDENTIAL management only.
                # Attaching a policy to yourself is one call from
                # AdministratorAccess, and it was filed beside "rotate my own
                # access key" (review 2, R-19).
                if own and key in SELF_SERVICE_ACTIONS:
                    self_service.append("%s allows %s, on its own user only"
                                        % (label, named))
                    continue
                if own:
                    escalation.append(
                        "%s allows %s on its own user — which is the holder "
                        "granting itself, not managing its own credentials: %s%s"
                        % (label, named, why, guard))
                    continue
                users = _named_targets(resources, "user")
                if users and key not in SELF_SERVICE_ACTIONS:
                    escalation.append(
                        "%s allows %s, limited to %s — a named user, and one "
                        "the holder may be or may hold a key for: %s%s"
                        % (label, named, _brief(users), why, guard))
                    continue
                if users:
                    # The generic reason says "for any user", which is exactly
                    # what a named resource makes untrue. Whether it matters
                    # depends on who that user is, which is the reader's call
                    # and is why the target is named here.
                    scoped.append("%s allows %s, limited to %s — one named "
                                  "user, not any user"
                                  % (label, named, _brief(users)))
                    continue
                escalation.append("%s allows %s — %s%s"
                                  % (label, named, why, guard))
    return PolicyRead(_unique(escalation), _unique(self_service),
                      _unique(scoped), _unique(notes))


def _escalation_reasons(doc: object, label: str) -> List[str]:
    """Only the reasons that say this policy grants a path to more."""
    return read_policy(doc, label).escalation


def _policy_docs_by_arn(details: dict) -> Dict[str, object]:
    """Every customer-managed policy's DEFAULT version document, by ARN."""
    out: Dict[str, object] = {}
    for policy in _rows(details.get("Policies")):
        arn = str(policy.get("Arn", ""))
        if not arn:
            continue
        for version in _rows(policy.get("PolicyVersionList")):
            if version.get("IsDefaultVersion"):
                out[arn] = version.get("Document")
                break
    return out


def _principal_reasons(principal: dict, docs: Dict[str, object],
                       groups: Dict[str, dict], kind: str) -> PolicyRead:
    """Every escalation path a principal has, from every policy that reaches it.

    Inline, attached, and — for a user — inherited through each group it
    belongs to. The group hop is the reason this reads the whole graph rather
    than one principal at a time: a user with no policies of its own can still
    be an administrator through a group, and a check that looked only at the
    user would call it clean."""
    esc: List[str] = []
    self_service: List[str] = []
    scoped: List[str] = []
    notes: List[str] = []

    def take(read: PolicyRead) -> None:
        esc.extend(read.escalation)
        self_service.extend(read.self_service)
        scoped.extend(read.scoped)
        notes.extend(read.notes)

    listkey = "UserPolicyList" if kind == "user" else "RolePolicyList"
    for inline in _rows(principal.get(listkey)):
        take(read_policy(inline.get("PolicyDocument"),
                         "inline policy %s" % inline.get("PolicyName", "?")))
    for attached in _rows(principal.get("AttachedManagedPolicies")):
        arn = str(attached.get("PolicyArn", ""))
        name = str(attached.get("PolicyName", ""))
        if AWS_MANAGED in arn:
            if name in ("AdministratorAccess", "PowerUserAccess", "IAMFullAccess"):
                esc.append("%s (AWS-managed) grants administrative IAM "
                           "permissions" % name)
            continue
        take(read_policy(docs.get(arn), "policy %s" % name))
    for group_name in (principal.get("GroupList") or []):
        group = groups.get(str(group_name))
        if not group:
            continue
        for inline in _rows(group.get("GroupPolicyList")):
            take(read_policy(
                inline.get("PolicyDocument"),
                "group %s inline policy %s" % (group_name,
                                               inline.get("PolicyName", "?"))))
        for attached in _rows(group.get("AttachedManagedPolicies")):
            arn = str(attached.get("PolicyArn", ""))
            name = str(attached.get("PolicyName", ""))
            if AWS_MANAGED in arn:
                if name in ("AdministratorAccess", "PowerUserAccess",
                            "IAMFullAccess"):
                    esc.append("group %s carries %s (AWS-managed)"
                               % (group_name, name))
                continue
            take(read_policy(docs.get(arn),
                             "group %s policy %s" % (group_name, name)))
    return PolicyRead(_unique(esc), _unique(self_service), _unique(scoped),
                      _unique(notes))


# A reason that says the principal is ALREADY administrative, as opposed to one
# that says it could become so. The distinction matters: a role holding
# AdministratorAccess does not need to escalate, it is already there, and
# listing it under "can grant themselves more" is a category error that put the
# account's own SSO admin role in a list of privilege-escalation paths
# (measured on a real account, 2026-09-09).
ADMIN_MARKERS = ("allows every action", "allows every IAM action",
                 "grants administrative IAM permissions")


def is_already_admin(reasons: List[str]) -> bool:
    return any(any(m in r for m in ADMIN_MARKERS) for r in reasons)


def escalation_only(reasons: List[str]) -> List[str]:
    """The reasons that describe becoming more, with the ones that describe
    already being everything removed."""
    return [r for r in reasons if not any(m in r for m in ADMIN_MARKERS)]


# --------------------------------------------------------------------------- #
# Who can assume a role.
#
# "A role is only a path for whoever can assume it" was a caveat on the page,
# which is another way of saying the tool raised the question and left it to
# the reader. Against a real account that produced eleven roles that can grant
# themselves more and no way to tell which of them mattered.
#
# The trust policy is the answer, and it was already in the graph response --
# fetched, and then dropped. A role that can escalate is ordinary; a role that
# can escalate AND is assumable by an unconstrained or external principal is
# the combination.
# --------------------------------------------------------------------------- #

GITHUB_OIDC = "token.actions.githubusercontent.com"


def _principal_values(principal: object) -> List[Tuple[str, str]]:
    """A trust policy Principal as [(kind, value)], whatever shape it took."""
    out: List[Tuple[str, str]] = []
    if isinstance(principal, str):
        return [("AWS", principal)]
    if not isinstance(principal, dict):
        return out
    for kind, value in principal.items():
        values = [value] if isinstance(value, str) else [
            v for v in (value or []) if isinstance(v, str)]
        out.extend((str(kind), v) for v in values)
    return out


# Operators that say the OPPOSITE of the ones beside them. `StringEquals` on
# `aws:PrincipalAccount` names this account; `StringNotEquals` on the same key
# names every account except this one. Flattening operators away made those
# identical, so a role every account on AWS except this one can assume was
# filed as "internal", and a topic granted to the whole world minus the
# owner's organization was filed as nothing at all -- the exact inverse of the
# policy, printed with confidence (review 2, R-18).
#
# `...IfExists` is a suffix on any of them and changes when the test applies,
# not what it means, so it is stripped before the comparison.
NEGATING_OPERATORS = frozenset({
    "stringnotequals", "stringnotequalsignorecase", "stringnotlike",
    "arnnotequals", "arnnotlike", "numericnotequals", "datenotequals",
    "notipaddress", "binarynotequals",
})

# `Null` says whether the key is PRESENT, not what it equals. It narrows
# nothing about who, in either direction.
PRESENCE_OPERATORS = frozenset({"null"})


# The set-operator prefixes. `ForAnyValue:StringNotEquals` is StringNotEquals
# applied across a multivalued key, and it negates exactly as the bare form
# does. Stripping only `IfExists` left both prefixed forms reading as
# affirming, so a `*` narrowed by `ForAllValues:StringNotLike` on an org key
# produced no finding at all (review 3, R-39).
SET_OPERATOR_PREFIXES = ("foranyvalue:", "forallvalues:")


def _operator_sense(operator: str) -> str:
    """"affirms", "negates" or "neither", for one condition operator."""
    low = str(operator).lower().replace("ifexists", "")
    for prefix in SET_OPERATOR_PREFIXES:
        if low.startswith(prefix):
            low = low[len(prefix):]
    if low in PRESENCE_OPERATORS:
        return "neither"
    if low in NEGATING_OPERATORS:
        return "negates"
    return "affirms"


def _condition_values(value: object) -> List[str]:
    """A condition value as the strings IAM compares it as.

    The policy grammar allows a string, a number or a Boolean, alone or in a
    list, and the CLI hands the document through as parsed JSON -- so an
    MFA-enforcing trust policy written with an unquoted `true`, which is how
    Terraform's jsonencode writes it, arrived here as a bool. Iterating a bool
    raised TypeError out of all three policy readers, and the stage runner
    turned that into `error` for the whole IAM or data-services stage: one
    such trust policy removed the identity reading for the account (review 3,
    R-36). IAM compares numbers and booleans as strings, so that is what they
    become here. Anything else is nothing, not a crash."""
    if isinstance(value, bool):
        return ["true" if value else "false"]
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [s for v in value if not isinstance(v, (list, tuple, dict))
                for s in _condition_values(v)]
    return []


def _condition_map(condition: object) -> Dict[str, List[Tuple[str, List[str]]]]:
    """Every condition key, lowercased, with the operators applied to it.

    The shape `_condition_keys` throws away. A reader that decides who a
    statement admits has to know whether the operator said "is" or "is not"."""
    out: Dict[str, List[Tuple[str, List[str]]]] = {}
    if not isinstance(condition, dict):
        return out
    for operator, block in condition.items():
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            out.setdefault(str(key).lower(), []).append(
                (_operator_sense(operator), _condition_values(value)))
    return out


def _condition_keys(condition: object) -> Dict[str, List[str]]:
    """Every condition key in a statement, lowercased, with its values.

    Flattened across operators. Callers that decide WHO a statement admits
    must use `_condition_map` instead: this one answers only "is there a
    condition on this key at all", which is a different question and the one
    the narrowed/unnarrowed split still asks."""
    out: Dict[str, List[str]] = {}
    for key, clauses in _condition_map(condition).items():
        for _sense, values in clauses:
            out.setdefault(key, []).extend(values)
    return out


def _affirmed(clauses: "Optional[List[Tuple[str, List[str]]]]") -> List[str]:
    """The values a key is positively tested against, or [] if none are."""
    return [v for sense, values in (clauses or []) if sense == "affirms"
            for v in values]


def _is_negated(clauses: "Optional[List[Tuple[str, List[str]]]]") -> bool:
    """Whether any clause on this key says "is not"."""
    return any(sense == "negates" for sense, _values in (clauses or []))


def _mask_account_ids(value: str) -> str:
    """An ARN with its account id masked, for text that reaches the page.

    Trust policies name other accounts, and an account id is an identifier this
    tool does not print (PRODUCT rule 6)."""
    return _ACCOUNT_IN_ARN.sub(lambda m: mask_account(m.group(0)), value)


def who_can_assume(doc: object, account: str,
                   org: "Optional[dict]" = None) -> List[dict]:
    """Who this trust policy admits, as {kind, who, reach, why}.

    `reach` is the load-bearing field: "anyone", "external", "organization",
    "federated", "service" or "internal". A role reachable only by a principal
    inside the same account is a different risk from one any GitHub workflow on
    earth can assume, and the difference is not visible in the role's
    permissions.

    `org` is what the organization stage read earlier in the same run --
    {"id", "management", "accounts"} -- and it decides the third reach. Without
    it, AWS Organizations' own `OrganizationAccountAccessRole` reads as an
    administrative role reachable from outside the account, which is CRITICAL:
    every member account of every organization would open on a critical finding
    about the role AWS put there (review 2, R-25). It is optional, and when it
    is missing the answer stays `external`, because "this might be a member of
    an organization nobody read" is not something to assume either way.
    """
    data = _as_policy_doc(doc)
    if not data:
        return []
    statements = data.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    out: List[dict] = []
    for st in _rows(statements):
        if str(st.get("Effect", "")).lower() != "allow":
            continue
        clauses = _condition_map(st.get("Condition"))
        conditions = _condition_keys(st.get("Condition"))
        # The keys a negated operator sits on. `_federated_reach` reads the
        # flattened map, and a `StringNotLike` on a GitHub `sub` -- a denylist
        # that keeps a few repositories out and admits every other one -- read
        # as a pin to the organization it named (review 3, R-39).
        negated = frozenset(k for k, c in clauses.items() if _is_negated(c))
        scope, who = _who_a_condition_names(st.get("Condition"), account, org)
        # Only a condition that names WHO narrows a `*` principal. The common
        # false friend is `sts:ExternalId`: a shared string against the confused
        # deputy, not an identity, so a role trusting `*` with nothing but an
        # ExternalId is assumable by anyone who learns it. `aws:SourceArn` is
        # the other -- it names the resource that called, which sts:AssumeRole
        # does not populate for an `AWS: "*"` principal. Both used to read as
        # narrowings because the check was `bool(conditions)`.
        names_who = scope in ("internal", "organization", "external",
                              "unsettled")
        excluded = _principal_values(st.get("NotPrincipal"))
        if excluded:
            # An allow on NotPrincipal admits every principal it does not name,
            # which is the widest grant a trust policy can express. Reading only
            # `Principal` meant this statement produced nothing at all.
            out.append({"kind": "aws", "who": "*", "reach": "anyone",
                        "why": "everyone EXCEPT %s — a NotPrincipal allow names "
                               "who is kept out, not who is let in"
                               % ", ".join(_mask_account_ids(v)
                                           for _k, v in excluded[:3])})
            continue
        for kind, value in _principal_values(st.get("Principal")):
            if kind.lower() == "service":
                out.append({"kind": "service", "who": value, "reach": "service",
                            "why": "an AWS service assumes this role"})
                continue
            if kind.lower() == "federated":
                out.append(_federated_reach(value, conditions, account,
                                            negated))
                continue
            if value == "*":
                if scope == "inverted":
                    # The policy names who is kept OUT. A role every account on
                    # AWS except this one can assume was filed as internal
                    # (review 2, R-18).
                    out.append({"kind": "aws", "who": "*", "reach": "anyone",
                                "why": "ANY AWS principal — the condition "
                                       "admits %s, which is wider than the "
                                       "`*` it sits beside, not narrower"
                                       % who})
                elif names_who:
                    # `organization` is its own answer. Collapsing it into
                    # `external` filed a `*` narrowed to aws:PrincipalOrgID as
                    # a role outside the account, while the identical condition
                    # on an SNS topic was read as "the answer to who" and
                    # produced nothing -- the scale disagreeing with itself
                    # (review 2, R-25).
                    out.append({"kind": "aws", "who": "*",
                                "reach": scope if scope in
                                ("internal", "organization", "unsettled")
                                else "external",
                                "why": "any principal, narrowed to %s" % who})
                elif conditions:
                    out.append({"kind": "aws", "who": "*", "reach": "anyone",
                                "why": "ANY AWS principal — the condition on %s "
                                       "narrows something other than who"
                                       % ", ".join(sorted(conditions))})
                else:
                    out.append({"kind": "aws", "who": "*", "reach": "anyone",
                                "why": "ANY AWS principal, with no condition "
                                       "narrowing it"})
                continue
            found = _ACCOUNT_IN_ARN.search(value)
            other = found.group(0) if found else ""
            if other and account and other != account:
                where, why = _inside_the_organization(other, org)
                out.append({"kind": "aws", "who": value,
                            "reach": ORGANIZATION_REACH.get(where, "external"),
                            "why": why or ("a principal in account %s"
                                           % mask_account(other))})
            else:
                out.append({"kind": "aws", "who": value, "reach": "internal",
                            "why": "a principal in this account"})
    return out


# What `_inside_the_organization` can say, mapped to a reach. "unlisted" is
# the fourth answer: the organization is known and its members are not, so a
# foreign account is neither a sibling nor a stranger.
ORGANIZATION_REACH = {"management": "organization", "member": "organization",
                      "unlisted": "unsettled"}


def _inside_the_organization(other: str,
                             org: "Optional[dict]") -> Tuple[str, str]:
    """Where another account stands to this organization: "management",
    "member", "unlisted", or "" for a stranger or no organization to compare.

    The management account is called out by name because it is the one that
    matters: `OrganizationAccountAccessRole` trusts it in every account
    Organizations creates, and a role trusting it is how an organization is
    administered rather than a grant to a third party.

    "unlisted" exists because a member account's audit role is usually NOT
    allowed to call list-accounts. With only member-or-stranger to choose
    from, every sibling read as a stranger on that ordinary path, and a role
    trusting one was a CRITICAL under a 7700 saying the exposure is live
    (review 3, R-37). Not settled is its own answer.
    """
    if not isinstance(org, dict) or org.get("standalone"):
        return "", ""
    if other and other == str(org.get("management") or ""):
        return "management", ("this organization's management account, which "
                              "is what OrganizationAccountAccessRole and its "
                              "kind trust")
    # A list of account ids, not of rows -- `_rows` keeps mappings and would
    # quietly return nothing here, which is the silent-empty shape this whole
    # tool exists to refuse.
    listed = org.get("accounts")
    members = {str(a) for a in listed if a} if isinstance(listed, list) else set()
    if other and other in members:
        return "member", "another account in this organization"
    if other and org.get("id") and not org.get("accounts_listed", bool(members)):
        return "unlisted", ("an account that may be in this organization: "
                            "the organization answered and its account list "
                            "was refused, so this could not be settled")
    return "", ""


_ACCOUNT_IN_ARN = re.compile(r"(?<![0-9])\d{12}(?![0-9])")


def _github_sub_scope(sub: str) -> str:
    """How much of a GitHub `sub` claim actually pins the caller.

    A GitHub OIDC subject reads `repo:<owner>/<name>:<context>`, and the three
    parts narrow by very different amounts. Everything before the first slash
    is the owner, and a wildcard there is not a narrowing at all: `repo:*/*`,
    `repo:*:*` and `repo:*` each admit every repository on GitHub, which is the
    exact configuration this whole function exists to name. The previous test
    was `sub.startswith("*")`, so all three came back "pinned" and no finding
    fired (review R-5, reproduction 4).

    Returns "loose" (pins nobody), "organization" (pins the owner but not the
    repository) or "repository" (pins both).
    """
    value = sub.strip()
    if not value or value == "*":
        return "loose"
    body = value[len("repo:"):] if value.startswith("repo:") else value
    owner = body.split("/", 1)[0]
    if not owner or "*" in owner or "?" in owner:
        return "loose"
    if "/" not in body:
        return "organization"
    name = body.split("/", 1)[1].split(":", 1)[0]
    if not name or "*" in name or "?" in name:
        return "organization"
    return "repository"


def _federated_reach(value: str, conditions: Dict[str, List[str]],
                     account: str = "",
                     negated: "Optional[frozenset]" = None) -> dict:
    """A federated principal, and whether anything narrows it.

    GitHub Actions is called out by name because the failure has a shape: a
    role trusted by GitHub's OIDC provider with no condition on the `sub` claim
    is assumable from ANY repository on GitHub, not only yours. It is a known
    and exploited misconfiguration, and it looks identical to a correct
    configuration until you read the condition.

    `negated` is the set of condition keys a negated operator sits on. This
    reader takes the flattened map, which has no operators in it, so a
    `StringNotLike` on `sub` -- a denylist -- read as a pin to whatever
    organization it happened to name (review 3, R-39). A negated key narrows
    nothing about who; it says who is kept out."""
    negated = negated or frozenset()
    if GITHUB_OIDC in value:
        sub_key = "%s:sub" % GITHUB_OIDC
        if sub_key in negated:
            return {"kind": "federated", "who": value, "reach": "anyone",
                    "pin": "nothing",
                    "why": "GitHub Actions OIDC whose sub condition is a "
                           "NEGATED test — a denylist that keeps the named "
                           "repositories out and admits every other repository "
                           "on GitHub, so it pins nothing"}
        subs = conditions.get(sub_key, [])
        if not subs:
            return {"kind": "federated", "who": value, "reach": "anyone",
                    "pin": "nothing",
                    "why": "GitHub Actions OIDC with NO condition on the sub "
                           "claim — any repository on GitHub can assume this "
                           "role, not only yours"}
        scopes = [(sub, _github_sub_scope(sub)) for sub in subs]
        loose = [sub for sub, scope in scopes if scope == "loose"]
        if loose:
            return {"kind": "federated", "who": value, "reach": "anyone",
                    "pin": "nothing",
                    "why": "GitHub Actions OIDC whose sub condition (%s) has a "
                           "wildcard where the owner belongs, so any repository "
                           "on GitHub matches it, not only yours"
                           % ", ".join(loose[:2])}
        org = [sub for sub, scope in scopes if scope == "organization"]
        if org:
            return {"kind": "federated", "who": value, "reach": "federated",
                    "pin": "github-organisation",
                    "why": "GitHub Actions OIDC pinned to the organization, "
                           "not the repository (%s) — any repository in it can "
                           "assume this role" % ", ".join(org[:2])}
        return {"kind": "federated", "who": value, "reach": "federated",
                "pin": "github-repository",
                "why": "GitHub Actions OIDC, pinned to %s"
                       % ", ".join(subs[:2])}
    if COGNITO_PROVIDER in value:
        return _cognito_reach(value, conditions)
    # Only the keys that AFFIRM something narrow who; the rest say who is
    # kept out and leave everyone else in.
    narrowing = {k: v for k, v in conditions.items() if k not in negated}
    provider = next((m for m in FEDERATION_PROVIDERS if m in value), "")
    if provider:
        # The provider IS the guard. A role trusted by a SAML provider can only
        # be assumed with an assertion that provider signed, so the absence of
        # the conventional `SAML:aud` condition does not make it assumable by
        # anyone -- it made an Okta-backed administrator role read as CRITICAL
        # (review 2, R-26). Whose provider it is still matters.
        owner = _ACCOUNT_IN_ARN.search(value)
        outside = bool(owner and account and owner.group(0) != account)
        kind = "SAML" if provider == ":saml-provider/" else "OIDC"
        if not narrowing:
            return {"kind": "federated", "who": value,
                    "reach": "external" if outside else "federated",
                    "pin": "%s-unpinned" % kind.lower(),
                    "why": "a %s provider %s, with no condition on the "
                           "assertion. The provider decides who it signs for, "
                           "so this is not open to anyone — but nothing here "
                           "pins WHICH identity it admits"
                           % (kind, "in another account" if outside
                              else "this account created")}
        return {"kind": "federated", "who": value,
                "reach": "external" if outside else "federated",
                "pin": kind.lower(),
                "why": "a %s provider %s, narrowed by %s"
                       % (kind, "in another account" if outside
                          else "this account created",
                          ", ".join(sorted(narrowing)))}
    if not narrowing:
        # A public web identity -- Google, Facebook, Login with Amazon -- with
        # nothing pinning the subject really is assumable by any account on
        # that provider, which is what this branch is for.
        return {"kind": "federated", "who": value, "reach": "anyone",
                "why": "a federated provider with no condition narrowing which "
                       "identity it admits%s"
                       % (" — its only condition is a negated test, which "
                          "keeps some identities out and admits the rest"
                          if conditions else "")}
    return {"kind": "federated", "who": value, "reach": "federated",
            "pin": "condition",
            "why": "a federated provider, narrowed by %s"
                   % ", ".join(sorted(narrowing))}

COGNITO_PROVIDER = "cognito-identity.amazonaws.com"
COGNITO_AMR = "%s:amr" % COGNITO_PROVIDER
COGNITO_AUD = "%s:aud" % COGNITO_PROVIDER


def _cognito_reach(value: str, conditions: Dict[str, List[str]]) -> dict:
    """A Cognito identity pool role, read by what its `amr` claim says.

    An identity pool hands GUEST callers a role whose trust carries
    `amr = unauthenticated`. Anyone who knows the pool id -- which is not a
    secret; it ships in the client -- can assume it, by design. Two condition
    keys were present, so it read as narrowed and produced nothing at all
    (review 2, R-28).
    """
    amr = [v.lower() for v in conditions.get(COGNITO_AMR, [])]
    if any("unauthenticated" in v for v in amr):
        return {"kind": "federated", "who": value, "reach": "anyone",
                "pin": "cognito-guest",
                "why": "a Cognito identity pool's GUEST role — the trust "
                       "policy matches amr=unauthenticated, so anyone who "
                       "knows the pool id can assume it. That is what an "
                       "unauthenticated identity pool is for; what matters is "
                       "what the role can do"}
    if any("authenticated" in v for v in amr):
        return {"kind": "federated", "who": value, "reach": "federated",
                "pin": "cognito",
                "why": "a Cognito identity pool role for signed-in callers "
                       "(amr=authenticated)"}
    if conditions.get(COGNITO_AUD):
        return {"kind": "federated", "who": value, "reach": "federated",
                "pin": "cognito-pool",
                "why": "a Cognito identity pool role pinned to one pool, with "
                       "no amr condition — whether a GUEST of that pool can "
                       "assume it is decided by the pool's own setting, which "
                       "is not read here"}
    return {"kind": "federated", "who": value, "reach": "anyone",
            "why": "a Cognito identity pool role with no condition on the pool "
                   "or on amr"}


# Widest first. `organization` had no rank and fell to the fallback of 9,
# which put it NARROWER than internal: a role with one statement trusting a
# sibling account and one trusting a principal here reported its reach as
# internal (review 3). `unsettled` sits between external and federated --
# wider than a known federation, and not known to be outside.
REACH_RANK = {"anyone": 0, "external": 1, "unsettled": 2, "federated": 3,
              "organization": 4, "service": 5, "internal": 6}


def widest_reach(entries: List[dict]) -> str:
    """The widest way in, because a role is as reachable as its loosest
    statement — the tight ones do not make up for it."""
    if not entries:
        return "unknown"
    return min((e["reach"] for e in entries), key=lambda r: REACH_RANK.get(r, 9))


def _user_credentials(name: str, timeout: int) -> dict:
    """MFA devices and access keys for one user, as reads.

    The credential report would give both in one call and generating one is a
    write, so this asks the two questions directly instead."""
    mfa_count: Optional[int] = None
    key_rows: List[dict] = []
    unreadable: List[str] = []
    unreadable_console = ""
    # Does this user have a console password? The credential report answers it
    # and generating one is a write, so ask directly. Without this the rule
    # below silently skipped a user with a console password and no MFA -- the
    # classic finding -- because it had no access key. Measured against a real
    # account: the tile said "2 without an MFA device" and one of them was
    # never explained (2026-09-09).
    console: Optional[bool] = None
    profile, why = _aws_json(["iam", "get-login-profile", "--user-name", name],
                             timeout)
    if profile is not None:
        console = bool(profile.get("LoginProfile"))
    elif "nosuchentity" in why.lower() or "cannot be found" in why.lower():
        console = False                  # no console password: a real answer
    else:
        unreadable_console = why
    mfa, why = _aws_json(["iam", "list-mfa-devices", "--user-name", name], timeout)
    if mfa is None:
        unreadable.append("MFA devices (%s)" % why)
    else:
        mfa_count = len(_rows(mfa.get("MFADevices")))
    keys, why = _aws_json(["iam", "list-access-keys", "--user-name", name], timeout)
    if keys is None:
        unreadable.append("access keys (%s)" % why)
    else:
        key_rows = [{"id": str(k.get("AccessKeyId", "")),
                     "status": str(k.get("Status", "")),
                     "created": str(k.get("CreateDate", ""))}
                    for k in _rows(keys.get("AccessKeyMetadata"))]
    if unreadable_console:
        unreadable.append("console access (%s)" % unreadable_console)
    return {"mfa": mfa_count, "keys": key_rows, "console": console,
            "unreadable": unreadable}


def aws_iam_graph(ctx: "RunContext") -> "Union[str, Tuple[str, str, str]]":
    """The account's whole permission model, and what it lets people become."""
    if not tool_path("aws"):
        return (json.dumps({"users": [], "counts": {}}, indent=2), "error",
                "aws CLI not installed — nothing was read")
    _CALLS["n"] = 0
    started = time.monotonic()
    call_timeout = _budget(ctx, "cloud_call_timeout", 30)
    limit = _budget(ctx, "cloud_max_principals", 1000)
    # This stage had no deadline at all. Every other cloud stage is bounded by
    # cloud_inventory_budget, and this one asks three questions per user, so on
    # an account with many users it was the stage with no ceiling (R-13).
    budget = _budget(ctx, "cloud_inventory_budget", 600)
    deadline = time.monotonic() + budget
    # What the organization stage read earlier in this run, if it ran at all.
    org = organization_read(ctx)

    ident, why = _aws_json(["sts", "get-caller-identity"], call_timeout)
    if ident is None or not ident.get("Account"):
        return (json.dumps({"users": [], "counts": {}}, indent=2), "error",
                "could not resolve an AWS identity: %s — nothing was read"
                % (why or "no Account in the response"))

    details, why = _aws_json(["iam", "get-account-authorization-details",
                              "--max-items", str(limit)], call_timeout)
    if details is None:
        return (json.dumps({"users": [], "counts": {}}, indent=2), "error",
                "could not read the IAM graph: %s — every conclusion below "
                "would have been about nothing" % why)

    users = _rows(details.get("UserDetailList"))
    roles = _rows(details.get("RoleDetailList"))
    groups = {str(g.get("GroupName", "")): g
              for g in _rows(details.get("GroupDetailList"))}
    docs = _policy_docs_by_arn(details)

    rows = []
    users_unread = 0
    for user in users:
        name = str(user.get("UserName", ""))
        if not name:
            continue
        if time.monotonic() >= deadline:
            # Recorded, not dropped. iam_findings already reports a user whose
            # MFA could not be read as unknown, and the coverage extractor
            # already counts it -- so the honest thing is to hand them a user
            # with nothing read rather than a shorter list (I12, I14).
            users_unread += 1
            rows.append({
                "name": name, "arn": str(user.get("Arn", "")),
                "created": str(user.get("CreateDate", "")),
                "groups": [str(g) for g in (user.get("GroupList") or [])],
                "mfa": None, "keys": [], "console": None,
                "unreadable": ["the %ds budget ran out before this user was "
                               "read" % budget],
                "self_service": [], "scoped": [], "notes": [],
                "escalation": []})
            continue
        creds = _user_credentials(name, call_timeout)
        read = _principal_reasons(user, docs, groups, "user")
        rows.append({
            "name": name, "arn": str(user.get("Arn", "")),
            "created": str(user.get("CreateDate", "")),
            "groups": [str(g) for g in (user.get("GroupList") or [])],
            "mfa": creds["mfa"], "keys": creds["keys"],
            "console": creds["console"],
            "unreadable": creds["unreadable"],
            # Kept apart on purpose. Managing your own access keys is not a
            # path to more, and folding it into `escalation` is what made
            # AWS's own self-service policy read as three of them (R-4).
            "self_service": read.self_service,
            "scoped": read.scoped,
            "notes": read.notes,
            "escalation": read.escalation})

    role_rows, admin_roles, all_roles = [], [], []
    for role in roles:
        name = str(role.get("RoleName", ""))
        read = _principal_reasons(role, docs, groups, "role")
        reasons = read.escalation
        # Every role, not only the ones with something to say about them. The
        # IAM tile counts roles and the reader can open that count, so the
        # members have to be in the evidence: with only the flagged ones kept,
        # a page saying 140 roles expanded to the three that could escalate.
        # The trust policy is already in this response, so `reach` costs
        # nothing but the parse.
        trust_all = who_can_assume(role.get("AssumeRolePolicyDocument"),
                                   str(ident["Account"]), org)
        all_roles.append({"name": name, "reach": widest_reach(trust_all),
                          "escalation": len(escalation_only(reasons)),
                          "admin": is_already_admin(reasons)})
        if not reasons:
            continue
        # The trust policy was already in this response and was being dropped.
        # Escalation says what a role can do; this says who can make it do it,
        # and the second is what turns eleven undifferentiated flags into a
        # ranked answer.
        row = {"name": name, "arn": str(role.get("Arn", "")),
               "trust": trust_all, "reach": widest_reach(trust_all)}
        if is_already_admin(reasons):
            admin_roles.append(dict(row, why=reasons[:2]))
            continue
        role_rows.append(dict(row, escalation=reasons,
                              self_service=read.self_service,
                              scoped=read.scoped, notes=read.notes))

    payload = {
        "account": str(ident["Account"]),
        # The ARN, with the ADDRESS out of it. Attribution needs the
        # account id and keeps it; nothing needs the operator's email,
        # and evidence outlives the run (PRODUCT rule 6, review R-3).
        "read_as": mask_email(ident.get("Arn", "")),
        "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api_calls": _CALLS["n"],
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "truncated": bool(details.get("NextToken") or details.get("IsTruncated")),
        "limit": limit,
        "budget": budget,
        "users_unread": users_unread,
        "counts": {"users": len(users), "roles": len(roles),
                   "groups": len(groups), "policies": len(_rows(details.get("Policies")))},
        "users": rows,
        "roles": all_roles,
        "roles_with_escalation": role_rows,
        "roles_already_admin": admin_roles,
    }
    # A user whose MFA, keys or console access could not be read is already
    # recorded per user and already reported as unknown by iam_findings. What
    # did not happen was the ledger row moving off `ok`, so the Scan page
    # showed a clean IAM stage over a run that had been refused
    # `list-mfa-devices` (denial sweep, 2026-09-12).
    refused = ["%s: %s" % (row["name"], why)
               for row in rows for why in (row.get("unreadable") or [])]
    return _partial(json.dumps(payload, indent=2, sort_keys=True),
                    refused, "identity read(s)")



# --------------------------------------------------------------------------- #
# The edge — what the internet can actually talk to.
#
# The inventory counts instances. On a container-first account that is the
# wrong denominator: a hundred and three network interfaces against seven
# instances says the workloads are Lambda, ECS tasks and load balancers, and
# none of those were read at all. Every reachability rule shipped so far was
# about an EC2 instance, so an account like that got a clean answer from checks
# that had no subject.
# --------------------------------------------------------------------------- #

# What an interface's type means, in the words an operator uses. AWS's own
# InterfaceType values are terse and a few of the important ones only show up
# in the description.
ENI_KINDS = (
    ("lambda", "Lambda function"),
    ("network_load_balancer", "network load balancer"),
    ("gateway_load_balancer", "gateway load balancer"),
    ("vpc_endpoint", "VPC endpoint"),
    ("nat_gateway", "NAT gateway"),
    ("transit_gateway", "transit gateway"),
    ("efa", "EFA adapter"),
    ("branch", "branch interface"),
    # `interface` is deliberately NOT in this table. It is the DEFAULT
    # InterfaceType and means "an ordinary elastic network interface", which is
    # true of most of the entries above as well -- so rendering it as a
    # category produced a tile reading "interface · 7", which looks like an
    # answer and is not one (measured on a real account, 2026-09-09). An
    # interface whose owner we could not name is reported as unattributed,
    # because "we did not work it out" and "it is an interface" are different
    # statements.
)


def eni_owner(eni: dict) -> str:
    """Who owns one network interface, from its type and description."""
    kind = str(eni.get("InterfaceType", "")).lower()
    desc = str(eni.get("Description", ""))
    low = desc.lower()
    if eni.get("InstanceId"):
        return "EC2 instance"
    if kind == "lambda" or low.startswith("aws lambda vpc"):
        return "Lambda function"
    if low.startswith("elb app/") or low.startswith("elb net/"):
        return "load balancer"
    if low.startswith("elb "):
        return "load balancer (classic)"
    if "arn:aws:ecs" in low:
        return "ECS task"
    if kind == "vpc_endpoint" or low.startswith("vpc endpoint"):
        return "VPC endpoint"
    if kind == "nat_gateway" or low.startswith("interface for nat gateway"):
        return "NAT gateway"
    if kind == "transit_gateway":
        return "transit gateway"
    if low.startswith("rdsnet") or "rds" in low.split():
        return "RDS instance"
    for token, label in ENI_KINDS:
        if kind == token:
            return label
    return "not attributed"


def _partial(payload: str, unreadable: List[str], noun: str) -> "Union[str, Tuple[str, str, str]]":
    """A reading with a failed read in it is a gap, not an ok run.

    Recording the failure in the evidence is half the job; the other half is
    the ledger, and until this existed a stage could write an `unreadable`
    entry and still report `ok` because `_apply_coverage` only degrades a zero
    over an empty denominator. One load balancer read successfully was enough
    to carry a denied `list-functions` through as a clean stage (review R-2).

    An internal stage may return (json, status, detail) to declare its own
    outcome, which is exactly what this is for."""
    if not unreadable:
        return payload
    shown = "; ".join(unreadable[:3])
    if len(unreadable) > 3:
        shown += " and %d more" % (len(unreadable) - 3)
    return (payload, "gap",
            "%d %s could not be read — %s. What was read is here; what was "
            "not is not zero" % (len(unreadable), noun, shown))


def _lambda_functions(region: str, limit: int,
                      timeout: int) -> Tuple[List[dict], bool, str]:
    """(functions, more than the limit, why the read failed).

    The third value used to be dropped, and a denied `list-functions` produced
    an empty list and no record of the denial -- so the edge stage wrote zero
    functions, the coverage note counted zero errors, and the page said "no
    function URL is open without authentication ... read, not assumed" about a
    read that never happened (review R-2)."""
    data, why = _aws_json(["lambda", "list-functions", "--region", region,
                           "--max-items", str(limit)], timeout)
    if data is None:
        return [], False, why
    rows = [{"name": str(f.get("FunctionName", "")),
             "role": str(f.get("Role", "")),
             "in_vpc": bool((f.get("VpcConfig") or {}).get("SubnetIds"))}
            for f in _rows(data.get("Functions"))]
    return rows, bool(data.get("NextToken") or data.get("NextMarker")), ""


def _function_url(region: str, name: str, timeout: int) -> Optional[dict]:
    """A function's URL configuration, or None when it has none.

    "No URL" is the common case and comes back as an error, so the error text
    is the answer -- distinguished from a permissions failure, which is not."""
    data, why = _aws_json(["lambda", "list-function-url-configs",
                           "--function-name", name, "--region", region], timeout)
    if data is None:
        low = why.lower()
        if "resourcenotfound" in low or "not found" in low:
            return None
        return {"auth": "unknown", "url": "", "why": why, "cors": []}
    configs = _rows(data.get("FunctionUrlConfigs"))
    if not configs:
        return None
    conf = configs[0]
    cors = (conf.get("Cors") or {}).get("AllowOrigins") or []
    return {"auth": str(conf.get("AuthType", "")),
            "url": str(conf.get("FunctionUrl", "")), "why": "",
            "cors": [str(c) for c in cors if isinstance(c, str)]}


def _load_balancers(region: str, timeout: int) -> Tuple[List[dict], List[str]]:
    out: List[dict] = []
    unreadable: List[str] = []
    data, why = _aws_json(["elbv2", "describe-load-balancers",
                           "--region", region], timeout)
    if data is None:
        unreadable.append("application/network load balancers (%s)" % why)
    else:
        for lb in _rows(data.get("LoadBalancers")):
            out.append({"name": str(lb.get("LoadBalancerName", "")),
                        "scheme": str(lb.get("Scheme", "")),
                        "type": str(lb.get("Type", "")),
                        "vpc": str(lb.get("VpcId", "")),
                        "groups": [str(g) for g in (lb.get("SecurityGroups") or [])],
                        "dns": str(lb.get("DNSName", ""))})
    classic, why = _aws_json(["elb", "describe-load-balancers",
                              "--region", region], timeout)
    if classic is None:
        unreadable.append("classic load balancers (%s)" % why)
    else:
        for lb in _rows(classic.get("LoadBalancerDescriptions")):
            out.append({"name": str(lb.get("LoadBalancerName", "")),
                        "scheme": str(lb.get("Scheme", "")),
                        "type": "classic",
                        "vpc": str(lb.get("VPCId", "")),
                        "groups": [str(g) for g in (lb.get("SecurityGroups") or [])],
                        "dns": str(lb.get("DNSName", ""))})
    return out, unreadable


def aws_edge(ctx: "RunContext") -> "Union[str, Tuple[str, str, str]]":
    """Lambda functions and their URLs, and load balancers, per region."""
    if not tool_path("aws"):
        return (json.dumps({"regional": {}}, indent=2), "error",
                "aws CLI not installed — nothing was read")
    _CALLS["n"] = 0
    started = time.monotonic()
    budget = _budget(ctx, "cloud_inventory_budget", 600)
    call_timeout = _budget(ctx, "cloud_call_timeout", 30)
    limit = _budget(ctx, "cloud_max_functions", 500)
    deadline = time.monotonic() + budget

    ident, why = _aws_json(["sts", "get-caller-identity"], call_timeout)
    if ident is None or not ident.get("Account"):
        return (json.dumps({"regional": {}}, indent=2), "error",
                "could not resolve an AWS identity: %s — nothing was read"
                % (why or "no Account in the response"))

    regions, region_why = _enabled_regions(call_timeout)
    if not regions:
        return (json.dumps({"account": str(ident["Account"]), "regional": {}},
                           indent=2), "error",
                "could not list the account's regions: %s — a per-region "
                "answer with no denominator would be a guess"
                % (region_why or "none returned"))

    regional: Dict[str, dict] = {}
    unread: List[str] = []
    truncated = False
    for region in regions:
        if time.monotonic() >= deadline:
            unread.append(region)
            continue
        functions, more, why = _lambda_functions(region, limit, call_timeout)
        truncated = truncated or more
        lambda_bad = ["Lambda functions (%s)" % why] if why else []
        urls = []
        for fn in functions:
            if time.monotonic() >= deadline:
                # Entered, not finished. Recording it as never read put this
                # region in regions_read AND regions_unread at the same time,
                # while keeping the functions it had already found (R-13).
                lambda_bad.append("function URLs in %s (%s)"
                                  % (region, BUDGET_MARK))
                break
            conf = _function_url(region, fn["name"], call_timeout)
            if conf:
                urls.append(dict(fn, **conf))
                # "No URL" is an answer and comes back as an error, so
                # `_function_url` reads the error text to tell the two apart.
                # A refusal takes the other branch and lands here with
                # auth "unknown" — a URL whose authentication nobody could
                # read, which is exactly the row that must not sit under a
                # green stage (denial sweep, 2026-09-12).
                if conf.get("auth") == "unknown" and conf.get("why"):
                    lambda_bad.append("URL auth for %s in %s (%s)"
                                      % (fn["name"], region, conf["why"]))
        balancers, unreadable = _load_balancers(region, call_timeout)
        # The functions themselves, not how many. Keeping only the count meant
        # the page could show 18 and had nothing to expand it to: the drill-down
        # rendered one row reading "18 function(s)", which is the number again
        # rather than what is behind it. A count whose members are not in the
        # evidence is a claim a reader cannot check.
        regional[region] = {"functions": functions, "urls": urls,
                            "load_balancers": balancers,
                            "unreadable": lambda_bad + unreadable}

    payload = {
        "account": str(ident["Account"]),
        # The ARN, with the ADDRESS out of it. Attribution needs the
        # account id and keeps it; nothing needs the operator's email,
        # and evidence outlives the run (PRODUCT rule 6, review R-3).
        "read_as": mask_email(ident.get("Arn", "")),
        "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api_calls": _CALLS["n"],
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "truncated": truncated, "limit": limit,
        "regions_enabled": regions,
        "regions_read": sorted(set(regional) - set(_partial_regions(regional))),
        "regions_partial": _partial_regions(regional),
        "regions_unread": sorted(set(unread)),
        "regional": regional,
    }
    body = json.dumps(payload, indent=2, sort_keys=True)
    return _partial(body, [w for per in regional.values()
                           if isinstance(per, dict)
                           for w in (per.get("unreadable") or [])],
                    "read(s)")



# --------------------------------------------------------------------------- #
# Storage — where the data actually is.
#
# S3 and RDS carry the two combinations that put organisations in the news, and
# both are joins: public AND unencrypted, reachable AND unencrypted. Neither
# half is a finding on its own -- a public bucket may be a website, and an
# unencrypted one may hold nothing that matters.
#
# The account-wide S3 block changes what a per-bucket answer MEANS, which is
# why this reading is judged against the enablement reading rather than alone:
# with `BlockPublicPolicy` and `RestrictPublicBuckets` on, a bucket policy that
# says "public" does not make the bucket public. Reporting it as live exposure
# would be true about the policy and false about the world.
# --------------------------------------------------------------------------- #

# The four settings of an S3 public access block. The first two decide whether
# an ACL can make a bucket public; the last two decide whether a POLICY can.
BLOCK_SETTINGS = ("BlockPublicAcls", "IgnorePublicAcls",
                  "BlockPublicPolicy", "RestrictPublicBuckets")

# The two that hold a public POLICY shut. Squawk reads policy status, not ACLs,
# so these are the two its own finding depends on.
POLICY_BLOCK_SETTINGS = ("BlockPublicPolicy", "RestrictPublicBuckets")


def _bucket_facts(name: str, region: str, timeout: int) -> dict:
    """One bucket's public/encryption state, or why each is unknown."""
    row: Dict[str, object] = {"name": name, "region": region,
                              "public": None, "encrypted": None,
                              "block": None, "unreadable": []}
    unreadable: List[str] = []
    args = ["--region", region] if region else []

    status, why = _aws_json(["s3api", "get-bucket-policy-status",
                             "--bucket", name, *args], timeout)
    if status is None:
        low = why.lower()
        if "nosuchbucketpolicy" in low:
            row["public"] = False          # no policy at all: a real answer
        else:
            unreadable.append("policy status (%s)" % why)
    else:
        row["public"] = bool((status.get("PolicyStatus") or {}).get("IsPublic"))

    block, why = _aws_json(["s3api", "get-public-access-block",
                            "--bucket", name, *args], timeout)
    if block is None:
        if "nosuchpublicaccessblock" in why.lower():
            # Configured with nothing on: a real answer, and all four off.
            row["block"] = dict.fromkeys(BLOCK_SETTINGS, False)
        else:
            unreadable.append("public access block (%s)" % why)
    else:
        # The four settings, not how many are on. Two of them decide whether
        # a public POLICY takes effect and the other two are about ACLs, so a
        # count of three could be either answer -- which is one reason this
        # field was written and never read, and a bucket whose own block was
        # holding a public policy shut was reported as "reachable by anyone"
        # (review R-6).
        conf = block.get("PublicAccessBlockConfiguration") or {}
        row["block"] = {key: bool(conf.get(key)) for key in BLOCK_SETTINGS}

    enc, why = _aws_json(["s3api", "get-bucket-encryption",
                          "--bucket", name, *args], timeout)
    if enc is None:
        if "serversideencryptionconfigurationnotfound" in why.lower():
            row["encrypted"] = False
        else:
            unreadable.append("encryption (%s)" % why)
    else:
        rules = _rows((enc.get("ServerSideEncryptionConfiguration") or {})
                      .get("Rules"))
        row["encrypted"] = bool(rules)
    row["unreadable"] = unreadable
    return row


def _databases(region: str, timeout: int) -> Tuple[List[dict], List[str]]:
    out: List[dict] = []
    unreadable: List[str] = []
    data, why = _aws_json(["rds", "describe-db-instances", "--region", region],
                          timeout)
    if data is None:
        unreadable.append("database instances (%s)" % why)
    else:
        for db in _rows(data.get("DBInstances")):
            subnets = [str(s.get("SubnetIdentifier", "")) for s in
                       _rows((db.get("DBSubnetGroup") or {}).get("Subnets"))]
            out.append({
                "id": str(db.get("DBInstanceIdentifier", "")),
                "kind": "instance",
                "engine": str(db.get("Engine", "")),
                "public": bool(db.get("PubliclyAccessible")),
                "encrypted": bool(db.get("StorageEncrypted")),
                # The port the group has to admit for the flag to mean
                # anything. Without it the join can only ask about every port.
                "port": (db.get("Endpoint") or {}).get("Port"),
                "subnets": subnets,
                "groups": [str(g.get("VpcSecurityGroupId", "")) for g in
                           _rows(db.get("VpcSecurityGroups"))]})
    # A cluster names its subnet group and does not expand it, so without this
    # one call every Aurora cluster's subnet leg would be permanently unknown
    # and the reachability join could never answer about one.
    groups_by_name: Dict[str, List[str]] = {}
    subnet_groups, why = _aws_json(
        ["rds", "describe-db-subnet-groups", "--region", region], timeout)
    if subnet_groups is None:
        unreadable.append("database subnet groups (%s)" % why)
    else:
        for grp in _rows(subnet_groups.get("DBSubnetGroups")):
            groups_by_name[str(grp.get("DBSubnetGroupName", ""))] = [
                str(sub.get("SubnetIdentifier", ""))
                for sub in _rows(grp.get("Subnets"))]

    clusters, why = _aws_json(["rds", "describe-db-clusters", "--region", region],
                              timeout)
    if clusters is None:
        unreadable.append("database clusters (%s)" % why)
    else:
        for db in _rows(clusters.get("DBClusters")):
            out.append({
                "id": str(db.get("DBClusterIdentifier", "")),
                "kind": "cluster",
                "engine": str(db.get("Engine", "")),
                "public": bool(db.get("PubliclyAccessible")),
                "encrypted": bool(db.get("StorageEncrypted")),
                "port": db.get("Port"),
                # A cluster's subnets come from its subnet group, which
                # describe-db-clusters names but does not expand.
                "subnet_group": str(db.get("DBSubnetGroup", "")),
                "subnets": groups_by_name.get(
                    str(db.get("DBSubnetGroup", "")), []),
                "groups": [str(g.get("VpcSecurityGroupId", "")) for g in
                           _rows(db.get("VpcSecurityGroups"))]})
    return out, unreadable


def _account_block_beside(raw_path: str) -> "Optional[bool]":
    """Whether the account-wide S3 block is fully on, from the enablement
    reading written earlier in this same run. None when it is not there --
    unknown, which the caller treats as the stricter answer."""
    if not raw_path:
        return None
    sibling = os.path.join(os.path.dirname(raw_path), "cloud-enablement.json")
    try:
        with open(sibling, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    row = (data.get("account") or {}).get("s3block") or {}
    return str(row.get("state", "")) == "on"


def aws_storage(ctx: "RunContext") -> "Union[str, Tuple[str, str, str]]":
    """Buckets and databases, and whether they are public or unencrypted."""
    if not tool_path("aws"):
        return (json.dumps({"buckets": [], "databases": {}}, indent=2), "error",
                "aws CLI not installed — nothing was read")
    _CALLS["n"] = 0
    started = time.monotonic()
    budget = _budget(ctx, "cloud_inventory_budget", 600)
    call_timeout = _budget(ctx, "cloud_call_timeout", 30)
    limit = _budget(ctx, "cloud_max_buckets", 100)
    deadline = time.monotonic() + budget

    ident, why = _aws_json(["sts", "get-caller-identity"], call_timeout)
    if ident is None or not ident.get("Account"):
        return (json.dumps({"buckets": [], "databases": {}}, indent=2), "error",
                "could not resolve an AWS identity: %s — nothing was read"
                % (why or "no Account in the response"))

    # Whether the account-wide S3 block is on changes what a public bucket
    # POLICY means, and the enablement stage already answered it earlier in
    # this same run. Read from its evidence beside ours rather than asked
    # again -- and recorded HERE, in this reading, because the reading is what
    # a later reader has. A normalizer receives the scan base, not the run
    # directory, so a lookup at that layer would have silently found nothing:
    # the same relative-path trap that made cloud_correlations return an empty
    # list on every real run.
    account_block = _account_block_beside(getattr(ctx, "raw_path", ""))

    listed, why = _aws_json(["s3api", "list-buckets"], call_timeout)
    buckets: List[dict] = []
    bucket_total = 0
    bucket_error = ""
    if listed is None:
        bucket_error = why
    else:
        names = [str(b.get("Name", "")) for b in _rows(listed.get("Buckets"))
                 if b.get("Name")]
        bucket_total = len(names)
        for name in names[:limit]:
            if time.monotonic() >= deadline:
                break
            where, why = _aws_json(["s3api", "get-bucket-location",
                                    "--bucket", name], call_timeout)
            region = ""
            if where is not None:
                # us-east-1 comes back as null, which is the API saying
                # "the original region" rather than "unknown".
                region = str(where.get("LocationConstraint") or "us-east-1")
            facts = _bucket_facts(name, region, call_timeout)
            if where is None:
                # Every per-bucket call below was made against the default
                # region because this one failed. Whatever they returned is
                # about a guess, and the bucket says so.
                facts["region"] = ""
                facts["unreadable"] = [
                    *facts["unreadable"],
                    "location (%s) — the reads below used the default region"
                    % why]
            buckets.append(facts)

    regions, region_why = _enabled_regions(call_timeout)
    databases: Dict[str, dict] = {}
    unread: List[str] = []
    for region in regions:
        if time.monotonic() >= deadline:
            unread.append(region)
            continue
        rows, unreadable = _databases(region, call_timeout)
        databases[region] = {"databases": rows, "unreadable": unreadable}

    payload = {
        "account": str(ident["Account"]),
        # The ARN, with the ADDRESS out of it. Attribution needs the
        # account id and keeps it; nothing needs the operator's email,
        # and evidence outlives the run (PRODUCT rule 6, review R-3).
        "read_as": mask_email(ident.get("Arn", "")),
        "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api_calls": _CALLS["n"],
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "bucket_total": bucket_total,
        "bucket_limit": limit,
        "bucket_error": bucket_error,
        "account_block_on": account_block,
        "buckets": buckets,
        "regions_enabled": regions,
        "regions_read": sorted(set(databases) - set(_partial_regions(databases))),
        "regions_partial": _partial_regions(databases),
        "regions_unread": sorted(set(unread)),
        "region_error": region_why if not regions else "",
        "databases": databases,
    }
    # The same treatment every other stage got in step 1 of plan 11. This one
    # returned a bare string, so a bucket list that could not be read reached
    # the ledger as `ok` and relied on the coverage denominator to catch it --
    # which stopped catching it once the denominator became reads that
    # answered rather than resources found (review 2, R-20).
    # The region list is the denominator for the database half, and losing it
    # is not the same failure as losing one region's read. Every other regional
    # stage refuses outright when `describe-regions` is denied; this one keeps
    # going because buckets are worth reading on their own. What it must not do
    # is then report `ok`: with no region list, `databases` is empty, and an
    # empty databases map rendered as "0 databases" beside a green stage. That
    # is the silent cap (I12) wearing the coverage machinery's own clothes --
    # `_partial` was fed the per-region failures and never the failure to learn
    # what the regions WERE, so there were no regions to fail (denial sweep,
    # 2026-09-12).
    region_gap = ([] if regions else
                  ["the account's region list (%s), so no region was scoped "
                   "for databases" % (region_why or "none returned")])
    # Both halves, not one. `_partial` was fed the DATABASE failures and the
    # whole-list failure, and never the per-bucket ones — so a refused
    # `get-bucket-policy-status` on every bucket in the account still reported
    # `ok`, and "0 public buckets" was a count of buckets nobody could ask
    # about (denial sweep, 2026-09-12).
    return _partial(json.dumps(payload, indent=2, sort_keys=True),
                    ([bucket_error] if bucket_error else [])
                    + region_gap
                    + ["bucket %s: %s" % (b.get("name", "?"), w)
                       for b in buckets
                       for w in (b.get("unreadable") or [])]
                    + [w for per in databases.values()
                       if isinstance(per, dict)
                       for w in (per.get("unreadable") or [])],
                    "storage read(s)")



# --------------------------------------------------------------------------- #
# The organization — the denominator every other number on the page sits over.
#
# Squawk reads ONE account: whichever the credential chain resolves to. On a
# standalone account that is the whole estate. In an organization it is one of
# many, and every count on the page is then a count about a fraction of the
# estate while looking exactly like a count about all of it.
#
# So this reads the organization's account list and says the fraction out loud.
# It does NOT assume roles into the other accounts: minting credentials would
# mean Squawk holding them, and PRODUCT rule 1 says it never does. What it does
# instead is map the profiles the operator has already configured to the
# accounts they reach, so the answer is "you can reach 3 of 47 from here" --
# a fact the operator can act on, arrived at without a credential.
# --------------------------------------------------------------------------- #

def _org_accounts(timeout: int) -> Tuple[Optional[dict], List[dict], str, str]:
    """The organization and its accounts: (info, accounts, why the
    organization could not be read, why its account list could not).

    Two refusals, kept apart. `describe-organization` failing means nothing
    is known; `list-accounts` failing with the organization answered is the
    ORDINARY member-account run -- an audit role may describe the
    organization and usually may not list it. Returning the second in the
    first's slot made them look alike, so the stage examined zero, became a
    gap, and the banner written for exactly this case never rendered
    (review 3, R-37).

    Emails are deliberately dropped. `list-accounts` returns the root email of
    every account in the organization -- real addresses for real people, which
    this tool has no use for and no business writing into evidence that
    outlives the run."""
    org, why = _aws_json(["organizations", "describe-organization"], timeout)
    if org is None:
        low = why.lower()
        if "awsorganizationsnotinuse" in low:
            return None, [], "standalone", ""
        return None, [], why, ""
    detail = org.get("Organization") or {}
    info = {"id": str(detail.get("Id", "")),
            "feature_set": str(detail.get("FeatureSet", "")),
            "management_account": str(detail.get("MasterAccountId", ""))}
    listed, why = _aws_json(["organizations", "list-accounts"], timeout)
    if listed is None:
        return info, [], "", why
    accounts = [{"id": str(a.get("Id", "")),
                 "name": str(a.get("Name", "")),
                 "status": str(a.get("Status", ""))}
                for a in _rows(listed.get("Accounts")) if a.get("Id")]
    return info, accounts, "", ""


def profiles_ack() -> Tuple[bool, str]:
    """Whether the operator has acknowledged the profile probe specifically.

    A second acknowledgement, on top of SQUAWK_CLOUD_ACK, because it buys
    something different. The cloud ack says "read this estate". This probe
    reads a DIFFERENT thing: it asks every profile in the local CLI config who
    it is, and for a `role_arn` profile that is an AssumeRole into an account
    the operator did not target, while for a `credential_process` profile it
    EXECUTES the configured command. One acknowledgement given for one estate
    does not cover either (review R-12, PRODUCT rule 8).

    The alternative the plan recommended was deleting the probe. Kept and gated
    instead: which of your profiles reach which accounts is your own blast
    radius, and a security tool that cannot tell you that is less useful than
    one that asks first. The gate is the same shape as the cloud ack itself."""
    if env("CLOUD_PROFILES_ACK"):
        return True, "SQUAWK_CLOUD_PROFILES_ACK set"
    return False, ("SQUAWK_CLOUD_PROFILES_ACK not set — the local CLI profiles "
                   "were not asked who they reach. Setting it runs one "
                   "sts:GetCallerIdentity per profile, which assumes a role "
                   "for a role_arn profile and runs the configured command for "
                   "a credential_process one")


CREDENTIAL_PROCESS_KEY = "credential_process"


def profiles_running_a_command(names: List[str]) -> Tuple[List[str], str]:
    """Which of these CLI profiles resolve through a `credential_process`.

    The read-only recorder asserts over every argv the cloud stages build. It
    cannot see what the CLI does with one. A `credential_process` line in the
    CLI's config runs whatever command it names, in this shell, before any
    request is signed -- so `aws sts get-caller-identity` is a read to the
    recorder and a shell command to the machine (review 2, R-33).

    This is not a defect in the recorder; it is the limit of what an argv
    recorder can promise, and the honest answer is to say which profiles carry
    one rather than to pretend the question does not exist. The config is a
    plain INI file and the KEY is what is read -- never the value, which is a
    command line and may carry anything.

    Returns (profile names, why the config could not be read).
    """
    paths = [os.environ.get("AWS_CONFIG_FILE")
             or os.path.expanduser("~/.aws/config"),
             os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
             or os.path.expanduser("~/.aws/credentials")]
    wanted = {n.strip() for n in names if n and n.strip()}
    found: List[str] = []
    read_any = False
    for path in paths:
        if not os.path.isfile(path):
            continue
        parser = configparser.RawConfigParser()
        try:
            with io.open(path, encoding="utf-8", errors="replace") as fh:
                parser.read_file(fh)
            read_any = True
        except (OSError, configparser.Error):
            continue
        for section in parser.sections():
            # `~/.aws/config` writes "[profile name]"; the credentials file
            # writes "[name]". Both are the same profile to the CLI.
            name = section.split(None, 1)[1] if section.startswith("profile ") \
                else section
            if name in wanted and parser.has_option(section,
                                                    CREDENTIAL_PROCESS_KEY):
                found.append(name)
    if not read_any:
        return [], ("no readable AWS CLI config, so whether a profile runs a "
                    "credential_process is unknown")
    return sorted(set(found)), ""


def _profile_accounts(timeout: int, cap: int = 24,
                      deadline: "Optional[float]" = None
                      ) -> Tuple[Dict[str, str], List[str], str]:
    """Which account each configured CLI profile reaches.

    Profile NAMES are read from the CLI's own config listing — never the
    credentials behind them. Each profile is then asked who it is, which is the
    only way to know what it reaches without assuming anything. A profile that
    cannot answer is recorded as unreachable rather than dropped: "this profile
    needs a login" is useful and "this profile does not exist" is false.

    Gated: see profiles_ack. Callers must check it before calling this."""
    code, out, err = run_cmd(["aws", "configure", "list-profiles"], None, timeout)
    if code != 0:
        # Not "no profiles". The list could not be read, so which accounts this
        # machine can reach is unknown -- and an unknown that renders as zero
        # is the substitution I1 exists to refuse (review R-2).
        lines = (err or out or "list-profiles failed").strip().splitlines()
        text = lines[-1] if lines else "list-profiles failed"
        return {}, [], redact_identifiers(text)[:200]
    found = [n.strip() for n in out.splitlines() if n.strip()]
    names = found[:cap]
    reached: Dict[str, str] = {}
    unreachable: List[str] = []
    if len(found) > cap:
        # A cap that is not said is a silent cap (I12).
        unreachable.append("%d more profile(s) beyond cloud_max_profiles=%d "
                           "were not asked" % (len(found) - cap, cap))
    for name in names:
        # Up to `cap` profiles, each an identity call that can take the whole
        # call timeout. Unbounded, that is the one cloud stage with no ceiling
        # -- and a profile the clock cut off is unreachable-unknown, not a
        # profile that does not exist (R-13).
        if deadline is not None and time.monotonic() >= deadline:
            unreachable.append("%s (%s before it was asked)"
                               % (name, BUDGET_MARK))
            continue
        ident, why = _aws_json_env(["sts", "get-caller-identity"], timeout,
                                   {"AWS_PROFILE": name})
        if ident is None or not ident.get("Account"):
            unreachable.append("%s (%s)" % (name, why or "no account returned"))
            continue
        reached[name] = str(ident["Account"])
    return reached, unreachable, ""


def _aws_json_env(argv: List[str], timeout: int,
                  env: Dict[str, str]) -> Tuple[Optional[dict], str]:
    """One read-only AWS call under a different profile.

    The profile NAME reaches the child through the environment, which is where
    the CLI looks for it. No credential is read, held or passed: the CLI
    resolves the profile itself, exactly as it does for the run's own identity
    (credential rules 1 and 3)."""
    _CALLS["n"] += 1
    child = dict(os.environ)
    child.update(env)
    child.pop("AWS_ACCESS_KEY_ID", None)
    child.pop("AWS_SECRET_ACCESS_KEY", None)
    child.pop("AWS_SESSION_TOKEN", None)
    try:
        proc = subprocess.run(["aws", *argv, "--output", "json"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=child, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)[:200]
    if proc.returncode != 0:
        lines = (proc.stderr.decode("utf-8", "replace")
                 or "call failed").strip().splitlines()
        text = lines[-1] if lines else "call failed"
        return None, redact_identifiers(text)[:240]
    data = _report(proc.stdout.decode("utf-8", "replace"), dict)
    return (data if isinstance(data, dict) else None), ""


# --------------------------------------------------------------------------- #
# Access Analyzer — AWS's own answer to the question this tool hand-rolls.
#
# Plan 10 said AWS should evaluate policies wherever it can, applied that to
# one S3 call (`get-bucket-policy-status`, which is why the storage panel can
# say "AWS evaluated its policy and said so"), and then hand-rolled evaluation
# for identity, trust and resource policies -- while reading Access Analyzer as
# an on/off tile and never asking it anything.
#
# It is the same question. An analyzer's findings are exactly "this resource
# grants access to a principal outside the zone of trust", computed by the
# service that owns the semantics, including the condition keys, the SCPs and
# the resource control policies that step 5's reader explicitly cannot see.
#
# It does not replace the reader. An account with no analyzer gets nothing from
# this, so the reader stays and says it is the fallback; and where both answer,
# BOTH are shown, because a disagreement is the most interesting thing on the
# page and hiding either half would waste it.
# --------------------------------------------------------------------------- #

# Resource types Access Analyzer reports on, mapped to the panel that already
# says something about that kind of thing. A type not in here is still shown --
# under its own name -- because a list that silently dropped a type would be a
# cap nobody declared (I12).
ANALYZER_KINDS = {
    "AWS::IAM::Role": "roles",
    "AWS::S3::Bucket": "buckets",
    "AWS::S3::AccessPoint": "buckets",
    "AWS::S3Express::DirectoryBucket": "buckets",
    "AWS::SQS::Queue": "queues",
    "AWS::SNS::Topic": "topics",
    "AWS::ECR::Repository": "repositories",
    "AWS::SecretsManager::Secret": "secrets",
    "AWS::KMS::Key": "keys",
    "AWS::Lambda::Function": "functions",
    "AWS::Lambda::LayerVersion": "functions",
    "AWS::EFS::FileSystem": "filesystems",
    "AWS::RDS::DBSnapshot": "databases",
    "AWS::RDS::DBClusterSnapshot": "databases",
    "AWS::EC2::Snapshot": "snapshots",
    "AWS::DynamoDB::Table": "tables",
    "AWS::DynamoDB::Stream": "tables",
    "AWS::IAM::User": "users",
}


# Access Analyzer answers more than one question, and `ListFindings` answers
# only the first. ACCOUNT and ORGANIZATION analyzers find EXTERNAL access;
# ACCOUNT_UNUSED_ACCESS and ORGANIZATION_UNUSED_ACCESS find unused permissions,
# and the INTERNAL_ACCESS pair find something else again. Calling ListFindings
# on any of the other four is rejected with FIELD_VALIDATION_FAILED -- which is
# exactly what happened on a real account that runs an unused-access analyzer,
# taking the whole stage to `gap` and the whole section off the page.
EXTERNAL_ACCESS_ANALYZERS = ("ACCOUNT", "ORGANIZATION")


# What an Access Analyzer finding is ABOUT, beyond public/not-public.
#
# The analyzer's zone of trust is the account, and a federated principal comes
# from outside it by definition -- so every IRSA role in an EKS cluster, every
# GitHub Actions OIDC role and every SSO role in the account is reported as
# external access. On a real account that was thirty-six findings at medium,
# all of them the account's own identity federation, including the SSO role the
# operator was running Squawk as (review 2, R-23 and R-24).
#
# "Outside the account" and "outside your control" are different sentences, and
# the difference is whether the provider is one this account created.
FEDERATION_PROVIDERS = (":oidc-provider/", ":saml-provider/")


def _federation_scope(principal: dict, account: str) -> str:
    """"own-federation", "external", or "" when the principal is neither.

    A provider ARN in THIS account is identity federation the account set up:
    an EKS cluster's own OIDC provider, a GitHub Actions provider, an IAM
    Identity Center SAML provider. One in another account is not."""
    values = [str(v) for v in (principal or {}).values()]
    if not values:
        return ""
    federated = [v for v in values
                 if any(marker in v for marker in FEDERATION_PROVIDERS)]
    if not federated:
        return ""
    owners = {m.group(0) for v in federated
              for m in [_ACCOUNT_IN_ARN.search(v)] if m}
    if account and owners and owners == {account}:
        return "own-federation"
    return "external"


def _federation_kind(principal: dict) -> str:
    """The words for which of the account's own providers this is."""
    blob = " ".join(str(v) for v in (principal or {}).values())
    if "token.actions.githubusercontent.com" in blob:
        return "its own GitHub Actions OIDC provider"
    if "oidc.eks." in blob:
        return "its own EKS cluster's OIDC provider, which is how a pod assumes a role"
    if ":saml-provider/" in blob:
        return "its own SAML provider, which is how people sign in"
    if ":oidc-provider/" in blob:
        return "an OIDC provider this account created"
    return "a federated provider this account created"


def _analyzer_findings(arn: str, region: str, limit: int, timeout: int,
                       account: str = "") -> Tuple[List[dict], List[str]]:
    """One analyzer's active findings, projected to what a reader needs.

    No `--filter`: the status is filtered here instead, so the argv stays a
    plain read with no JSON document in it, and a finding whose status this
    version of the CLI spells differently is still recorded rather than
    silently dropped."""
    data, why = _aws_json(["accessanalyzer", "list-findings",
                           "--analyzer-arn", arn, "--region", region,
                           "--max-results", str(limit)], timeout)
    if data is None:
        return [], ["Access Analyzer findings for %s (%s)"
                    % (arn.rsplit("/", 1)[-1], why)]
    out: List[dict] = []
    for row in _rows(data.get("findings")):
        if str(row.get("status", "")).upper() != "ACTIVE":
            continue
        resource = str(row.get("resource", ""))
        kind = str(row.get("resourceType", ""))
        raw_principal = row.get("principal") or {}
        # Decided BEFORE masking: the comparison needs the account id, and the
        # evidence must not keep it.
        scope = ("public" if row.get("isPublic")
                 else _federation_scope(raw_principal, account) or "external")
        out.append({
            "scope": scope,
            "federation": (_federation_kind(raw_principal)
                           if scope == "own-federation" else ""),
            "id": str(row.get("id", "")),
            # The ARN with the account id masked. Attribution keeps the id and
            # the page masks it; evidence outlives the run (PRODUCT rule 6).
            "resource": _mask_account_ids(resource),
            # The last path segment for a role or a repository, the last ARN
            # field for a bucket, a topic or a queue. `rsplit("/")[-1] or ...`
            # returned the WHOLE ARN whenever there was no slash, so a
            # bucket's name never matched the storage reader's and the
            # comparison card called every bucket a disagreement (review 3,
            # R-38).
            "name": (resource.rsplit("/", 1)[-1] if "/" in resource
                     else resource.rsplit(":", 1)[-1]),
            "kind": kind,
            "panel": ANALYZER_KINDS.get(kind, ""),
            "public": bool(row.get("isPublic")),
            # Who it lets in, as the service names them, masked the same way.
            "principal": {str(k): _mask_account_ids(str(v))
                          for k, v in (row.get("principal") or {}).items()},
            "actions": [str(a) for a in (row.get("action") or [])][:8],
            "conditions": sorted(str(k) for k in (row.get("condition") or {})),
            "analyzed_at": str(row.get("analyzedAt", "")),
        })
    truncated = bool(data.get("nextToken"))
    if truncated:
        out.append({"id": "", "resource": "", "name": "", "kind": "",
                    "panel": "", "public": False, "principal": {},
                    "scope": "", "federation": "",
                    "actions": [], "conditions": [], "analyzed_at": "",
                    "truncated": True})
    return out, []


def aws_analyzer(ctx: "RunContext") -> "Union[str, Tuple[str, str, str]]":
    """What AWS's own external-access analyzer says is reachable from outside."""
    if not tool_path("aws"):
        return (json.dumps({"regional": {}}, indent=2), "error",
                "aws CLI not installed — nothing was read")
    _CALLS["n"] = 0
    started = time.monotonic()
    budget = _budget(ctx, "cloud_inventory_budget", 600)
    call_timeout = _budget(ctx, "cloud_call_timeout", 30)
    limit = _budget(ctx, "cloud_max_items", 200)
    deadline = time.monotonic() + budget

    ident, why = _aws_json(["sts", "get-caller-identity"], call_timeout)
    if ident is None or not ident.get("Account"):
        return (json.dumps({"regional": {}}, indent=2), "error",
                "could not resolve an AWS identity: %s — nothing was read"
                % (why or "no Account in the response"))

    regions, region_why = _enabled_regions(call_timeout)
    if not regions:
        return (json.dumps({"regional": {}}, indent=2), "error",
                "could not list the account's regions: %s" % region_why)

    regional: Dict[str, dict] = {}
    unread: List[str] = []
    for region in regions:
        if time.monotonic() >= deadline:
            unread.append(region)
            continue
        unreadable: List[str] = []
        listed, why = _aws_json(
            ["accessanalyzer", "list-analyzers", "--region", region],
            call_timeout)
        if listed is None:
            unreadable.append("Access Analyzer analyzers (%s)" % why)
            regional[region] = {"analyzers": [], "findings": [],
                                "unreadable": unreadable}
            continue
        active = [a for a in _rows(listed.get("analyzers"))
                  if str(a.get("status", "")).upper() == "ACTIVE"]
        analyzers = [a for a in active
                     if str(a.get("type", "")).upper()
                     in EXTERNAL_ACCESS_ANALYZERS]
        # The other kinds are recorded, not dropped. An account that runs only
        # an unused-access analyzer has an Access Analyzer and has NOT been
        # asked the external-access question, and those are different sentences.
        other = [{"name": str(a.get("name", "")),
                  "kind": str(a.get("type", ""))}
                 for a in active if a not in analyzers]
        findings: List[dict] = []
        for analyzer in analyzers:
            if time.monotonic() >= deadline:
                unreadable.append("Access Analyzer findings in %s (%s)"
                                  % (region, BUDGET_MARK))
                break
            rows, bad = _analyzer_findings(str(analyzer.get("arn", "")), region,
                                           limit, call_timeout,
                                           str(ident["Account"]))
            findings.extend(rows)
            unreadable.extend(bad)
        regional[region] = {
            "analyzers": [{"name": str(a.get("name", "")),
                           "kind": str(a.get("type", "")),
                           "arn": _mask_account_ids(str(a.get("arn", "")))}
                          for a in analyzers],
            "other_analyzers": other,
            "findings": findings,
            "unreadable": unreadable}

    payload = {
        "account": str(ident["Account"]),
        "read_as": mask_email(ident.get("Arn", "")),
        "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api_calls": _CALLS["n"],
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "limit": limit,
        "truncated": any(f.get("truncated") for per in regional.values()
                         for f in (per.get("findings") or [])),
        "regions_enabled": regions,
        "regions_read": sorted(set(regional) - set(_partial_regions(regional))),
        "regions_partial": _partial_regions(regional),
        "regions_unread": sorted(set(unread)),
        "regional": regional,
    }
    body = json.dumps(payload, indent=2, sort_keys=True)
    return _partial(body, [w for per in regional.values()
                           if isinstance(per, dict)
                           for w in (per.get("unreadable") or [])],
                    "Access Analyzer read(s)")


def aws_organization(ctx: "RunContext") -> "Union[str, Tuple[str, str, str]]":
    """How much of the estate this run covers."""
    if not tool_path("aws"):
        return (json.dumps({"accounts": []}, indent=2), "error",
                "aws CLI not installed — nothing was read")
    _CALLS["n"] = 0
    started = time.monotonic()
    call_timeout = _budget(ctx, "cloud_call_timeout", 30)
    budget = _budget(ctx, "cloud_inventory_budget", 600)
    deadline = time.monotonic() + budget

    ident, why = _aws_json(["sts", "get-caller-identity"], call_timeout)
    if ident is None or not ident.get("Account"):
        return (json.dumps({"accounts": []}, indent=2), "error",
                "could not resolve an AWS identity: %s — nothing was read"
                % (why or "no Account in the response"))
    this_account = str(ident["Account"])

    info, accounts, org_why, list_why = _org_accounts(call_timeout)

    # Gated. Without the acknowledgement this reports that it did not look,
    # which is a different answer from "no profile reaches anything" -- the
    # substitution I1 exists to refuse.
    asked, ack_why = profiles_ack()
    if asked:
        reached, unreachable, profiles_error = _profile_accounts(
            call_timeout, cap=_budget(ctx, "cloud_max_profiles", 24),
            deadline=deadline)
    else:
        reached, unreachable, profiles_error = {}, [], ack_why
    asked_names = sorted(reached) + [p.split(" (")[0] for p in unreachable]
    ran_a_command, config_why = (profiles_running_a_command(asked_names)
                                 if asked else ([], ""))

    payload = {
        "account": this_account,
        "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api_calls": _CALLS["n"],
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "standalone": org_why == "standalone",
        "org_error": "" if org_why in ("", "standalone") else org_why,
        "organization": info or {},
        "accounts": accounts,
        # The account list's own refusal, apart from the organization's. An
        # audit role that can describe the organization and cannot list it
        # is the ordinary case, and the page has a card for it (review 3,
        # R-37).
        "accounts_error": list_why,
        # Which estates this run touched, by name, so the evidence says it
        # rather than leaving it to be inferred from what came back.
        "profiles_asked": sorted(reached) + [p.split(" (")[0]
                                             for p in unreachable],
        "profiles_probed": asked,
        "profiles_reaching": reached,
        "profiles_unreachable": unreachable,
        "profiles_error": profiles_error,
        # What the read-only recorder cannot see. A `credential_process` in
        # the CLI config runs whatever command it names before any request is
        # signed, so a recorded read is a shell command on this machine
        # (review 2, R-33). Only the KEY is read -- the value is a command
        # line and may carry anything.
        "profiles_running_a_command": ran_a_command,
        "profiles_config_error": config_why,
    }
    # Handed to the stages that run after this one, the way syft hands grype
    # its SBOM. The IAM stage needs it to tell a role trusting this
    # organization's management account -- which is how an organization is
    # administered -- from one trusting a stranger (review 2, R-25). Stage
    # order puts cloud-org first; a stage that runs without it falls back to
    # "external", which is what this tool knew before.
    artifacts = getattr(ctx, "artifacts", None)
    if isinstance(artifacts, dict):
        artifacts["organization"] = json.dumps({
            "id": (info or {}).get("id", ""),
            "management": (info or {}).get("management_account", ""),
            "accounts": [a["id"] for a in accounts if a.get("id")],
            # Two facts the readers downstream need and could not infer from
            # an empty list: whether the list was READ, and whether there is
            # an organization at all. Without the first, a sibling whose
            # organization could not be enumerated read as a stranger;
            # without the second, a standalone account's grant narrowed to
            # some organization read as "inside the organization this
            # account belongs to" (review 3, R-37 and R-41).
            "accounts_listed": not list_why,
            "standalone": org_why == "standalone",
        })
    # A refused account list is a refused read, and the ledger row of the
    # stage that asked has to move (I1). Through `_partial`, so the page
    # renders what was read -- the organization -- with the refusal above it.
    return _partial(json.dumps(payload, indent=2, sort_keys=True),
                    ["the organization's account list (%s)" % list_why]
                    if list_why else [], "organization read(s)")


def organization_read(ctx: "RunContext") -> "Optional[dict]":
    """What the organization stage read, or None if it did not run.

    None and "no organization" are different answers and the caller has to be
    able to tell them apart, which is why this returns None rather than {}.
    """
    blob = getattr(ctx, "artifacts", {}).get("organization")
    if not blob:
        return None
    try:
        data = json.loads(blob)
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# --------------------------------------------------------------------------- #
# Front doors — API Gateway and CloudFront.
#
# The account this was written against reads: no public instances, no function
# URLs, no internet-facing load balancers, no public buckets. And it has a
# deploy role named for API Gateway ingest and forty-six VPC endpoint
# interfaces. Traffic is arriving somewhere.
#
# "0 reachable from the internet" under a caveat saying API Gateway is not read
# is not the same weight as the number above it. A tile that says zero, over a
# thing that was never looked at, is the failure this tool exists to prevent
# wearing a caveat as a fig leaf. So it gets looked at.
# --------------------------------------------------------------------------- #

# API Gateway authorization values that mean "anyone who has the URL".
OPEN_AUTH = ("NONE", "")


def _api_stages(argv: List[str], timeout: int
                ) -> Tuple[Optional[List[str]], str]:
    """The deployed stages of one API, or (None, why) if the read failed.

    An API with no stage has no endpoint that answers. Neither reader asked,
    so an API that was never deployed, or whose stage was deleted, was
    reported as "answers on its public endpoint and API Gateway authenticates
    none of N of its N route(s)" at high (review 2, R-32). The recorder's fake
    CLI has stocked responses for both of these calls since it was written,
    and nothing called them.

    None and [] are different answers: a read that failed is unknown, and an
    API with no stage is a fact.
    """
    data, why = _aws_json(argv, timeout)
    if data is None:
        return None, why
    # v1 returns `item`, v2 returns `Items`. The models differ and both are
    # checked, because a reader that knows one shape reports the other as
    # empty -- which here would read as "not deployed".
    rows = _rows(data.get("item")) + _rows(data.get("Items"))
    names = [str(r.get("stageName") or r.get("StageName") or "") for r in rows]
    return [n for n in names if n], ""


def _http_apis(region: str, timeout: int, deadline: float) -> Tuple[List[dict], List[str]]:
    """HTTP and WebSocket APIs (API Gateway v2), and their open routes."""
    out: List[dict] = []
    unreadable: List[str] = []
    data, why = _aws_json(["apigatewayv2", "get-apis", "--region", region], timeout)
    if data is None:
        return out, ["HTTP APIs (%s)" % why]
    for api in _rows(data.get("Items")):
        api_id = str(api.get("ApiId", ""))
        row = {
            "id": api_id, "name": str(api.get("Name", "")),
            "kind": str(api.get("ProtocolType", "") or "HTTP"),
            "endpoint": str(api.get("ApiEndpoint", "")),
            # The default execute-api endpoint is public unless it is turned
            # off. With it disabled the API is only reachable through whatever
            # custom domain fronts it, which is a materially different door.
            "default_endpoint_open": not api.get("DisableExecuteApiEndpoint"),
            "open_routes": [], "routes": 0, "unreadable": "",
            "stages": None, "stages_unreadable": "",
        }
        if time.monotonic() >= deadline:
            row["unreadable"] = "the budget ran out before its routes were read"
            out.append(row)
            continue
        routes, why = _aws_json(["apigatewayv2", "get-routes", "--api-id", api_id,
                                 "--region", region], timeout)
        if routes is None:
            row["unreadable"] = why
        else:
            items = _rows(routes.get("Items"))
            row["routes"] = len(items)
            row["open_routes"] = [
                str(r.get("RouteKey", "")) for r in items
                if str(r.get("AuthorizationType", "")).upper() in OPEN_AUTH
                and not r.get("ApiKeyRequired")]
        stages, why_stages = _api_stages(
            ["apigatewayv2", "get-stages", "--api-id", api_id,
             "--region", region], timeout)
        row["stages"] = stages
        if stages is None:
            row["stages_unreadable"] = why_stages
        out.append(row)
    return out, unreadable


def _rest_apis(region: str, timeout: int, deadline: float) -> Tuple[List[dict], List[str]]:
    """REST APIs (API Gateway v1), and their open methods."""
    out: List[dict] = []
    data, why = _aws_json(["apigateway", "get-rest-apis", "--region", region],
                          timeout)
    if data is None:
        return out, ["REST APIs (%s)" % why]
    for api in _rows(data.get("items")):
        api_id = str(api.get("id", ""))
        kinds = [str(t) for t in
                 ((api.get("endpointConfiguration") or {}).get("types") or [])]
        open_routes: List[str] = []
        routes = 0
        # A REST API can turn off its default execute-api endpoint exactly as
        # an HTTP API can. `_http_apis` has always read the flag; this reader
        # did not, so a REST API reachable only through a custom domain was
        # judged as if its public endpoint were live (review R-1).
        endpoint_off = bool(api.get("disableExecuteApiEndpoint"))
        # A PRIVATE REST API is reachable only from inside a VPC through an
        # interface endpoint. That is not a front door, and calling it one
        # would be the alarm crying wolf on a correct design.
        row: Dict[str, object] = {
            "id": api_id, "name": str(api.get("name", "")),
            "kind": "REST", "endpoint": "",
            "private": "PRIVATE" in kinds,
            "default_endpoint_open": "PRIVATE" not in kinds and not endpoint_off,
            "open_routes": open_routes, "routes": 0, "unreadable": "",
            # None until read: an API whose stages were never asked about is
            # not an API with no stages.
            "stages": None, "stages_unreadable": "",
        }
        if time.monotonic() >= deadline:
            row["unreadable"] = "the budget ran out before its methods were read"
            out.append(row)
            continue
        # WITHOUT `--embed methods` every method comes back as `{}`, so
        # `authorizationType` is absent, and a reader that treats absent as
        # open calls every method on every REST API unauthenticated. AWS's own
        # documentation: "the request supports only retrieval of the embedded
        # Method resources this way" (review R-1).
        res, why = _aws_json(["apigateway", "get-resources", "--rest-api-id",
                              api_id, "--embed", "methods",
                              "--region", region], timeout)
        if res is None:
            row["unreadable"] = why
        else:
            bare = 0
            for resource in _rows(res.get("items")):
                methods = resource.get("resourceMethods") or {}
                if not isinstance(methods, dict):
                    continue
                for verb, method in methods.items():
                    routes += 1
                    if not isinstance(method, dict) or not method:
                        # Asked for embedded methods and got a bare shape back.
                        # That is a report we cannot read (I14), and the one
                        # thing it must not become is "open".
                        bare += 1
                        continue
                    auth = str(method.get("authorizationType", "")).upper()
                    if auth in OPEN_AUTH and not method.get("apiKeyRequired"):
                        open_routes.append(
                            "%s %s" % (verb, resource.get("path", "/")))
            row["routes"] = routes
            if bare:
                row["unreadable"] = ("method details absent from the response "
                                     "for %d of %d route(s) — asked for "
                                     "embedded methods and did not get them"
                                     % (bare, routes))
                row["open_routes"] = []
        stages, why_stages = _api_stages(
            ["apigateway", "get-stages", "--rest-api-id", api_id,
             "--region", region], timeout)
        row["stages"] = stages
        if stages is None:
            row["stages_unreadable"] = why_stages
        out.append(row)
    return out, []


def _distributions(timeout: int) -> Tuple[List[dict], str]:
    """CloudFront distributions. Global, so asked once."""
    data, why = _aws_json(["cloudfront", "list-distributions"], timeout)
    if data is None:
        return [], why
    out = []
    for dist in _rows((data.get("DistributionList") or {}).get("Items")):
        origins = _rows((dist.get("Origins") or {}).get("Items"))
        plain = []
        for origin in origins:
            custom = origin.get("CustomOriginConfig") or {}
            policy = str(custom.get("OriginProtocolPolicy", "")).lower()
            if policy in ("http-only", "match-viewer"):
                plain.append("%s (%s)" % (origin.get("DomainName", "?"), policy))
        behaviour = dist.get("DefaultCacheBehavior") or {}
        out.append({
            "id": str(dist.get("Id", "")),
            "domain": str(dist.get("DomainName", "")),
            "enabled": bool(dist.get("Enabled")),
            "waf": str(dist.get("WebACLId", "")),
            "viewer_policy": str(behaviour.get("ViewerProtocolPolicy", "")),
            "plain_origins": plain,
            "origins": [str(o.get("DomainName", "")) for o in origins]})
    return out, ""


def aws_frontdoor(ctx: "RunContext") -> "Union[str, Tuple[str, str, str]]":
    """Where traffic from the internet actually arrives."""
    if not tool_path("aws"):
        return (json.dumps({"regional": {}, "distributions": []}, indent=2),
                "error", "aws CLI not installed — nothing was read")
    _CALLS["n"] = 0
    started = time.monotonic()
    budget = _budget(ctx, "cloud_inventory_budget", 600)
    call_timeout = _budget(ctx, "cloud_call_timeout", 30)
    deadline = time.monotonic() + budget

    ident, why = _aws_json(["sts", "get-caller-identity"], call_timeout)
    if ident is None or not ident.get("Account"):
        return (json.dumps({"regional": {}, "distributions": []}, indent=2),
                "error",
                "could not resolve an AWS identity: %s — nothing was read"
                % (why or "no Account in the response"))

    regions, region_why = _enabled_regions(call_timeout)
    if not regions:
        return (json.dumps({"account": str(ident["Account"]), "regional": {},
                            "distributions": []}, indent=2), "error",
                "could not list the account's regions: %s — a per-region "
                "answer with no denominator would be a guess"
                % (region_why or "none returned"))

    regional: Dict[str, dict] = {}
    unread: List[str] = []
    for region in regions:
        if time.monotonic() >= deadline:
            unread.append(region)
            continue
        http, http_bad = _http_apis(region, call_timeout, deadline)
        rest, rest_bad = _rest_apis(region, call_timeout, deadline)
        regional[region] = {"apis": http + rest,
                            "unreadable": http_bad + rest_bad}

    distributions, dist_why = _distributions(call_timeout)
    payload = {
        "account": str(ident["Account"]),
        # The ARN, with the ADDRESS out of it. Attribution needs the
        # account id and keeps it; nothing needs the operator's email,
        # and evidence outlives the run (PRODUCT rule 6, review R-3).
        "read_as": mask_email(ident.get("Arn", "")),
        "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api_calls": _CALLS["n"],
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "regions_enabled": regions,
        "regions_read": sorted(set(regional) - set(_partial_regions(regional))),
        "regions_partial": _partial_regions(regional),
        "regions_unread": sorted(set(unread)),
        "regional": regional,
        "distributions": distributions,
        "distribution_error": dist_why,
    }
    body = json.dumps(payload, indent=2, sort_keys=True)
    # Three sources, not one. The region's `unreadable` only holds the failure
    # to LIST apis; a refused `get-resources` or `get-stages` is recorded on
    # the API row, and a refused `list-distributions` in its own field. Feeding
    # only the first meant an API whose methods nobody could read reported
    # "0 open routes" from a green stage, which is the strongest clean signal
    # this page has (denial sweep, 2026-09-12).
    per_api = [w for per in regional.values() if isinstance(per, dict)
               for api in _rows(per.get("apis"))
               for w in (str(api.get("unreadable") or ""),
                         str(api.get("stages_unreadable") or ""))
               if w]
    return _partial(body, [w for per in regional.values()
                           if isinstance(per, dict)
                           for w in (per.get("unreadable") or [])]
                    + per_api
                    + ([dist_why] if dist_why else []),
                    "front-door read(s)")



# --------------------------------------------------------------------------- #
# Containers — ECS and EKS.
#
# The last compute surface the tool could not see. An account whose workloads
# are ECS tasks has no EC2 instances to find, and every reachability rule
# written so far is about an instance — so it answered cleanly about a thing it
# had not looked at.
#
# The two findings that matter here are not subtle. A Kubernetes API server
# reachable from 0.0.0.0/0 is the control plane of the cluster on the public
# internet. An ECS service that assigns public IPs puts its tasks directly on
# one, with only its security group in between.
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# What a condition says about WHO.
#
# A `*` principal is only half a sentence. The other half is the condition, and
# some condition keys answer "who may use this" outright: an account id, an
# organization, a principal ARN. Those are not a footnote to the `*` -- they
# are the grant.
#
# Reading only the key's NAME, which is what this did, meant the policy AWS
# itself attaches to every new SNS topic -- Principal `*` narrowed by
# `AWS:SourceOwner` equal to the account -- was reported as "usable by any AWS
# principal". Eleven of those on one real account, all of them the service's
# own default (review R-7, measured 2026-09-10).
# --------------------------------------------------------------------------- #

# Keys whose value names an account. All three answer the same question, and
# AWS uses different ones in different services for historical reasons:
# `aws:SourceOwner` on SNS, `aws:SourceAccount` on most integrations,
# `aws:PrincipalAccount` on identity-based comparisons.
ACCOUNT_KEYS = ("aws:principalaccount", "aws:sourceaccount", "aws:sourceowner")

# Keys whose value names an organization. An org path legitimately ends in
# `/*` -- that wildcard walks the OU tree, it does not widen the org.
ORG_KEYS = ("aws:principalorgid", "aws:principalorgpaths")

# The key whose value names principals directly.
PRINCIPAL_ARN_KEY = "aws:principalarn"

# The key that names the RESOURCE doing the calling rather than the caller:
# S3 to SNS, SNS to SQS, EventBridge to anything. Narrowing, and a different
# sentence from an account.
SOURCE_ARN_KEY = "aws:sourcearn"


def _pins(values: List[str]) -> bool:
    """Whether every value pins something, rather than being a wildcard.

    A condition key with `*` for its value narrows nothing, and a check that
    counted the key's presence would read it as a narrowing -- the same mistake
    one level down."""
    return bool(values) and all(
        v and "*" not in v and "?" not in v for v in values)


def _is_policy_variable(value: str) -> bool:
    """`${aws:PrincipalAccount}`, `${aws:ResourceOrgID}` and their kind."""
    v = str(value).strip()
    return v.startswith("${") and v.endswith("}")


def _outside_account(other: str, org: "Optional[dict]",
                     named: bool = False,
                     alongside: bool = False) -> Tuple[str, str]:
    """The scope for a condition that names an account that is not this one,
    read against the organization reading: a sibling is `organization`, an
    account that may be one is `unsettled`, and a stranger is `external`."""
    words = ("%sprincipals in account %s%s"
             % ("named " if named else "", mask_account(other),
                ", alongside this one" if alongside else ""))
    where, why = _inside_the_organization(other, org)
    if where in ("management", "member"):
        return "organization", "%s — %s" % (words, why)
    if where == "unlisted":
        return "unsettled", "%s — %s" % (words, why)
    return "external", words


def _who_a_condition_names(conditions: object, account: str,
                           org: "Optional[dict]" = None) -> Tuple[str, str]:
    """Who a condition admits, as (scope, words), or ("", "") for no one.

    `scope` is what the caller acts on: "internal" and "organization" are not
    findings, "service" is an integration, "external" names an account that is
    not this one, "unsettled" names an account that may or may not be in this
    organization because the member list was refused, "inverted" is a
    condition that names who is kept OUT and so admits everyone else, and ""
    means the condition does not name a principal at all -- an address range,
    a TLS flag, a referer -- so the `*` still stands.

    Takes the raw Condition block. It used to take the flattened key/value map,
    which had already thrown the operator away -- and the operator is half the
    sentence (review 2, R-18).

    `org` is the organization stage's reading -- {"id", "management",
    "accounts", "accounts_listed", "standalone"} -- or None when that stage
    did not run. It used to take only the id, so a standalone account, whose
    reading has no id, was indistinguishable from an account whose
    organization could not be read (review 3, R-41).
    """
    clauses = (conditions if isinstance(conditions, dict)
               and any(isinstance(v, list) for v in conditions.values())
               else None)
    by_key = clauses or _condition_map(conditions)
    org = org if isinstance(org, dict) else None
    org_id = str(org.get("id") or "") if org else ""
    standalone = bool(org and org.get("standalone"))

    # A negated test on a key that names WHO is the policy saying "everybody
    # except these", which is wider than the bare `*` it sits beside, not
    # narrower. It is reported before any affirming clause, because one
    # negation is enough to admit the world.
    for key in tuple(ORG_KEYS) + tuple(ACCOUNT_KEYS) + (PRINCIPAL_ARN_KEY,):
        if _is_negated(by_key.get(key)):
            return "inverted", ("everyone the %s condition does NOT match" % key)

    for key in ORG_KEYS:
        affirmed = _affirmed(by_key.get(key))
        if not affirmed:
            continue
        if all(_is_policy_variable(v) for v in affirmed):
            # `${aws:PrincipalOrgID}` and its kind: the organization the
            # resource itself is in, by variable. That names who in the one
            # way a policy can name itself, and it read as a narrowing that
            # names nobody (review 3, R-47).
            return "organization", ("principals in this organization, by "
                                    "policy variable")
        values = [v for v in affirmed if v.startswith("o-")]
        if not values:
            continue
        # WHICH organization. A queue narrowed to somebody else's org id read
        # as "principals in this organization" and produced nothing, because
        # the reader never knew which one this account belongs to -- and the
        # organization stage read it in the same run (review 2, R-27).
        if standalone:
            # This account is in no organization, so every principal an
            # organization id admits is outside it -- and the reading said
            # so, which is why this is not the unsettled branch below. It
            # used to read as "inside the organization this account belongs
            # to" (review 3, R-41).
            return "external", ("principals in an organization, and this "
                                "account is in none, so every one of them is "
                                "outside it")
        if not org_id:
            # Which organization is unknown, and inventing an answer in either
            # direction is worse than saying so. It stays `organization`, so
            # nothing about the verdict changes on an account whose
            # organization could not be read; the WORDS say what was not
            # settled, and the section's caveats say it again where a reader
            # who never opens a finding will see it.
            return "organization", ("principals in an organization — this run "
                                    "could not read which organization this "
                                    "account is in, so whether it is the same "
                                    "one is unsettled")
        if all(v.split("/")[0] == org_id for v in values):
            return "organization", "principals in this organization"
        return "external", ("principals in a DIFFERENT organization from the "
                            "one this account belongs to")

    for key in ACCOUNT_KEYS:
        values = _affirmed(by_key.get(key))
        if not values:
            continue
        if all(_is_policy_variable(v) for v in values):
            # `"aws:PrincipalAccount": "${aws:ResourceAccount}"` is the
            # documented way to write "the same account as the resource" in a
            # resource policy. It read as a narrowing that names nobody, at
            # medium (review 3, R-47).
            return "internal", "principals in this account, by policy variable"
        if not _pins(values) or not all(v.isdigit() and len(v) == 12
                                        for v in values):
            continue
        others = sorted(set(values) - {account}) if account else []
        if others:
            return _outside_account(others[0], org)
        return "internal", "principals in this account"

    arns = _affirmed(by_key.get(PRINCIPAL_ARN_KEY))
    if arns and all(v.startswith("arn:") for v in arns):
        found = {m.group(0) for v in arns
                 for m in [_ACCOUNT_IN_ARN.search(v)] if m}
        if account and found == {account}:
            return "internal", "named principals in this account"
        # A list that MIXES this account with another still admits the other
        # one. The test was whether the set equalled this account, and a mixed
        # set does not -- so a `*` narrowed to "role/app here plus role/partner
        # over there" fell through to "internal, named principals" and produced
        # nothing (review 2, R-28).
        others = sorted(found - {account}) if account else sorted(found)
        if others and account:
            return _outside_account(others[0], org, named=True,
                                    alongside=account in found)
        if found:
            # No account to compare against: the condition names principals and
            # this reading cannot say whose. Not a finding, and not a clean
            # answer either -- it is what the identity read could not settle.
            return "internal", "named principals"

    sources = _affirmed(by_key.get(SOURCE_ARN_KEY))
    if sources and all(v.startswith("arn:") for v in sources):
        return "service", "one named AWS resource"

    return "", ""

# A `*` that something narrowed, but not to anyone this account can name: the
# medium branch. Kept as text markers because the reasons travel to the page
# and back through the evidence file as strings.
NARROWED_MARKERS = ("narrowed only by", "which is not this one")

# A grant to an account whose place in this organization could not be settled:
# neither the medium branch nor the high one, but unknown (review 3, R-37).
UNSETTLED_MARKER = "could not be settled"


def is_unsettled_public(reason: str) -> bool:
    """Whether a public-policy reason names an account the organization
    reading could not place -- its member list was refused -- so the finding
    is a question rather than an answer."""
    return UNSETTLED_MARKER in reason


def is_narrowed_public(reason: str) -> bool:
    """Whether a public-policy reason describes a narrowed `*` rather than a
    bare one. The difference between medium and high, in one place so the two
    call sites that need it cannot drift apart."""
    return any(m in reason for m in NARROWED_MARKERS)


def _named_outsiders(principals: "List[Tuple[str, str]]", label: str,
                     account: str, org: "Optional[dict]") -> List[str]:
    """Statements that name a principal outright, when that principal is not
    this account's.

    Inside the same organization is its own answer here too, for the same
    reason it is on a trust policy: a queue shared with a sibling account is a
    boundary somebody chose, and reporting it beside a grant to a stranger
    makes both harder to see."""
    out: List[str] = []
    for kind, value in principals:
        if kind.lower() in ("service",) or value == "*":
            continue
        found = _ACCOUNT_IN_ARN.search(value)
        other = found.group(0) if found else ""
        if not other or not account or other == account:
            continue
        where, why = _inside_the_organization(other, org)
        if where in ("management", "member"):
            out.append("%s allows %s — which is not this account, and is "
                       "inside this organization" % (label, why))
        elif where == "unlisted":
            out.append("%s allows %s" % (label, why))
        else:
            out.append("%s allows a principal in account %s, which is not "
                       "this one" % (label, mask_account(other)))
    return out


def _public_policy_reasons(doc: object, label: str, account: str = "",
                           org: "Optional[dict]" = None) -> List[str]:
    """Why a RESOURCE policy admits somebody who is not this account.

    Same shape of question as a trust policy and a different answer: here the
    principal is who may use the resource. `*` with no condition narrowing it
    is the policy saying "anyone", in its own words. A condition that names an
    account, an organization or a principal ARN is the answer to "who", so the
    statement is internal and there is nothing to report. A condition that
    narrows something else -- an address range, a TLS flag -- leaves the `*`
    standing, and that is the narrowed branch."""
    data = _as_policy_doc(doc)
    if not data:
        return []
    statements = data.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    out: List[str] = []
    for st in _rows(statements):
        if str(st.get("Effect", "")).lower() != "allow":
            continue
        principals = _principal_values(st.get("Principal"))
        wide = [v for kind, v in principals
                if v == "*" and kind.lower() not in ("service",)]
        if not wide:
            # A statement that names a foreign account OUTRIGHT. This function
            # only ever looked at `*`, so a topic granted to another account by
            # its ARN produced nothing -- under an empty state reading "No
            # topic, queue or repository admits a principal outside this
            # account" (review 2, R-27). It is the case the analyzer files at
            # medium, and this is the same weight.
            out.extend(_named_outsiders(principals, label, account, org))
            continue
        conditions = _condition_keys(st.get("Condition"))
        scope, who = _who_a_condition_names(st.get("Condition"), account, org)
        if scope in ("internal", "organization", "service"):
            continue                      # the condition IS the answer to who
        if scope == "unsettled":
            out.append("%s allows %s" % (label, who))
        elif scope == "inverted":
            # A topic granted to the whole world minus the owner's organization
            # was filed as nothing at all (review 2, R-18).
            out.append("%s allows ANY principal except those the condition "
                       "names — %s — which is wider than an unconditional `*`, "
                       "not narrower" % (label, who))
        elif scope == "external":
            out.append("%s allows %s, which is not this one" % (label, who))
        elif conditions:
            out.append("%s allows any principal, narrowed only by %s, which "
                       "does not name who" % (label, ", ".join(sorted(conditions))))
        else:
            out.append("%s allows ANY principal, with no condition narrowing it"
                       % label)
    return out


def _eks_clusters(region: str, timeout: int) -> Tuple[List[dict], List[str]]:
    data, why = _aws_json(["eks", "list-clusters", "--region", region], timeout)
    if data is None:
        return [], ["EKS clusters (%s)" % why]
    out: List[dict] = []
    unreadable: List[str] = []
    for name in (data.get("clusters") or []):
        got, why = _aws_json(["eks", "describe-cluster", "--name", str(name),
                              "--region", region], timeout)
        if got is None:
            unreadable.append("EKS cluster %s (%s)" % (name, why))
            continue
        cluster = got.get("cluster") or {}
        vpc = cluster.get("resourcesVpcConfig") or {}
        logging_on: List[str] = []
        for block in _rows((cluster.get("logging") or {}).get("clusterLogging")):
            if block.get("enabled"):
                logging_on.extend(str(t) for t in (block.get("types") or []))
        out.append({
            "name": str(cluster.get("name", name)),
            "version": str(cluster.get("version", "")),
            "public": bool(vpc.get("endpointPublicAccess")),
            "private": bool(vpc.get("endpointPrivateAccess")),
            "public_cidrs": [str(c) for c in (vpc.get("publicAccessCidrs") or [])],
            "logging": sorted(set(logging_on)),
            "encrypted": bool(_rows(cluster.get("encryptionConfig"))),
        })
    return out, unreadable


def _ecs_services(region: str, timeout: int, deadline: float,
                  limit: int) -> Tuple[List[dict], List[str], bool]:
    """(services, why any read failed, whether a list was longer than the cap).

    The third value is new. Both slices below were silent caps: an account with
    more clusters or more services than the limit reported the first N and said
    nothing, which is the truncation I12 forbids (review R-13)."""
    data, why = _aws_json(["ecs", "list-clusters", "--region", region], timeout)
    if data is None:
        return [], ["ECS clusters (%s)" % why], False
    out: List[dict] = []
    unreadable: List[str] = []
    truncated = False
    all_clusters = [str(a) for a in (data.get("clusterArns") or [])]
    truncated = truncated or len(all_clusters) > limit
    for arn in all_clusters[:limit]:
        if time.monotonic() >= deadline:
            unreadable.append("ECS services in %s (the budget ran out)" % region)
            break
        listed, why = _aws_json(["ecs", "list-services", "--cluster", str(arn),
                                 "--region", region], timeout)
        if listed is None:
            unreadable.append("ECS services in cluster %s (%s)"
                              % (str(arn).rsplit("/", 1)[-1], why))
            continue
        all_services = [str(s) for s in (listed.get("serviceArns") or [])]
        truncated = truncated or len(all_services) > limit
        arns = all_services[:limit]
        for chunk in [arns[i:i + 10] for i in range(0, len(arns), 10)]:
            if not chunk or time.monotonic() >= deadline:
                break
            got, why = _aws_json(["ecs", "describe-services", "--cluster",
                                  str(arn), "--services", *chunk,
                                  "--region", region], timeout)
            if got is None:
                unreadable.append("ECS service detail in %s (%s)" % (region, why))
                continue
            for svc in _rows(got.get("services")):
                net = ((svc.get("networkConfiguration") or {})
                       .get("awsvpcConfiguration") or {})
                out.append({
                    "name": str(svc.get("serviceName", "")),
                    "cluster": str(arn).rsplit("/", 1)[-1],
                    "launch": str(svc.get("launchType", "")),
                    "public_ip": str(net.get("assignPublicIp", "")).upper()
                                 == "ENABLED",
                    "subnets": [str(s) for s in (net.get("subnets") or [])],
                    "groups": [str(g) for g in (net.get("securityGroups") or [])],
                    "running": svc.get("runningCount") or 0})
    return out, unreadable, truncated


def aws_containers(ctx: "RunContext") -> "Union[str, Tuple[str, str, str]]":
    """ECS services and EKS clusters, per region."""
    if not tool_path("aws"):
        return (json.dumps({"regional": {}}, indent=2), "error",
                "aws CLI not installed — nothing was read")
    _CALLS["n"] = 0
    started = time.monotonic()
    budget = _budget(ctx, "cloud_inventory_budget", 600)
    call_timeout = _budget(ctx, "cloud_call_timeout", 30)
    limit = _budget(ctx, "cloud_max_items", 200)
    deadline = time.monotonic() + budget

    ident, why = _aws_json(["sts", "get-caller-identity"], call_timeout)
    if ident is None or not ident.get("Account"):
        return (json.dumps({"regional": {}}, indent=2), "error",
                "could not resolve an AWS identity: %s — nothing was read"
                % (why or "no Account in the response"))
    regions, region_why = _enabled_regions(call_timeout)
    if not regions:
        return (json.dumps({"account": str(ident["Account"]), "regional": {}},
                           indent=2), "error",
                "could not list the account's regions: %s — a per-region "
                "answer with no denominator would be a guess"
                % (region_why or "none returned"))

    regional: Dict[str, dict] = {}
    unread: List[str] = []
    truncated = False
    for region in regions:
        if time.monotonic() >= deadline:
            unread.append(region)
            continue
        clusters, eks_bad = _eks_clusters(region, call_timeout)
        services, ecs_bad, more = _ecs_services(region, call_timeout, deadline,
                                                limit)
        truncated = truncated or more
        regional[region] = {"eks": clusters, "ecs": services,
                            "unreadable": eks_bad + ecs_bad}

    payload = {
        "account": str(ident["Account"]),
        # The ARN, with the ADDRESS out of it. Attribution needs the
        # account id and keeps it; nothing needs the operator's email,
        # and evidence outlives the run (PRODUCT rule 6, review R-3).
        "read_as": mask_email(ident.get("Arn", "")),
        "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api_calls": _CALLS["n"],
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "regions_enabled": regions,
        "regions_read": sorted(set(regional) - set(_partial_regions(regional))),
        "regions_partial": _partial_regions(regional),
        "regions_unread": sorted(set(unread)),
        "truncated": truncated, "limit": limit,
        "regional": regional,
    }
    body = json.dumps(payload, indent=2, sort_keys=True)
    return _partial(body, [w for per in regional.values()
                           if isinstance(per, dict)
                           for w in (per.get("unreadable") or [])],
                    "container read(s)")


# --------------------------------------------------------------------------- #
# Data services — the queues, topics, secrets and tables.
#
# These are read for one question each, and it is the same question: can
# somebody who is not you use this? A topic or a queue with a resource policy
# admitting `*` is reachable by any AWS principal on earth, and neither shows
# up in any network view.
# --------------------------------------------------------------------------- #

def _policy_backed(kind: str, region: str, names: List[str], timeout: int,
                   deadline: float, account: str = "",
                   org: "Optional[dict]" = None
                   ) -> Tuple[List[dict], List[str]]:
    """Topics or queues, with whatever their resource policy admits.

    `account` is what makes a condition legible: `AWS:SourceOwner` equal to
    this account is the whole grant, and without the account to compare it
    to the key is just a name (review R-7)."""
    out: List[dict] = []
    unreadable: List[str] = []
    for name in names:
        if time.monotonic() >= deadline:
            unreadable.append("%s in %s (the budget ran out)" % (kind, region))
            break
        if kind == "sns":
            got, why = _aws_json(["sns", "get-topic-attributes", "--topic-arn",
                                  name, "--region", region], timeout)
            attrs = (got or {}).get("Attributes") or {}
            label = name.rsplit(":", 1)[-1]
            encrypted = bool(attrs.get("KmsMasterKeyId"))
        else:
            got, why = _aws_json(["sqs", "get-queue-attributes", "--queue-url",
                                  name, "--attribute-names", "Policy",
                                  "KmsMasterKeyId", "SqsManagedSseEnabled",
                                  "--region", region], timeout)
            attrs = (got or {}).get("Attributes") or {}
            label = name.rsplit("/", 1)[-1]
            encrypted = bool(attrs.get("KmsMasterKeyId")
                             or str(attrs.get("SqsManagedSseEnabled", "")).lower()
                             == "true")
        if got is None:
            unreadable.append("%s %s (%s)" % (kind, name.rsplit("/", 1)[-1], why))
            continue
        out.append({"name": label, "kind": kind, "encrypted": encrypted,
                    "public": _public_policy_reasons(
                        attrs.get("Policy"), "%s policy" % kind, account, org)})
    return out, unreadable


def aws_dataservices(ctx: "RunContext") -> "Union[str, Tuple[str, str, str]]":
    """Topics, queues, secrets and container repositories, per region."""
    if not tool_path("aws"):
        return (json.dumps({"regional": {}}, indent=2), "error",
                "aws CLI not installed — nothing was read")
    _CALLS["n"] = 0
    started = time.monotonic()
    budget = _budget(ctx, "cloud_inventory_budget", 600)
    call_timeout = _budget(ctx, "cloud_call_timeout", 30)
    limit = _budget(ctx, "cloud_max_items", 200)
    deadline = time.monotonic() + budget
    # The organization stage runs first and read which organization this
    # account is in. Without it, a resource policy narrowed to SOMEBODY
    # ELSE'S organization reads as this one's (review 2, R-27).
    org = organization_read(ctx)

    ident, why = _aws_json(["sts", "get-caller-identity"], call_timeout)
    if ident is None or not ident.get("Account"):
        return (json.dumps({"regional": {}}, indent=2), "error",
                "could not resolve an AWS identity: %s — nothing was read"
                % (why or "no Account in the response"))
    regions, region_why = _enabled_regions(call_timeout)
    if not regions:
        return (json.dumps({"account": str(ident["Account"]), "regional": {}},
                           indent=2), "error",
                "could not list the account's regions: %s — a per-region "
                "answer with no denominator would be a guess"
                % (region_why or "none returned"))

    regional: Dict[str, dict] = {}
    unread: List[str] = []
    truncated = False
    for region in regions:
        if time.monotonic() >= deadline:
            unread.append(region)
            continue
        unreadable: List[str] = []

        topics, why = _aws_json(["sns", "list-topics", "--region", region],
                                call_timeout)
        topic_names: List[str] = []
        if topics is None:
            unreadable.append("SNS topics (%s)" % why)
        else:
            all_topics = [str(t.get("TopicArn", ""))
                          for t in _rows(topics.get("Topics")) if t.get("TopicArn")]
            truncated = truncated or len(all_topics) > limit
            topic_names = all_topics[:limit]
        sns_rows, bad = _policy_backed("sns", region, topic_names, call_timeout,
                                       deadline, str(ident["Account"]), org)
        unreadable.extend(bad)

        queues, why = _aws_json(["sqs", "list-queues", "--region", region],
                                call_timeout)
        queue_urls: List[str] = []
        if queues is None:
            # ANY failure, not only a denial. These two branches used to record
            # nothing unless the error text said AccessDenied, so a throttle, a
            # timeout or an endpoint failure was zero queues and zero
            # repositories, silently (review R-2). There is no error a service
            # returns for "nothing here" -- an empty list is an empty list --
            # so there is nothing left for the condition to have been for.
            unreadable.append("SQS queues (%s)" % why)
        else:
            all_queues = [str(q) for q in (queues.get("QueueUrls") or [])]
            truncated = truncated or len(all_queues) > limit
            queue_urls = all_queues[:limit]
        sqs_rows, bad = _policy_backed("sqs", region, queue_urls, call_timeout,
                                       deadline, str(ident["Account"]), org)
        unreadable.extend(bad)

        secrets: List[dict] = []
        listed, why = _aws_json(["secretsmanager", "list-secrets",
                                 "--region", region], call_timeout)
        if listed is None:
            unreadable.append("secrets (%s)" % why)
        else:
            all_secrets = _rows(listed.get("SecretList"))
            truncated = truncated or len(all_secrets) > limit
            for secret in all_secrets[:limit]:
                secrets.append({
                    "name": str(secret.get("Name", "")),
                    "rotation": bool(secret.get("RotationEnabled")),
                    "customer_key": bool(secret.get("KmsKeyId"))})

        repos: List[dict] = []
        described, why = _aws_json(["ecr", "describe-repositories",
                                    "--region", region], call_timeout)
        if described is None:
            unreadable.append("ECR repositories (%s)" % why)
        else:
            all_repos = _rows(described.get("repositories"))
            truncated = truncated or len(all_repos) > limit
            for repo in all_repos[:limit]:
                name = str(repo.get("repositoryName", ""))
                policy, why = _aws_json(["ecr", "get-repository-policy",
                                         "--repository-name", name,
                                         "--region", region], call_timeout)
                # "No policy" and "the policy could not be read" are different
                # answers. RepositoryPolicyNotFound is the first; anything else
                # is the second, and rendering it as an empty `public` list
                # would have made an unreadable repository look private.
                policy_unreadable = ""
                if policy is None and "repositorypolicynotfound" not in why.lower():
                    policy_unreadable = why
                    unreadable.append("ECR policy for %s (%s)" % (name, why))
                repos.append({
                    "policy_unreadable": policy_unreadable,
                    "name": name,
                    "scan_on_push": bool((repo.get("imageScanningConfiguration")
                                          or {}).get("scanOnPush")),
                    "mutable": str(repo.get("imageTagMutability", "")).upper()
                               == "MUTABLE",
                    "public": _public_policy_reasons(
                        (policy or {}).get("policyText"), "repository policy",
                        str(ident["Account"]), org)})

        regional[region] = {"topics": sns_rows, "queues": sqs_rows,
                            "secrets": secrets, "repositories": repos,
                            "unreadable": unreadable}

    payload = {
        "account": str(ident["Account"]),
        # The ARN, with the ADDRESS out of it. Attribution needs the
        # account id and keeps it; nothing needs the operator's email,
        # and evidence outlives the run (PRODUCT rule 6, review R-3).
        "read_as": mask_email(ident.get("Arn", "")),
        "read_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api_calls": _CALLS["n"],
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "truncated": truncated, "limit": limit,
        "regions_enabled": regions,
        "regions_read": sorted(set(regional) - set(_partial_regions(regional))),
        "regions_partial": _partial_regions(regional),
        "regions_unread": sorted(set(unread)),
        "regional": regional,
    }
    body = json.dumps(payload, indent=2, sort_keys=True)
    return _partial(body, [w for per in regional.values()
                           if isinstance(per, dict)
                           for w in (per.get("unreadable") or [])],
                    "data-service read(s)")


__all__ = [
    'ACCOUNT_KEYS',
    'ADMIN_MARKERS',
    'ANALYZER_KINDS',
    'AST10',
    'AWS_MANAGED',
    'BLOCK_SETTINGS',
    'BROAD_POLICIES',
    'BUDGET_MARK',
    'CALIBRATION_PATH',
    'COGNITO_AMR',
    'COGNITO_AUD',
    'COGNITO_PROVIDER',
    'CREDENTIAL_PROCESS_KEY',
    'ENI_KINDS',
    'ESCALATION_ACTIONS',
    'EVIDENCE_FREE_CRIT',
    'EVIDENCE_FREE_WARN',
    'EXTERNAL_ACCESS_ANALYZERS',
    'FEDERATION_PROVIDERS',
    'GITHUB_OIDC',
    'INVENTORY_READS',
    'NARROWED_MARKERS',
    'NEGATING_OPERATORS',
    'OPEN_AUTH',
    'ORGANIZATION_REACH',
    'ORG_KEYS',
    'POLICY_BLOCK_SETTINGS',
    'PRESENCE_OPERATORS',
    'PRINCIPAL_ARN_KEY',
    'REACH_RANK',
    'RECON_PATHS',
    'RECON_PORTS',
    'REGIONAL_SERVICES',
    'ROLE_TARGET_ACTIONS',
    'SELF_AUDIT_AREAS',
    'SELF_SERVICE_ACTIONS',
    'SET_OPERATOR_PREFIXES',
    'SOURCE_ARN_KEY',
    'UNSETTLED_MARKER',
    '_ACCOUNT_IN_ARN',
    '_CALLS',
    '_KNOWN_APPS',
    'PolicyRead',
    '_CallCounter',
    '_access_analyzer',
    '_account_block_beside',
    '_affirmed',
    '_analyzer_findings',
    '_api_stages',
    '_as_policy_doc',
    '_audit_evidence',
    '_audit_freshness',
    '_audit_integrity',
    '_audit_logging',
    '_audit_mcp',
    '_audit_privilege',
    '_audit_skill_md',
    '_audit_time',
    '_audit_trail',
    '_aws_json',
    '_aws_json_env',
    '_brief',
    '_broad_reasons',
    '_bucket_facts',
    '_budget',
    '_chk',
    '_cloudtrail',
    '_cognito_reach',
    '_condition_keys',
    '_condition_map',
    '_condition_values',
    '_config',
    '_databases',
    '_distributions',
    '_ecs_services',
    '_eks_clusters',
    '_enabled_regions',
    '_escalation_matches',
    '_escalation_reasons',
    '_everything_arn',
    '_excludes_escalation',
    '_federated_reach',
    '_federation_kind',
    '_federation_scope',
    '_frontmatter',
    '_function_url',
    '_github_sub_scope',
    '_guardduty',
    '_hit',
    '_http_apis',
    '_http_probe',
    '_in_git_worktree',
    '_inside_the_organization',
    '_inspector',
    '_is_negated',
    '_is_policy_variable',
    '_keep',
    '_lambda_functions',
    '_load_balancers',
    '_mask_account_ids',
    '_named_outsiders',
    '_named_targets',
    '_only_own_user',
    '_operator_sense',
    '_org_accounts',
    '_outside_account',
    '_partial',
    '_partial_regions',
    '_password_policy',
    '_pins',
    '_policy_backed',
    '_policy_docs_by_arn',
    '_policy_is_broad',
    '_port_open',
    '_principal_reasons',
    '_principal_values',
    '_profile_accounts',
    '_profile_role',
    '_project',
    '_public_policy_reasons',
    '_ran_out',
    '_read_policy_document',
    '_read_text',
    '_rest_apis',
    '_role_breadth',
    '_root_account',
    '_s3_account_block',
    '_securityhub',
    '_string_values',
    '_unique',
    '_user_credentials',
    '_who_a_condition_names',
    'aws_analyzer',
    'aws_containers',
    'aws_dataservices',
    'aws_edge',
    'aws_enablement',
    'aws_frontdoor',
    'aws_iam_graph',
    'aws_inventory',
    'aws_organization',
    'aws_storage',
    'eni_owner',
    'escalation_only',
    'is_already_admin',
    'is_narrowed_public',
    'is_unsettled_public',
    'organization_read',
    'profiles_ack',
    'profiles_running_a_command',
    'read_policy',
    'recon_probe',
    'self_audit',
    'self_audit_checks',
    'skill_audit',
    'who_can_assume',
    'widest_reach',
]

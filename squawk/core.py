"""Constants, logging, the finding model, and the small helpers everything else uses."""

import calendar
import hashlib
import json
import logging
import logging.handlers
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Dict, List, Mapping, NamedTuple, Optional, Tuple

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

DEFAULT_EVIDENCE = os.path.expanduser("~/scan-evidence")
LOG_NAME = "squawk.log"
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_KEEP = 5

# Logging is ON by default and not optional.
#
# Nothing here is "done" because it was asserted to work; it is done when there
# is a record showing it ran. That matters twice over for the refusals — the
# loopback bind guard, the private-target rail, the cross-origin block. A
# control that refuses something and leaves no trace cannot be audited later,
# by anyone, including the person who wrote it. So every refusal is logged at
# WARNING with the reason, alongside the ordinary lifecycle events.
LOG = logging.getLogger("squawk")


def setup_logging(evidence_root, verbose=False):
    """Attach a rotating file log under the evidence root. Returns its path, or
    None if the log could not be opened — and says so on stderr rather than
    continuing silently, because a run nobody can audit should not look like a
    normal one."""
    if LOG.handlers:
        return getattr(LOG, "_squawk_path", None)
    LOG.setLevel(logging.DEBUG if verbose else logging.INFO)
    LOG.propagate = False
    path = os.path.join(evidence_root, LOG_NAME)
    try:
        os.makedirs(evidence_root, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=LOG_MAX_BYTES, backupCount=LOG_KEEP, encoding="utf-8")
        # Owner-only, both of them. The host self-audit flagged this on its
        # first real run: the evidence root and the log were being created with
        # the default umask, so every finding, target and refusal this tool
        # recorded was readable by any other local user. The log is the more
        # awkward of the two, because it is a list of everything this machine
        # has been pointed at.
        #
        # Best-effort by design. A pre-existing directory owned by someone else
        # cannot be chmod'ed here, and failing the run over it would be worse
        # than continuing — the self-audit reports the condition either way.
        for target_path, mode in ((evidence_root, 0o700), (path, 0o600)):
            try:
                os.chmod(target_path, mode)
            except OSError:
                pass
    except OSError as exc:
        sys.stderr.write("squawk: LOGGING IS OFF — could not open %s (%s). "
                         "Actions will not be recorded and cannot be audited.\n"
                         % (path, exc))
        return None
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s",
                            datefmt="%Y-%m-%dT%H:%M:%SZ")
    fmt.converter = time.gmtime          # UTC, to match run ids
    handler.setFormatter(fmt)
    LOG.addHandler(handler)
    LOG._squawk_path = path
    return path
DEFAULT_PORT = 8787
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def host_is_loopback(hostport: str) -> bool:
    """True if an HTTP Host header names this machine's loopback.

    The server binds loopback, but a browser that was DNS-rebound to
    127.0.0.1 sends `Host: evil.example:8787`, and a page from that origin is
    then same-origin with Squawk: it can read every finding and POST a scan.
    Comparing Origin to Host does not catch that, because both are the
    attacker's. Refusing any Host that is not loopback does."""
    h = (hostport or "").strip().lower()
    if h.startswith("["):                     # [::1]:8787
        h = h[1:h.index("]")] if "]" in h else h[1:]
    elif h.count(":") == 1:                   # 127.0.0.1:8787, not a bare IPv6
        h = h.split(":", 1)[0]
    return h in LOOPBACK_HOSTS
BASE_TITLE = "Local scan report"  # baseline-issue title convention (later iteration)

# Directories a lived-in working tree accumulates that no scanner's default
# exclusion knows about. Counting these would turn provider plugin binaries and
# virtualenvs into thousands of phantom "findings". We filter them from every
# count and report the excluded total separately, so the noise is visible, not
# hidden. See the handoff's grype 12 -> 1,270 story.
CONTAMINATION_DIRS = (".terraform", ".terraform.nosync", ".venv", ".local-scans")

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")

# --------------------------------------------------------------------------- #
# Core data model
# --------------------------------------------------------------------------- #


class Finding(NamedTuple):
    scanner: str
    identity: str          # stable key: no timestamps, no absolute paths
    severity: str          # normalized to SEVERITY_ORDER
    title: str
    path: str              # repo-relative where meaningful, else a locator
    # Everything a reader needs to DECIDE, kept rather than discarded: what it
    # is, what proved it, and what to do about it. A finding you cannot act on
    # is a finding you will not act on.
    detail: Optional[dict] = None


class StageResult(NamedTuple):
    tool: str
    mode: str
    status: str            # "ok" | "skipped" | "error" | "gap"
    detail: str
    raw_file: Optional[str]
    findings: List[Finding]
    excluded: int          # findings dropped by the contamination filter
    coverage: "Optional[Coverage]" = None   # what the scanner examined
    ran: Optional[dict] = None              # the command, its timeout and where each came from


def norm_severity(value: Optional[str]) -> str:
    if not value:
        return "unknown"
    v = str(value).strip().lower()
    aliases = {
        "crit": "critical",
        "important": "high",
        "moderate": "medium",
        "warning": "medium",
        "note": "low",
        "informational": "info",
        "unknown": "unknown",
        "error": "high",
    }
    v = aliases.get(v, v)
    return v if v in SEVERITY_ORDER else "unknown"


# Where a finding lives decides what question it answers. `assert` in a test is
# what a test is made of; the same line in shipped code is bandit's B101. A real
# first run of this repository reported 2435 findings, 2355 of them in test
# files -- the 80 that were about the product could not be seen past them.
#
# Nothing is dropped for being here. The findings are recorded, counted and
# linked; the page shows the product's findings first and says how many are
# behind the other number (I12: the cap that is printed is not a cap).
# Only the names that mean tests in every ecosystem that uses them.
# `fixtures/`, `testdata/`, `e2e/`, `spec/` and `specs/` were here too, and a
# Terraform module under fixtures/ -- the world-open security group in the
# review's own synthetic repository -- went behind the test-code link while
# the Overview counted it as one of three high findings (review 3, R-40).
# The safe direction to be wrong in is product code.
TEST_DIRS = ("test", "tests", "testing", "__tests__")
TEST_PREFIXES = ("test_", "conftest")
TEST_SUFFIXES = ("_test", "_spec", ".test", ".spec")


def is_test_code(relpath: str) -> bool:
    """True when a path is test code by the conventions of its ecosystem.

    Deliberately conservative on both sides. `tests/` and `test_x.py` are
    unambiguous; a directory merely CONTAINING the word ("latest", "contest")
    is not, which is why the check is on whole path segments. A project that
    keeps tests somewhere else reads as product code here, which is the safe
    direction to be wrong in: a finding shown that did not need to be is a
    nuisance, and a finding hidden that mattered is this tool's cardinal sin.
    """
    parts = [p for p in str(relpath or "").replace("\\", "/").split("/") if p]
    if not parts:
        return False
    if any(p.lower() in TEST_DIRS for p in parts[:-1]):
        return True
    base = parts[-1].lower()
    stem = base.rsplit(".", 1)[0] if "." in base else base
    return (base.startswith(TEST_PREFIXES)
            or stem.endswith(TEST_SUFFIXES)
            or base in TEST_DIRS)


def is_contaminated(relpath: str) -> bool:
    parts = relpath.replace("\\", "/").split("/")
    for p in parts:
        for bad in CONTAMINATION_DIRS:
            if p == bad or (bad == ".venv" and p.startswith(".venv")):
                return True
    return False


# --------------------------------------------------------------------------- #
# Append-only files whose lines hash the line before them: the decisions ledger
# and the retention record. One discipline, so a line cannot be edited, removed
# or forged into the middle without every later line disagreeing. Shared here
# because both `decisions` and `evidence` need it and neither may import the
# other.
# --------------------------------------------------------------------------- #

_CHAIN_LOCK = threading.Lock()


def line_sha256(line: str) -> str:
    """The hash of one ledger line: its bytes, without the newline."""
    return hashlib.sha256(line.rstrip("\n").encode("utf-8")).hexdigest()


def last_line_sha256(path: str) -> str:
    """The hash of the last line already in the file, or "" for the first
    line ever. Empty is the honest value for "there is nothing before this"."""
    prev = ""
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                if raw.strip():
                    prev = line_sha256(raw)
    except (OSError, ValueError):
        return prev
    return prev


def append_chained(path: str, event: dict) -> dict:
    """Append one JSON line carrying `prev_sha256`, the hash of the line before
    it. The read of the previous line and the append happen under one lock —
    a thread lock, and an exclusive file lock where the platform has one — so
    two writers cannot both read the same predecessor and leave the file with
    a fork in its chain. That happened: two triage marks a moment apart, and
    `verify` then reported the ledger as tampered with."""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        with _CHAIN_LOCK:
            locked = False
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
                locked = True
            except (ImportError, OSError):
                locked = False      # no cross-process lock here; the thread lock holds
            try:
                event["prev_sha256"] = last_line_sha256(path)
                line = json.dumps(event, sort_keys=True) + "\n"
                os.write(fd, line.encode("utf-8"))
            finally:
                if locked:
                    fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
    return event


def walk_chain(path: str, since_head: str = "", min_version: int = 2,
               what: str = "entry") -> dict:
    """Walk a chained file and name the first line that does not hold.

    Returns the line count, the state (`ok`, `broken`, `unverifiable`), why,
    `head` (the hash of the last line, which the caller records so the next
    walk can tell whether the newest line changed), and every parsed event.
    A chain vouches for every line except its own last one; `since_head` is
    what closes that, by carrying the previous walk's head forward. A line
    older than `min_version` has no `prev_sha256` and is `unverifiable`,
    never `ok`: "I could not tell" is not a pass."""
    out: Dict[str, object] = {"path": path, "present": os.path.exists(path),
                              "lines": 0, "state": "ok", "detail": "",
                              "broken_at": 0, "unverifiable": 0, "head": "",
                              "events": []}
    events: List[dict] = []
    if not out["present"]:
        out["detail"] = "nothing recorded"
        if since_head:
            out["state"] = "broken"
            out["detail"] = "the file verified earlier is gone"
        return out
    prev = ""
    seen = set()
    lines = unverifiable = 0
    try:
        with open(path, encoding="utf-8") as fh:
            for n, raw in enumerate(fh, 1):
                if not raw.strip():
                    continue
                lines += 1
                try:
                    ev = json.loads(raw)
                except ValueError:
                    out.update(state="broken", broken_at=n, lines=lines,
                               detail="line %d does not parse" % n)
                    return out
                if not isinstance(ev, dict):
                    out.update(state="broken", broken_at=n, lines=lines,
                               detail="line %d is not a record" % n)
                    return out
                if int(ev.get("v", 1) or 1) < min_version:
                    unverifiable += 1
                elif ev.get("prev_sha256", "") != prev:
                    # The line that changed is the one BEFORE this one: this
                    # line still records what it was told, and what it was
                    # told no longer matches what is there.
                    out.update(state="broken", broken_at=n, lines=lines,
                               detail=("line %d records the line before it as %s, "
                                       "but line %d now hashes to %s — line %d was "
                                       "changed, replaced or removed"
                                       % (n, (ev.get("prev_sha256") or "nothing")[:16],
                                          n - 1, (prev or "nothing")[:16], n - 1)))
                    return out
                prev = line_sha256(raw)
                seen.add(prev)
                events.append(ev)
    except OSError as exc:
        out.update(state="unverifiable", detail="cannot read it: %s" % exc)
        return out
    out.update(lines=lines, unverifiable=unverifiable, head=prev, events=events)
    if since_head and since_head not in seen:
        out.update(state="broken", broken_at=lines,
                   detail=("the last line verified on the previous run (%s) is no "
                           "longer there: the newest %s was changed or removed"
                           % (since_head[:16], what)))
        return out
    if unverifiable:
        out.update(state="unverifiable",
                   detail="%d line(s) were written before this file was chained"
                          % unverifiable)
    else:
        out["detail"] = "%d line(s), each linked to the one before it" % lines
    return out


def sha256_file(path: str) -> str:
    """The sha256 of a file, read in blocks so a large raw report does not have
    to fit in memory. Full 64 hex chars: this one is used to prove a file was
    not edited, so it is never truncated the way `fingerprint` is."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def fingerprint(identities: List[str]) -> str:
    """The per-scanner fingerprint the dashboards and baselines both use:
    sha256 over the sorted identity set, first 16 hex chars."""
    joined = "\n".join(sorted(identities))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Scanner registry — add a scanner by adding an entry + a normalizer.
# --------------------------------------------------------------------------- #


class Scanner(NamedTuple):
    name: str
    binary: str
    kind: str                       # secrets | sast | iac | sca | sbom | dast | recon | cloud
    version_args: Tuple[str, ...]
    network: bool                   # reaches out on first run
    contributes: str
    internal: bool = False          # built into Squawk, no external binary


# One scanner, three stages, two kinds. `trivy config` reads infrastructure as
# code; `trivy fs` and `trivy image` read dependencies. The registry gives a
# SCANNER one kind, so a correlation that needed `iac` reported "cannot
# evaluate: no iac scanner ran" over 288 IaC findings trivy had just produced
# on a real repository (the operator, 2026-09-12). A correlation states its
# denominator (I16), and the denominator was wrong.
# Folder names that mean a cloud-sync client owns this path.
#
# Every one of these has an on-demand mode: the file on disk is a placeholder
# and opening it fetches the contents over the network. A scanner that walks a
# tree opens every file to decide whether it is interesting, so the cost is
# thousands of network round-trips and it is paid before a single byte is
# scanned.
#
# Measured on the operator's machine, 2026-09-14: gitleaks reads ~20 MB/s of
# scannable text on local disk and skips binaries itself -- a 1.4 GB tree came
# back as 15.9 MB scanned in 0.8s. The same tool timed out after 900s on a test
# repository inside OneDrive, and semgrep after 1200s, while bandit finished in
# 7s and `trivy config` in 5s. Those two filter to `.py` and to IaC files
# BEFORE reading, so they open a fraction of the tree. That split is the
# signature: the time is in opening files, not in reading them.
#
# Matched on a path SEGMENT, so `~/OneDrive - Company/repo` matches on its
# first segment and a source file called `dropbox_client.py` does not.
SYNC_ROOTS = (
    "onedrive", "dropbox", "google drive", "googledrive", "box sync",
    "nextcloud", "owncloud", "pcloud", "sync.com", "mega",
    # iCloud Drive's real path on macOS.
    "mobile documents", "com~apple~clouddocs",
)


def sync_root(path: str) -> str:
    """The cloud-sync folder a path sits under, or "".

    A heuristic on names, and it says only what it saw: this path is inside a
    folder a sync client owns. It does not claim the files are placeholders --
    that depends on a per-folder setting this cannot read -- which is why the
    caller reports it as something to know rather than as a fault."""
    if not path:
        return ""
    for part in os.path.abspath(path).split(os.sep):
        low = part.lower()
        for root in SYNC_ROOTS:
            # Exact, or followed by a SPACE, because the corporate folder is
            # routinely "OneDrive - Company". A `root + "-"` prefix was in here
            # too and matched `onedrive-notes.md`, which is a file about a sync
            # client and not a file inside one. This note is advisory, so a
            # false positive costs more than a miss: one that cries wolf trains
            # the reader to skip the line, and then it is worth nothing on the
            # run where it was right. `OneDrive-Personal` is the miss that buys
            # that, and it is worth it.
            if low == root or low.startswith(root + " "):
                return part
    return ""


MODE_KINDS = {("trivy", "config"): "iac"}


def result_kind(tool: str, mode: str) -> str:
    """What a finished stage actually READ, which is not always its scanner's
    kind. Empty for a tool that is not registered."""
    scanner = SCANNERS.get(tool)
    if scanner is None:
        return ""
    return MODE_KINDS.get((tool, mode), scanner.kind)


SCANNERS: Dict[str, Scanner] = {
    "gitleaks": Scanner("gitleaks", "gitleaks", "secrets", ("version",), False,
                        "secrets, including git history"),
    "semgrep": Scanner("semgrep", "semgrep", "sast", ("--version",), True,
                       "code patterns from the registry"),
    "bandit": Scanner("bandit", "bandit", "sast", ("--version",), False,
                      "Python-specific weaknesses"),
    "checkov": Scanner("checkov", "checkov", "iac", ("--version",), False,
                       "Terraform / IaC policy"),
    "trivy": Scanner("trivy", "trivy", "sca", ("--version",), True,
                     "dependencies, misconfig, secrets, image layers"),
    "syft": Scanner("syft", "syft", "sbom", ("version",), False,
                    "SBOM — the component inventory"),
    "grype": Scanner("grype", "grype", "sca", ("version",), True,
                     "CVEs, read from the SBOM"),
    "zap": Scanner("zap", "docker", "dast", ("--version",), True,
                   "dynamic testing of a RUNNING app (OWASP ZAP, via its Docker "
                   "image unless zap-baseline.py / zap-full-scan.py are on PATH)"),
    "awscli": Scanner("awscli", "aws", "cloud", ("--version",), True,
                      "the findings an AWS account already holds (Security Hub, "
                      "read-only, as the identity in your credential chain)"),
    # Internal, but it is not stdlib-only the way recon is: it drives the AWS
    # CLI as a subprocess, many times, and holds no credential of its own. The
    # binary is named so `doctor` reports it missing instead of the stage
    # failing on a machine without it.
    "cloudinv": Scanner("cloudinv", "aws", "cloud", ("--version",), True,
                        "the account's OWN resources — networking, compute and "
                        "the roles attached to them — read through the provider "
                        "API and joined into the combinations no single check "
                        "reports", internal=True),
    "cloudenable": Scanner("cloudenable", "aws", "cloud", ("--version",), True,
                           "which security services are watching the account, "
                           "per region — and which are not, which is the fact "
                           "every tool that only reads Security Hub cannot see",
                           internal=True),
    "cloudiam": Scanner("cloudiam", "aws", "cloud", ("--version",), True,
                        "the account's whole IAM graph — who exists, what "
                        "reaches them, and which of them can grant themselves "
                        "more than they have", internal=True),
    "cloudedge": Scanner("cloudedge", "aws", "cloud", ("--version",), True,
                         "what the internet can actually talk to — Lambda "
                         "function URLs and load balancers, which is where a "
                         "container-first account's front doors are and where "
                         "no instance-shaped check ever looked", internal=True),
    "cloudstore": Scanner("cloudstore", "aws", "cloud", ("--version",), True,
                          "where the data is — buckets and databases, and "
                          "whether anything but the account's own settings is "
                          "keeping people out of them", internal=True),
    "cloudorg": Scanner("cloudorg", "aws", "cloud", ("--version",), True,
                        "how much of the estate one run covers — the "
                        "organization's account list, and which of those "
                        "accounts this machine can actually reach",
                        internal=True),
    "cloudfront": Scanner("cloudfront", "aws", "cloud", ("--version",), True,
                          "where traffic from the internet actually arrives — "
                          "API Gateway and CloudFront, the doors an account "
                          "with no public instances and no public load "
                          "balancers still has", internal=True),
    "cloudcontain": Scanner("cloudcontain", "aws", "cloud", ("--version",), True,
                            "ECS services and EKS clusters — the compute an "
                            "account has when it has no instances, and the "
                            "Kubernetes control plane, which sits outside "
                            "every network view", internal=True),
    "cloudanalyzer": Scanner("cloudanalyzer", "aws", "cloud", ("--version",), True,
                             "AWS's own external-access analyzer, asked what it "
                             "found rather than only whether it is on. It "
                             "evaluates the policies this tool otherwise reads "
                             "by hand, including the SCPs and condition keys a "
                             "reader cannot see", internal=True),
    "clouddata": Scanner("clouddata", "aws", "cloud", ("--version",), True,
                         "topics, queues, secrets and container repositories — "
                         "reachable by policy alone, with no subnet or "
                         "security group between a caller and them",
                         internal=True),
    "recon": Scanner("recon", "", "recon", (), True,
                     "discovers reachable web apps on a target so the kiosk "
                     "knows what to scan", internal=True),
    "skillaudit": Scanner("skillaudit", "", "agentic", (), False,
                          "audits agent skills and MCP configs against the "
                          "OWASP Agentic Skills Top 10", internal=True),
    "correlation": Scanner("correlation", "", "correlation", (), False,
                          "joins findings across scanners into toxic "
                          "combinations", internal=True),
    "selfaudit": Scanner("selfaudit", "", "host", (), False,
                         "audits the machine running the scans — logging, "
                         "evidence permissions, clock sync, PATH integrity",
                         internal=True),
}

SUPPORTING = {
    "git": "repo-scope scans (branch, commit, dirty state)",
    "docker": "scanning a local image by name",
    "gh": "pulling per-finding baselines out of GitHub issues",
}


DB_STALE_DAYS = 7          # vulnerability data is published daily
STALE_SCAN_DAYS = 7        # the overview's own words: a week with no scan is a gap
__version__ = "0.9.0"
PID_FILENAME = "squawk.pid"      # under the evidence root; who is serving, where
SERVE_LOG = "squawk-serve.log"   # stdout/stderr of a background (--daemon) server
ABORT_SWEEP_AGE = 3 * 3600       # an unfinished run older than this is recorded aborted
# The code is a package (squawk/) beside the entry point (squawk.py). Paths that
# used to hang off __file__ hang off the entry's directory instead.
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRY_PATH = os.path.join(APP_DIR, "squawk.py")


def app_sources() -> List[str]:
    """Every source file that is the running app: the entry point and the
    package modules. Used where the tool audits its own code."""
    pkg = os.path.dirname(os.path.abspath(__file__))
    out = [ENTRY_PATH] if os.path.isfile(ENTRY_PATH) else []
    try:
        out += sorted(os.path.join(pkg, n) for n in os.listdir(pkg) if n.endswith(".py"))
    except OSError:
        pass
    return out


# No vulnerability database predates the tools that build them, and none is
# built in the future. A date outside that window is a field nobody set. Go
# renders an unset time.Time as 0001-01-01T00:00:00Z, which is what grype
# prints when its database has never been built. Reading that literally
# reports a database "739855 days old" instead of saying there is none.
DB_DATE_FLOOR_YEAR = 2000
GO_ZERO_TIME = "0001-01-01"


def _age_days(text: str) -> Optional[int]:
    """Days since the first plausible YYYY-MM-DD in a version/status string, or
    None when the string carries no usable date.

    Tolerant on purpose, since each tool prints its date in a different shape
    and the day is all that matters for a staleness call. Bounded on purpose
    too, because an unset field has to read as absent. A number nobody can act
    on is worse than no number: it looks like an answer, so it stops the
    question."""
    for m in re.finditer(r"(\d{4})-(\d{2})-(\d{2})", text or ""):
        year = int(m.group(1))
        if year < DB_DATE_FLOOR_YEAR:
            continue                      # an unset sentinel, not a build date
        try:
            stamp = calendar.timegm((year, int(m.group(2)), int(m.group(3)),
                                     0, 0, 0, 0, 0, 0))
        except (ValueError, OverflowError):
            continue
        age = int((time.time() - stamp) // 86400)
        if age < -1:                      # tolerate a day of clock skew, no more
            continue
        return max(0, age)
    return None


def _db_never_built(text: str) -> bool:
    """True when the tool reported a build date it never set, which means the
    database is missing rather than unreadable. Worth separating: one is fixed
    by running --update, the other by looking at why the tool will not answer."""
    return GO_ZERO_TIME in (text or "")


def vuln_db_ages() -> List[Tuple[str, Optional[int], str]]:
    """(tool, age_in_days, detail) for scanners that carry a vulnerability
    database. This is reported rather than assumed because a tool at the right
    version with a month-old database quietly finds fewer CVEs than exist —
    the same substitution the rest of this tool refuses to make."""
    out: List[Tuple[str, Optional[int], str]] = []
    if tool_path("trivy"):
        _c, txt, _e = run_cmd(["trivy", "version", "--format", "json"], None, 30)
        age = _age_days(txt)
        out.append(("trivy", age,
                    "no database downloaded yet" if age is None else ""))
    if tool_path("grype"):
        _c, txt, err = run_cmd(["grype", "db", "status"], None, 60)
        blob = "\n".join(x for x in (txt, err) if x)
        age = _age_days(blob)
        detail = ""
        if age is None:
            detail = ("no database downloaded yet" if _db_never_built(blob)
                      else "could not read db status")
        out.append(("grype", age, detail))
    return out


# A bare twelve-digit run is an AWS account id, in a target or inside an ARN.
_ACCOUNT_ID = re.compile(r"(?<![0-9])(\d{8})(\d{4})(?![0-9])")

# An SSO session name is the person's work email, and it sits in the middle of
# every assumed-role ARN this tool prints:
#
#   arn:aws:sts::************:assumed-role/AWSReservedSSO_.../First.Last@example.com
#
# The account id beside it was masked from the day it was first printed; the
# address next to it went out in full, on the page people screenshot into
# threads (measured 2026-09-09). Masked to the first character and the domain's
# last label, which is enough to recognise yourself and not enough to be a
# contact detail.
# An access key id is not a secret -- it is the public half, and it shows up in
# CloudTrail -- but it names a specific credential in a specific account, and
# these lines get screenshotted. Masked to the prefix and the last four, which
# is still enough to find the key in the console and rotate it.
_ACCESS_KEY = re.compile(r"\b((?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{2})([A-Z0-9]{10})([A-Z0-9]{4})\b")

_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])([A-Za-z0-9._%+-]*)@([A-Za-z0-9.-]+)\b")


def as_text(value: object) -> str:
    """Any value read back from persisted JSON, as a display string.

    `manifest.get("target", "")` returns **None**, not `""`, when the key is
    present holding a JSON null -- and a manifest is data on disk that an older
    version of this tool wrote, or that a partial run left behind. One such run
    among seventy-seven took the whole Findings page down with a TypeError,
    because the run picker renders every run on disk and one of them had a null
    target (measured on a real evidence root, 2026-09-08).

    So the boundary between persisted data and display text coerces, once, in a
    named place. Nothing here invents a value: a null becomes the empty string,
    which is what the caller asked for when it passed that default."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""          # a list or dict is not a label; refuse to render one


def mask_email(text: object) -> str:
    """An address reduced to its first letter and its domain's last label."""
    def sub(m: "re.Match") -> str:
        domain = m.group(3)
        tail = domain.rsplit(".", 1)[-1] if "." in domain else domain
        return "%s%s@%s%s" % (m.group(1), "*" * max(len(m.group(2)), 3),
                              "*" * 3, "." + tail if "." in domain else "")
    return _EMAIL.sub(sub, as_text(text))


def mask_key_id(text: object) -> str:
    """An AWS key id with only its prefix and last four characters shown."""
    return _ACCESS_KEY.sub(lambda m: "%s%s%s" % (m.group(1), "*" * 10, m.group(3)),
                           as_text(text))


def redact_identifiers(text: object) -> str:
    """Everything that must not leave this machine in a paste, removed at once.

    The account id and the SSO session address travel together inside a single
    assumed-role ARN, so anywhere one is masked the other has to be. Two
    separate calls at each site is how the second one gets forgotten, and it
    was."""
    return mask_key_id(mask_email(mask_account(text)))


def mask_account(text: object) -> str:
    """An AWS account id with only its last four digits shown.

    A cloud run's target IS the account number, so it lands in the CLI header,
    the run picker, the Findings heading and every target list — and from
    there into the first paste or screenshot anyone makes. That happened three
    times in one afternoon while the guide asked, in prose, that it not.
    A rule enforced by asking is a claim; this is the control.

    Display only. The evidence keeps the full value, because a run has to be
    attributable to the account it read and has to diff against the last one.
    Four digits are enough to tell two accounts apart at a glance, which is
    what the screen is for."""
    return _ACCOUNT_ID.sub(lambda m: "%s%s" % ("*" * 8, m.group(2)), as_text(text))


def human_seconds(seconds: float) -> str:
    """A duration a person reads at a glance: `42s`, `7m 12s`, `1h 03m`. Used
    wherever elapsed time is shown, so a scan that has been running for a
    while says so in one form rather than three."""
    total = round(seconds)
    if total < 60:
        return "%ds" % total
    if total < 3600:
        return "%dm %02ds" % divmod(total, 60)
    hours, rest = divmod(total, 3600)
    return "%dh %02dm" % (hours, rest // 60)


def env(name: str) -> Optional[str]:
    """SQUAWK_* first, TOWER_* honoured as the pre-rename name so an existing
    shell or script keeps working rather than silently falling back to a
    default — a config that stops being read without saying so is its own
    silent failure."""
    val = os.environ.get("SQUAWK_" + name)
    if val:
        return val
    return os.environ.get("TOWER_" + name)


def tool_path(binary: str) -> Optional[str]:
    return shutil.which(binary)


def tool_version(sc: Scanner) -> Optional[str]:
    path = tool_path(sc.binary)
    if not path:
        return None
    try:
        out = subprocess.run([path, *sc.version_args], capture_output=True,
                             text=True, timeout=30)
        text = (out.stdout or out.stderr or "").strip().splitlines()
        return text[0].strip() if text else "(installed)"
    except Exception:
        return "(installed)"


# --------------------------------------------------------------------------- #
# Subprocess runner
# --------------------------------------------------------------------------- #


# Every scanner Squawk starts, while it runs. Kept so that stopping Squawk
# stops them: before this existed, `squawk stop` recorded a scan as aborted and
# exited, and the scanner it had started — an active DAST probe, say — kept
# attacking the target for up to ninety more minutes. "Aborted" was a claim
# about a file, not about the traffic. Each child runs in its own session so
# its whole tree can be signalled at once, and docker's client forwards the
# signal into the container it started.
_CHILDREN: Dict[int, "subprocess.Popen[str]"] = {}
_CHILDREN_LOCK = threading.Lock()
CHILD_GRACE_SECONDS = 5.0

# Set by the server on its way out, before it kills anything. A stage whose
# scanner was killed used to return an error and the run went on to write a
# normal manifest — the reason the scan ended (the operator stopped it) was
# lost, and "aborted" was never recorded. With this set, the engine stops at
# the next stage boundary and the run is written up as aborted, with why.
STOP_REQUESTED = threading.Event()


class RunInterrupted(BaseException):
    """Raised inside a run when the server is stopping. A BaseException, like
    KeyboardInterrupt, so nothing that catches Exception swallows it and the
    run is recorded as aborted by `execute_service`."""

    def __str__(self) -> str:
        return "server stopped mid-run"


def _kill_group(proc: "subprocess.Popen[str]", grace: float = CHILD_GRACE_SECONDS) -> None:
    """SIGTERM the child's process group, wait, then SIGKILL what is left."""
    for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, 1.0)):
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.send_signal(sig)
            except OSError:
                return
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def container_of(argv: object) -> Optional[str]:
    """The `--name` a `docker run` command line gives its container, or None.
    Every container Squawk starts carries one (see `stages.container_name`)."""
    if not isinstance(argv, (list, tuple)) or len(argv) < 3:
        return None
    args = [str(a) for a in argv]
    if args[0] != "docker" or args[1] != "run" or "--name" not in args:
        return None
    i = args.index("--name")
    return args[i + 1] if i + 1 < len(args) else None


def _container_alive(name: str) -> Optional[bool]:
    """True/False from `docker ps`; None when docker itself cannot answer."""
    docker = shutil.which("docker")
    if not docker:
        return None
    try:
        res = subprocess.run([docker, "ps", "-q", "--filter", "name=^/%s$" % name],
                             capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if res.returncode != 0:
        return None
    return bool(res.stdout.strip())


def stop_container(name: str, wait: float = 10.0) -> Dict[str, object]:
    """Stop a container Squawk started, and check that it is gone.

    Killing the `docker run` client does not stop the container: past its
    grace period the client is SIGKILLed and the container is left running,
    detached. For a ZAP scan that is the attack traffic continuing after
    "stopped". So the container is killed by name and `docker ps` is asked
    before anything claims it stopped. The result says which."""
    out: Dict[str, object] = {"container": name, "stopped": None, "detail": ""}
    alive = _container_alive(name)
    if alive is None:
        out["detail"] = "docker did not answer; whether the container is running is unknown"
        return out
    if not alive:
        out["stopped"] = True
        out["detail"] = "already gone"
        return out
    docker = shutil.which("docker") or "docker"
    try:
        res = subprocess.run([docker, "kill", name], capture_output=True, text=True,
                             timeout=wait + 20)
        if res.returncode != 0:
            out["detail"] = (res.stderr or res.stdout).strip()[:200]
    except (OSError, subprocess.TimeoutExpired) as exc:
        out["detail"] = str(exc)[:200]
    deadline = time.time() + wait
    while time.time() < deadline:
        if _container_alive(name) is False:
            out["stopped"] = True
            out["detail"] = out["detail"] or "killed"
            return out
        time.sleep(0.25)
    out["stopped"] = False
    out["detail"] = out["detail"] or "still listed by docker ps after %.0fs" % wait
    LOG.error("container %s did NOT stop: %s", name, out["detail"])
    return out


def terminate_children(grace: float = CHILD_GRACE_SECONDS) -> List[Dict[str, object]]:
    """Stop every scanner still running — the process group, and the container
    it started if it started one. Returns one record per scanner: what it was,
    and for a container whether `docker ps` confirms it is gone. A caller that
    prints "stopped" prints it from this, not from having sent a signal."""
    with _CHILDREN_LOCK:
        live = [p for p in _CHILDREN.values() if p.poll() is None]
    out: List[Dict[str, object]] = []
    for proc in live:
        argv = list(proc.args) if isinstance(proc.args, (list, tuple)) else [str(proc.args)]
        LOG.warning("stopping scanner pid=%d: %s", proc.pid, " ".join(map(str, argv[:3])))
        rec: Dict[str, object] = {"pid": proc.pid, "cmd": " ".join(map(str, argv[:3])),
                                  "container": None, "container_stopped": None,
                                  "detail": ""}
        _kill_group(proc, grace)
        name = container_of(argv)
        if name:
            res = stop_container(name)
            rec.update(container=name, container_stopped=res["stopped"],
                       detail=res["detail"])
        out.append(rec)
    return out


def run_cmd(cmd: List[str], cwd: Optional[str], timeout: int) -> Tuple[int, str, str]:
    """Run one scanner and capture its output. The child gets its own process
    group and is registered while it runs, so a timeout, a Ctrl-C or a server
    stop ends the scanner and everything it spawned, not only the front
    process. See `terminate_children`."""
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True,
                                start_new_session=True)
    except FileNotFoundError:
        return 127, "", "binary not found"
    except Exception as exc:  # a bad scanner must never crash the run
        return 1, "", str(exc)
    with _CHILDREN_LOCK:
        _CHILDREN[proc.pid] = proc
    try:
        try:
            out, err = proc.communicate(timeout=timeout)
            result = (proc.returncode, out, err)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            name = container_of(cmd)
            note = ""
            if name:
                res = stop_container(name)
                note = ("; container %s %s" % (name, "stopped" if res["stopped"]
                                               else "NOT stopped: %s" % res["detail"]))
            result = (124, "", "timed out after %ss%s" % (timeout, note))
        except BaseException:           # Ctrl-C, or the server going down
            _kill_group(proc)
            name = container_of(cmd)
            if name:
                stop_container(name)
            raise
        if STOP_REQUESTED.is_set():
            # The scanner ended because the server is going — terminate_children
            # killed it and communicate() returned. Say so, rather than handing
            # the stage an exit code it would record as an ordinary error and a
            # run that would then be written up as finished.
            raise RunInterrupted()
        return result
    finally:
        with _CHILDREN_LOCK:
            _CHILDREN.pop(proc.pid, None)


# --------------------------------------------------------------------------- #
# Normalizers — one per scanner. Each turns raw JSON into Findings with a
# stable identity. Identity keys must never include a timestamp or an absolute
# path, or two identical runs would diff as changed (handoff §8.4).
# --------------------------------------------------------------------------- #


def _rel(path: str, base: str) -> str:
    if not path:
        return ""
    try:
        return os.path.relpath(path, base) if os.path.isabs(path) else path
    except ValueError:
        return path


def _rows(value) -> List[dict]:
    """The dict entries of a parsed list, and nothing else.

    A report is a list of records until a scanner emits a list of something
    else. Iterating that and calling .get() on an int is the same class of
    failure as parsing the wrong shape, one level down."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


class Coverage(NamedTuple):
    """What a scanner examined, alongside what it found.

    A finding count is a numerator. On its own it cannot tell a clean scan from
    a scan that looked at nothing, because both print zero. This is the missing
    denominator, taken from what the scanner already reports.

    `examined is None` is the honest third state: this tool does not publish its
    coverage (gitleaks says nothing about it in JSON), so we do not know, and we
    do not invent a zero. `examined == 0` is the finding that matters: the
    scanner ran and looked at nothing."""
    examined: Optional[int]      # units the scanner reported examining, or None
    unit: str                    # "files" | "resources" | "packages" | ...
    skipped: int                 # units it declined to read
    errors: int                  # the tool's own error channel, count
    note: str = ""               # a short human phrase, e.g. "empty ruleset"


NO_COVERAGE = Coverage(None, "", 0, 0, "tool publishes no coverage")


def _report(raw: str, shape):
    """Parse a scanner report into the shape this normalizer expects, or an
    empty one.

    Scanners change their output between versions, and a normalizer that raises
    on a shape it did not expect turns a parsing problem into a crashed stage.
    Nine of ten normalizers here raised AttributeError on a JSON array, because
    they called .get() on a list — valid JSON, wrong shape, and nothing about
    the code said so. Returning empty keeps the failure where it belongs: the
    stage reports no findings from an unreadable report, which the run then
    treats as the gap it is rather than as a clean result."""
    try:
        data = json.loads(raw) if raw and raw.strip() else shape()
    except (json.JSONDecodeError, ValueError):
        return shape()
    return data if isinstance(data, shape) else shape()


def _mode_of(path: str) -> Optional[int]:
    try:
        return os.stat(path).st_mode & 0o777
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# Stages — one scanner invocation in one mode. A stage knows how to build its
# command for a given target and how to consume/produce run artifacts.
# --------------------------------------------------------------------------- #


class RunContext:
    """Carries per-run state between stages (e.g. the SBOM syft hands to grype)."""

    def __init__(self, target: str, scope: str, run_dir: str, base: str,
                 service: str = "", profile: "Optional[Profile]" = None) -> None:
        self.target = target
        self.scope = scope            # repo | dir | image | url | host | aws
        self.run_dir = run_dir
        self.base = base              # path findings are made relative to
        # Runs live directly under the evidence root, so the parent of the run
        # directory is that root. The host audit needs it: the thing it examines
        # is where evidence is kept, not whatever the run happens to target.
        self.evidence_root = os.path.dirname(os.path.abspath(run_dir))
        self.artifacts: Dict[str, str] = {}
        self.raw_path = ""            # set by the runner before each build
        self.service = service        # the service key, for the profile lookup
        self.profile = profile        # the budgets this run runs under, if any


# --------------------------------------------------------------------------- #
# Profiles — timing, budgets and options per service or per target, read from
# squawk.toml. Three rules, each a test: every value a profile changes is
# printed on the run and written into the manifest (I12); a value that is
# parsed is a value that reaches the command (each knob is asserted in argv);
# and a profile never holds a credential (PRODUCT rule 1) or a destructive
# option (I3). A key the table below does not name is refused by name, so a
# typo cannot be read, ignored and still reported as applied.
# --------------------------------------------------------------------------- #

PROFILE_FILE = "squawk.toml"
PROFILE_TABLES = ("defaults", "services", "targets", "scanners")


class Knob(NamedTuple):
    builtin: Optional[int]   # None: each stage has its own (stage_timeout)
    unit: str
    what: str


PROFILE_KEYS: Dict[str, Knob] = {
    "stage_timeout": Knob(
        None, "seconds",
        "how long a stage may run before it is killed and recorded as timed "
        "out; each stage has its own built-in"),
    "zap_spider_minutes": Knob(
        5, "minutes",
        "-m on the live probe: the traditional and AJAX spider budget"),
    "zap_active_spider_minutes": Knob(
        10, "minutes",
        "-m on the active probe: the crawl an active scan is only as good as"),
    "zap_startup_wait": Knob(
        20, "minutes",
        "-T on the active probe: startup and passive-scan wait, not a cap"),
    # ZAP's launcher takes a quarter of the memory it thinks it has as its
    # heap. In a container under cgroup v2 it reads the HOST's memory — the
    # code that would read the limit looks for a cgroup v1 file that is not
    # there — so a probe on an 8 GB machine asks for -Xmx1983m whatever the
    # container is capped to. Measured 2026-09-08: `Available memory: 7933 MB
    # · Using JVM args: -Xmx1983m`, identical with and without `docker -m`.
    #
    # So the heap is set where ZAP actually reads it, its JVM properties file,
    # and the container is NOT capped: `-m` was measured to break this image's
    # baseline scan outright (rc=3 in 40s at 2048m and at 4096m, with and
    # without a larger /dev/shm, where the same scan with the heap set and no
    # cap passes). Unset by default because only the operator knows the machine.
    # How many findings a cloud read pulls before it stops and says so.
    # Unbounded, `get-findings` paginates a hundred at a time until it has
    # every finding an account holds: on a real estate that ran 46 minutes
    # and then produced NOTHING, because a stage killed at its budget throws
    # its output away (2026-09-08). A bounded read answers in seconds, and the
    # CLI hands back a NextToken when there is more — so the count comes with
    # proof that it is a floor rather than a total. A floor that says it is a
    # floor is a usable answer; an hour of silence is not.
    # How long the whole inventory read may take, across every region.
    # Region count is the denominator for every cloud claim, and an account
    # with seventeen enabled regions is seventeen times the calls of one. The
    # budget is what keeps that from becoming the forty-six-minute run again;
    # the regions it did not reach are NAMED, so a bounded read stays a
    # bounded read and never quietly becomes a clean one (I12).
    # How many IAM principals one read pulls before it stops and says so.
    # `get-account-authorization-details` returns the whole graph, which on a
    # large account is large; the read is bounded like every other and reports
    # the count as a floor when the account holds more.
    # How many Lambda functions one region's read pulls before it stops. Each
    # function costs a second call to ask whether it has a public URL, so this
    # is the knob that decides what an edge read costs on a serverless estate.
    # How many buckets one storage read examines. Each costs four calls -- its
    # region, its policy status, its access block and its encryption -- so this
    # is the knob that decides what a storage read costs on an estate with many
    # buckets. The total is always reported, so a bounded read says so.
    # How many topics, queues, secrets or repositories one region's read
    # examines. Each costs a second call to ask what its resource policy
    # admits, so this is what a data-services read costs on a busy account.
    "cloud_max_items": Knob(
        200, "items",
        "how many topics, queues, secrets or repositories one region's read "
        "examines before it stops and reports the count as a floor"),
    "cloud_max_buckets": Knob(
        100, "buckets",
        "how many S3 buckets one storage read examines before it stops and "
        "reports the count as a floor"),
    "cloud_max_functions": Knob(
        500, "functions",
        "how many Lambda functions one region's edge read pulls before it "
        "stops and reports the count as a floor"),
    "cloud_max_principals": Knob(
        1000, "principals",
        "how many IAM users, roles, groups and policies one graph read pulls "
        "before it stops and reports the count as a floor"),
    "cloud_inventory_budget": Knob(
        600, "seconds",
        "how long EACH cloud stage may take across all regions before it "
        "stops. Every one of them is bounded by this, the IAM graph included; "
        "a stage that stops names the regions it never reached and the ones "
        "it entered and did not finish, separately"),
    # One AWS call's own timeout. Small on purpose: a single describe that
    # hangs must not eat the whole inventory budget and take every region
    # after it down with it.
    "cloud_call_timeout": Knob(
        30, "seconds",
        "how long one AWS API call may take before it is recorded as an "
        "error and the read moves on"),
    # Replaces a literal 24 that nothing printed. A cap a reader cannot see is
    # a silent cap, and this one bounds how many of THEIR OWN profiles the run
    # asks about -- which is exactly the number they would want to know.
    "cloud_max_profiles": Knob(
        24, "profiles",
        "how many local AWS CLI profiles the organization stage asks who they "
        "reach, when SQUAWK_CLOUD_PROFILES_ACK=1 permits it at all. Profiles "
        "beyond this are named as not asked, never as unreachable"),
    "cloud_max_findings": Knob(
        1000, "findings",
        "how many findings a cloud read pulls before stopping. It reports "
        "the count as a floor when the account has more"),
    "zap_memory_mb": Knob(
        None, "megabytes",
        "ZAP's Java heap (-Xmx), set in the JVM properties file it reads. "
        "Unset means ZAP takes a quarter of the whole machine"),
}

# Exact tokens, not substrings: `rm` appears inside `--report-format`, which
# made a naive substring check flag gitleaks for deleting things. The charter
# test holds every built command to this list; a profile's extra_args are
# held to it here, at load time, with no exemption at all.
DESTRUCTIVE_TOKENS = frozenset({
    "delete", "destroy", "remove", "rm", "apply", "create", "put",
    "write", "push", "upload", "modify", "terminate", "revoke",
    "attach", "detach", "-delete", "--delete", "--force",
})

# `--rm` removes the *container* Squawk just started, not anything belonging
# to the user. Named here so the exemption is a recorded decision rather than
# a hole in a regex. It applies to Squawk's own commands, never to a profile.
READ_ONLY_EXEMPT = frozenset({"--rm"})

# What a credential looks like when it is pasted where it must not be. A
# profile value that matches is refused with its key named; the value itself
# is never printed and never logged.
SECRET_SHAPES = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),
)
SECRET_KEY_WORDS = ("password", "passwd", "secret", "token", "api_key", "apikey",
                    "credential", "auth")


class ProfileError(ValueError):
    """A profile that cannot be applied as written. The message names the
    file and the line, key or token at fault — never a value that could be a
    credential."""


# Said once, wherever a profile is refused. A profile is one document: if any
# part of it cannot be applied, none of it is, for every service — otherwise
# the same file would be refused for one run and accepted for the next, and an
# operator would read the acceptance as "the file is fine". The note exists
# because the refusal reads as a non-sequitur without it: a `[scanners.zap]`
# fault stopping a host audit that never runs zap looks like a bug until you
# know the rule. Seen in field use, 2026-09-07.
PROFILE_REFUSED_NOTE = (
    "The whole file is refused, for every service — a profile that cannot be "
    "applied as written is not applied in part. Fix or delete it and run again."
)


class Setting(NamedTuple):
    key: str
    value: object
    builtin: object
    section: str            # "[services.liveprobe]", or "built-in"

    @property
    def changed(self) -> bool:
        return self.section != "built-in"


# --- the TOML subset -------------------------------------------------------- #
# Python 3.9 has no tomllib, and a profile needs a few tables of strings,
# whole numbers, booleans and arrays. This reads exactly that, refuses the
# rest with a line number, and is cross-checked against tomllib where one
# exists (TestProfiles), so the subset and the standard agree on every
# document the subset accepts.

_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")


def _strip_comment(line: str) -> str:
    """Drop a `#` comment, but not a `#` inside a string."""
    out: List[str] = []
    quote = ""
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            out.append(c)
            if c == "\\" and quote == '"' and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
            out.append(c)
        elif c == "#":
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _bracket_depth(text: str) -> int:
    depth = 0
    quote = ""
    i = 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
        i += 1
    return depth


def _toml_string(s: str, i: int, line_no: int) -> Tuple[str, int]:
    quote = s[i]
    j = i + 1
    out: List[str] = []
    escapes = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"'}
    while j < len(s):
        c = s[j]
        if c == quote:
            return "".join(out), j + 1
        if quote == '"' and c == "\\":
            j += 1
            if j >= len(s) or s[j] not in escapes:
                raise ProfileError("line %d: unsupported escape in string" % line_no)
            out.append(escapes[s[j]])
        else:
            out.append(c)
        j += 1
    raise ProfileError("line %d: unterminated string" % line_no)


def _toml_value(s: str, i: int, line_no: int) -> Tuple[object, int]:
    """One value at s[i]: a string, a whole number, a boolean or an array of
    those. Returns (value, index after it)."""
    j = i
    while j < len(s) and s[j] in " \t\n":
        j += 1
    if j >= len(s):
        raise ProfileError("line %d: a value is missing" % line_no)
    c = s[j]
    if c in "\"'":
        return _toml_string(s, j, line_no)
    if c == "[":
        items: List[object] = []
        j += 1
        while True:
            while j < len(s) and s[j] in " \t\n":
                j += 1
            if j >= len(s):
                raise ProfileError("line %d: unterminated array" % line_no)
            if s[j] == "]":
                return items, j + 1
            val, j = _toml_value(s, j, line_no)
            if isinstance(val, list):
                raise ProfileError("line %d: nested arrays are not supported" % line_no)
            items.append(val)
            while j < len(s) and s[j] in " \t\n":
                j += 1
            if j < len(s) and s[j] == ",":
                j += 1
                continue
            if j < len(s) and s[j] == "]":
                return items, j + 1
            raise ProfileError("line %d: expected , or ] in the array" % line_no)
    if c == "{":
        raise ProfileError("line %d: inline tables are not supported — use a [table]"
                           % line_no)
    m = re.match(r"(true|false)\b", s[j:])
    if m:
        return m.group(1) == "true", j + m.end()
    m = re.match(r"[+-]?[0-9](?:_?[0-9])*", s[j:])
    if m:
        after = s[j + m.end():j + m.end() + 1]
        if after in (".", "e", "E", ":", "-"):
            raise ProfileError("line %d: only whole numbers are supported — seconds "
                               "or minutes, no fractions" % line_no)
        return int(m.group(0).replace("_", "")), j + m.end()
    raise ProfileError("line %d: cannot read the value" % line_no)


def _table_segments(header: str, line_no: int) -> List[str]:
    """`services.liveprobe` -> [services, liveprobe]; a quoted segment may
    hold anything, which is how a target URL becomes a table name."""
    segs: List[str] = []
    i = 0
    text = header.strip()
    while i < len(text):
        while i < len(text) and text[i] in " \t":
            i += 1
        if i >= len(text):
            break
        if text[i] in "\"'":
            seg, i = _toml_string(text, i, line_no)
        else:
            m = _BARE_KEY.match(text, i)
            if not m:
                raise ProfileError("line %d: bad table name" % line_no)
            seg, i = m.group(0), m.end()
        segs.append(seg)
        while i < len(text) and text[i] in " \t":
            i += 1
        if i < len(text):
            if text[i] != ".":
                raise ProfileError("line %d: bad table name" % line_no)
            i += 1
            if i >= len(text.rstrip()):
                raise ProfileError("line %d: bad table name" % line_no)
    if not segs:
        raise ProfileError("line %d: empty table name" % line_no)
    return segs


def parse_toml(text: str) -> Dict[str, object]:
    """The subset of TOML a profile needs: [tables] with bare or quoted
    segments, `key = value` with strings, whole numbers, booleans and arrays
    of those, and comments. Anything else is refused with its line number
    rather than read as something it is not. Tables come back nested."""
    root: Dict[str, object] = {}
    table = root
    headers_seen: Dict[str, int] = {}
    logical: List[Tuple[int, str]] = []
    buf, start = "", 0
    for n, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw)
        if not buf:
            if not line.strip():
                continue
            start = n
        buf = (buf + "\n" + line) if buf else line
        depth = _bracket_depth(buf)
        if depth < 0:
            raise ProfileError("line %d: unexpected ]" % n)
        if depth == 0:
            logical.append((start, buf))
            buf = ""
    if buf:
        raise ProfileError("line %d: unterminated array" % start)

    for n, line in logical:
        s = line.strip()
        if s.startswith("[["):
            raise ProfileError("line %d: arrays of tables are not supported" % n)
        if s.startswith("["):
            if not s.endswith("]"):
                raise ProfileError("line %d: bad table header" % n)
            segs = _table_segments(s[1:-1], n)
            name = ".".join(segs)
            if name in headers_seen:
                # Both line numbers: the second one alone leaves the reader
                # hunting for the first, which is the whole job of the message.
                # Appending a second copy of a section to a profile that
                # already had one is how this happens (2026-09-07).
                raise ProfileError("line %d: [%s] is defined twice — it is "
                                   "already open at line %d; put the settings "
                                   "under one heading"
                                   % (n, name, headers_seen[name]))
            headers_seen[name] = n
            table = root
            for seg in segs:
                nxt = table.get(seg)
                if nxt is None:
                    nxt = {}
                    table[seg] = nxt
                elif not isinstance(nxt, dict):
                    raise ProfileError("line %d: %s is a value, not a table" % (n, name))
                table = nxt
            continue
        m = re.match(r'\s*("(?:[^"\\]|\\.)*"|\'[^\']*\'|[A-Za-z0-9_-]+)\s*=\s*(.*)$',
                     line, re.DOTALL)
        if not m:
            if re.match(r"\s*[A-Za-z0-9_-]+\.", line):
                raise ProfileError("line %d: dotted keys are not supported — use a "
                                   "[table]" % n)
            raise ProfileError("line %d: expected key = value" % n)
        key = m.group(1)
        if key[0] in "\"'":
            key, _end = _toml_string(key, 0, n)
        value, end = _toml_value(m.group(2), 0, n)
        if m.group(2)[end:].strip():
            raise ProfileError("line %d: text after the value" % n)
        if key in table:
            raise ProfileError("line %d: %s is set twice" % (n, key))
        table[key] = value
    return root


# --- the profile ------------------------------------------------------------ #

def _looks_secret(value: object) -> bool:
    if isinstance(value, str):
        return any(rx.search(value) for rx in SECRET_SHAPES)
    if isinstance(value, list):
        return any(_looks_secret(v) for v in value)
    return False


def _secret_key(key: str) -> bool:
    k = key.lower()
    return any(w in k for w in SECRET_KEY_WORDS)


class Profile:
    """The budgets and options a run runs under, and where each came from.
    `path` is "" and `source` "built-in" when there is no profile at all —
    which is a profile like any other, so a run always says what it used."""

    def __init__(self, path: str, source: str, data: Dict[str, object]) -> None:
        self.path = path
        self.source = source           # --profile | SQUAWK_PROFILE | evidence root | built-in
        self.data = data

    # -- validation, at load, before any stage runs ------------------------- #

    def validate(self) -> None:
        """Refuse anything that is not a setting the table names, a credential
        shape, or a destructive option. Raises ProfileError naming the fault."""
        where = self.path or PROFILE_FILE
        for name, table in self.data.items():
            if name not in PROFILE_TABLES:
                raise ProfileError("%s: [%s] is not a section a profile has — the "
                                   "sections are %s" % (where, name,
                                                        ", ".join(PROFILE_TABLES)))
            if not isinstance(table, dict):
                raise ProfileError("%s: %s must be a [table], not a value" % (where, name))
            if name == "defaults":
                self._check_keys(where, "[defaults]", table, extra_ok=False)
                continue
            for sub, inner in table.items():
                if not isinstance(inner, dict):
                    raise ProfileError("%s: [%s] holds one table per %s — [%s.%s] — "
                                       "not a bare value" % (where, name, name[:-1],
                                                              name, sub))
                shown = ("[%s.%s]" % (name, sub) if _BARE_KEY.fullmatch(sub)
                         else '[%s."%s"]' % (name, sub))
                self._check_keys(where, shown, inner, extra_ok=(name == "scanners"))

    @staticmethod
    def _check_keys(where: str, section: str, table: Dict[str, object],
                    extra_ok: bool) -> None:
        for key, val in table.items():
            if _secret_key(key) or _looks_secret(val):
                raise ProfileError("%s: %s %s looks like a credential — a profile never "
                                   "holds one (PRODUCT rule 1); the value was not "
                                   "printed" % (where, section, key))
            if key == "extra_args":
                if not extra_ok:
                    raise ProfileError("%s: %s extra_args belongs under [scanners.<tool>]"
                                       % (where, section))
                if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
                    raise ProfileError("%s: %s extra_args must be a list of strings"
                                       % (where, section))
                for tok in val:
                    t = tok.strip().lower()
                    if t in DESTRUCTIVE_TOKENS or t in READ_ONLY_EXEMPT:
                        raise ProfileError("%s: %s extra_args carries %r, a destructive "
                                           "option — Squawk is read-only (I3)"
                                           % (where, section, tok))
                continue
            knob = PROFILE_KEYS.get(key)
            if knob is None:
                raise ProfileError("%s: %s %s is not a setting — the settings are %s"
                                   % (where, section, key, ", ".join(PROFILE_KEYS)))
            if isinstance(val, bool) or not isinstance(val, int) or val < 1:
                raise ProfileError("%s: %s %s must be a whole number of %s, at least 1"
                                   % (where, section, key, knob.unit))

    def check_names(self, services: Mapping[str, object],
                    scanners: Mapping[str, object]) -> None:
        """A section for a service or a scanner that does not exist is refused
        by name: it would be read, applied to nothing, and reported as applied."""
        where = self.path or PROFILE_FILE
        for name, known, noun in (("services", services, "service"),
                                  ("scanners", scanners, "scanner")):
            table = self.data.get(name)
            for sub in (table if isinstance(table, dict) else {}):
                if sub not in known:
                    raise ProfileError("%s: [%s.%s] names no %s — the %s are %s"
                                       % (where, name, sub, noun, name, ", ".join(known)))

    # -- lookup ------------------------------------------------------------- #

    def _sections(self, service: str, target: str, tool: str
                  ) -> List[Tuple[str, Dict[str, object]]]:
        """Least to most specific: defaults, the service, the target, the tool."""
        out: List[Tuple[str, Dict[str, object]]] = []
        d = self.data.get("defaults")
        if isinstance(d, dict):
            out.append(("[defaults]", d))
        for name, sub, shown in (("services", service, "[services.%s]" % service),
                                 ("targets", target, '[targets."%s"]' % target),
                                 ("scanners", tool, "[scanners.%s]" % tool)):
            table = self.data.get(name)
            inner = table.get(sub) if isinstance(table, dict) and sub else None
            if isinstance(inner, dict):
                out.append((shown, inner))
        return out

    def setting(self, service: str, target: str, tool: str, key: str,
                builtin: object) -> Setting:
        value, section = builtin, "built-in"
        for shown, table in self._sections(service, target, tool):
            if key in table:
                value, section = table[key], shown
        return Setting(key, value, builtin, section)

    def extra_args(self, tool: str) -> List[str]:
        table = self.data.get("scanners")
        inner = table.get(tool) if isinstance(table, dict) else None
        if isinstance(inner, dict):
            args = inner.get("extra_args")
            if isinstance(args, list):
                return [str(a) for a in args]
        return []

    # -- what a run ran under, for the CLI, the run page and the manifest ---- #

    def summary(self, service: str, target: str, rows: List[dict]) -> dict:
        """rows: one per stage — {"stage", "tool", "knobs": (keys the stage
        reads besides its timeout,), "timeout_builtin": int or None}. Returns
        every setting with its source, the ones that differ from the
        built-in, the extra_args per tool, and notes a reader should see."""
        settings: List[dict] = []
        extra: Dict[str, List[str]] = {}
        notes: List[str] = []
        for row in rows:
            if row.get("internal"):
                continue
            stage, tool = str(row["stage"]), str(row["tool"])
            timeout = None
            tb = row.get("timeout_builtin")
            if tb:
                st = self.setting(service, target, tool, "stage_timeout", tb)
                timeout = st.value if isinstance(st.value, int) else int(tb)
                settings.append({"stage": stage, "tool": tool, "key": st.key,
                                 "value": st.value, "builtin": st.builtin,
                                 "section": st.section})
            for key in row.get("knobs") or ():
                knob = PROFILE_KEYS[key]
                st = self.setting(service, target, tool, key, knob.builtin)
                settings.append({"stage": stage, "tool": tool, "key": st.key,
                                 "value": st.value, "builtin": st.builtin,
                                 "section": st.section})
                minutes = st.value if isinstance(st.value, int) else 0
                if key.endswith("_minutes") and timeout and minutes * 60 >= timeout:
                    notes.append("%s: %s is %s min but stage_timeout is %d s, so the "
                                 "timeout would end the crawl first — raise "
                                 "stage_timeout or lower %s"
                                 % (stage, key, st.value, timeout, key))
            args = self.extra_args(tool)
            if args and tool not in extra:
                extra[tool] = args
        changed = [s for s in settings if s["section"] != "built-in"]
        return {"path": self.path, "source": self.source, "changed": changed,
                "settings": settings, "extra_args": extra, "notes": notes}


def show_setting(value: object) -> str:
    """A profile value as a person reads it. A knob with no built-in — the ZAP
    memory cap — is `no cap`, never the word None, which says nothing about
    what the run will do."""
    return "no cap" if value is None else str(value)


def profile_path(evidence_root: str, explicit: Optional[str] = None) -> Tuple[str, str]:
    """Where the profile comes from, in order: --profile, SQUAWK_PROFILE, then
    squawk.toml in the evidence root. ("", "built-in") when there is none."""
    if explicit:
        return explicit, "--profile"
    from_env = env("PROFILE")
    if from_env:
        return from_env, "SQUAWK_PROFILE"
    candidate = os.path.join(evidence_root, PROFILE_FILE)
    if os.path.isfile(candidate):
        return candidate, "evidence root"
    return "", "built-in"


def load_profile(evidence_root: str, explicit: Optional[str] = None) -> Profile:
    """Read and validate the profile a run would use. A path that was asked
    for and cannot be read is refused, never quietly replaced by the
    built-ins: a config that stops being read without saying so is its own
    silent failure. Raises ProfileError."""
    path, source = profile_path(evidence_root, explicit)
    if not path:
        return Profile("", "built-in", {})
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise ProfileError("%s: cannot read the profile (%s) — named by %s"
                           % (path, exc.strerror or exc.__class__.__name__,
                              source)) from None
    try:
        data = parse_toml(text)
    except ProfileError as exc:
        raise ProfileError("%s: %s" % (path, exc)) from None
    prof = Profile(path, source, data)
    prof.validate()
    return prof


# --------------------------------------------------------------------------- #
# Target / evidence resolution
# --------------------------------------------------------------------------- #


def resolve_repo(explicit: Optional[str]) -> Optional[str]:
    start = explicit or os.getcwd()
    start = os.path.abspath(start)
    cur = start
    while True:
        if os.path.isdir(os.path.join(cur, ".git")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return explicit if explicit else None
        cur = parent


def evidence_writable(root: str) -> bool:
    try:
        os.makedirs(root, exist_ok=True)
        probe = os.path.join(root, ".write-probe")
        with open(probe, "w") as fh:
            fh.write("ok")
        os.remove(probe)
        return True
    except Exception:
        return False


def guard_host(host: str) -> None:
    """Squawk refuses to bind anything but loopback. On a reachable interface it
    is remote code execution as your user (it runs scanners and reads any path).
    """
    if host not in LOOPBACK_HOSTS:
        LOG.warning("REFUSED bind: host=%s not loopback", host)
        sys.stderr.write(
            "REFUSING to bind %r. Squawk runs scanners as subprocesses and reads\n"
            "any path with no authentication; off loopback that is RCE as you.\n"
            "Allowed: %s. If two people need it, run two copies.\n"
            % (host, ", ".join(LOOPBACK_HOSTS)))
        raise SystemExit(2)


# --------------------------------------------------------------------------- #
# Doctor
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Install and update evidence
#
# The updater was the one operation that changed the machine and left no record
# of having done it. It shelled out to the installer, printed whatever the
# script printed, and returned. Afterwards nothing could answer the ordinary
# administrative questions: what version am I on, what moved, when, who ran it,
# and did any of it actually fail.
#
# So an install or update is now treated like a scan: inventory before,
# transcript during, inventory after, and a written record that survives the
# terminal it was run in. A tool that audits other people's estates should be
# able to account for its own changes.
# --------------------------------------------------------------------------- #

INSTALL_DIRNAME = "installs"

# --------------------------------------------------------------------------- #
# Phase 2b: exploitability. Two public feeds rank a CVE by whether it is being
# exploited (CISA KEV) and how likely it is to be (FIRST EPSS). They are cached
# under the evidence root with provenance, like an install record, and their
# age is reported like a vulnerability database's: a ranking made against a
# missing or stale feed says so, rather than quietly falling back to severity
# and calling that exploitability.
FEEDS_DIRNAME = "feeds"


__all__ = [
    'ABORT_SWEEP_AGE',
    'APP_DIR',
    'BASE_TITLE',
    'CHILD_GRACE_SECONDS',
    'CONTAMINATION_DIRS',
    'DB_DATE_FLOOR_YEAR',
    'DB_STALE_DAYS',
    'DEFAULT_EVIDENCE',
    'DEFAULT_PORT',
    'DESTRUCTIVE_TOKENS',
    'ENTRY_PATH',
    'FEEDS_DIRNAME',
    'GO_ZERO_TIME',
    'INSTALL_DIRNAME',
    'LOG',
    'LOG_KEEP',
    'LOG_MAX_BYTES',
    'LOG_NAME',
    'LOOPBACK_HOSTS',
    'MODE_KINDS',
    'NO_COVERAGE',
    'PID_FILENAME',
    'PROFILE_FILE',
    'PROFILE_KEYS',
    'PROFILE_REFUSED_NOTE',
    'PROFILE_TABLES',
    'READ_ONLY_EXEMPT',
    'SCANNERS',
    'SECRET_KEY_WORDS',
    'SECRET_SHAPES',
    'SERVE_LOG',
    'SEVERITY_ORDER',
    'STALE_SCAN_DAYS',
    'STOP_REQUESTED',
    'SUPPORTING',
    'SYNC_ROOTS',
    'TEST_DIRS',
    'TEST_PREFIXES',
    'TEST_SUFFIXES',
    '_ACCESS_KEY',
    '_ACCOUNT_ID',
    '_BARE_KEY',
    '_CHAIN_LOCK',
    '_CHILDREN',
    '_CHILDREN_LOCK',
    '_EMAIL',
    'Coverage',
    'Finding',
    'Knob',
    'Profile',
    'ProfileError',
    'RunContext',
    'RunInterrupted',
    'Scanner',
    'Setting',
    'StageResult',
    '__version__',
    '_age_days',
    '_bracket_depth',
    '_container_alive',
    '_db_never_built',
    '_kill_group',
    '_looks_secret',
    '_mode_of',
    '_rel',
    '_report',
    '_rows',
    '_secret_key',
    '_strip_comment',
    '_table_segments',
    '_toml_string',
    '_toml_value',
    'app_sources',
    'append_chained',
    'as_text',
    'container_of',
    'env',
    'evidence_writable',
    'fingerprint',
    'guard_host',
    'host_is_loopback',
    'human_seconds',
    'is_contaminated',
    'is_test_code',
    'last_line_sha256',
    'line_sha256',
    'load_profile',
    'mask_account',
    'mask_email',
    'mask_key_id',
    'norm_severity',
    'parse_toml',
    'profile_path',
    'redact_identifiers',
    'resolve_repo',
    'result_kind',
    'run_cmd',
    'setup_logging',
    'sha256_file',
    'show_setting',
    'stop_container',
    'sync_root',
    'terminate_children',
    'tool_path',
    'tool_version',
    'vuln_db_ages',
    'walk_chain',
]

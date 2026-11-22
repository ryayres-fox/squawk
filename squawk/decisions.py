"""Triage decisions, recorded in the evidence store rather than a browser.

A decision is human input: who marked an advisory reviewed, flagged or skipped,
when, and why. It cannot be reconstructed from scanner output the way a
finding's history can, so it is the one thing Squawk keeps in a ledger of its
own. The ledger is append-only: every mark is one line in
`<evidence_root>/decisions/ledger.jsonl`, and the current state of any finding is
the last line that covers it. Nothing is ever edited or removed, so the record
shows the sequence of minds changed, not only the last one.

A decision is keyed to the target the run scanned and to each finding identity it
covered, so it follows the finding on to every later run of that target and
never leaks to a different target that happens to contain the same identity.
"""

import getpass
import json
import os
import re
import time
from typing import Dict, List, Optional, Tuple

from squawk.core import LOG, append_chained, walk_chain

DECISION_STATES = ("open", "reviewed", "flagged", "skipped")
NOTE_CAP = 2000
_LEDGER_VERSION = 2       # v2 lines carry prev_sha256; v1 lines cannot be chained
LEDGER_STATES = ("ok", "broken", "unverifiable")


def ledger_path(evidence_root: str) -> str:
    return os.path.join(evidence_root, "decisions", "ledger.jsonl")


def who() -> str:
    """The person recording a decision. `SQUAWK_USER` wins, so a shared
    workstation can name the actual reviewer; otherwise the login user."""
    name = os.environ.get("SQUAWK_USER", "").strip()
    if name:
        return name
    for var in ("USER", "LOGNAME"):
        if os.environ.get(var, "").strip():
            return os.environ[var].strip()
    try:
        return getpass.getuser()
    except Exception:  # no login name in this environment (a container, say)
        return "unknown"


def record_decision(evidence_root: str, run_id: str, target: str, service: str,
                    scanner: str, rule: str, status: str, identities: List[str],
                    note: str = "", by: Optional[str] = None,
                    at: Optional[str] = None) -> dict:
    """Append one decision and return it. Raises ValueError rather than writing
    anything it would later have to explain away: an unknown status, no
    identities, or a note past the cap."""
    if status not in DECISION_STATES:
        raise ValueError("unknown decision status %r (one of %s)"
                         % (status, ", ".join(DECISION_STATES)))
    idents = sorted({i for i in identities if isinstance(i, str) and i})
    if not idents:
        raise ValueError("a decision must cover at least one finding identity")
    if len(note) > NOTE_CAP:
        raise ValueError("note is longer than %d characters" % NOTE_CAP)
    event = {
        "v": _LEDGER_VERSION,
        "at": at or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
        "who": by or who(),
        "run_id": run_id,
        "target": target,
        "service": service,
        "scanner": scanner,
        "rule": rule,
        "status": status,
        "note": note,
        "identities": idents,
    }
    # Append-only by construction and chained: each line carries the hash of
    # the line before it, the read of that line and the append happen under
    # one lock, and the append is one write. See `core.append_chained` for
    # why the lock exists — two marks a moment apart used to fork the chain.
    append_chained(ledger_path(evidence_root), event)
    LOG.info("decision recorded: %s %s/%s -> %s by %s (%d identities)",
             target, scanner, rule, status, event["who"], len(idents))
    return event


def verify_ledger(evidence_root: str, since_head: str = "") -> dict:
    """Walk the decisions ledger and name the first line that does not hold.

    Returns the line count, the first break, why, and `head` — the hash of the
    last line, which the caller records so the next walk can tell whether the
    newest line changed. A line written before the chain existed (v1) is
    `unverifiable`, never `ok`. The walk itself is `core.walk_chain`; this
    adds the one decision-specific rule, that every chained line is a
    decision."""
    out = walk_chain(ledger_path(evidence_root), since_head,
                     min_version=2, what="decision")
    events = out.pop("events", [])
    if not out["present"]:
        out["detail"] = "no decisions recorded" if not since_head else \
            "the ledger verified earlier is gone"
        return out
    if out["state"] == "ok":
        bad = [i + 1 for i, ev in enumerate(events)
               if ev.get("status") not in DECISION_STATES
               or not isinstance(ev.get("identities"), list)]
        if bad:
            out.update(state="broken", broken_at=bad[0],
                       detail="line %d is chained but is not a decision" % bad[0])
    return out


def load_decisions(evidence_root: str,
                   problems: Optional[List[str]] = None) -> List[dict]:
    """Every decision in the order it was recorded. A line that does not parse
    is skipped and reported through `problems`, never silently dropped: a
    ledger with a damaged line is a ledger the reader must know is damaged."""
    path = ledger_path(evidence_root)
    events: List[dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for n, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    ev = json.loads(raw)
                except json.JSONDecodeError as exc:
                    msg = "ledger line %d does not parse: %s" % (n, exc)
                    LOG.warning("decisions: %s", msg)
                    if problems is not None:
                        problems.append(msg)
                    continue
                if not isinstance(ev, dict) or ev.get("status") not in DECISION_STATES \
                        or not isinstance(ev.get("identities"), list):
                    msg = "ledger line %d is not a decision" % n
                    LOG.warning("decisions: %s", msg)
                    if problems is not None:
                        problems.append(msg)
                    continue
                events.append(ev)
    except FileNotFoundError:
        return []
    except OSError as exc:
        LOG.warning("decisions: cannot read %s: %s", path, exc)
        if problems is not None:
            problems.append("cannot read the ledger: %s" % exc)
    return events


def current_decisions(evidence_root: str, target: str) -> Dict[Tuple[str, str], dict]:
    """{(scanner, identity): latest decision} for one target. Later lines win,
    so re-marking an advisory supersedes the earlier mark without erasing it."""
    out: Dict[Tuple[str, str], dict] = {}
    for ev in load_decisions(evidence_root):
        if ev.get("target") != target:
            continue
        for ident in ev.get("identities", []):
            out[(ev.get("scanner", ""), ident)] = ev
    return out


def summarize(events: List[Optional[dict]]) -> dict:
    """The state of a group of findings from their individual decisions.

    Every item decided the same way is that status; nothing decided is `open`;
    anything else is `partial`, with the counts, so a rule that gained new
    instances since it was reviewed reads as "reviewed 3/5" rather than as
    reviewed. `who`, `at` and `note` come from the most recent decision."""
    total = len(events)
    decided = [e for e in events if e]
    latest = max(decided, key=lambda e: e.get("at", "")) if decided else None
    statuses = {e["status"] for e in decided}
    if not decided or (statuses == {"open"} and len(decided) == total):
        status = "open"
    elif len(decided) == total and len(statuses) == 1:
        status = statuses.pop()
    else:
        status = "partial"
    return {"status": status, "decided": len(decided), "total": total,
            "who": latest.get("who", "") if latest else "",
            "at": latest.get("at", "") if latest else "",
            "note": latest.get("note", "") if latest else "",
            "latest": latest.get("status", "") if latest else ""}


# ---- the watchlist -------------------------------------------------------
# CVEs the operator wants flagged whenever they appear in the estate. Human
# input like a decision, so it is kept the same way: one append-only, chained
# line per change in `<evidence_root>/intel/watch.jsonl`, and the current list
# is the last line for each CVE. Taking a CVE off the list is a new line, never
# an edit, so the record shows when it was watched and when it stopped being.
# Plan 06, step 6.

WATCH_ACTIONS = ("watch", "unwatch")
# The same shape `feeds.cve_of` reads off a finding, matched whole: `$` would
# also accept a trailing newline, and that id never equals an estate key.
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")


def watch_path(evidence_root: str) -> str:
    """Where the watchlist lives in an evidence root."""
    return os.path.join(evidence_root, "intel", "watch.jsonl")


def record_watch(evidence_root: str, cve: str, action: str = "watch",
                 reason: str = "", by: Optional[str] = None,
                 at: Optional[str] = None) -> dict:
    """Add a CVE to the watchlist or take it off, and return the line written.
    Raises ValueError, writing nothing, for an unknown action, an id that is not
    a CVE, or a reason past the cap."""
    if action not in WATCH_ACTIONS:
        raise ValueError("unknown watch action %r (one of %s)"
                         % (action, ", ".join(WATCH_ACTIONS)))
    cve = (cve or "").strip().upper()
    if not is_cve_id(cve):
        raise ValueError("not a CVE id: %r (expected CVE-YYYY-NNNN)" % cve)
    if len(reason) > NOTE_CAP:
        raise ValueError("reason is longer than %d characters" % NOTE_CAP)
    event = {
        "v": _LEDGER_VERSION,
        "at": at or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
        "who": by or who(),
        "action": action,
        "cve": cve,
        "reason": reason,
    }
    append_chained(watch_path(evidence_root), event)
    LOG.info("watchlist: %s %s by %s", action, cve, event["who"])
    return event


def is_cve_id(text: str) -> bool:
    """True for a whole CVE id (`CVE-2021-44228`), nothing before or after it."""
    return bool(_CVE_ID.fullmatch(text or ""))


def _is_watch_line(ev: object) -> bool:
    """A parsed line is a watch entry: a known action on a whole CVE id."""
    return (isinstance(ev, dict) and ev.get("action") in WATCH_ACTIONS
            and isinstance(ev.get("cve"), str) and is_cve_id(ev["cve"]))


def load_watch_events(evidence_root: str,
                      problems: Optional[List[str]] = None) -> List[dict]:
    """Every watchlist line in the order written. A line that does not parse or
    is not a watch line is skipped and reported through `problems`: a damaged
    watchlist is one the reader must be told about, because a lost line can
    silently un-watch a CVE."""
    path = watch_path(evidence_root)
    events: List[dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for n, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    ev = json.loads(raw)
                except json.JSONDecodeError as exc:
                    msg = "watchlist line %d does not parse: %s" % (n, exc)
                    LOG.warning("watchlist: %s", msg)
                    if problems is not None:
                        problems.append(msg)
                    continue
                if not _is_watch_line(ev):
                    msg = "watchlist line %d is not a watch entry" % n
                    LOG.warning("watchlist: %s", msg)
                    if problems is not None:
                        problems.append(msg)
                    continue
                events.append(ev)
    except FileNotFoundError:
        return []
    except OSError as exc:
        LOG.warning("watchlist: cannot read %s: %s", path, exc)
        if problems is not None:
            problems.append("cannot read the watchlist: %s" % exc)
    return events


def current_watchlist(evidence_root: str,
                      problems: Optional[List[str]] = None) -> Dict[str, dict]:
    """{CVE: the line that put it on the list} for every CVE watched now. The
    last line for a CVE wins, so an unwatch removes it and a later watch puts it
    back, with that later line's reason."""
    latest: Dict[str, dict] = {}
    for ev in load_watch_events(evidence_root, problems):
        latest[ev["cve"]] = ev
    return {c: ev for c, ev in sorted(latest.items()) if ev["action"] == "watch"}


def verify_watchlist(evidence_root: str, since_head: str = "") -> dict:
    """Walk the watchlist's chain and name the first line that does not hold:
    the same walk as the decisions ledger, plus the rule that every chained
    line is a watch entry (a known action on a CVE id)."""
    out = walk_chain(watch_path(evidence_root), since_head,
                     min_version=2, what="watch entry")
    events = out.pop("events", [])
    if not out["present"]:
        out["detail"] = "nothing on the watchlist" if not since_head else \
            "the watchlist verified earlier is gone"
        return out
    if out["state"] == "ok":
        bad = [i + 1 for i, ev in enumerate(events) if not _is_watch_line(ev)]
        if bad:
            out.update(state="broken", broken_at=bad[0],
                       detail="line %d is chained but is not a watch entry" % bad[0])
    return out


__all__ = [
    'DECISION_STATES',
    'LEDGER_STATES',
    'NOTE_CAP',
    'WATCH_ACTIONS',
    '_CVE_ID',
    '_LEDGER_VERSION',
    '_is_watch_line',
    'current_decisions',
    'current_watchlist',
    'is_cve_id',
    'ledger_path',
    'load_decisions',
    'load_watch_events',
    'record_decision',
    'record_watch',
    'summarize',
    'verify_ledger',
    'verify_watchlist',
    'watch_path',
    'who',
]

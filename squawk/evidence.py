"""Reading runs back from the evidence root: manifests, findings, identities, history."""

import json
import os
import time
from typing import Callable, Dict, List, Optional, Tuple

from squawk.core import (
    FEEDS_DIRNAME,
    INSTALL_DIRNAME,
    LOG,
    append_chained,
    as_text,
    sha256_file,
    walk_chain,
)

# --------------------------------------------------------------------------- #
# Evidence reading — the run directory is the source of truth. Nothing here
# re-runs a scanner; it reads what a run left behind.
# --------------------------------------------------------------------------- #


def list_runs(evidence_root: str) -> List[dict]:
    """Every run's digest + manifest, newest first."""
    runs: List[dict] = []
    if not os.path.isdir(evidence_root):
        return runs
    for name in os.listdir(evidence_root):
        run_dir = os.path.join(evidence_root, name)
        man_path = os.path.join(run_dir, "manifest.json")
        if not os.path.isfile(man_path):
            continue
        try:
            with open(man_path, encoding="utf-8") as fh:
                man = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        man["_dir"] = run_dir
        ok = set()
        for row in man.get("ledger", []):
            if row.get("status") == "ok":
                ok.add(row["tool"])
        man["_ok_tools"] = ok
        runs.append(man)
    runs.sort(key=lambda m: m.get("run_id", ""), reverse=True)
    return runs


def count_runs(evidence_root: str) -> int:
    """How many runs are on disk, by looking rather than by reading.

    The top bar shows this on every page, and the job page reloads every few
    seconds while a scan runs, so `len(list_runs(...))` meant parsing every
    manifest in the store several times a minute — eighty-five JSON documents
    on the owner's box, for one number. Measured after the owner reported the
    machine getting sluggish while watching a probe (#126, 2026-09-07)."""
    if not os.path.isdir(evidence_root):
        return 0
    n = 0
    for name in os.listdir(evidence_root):
        if os.path.isfile(os.path.join(evidence_root, name, "manifest.json")):
            n += 1
    return n


def load_identities(run_dir: str) -> Dict[str, List[str]]:
    try:
        with open(os.path.join(run_dir, "identities.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def load_findings(run_dir: str) -> List[dict]:
    try:
        with open(os.path.join(run_dir, "findings.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []


def target_key(man: dict) -> str:
    """Runs are only comparable if they scanned the same thing the same way.
    The reference you gave is part of the identity: repo:/a and repo:/b differ,
    and an image compared against a repo is nonsense wearing a diff's clothes."""
    return "%s|%s|%s" % (man.get("service"), man.get("scope"), man.get("target"))


def diff_runs(older: dict, newer: dict) -> Dict[str, dict]:
    """Per-scanner identity diff. A scanner that did not run OK in BOTH runs is
    reported as silent, never as resolved — otherwise a one-tool run would read
    as everything else being fixed."""
    old_ids = load_identities(older["_dir"])
    new_ids = load_identities(newer["_dir"])
    old_ok = older.get("_ok_tools", set())
    new_ok = newer.get("_ok_tools", set())
    out: Dict[str, dict] = {}
    for tool in sorted(set(old_ids) | set(new_ids) | old_ok | new_ok):
        if tool in old_ok and tool in new_ok:
            o, n = set(old_ids.get(tool, [])), set(new_ids.get(tool, []))
            out[tool] = {"silent": False,
                         "added": sorted(n - o), "removed": sorted(o - n),
                         "unchanged": len(o & n)}
        else:
            missing = "new run" if tool not in new_ok else "previous run"
            out[tool] = {"silent": True, "reason": "did not run in the %s" % missing,
                         "added": [], "removed": [], "unchanged": 0}
    return out


def estate_runs(root: str) -> Tuple[Dict[str, dict], Dict[str, dict], Dict[str, List[dict]]]:
    """(live, vanished, by_target) — the newest run of each target, split by
    whether the target is still on disk, plus every run per target.

    A target whose directory is gone (a temp dir from an earlier run) is not
    the estate as it stands. It is kept as evidence and shown, never counted,
    so it cannot pad a total. One function so every page that answers "what do
    I look after" answers it the same way.
    """
    latest: Dict[str, dict] = {}
    by_target: Dict[str, List[dict]] = {}
    for man in list_runs(root):                       # newest first
        latest.setdefault(target_key(man), man)
        by_target.setdefault(target_key(man), []).append(man)
    vanished = {k: m for k, m in latest.items()
                if m.get("scope") in ("repo", "dir")
                and not os.path.isdir(m.get("target", ""))}
    live = {k: m for k, m in latest.items() if k not in vanished}
    return live, vanished, by_target


def iso_week(run_id: str) -> str:
    try:
        t = time.strptime(run_id[:15], "%Y%m%dT%H%M%S")
        y, w, _ = time.strftime("%G-%V-1", t).split("-")
        return "%s-W%s" % (y, w)
    except (ValueError, IndexError):
        return "?"


def finding_history(root: str, man: dict) -> Dict[str, dict]:
    """{identity: {first, last, runs}} across every comparable run of this
    target. Reconstructed from immutable run evidence rather than kept in a
    separate ledger, so it cannot drift from what was actually recorded."""
    key = target_key(man)
    same = sorted((m for m in list_runs(root) if target_key(m) == key),
                  key=lambda m: m["run_id"])
    hist: Dict[str, dict] = {}
    for run in same:
        rid = run["run_id"]
        for ids in load_identities(run["_dir"]).values():
            for ident in ids:
                h = hist.setdefault(ident, {"first": rid, "last": rid, "runs": 0})
                h["last"] = rid
                h["runs"] += 1
    return hist


HISTORY_FILE = "history.json"
REMEDIATION_STATES = ("open", "resolved", "regressed")


def remediation_timeline(root: str, man: dict) -> Dict[Tuple[str, str], dict]:
    """{(scanner, identity): {first_seen, last_seen, runs, status, resolved_on,
    regressed_on, regressions}} for every finding this target has ever
    recorded, as of the run `man`, walking its comparable runs in order.

    The rule that keeps it honest: only a run in which a scanner ran OK can say
    anything about that scanner's findings. Present in such a run is open (or
    regressed, if it had been resolved); absent from such a run after having
    been seen is resolved, dated to that run. A run where the scanner was a
    gap, an error or skipped changes nothing, so a disabled scanner never reads
    as a fix. Reconstructed from the immutable run evidence rather than kept in
    a mutable ledger, so it cannot drift from what was recorded."""
    key = target_key(man)
    same = sorted((m for m in list_runs(root)
                   if target_key(m) == key and m["run_id"] <= man["run_id"]),
                  key=lambda m: m["run_id"])
    state: Dict[Tuple[str, str], dict] = {}
    for run in same:
        rid = run["run_id"]
        ids = load_identities(run["_dir"])
        for tool in sorted(run.get("_ok_tools", set())):
            present = set(ids.get(tool, []))
            for ident in sorted(present):
                h = state.get((tool, ident))
                if h is None:
                    state[(tool, ident)] = {
                        "first_seen": rid, "last_seen": rid, "runs": 1,
                        "status": "open", "resolved_on": None,
                        "regressed_on": None, "regressions": 0}
                    continue
                h["runs"] += 1
                h["last_seen"] = rid
                if h["status"] == "resolved":
                    h["status"] = "regressed"
                    h["regressed_on"] = rid
                    h["regressions"] += 1
            for (t, ident), h in state.items():
                if t == tool and ident not in present and h["status"] != "resolved":
                    h["status"] = "resolved"
                    h["resolved_on"] = rid
    return state


def history_counts(entries: Dict[Tuple[str, str], dict]) -> Dict[str, int]:
    counts = {st: 0 for st in REMEDIATION_STATES}
    for h in entries.values():
        st = h.get("status", "open")
        counts[st] = counts.get(st, 0) + 1
    return counts


def history_document(run_id: str, entries: Dict[Tuple[str, str], dict]) -> dict:
    """The history.json a run writes: its target's timeline as of that run, so
    what the tool reported on that date is itself part of the evidence."""
    rows = [dict(scanner=t, identity=i, **h) for (t, i), h in sorted(entries.items())]
    return {"schema": 1, "schema_version": SCHEMA_VERSION, "run_id": run_id,
            "counts": history_counts(entries), "entries": rows}


def load_history(run_dir: str) -> Optional[dict]:
    try:
        with open(os.path.join(run_dir, HISTORY_FILE), encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    return doc if isinstance(doc, dict) and isinstance(doc.get("entries"), list) else None


def history_entries(root: str, man: dict) -> Tuple[Dict[Tuple[str, str], dict], bool]:
    """The remediation state of every finding this target has recorded, as of
    `man`: the history.json the run wrote when it has one, else reconstructed
    now (runs older than the file). The flag says which, so a page can say
    whether it is reading a record or computing one."""
    doc = load_history(man.get("_dir", ""))
    if doc is not None:
        out: Dict[Tuple[str, str], dict] = {}
        for e in doc["entries"]:
            if isinstance(e, dict):
                out[(str(e.get("scanner", "")), str(e.get("identity", "")))] = e
        return out, True
    return remediation_timeline(root, man), False


# --------------------------------------------------------------------------- #
# Tamper-evident evidence — the digest chain.
#
# Every run writes `digest.json` last, holding the sha256 of every other file in
# the run directory, the id of the run that preceded it anywhere in the evidence
# root, and the sha256 of that run's digest. So each run proves its own contents
# and proves the previous run existed at the moment this one was written.
#
# What this proves: nothing was edited or removed after the fact by anyone who
# did not also rewrite every later digest. What it does NOT prove: who wrote it.
# There are no signatures and no keys here, so a person who can write the whole
# evidence root can rebuild a consistent chain. It is tamper *evidence* for the
# person who holds the files, not proof of authorship to a third party.
# --------------------------------------------------------------------------- #

SCHEMA_VERSION = 1
MANIFEST_FILE = "manifest.json"
DIGEST_FILE = "digest.json"
PRUNE_RECORD = "pruned.json"
TRIM_PARTS = ("raw", "history.json")
DROPPED_FILE = "pruned-runs.jsonl"     # the retention record: every trim and drop, chained
RETENTION_VERSION = 2                  # v2 lines carry kind, parts and prev_sha256
STARTED_FILE = "started.json"
VERIFY_FILE = "verify.json"            # the last `squawk verify` result
# Files that may legitimately appear in a run directory after the digest was
# sealed. Everything else that is not in the digest is an addition, and an
# addition to write-once evidence is reported.
LATER_FILES = (DIGEST_FILE, PRUNE_RECORD)

VERIFY_STATES = ("ok", "altered", "missing", "extra", "chain broken", "unverifiable")


def run_file_names(run_dir: str) -> List[str]:
    """Every file in a run directory, relative and sorted, except the digest
    itself — a file cannot hold its own hash."""
    out: List[str] = []
    for cur, _dirs, files in os.walk(run_dir):
        for name in files:
            rel = os.path.relpath(os.path.join(cur, name), run_dir)
            if rel == DIGEST_FILE:
                continue
            out.append(rel.replace(os.sep, "/"))
    return sorted(out)


def hash_run_files(run_dir: str) -> Dict[str, str]:
    """{relative path: sha256} for everything the digest will cover."""
    out: Dict[str, str] = {}
    for rel in run_file_names(run_dir):
        try:
            out[rel] = sha256_file(os.path.join(run_dir, rel.replace("/", os.sep)))
        except OSError as exc:
            LOG.warning("digest: cannot hash %s in %s: %s", rel, run_dir, exc)
    return out


def run_ids(root: str) -> List[str]:
    """Every run id in the evidence root, oldest first, for the chain and for
    `verify`. A run is a directory that was ever a run: it holds a digest, a
    manifest, or the started.json a run writes before anything else. Not only
    a manifest — that definition let a run whose manifest had been deleted
    vanish from `verify` with exit 0, which is the opposite of its job. (The
    pages still read runs through `list_runs`, which needs the manifest to
    have anything to show; a run without one is `verify`'s business.)"""
    out: List[str] = []
    try:
        names = os.listdir(root)
    except OSError:
        return out
    for name in names:
        if name in (INSTALL_DIRNAME, FEEDS_DIRNAME, "decisions"):
            continue
        d = os.path.join(root, name)
        if not os.path.isdir(d):
            continue
        if any(os.path.isfile(os.path.join(d, f))
               for f in (DIGEST_FILE, MANIFEST_FILE, STARTED_FILE)):
            out.append(name)
    return sorted(out)


def retention_records(root: str) -> List[dict]:
    """Every trim and drop retention ever recorded, in order. A line that does
    not parse is skipped and logged, never silently dropped. Lines written
    before the record was chained (no `kind`) are drops: that was all it held."""
    path = os.path.join(root, DROPPED_FILE)
    out: List[dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for n, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except ValueError:
                    LOG.warning("retention record line %d does not parse", n)
                    continue
                if not isinstance(rec, dict) or not rec.get("run_id"):
                    continue
                rec.setdefault("kind", "drop")
                out.append(rec)
    except FileNotFoundError:
        return out
    except OSError as exc:
        LOG.warning("cannot read %s: %s", DROPPED_FILE, exc)
    return out


def dropped_runs(root: str) -> Dict[str, dict]:
    """Runs retention removed, by run id, each carrying the removed run's
    digest hash so the link before and after it still verifies. A drop with
    no record is a hole in the chain; a drop with one is listed, by name and
    date, every time `verify` runs — a record is only as good as the machine
    that wrote it, so it is shown rather than trusted quietly."""
    return {r["run_id"]: r for r in retention_records(root) if r.get("kind") == "drop"}


def trimmed_parts(root: str) -> Dict[str, List[str]]:
    """{run_id: [part, ...]} that retention recorded trimming. Only the parts
    retention can trim count (`TRIM_PARTS`): a record claiming findings.json
    was trimmed is not a record of a trim, and a file it names stays
    `missing`. This record, not the run's own `pruned.json`, is what `verify`
    reads: `pruned.json` sits inside the run after the digest was sealed, so
    it is exactly the file a forger would write."""
    out: Dict[str, List[str]] = {}
    for r in retention_records(root):
        if r.get("kind") != "trim":
            continue
        parts = [str(p) for p in (r.get("parts") or []) if str(p) in TRIM_PARTS]
        out.setdefault(r["run_id"], [])
        out[r["run_id"]].extend(p for p in parts if p not in out[r["run_id"]])
    return out


def record_prune(root: str, kind: str, run_id: str, target: str,
                 parts: Optional[List[str]] = None, digest_sha256: str = "",
                 by: str = "") -> dict:
    """Record one retention act before it happens. `kind` is `trim` (with the
    parts) or `drop` (with the run's digest hash). Append-only and chained,
    the same discipline as the decisions ledger, so a record cannot be edited
    or removed later without the next line disagreeing."""
    if kind not in ("trim", "drop"):
        raise ValueError("kind must be trim or drop, not %r" % kind)
    rec = {"v": RETENTION_VERSION, "kind": kind, "run_id": run_id, "target": target,
           "at": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()), "by": by}
    if kind == "trim":
        rec["parts"] = [p for p in (parts or []) if p in TRIM_PARTS]
    else:
        rec["digest_sha256"] = digest_sha256
    return append_chained(os.path.join(root, DROPPED_FILE), rec)


def verify_retention(root: str, since_head: str = "") -> dict:
    """The retention record's own chain. `verify` reads what the record says
    only after checking the record itself holds."""
    out = walk_chain(os.path.join(root, DROPPED_FILE), since_head,
                     min_version=RETENTION_VERSION, what="retention record")
    out.pop("events", None)
    if not out["present"]:
        out["detail"] = "nothing pruned"
    return out


def previous_run(root: str, run_id: str) -> Optional[str]:
    """The run that precedes this one anywhere in the evidence root — across
    every target, because the chain is over the store, not over one target.
    A run retention removed still counts: its record keeps the link.

    Only a *finished* run can be linked to: one that has written its digest.
    A run still in progress has no digest to hash, and linking to it would
    record either nothing or, worse, the hash of a half-written file — which
    happened when two runs finished within the same second."""
    finished = {rid for rid in run_ids(root)
                if os.path.isfile(os.path.join(root, rid, DIGEST_FILE))}
    candidates = finished | set(dropped_runs(root))
    older = sorted(c for c in candidates if c < run_id)
    return older[-1] if older else None


def write_digest(run_dir: str, digest: dict) -> None:
    """Write digest.json so that no reader ever sees a partial file: to a
    temporary name in the same directory, then one atomic rename. Another run
    finishing at the same moment hashes this file for its own chain link, and
    a hash of half a file is a chain that breaks at the next verify."""
    final = os.path.join(run_dir, DIGEST_FILE)
    tmp = os.path.join(run_dir, ".%s.tmp" % DIGEST_FILE)
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(digest, fh, indent=2, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, final)


def load_digest(run_dir: str) -> Optional[dict]:
    try:
        with open(os.path.join(run_dir, DIGEST_FILE), encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def digest_sha256(run_dir: str) -> str:
    """The sha256 of a run's digest.json as written. Empty if it is not there."""
    try:
        return sha256_file(os.path.join(run_dir, DIGEST_FILE))
    except OSError:
        return ""


def chain_fields(root: str, run_id: str) -> Dict[str, Optional[str]]:
    """The two fields that link a run to the one before it. Computed at write
    time, when the previous run is whatever was newest in the store."""
    prev = previous_run(root, run_id)
    if prev is None:
        return {"prev_run": None, "prev_digest_sha256": None}
    sha: Optional[str] = digest_sha256(os.path.join(root, prev)) or None
    if sha is None:
        drop = dropped_runs(root).get(prev) or {}
        sha = str(drop.get("digest_sha256", "")) or None
    return {"prev_run": prev, "prev_digest_sha256": sha}


def seal_run(run_dir: str) -> int:
    """Make every file in a finished run read-only to its owner (0400).

    This is a tripwire, not tamper evidence: anyone who can write the directory
    can chmod it back. What it buys is that no ordinary mistake — a script with
    a stray `>`, an editor saving over a manifest — can change evidence without
    a deliberate act first. The digest is what actually detects a change.
    Returns how many files were sealed; a failure is logged, never fatal."""
    n = 0
    for cur, _dirs, files in os.walk(run_dir):
        for name in files:
            try:
                os.chmod(os.path.join(cur, name), 0o400)
                n += 1
            except OSError as exc:
                LOG.warning("could not seal %s: %s", os.path.join(cur, name), exc)
    return n


def _accounted_for(rel: str, parts: List[str]) -> bool:
    return any(rel == part or rel.startswith(part.rstrip("/") + "/") for part in parts)


def verify_run(root: str, run_id: str, dropped: Dict[str, dict],
               trimmed: Optional[Dict[str, List[str]]] = None) -> dict:
    """One run against its own digest and against the run before it."""
    run_dir = os.path.join(root, run_id)
    man = {}
    try:
        with open(os.path.join(run_dir, MANIFEST_FILE), encoding="utf-8") as fh:
            man = json.load(fh)
    except (OSError, ValueError):
        man = {}
    out = {"run_id": run_id, "target": man.get("target", ""),
           "service": man.get("service", ""), "state": "ok", "detail": "",
           "altered": [], "missing": [], "pruned": [], "extra": [], "notes": [],
           "digest_sha256": ""}

    doc = load_digest(run_dir)
    if doc is None:
        out["state"] = "unverifiable"
        if not man and os.path.isfile(os.path.join(run_dir, STARTED_FILE)):
            out["detail"] = ("unfinished: started and never wrote a manifest — "
                             "still running, or waiting to be recorded as aborted")
        else:
            out["detail"] = "no digest.json"
        return out
    out["digest_sha256"] = digest_sha256(run_dir)
    files = doc.get("files")
    if not isinstance(files, dict):
        out["state"] = "unverifiable"
        out["detail"] = ("written before digests carried file hashes "
                         "(schema %s)" % doc.get("schema_version", 0))
        return out

    parts = (trimmed or {}).get(run_id, [])
    for rel in sorted(files):
        path = os.path.join(run_dir, rel.replace("/", os.sep))
        if not os.path.exists(path):
            (out["pruned"] if _accounted_for(rel, parts) else out["missing"]).append(rel)
            continue
        try:
            if sha256_file(path) != files[rel]:
                out["altered"].append(rel)
        except OSError as exc:
            out["missing"].append("%s (%s)" % (rel, exc))
    for rel in run_file_names(run_dir):
        if rel not in files and rel not in LATER_FILES:
            out["extra"].append(rel)

    # The chain. The strong link is the previous run's digest hash; a run that
    # is simply older than this one but was copied in later is noted, not
    # failed, because the tool cannot have written it into this chain.
    prev = doc.get("prev_run")
    prev_sha = doc.get("prev_digest_sha256")
    if prev:
        have = digest_sha256(os.path.join(root, str(prev)))
        tomb = dropped.get(str(prev))
        if not have and tomb:
            have = tomb.get("digest_sha256", "")
            out["notes"].append("previous run %s was removed by retention on %s"
                                % (prev, tomb.get("at", "an unrecorded date")))
        if not have:
            out["state"] = "chain broken"
            out["detail"] = ("expected the run before it to be %s; that run is "
                             "gone and nothing records its removal" % prev)
            return out
        if prev_sha and have != prev_sha:
            out["state"] = "chain broken"
            out["detail"] = ("the run before it (%s) does not match what was "
                             "recorded here: expected %s, found %s"
                             % (prev, str(prev_sha)[:16], have[:16]))
            return out
    actual = previous_run(root, run_id)
    if actual != (prev or None):
        out["notes"].append("the run before it is now %s, was %s when this was "
                            "written" % (actual or "none", prev or "none"))

    if out["altered"]:
        out["state"] = "altered"
        out["detail"] = ", ".join(out["altered"])
    elif out["missing"]:
        out["state"] = "missing"
        out["detail"] = ", ".join(out["missing"])
    elif out["extra"]:
        out["state"] = "extra"
        out["detail"] = ", ".join(out["extra"])
    elif out["pruned"]:
        out["detail"] = "%d file(s) removed by retention, recorded" % len(out["pruned"])
    return out


def verify_runs(root: str, previous: Optional[dict] = None,
                progress: Optional[Callable[[dict], None]] = None) -> dict:
    """Every run in the evidence root, oldest first, against its digest, the
    chain, and what the previous verify saw. Pure: it prints nothing and writes
    nothing; `progress` is called with each run's row as it is finished, so a
    caller can show movement on a large root.

    `previous` is the last verify's report. It carries `digests`, the hash of
    every run's digest.json as it stood then, which is what a hash chain cannot
    give itself: nothing vouches for the newest run's digest, so a forger could
    alter the newest run and rewrite its digest to match. Once a verify has
    recorded that digest, the next verify sees the rewrite. And a run that was
    there then and is gone now must have a retention record, or it is missing
    — not merely absent from a list that no longer mentions it."""
    dropped = dropped_runs(root)
    trimmed = trimmed_parts(root)
    seen_before = (previous or {}).get("digests") or {}
    verified_at = (previous or {}).get("at", "")
    rows: List[dict] = []
    for rid in run_ids(root):
        row = verify_run(root, rid, dropped, trimmed)
        # The comparison with the previous verify happens BEFORE the row is
        # handed to `progress`: the CLI prints each row as it arrives, and a
        # row amended after printing is a row the reader never sees amended.
        sha = seen_before.get(rid)
        if row["digest_sha256"] and sha and row["digest_sha256"] != sha:
            if row["state"] in ("ok", "unverifiable"):
                row["state"] = "altered"
                row["altered"].append(DIGEST_FILE)
                row["detail"] = ("digest.json was rewritten after the verify on %s"
                                 % verified_at)
            else:
                row["notes"].append("digest.json was also rewritten after the "
                                    "verify on %s" % verified_at)
        rows.append(row)
        if progress:
            progress(row)
    now = {r["run_id"] for r in rows}
    for rid in sorted(seen_before):
        if rid in now or rid in dropped:      # present, or removed by retention and listed
            continue
        gone = {"run_id": rid, "target": "", "service": "", "state": "missing",
                "detail": ("verified on %s, now gone, and nothing records its "
                           "removal" % verified_at),
                "altered": [], "missing": ["(the whole run)"], "pruned": [],
                "extra": [], "notes": [], "digest_sha256": ""}
        rows.append(gone)
        if progress:
            progress(gone)
    rows.sort(key=lambda r: r["run_id"])
    counts = {st: sum(1 for r in rows if r["state"] == st) for st in VERIFY_STATES}
    pruned = [{"run_id": r["run_id"], "kind": r.get("kind", "drop"),
               "at": r.get("at", ""), "by": r.get("by", ""),
               "parts": r.get("parts", [])} for r in retention_records(root)]
    return {"runs": rows, "counts": counts, "dropped": len(dropped),
            "pruned_runs": pruned,
            "digests": {r["run_id"]: r["digest_sha256"] for r in rows
                        if r["digest_sha256"]},
            "failed": sum(counts[st] for st in VERIFY_STATES
                          if st not in ("ok", "unverifiable")),
            "unverifiable": counts["unverifiable"], "total": len(rows)}


def load_verify(root: str) -> Optional[dict]:
    """The last verify result, or None — which the pages must show as `never
    verified`, never as ok."""
    try:
        with open(os.path.join(root, VERIFY_FILE), encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def save_verify(root: str, report: dict) -> str:
    path = os.path.join(root, VERIFY_FILE)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
    return path


def record_aborted_run(run_dir: str, reason: str) -> bool:
    """Write the manifest of a run that never finished: aborted, with the
    service and target it was for (from started.json), an empty ledger so it
    reads as incomplete everywhere, and the reason. O_EXCL, so a run finishing
    at the same moment is never clobbered. True if a manifest was written."""
    if os.path.exists(os.path.join(run_dir, MANIFEST_FILE)):
        return False
    if os.path.exists(os.path.join(run_dir, DIGEST_FILE)):
        # A digest means the run finished and was sealed. A manifest missing
        # beside it is evidence that was removed, which is `verify`'s to name;
        # writing an "aborted" manifest over it would paper over the removal,
        # and the digest is 0400 so the write would fail and take the server
        # down with it. Both happened before this line existed.
        LOG.warning("run %s has a digest but no manifest: not a run to record "
                    "as aborted; `squawk verify` will name what is missing",
                    os.path.basename(run_dir.rstrip(os.sep)))
        return False
    started_path = os.path.join(run_dir, STARTED_FILE)
    if not os.path.exists(started_path):
        return False                       # not a run this tool started
    try:
        with open(started_path, encoding="utf-8") as fh:
            st = json.load(fh)
    except (OSError, ValueError):
        st = {}
    name = os.path.basename(run_dir.rstrip(os.sep))
    man = {"schema_version": SCHEMA_VERSION,
           "run_id": name, "service": st.get("service", ""),
           "service_label": st.get("service_label", "aborted run"),
           # as_text, not `.get(k, "")`: a started.json holding a null gets
           # that null copied into the manifest, where it outlives the run and
           # breaks whatever renders it later.
           "scope": as_text(st.get("scope")), "target": as_text(st.get("target")),
           "not_covered": as_text(st.get("not_covered")),
           "counts": {"total": 0, "excluded": 0}, "severities": {}, "ledger": [],
           "aborted": True, "aborted_reason": reason,
           "aborted_at": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
           "started_at": st.get("started_at", "")}
    try:
        fd = os.open(os.path.join(run_dir, "manifest.json"),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(man, fh, indent=2, sort_keys=True)
    for fname, obj in (("findings.json", []), ("identities.json", {})):
        fpath = os.path.join(run_dir, fname)
        if not os.path.exists(fpath):
            with open(fpath, "w", encoding="utf-8") as fh:
                json.dump(obj, fh)
    # The digest goes last and covers what actually exists, so a run that never
    # finished is still provably unaltered since it was abandoned. An aborted
    # run is evidence too, and evidence that cannot be verified is a gap.
    root = os.path.dirname(os.path.abspath(run_dir.rstrip(os.sep)))
    digest = {"schema_version": SCHEMA_VERSION, "run_id": name, "aborted": True,
              "files": hash_run_files(run_dir)}
    digest.update(chain_fields(root, name))
    write_digest(run_dir, digest)
    seal_run(run_dir)
    LOG.warning("GAP run %s never finished: recorded as aborted (%s)", name, reason)
    return True


def record_aborted_runs(root: str, reason: str,
                        older_than: Optional[float] = None) -> List[str]:
    """Sweep the evidence root for runs that started and never finished. With
    older_than set, only runs started at least that many seconds ago are
    recorded, so a run in progress in another terminal is left alone."""
    out: List[str] = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return out
    now = time.time()
    for name in names:
        d = os.path.join(root, name)
        if not os.path.isdir(d) or name in (INSTALL_DIRNAME, FEEDS_DIRNAME):
            continue
        if older_than is not None:
            try:
                age = now - os.path.getmtime(os.path.join(d, "started.json"))
            except OSError:
                continue
            if age < older_than:
                continue
        try:
            if record_aborted_run(d, reason):
                out.append(name)
        except OSError as exc:
            # One damaged run directory must never stop the sweep, or the
            # server that runs it at start-up.
            LOG.warning("could not record %s as aborted: %s", name, exc)
    return out


__all__ = [
    'DIGEST_FILE',
    'DROPPED_FILE',
    'HISTORY_FILE',
    'LATER_FILES',
    'MANIFEST_FILE',
    'PRUNE_RECORD',
    'REMEDIATION_STATES',
    'RETENTION_VERSION',
    'SCHEMA_VERSION',
    'STARTED_FILE',
    'TRIM_PARTS',
    'VERIFY_FILE',
    'VERIFY_STATES',
    '_accounted_for',
    'chain_fields',
    'count_runs',
    'diff_runs',
    'digest_sha256',
    'dropped_runs',
    'estate_runs',
    'finding_history',
    'hash_run_files',
    'history_counts',
    'history_document',
    'history_entries',
    'iso_week',
    'list_runs',
    'load_digest',
    'load_findings',
    'load_history',
    'load_identities',
    'load_verify',
    'previous_run',
    'record_aborted_run',
    'record_aborted_runs',
    'record_prune',
    'remediation_timeline',
    'retention_records',
    'run_file_names',
    'run_ids',
    'save_verify',
    'seal_run',
    'target_key',
    'trimmed_parts',
    'verify_retention',
    'verify_run',
    'verify_runs',
    'write_digest',
]

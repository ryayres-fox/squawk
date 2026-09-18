"""Retention: what evidence is kept, what is let go, and what is said about it.

Evidence grows without bound. A run of a working repository is a megabyte or so and
the biggest parts of it are the scanner's original output and, on a target with
history, a copy of that target's whole timeline; sixty runs of one target is a
directory nobody planned. The self-audit already warns when the volume is
filling, which is a report on a problem nothing solves.

Two rules shape everything here.

**Pruned evidence must never look like evidence that never existed.** Deleting a
run's raw output and showing the same blank space a run without raw output
shows is the tool's own cardinal sin wearing a housekeeping hat. Every run this
touches gets a `pruned.json` beside its manifest saying what went and when, and
the pages read it.

**Nothing is edited, only added or removed.** Run files are written once. So the
record of a prune is a new file rather than a field appended to the manifest,
and pruning removes whole files rather than rewriting any.

The policy has two tiers, because the parts of a run are not equally valuable:

  trim  drops `raw/` and the superseded `history.json`, keeping the manifest,
        the findings, the identities and the digest. Every page still renders,
        diffs still work, the timeline still resolves. What is lost is the
        ability to re-parse the scanner's own output or check a finding against
        it. Most of the bytes, little of the meaning.
  drop  removes the run directory entirely. The run stops existing, and the
        target's history gets shorter, which is a real loss and is why it is
        the second tier and never the default.

`history.json` is safe to trim from every run but the newest of its target: each
run writes the timeline as of itself, so the newest copy supersedes all the
others, and that is the one a page reads.
"""

import os
import shutil
import time
from typing import Dict, List, Optional, Tuple

from squawk.baselines import baseline_identity_set
from squawk.core import LOG
from squawk.decisions import load_decisions
from squawk.evidence import (
    PRUNE_RECORD,
    TRIM_PARTS,
    digest_sha256,
    list_runs,
    load_identities,
    record_prune,
    target_key,
)

# `PRUNE_RECORD` and `TRIM_PARTS` are defined in `squawk.evidence`, beside the
# digest that has to know a pruned file from a missing one, and imported here.

# Defaults chosen to be boring: a season of full evidence, a year of the record.
DEFAULT_TRIM_DAYS = 90
DEFAULT_DROP_DAYS = 365


def _size(path: str) -> int:
    if os.path.isfile(path):
        try:
            return os.path.getsize(path)
        except OSError:
            return 0
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def run_size(run_dir: str) -> Tuple[int, int]:
    """(total bytes, bytes a trim would reclaim) for one run."""
    return _size(run_dir), sum(_size(os.path.join(run_dir, p)) for p in TRIM_PARTS)


def run_age_days(man: dict, now: Optional[float] = None) -> Optional[float]:
    """Age from the run id, which is a UTC timestamp. None when it does not
    parse, and an unparseable id is never pruned: a run whose date cannot be
    read is not a run whose date is old."""
    try:
        t = time.strptime(str(man.get("run_id", ""))[:15], "%Y%m%dT%H%M%S")
    except (ValueError, TypeError):
        return None
    return ((now if now is not None else time.time()) - time.mktime(t)
            + time.timezone) / 86400.0


def protections(root: str) -> Dict[str, List[Tuple[str, str]]]:
    """{run_id: [(reason, what it blocks), ...]} for every run something depends on.

    What a dependency protects against differs, and treating them the same
    protects too much. Dropping a run removes its identities, so a decision
    pointing at it dangles and a baselined finding loses its evidence: those
    block `drop`. Trimming only removes the scanner's own output and a
    superseded timeline, which neither of those depends on, so they do not
    block `trim`. The newest run of a target blocks both, because it is the
    current answer for that target and its raw output is the one you would go
    back to.

    The second value is "drop" or "both"."""
    out: Dict[str, List[Tuple[str, str]]] = {}

    def add(run_id: str, why: str, blocks: str) -> None:
        out.setdefault(run_id, [])
        if (why, blocks) not in out[run_id]:
            out[run_id].append((why, blocks))

    runs = list_runs(root)
    newest: Dict[str, dict] = {}
    for man in runs:                       # list_runs is newest first
        newest.setdefault(target_key(man), man)
    for man in newest.values():
        add(man["run_id"], "newest run of its target", "both")

    for ev in load_decisions(root):
        rid = str(ev.get("run_id", ""))
        if rid:
            add(rid, "a triage decision was recorded against it", "drop")

    baseline = baseline_identity_set(root)
    if baseline:
        # Walk oldest first and keep the LAST run that holds each baselined
        # identity, so the newest evidence for a filed finding survives.
        holder: Dict[Tuple[str, str], str] = {}
        for man in sorted(runs, key=lambda m: m["run_id"]):
            for scanner, idents in load_identities(man["_dir"]).items():
                filed = baseline.get(scanner) or set()
                for ident in idents:
                    if ident in filed:
                        holder[(scanner, ident)] = man["run_id"]
        for rid in set(holder.values()):
            add(rid, "holds the newest evidence for a finding filed as a baseline",
                "drop")
    return out


def plan_prune(root: str, trim_days: int = DEFAULT_TRIM_DAYS,
               drop_days: int = DEFAULT_DROP_DAYS,
               now: Optional[float] = None) -> dict:
    """What a prune would do, without doing any of it. The dry run is the
    default everywhere because deleting evidence is the one irreversible thing
    this tool does."""
    runs = list_runs(root)
    guarded = protections(root)
    trim, drop, keep = [], [], []
    for man in sorted(runs, key=lambda m: m["run_id"], reverse=True):
        rid = man["run_id"]
        run_dir = man["_dir"]
        age = run_age_days(man, now)
        total, reclaim = run_size(run_dir)
        reasons = guarded.get(rid, [])
        row = {"run_id": rid, "dir": run_dir, "target": man.get("target", ""),
               "service": man.get("service", ""), "age_days": age,
               "bytes": total, "reclaim": reclaim,
               "already_pruned": os.path.exists(os.path.join(run_dir, PRUNE_RECORD)),
               "why": [w for w, _b in reasons]}
        no_trim = any(b == "both" for _w, b in reasons)
        if age is None:
            row["why"] = [*row["why"], "its run id does not parse as a date"]
            keep.append(row)
        elif age >= drop_days and not reasons:
            drop.append(row)
        elif age >= trim_days and reclaim > 0 and not no_trim:
            # An old run something still points at is trimmed rather than
            # removed: the identities a decision or a baseline depends on live
            # in identities.json, which trimming keeps.
            trim.append(row)
        else:
            keep.append(row)
    return {"root": root, "trim_days": trim_days, "drop_days": drop_days,
            "trim": trim, "drop": drop, "keep": keep,
            "reclaim": sum(r["reclaim"] for r in trim) + sum(r["bytes"] for r in drop),
            "total": sum(r["bytes"] for r in trim + drop + keep)}


def apply_prune(plan: dict, by: str = "") -> dict:
    """Carry out a plan. Returns what actually happened, which is not assumed to
    match what was planned: a directory can vanish between the two."""
    import json
    trimmed, dropped, failed = [], [], []
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    root = plan.get("root") or ""
    for row in plan.get("trim", []):
        present = [p for p in TRIM_PARTS if os.path.exists(os.path.join(row["dir"], p))]
        if not present:
            continue
        # The record goes first, into the chained retention file at the root,
        # not only into the run: `verify` reads that record to tell a pruned
        # file from a missing one, and a record inside the run directory is
        # exactly the file a forger would write. If the removal then fails, the
        # record names parts that are still there, which verify checks as
        # normal files — an over-claim costs nothing; the reverse would.
        try:
            if root:
                record_prune(root, "trim", row["run_id"], row.get("target", ""),
                             parts=present, by=by)
        except OSError as exc:
            failed.append({"run_id": row["run_id"], "part": "retention record",
                           "error": str(exc)})
            continue
        removed = []
        for part in present:
            path = os.path.join(row["dir"], part)
            try:
                shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
                removed.append(part)
            except OSError as exc:
                failed.append({"run_id": row["run_id"], "part": part, "error": str(exc)})
        if not removed:
            continue
        # A separate file, not a field added to the manifest: run files are
        # written once, and the record of a prune is an addition, not an edit.
        record = {"schema": 1, "at": stamp, "by": by, "removed": removed,
                  "reason": "retention: older than %d days" % plan.get("trim_days", 0)}
        try:
            with open(os.path.join(row["dir"], PRUNE_RECORD), "w",
                      encoding="utf-8") as fh:
                json.dump(record, fh, indent=2)
        except OSError as exc:
            failed.append({"run_id": row["run_id"], "part": PRUNE_RECORD,
                           "error": str(exc)})
        LOG.info("PRUNE trim run=%s removed=%s bytes=%d",
                 row["run_id"], ",".join(removed), row["reclaim"])
        trimmed.append({**row, "removed": removed})
    for row in plan.get("drop", []):
        # The record is written BEFORE the directory goes, and carries the
        # run's digest hash. Removing a run is allowed; removing it without a
        # trace is what the chain refuses, so the next run's link still
        # resolves and `verify` lists the removal by name and date.
        sha = digest_sha256(row["dir"])
        try:
            if root:
                record_prune(root, "drop", row["run_id"], row.get("target", ""),
                             digest_sha256=sha, by=by)
        except OSError as exc:
            failed.append({"run_id": row["run_id"], "part": "tombstone",
                           "error": str(exc)})
            continue
        try:
            shutil.rmtree(row["dir"])
            LOG.info("PRUNE drop run=%s bytes=%d", row["run_id"], row["bytes"])
            dropped.append(row)
        except OSError as exc:
            failed.append({"run_id": row["run_id"], "part": "run", "error": str(exc)})
    return {"trimmed": trimmed, "dropped": dropped, "failed": failed,
            "reclaimed": (sum(r["reclaim"] for r in trimmed)
                          + sum(r["bytes"] for r in dropped))}


def prune_record(run_dir: str) -> Optional[dict]:
    """What was pruned from this run, or None. A page that shows a run reads
    this so a trimmed run says so rather than showing the blank a run with no
    raw output would show."""
    import json
    try:
        with open(os.path.join(run_dir, PRUNE_RECORD), encoding="utf-8") as fh:
            rec = json.load(fh)
    except (OSError, ValueError):
        return None
    return rec if isinstance(rec, dict) and rec.get("removed") else None


def human_bytes(n: int) -> str:
    step = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if step < 1024 or unit == "TiB":
            return "%.0f %s" % (step, unit) if unit == "B" else "%.1f %s" % (step, unit)
        step /= 1024.0
    return "%d B" % n


__all__ = [
    'DEFAULT_DROP_DAYS',
    'DEFAULT_TRIM_DAYS',
    '_size',
    'apply_prune',
    'human_bytes',
    'plan_prune',
    'protections',
    'prune_record',
    'run_age_days',
    'run_size',
]

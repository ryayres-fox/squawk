"""Engagements: which engagement each target belongs to, for grouping and
scoping the web UI.

An engagement is a `session` tag — the word the CLI and reports already use: a
session tag groups runs and notes into an engagement. A run carries its
engagement in its manifest `session` field, stamped at scan time with
`--session` / `--engagement`. That leaves two gaps this module fills: a target
scanned before an engagement was named carries no tag, and re-tagging it would
mean re-scanning.

So an `engagements.json` file in the evidence root MAPS targets to an
engagement by name or glob, and the mapping WINS over the per-run tag — it is
how a target is reassigned without re-scanning. A target with neither is
`Unassigned`, and each target resolves to exactly one engagement (the first
assignment that matches, so order is priority).

The file, human-editable or written by `squawk engagements`:

    {
      "version": 1,
      "assignments": [
        {"engagement": "Acme web app", "match": ["acme-*", "*/acme-vuln"]},
        {"engagement": "Beacon API",   "match": ["beacon-*"]}
      ]
    }
"""
import fnmatch
import json
import os
from collections import OrderedDict
from typing import Dict, Iterable, List, Optional

#: The bucket for a target that no assignment and no run tag names.
UNASSIGNED = "Unassigned"

#: The mapping file, at the evidence root so it is easy to find and edit by hand.
ENGAGEMENTS_FILE = "engagements.json"


def engagements_path(evidence_root: str) -> str:
    return os.path.join(evidence_root, ENGAGEMENTS_FILE)


def load_engagements(evidence_root: str) -> dict:
    """The mapping, or an empty one when the file is missing or unreadable — the
    same fail-soft shape as the baselines and decisions readers."""
    try:
        with open(engagements_path(evidence_root), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"version": 1, "assignments": [], "hidden": []}
    if not isinstance(data, dict):
        return {"version": 1, "assignments": [], "hidden": []}
    data.setdefault("version", 1)
    if not isinstance(data.get("assignments"), list):
        data["assignments"] = []
    if not isinstance(data.get("hidden"), list):
        data["hidden"] = []
    return data


def remove_engagement(evidence_root: str, name: str) -> dict:
    """Drop an engagement's mapping assignment (unmap). Its targets fall back to
    their run tag or Unassigned; nothing sealed is deleted. Returns the mapping."""
    want = (name or "").strip()
    data = load_engagements(evidence_root)
    data["assignments"] = [a for a in data["assignments"]
                           if str(a.get("engagement") or "").strip() != want]
    save_engagements(evidence_root, data)
    return data


def hidden_reports(evidence_root: str) -> set:
    """The session/report names hidden from the Reports page."""
    return {str(h).strip() for h in load_engagements(evidence_root).get("hidden") or []
            if str(h).strip()}


def hide_report(evidence_root: str, name: str) -> dict:
    """Hide a session from the Reports page (reversible; its runs are untouched)."""
    want = (name or "").strip()
    if not want:
        raise ValueError("a session name is required")
    data = load_engagements(evidence_root)
    if want not in (data["hidden"] or []):
        data["hidden"].append(want)
    save_engagements(evidence_root, data)
    return data


def unhide_report(evidence_root: str, name: str) -> dict:
    """Show a previously hidden session again."""
    want = (name or "").strip()
    data = load_engagements(evidence_root)
    data["hidden"] = [h for h in (data["hidden"] or []) if str(h).strip() != want]
    save_engagements(evidence_root, data)
    return data


def _target_matches(pattern: str, target: str) -> bool:
    """A glob matches the full target string OR its basename, so `acme-*`
    catches both `acme-notes` and `/tmp/acme-vuln`."""
    pattern = (pattern or "").strip()
    if not pattern:
        return False
    target = target or ""
    return (fnmatch.fnmatch(target, pattern)
            or fnmatch.fnmatch(os.path.basename(target), pattern))


def engagement_for(man: dict, data: dict) -> str:
    """The engagement a run's target belongs to: the first mapping assignment
    that matches its target, else the run's own `session` tag, else Unassigned.
    The mapping wins over the tag on purpose."""
    target = str(man.get("target") or "")
    for assignment in data.get("assignments") or []:
        name = str(assignment.get("engagement") or "").strip()
        if not name:
            continue
        for pattern in assignment.get("match") or []:
            if _target_matches(str(pattern), target):
                return name
    return str(man.get("session") or "").strip() or UNASSIGNED


def engagement_names(mans: Iterable[dict], data: dict) -> List[str]:
    """Every engagement present across these runs, sorted, with Unassigned last
    — it is a residue, not an engagement."""
    names = {engagement_for(m, data) for m in mans}
    named = sorted(n for n in names if n != UNASSIGNED)
    if UNASSIGNED in names:
        named.append(UNASSIGNED)
    return named


def group_by_engagement(mans: Iterable[dict], data: dict) -> Dict[str, List[dict]]:
    """The runs grouped by engagement, engagement order from `engagement_names`,
    each group keeping the order it was given."""
    mans = list(mans)
    groups: Dict[str, List[dict]] = OrderedDict()
    for name in engagement_names(mans, data):
        groups[name] = []
    for m in mans:
        groups.setdefault(engagement_for(m, data), []).append(m)
    return groups


def resolve_engagement(requested: Optional[str], mans: Iterable[dict],
                       data: dict) -> Optional[str]:
    """Normalise a requested engagement filter against the engagements actually
    present: the matching name (case-insensitive), or None for "all" / an
    unknown value — so a stale link reads as the whole estate, never an empty
    page that looks clean."""
    want = (requested or "").strip()
    if not want:
        return None
    for name in engagement_names(mans, data):
        if name.lower() == want.lower():
            return name
    return None


def save_engagements(evidence_root: str, data: dict) -> None:
    """Write the mapping atomically (temp + replace), so a crash never leaves a
    half-written file the reader would treat as empty."""
    path = engagements_path(evidence_root)
    os.makedirs(evidence_root, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def assign(evidence_root: str, engagement: str, patterns: List[str]) -> dict:
    """Add target patterns to an engagement (creating it when new); patterns are
    de-duplicated, order preserved. Returns the updated mapping."""
    name = (engagement or "").strip()
    if not name:
        raise ValueError("an engagement name is required")
    pats: List[str] = []
    for p in (x.strip() for x in patterns if x and x.strip()):
        if p not in pats:                      # de-duplicate, order preserved
            pats.append(p)
    if not pats:
        raise ValueError("at least one target pattern is required")
    data = load_engagements(evidence_root)
    for assignment in data["assignments"]:
        if str(assignment.get("engagement") or "").strip() == name:
            existing = assignment.setdefault("match", [])
            for p in pats:
                if p not in existing:
                    existing.append(p)
            break
    else:
        data["assignments"].append({"engagement": name, "match": pats})
    save_engagements(evidence_root, data)
    return data


def unassign(evidence_root: str, patterns: List[str]) -> dict:
    """Remove target patterns from every engagement; an engagement left with no
    patterns is dropped. Returns the updated mapping."""
    drop = {p.strip() for p in patterns if p and p.strip()}
    data = load_engagements(evidence_root)
    kept = []
    for assignment in data["assignments"]:
        match = [p for p in (assignment.get("match") or []) if p not in drop]
        if match:
            assignment["match"] = match
            kept.append(assignment)
    data["assignments"] = kept
    save_engagements(evidence_root, data)
    return data


__all__ = [
    "ENGAGEMENTS_FILE",
    "UNASSIGNED",
    "_target_matches",
    "assign",
    "engagement_for",
    "engagement_names",
    "engagements_path",
    "group_by_engagement",
    "hidden_reports",
    "hide_report",
    "load_engagements",
    "remove_engagement",
    "resolve_engagement",
    "save_engagements",
    "unassign",
    "unhide_report",
]

"""GitHub-issue baselines: what has been filed, and the diff against it."""

import json
import os
import time
from typing import Dict, List, Optional, Tuple

from squawk.core import BASE_TITLE, env, fingerprint, run_cmd, tool_path
from squawk.evidence import load_identities

# --------------------------------------------------------------------------- #
# GitHub-issue baselines.
#
# A scan-report issue carries a "## Diff baseline" section: a table of
# | scanner | findings | sha256 | rows, and one <details> block per scanner
# wrapping a fenced list of identity keys. Squawk reads those so a fresh
# machine with no local history can still diff per finding.
#
# The truncation guard is the part that matters. A GitHub comment caps at
# 65,536 characters, so a large identity set can arrive truncated — and a
# short set read as authoritative would mark live findings "already filed",
# the worst possible failure for this tool. So the parser recomputes
# sha256(sorted ids)[:16] from whatever it actually parsed and compares it to
# the hash posted beside it. Only scanners whose hash reconciles are used;
# the rest are excluded with the reason shown on screen.
# --------------------------------------------------------------------------- #

GH_COMMENT_CAP = 65536
_SUMMARY_RE = None  # compiled lazily; re imported here to keep the top stdlib-only list tidy


def _baseline_res():
    global _SUMMARY_RE
    if _SUMMARY_RE is None:
        import re
        _SUMMARY_RE = {
            "summary": re.compile(
                r"<summary>\s*([\w.-]+)\s+—\s+(\d+)\s+identities"
                r"(?:\s+\(part\s+(\d+)\s+of\s+(\d+)\))?\s*</summary>"),
            "row": re.compile(
                r"^\|\s*([\w.-]+)\s*\|\s*(\d+)\s*\|\s*([0-9a-f]{16})\s*\|\s*$",
                re.MULTILINE),
            "fence": re.compile(r"```\n(.*?)```", re.DOTALL),
        }
    return _SUMMARY_RE


def parse_baseline_text(text: str) -> Dict[str, dict]:
    """Parse one issue's concatenated body+comments into per-scanner baselines.

    Returns {scanner: {"posted_hash", "posted_count", "ids", "status", "reason"}}
    where status is "ok" only when the recomputed hash reconciles."""
    rx = _baseline_res()
    posted: Dict[str, Tuple[int, str]] = {}
    for m in rx["row"].finditer(text):
        name, count, digest = m.group(1), int(m.group(2)), m.group(3)
        if name.lower() in ("scanner", "---"):
            continue
        posted[name] = (count, digest)

    # collect identity slices per scanner: {scanner: {part_no: [ids]}, total_parts}
    slices: Dict[str, Dict[int, List[str]]] = {}
    declared_parts: Dict[str, int] = {}
    pos = 0
    while True:
        m = rx["summary"].search(text, pos)
        if not m:
            break
        scanner = m.group(1)
        part = int(m.group(3)) if m.group(3) else 1
        total = int(m.group(4)) if m.group(4) else 1
        fence = rx["fence"].search(text, m.end())
        pos = m.end()
        if not fence:
            continue
        part_ids = [ln.strip() for ln in fence.group(1).splitlines() if ln.strip()]
        slices.setdefault(scanner, {})[part] = part_ids
        declared_parts[scanner] = max(declared_parts.get(scanner, 1), total)
        pos = fence.end()

    out: Dict[str, dict] = {}
    for scanner, (count, digest) in posted.items():
        entry = {"posted_hash": digest, "posted_count": count, "ids": [],
                 "status": "unusable", "reason": ""}
        if scanner not in slices:
            # Counts are not baselines: they cannot distinguish a new finding
            # from a shifted one, and Squawk will not guess.
            entry["reason"] = "counts only — no identity set posted"
            out[scanner] = entry
            continue
        total = declared_parts.get(scanner, 1)
        missing = [p for p in range(1, total + 1) if p not in slices[scanner]]
        if missing:
            entry["reason"] = ("incomplete — missing part(s) %s of %d"
                               % (", ".join(map(str, missing)), total))
            out[scanner] = entry
            continue
        ids: List[str] = []
        for p in range(1, total + 1):
            ids.extend(slices[scanner][p])
        recomputed = fingerprint(ids)
        if recomputed != digest:
            entry["reason"] = ("hash mismatch — posted %s, recomputed %s; "
                               "set likely truncated" % (digest, recomputed))
            out[scanner] = entry
            continue
        entry.update(ids=sorted(set(ids)), status="ok",
                     reason="hash reconciles (%d identities)" % len(ids))
        out[scanner] = entry
    # details blocks with no table row are unusable too — no hash to check
    for scanner in slices:
        if scanner not in out:
            out[scanner] = {"posted_hash": "", "posted_count": 0, "ids": [],
                            "status": "unusable",
                            "reason": "identity set posted with no hash row"}
    return out


def baselines_cache_path(evidence_root: str) -> str:
    return os.path.join(evidence_root, ".baselines", "baselines.json")


def load_baselines(evidence_root: str) -> dict:
    try:
        with open(baselines_cache_path(evidence_root), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def baseline_identity_set(evidence_root: str) -> Dict[str, set]:
    """{scanner: set(identity)} for reconciled scanners only."""
    cache = load_baselines(evidence_root)
    out: Dict[str, set] = {}
    for scanner, entry in (cache.get("scanners") or {}).items():
        if entry.get("status") == "ok":
            out[scanner] = set(entry.get("ids", []))
    return out


def resolve_gh_repo(explicit: Optional[str], repo_path: Optional[str]) -> Optional[str]:
    if explicit:
        return explicit
    from_env = env("GH_REPO")
    if from_env:
        return from_env
    if repo_path and tool_path("gh"):
        code, out, _err = run_cmd(
            ["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"],
            cwd=repo_path, timeout=30)
        if code == 0 and out.strip():
            return out.strip()
    return None


def sync_baselines(evidence_root: str, gh_repo: str) -> Tuple[bool, str, dict]:
    """Pull baseline issues via gh (read-only) and cache the reconciled sets."""
    if not tool_path("gh"):
        return False, "gh is not installed — baselines unavailable", {}
    code, out, err = run_cmd(
        ["gh", "issue", "list", "--repo", gh_repo, "--state", "all",
         "--search", '"%s" in:title' % BASE_TITLE,
         "--json", "number,title", "--limit", "20"], cwd=None, timeout=60)
    if code != 0:
        return False, "gh issue list failed: %s" % err.strip()[:200], {}
    try:
        issues = json.loads(out or "[]")
    except json.JSONDecodeError:
        return False, "unparseable gh output", {}
    issues = [i for i in issues if BASE_TITLE.lower() in i.get("title", "").lower()]
    if not issues:
        return False, "no issue titled '%s' found in %s" % (BASE_TITLE, gh_repo), {}

    merged: Dict[str, dict] = {}
    used_issue = None
    for issue in sorted(issues, key=lambda i: i["number"], reverse=True):
        code, out, _err = run_cmd(
            ["gh", "issue", "view", str(issue["number"]), "--repo", gh_repo,
             "--json", "body,comments"], cwd=None, timeout=60)
        if code != 0:
            continue
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            continue
        text = (data.get("body") or "") + "\n\n" + "\n\n".join(
            c.get("body", "") for c in (data.get("comments") or []))
        parsed = parse_baseline_text(text)
        if parsed:
            merged = parsed
            used_issue = issue["number"]
            break  # newest issue with any baseline section wins

    if not merged:
        return False, "no '## Diff baseline' section found in any candidate issue", {}

    cache = {"repo": gh_repo, "issue": used_issue,
             "synced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "scanners": merged}
    path = baselines_cache_path(evidence_root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cache, fh, indent=2)
    ok_n = sum(1 for e in merged.values() if e["status"] == "ok")
    return True, ("issue #%s: %d scanner(s) reconcile, %d unusable"
                  % (used_issue, ok_n, len(merged) - ok_n)), cache


def generate_baseline_comments(run_dir: str) -> List[str]:
    """Produce the paste-ready comment(s) for a run's baseline. Splits across
    comments — and within a scanner when one outgrows a comment on its own,
    labeling slices (part N of M) so a reader must concatenate before the hash
    reconciles. Squawk generates but never posts."""
    identities = load_identities(run_dir)
    header = ["## Diff baseline", "",
              "| scanner | findings | sha256 |", "|---|---|---|"]
    for tool, ids in sorted(identities.items()):
        header.append("| %s | %d | %s |" % (tool, len(ids), fingerprint(ids)))
    comments: List[str] = ["\n".join(header)]

    budget = GH_COMMENT_CAP - 2000  # headroom for wrapper text
    for tool, ids in sorted(identities.items()):
        ids = sorted(ids)
        body_all = "\n".join(ids)
        parts: List[List[str]]
        if len(body_all) + 200 < budget:
            parts = [ids]
        else:
            parts = []
            cur: List[str] = []
            size = 0
            for ident in ids:
                if size + len(ident) + 1 > budget and cur:
                    parts.append(cur)
                    cur, size = [], 0
                cur.append(ident)
                size += len(ident) + 1
            if cur:
                parts.append(cur)
        total = len(parts)
        for idx, chunk in enumerate(parts, 1):
            label = ("%s — %d identities" % (tool, len(ids)) if total == 1 else
                     "%s — %d identities (part %d of %d)" % (tool, len(ids), idx, total))
            block = ("<details><summary>%s</summary>\n\n```\n%s\n```\n\n</details>"
                     % (label, "\n".join(chunk)))
            if len(comments[-1]) + len(block) + 2 > GH_COMMENT_CAP - 500:
                comments.append(block)
            else:
                comments[-1] += "\n\n" + block
    return comments


__all__ = [
    'GH_COMMENT_CAP',
    '_SUMMARY_RE',
    '_baseline_res',
    'baseline_identity_set',
    'baselines_cache_path',
    'generate_baseline_comments',
    'load_baselines',
    'parse_baseline_text',
    'resolve_gh_repo',
    'sync_baselines',
]

"""An engagement, as a document somebody can hand over.

Markdown, because it is diffable, pasteable into a ticket, readable in a
terminal, and needs nothing installed to produce or to read.

The thing that makes this different from every other scan report is the section
nobody else writes: **what was not covered**. A findings list with no statement
of what was looked at is a floor, not an assessment, and a reader cannot tell a
clean estate from an unfinished one. Every service declares what it does not
cover, every stage publishes what it examined, and both go in the report next to
the findings rather than in an appendix nobody reads.

Two kinds of finding appear here and they are never mixed: a scanner's, and one
an operator recorded by hand. The second says so on its own line, every time.
"""
from typing import Dict, List, Optional, Tuple

from squawk.core import SEVERITY_ORDER, mask_account, redact_identifiers
from squawk.evidence import list_runs, load_findings

__all__ = [
    'MANUAL_SCANNER',
    '_coverage_line',
    '_finding_block',
    '_severity_table',
    'report_markdown',
    'runs_for_session',
]

#: The scanner name `write_note` stamps on a finding a person recorded.
MANUAL_SCANNER = "operator"


def runs_for_session(root: str, session: str) -> List[dict]:
    """Every run tagged with this session, oldest first.

    An exact match on the tag, never a prefix or a time window: a report that
    quietly includes a run from other work is worse than one that misses it,
    because the reader cannot see the difference.
    """
    want = (session or "").strip()
    out = [m for m in list_runs(root) if (m.get("session") or "").strip() == want]
    return sorted(out, key=lambda m: str(m.get("run_id") or ""))


def _severity_table(findings: List[dict]) -> str:
    counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = (f.get("severity") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    rows = ["| Severity | Count |", "|---|---|"]
    rows += ["| %s | %d |" % (s, counts[s]) for s in SEVERITY_ORDER if counts[s]]
    if len(rows) == 2:
        rows.append("| _none recorded_ | 0 |")
    return "\n".join(rows)


def _coverage_line(row: dict) -> str:
    """One stage, and what it actually read."""
    cov = row.get("coverage") or {}
    examined, unit = cov.get("examined"), cov.get("unit")
    if examined is None:
        seen = "did not publish what it examined"
    else:
        seen = "examined %s %s" % (examined, unit or "unit(s)")
    return "| `%s` | %s | %s | %s |" % (
        row.get("tool") or "?", row.get("mode") or "", row.get("status") or "?",
        redact_identifiers(str(row.get("detail") or "")) or seen)


def _finding_block(f: dict, n: int) -> str:
    """One finding, in the order a report wants: what, where, how it was found,
    what proved it, what it gets an attacker, what fixes it."""
    detail = f.get("detail") or {}
    manual = (f.get("scanner") or "") == MANUAL_SCANNER
    out = ["### %d. %s" % (n, redact_identifiers(f.get("title") or "untitled")),
           "",
           "| | |", "|---|---|",
           "| Severity | **%s** |" % (f.get("severity") or "unknown"),
           "| Affected | `%s` |" % mask_account(str(f.get("path") or "")),
           "| Identity | `%s` |" % (f.get("identity") or ""),
           ]
    if manual:
        # Said on its own line, every time. A finding a person typed and a
        # finding a scanner produced are different evidence, and a report that
        # renders them identically is making a claim it cannot support.
        out.append("| Source | **recorded by hand** by the operator — not a "
                   "scanner finding |")
    else:
        out.append("| Source | `%s` |" % (f.get("scanner") or "?"))
    out.append("")

    for key, heading in (("how_found", "How it was found"),
                         ("evidence", "Evidence"),
                         ("impact", "Impact"),
                         ("remediation", "Remediation"),
                         ("description", "Description")):
        val = str(detail.get(key) or "").strip()
        if not val:
            continue
        out += ["**%s**" % heading, "", "```", redact_identifiers(val), "```", ""]

    att = detail.get("attachments") or []
    if att:
        out += ["**Attached evidence**", ""]
        out += ["- `%s` — sha256 `%s`" % (a.get("name"), (a.get("sha256") or "")[:16])
                for a in att]
        out.append("")
    return "\n".join(out)


def report_markdown(root: str, session: str,
                    verify: Optional[dict] = None) -> Tuple[str, int]:
    """The engagement as markdown, and the number of findings in it."""
    runs = runs_for_session(root, session)
    lines: List[str] = ["# %s" % (session or "(no session)"), ""]

    if not runs:
        lines += [
            "No run carries this session tag.",
            "",
            "That is not the same as an engagement with no findings, and this "
            "document will not pretend otherwise. Tag runs with "
            "`--session %s` and they will appear here." % (session or "NAME"),
            "",
        ]
        return "\n".join(lines), 0

    findings: List[dict] = []
    for man in runs:
        findings.extend(load_findings(str(man.get("_dir") or "")))

    targets = sorted({str(m.get("target") or "") for m in runs})
    manual = sum(1 for f in findings if (f.get("scanner") or "") == MANUAL_SCANNER)

    lines += [
        "## Summary", "",
        "| | |", "|---|---|",
        "| Runs | %d |" % len(runs),
        "| Targets | %d |" % len(targets),
        "| Findings | %d, of which **%d recorded by hand** |" % (len(findings), manual),
        "| First run | `%s` |" % runs[0].get("run_id"),
        "| Last run | `%s` |" % runs[-1].get("run_id"),
        "",
        _severity_table(findings),
        "",
        "### Targets", "",
    ]
    lines += ["- `%s`" % mask_account(t) for t in targets]
    lines.append("")

    # The section that makes this a report rather than a list.
    lines += [
        "## What was not covered", "",
        "Read this before the findings. Each service states what it does not "
        "look at; a finding absent from this report may be absent because "
        "nothing looked for it.", "",
    ]
    seen_nc = []
    for man in runs:
        nc = str(man.get("not_covered") or "").strip()
        if nc and nc not in seen_nc:
            seen_nc.append(nc)
            lines += ["- **%s** — %s" % (man.get("service_label")
                                         or man.get("service") or "?", nc)]
    if not seen_nc:
        lines.append("- _No service in this session declared a coverage limit._")
    lines.append("")

    lines += ["## What ran, and what it read", "",
              "| Tool | Mode | Status | Detail |", "|---|---|---|---|"]
    for man in runs:
        for row in man.get("ledger") or []:
            lines.append(_coverage_line(row))
    lines.append("")

    if verify:
        lines += [
            "## Evidence integrity", "",
            "`%s` — %s" % (verify.get("status", "unknown"),
                           verify.get("summary", "")),
            "",
            "Every run above is a sealed directory whose digest covers each file "
            "in it, including attached evidence, and each run records the digest "
            "of the one before it. This proves the evidence has not changed since "
            "it was written. It does not prove who wrote it: there are no "
            "signatures here.", "",
        ]

    lines += ["## Findings", ""]
    if not findings:
        lines += ["No findings were recorded in this session. See *What was not "
                  "covered* above before reading that as a clean result.", ""]
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    for n, f in enumerate(sorted(findings,
                                 key=lambda x: order.get(
                                     (x.get("severity") or "unknown").lower(), 9)), 1):
        lines.append(_finding_block(f, n))
    return "\n".join(lines), len(findings)

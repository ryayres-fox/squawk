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
import csv
import datetime
import getpass
import html
import io
import json
import os
import re
import shutil
import socket
import tempfile
import time
from typing import Callable, Dict, List, Optional, Tuple

from squawk.core import (
    DISPOSITIONS_FILE,
    REMEDIATION_DAYS,
    SCANNERS,
    SEVERITY_ORDER,
    load_profile,
    mask_account,
    redact_identifiers,
    run_cmd,
    running_as_root,
    tool_path,
)
from squawk.engagements import engagement_for, load_engagements
from squawk.evidence import list_runs, load_findings
from squawk.feeds import EPSS_HOT, cve_of, exploitability, load_feeds
from squawk.stages import DISPOSITION_SERVICE

__all__ = [
    'ABILITIES',
    'AUDIENCES',
    'CSV_COLUMNS',
    'CSV_KEEP_LINES',
    'MANUAL_SCANNER',
    'NOTE_META',
    'NOTE_RETEST_FALLBACK',
    'PDF_BROWSERS',
    'REMEDIATION_BASIS',
    'REMEDIATION_RULE',
    'REMEDIATION_SOURCES',
    'REMEDIATION_STATES',
    'RETEST_HOWTO',
    'RETEST_IMAGE',
    'RETEST_REPO',
    'SHARE_BODY',
    'SHARE_CSS',
    'SHARE_FORMATS',
    'SHARE_JS',
    'SHARE_PREAMBLE',
    '_CLOSED',
    '_FORMULA_START',
    '_VULN_ID',
    'Redactor',
    '_abilities_of',
    '_cell',
    '_coverage_line',
    '_day',
    '_deadlines_markdown',
    '_due_markdown',
    '_finding_block',
    '_image_rows',
    '_image_summary',
    '_newest_per_image',
    '_sections',
    '_sev_line',
    '_severity_table',
    '_short',
    '_sla_summary',
    '_summarised',
    '_when',
    '_where',
    'decision_for',
    'distinct_findings',
    'due_window',
    'first_seen_index',
    'html_to_pdf',
    'load_dispositions',
    'pdf_browser',
    'remediation_state',
    'report_markdown',
    'retest_for',
    'runs_for_session',
    'sessions_of',
    'share_csv',
    'share_file_name',
    'share_html',
    'share_markdown',
    'share_model',
    'today_utc',
    'tracked_keys',
    'write_share',
]

#: The scanner name `write_note` stamps on a finding a person recorded.
MANUAL_SCANNER = "operator"


def runs_for_session(root: str, session: str) -> List[dict]:
    """Every run in this engagement, oldest first: one tagged with the session,
    or mapped to it by `engagements.json`. An engagement defined only by the
    mapping (targets grouped without a per-run tag) still reports.

    Exact matches only, never a prefix or a time window — a report that quietly
    included a run from other work is worse than one that misses it. The mapping
    resolves the same way the UI groups (engagements.engagement_for), so a report
    and the Overview never disagree about what is in an engagement.
    """
    want = (session or "").strip()
    data = load_engagements(root)
    out = [m for m in list_runs(root)
           if (m.get("session") or "").strip() == want
           or engagement_for(m, data) == want]
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

    # Headings the template does not name, after its four, in the order typed.
    sections = detail.get("sections")
    for name, val in (sections.items() if isinstance(sections, dict) else ()):
        val = str(val or "").strip()
        if not val:
            continue
        heading = str(name)[:1].upper() + str(name)[1:]
        out += ["**%s**" % redact_identifiers(heading), "", "```",
                redact_identifiers(val), "```", ""]

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


# --------------------------------------------------------------------------- #
# The shareable report (plan 14): the same engagement, for somebody else.
#
# `report_markdown` is the operator's working document. This is the one handed
# over, and three things change. The local machine is removed at render
# time -- paths under a home directory, ~, /tmp or the evidence root become
# their last component, and the user and host names and real email addresses
# go -- while the sealed evidence keeps every original, so its digests still
# cover them. Each finding is listed once per identity across the session, not
# once per run: three overlapping scans of one tree used to triple the total.
# And the reviewer's own findings come first, with their control mapping and
# the attacker abilities they record.
# --------------------------------------------------------------------------- #

#: A note's own fields the report reads rather than lists as control mapping:
#: `abilities:` fills the attacker matrix, `reviewer:` says who recorded it.
#: Who recorded a finding is never inferred; a note without the line is the
#: operator's, as it always was.
NOTE_META = ("abilities", "reviewer", "retest", "references")

#: What stands for the scanned tree and the image in a retest command, so no
#: local path reaches a report.
RETEST_REPO = "<repo>"
RETEST_IMAGE = "<image>"
_VULN_ID = re.compile(r"^(CVE-\d{4}-\d+|GHSA-|PYSEC-|GO-|RUSTSEC-|TEMP-)")


def retest_for(f: dict) -> str:
    """The command that confirms a scanner's finding is fixed: the tool that
    found it, narrowed to the rule where the tool allows it, against the same
    file. The semgrep, bandit, checkov, hadolint, zizmor, dockle, trivy config
    and osv-scanner forms were run against a review target on 2026-10-23 and
    listed the finding before a fix. The image re-scans and the Squawk
    service re-runs are each one's ordinary invocation."""
    scanner = str(f.get("scanner") or "")
    d = f.get("detail") or {}
    ident = str(f.get("identity") or "")
    rule = str(d.get("rule") or ident.split(":", 1)[0])
    path = str(f.get("path") or "")
    line = d.get("line")
    at = (" at line %s" % line) if line not in (None, "") else ""
    repo_path = "%s/%s" % (RETEST_REPO, path) if path else RETEST_REPO
    parts = ident.split(":")
    if scanner == "semgrep":
        if rule.startswith("own-rules."):
            return ("semgrep --config <your rules> --metrics=off %s: rule %s no longer "
                    "fires%s" % (repo_path, rule.split(".", 1)[1], at))
        return "semgrep --config r/%s --metrics=off %s: no result%s" % (rule, repo_path, at)
    if scanner == "bandit":
        return "bandit -t %s %s: no issue%s" % (rule, repo_path, at)
    if scanner == "checkov":
        resource = parts[-1] if len(parts) > 2 else ""
        return "checkov -f %s --check %s: PASSED%s" % (
            repo_path, rule, (" for %s" % resource) if resource else "")
    if scanner == "hadolint":
        return "hadolint %s: no %s" % (repo_path, rule)
    if scanner == "zizmor":
        return ("zizmor --offline --no-ignores --persona auditor %s: no %s%s"
                % (repo_path, rule, at))
    if scanner == "dockle":
        return "dockle %s: %s no longer listed (rebuild the image first)" % (RETEST_IMAGE, rule)
    if scanner in ("trivy", "grype") and _VULN_ID.match(ident) and len(parts) >= 3:
        pkg, ver = parts[1], parts[2]
        tool = "trivy image" if scanner == "trivy" else "grype"
        return ("rebuild, then %s %s: no %s for %s (it was %s)"
                % (tool, RETEST_IMAGE, parts[0], pkg, ver))
    if scanner == "osv-scanner" and len(parts) >= 4:
        # osv-scanner prints the record's own ID (PYSEC-..., GHSA-...), not the
        # CVE the finding is filed under, and the reference ends in that ID.
        # Told to look for the CVE, the reader finds it absent while it is open.
        shown = str(d.get("reference") or "").rstrip("/").rsplit("/", 1)[-1]
        vid = (("%s (%s)" % (shown, parts[0]))
               if _VULN_ID.match(shown) and shown != parts[0] else parts[0])
        return ("osv-scanner scan source -r %s: no %s for %s (it was %s)"
                % (RETEST_REPO, vid, parts[2], parts[3]))
    if scanner == "trivy":
        folder = os.path.dirname(path)
        return "trivy config %s: %s not listed" % (
            "%s/%s" % (RETEST_REPO, folder) if folder else RETEST_REPO, rule)
    if scanner in ("gitleaks", "trufflehog"):
        return ("squawk run contraband --repo %s: the finding is gone (rotate the secret "
                "first: removing it does not un-leak it)" % RETEST_REPO)
    if scanner == "authz":
        return ("squawk run authprobe --target <url>: %s no longer reported" % rule)
    if scanner == "webauth":
        return ("squawk run authdast --target <url>: %s no longer reported" % rule)
    if scanner == "schemathesis":
        return ("squawk run apiprobe --target <url>: %s no longer reported" % rule)
    if scanner == "zap":
        return "squawk run liveprobe --target <url>: alert %s not raised%s" % (
            rule, (" for %s" % path) if path else "")
    return "re-run the service that found it: the finding is not in the newest run"


#: For a finding recorded by hand with no retest of its own.
NOTE_RETEST_FALLBACK = ("Repeat how it was found (above). It is fixed when that no "
                        "longer reproduces it.")

#: What a reviewer's note may say an attacker can do with the finding, in an
#: `abilities: read, modify` line. The matrix is built from these and nothing
#: else: a scanner finding carries no such claim, and inventing one would be the
#: assertion without evidence this tool refuses everywhere.
ABILITIES = ("destroy", "modify", "disrupt", "read")
SHARE_FORMATS = ("md", "html", "both", "pdf", "csv")

#: Who a shareable report is for. The engineer's is every finding with its
#: location and evidence; the executive's is the same page with those parts
#: left out: what an attacker can do, the reviewer's findings, the image's
#: exploited CVEs, what was not covered. One template, so the two cannot
#: disagree about a number.
AUDIENCES = ("engineer", "executive")


class Redactor:
    """Every string the shareable report shows goes through `clean`: local paths
    to their last component, the user and host names out, and then Squawk's own
    `redact_identifiers` (account ids, email addresses, key ids), the same control
    every other screen uses."""

    def __init__(self, evidence_root: str,
                 names: Optional[List[str]] = None) -> None:
        roots = [r"~", r"/home/[^/\s]+", r"/Users/[^/\s]+", r"/root",
                 r"/tmp", r"/var/folders/[^/\s]+"]  # noqa: S108 -- patterns, not temp files
        real = os.path.realpath(os.path.expanduser(evidence_root))
        if not re.match(r"^(/home/|/Users/|/root|/tmp)", real):
            roots.append(re.escape(real))
        self.path_re = re.compile(
            r"(?:%s)(?:/[^\s'\"`)\]<>,;|]*)?" % "|".join(roots))
        if names is None:
            host = socket.gethostname()
            names = [getpass.getuser(), host, host.split(".")[0],
                     os.environ.get("USER", "")]
        words = sorted({w for w in names if w and len(w) >= 3})
        self.word_re = (re.compile(r"\b(%s)\b" % "|".join(map(re.escape, words)),
                                   re.IGNORECASE) if words else None)

    @staticmethod
    def _last(m: "re.Match[str]") -> str:
        base = m.group(0).rstrip("/").rsplit("/", 1)[-1]
        return base if base and base != "~" else "[local path]"

    def clean(self, value: object) -> str:
        text = str(value if value is not None else "")
        text = self.path_re.sub(self._last, text)
        # Identifiers before names: removing the user name first turned
        # `alice@corp-mail.net` into `[removed]@corp-mail.net`, which no longer
        # reads as an address, so the mask passed it and the domain leaked.
        text = redact_identifiers(text)
        if self.word_re is not None:
            text = self.word_re.sub("[removed]", text)
        return text


def distinct_findings(runs: List[dict],
                      keep: Optional[Callable[[dict, dict], bool]] = None) -> List[dict]:
    """One finding per identity across the runs, each carrying the run ids that
    saw it; most severe first, the reviewer's before a scanner's. `keep`, given
    a run's manifest and a finding, says which of a run's findings count.

    The newest run's copy of a finding is the one shown: the runs come oldest
    first, and a finding seen again carries what the later run recorded. The
    first copy used to win, so a re-run that recorded a finding's fix (trivy's,
    once its normalizer kept it) still showed the earlier copy without one."""
    by: Dict[str, dict] = {}
    for man in runs:
        for f in load_findings(str(man.get("_dir") or "")):
            if keep is not None and not keep(man, f):
                continue
            ident = str(f.get("identity") or "%s:%s" % (f.get("scanner"), f.get("title")))
            seen = by[ident]["runs"] if ident in by else []
            by[ident] = dict(f, runs=[*seen, man.get("run_id")])
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(by.values(), key=lambda f: (
        order.get(str(f.get("severity") or "unknown").lower(), 9),
        f.get("scanner") != MANUAL_SCANNER, str(f.get("title") or "")))


def _sections(f: dict) -> Dict[str, str]:
    sec = (f.get("detail") or {}).get("sections")
    return {str(k): str(v) for k, v in sec.items()} if isinstance(sec, dict) else {}


def _abilities_of(f: dict) -> List[str]:
    words = re.findall(r"[a-z]+", _sections(f).get("abilities", "").lower())
    return [a for a in ABILITIES if a in words]


def _where(f: dict, clean) -> str:
    """The file, with the line, or the resource the identity ends with: checkov
    keeps it there (`...:aws_subnet.public_a`), and without it two subnets'
    findings read as one finding listed twice."""
    d = f.get("detail") or {}
    path = clean(f.get("path") or "")
    if d.get("line"):
        return "%s:%s" % (path, d["line"])
    tail = str(f.get("identity") or "").rsplit(":", 1)[-1]
    if tail and not tail.isdigit() and "." in tail and "/" not in tail \
            and tail != (f.get("path") or ""):
        return "%s · %s" % (path, clean(tail))
    return path


def _when(rid: str) -> str:
    m = re.match(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})", rid or "")
    return "%s-%s-%s %s:%s UTC" % m.groups() if m else (rid or "")


def _summarised(f: dict) -> bool:
    """Whether an image run's finding is a package advisory, counted in the
    image summary, rather than a finding listed with the rest.

    The summary was written when every row of an image run was trivy's or
    grype's. dockle added configuration findings to the same run (the image
    runs as root, carries its `.git`), and the summary counted each one as an
    "advisory with no CVE id" and listed none of them (found 2026-10-23 on a
    review image: six of the 59 so counted were dockle's)."""
    sc = SCANNERS.get(str(f.get("scanner") or ""))
    return sc is not None and sc.kind in ("sca", "sbom")


def _newest_per_image(runs: List[dict]) -> List[dict]:
    """The newest image run of each image, in the order the images were first
    scanned. An image scanned twice in a session is one image: summarised
    once per run it was shown twice and its CSV rows came twice (found
    2026-10-23, re-running `cargo` to pick up a normalizer change)."""
    newest: Dict[str, dict] = {}
    order: List[str] = []
    for man in runs:                       # runs_for_session is oldest first
        if man.get("scope") != "image":
            continue
        ref = str(man.get("target") or "")
        if ref not in newest:
            order.append(ref)
        newest[ref] = man
    return [newest[ref] for ref in order]


def _image_summary(man: dict, feeds: dict, clean) -> dict:
    """An image scan, summarised: its rows run to thousands, and the useful
    answer is how many distinct CVEs, which are known to be exploited, and
    where the critical ones sit. Findings that are not package advisories
    are listed with the others and named here by count."""
    every = load_findings(str(man.get("_dir") or ""))
    rows = [f for f in every if _summarised(f)]
    listed: Dict[str, int] = {}
    for f in every:
        if not _summarised(f):
            listed[str(f.get("scanner"))] = listed.get(str(f.get("scanner")), 0) + 1
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    cves: Dict[str, dict] = {}
    other_ids = set()
    for f in rows:
        parts = str(f.get("identity") or "").split(":")
        pkg = parts[1] if len(parts) > 2 else ""
        cve = cve_of(f)
        if not cve:
            other_ids.add(parts[0])
            continue
        entry = cves.setdefault(cve, {"sev": f.get("severity"), "pkgs": set()})
        entry["pkgs"].add(pkg)
        # Counted at the highest rating either scanner gave it.
        if rank.get(str(f.get("severity")), 9) < rank.get(str(entry["sev"]), 9):
            entry["sev"] = f.get("severity")
    crit: Dict[str, int] = {}
    for v in cves.values():
        if v["sev"] == "critical":
            for p in v["pkgs"]:
                crit[p] = crit.get(p, 0) + 1
    kev, hot = [], 0
    for cve, v in sorted(cves.items()):
        ex = exploitability(cve, feeds)
        if ex.get("kev"):
            kev.append({"cve": cve, "severity": v["sev"], "pkgs": sorted(v["pkgs"])})
        if (ex.get("epss") or 0) >= EPSS_HOT:
            hot += 1
    examined = ""
    for row in man.get("ledger") or []:
        cov = row.get("coverage") or {}
        if row.get("tool") == "syft" and cov.get("examined") is not None:
            examined = "%s %s" % (cov.get("examined"), cov.get("unit") or "")
    tools: Dict[str, int] = {}
    for f in rows:
        tools[str(f.get("scanner"))] = tools.get(str(f.get("scanner")), 0) + 1
    return {"ref": clean(man.get("target")), "run": man.get("run_id"),
            "rows": len(rows), "by_tool": tools, "packages": examined,
            "listed_apart": listed,
            "distinct_cves": len(cves), "other_advisories": len(other_ids),
            "critical_cves": sum(1 for v in cves.values() if v["sev"] == "critical"),
            "feeds": bool(feeds.get("present")), "kev": kev, "epss_hot": hot,
            "top_critical": sorted(crit.items(), key=lambda kv: (-kv[1], kv[0]))[:6]}


#: What each built-in remediation window rests on. A reader must be able to tell
#: a regulation from a policy choice, so each says which it is.
REMEDIATION_SOURCES = {
    "critical": "Proposed HIPAA Security Rule, 45 CFR 164.308(a)(4)(ii)(C)(1): 15 "
                "calendar days for a critical risk. Proposed, not final (NPRM, 90 FR 898, "
                "6 January 2025).",
    "high": "The same proposal, 164.308(a)(4)(ii)(C)(2): 30 calendar days for a high risk.",
    "medium": "Policy. The proposal leaves risks below high to written policy "
              "(164.308(a)(4)(ii)(C)(3)); 90 days is FedRAMP's long-standing window for a "
              "moderate finding.",
    "low": "Policy, as for medium; 180 days is FedRAMP's long-standing window for a low one.",
    "kev": "CISA BOD 26-04 (10 June 2026): 14 days for most known exploited "
           "vulnerabilities, 3 where exploitation gives total control of the system. It "
           "binds federal agencies; here it is policy.",
}

#: How a finding is closed, said in both reports. %d is the longest a risk
#: acceptance may run.
REMEDIATION_RULE = (
    "Each finding's clock starts at the first sealed run that reported it. By its due "
    "date, each is fixed, shown by a re-run that no longer reports it or, for a finding "
    "recorded by hand, by its retest evidence; or found false, with the reason; or its "
    "risk accepted in writing by the accountable role, with the reason, the compensating "
    "controls and an expiry no more than %d days away, when it is decided again. One "
    "with none of these by its due date is overdue. Each decision is a sealed record in "
    "the same evidence as the findings, written with `squawk disposition`.")
#: Why the windows are policy, said under the rule.
REMEDIATION_BASIS = (
    "The HIPAA Security Rule in force sets no deadline. It requires risks be reduced "
    "to a reasonable and appropriate level (45 CFR 164.308(a)(1)(ii)(B)), and the "
    "documentation of how kept six years (164.316(b)(2)(i)). The windows above are "
    "therefore policy, and each says where it comes from.")

#: The states a finding can be in, open ones first. `decided` and `fixed`
#: close it; the rest are counted against its due date.
REMEDIATION_STATES = ("overdue", "open", "in progress", "risk accepted",
                      "false positive", "fixed late", "fixed")
_CLOSED = ("risk accepted", "false positive", "fixed late", "fixed")


def today_utc() -> str:
    """Today in UTC, YYYY-MM-DD: what "overdue" is measured against."""
    return time.strftime("%Y-%m-%d", time.gmtime())


def _day(stamp: str) -> Optional[datetime.date]:
    """The date a run id or a recorded_at stamp (YYYYMMDDTHHMMSSZ...) names."""
    try:
        return datetime.date(int(stamp[0:4]), int(stamp[4:6]), int(stamp[6:8]))
    except (TypeError, ValueError):
        return None


def due_window(severity: str, kev: bool, policy: Dict[str, Tuple[int, str]]
               ) -> Tuple[Optional[int], str]:
    """(days, why) for one finding: its severity's window, or the known
    exploited one if that is sooner. None for info and unrated findings."""
    sev = (severity or "unknown").lower()
    days = policy[sev][0] if sev in REMEDIATION_DAYS else None
    if kev and (days is None or policy["kev"][0] < days):
        return policy["kev"][0], "known exploited, %d days" % policy["kev"][0]
    if days is None:
        return None, ("no deadline: informational" if sev == "info"
                      else "no deadline until it is rated")
    return days, "%s, %d days" % (sev, days)


def load_dispositions(runs: List[dict]
                      ) -> Tuple[Dict[Tuple[str, str], dict], List[str]]:
    """{(target, identity): newest decision}, and the decision runs that could
    not be read. `runs` comes oldest first, so a later decision replaces an
    earlier one; every one stays sealed in its run.

    Keyed like the triage ledger (decisions.py), to the target and identity,
    so a risk acceptance follows its finding into the next engagement on the
    same target and never onto a different target that shares an identity.

    A run that cannot be read is named, never skipped in silence: a risk
    acceptance that quietly stopped applying would read as an overdue
    finding nobody decided."""
    out: Dict[Tuple[str, str], dict] = {}
    unreadable: List[str] = []
    for man in runs:
        if man.get("service") != DISPOSITION_SERVICE.key:
            continue
        rid = str(man.get("run_id") or "")
        try:
            with open(os.path.join(str(man.get("_dir") or ""), DISPOSITIONS_FILE),
                      encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            unreadable.append(rid)
            continue
        rows = doc.get("decisions") if isinstance(doc, dict) else None
        if not isinstance(rows, list):
            unreadable.append(rid)
            continue
        for d in rows:
            if not (isinstance(d, dict) and d.get("finding") and d.get("targets")
                    and d.get("identities")):
                unreadable.append(rid)
                break
            for target in d["targets"]:
                for ident in d["identities"]:
                    out[(str(target), str(ident))] = dict(d, run=rid)
    return out, unreadable


def first_seen_index(runs: List[dict]) -> Dict[Tuple[str, str], str]:
    """{(target, identity): the first run in the evidence root that reported
    it}. The clock starts there, not at the first run of this engagement: a
    finding carried into a new session keeps its date, or opening a session
    would reset every deadline."""
    out: Dict[Tuple[str, str], str] = {}
    for man in sorted(runs, key=lambda m: str(m.get("run_id") or "")):
        target, rid = str(man.get("target") or ""), str(man.get("run_id") or "")
        for f in load_findings(str(man.get("_dir") or "")):
            out.setdefault((target, str(f.get("identity") or "")), rid)
    return out


def decision_for(decided: Dict[Tuple[str, str], dict],
                  pairs: List[Tuple[str, str]]) -> Optional[dict]:
    """The newest decision covering any of a finding's (target, identity) pairs."""
    hits = [decided[p] for p in pairs if p in decided]
    return max(hits, key=lambda d: (str(d.get("recorded_at")), str(d.get("run")))) \
        if hits else None


def remediation_state(severity: str, kev: bool, first_seen: str,
                      policy: Dict[str, Tuple[int, str]], today: str,
                      decision: Optional[dict], rescan: Optional[str]) -> dict:
    """Where one finding stands against its deadline.

    `rescan` is None when no re-run can check the finding (one recorded by
    hand), "" when the newest run still reports it, or the id of the first run
    that no longer did. A re-run is evidence and outranks a decision: a
    finding recorded as fixed that the newest run still reports is not fixed,
    and one a re-run no longer reports is fixed whatever was decided."""
    days, basis = due_window(severity, kev, policy)
    first = _day(first_seen)
    due = first + datetime.timedelta(days=days) if first and days is not None else None
    now = datetime.date.fromisoformat(today)
    out = {"first_seen": first.isoformat() if first else "",
           "due": due.isoformat() if due else "", "basis": basis}

    def against_due(label: str, why: str) -> dict:
        if due and now > due:
            when = "%d days past due" % (now - due).days
            return dict(out, status="overdue", decision="; ".join(x for x in (why, when) if x))
        when = ("due in %d days" % (due - now).days) if due else basis
        return dict(out, status=label, decision="; ".join(x for x in (why, when) if x))

    def fixed(on: Optional[datetime.date], why: str) -> dict:
        late = bool(due and on and on > due)
        return dict(out, status="fixed late" if late else "fixed", decision=why + (
            ", %d days after the due date" % (on - due).days if late and on and due else ""))

    if rescan:
        on = _day(rescan)
        return fixed(on, "not reported by run %s (%s)" % (rescan, on.isoformat() if on else "?"))
    d = decision or {}
    state, by = str(d.get("state") or ""), str(d.get("by") or "")
    ticket = (", %s" % d["ticket"]) if d.get("ticket") else ""
    held = " (decision run %s)" % d["run"] if d.get("run") else ""
    if state == "fixed":
        if rescan == "":
            return against_due("open", "recorded fixed by %s, but the newest run still "
                                       "reports it" % by)
        on = _day(str(d.get("recorded_at") or ""))
        return fixed(on, "recorded fixed by %s on %s, with the retest evidence%s%s"
                     % (by, on.isoformat() if on else "?", ticket, held))
    if state == "false positive":
        return dict(out, status="false positive", decision="by %s: %s%s" % (
            by, " ".join(str(d.get("reason") or "").split()), held))
    if state == "risk accepted":
        until = str(d.get("expires") or "")
        if until and now <= datetime.date.fromisoformat(until):
            return dict(out, status="risk accepted", decision=(
                "by %s until %s%s: %s Compensating controls: %s%s" % (
                    by, until, ticket, " ".join(str(d.get("reason") or "").split()),
                    " ".join(str(d.get("compensating_controls") or "").split()), held)))
        return against_due("open", "risk acceptance by %s expired on %s" % (by, until))
    if state == "in progress":
        return against_due("in progress", "in progress, %s%s" % (by, ticket))
    return against_due("open", "")


def _sla_summary(items: List[dict], policy: Dict[str, Tuple[int, str]], today: str,
                 images: int, unreadable: List[str]) -> dict:
    """The deadlines section: the policy with its sources, and every tracked
    item counted by severity and state."""
    rows = []
    for sev in SEVERITY_ORDER:
        mine = [x for x in items if x["severity"] == sev]
        if not mine:
            continue
        waiting = [x["due"] for x in mine if x["due"] and x["status"] not in _CLOSED]
        days = policy[sev][0] if sev in REMEDIATION_DAYS else None
        count = {st: sum(1 for x in mine if x["status"] == st) for st in REMEDIATION_STATES}
        window = ("%d days" % days if days else
                  "none" if sev == "info" else "none until rated")
        rows.append({"severity": sev, "window": window,
                     "next_due": min(waiting) if waiting else "", "total": len(mine),
                     "open": count["open"] + count["in progress"],
                     "overdue": count["overdue"],
                     "decided": count["risk accepted"] + count["false positive"],
                     "fixed": count["fixed"] + count["fixed late"]})
    shown = [("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
             ("low", "Low"), ("kev", "Known exploited")]
    # A known exploited finding is counted under its rating but is due on the
    # shorter clock, which is why a medium row can fall due before a high one.
    kev = sorted(x["due"] for x in items if x.get("kev") and x["due"]
                 and x["status"] not in _CLOSED)
    return {
        "as_of": today, "rows": rows, "tracked": len(items), "images": images,
        "kev_open": len(kev), "kev_next_due": kev[0] if kev else "",
        "basis": REMEDIATION_BASIS,
        "policy": [{"name": label, "days": policy[key][0],
                    "source": REMEDIATION_SOURCES[key] if policy[key][1] == "built-in"
                    else "Set in this engagement's squawk.toml [remediation]."}
                   for key, label in shown],
        "rule": REMEDIATION_RULE % policy["accept_max_days"][0],
        "unreadable": unreadable,
    }


def share_model(root: str, session: str,
                redactor: Optional[Redactor] = None,
                today: Optional[str] = None) -> dict:
    """The shareable report as data: every string redacted, every finding once.

    The Markdown and the HTML page are both drawn from this, so the two cannot
    disagree, and a page served by the UI can draw from it too."""
    r = redactor or Redactor(root)
    clean = r.clean
    runs = runs_for_session(root, session)
    images = _newest_per_image(runs)
    rest = [m for m in runs if m.get("scope") != "image"]
    # An image run's package advisories go to its summary; what else it found
    # (dockle's configuration checks) is listed with everything else.
    found = distinct_findings(rest + images, keep=lambda man, f: (
        man.get("scope") != "image" or not _summarised(f)))
    manual = [f for f in found if f.get("scanner") == MANUAL_SCANNER]
    scanner = [f for f in found if f.get("scanner") != MANUAL_SCANNER]
    # Retesting is re-running the service: a fixed finding is one the newest
    # run of the same service on the same target no longer reports. Without
    # this the report listed it from the older runs as if nothing changed.
    key_of = {str(m.get("run_id")): (str(m.get("service")), str(m.get("target") or ""))
              for m in runs}
    newest: Dict[Tuple[str, str], str] = {}
    for m in runs:                          # oldest first, so the last one wins
        newest[key_of[str(m.get("run_id"))]] = str(m.get("run_id"))

    by_key: Dict[Tuple[str, str], List[str]] = {}
    for m in runs:
        by_key.setdefault(key_of[str(m.get("run_id"))], []).append(str(m.get("run_id")))

    def rescan_of(f: dict) -> str:
        """"" while the newest run of any service that saw it still reports
        it; else the run after which no run reported it."""
        seen = {str(r) for r in f["runs"]}
        gone = []
        for key in {key_of[r] for r in seen if r in key_of}:
            if newest[key] in seen:
                return ""
            last = max(r for r in seen if key_of.get(r) == key)
            gone.append(min(r for r in by_key[key] if r > last))
        return max(gone) if gone else ""

    policy = load_profile(root).remediation()
    when = today or today_utc()
    everything = list_runs(root)
    decided, unreadable = load_dispositions(
        sorted(everything, key=lambda m: str(m.get("run_id") or "")))
    seen_first = first_seen_index(everything)
    feeds = load_feeds(root)
    run_target = {str(m.get("run_id")): str(m.get("target") or "") for m in runs}
    # What a decision about each finding is keyed to, by the ID the reader
    # copies into one (redacted, as the report prints it). Kept out of the page.
    keys: Dict[str, dict] = {}

    def sla(f: dict, kev: bool, rescan: Optional[str]) -> dict:
        raw = str(f.get("identity") or "")
        targets = sorted({run_target[str(x)] for x in f["runs"] if str(x) in run_target})
        pairs = [(t, raw) for t in targets]
        first = min([seen_first[p] for p in pairs if p in seen_first]
                    + [str(x) for x in f["runs"]])
        fid = clean(raw)
        keys[fid] = {"targets": targets, "identities": [raw]}
        return dict(remediation_state(
            str(f.get("severity") or "unknown").lower(), kev, first, policy, when,
            decision_for(decided, pairs), rescan), finding_id=fid)

    by_sev: Dict[str, int] = {}
    for f in found:
        s = str(f.get("severity") or "unknown").lower()
        by_sev[s] = by_sev.get(s, 0) + 1
    by_tool: Dict[str, int] = {}
    for f in scanner:
        by_tool[str(f.get("scanner"))] = by_tool.get(str(f.get("scanner")), 0) + 1

    # A reviewer finding's number follows the order it was first recorded, so
    # recording another never renumbers the rest: a document that cites R3
    # still means the same finding after R6 is added. The list stays most
    # severe first; the numbers were the position in it, and moved.
    first = sorted(manual, key=lambda f: (min(str(x) for x in f["runs"]),
                                          str(f.get("identity") or "")))
    number = {id(f): n for n, f in enumerate(first, 1)}
    reviewer = []
    for f in manual:
        n = number[id(f)]
        d = f.get("detail") or {}
        controls = "; ".join(v.replace("\n", " ") for k, v in _sections(f).items()
                             if k not in NOTE_META)
        reviewer.append({
            "id": "R%d" % n, "severity": str(f.get("severity") or "unknown"),
            "title": clean(f.get("title")), "target": clean(f.get("path")),
            "how_found": clean(d.get("how_found", "")),
            "evidence": clean(d.get("evidence", "")),
            "impact": clean(d.get("impact", "")), "controls": clean(controls),
            "remediation": clean(d.get("remediation", "")),
            "abilities": _abilities_of(f),
            "recorded_by": clean(_sections(f).get("reviewer", "")),
            "retest": clean(_sections(f).get("retest") or NOTE_RETEST_FALLBACK),
            "references": clean(_sections(f).get("references") or ""),
            "attachments": [{"name": clean(a.get("name")),
                             "sha256": str(a.get("sha256") or "")[:16]}
                            for a in d.get("attachments") or []],
            **sla(f, False, None),
        })

    abilities = []
    for ability in ABILITIES:
        who = [x for x in reviewer if ability in x["abilities"]]
        if not who:
            verdict = "none recorded"
        elif any(x["severity"] in ("critical", "high") for x in who):
            verdict = "yes"
        else:
            verdict = "partly"
        abilities.append({"ability": ability, "verdict": verdict,
                          "findings": [{"id": x["id"], "title": x["title"]} for x in who]})

    not_covered: List[List[str]] = []
    ran = []
    for man in runs:
        nc = clean(man.get("not_covered") or "").strip()
        label = clean(man.get("service_label") or man.get("service") or "?")
        if nc and [label, nc] not in not_covered:
            not_covered.append([label, nc])
        tools = []
        for row in man.get("ledger") or []:
            cov = row.get("coverage") or {}
            seen = ("%s %s" % (cov.get("examined"), cov.get("unit") or "")).strip() \
                if cov.get("examined") is not None else ""
            tools.append([clean(row.get("tool")), clean(row.get("status")), clean(seen)])
        ran.append({"run": man.get("run_id"), "service": label,
                    "target": clean(man.get("target")), "tools": tools})
    scanner_rows = []
    for f in scanner:
        kev = bool(exploitability(cve_of(f), feeds).get("kev"))
        scanner_rows.append(dict({
            "severity": str(f.get("severity") or "unknown").lower(),
            "title": clean(f.get("title")), "where": _where(f, clean),
            "source": str(f.get("scanner") or "?"),
            "rule": clean((f.get("detail") or {}).get("rule") or ""),
            "remediation": clean((f.get("detail") or {}).get("remediation") or ""),
            "reference": clean((f.get("detail") or {}).get("reference") or ""),
            "cve": cve_of(f) or "", "kev": kev, "retest": clean(retest_for(f)),
            "runs": len(f["runs"])}, **sla(f, kev, rescan_of(f))))
    image_rows = _image_rows(runs, r, feeds, policy, when, decided, seen_first, keys)
    ids = [str(m.get("run_id") or "") for m in runs]
    targets = sorted({clean(m.get("target")) for m in rest
                      if m.get("service") not in ("note", DISPOSITION_SERVICE.key)}
                     | {str(x["target"]) for x in reviewer})
    return {
        "session": clean(session), "runs": len(runs),
        "first": _when(min(ids)) if ids else "", "last": _when(max(ids)) if ids else "",
        "distinct": len(found), "by_severity": by_sev, "by_tool": by_tool,
        "targets": targets, "reviewer": reviewer, "abilities": abilities,
        "abilities_recorded": any(a["findings"] for a in abilities),
        "scanner": scanner_rows,
        "images": [_image_summary(m, feeds, clean) for m in images],
        "sla": _sla_summary(reviewer + scanner_rows + image_rows, policy, when,
                            len(image_rows), unreadable),
        "disagreements": [clean(d.get("note") or "") for m in runs
                          for d in m.get("differential") or []],
        "not_covered": not_covered, "ran": ran,
        "_image_rows": image_rows, "_keys": keys,
    }


#: The retest method, said once at the top of the engineering report.
RETEST_HOWTO = (
    "Each finding below carries the command that confirms it is fixed: the tool "
    "that found it, narrowed to its rule, against the same file. `<repo>` is the "
    "checkout, `<image>` the rebuilt image and `<url>` a test instance seeded with "
    "test data. After a fix, run that command, then "
    "re-run the Squawk service that found it into this session; a fixed finding is "
    "marked **fixed**, dated to the first run that no longer reports it. A finding "
    "recorded by hand carries its own retest, the steps that proved it run again "
    "with the opposite result "
    "expected. `squawk verify` shows the evidence of both runs is intact.")


def _short(s: str, limit: int) -> str:
    """One line, cut at a word with an ellipsis when it is longer than `limit`."""
    s = " ".join((s or "").split())
    if len(s) <= limit:
        return s
    return (s[:limit].rsplit(" ", 1)[0] or s[:limit]).rstrip() + "…"


def _sev_line(model: dict) -> str:
    return ", ".join("%s %d" % (s, model["by_severity"][s])
                     for s in SEVERITY_ORDER if model["by_severity"].get(s))


SHARE_PREAMBLE = (
    "Paths are shown relative to each target. Local directories, the user name, "
    "the host name and email addresses are removed from this copy; the sealed "
    "evidence keeps the originals, and its digests cover them.")


def _due_markdown(x: dict) -> str:
    """One finding's deadline line: due, why, where it stands, and its ID."""
    return "Due: %s (%s) · **%s**%s · ID `%s`" % (
        x["due"] or "none", x["basis"], x["status"],
        " — %s" % x["decision"] if x["decision"] else "", x["finding_id"])


def _deadlines_markdown(sla: dict) -> List[str]:
    out = ["## Remediation deadlines", "",
           "As of %s. %s" % (sla["as_of"], "Counted: the reviewer's findings, the "
                             "scanners', and each image advisory once per package, "
                             "{:,} in all, the rows of the CSV.".format(sla["tracked"])), "",
           "| Severity | Fix within | Next due | Open | Overdue | Accepted or false | Fixed |",
           "|---|---|---|---|---|---|---|"]
    out += ["| %s | %s | %s | %d | %d | %d | %d |" % (
        x["severity"], x["window"], x["next_due"] or "—", x["open"], x["overdue"],
        x["decided"], x["fixed"]) for x in sla["rows"]]
    if sla["kev_open"]:
        out += ["", "Known exploited: %d open, each counted under its rating and due on the "
                "known-exploited clock, the first on %s." % (sla["kev_open"],
                                                              sla["kev_next_due"])]
    out += ["", "**Where each window comes from**", ""]
    out += ["- **%s, %d days.** %s" % (p["name"], p["days"], p["source"])
            for p in sla["policy"]]
    out += ["", sla["rule"], "", sla["basis"], ""]
    if sla["unreadable"]:
        out += ["**Not applied:** the decisions in run(s) %s could not be read. `squawk "
                "verify` says why." % ", ".join("`%s`" % x for x in sla["unreadable"]), ""]
    return out


def share_markdown(model: dict, verify: Optional[dict] = None) -> str:
    """The shareable report as Markdown."""
    v = verify or {}
    out = ["# Security review: %s" % model["session"], "",
           "%s to %s · %d sealed runs · evidence check: **%s**" % (
               model["first"], model["last"], model["runs"], v.get("status", "not run")),
           "", "> " + SHARE_PREAMBLE, "",
           "## Summary", "", "| | |", "|---|---|",
           "| Targets | %s |" % "; ".join("`%s`" % t for t in model["targets"]),
           "| Distinct findings | **%d** (%s) |" % (model["distinct"], _sev_line(model) or "none"),
           "| Recorded by the reviewer | %d |" % len(model["reviewer"]),
           "| From scanners | %d (%s) |" % (len(model["scanner"]), ", ".join(
               "%s %d" % kv for kv in sorted(model["by_tool"].items()))), ""]
    if model["abilities_recorded"]:
        out += ["## What an attacker can do", "",
                "From the abilities each finding recorded by the reviewer names.", "",
                "| Ability | Verdict | Findings |", "|---|---|---|"]
        out += ["| %s | %s | %s |" % (a["ability"].capitalize(), a["verdict"],
                                     ", ".join("%s %s" % (x["id"], x["title"])
                                               for x in a["findings"]) or "—")
                for a in model["abilities"]]
        out.append("")
    out += _deadlines_markdown(model["sla"])
    out += ["## How to retest", "", RETEST_HOWTO, ""]
    out += ["## Findings recorded by the reviewer", ""]
    if not model["reviewer"]:
        out += ["_None recorded._", ""]
    else:
        out += ["| # | Severity | Finding | Due | Control mapping |", "|---|---|---|---|---|"]
        out += ["| %s | %s | %s | %s · %s | %s |" % (
            x["id"], x["severity"], x["title"], x["due"] or "none", x["status"],
            x["controls"] or "—") for x in model["reviewer"]]
        out.append("")
        for x in model["reviewer"]:
            out += ["### %s. %s" % (x["id"], x["title"]), "",
                    "**Severity:** %s · **Target:** `%s`%s" % (
                        x["severity"], x["target"],
                        " · **Recorded by:** %s" % x["recorded_by"] if x["recorded_by"] else ""),
                    "", _due_markdown(x), ""]
            for key, head in (("how_found", "How it was found"), ("evidence", "Evidence"),
                              ("impact", "Impact")):
                if x[key]:
                    out += ["**%s**" % head, "", "```", x[key], "```", ""]
            if x["controls"]:
                out += ["**Control mapping**", "", x["controls"], ""]
            if x["remediation"]:
                out += ["**Remediation**", "", x["remediation"], ""]
            out += ["**How to retest**", "", "```", x["retest"], "```", ""]
            if x["references"]:
                out += ["**References**", "", x["references"], ""]
            out += ["- Attached: `%s` · sha256 `%s`" % (a["name"], a["sha256"])
                    for a in x["attachments"]]
            out.append("")
    for im in model["images"]:
        out += ["## Container image: `%s`" % im["ref"], "",
                "%d rows (%s) over %s: **%d distinct CVEs**, %d rated critical%s." % (
                    im["rows"], ", ".join("%s %d" % kv for kv in sorted(im["by_tool"].items())),
                    im["packages"] or "an unknown number of packages", im["distinct_cves"],
                    im["critical_cves"],
                    ", plus %d advisories with no CVE id" % im["other_advisories"]
                    if im["other_advisories"] else ""), ""]
        if im.get("listed_apart"):
            out += ["Also from this image, listed with the scanner findings: %s." % ", ".join(
                "%d from %s" % (n, t) for t, n in sorted(im["listed_apart"].items())), ""]
        if not im["feeds"]:
            out += ["Exploitability unknown: the KEV and EPSS feeds were not fetched "
                    "(`squawk feeds`). That is not a statement that none is exploited.", ""]
        else:
            out += ["- Known exploited (CISA KEV): **%d**%s" % (len(im["kev"]), "".join(
                "\n  - `%s` in %s, rated %s" % (k["cve"], ", ".join(k["pkgs"]), k["severity"])
                for k in im["kev"])),
                "- Likely to be exploited soon (EPSS ≥ %.2f): %d" % (EPSS_HOT, im["epss_hot"]), ""]
        if im["top_critical"]:
            out += ["Where the critical CVEs are: %s." % ", ".join(
                "`%s` (%d)" % kv for kv in im["top_critical"]), ""]
    out += ["## Findings from scanners", "", "Each finding once, however many runs saw it.", ""]
    for s in SEVERITY_ORDER:
        rows = [f for f in model["scanner"] if f["severity"] == s]
        if rows:
            out += ["### %s (%d)" % (s.capitalize(), len(rows)), ""]
            for f in rows:
                source = ("%s · %s" % (f["source"], f["rule"])) if f["rule"] else f["source"]
                out.append("- **%s** · `%s` · %s · %d run(s)" % (
                    f["title"], f["where"], source, f["runs"]))
                out.append("  - " + _due_markdown(f))
                out.append("  - Fix: %s" % (f["remediation"] or "_none given by the tool; "
                                                                "see the reference_"))
                out.append("  - Retest: `%s`" % f["retest"])
                if f["reference"]:
                    out.append("  - Reference: %s" % f["reference"])
            out.append("")
    out += ["## Where the tools disagreed", ""]
    out += ["- %s" % d for d in model["disagreements"]] or [
        "- No disagreement between overlapping tools was recorded."]
    out += ["", "## What was not covered", ""]
    out += ["- **%s:** %s" % (a, b) for a, b in model["not_covered"]] or ["- _Nothing declared._"]
    out += ["", "## What ran", "", "| Run | Service | Target | Tools |", "|---|---|---|---|"]
    out += ["| `%s` | %s | `%s` | %s |" % (x["run"], x["service"], x["target"], "; ".join(
        "%s %s%s" % (t, st, " (%s)" % seen if seen else "") for t, st, seen in x["tools"]))
            for x in model["ran"]]
    out += ["", "## Evidence integrity", "",
            "`%s` — %s" % (v.get("status", "not run"), v.get("summary", "")), "",
            "Every run is a sealed directory whose digest covers each file in it, attached "
            "evidence included, and each run records the digest of the one before it. This "
            "shows the evidence has not changed since it was written; it does not prove who "
            "wrote it.", ""]
    return "\n".join(out)


#: The page's look: Squawk's teal, light and dark, system fonts only. A report
#: that loads a web font tells a font host who opened it, which is the wrong
#: thing for a document whose first lines say what was removed.
SHARE_CSS = """
:root{--bg:#f4f7f7;--surface:#fff;--surface-2:#eaf1f1;--ink:#10201f;--soft:#4d6261;
--line:#d3dfde;--accent:#0b7f78;--accent-ink:#fff;--crit:#b8232b;--high:#c2410c;
--med:#a16207;--low:#1d5fa8;--info:#5b6d6c;--yes:#b8232b;--partly:#a16207;--none:#5b6d6c;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#0b1416;--surface:#111d20;--surface-2:#17272a;
--ink:#e4efee;--soft:#94aaa8;--line:#24393c;--accent:#3fd6cc;--accent-ink:#052523;
--crit:#ff6b6b;--high:#ff9858;--med:#f0c04a;--low:#7cb6ff;--info:#a2b4b2;--yes:#ff6b6b;
--partly:#f0c04a;--none:#a2b4b2;color-scheme:dark}}
*{box-sizing:border-box}html,body{margin:0}
body{background:var(--bg);color:var(--ink);font:400 15px/1.6 var(--sans)}
main{max-width:1080px;margin:0 auto;padding:32px max(16px,env(safe-area-inset-right,0px))
72px max(16px,env(safe-area-inset-left,0px));display:grid;gap:40px}
h1,h2,h3{margin:0;line-height:1.2;text-wrap:balance}h1{font-size:2rem}h2{font-size:1.4rem}
h3{font-size:1.1rem}p{margin:0;max-width:72ch}code,pre,.mono{font-family:var(--mono);
font-size:.82rem}
.eyebrow{font:500 .75rem var(--mono);letter-spacing:.08em;text-transform:uppercase;
color:var(--accent)}
.muted{color:var(--soft)}section{display:grid;gap:14px;min-width:0}
.head{display:grid;gap:4px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.meta{display:flex;flex-wrap:wrap;gap:8px 16px;color:var(--soft);
font-variant-numeric:tabular-nums}
.note{background:var(--surface-2);border-radius:10px;padding:10px 14px;color:var(--soft);
max-width:none}
.two{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr);gap:20px;
align-items:start}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:18px;
min-width:0}
.big{font:700 2.4rem/1 var(--sans);font-variant-numeric:tabular-nums}
.bar{display:flex;height:18px;border-radius:6px;overflow:hidden;background:var(--surface-2);
margin-top:10px}
.bar span{display:block;height:100%}.legend{display:flex;flex-wrap:wrap;gap:6px 14px;
margin-top:10px}
dl{margin:0}.facts{display:grid;gap:8px}.facts div,.kv{display:grid;
grid-template-columns:170px minmax(0,1fr);gap:6px 14px}
dt{color:var(--soft)}dd{margin:0;min-width:0;overflow-wrap:anywhere}.lines{white-space:pre-line}
.sev{display:inline-block;padding:1px 9px;border-radius:999px;font:600 .72rem var(--mono);
color:var(--surface);white-space:nowrap}
.sev.critical{background:var(--crit)}.sev.high{background:var(--high)}
.sev.medium{background:var(--med)}
.sev.low{background:var(--low)}.sev.info,.sev.unknown{background:var(--info)}
.ability{display:grid;grid-template-columns:120px 130px minmax(0,1fr);gap:14px;
align-items:start;
background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.verdict{justify-self:start;padding:2px 10px;border-radius:999px;font:600 .75rem var(--mono);
border:1.5px solid currentColor}
.verdict.yes{color:var(--yes)}.verdict.partly{color:var(--partly)}
.verdict.none{color:var(--none)}
.card{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--line);
border-radius:10px;padding:16px 18px;display:grid;gap:10px;min-width:0}
.card.critical{border-left-color:var(--crit)}.card.high{border-left-color:var(--high)}
.card.medium{border-left-color:var(--med)}
.card-head{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:baseline}
.card-head h3{flex:1 1 320px}
pre{margin:6px 0 0;background:var(--surface-2);border-radius:8px;padding:10px 12px;
white-space:pre-wrap;
overflow-wrap:anywhere;max-height:260px;overflow:auto}
summary{cursor:pointer;color:var(--accent);font-weight:500}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.stat{background:var(--surface);border:1px solid var(--line);border-radius:10px;
padding:12px 14px}
.stat b{display:block;font-size:1.5rem;font-variant-numeric:tabular-nums}
.callout{border:1.5px solid var(--crit);border-radius:10px;padding:14px 16px;
background:var(--surface);display:grid;gap:6px}
ul{margin:0;padding-left:1.1rem;display:grid;gap:4px}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--surface)}
table{width:100%;border-collapse:collapse;font-size:.86rem}
th,td{text-align:left;vertical-align:top;padding:8px 12px;border-bottom:1px solid var(--line)}
th{background:var(--surface-2);font-weight:600}tbody tr:last-child td{border-bottom:none}
td.num{text-align:right;font-variant-numeric:tabular-nums}td code{overflow-wrap:anywhere}
.filters{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.chip{font:500 .78rem var(--mono);padding:4px 10px;border-radius:999px;cursor:pointer;
border:1px solid var(--line);
background:var(--surface);color:var(--soft)}
.chip[aria-pressed=true]{background:var(--accent);border-color:var(--accent);
color:var(--accent-ink)}
select,input[type=search]{font:inherit;padding:6px 10px;border-radius:8px;
border:1px solid var(--line);
background:var(--surface);color:var(--ink)}input[type=search]{flex:1 1 220px;min-width:0}
footer{color:var(--soft);font-size:.85rem;border-top:1px solid var(--line);padding-top:14px}
@media (max-width:760px){.two{grid-template-columns:minmax(0,1fr)}
.ability{grid-template-columns:minmax(0,1fr);gap:8px}
.facts div,.kv{grid-template-columns:minmax(0,1fr);gap:2px}}
[hidden]{display:none!important}
@media print{main{padding:0}.filters{display:none}.card,tr,.keep{break-inside:avoid}
article.card{break-inside:auto;display:block}article.card>*+*{margin-top:10px}
article .kv{display:block}article dt{margin-top:6px}
.card-head,dt,.head{break-after:avoid}pre{break-inside:avoid;max-height:none;overflow:visible}
table.findings{table-layout:fixed;width:100%}
table.findings th:nth-child(1){width:11%}table.findings th:nth-child(2){width:50%}
table.findings th:nth-child(3){width:17%}table.findings th:nth-child(4){width:14%}
table.findings th:nth-child(5){width:8%}}
body[data-audience=executive] .eng{display:none!important}
body:not([data-audience=executive]) .exec-only{display:none!important}
"""

#: The page's structure. Every value is filled in by SHARE_JS from the embedded
#: data, with textContent: nothing from the evidence is ever parsed as markup.
SHARE_BODY = """
<main>
<header style="display:grid;gap:10px">
<p class="note exec-only">This summary leaves out each finding's location and
evidence. The engineering report from the same session carries them.</p>
<span class="eyebrow" id="eyebrow">Squawk · engagement report</span>
<h1 id="title"></h1><div class="meta" id="meta"></div><p class="note" id="preamble"></p>
</header>
<section><div class="head"><h2>Summary</h2></div><div class="two">
<div class="panel"><div class="big" id="distinct"></div>
<p class="muted">distinct findings, each counted once however many runs saw it</p>
<div class="bar" id="sevbar" role="img" aria-label="Findings by severity"></div>
<div class="legend" id="legend"></div></div>
<div class="panel"><dl class="facts" id="facts"></dl></div></div></section>
<section><div class="head"><h2>What an attacker can do</h2>
<p class="muted" id="abilities-sub"></p></div>
<div style="display:grid;gap:10px" id="abilities"></div></section>
<section><div class="head"><h2>Remediation deadlines</h2>
<p class="muted" id="sla-sub"></p></div>
<div class="wrap keep"><table><thead><tr><th>Severity</th><th>Fix within</th><th>Next due</th>
<th>Open</th><th>Overdue</th><th>Accepted or false</th><th>Fixed</th></tr></thead>
<tbody id="sla-rows"></tbody></table></div>
<h3 style="margin-top:14px">Where each window comes from</h3><ul id="sla-policy"></ul>
<p class="muted" id="sla-kev"></p>
<p id="sla-rule"></p><p class="muted" id="sla-basis"></p>
<p class="callout" id="sla-unreadable" hidden></p></section>
<section class="eng"><div class="head"><h2>How to retest</h2></div>
<p id="retest-howto"></p></section>
<section><div class="head"><h2>Findings recorded by the reviewer</h2>
<p class="muted">Found by reading the code and testing the running service,
with the evidence attached.</p></div>
<div class="wrap"><table><thead><tr><th>#</th><th>Severity</th><th>Finding</th>
<th>Due</th><th>Control mapping</th></tr></thead>
<tbody id="rev-table"></tbody></table></div>
<div class="eng" style="display:grid;gap:14px" id="reviewer">
</div></section>
<div id="images" style="display:grid;gap:40px"></div>
<section class="eng"><div class="head"><h2>Findings from scanners</h2>
<p class="muted">Code, configuration and dependencies, each finding once.
Container images are summarised above.</p></div>
<div class="filters" role="group" aria-label="Filter scanner findings">
<div class="filters" id="chips"></div>
<label class="muted" for="source">Source</label><select id="source">
<option value="">All sources</option></select>
<label class="muted" for="q">Search</label>
<input type="search" id="q" placeholder="Title, file or rule">
<span class="muted" id="count" aria-live="polite"></span></div>
<div class="wrap"><table class="findings"><thead><tr><th>Severity</th><th>Finding</th>
<th>First seen</th><th>Due</th><th>Runs</th></tr></thead>
<tbody id="scanner"></tbody></table></div></section>
<section class="eng"><div class="head"><h2>Where the tools disagreed</h2></div>
<ul id="disagree"></ul>
</section>
<section><div class="head"><h2>What was not covered</h2></div><ul id="nc"></ul></section>
<section class="eng"><div class="head"><h2>What ran</h2></div><details>
<summary>Every run in the session, with what each tool examined</summary>
<div class="wrap" style="margin-top:10px"><table><thead><tr><th>Run</th><th>Service</th>
<th>Target</th><th>Tools</th></tr></thead>
<tbody id="ran"></tbody></table></div></details></section>
<section class="keep"><div class="head"><h2>Evidence integrity</h2></div><p id="integrity"></p>
<p class="muted">Every run is a sealed directory whose digest covers each file in it,
attached evidence included, and each run records the digest of the one before it.
This shows the evidence has not changed since it was written. It does not prove who
wrote it.</p>
<footer id="footer"></footer></section>
</main>
"""

SHARE_JS = r"""
(function () {
  "use strict";
  var D = JSON.parse(document.getElementById("report-data").textContent);
  var M = D.model, V = D.verify || {};
  var ORDER = ["critical", "high", "medium", "low", "info", "unknown"];
  var COLOR = {critical: "var(--crit)", high: "var(--high)", medium: "var(--med)",
               low: "var(--low)", info: "var(--info)", unknown: "var(--info)"};
  var DASH = "—", DOT = " · ";

  function el(tag, attrs, kids) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") { n.textContent = attrs[k]; } else { n.setAttribute(k, attrs[k]); }
    });
    (kids || []).forEach(function (c) {
      if (c != null) { n.appendChild(typeof c === "string" ? document.createTextNode(c) : c); }
    });
    return n;
  }
  function pill(s) {
    s = (s || "unknown").toLowerCase();
    return el("span", {"class": "sev " + s, text: s});
  }
  function $(id) { return document.getElementById(id); }
  function fmt(n) { return Number(n).toLocaleString("en-US"); }
  function row(cells) { return el("tr", {}, cells); }
  function td(text) { return el("td", {text: text}); }
  function tdCode(text) { return el("td", {}, [el("code", {text: text})]); }

  // Header and summary
  document.title = "Security review: " + M.session;
  var EXEC = D.audience === "executive";
  $("title").textContent = (EXEC ? "Executive summary: " : "Security review: ") + M.session;
  $("eyebrow").textContent = EXEC ? "Squawk · executive summary" : "Squawk · engineering report";
  $("retest-howto").textContent = D.retest || "";
  $("meta").append(el("span", {text: M.first + " to " + M.last}),
                   el("span", {text: M.runs + " sealed runs"}),
                   el("span", {text: "evidence check: " + (V.status || "not run")}));
  $("preamble").textContent = D.preamble;
  $("distinct").textContent = fmt(M.distinct);
  ORDER.forEach(function (k) {
    var n = M.by_severity[k] || 0;
    if (!n) { return; }
    $("sevbar").append(el("span", {title: k + " " + n,
      style: "width:" + (100 * n / M.distinct) + "%;background:" + COLOR[k]}));
    $("legend").append(el("span", {}, [pill(k), " " + fmt(n)]));
  });
  var tools = Object.keys(M.by_tool).sort().map(function (t) {
    return t + " " + M.by_tool[t];
  }).join(", ");
  var facts = [["Targets", M.targets.join("; ")],
               ["Recorded by the reviewer", String(M.reviewer.length)],
               ["From scanners", M.scanner.length + (tools ? " (" + tools + ")" : "")]];
  M.images.forEach(function (i) {
    facts.push(["Container image", i.ref + ": " + fmt(i.distinct_cves) + " distinct CVEs" +
                (i.feeds ? ", " + i.kev.length + " known exploited" : "")]);
  });
  facts.forEach(function (f) {
    $("facts").append(el("div", {}, [el("dt", {text: f[0]}), el("dd", {text: f[1]})]));
  });

  // What an attacker can do: only what the reviewer's notes recorded
  if (M.abilities_recorded) {
    $("abilities-sub").textContent = "From the abilities each finding recorded by the " +
      "reviewer names. A verdict is yes when a critical or high finding gives the ability.";
    M.abilities.forEach(function (a) {
      var cls = a.verdict === "none recorded" ? "none" : a.verdict;
      var who = a.findings.length ? a.findings.map(function (x) {
        return el("p", {}, [el("span", {"class": "mono muted", text: x.id + " "}), x.title]);
      }) : [el("p", {"class": "muted", text: "No finding recorded this ability."})];
      $("abilities").append(el("div", {"class": "ability"}, [
        el("h3", {text: a.ability.charAt(0).toUpperCase() + a.ability.slice(1)}),
        el("span", {"class": "verdict " + cls, text: a.verdict}),
        el("div", {}, who)]));
    });
  } else {
    $("abilities-sub").textContent = "No finding recorded an attacker ability. A note can " +
      "carry a line such as “abilities: read, modify”, from destroy, modify, " +
      "disrupt and read.";
  }

  // Remediation deadlines: the policy, its sources, and where each item stands
  var S = M.sla;
  $("sla-sub").textContent = "As of " + S.as_of + ". Counted: the reviewer's findings, " +
    "the scanners', and each image advisory once per package, " + fmt(S.tracked) +
    " in all, the rows of the CSV.";
  S.rows.forEach(function (x) {
    $("sla-rows").append(row([el("td", {}, [pill(x.severity)]), td(x.window),
      td(x.next_due || DASH), el("td", {"class": "num", text: fmt(x.open)}),
      el("td", {"class": "num", text: fmt(x.overdue)}),
      el("td", {"class": "num", text: fmt(x.decided)}),
      el("td", {"class": "num", text: fmt(x.fixed)})]));
  });
  S.policy.forEach(function (p) {
    $("sla-policy").append(el("li", {}, [el("b", {text: p.name + ", " + p.days + " days. "}),
                                         p.source]));
  });
  $("sla-rule").textContent = S.rule.replace(/`/g, "");
  $("sla-basis").textContent = S.basis;
  if (S.kev_open) {
    $("sla-kev").textContent = "Known exploited: " + S.kev_open + " open, each counted under " +
      "its rating and due on the known-exploited clock, the first on " + S.kev_next_due + ".";
  }
  if (S.unreadable.length) {
    $("sla-unreadable").hidden = false;
    $("sla-unreadable").textContent = "Not applied: the decisions in run(s) " +
      S.unreadable.join(", ") + " could not be read. squawk verify says why.";
  }
  function due(f) {
    return "Due " + (f.due || "none") + " (" + f.basis + ")" + DOT + f.status +
      (f.decision ? " " + DASH + " " + f.decision : "");
  }

  // The reviewer's findings
  M.reviewer.forEach(function (f) {
    $("rev-table").append(row([td(f.id), el("td", {}, [pill(f.severity)]), td(f.title),
                               td((f.due || "none") + DOT + f.status),
                               td(f.controls || DASH)]));
    var attached = f.attachments.length ? f.attachments.map(function (a) {
      return el("div", {"class": "mono", text: a.name + DOT + "sha256 " + a.sha256});
    }) : [DASH];
    var kv = el("dl", {"class": "kv"}, [
      el("dt", {text: "Target"}), el("dd", {}, [el("code", {text: f.target})]),
      el("dt", {text: "Deadline"}), el("dd", {text: due(f)}),
      el("dt", {text: "ID"}), el("dd", {}, [el("code", {text: f.finding_id})]),
      el("dt", {text: "Recorded by"}), el("dd", {text: f.recorded_by || "the operator"}),
      el("dt", {text: "Impact"}), el("dd", {text: f.impact || DASH}),
      el("dt", {text: "Control mapping"}), el("dd", {text: f.controls || DASH}),
      el("dt", {text: "Remediation"}), el("dd", {text: f.remediation || DASH}),
      el("dt", {text: "How to retest"}), el("dd", {}, [el("pre", {text: f.retest})]),
      el("dt", {text: "References"}), el("dd", {"class": "lines", text: f.references || DASH}),
      el("dt", {text: "Attached evidence"}), el("dd", {}, attached)]);
    $("reviewer").append(el("article", {"class": "card " + f.severity}, [
      el("div", {"class": "card-head"}, [el("span", {"class": "mono muted", text: f.id}),
                                         el("h3", {text: f.title}), pill(f.severity)]),
      kv,
      el("details", {}, [el("summary", {text: "How it was found, and the evidence"}),
                         el("pre", {text: f.how_found || DASH}),
                         el("pre", {text: f.evidence || DASH})])]));
  });

  // Container images, summarised
  M.images.forEach(function (i) {
    var s = el("section", {}, [el("div", {"class": "head"}, [
      el("h2", {text: "Container image"}),
      el("p", {"class": "muted"}, ["Scanned image ", el("code", {text: i.ref}), "."])])]);
    var stats = [[fmt(i.rows), "rows from the scanners"], [i.packages || DASH, "inventoried"],
                 [fmt(i.distinct_cves), "distinct CVEs"],
                 [String(i.critical_cves), "rated critical"]];
    if (i.feeds) {
      stats.push([String(i.kev.length), "known exploited (CISA KEV)"]);
      stats.push([String(i.epss_hot), "likely exploited soon (EPSS)"]);
    }
    var grid = el("div", {"class": "stats"});
    stats.forEach(function (x) {
      grid.append(el("div", {"class": "stat"}, [el("b", {text: x[0]}),
                                                el("span", {"class": "muted", text: x[1]})]));
    });
    s.append(grid);
    if (!i.feeds) {
      s.append(el("p", {"class": "muted", text: "Exploitability unknown: the KEV and EPSS " +
        "feeds were not fetched. That is not a statement that none is exploited."}));
    } else if (i.kev.length) {
      var c = el("div", {"class": "callout"}, [el("strong", {text: "Known to be exploited"})]);
      i.kev.forEach(function (k) {
        c.append(el("p", {}, [el("code", {text: k.cve}), " in " + k.pkgs.join(", ") +
                              ", rated ", pill(k.severity)]));
      });
      s.append(c);
    }
    if (i.top_critical.length) {
      s.append(el("div", {"class": "panel eng"}, [
        el("h3", {text: "Where the critical CVEs are"}),
        el("ul", {}, i.top_critical.map(function (p) {
          return el("li", {}, [el("code", {text: p[0]}), DOT + p[1]]);
        }))]));
    }
    if (i.other_advisories) {
      s.append(el("p", {"class": "muted", text: fmt(i.other_advisories) +
        " further advisories carry no CVE id and are counted separately."}));
    }
    var apart = Object.keys(i.listed_apart || {}).sort();
    if (apart.length) {
      s.append(el("p", {"class": "muted", text: "Also from this image, listed with " +
        "the scanner findings: " + apart.map(function (t) {
          return fmt(i.listed_apart[t]) + " from " + t; }).join(", ") + "."}));
    }
    $("images").append(s);
  });

  // Scanner findings, filterable by severity, source and text
  var on = {};
  ORDER.forEach(function (k) { on[k] = true; });
  var sources = {};
  M.scanner.forEach(function (f) { sources[f.source] = (sources[f.source] || 0) + 1; });
  Object.keys(sources).sort().forEach(function (s) {
    $("source").append(el("option", {value: s, text: s + " (" + sources[s] + ")"}));
  });
  ORDER.forEach(function (k) {
    var n = M.scanner.filter(function (f) { return f.severity === k; }).length;
    if (!n) { return; }
    var b = el("button", {type: "button", "class": "chip", "aria-pressed": "true",
                          id: "chip-" + k, text: k + " " + n});
    b.addEventListener("click", function () {
      on[k] = !on[k];
      b.setAttribute("aria-pressed", String(on[k]));
      draw();
    });
    $("chips").append(b);
  });
  function draw() {
    var src = $("source").value, q = $("q").value.trim().toLowerCase();
    var body = $("scanner"), shown = 0;
    body.textContent = "";
    M.scanner.forEach(function (f) {
      if (!on[f.severity] || (src && f.source !== src)) { return; }
      var hay = (f.title + " " + f.where + " " + f.rule + " " + f.source).toLowerCase();
      if (q && hay.indexOf(q) < 0) { return; }
      shown++;
      var what = el("td", {}, [f.title]);
      what.append(el("div", {"class": "muted"}, ["Where: ", el("code", {text: f.where})]));
      what.append(el("div", {"class": "muted"}, ["Source: ",
        el("code", {text: f.rule ? f.source + DOT + f.rule : f.source})]));
      var fix = f.remediation || "none given by the tool; see the reference";
      what.append(el("div", {"class": "muted", text: "Fix: " + fix}));
      what.append(el("div", {"class": "muted"}, ["Retest: ", el("code", {text: f.retest})]));
      if (f.reference) {
        what.append(el("div", {"class": "muted", text: "Reference: " + f.reference}));
      }
      body.append(row([el("td", {}, [pill(f.severity)]), what,
                       el("td", {text: f.first_seen || DASH}),
                       el("td", {text: (f.due || "none") + DOT + f.status}),
                       el("td", {"class": "num", text: String(f.runs)})]));
    });
    $("count").textContent = "Showing " + shown + " of " + M.scanner.length;
  }
  $("source").addEventListener("change", draw);
  // Paper cannot be clicked open: printed, every finding shows how it was
  // found and its evidence.
  window.addEventListener("beforeprint", function () {
    document.querySelectorAll("details").forEach(function (d) { d.open = true; });
  });
  $("q").addEventListener("input", draw);
  draw();

  // Method
  var dis = M.disagreements.length ? M.disagreements
    : ["No disagreement between overlapping tools was recorded."];
  dis.forEach(function (d) { $("disagree").append(el("li", {text: d})); });
  if (M.not_covered.length) {
    M.not_covered.forEach(function (x) {
      $("nc").append(el("li", {}, [el("b", {text: x[0] + ": "}), x[1]]));
    });
  } else {
    $("nc").append(el("li", {text: "Nothing declared."}));
  }
  M.ran.forEach(function (r) {
    var cells = r.tools.map(function (t) {
      return el("div", {text: t[0] + " " + t[1] + (t[2] ? " (" + t[2] + ")" : "")});
    });
    $("ran").append(row([tdCode(r.run), td(r.service), tdCode(r.target),
                         el("td", {}, cells)]));
  });
  $("integrity").append(el("code", {text: V.status || "not run"}), " " + DASH + " " +
    (V.summary || "squawk verify has not been run on this evidence root."));
  $("footer").textContent = "Built by Squawk from session " + M.session +
    ". Redacted copy: the sealed runs keep the originals.";
})();
"""


def share_html(model: dict, verify: Optional[dict] = None,
               audience: str = "engineer") -> str:
    """The shareable report as one self-contained page: no external request,
    every value drawn from embedded JSON with textContent. `</` is escaped in
    the JSON, so no value from the evidence can close the script block.

    The audience is set on the body, not only in the script, so the parts the
    executive summary leaves out are left out on paper as well as on screen,
    and with no script at all."""
    if audience not in AUDIENCES:
        raise ValueError("audience must be one of %s" % ", ".join(AUDIENCES))
    # Keys starting with "_" are for the CSV (each image advisory as a row):
    # the page summarises them, and embedding them would add a row per package.
    shown = {k: v for k, v in model.items() if not k.startswith("_")}
    data = json.dumps({"model": shown, "verify": verify or {},
                       "preamble": SHARE_PREAMBLE, "audience": audience,
                       "retest": RETEST_HOWTO.replace("**", "").replace("`", "")},
                      separators=(",", ":"))
    data = data.replace("</", "<\\/").replace("<!--", "<\\!--")
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' "
            "content='width=device-width,initial-scale=1,viewport-fit=cover'>"
            "<title>%s: %s</title><style>%s</style></head>"
            "<body data-audience='%s'>%s"
            "<script type='application/json' id='report-data'>%s</script>"
            "<script>%s</script></body></html>"
            % ("Executive summary" if audience == "executive" else "Security review",
               html.escape(model["session"]), SHARE_CSS, audience, SHARE_BODY, data,
               SHARE_JS))


#: The findings as rows, for a tracker or a spreadsheet: the reviewer's, the
#: scanners', and each image's advisories once per package.
CSV_COLUMNS = ("finding", "severity", "remediation", "retest", "status", "due",
               "first_seen", "decision", "where", "source", "rule", "cve", "kev", "kind",
               "runs", "reference", "id")

# A spreadsheet runs a cell that starts with one of these as a formula, and
# the text comes from the evidence: a scanned file can carry
# `=HYPERLINK(...)` as a title. Prefixed with a quote, it is text.
_FORMULA_START = ("=", "+", "-", "@")


#: Columns whose line breaks are kept: a retest is commands between sentences,
#: and run together on one line the command cannot be told from the prose.
CSV_KEEP_LINES = ("retest", "reference")


def _cell(value: object, lines: bool = False) -> str:
    """One CSV cell: whitespace collapsed, formula starts quoted.

    With `lines`, each non-blank line is kept on its own line and guarded on
    its own, so no line of a multi-line cell starts a formula either."""
    text = "" if value is None else str(value)
    out = []
    for line in (text.splitlines() if lines else [text]):
        one = " ".join(line.split())
        if one:
            out.append("'" + one if one.startswith(_FORMULA_START) else one)
    return "\n".join(out)


def _image_rows(runs: List[dict], r: "Redactor", feeds: dict,
                policy: Dict[str, Tuple[int, str]], today: str,
                decided: Dict[Tuple[str, str], dict],
                seen_first: Dict[Tuple[str, str], str],
                keys: Dict[str, dict]) -> List[dict]:
    """Each image's package advisories once per advisory and package, from the
    image's newest run, each with its deadline. One row stands for every
    scanner identity behind it (trivy's and grype's, each with the version),
    so its clock starts at the first run that reported any of them, and a
    decision about the row covers all of them."""
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    out: List[dict] = []
    for man in _newest_per_image(runs):
        raw = str(man.get("target") or "")
        ref = r.clean(raw)
        best: Dict[Tuple[str, str], dict] = {}
        for f in load_findings(str(man.get("_dir") or "")):
            if not _summarised(f):
                continue
            parts = str(f.get("identity") or "").split(":")
            key = (parts[0], parts[1] if len(parts) > 2 else "")
            sev = str(f.get("severity") or "unknown").lower()
            e = best.setdefault(key, {"sev": sev, "title": r.clean(f.get("title")),
                                      "sources": set(), "cve": cve_of(f) or "",
                                      "fixes": [], "refs": [], "idents": set()})
            e["sources"].add(str(f.get("scanner")))
            e["idents"].add(str(f.get("identity") or ""))
            if rank.get(sev, 9) < rank.get(e["sev"], 9):
                e["sev"] = sev
            d = f.get("detail") or {}
            if d.get("remediation"):
                e["fixes"].append(r.clean(d["remediation"]))
            if d.get("reference"):
                e["refs"].append(r.clean(d["reference"]))
        for (vid, pkg), e in sorted(best.items()):
            kev = bool(e["cve"] and exploitability(e["cve"], feeds).get("kev"))
            # An upgrade either scanner names beats a status line from the other.
            fix = next((x for x in e["fixes"] if x.startswith("Upgrade")),
                       e["fixes"][0] if e["fixes"] else "")
            # Only the tools that reported it: grype names a Python advisory by
            # its GHSA, trivy by the CVE, so either one's ID is absent from the
            # other's output whether or not it is fixed.
            scans = " and ".join(("trivy image " if t == "trivy" else t + " ") + RETEST_IMAGE
                                 for t in sorted(e["sources"]))
            ident = "%s:%s@%s" % (vid, pkg, ref)
            pairs = [(raw, i) for i in sorted(e["idents"])]
            keys[ident] = {"targets": [raw], "identities": sorted(e["idents"])}
            # Every row is from the image's newest run, so a re-run still reports it.
            state = remediation_state(
                e["sev"], kev, min([seen_first[p] for p in pairs if p in seen_first]
                                   + [str(man.get("run_id"))]),
                policy, today, decision_for(decided, pairs), "")
            out.append(dict(state, finding_id=ident, title=e["title"], severity=e["sev"],
                            remediation=fix,
                            retest="rebuild, then %s: no %s for %s" % (scans, vid, pkg),
                            where=ref, source="+".join(sorted(e["sources"])), rule=vid,
                            cve=e["cve"], kev=kev,
                            reference=e["refs"][0] if e["refs"] else ""))
    return out


def tracked_keys(root: str, session: str) -> Dict[str, dict]:
    """{finding ID: {targets, identities}} for every finding a decision can
    name in `session`: the reviewer's, the scanners' and each image
    advisory's, by the ID the report and the CSV print. The keys are what the
    decision is filed under, so it follows the finding to later sessions."""
    return dict(share_model(root, session)["_keys"])


def share_csv(root: str, session: str, redactor: Optional[Redactor] = None,
              today: Optional[str] = None) -> str:
    """The session's findings as CSV, redacted the way the report is: one row
    per tracked item, each with its deadline, where it stands, and the decision
    that put it there."""
    r = redactor or Redactor(root)
    model = share_model(root, session, r, today)
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    rows: List[dict] = []
    for x in model["reviewer"]:
        rows.append(dict(x, finding=x["title"], where=x["target"], source="reviewer",
                         rule=x["id"], cve="", kev=False, kind="reviewer", runs=1,
                         reference=x["references"]))
    for x in model["scanner"]:
        rows.append(dict(x, finding=x["title"], kind="scanner"))
    for x in model["_image_rows"]:
        rows.append(dict(x, finding=x["title"], kind="image", runs=""))
    kinds = {"reviewer": 0, "scanner": 1, "image": 2}
    rows.sort(key=lambda row: (kinds.get(str(row["kind"]), 9),
                               rank.get(str(row["severity"]), 9)))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    for row in rows:
        cells = dict(row, id=row["finding_id"], kev="yes" if row["kev"] else "")
        w.writerow([_cell(cells.get(c, ""), c in CSV_KEEP_LINES) for c in CSV_COLUMNS])
    return buf.getvalue()


#: The browsers a PDF can be printed with, in the order they are looked for.
PDF_BROWSERS = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable")


def pdf_browser() -> Optional[str]:
    for name in PDF_BROWSERS:
        found = tool_path(name)
        if found:
            return found
    return None


def html_to_pdf(page: str, out_pdf: str, timeout: int = 120) -> Tuple[bool, str]:
    """Print a self-contained page to PDF with headless Chromium, in a profile
    of its own that is deleted after, with its background requests off. The
    page makes no request of its own. Returns (ok, what happened).

    Squawk stays standard-library: with no Chromium the answer is the reason,
    and the HTML is what to print instead. Never `--no-sandbox`: as root
    Chromium refuses to start without it, and that is refused here instead."""
    browser = pdf_browser()
    if not browser:
        return False, ("no headless Chromium or Chrome found (%s); open the HTML "
                       "version and print it to PDF" % ", ".join(PDF_BROWSERS))
    if running_as_root():
        return False, ("Chromium runs headless as root only with --no-sandbox, which "
                       "Squawk does not pass; make the PDF as your own user")
    work = tempfile.mkdtemp(prefix="squawk-pdf-")
    try:
        src = os.path.join(work, "report.html")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(page)
        argv = [browser, "--headless=new", "--disable-gpu", "--no-first-run",
                "--no-default-browser-check", "--disable-background-networking",
                "--disable-component-update", "--disable-sync", "--disable-extensions",
                "--user-data-dir=" + os.path.join(work, "profile"),
                "--no-pdf-header-footer", "--virtual-time-budget=10000",
                "--print-to-pdf=" + out_pdf, "file://" + src]
        code, _out, err = run_cmd(argv, None, timeout)
        try:
            with open(out_pdf, "rb") as fh:
                ok = fh.read(5) == b"%PDF-"
        except OSError:
            ok = False
        if not ok:
            if "No usable sandbox" in (err or ""):
                # Measured on GitHub's Ubuntu runner, 2026-10-23: Chrome is
                # installed and exits FATAL, because Ubuntu 23.10 and later
                # restrict the unprivileged user namespaces its sandbox needs.
                return False, ("Chromium found no usable sandbox on this machine "
                               "(Ubuntu 23.10 and later restrict the user "
                               "namespaces it needs), and Squawk does not pass "
                               "--no-sandbox; print the page to PDF from a browser")
            first = next((x.strip() for x in (err or "").splitlines() if x.strip()), "")
            return False, first[:200] or "the browser exited %d and wrote no PDF" % code
        return True, "%d bytes" % os.path.getsize(out_pdf)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def sessions_of(root: str) -> List[dict]:
    """Every session tag in the evidence root, newest first, with how many
    runs and notes carry it."""
    by: Dict[str, dict] = {}
    for man in list_runs(root):
        name = str(man.get("session") or "")
        if not name:
            continue
        e = by.setdefault(name, {"session": name, "runs": 0, "notes": 0, "ids": []})
        e["runs"] += 1
        e["notes"] += 1 if man.get("service") == "note" else 0
        e["ids"].append(str(man.get("run_id") or ""))
    out = []
    for e in by.values():
        ids = sorted(e.pop("ids"))
        e["first"], e["last"] = _when(ids[0]), _when(ids[-1])
        e["_last"] = ids[-1]
        out.append(e)
    out.sort(key=lambda e: e["_last"], reverse=True)
    for e in out:
        e.pop("_last")
    return out


def share_file_name(session: str, audience: str, ext: str) -> str:
    """The file a report is written to, or served as: the session, and the
    audience when it is the executive summary or the findings table."""
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", session).strip("-") or "report"
    if ext == "csv":
        return "%s-findings.csv" % stem
    return "%s%s.%s" % (stem, "-executive" if audience == "executive" else "", ext)


def write_share(root: str, session: str, out_dir: str, fmt: str = "both",
                verify: Optional[dict] = None,
                audience: str = "engineer") -> Tuple[List[str], dict]:
    """Write the shareable report into `out_dir`; return the paths and the model.

    Refuses an `out_dir` inside the evidence root: a report is not evidence, and
    a file appearing among sealed runs would read as tampering. A PDF that
    could not be made raises RuntimeError with the reason."""
    if fmt not in SHARE_FORMATS:
        raise ValueError("format must be one of %s" % ", ".join(SHARE_FORMATS))
    if audience not in AUDIENCES:
        raise ValueError("audience must be one of %s" % ", ".join(AUDIENCES))
    if audience == "executive" and fmt in ("md", "both"):
        raise ValueError("the executive summary is a page: use --format html or pdf")
    real_root = os.path.realpath(root)
    real_out = os.path.realpath(out_dir)
    if real_out == real_root or real_out.startswith(real_root + os.sep):
        raise ValueError("the report directory is inside the evidence root; a report "
                         "is not evidence, so write it somewhere else")
    model = share_model(root, session)
    os.makedirs(real_out, exist_ok=True)
    paths = []
    if fmt in ("md", "both"):
        paths.append(os.path.join(real_out, share_file_name(session, audience, "md")))
        with open(paths[-1], "w", encoding="utf-8") as fh:
            fh.write(share_markdown(model, verify))
    if fmt in ("html", "both"):
        paths.append(os.path.join(real_out, share_file_name(session, audience, "html")))
        with open(paths[-1], "w", encoding="utf-8") as fh:
            fh.write(share_html(model, verify, audience))
    if fmt == "csv":
        paths.append(os.path.join(real_out, share_file_name(session, audience, "csv")))
        with open(paths[-1], "w", encoding="utf-8", newline="") as fh:
            fh.write(share_csv(root, session))
    if fmt == "pdf":
        target = os.path.join(real_out, share_file_name(session, audience, "pdf"))
        ok, detail = html_to_pdf(share_html(model, verify, audience), target)
        if not ok:
            raise RuntimeError(detail)
        paths.append(target)
    return paths, model

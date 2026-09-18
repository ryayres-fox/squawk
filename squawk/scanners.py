"""Reading each scanner's output: report shapes, coverage extractors, and the normalizers."""

import json
import os
import re
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from squawk.core import NO_COVERAGE, Coverage, Finding, _rel, _report, _rows, norm_severity
from squawk.probes import AST10

# What a report from each scanner looks like when it is the report we think it
# is. One of these fields is present in any version of the format we can read.
#
# This exists because the likeliest long-term failure of this tool is not a
# scanner breaking, it is a scanner changing its output. Rename `Results` to
# `results` and the normalizer reads nothing, returns no findings, and the stage
# says "ok, 0 findings". The scanner ran, exited 0 and produced data; we simply
# could not understand a word of it, and reported that as a clean result.
#
# That is the failure this whole tool exists to prevent, sitting in the part of
# it most likely to drift, and it is the part a second user would hit first and
# never notice. An empty tuple means the report is a bare JSON list, where an
# empty list is a legitimate clean answer.
REPORT_SHAPES: Dict[str, Tuple[str, ...]] = {
    "gitleaks": (),
    "semgrep": ("results", "errors", "paths"),
    "bandit": ("results", "metrics", "errors"),
    "checkov": ("results", "summary", "check_type"),
    "trivy": ("Results", "SchemaVersion", "ArtifactName"),
    "syft": ("artifacts", "source", "descriptor"),
    "grype": ("matches", "descriptor", "source"),
    "zap": ("site", "@version", "@generated"),
    "awscli": ("Findings",),   # securityhub get-findings: one top-level key
    # The inventory writes its own report, so the shape is ours: what was
    # read, what could not be, and the resources themselves.
    "cloudinv": ("resources", "reads", "regions_enabled"),
    "cloudenable": ("regional", "account", "regions_enabled"),
    "cloudiam": ("users", "counts", "roles_with_escalation"),
    "cloudedge": ("regional", "regions_enabled", "account"),
    "cloudstore": ("buckets", "databases", "regions_enabled"),
    "cloudorg": ("accounts", "organization", "profiles_reaching"),
    "cloudfront": ("regional", "distributions", "regions_enabled"),
    "cloudcontain": ("regional", "regions_enabled", "account"),
    "clouddata": ("regional", "regions_enabled", "account"),
    "cloudanalyzer": ("regional", "regions_enabled", "account"),
}


def report_unreadable(tool: str, raw: str) -> Optional[str]:
    """Why this report could not be understood, or None if it could.

    Deliberately not a parse: it asks only whether the document is the shape a
    report from this tool has ever been. Getting that wrong in the strict
    direction would turn a working scan into a false alarm, so it accepts any
    one recognised field."""
    markers = REPORT_SHAPES.get(tool)
    if markers is None:
        return None                       # internal stage; the shape is ours
    text = (raw or "").strip()
    if not text:
        return None                       # emptiness is judged elsewhere
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return "the output is not JSON (%d bytes)" % len(text)
    if not markers:
        if isinstance(data, list):
            return None
        return "expected a JSON list, got %s" % type(data).__name__
    if isinstance(data, list):
        data = data[0] if data and isinstance(data[0], dict) else {}
    if not isinstance(data, dict):
        return "expected a JSON object, got %s" % type(data).__name__
    if any(k in data for k in markers):
        return None
    seen = ", ".join(sorted(data)[:4]) or "nothing"
    return ("no recognised field (expected one of %s; saw %s)"
            % ("/".join(markers), seen))


def _cov_semgrep(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    d = _report(raw, dict)
    paths = d.get("paths") if isinstance(d.get("paths"), dict) else {}
    scanned = paths.get("scanned")
    skipped = paths.get("skipped")
    n = len(scanned) if isinstance(scanned, list) else None
    note = "empty ruleset or nothing matched" if n == 0 else ""
    return Coverage(n, "files",
                    len(skipped) if isinstance(skipped, list) else 0,
                    len(d.get("errors") or []), note)


def _cov_bandit(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    d = _report(raw, dict)
    metrics = d.get("metrics") if isinstance(d.get("metrics"), dict) else {}
    files = [k for k in metrics if k != "_totals"]
    return Coverage(len(files) if metrics else None, "files", 0,
                    len(d.get("errors") or []),
                    "no files examined" if metrics and not files else "")


def _cov_checkov(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    total = None
    for block in _checkov_blocks(raw):
        summ = block.get("summary")
        if isinstance(summ, dict) and isinstance(summ.get("resource_count"), int):
            total = (total or 0) + summ["resource_count"]
    return Coverage(total, "resources", 0, 0,
                    "no resources parsed" if total == 0 else "")


def _cov_trivy(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    d = _report(raw, dict)
    results = d.get("Results")
    if not isinstance(results, list):
        # Real trivy OMITS the Results key when it found nothing to scan,
        # rather than emitting an empty list. Measured, not assumed. If the
        # document is recognisably a trivy report, an absent key means it
        # examined zero targets (the defect-1 case) and must gate, not pass.
        if isinstance(d, dict) and ("SchemaVersion" in d or "ArtifactName" in d):
            return Coverage(0, "scan targets", 0, 0, "no scannable target found")
        return NO_COVERAGE
    # Each Results block is one target trivy actually scanned (a lockfile, an
    # image layer, a config set). Zero blocks means it found nothing to scan,
    # which is a real "looked at nothing" rather than a clean result.
    targets = [r.get("Target") for r in results if isinstance(r, dict)]
    return Coverage(len(targets), "scan targets", 0, 0,
                    "no scannable target found" if not targets else "")


def _cov_syft(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    d = _report(raw, dict)
    arts = d.get("artifacts")
    n = len(arts) if isinstance(arts, list) else None
    return Coverage(n, "packages", 0, 0,
                    "empty SBOM — nothing catalogued" if n == 0 else "")


# Scanner -> how to read its coverage. A scanner absent from this map publishes
# no denominator we can read (gitleaks, grype, zap, the internal stages), and is
# reported as coverage-unknown rather than assumed to have examined nothing.
def _cov_asff(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """What a Security Hub read examined: every finding it pulled back, passed
    controls included. A response with no Findings key, or an empty one, is
    examined 0 and therefore a gap (I15): Security Hub may be off in the
    region, or the identity may not see it. Never a clean zero.

    The read is bounded, so this number is often a **floor**. The CLI returns
    a NextToken when the account holds more than was asked for, and that token
    is the proof: with it, the note says the count is a floor and names the
    setting that would raise it. A cap that is printed is a bound; a cap that
    is silent is a lie about coverage (I12)."""
    data = _report(raw, dict)
    rows = _rows(data.get("Findings"))
    passed = sum(1 for f in rows
                 if str((f.get("Compliance") or {}).get("Status", "")).upper() == "PASSED")
    notes = []
    if data.get("NextToken"):
        notes.append("a FLOOR, not a total — the account holds more than the "
                     "%d returned here; raise cloud_max_findings in a profile "
                     "to pull further" % len(rows))
    if passed:
        notes.append("%d passed control(s) not carried as findings" % passed)
    if not rows:
        # The gap message degenerates here and nowhere else. Every other tool
        # has a unit that differs from its findings -- "examined 0 packages",
        # "examined 0 scan targets" -- so the sentence tells a reader what was
        # missing. Security Hub's numerator and denominator are the same thing,
        # so it read "0 findings, but examined 0 findings", which is true and
        # says nothing. The note is where the three real explanations go.
        notes.append("Security Hub returned nothing: it may be off in this "
                     "region, have no standards enabled, or this identity may "
                     "not be allowed to see it — all three look identical here")
    return Coverage(len(rows), "findings", passed, 0, " · ".join(notes))


_ZAP_TOTAL_URLS = re.compile(r"^Total of (\d+) URLs", re.M)


def _cov_zap(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """How much of the app a DAST run reached.

    A crawl is the whole scan for a probe. Without a denominator, a run that
    reached three URLs and one that reached three hundred both print "ok N
    finding(s)", and the thin one reads as the thorough one. Measured against
    Juice Shop: a scan without the AJAX spider reached a handful of paths and
    found no injectable flaw on an app built to be full of them, and nothing on
    screen said the crawl had been thin.

    Two sources, in order of honesty. ZAP's scan scripts print `Total of N
    URLs` when the crawl ends: that is the tool's own count of what it
    reached, and it is the denominator, on a clean target as much as a dirty
    one. It arrives on stdout, which the engine keeps beside the report for
    exactly this. Without it — a report copied in from elsewhere, an older
    run — the distinct URLs the alerts were seen at are a floor, and a report
    with no alerts and no crawl line returns unknown, not zero: turning
    silence into examined=0 would fabricate a gap on a target that might be
    clean."""
    data = _report(raw, dict)
    urls = set()
    alerts = 0
    for site in _rows(data.get("site")):
        for alert in _rows(site.get("alerts")):
            alerts += 1
            for inst in _rows(alert.get("instances")):
                uri = str(inst.get("uri", "")).strip()
                if uri:
                    # Query values are not coverage: the same endpoint probed
                    # forty times is one endpoint the crawl reached.
                    urls.add(uri.split("?")[0])
    m = _ZAP_TOTAL_URLS.search(stdout or "")
    if m:
        n = int(m.group(1))
        note = "%d alert(s) across them" % alerts if alerts else \
            ("the crawl reached nothing" if n == 0 else "no alerts")
        return Coverage(n, "URLs", 0, 0, note)
    if not alerts:
        return Coverage(None, "URLs", 0, 0, "")
    return Coverage(len(urls), "URLs", 0, 0,
                    "%d alert(s) across them; a floor, from where alerts were "
                    "seen, not the crawl's own count" % alerts)


def _cov_cloudinv(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """What a cloud inventory read examined: resources, across regions.

    The unit matters, and it was wrong. `examined` counted RESOURCES, so an
    account with a region that answered every read and holds nothing in it
    examined zero and became a gap -- a tool that found nothing looking like a
    tool that did not run (review 2, R-20). It counts the READS that answered:
    this stage records `{status, count}` per read per region, so the
    distinguishing fact was already in the evidence.

    The note carries the denominator the whole cloud story hangs on: how many
    of the account's enabled regions were actually read. "No public instances"
    across three of seventeen regions is a different claim from "no public
    instances", and a count that does not say which one it is, is a silent
    cap (I12)."""
    data = _report(raw, dict)
    enabled = _rows_or_empty(data.get("regions_enabled"))
    read = _rows_or_empty(data.get("regions_read"))
    unread = _rows_or_empty(data.get("regions_unread"))
    examined = errors = found = 0
    for _region, per_read in (data.get("reads") or {}).items():
        if not isinstance(per_read, dict):
            continue
        for _key, row in per_read.items():
            if not isinstance(row, dict):
                continue
            if row.get("status") == "ok":
                examined += 1
                found += int(row.get("count") or 0)
            else:
                errors += 1
    notes = []
    if enabled:
        notes.append("%d of %d enabled region(s) read" % (len(read), len(enabled)))
    notes.append("%d resource(s) found" % found)
    if unread:
        notes.append("a FLOOR, not a total — %s never reached within the "
                     "budget; raise cloud_inventory_budget in a profile to "
                     "read further" % ", ".join(sorted(unread)[:6]))
    return Coverage(examined, "reads that answered", 0, errors,
                    " · ".join(notes))


def _rows_or_empty(value) -> List[str]:
    """A JSON list of strings, or nothing. A malformed inventory must not take
    the coverage calculation down with it."""
    if not isinstance(value, list):
        return []
    return [str(v) for v in value if isinstance(v, (str, int))]


def norm_cloudinv(raw: str, base: str) -> List[Finding]:
    """Turn one inventory read into findings by running the cloud graph rules.

    The rules live in `analysis` with the other correlation logic, and
    `analysis` imports this module — so the import is deferred to call time
    rather than moving reasoning into the normalizer layer where nobody would
    look for it. This is the one place the layering bends, and it bends here on
    purpose: the alternative is cloud rules in a file named `scanners`."""
    from squawk.analysis import cloud_findings, correlate_cloud
    data = _report(raw, dict)
    if not isinstance(data, dict) or not data.get("regions_read"):
        return []
    return cloud_findings(correlate_cloud(data))


def _cov_cloudenable(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """What an enablement read examined: service checks, across regions.

    The unit is checks rather than services, because "GuardDuty" is one
    question asked seventeen times and answering it once would hide the
    sixteen regions where the answer differs. A read that asked nothing is a
    gap, as ever."""
    data = _report(raw, dict)
    regional = data.get("regional") or {}
    examined, errors = 0, 0
    for _region, per in regional.items():
        if not isinstance(per, dict):
            continue
        for _key, row in per.items():
            if not isinstance(row, dict):
                continue
            examined += 1
            if row.get("state") == "unknown":
                errors += 1
    for _key, row in (data.get("account") or {}).items():
        if isinstance(row, dict):
            examined += 1
            if row.get("state") == "unknown":
                errors += 1
    enabled = data.get("regions_enabled") or []
    read = data.get("regions_read") or []
    unread = data.get("regions_unread") or []
    notes = []
    if enabled:
        notes.append("%d of %d enabled region(s) read" % (len(read), len(enabled)))
    if unread:
        notes.append("a FLOOR, not a total — %s never reached within the budget"
                     % ", ".join(sorted(str(u) for u in unread)[:6]))
    return Coverage(examined, "service checks", 0, errors, " · ".join(notes))


def norm_cloudenable(raw: str, base: str) -> List[Finding]:
    """An enablement read produces no findings of its own.

    Whether a service being off is a problem depends on whether anything is
    running there, and that answer lives in the inventory — so the judgement is
    made where both readings meet (`watching_gaps`), not here where only half
    the evidence is in scope. A normalizer that guessed would be inventing the
    half it cannot see."""
    return []


def _cov_cloudiam(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """What an IAM read examined: principals and policies.

    Principals, and deliberately not "reads that answered" like the regional
    stages. R-20's argument is that zero found must not read as zero examined
    -- and it holds wherever zero is an ordinary answer. It is not here: an AWS
    account with no users, no roles, no groups and no policies does not exist,
    because AWS creates service-linked roles itself. A graph read that returns
    nothing is a read that did not happen, and that is worth the gap.

    When the read was truncated the note says the count is a floor, the same as
    everywhere else."""
    data = _report(raw, dict)
    counts = data.get("counts") or {}
    found = sum(int(counts.get(k) or 0)
                for k in ("users", "roles", "groups", "policies"))
    examined = found
    unreadable = sum(1 for u in _rows(data.get("users")) if u.get("mfa") is None)
    notes = []
    if data.get("truncated"):
        notes.append("a FLOOR, not a total — the account holds more than the "
                     "%s principals read; raise cloud_max_principals in a "
                     "profile" % data.get("limit", "?"))
    if unreadable:
        notes.append("%d user(s) whose MFA or keys could not be read" % unreadable)
    return Coverage(examined, "principals and policies", 0, unreadable,
                    " · ".join(notes))


def norm_cloudiam(raw: str, base: str) -> List[Finding]:
    """Users whose credentials are not guarded become findings.

    The rules live in `analysis` with the rest of the reasoning, so the import
    is deferred exactly as it is for the cloud graph -- for the same reason and
    with the same trade recorded there."""
    from squawk.analysis import iam_findings, role_findings
    data = _report(raw, dict)
    if not isinstance(data, dict):
        return []
    out: List[Finding] = []
    for row in role_findings(data):
        ident = "iam:%s:%s" % (row["key"], row["role"])
        out.append(Finding(
            "cloudiam", ident, norm_severity(row["severity"]),
            "Role assumable from outside the account that can grant itself more"
            if row["key"] == "escalation-reachable-from-outside"
            else "Administrative role assumable from outside the account",
            "aws:iam:%s" % row["role"],
            {"what": "%s can be assumed by %s" % (row["role"], row["why"]),
             "remediation": row["fix"], "rule": row["key"],
             "members": [row["role"]], "escalation": row.get("escalation", [])}))
    for row in iam_findings(data):
        if row.get("state") != "fired":
            continue
        ident = "iam:%s:%s" % (row["key"], row["user"])
        out.append(Finding(
            "cloudiam", ident, norm_severity(row["severity"]),
            "IAM user without MFA"
            if row["key"] == "credential-without-mfa"
            else "IAM user without MFA that can grant itself more",
            "aws:iam:%s" % row["user"],
            {"what": row["why"], "remediation": row["fix"],
             "members": row.get("members", []), "rule": row["key"],
             "escalation": row.get("escalation", [])}))
    return out


# --------------------------------------------------------------------------- #
# What a cloud stage EXAMINED.
#
# Six extractors counted resources FOUND. `_apply_coverage` turns zero examined
# into `gap`, a gap makes the run incomplete, the incomplete run raises 7600,
# and `_cloud_reading` then refuses to render the panel. So an account with no
# containers -- nothing denied, every list call answered -- got "This reading
# is not available", an incomplete run and a lost-communications alarm, on
# every run, forever (review 2, R-20).
#
# The denominator is the READS THAT ANSWERED, not what they returned. A stage
# that reached seventeen regions and found nothing examined seventeen regions
# and found nothing, which is a result. A stage that reached none examined
# nothing, which is a gap. That distinction is the whole of I15, and counting
# resources could not make it.
#
# Plan 10 wrote "a read of zero resources is still a gap" before failed reads
# were recorded anywhere. Step 1 of plan 11 records them; the rule outlived
# the reason for it.
# --------------------------------------------------------------------------- #

def _regions_answered(data: dict) -> int:
    """How many regions this stage got an answer from, complete or partial."""
    names = set()
    for key in ("regions_read", "regions_partial"):
        for region in (data.get(key) or []):
            if isinstance(region, str):
                names.add(region)
    return len(names)


def _regional_errors(data: dict) -> int:
    return sum(len((per or {}).get("unreadable") or [])
               for per in (data.get("regional") or {}).values()
               if isinstance(per, dict))


def _region_notes(data: dict, found: str) -> List[str]:
    """The sentences every regional cloud stage shares."""
    enabled = data.get("regions_enabled") or []
    read = data.get("regions_read") or []
    partial = data.get("regions_partial") or []
    unread = data.get("regions_unread") or []
    notes = []
    if enabled:
        notes.append("%d of %d enabled region(s) read" % (len(read), len(enabled)))
    if partial:
        notes.append("%d entered and not finished" % len(partial))
    if found:
        notes.append(found)
    if unread:
        notes.append("%s never reached within the budget"
                     % ", ".join(sorted(str(u) for u in unread)[:6]))
    return notes


def function_count(per: dict) -> int:
    """How many functions one region holds, from either shape of reading.

    `functions` was a count before it became the list, so the tile could
    expand to its members. The reader was updated and this extractor was not:
    `int` of a non-empty list raises, `stage_coverage` swallows it, and the
    edge stage reported NO COVERAGE AT ALL on every populated account for
    fourteen commits (review 2, R-22). Both shapes read here, and a shape
    neither of them is reads as zero rather than as an exception -- a region
    that answered keeps its denominator either way (I15).

    `analysis.edge_function_count` is the same function for the page.
    `TestTheEdgeStageCoversBothShapes` holds the two to the same answer,
    because two copies drifting apart is what this finding was.
    """
    value = per.get("functions")
    if isinstance(value, list):
        return len(value)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _cov_cloudedge(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """What an edge read examined: the regions whose reads answered."""
    data = _report(raw, dict)
    found = 0
    for _region, per in (data.get("regional") or {}).items():
        if not isinstance(per, dict):
            continue
        found += function_count(per)
        found += len(_rows(per.get("load_balancers")))
    notes = _region_notes(data, "%d function(s) and load balancer(s) found" % found)
    if data.get("truncated"):
        notes.append("a FLOOR, not a total — more functions than the %s read; "
                     "raise cloud_max_functions in a profile" % data.get("limit"))
    return Coverage(_regions_answered(data), "regions read", 0,
                    _regional_errors(data), " · ".join(notes))


def norm_cloudedge(raw: str, base: str) -> List[Finding]:
    """Front doors become findings.

    Whether an internet-facing load balancer is dangerous depends on the
    security groups in front of it, and those live in the inventory read — so
    that half is judged in `analysis`, where both readings meet. What is
    decided here needs only this reading: a function URL with no authentication
    is a public HTTP endpoint whatever else is true."""
    from squawk.analysis import edge_findings
    data = _report(raw, dict)
    if not isinstance(data, dict):
        return []
    out: List[Finding] = []
    for row in edge_findings(data):
        ident = "edge:%s:%s" % (row["key"], row["resource"])
        out.append(Finding(
            "cloudedge", ident, norm_severity(row["severity"]), row["title"],
            "aws:%s" % row.get("region", ""),
            {"what": row["why"], "remediation": row["fix"],
             "members": row.get("members", []), "rule": row["key"]}))
    return out


def _cov_cloudstore(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """What a storage read examined: buckets and databases."""
    data = _report(raw, dict)
    buckets = _rows(data.get("buckets"))
    dbs = [d for per in (data.get("databases") or {}).values()
           if isinstance(per, dict) for d in _rows(per.get("databases"))]
    errors = sum(1 for b in buckets if b.get("unreadable"))
    errors += sum(len(per.get("unreadable") or [])
                  for per in (data.get("databases") or {}).values()
                  if isinstance(per, dict))
    total = int(data.get("bucket_total") or 0)
    notes = []
    if total and len(buckets) < total:
        notes.append("a FLOOR, not a total — %d of %d bucket(s) examined; "
                     "raise cloud_max_buckets in a profile"
                     % (len(buckets), total))
    if data.get("bucket_error"):
        notes.append("the bucket list could not be read")
    enabled = data.get("regions_enabled") or []
    read = data.get("regions_read") or []
    if enabled:
        notes.append("%d of %d enabled region(s) read for databases"
                     % (len(read), len(enabled)))
    notes.append("%d bucket(s) and %d database(s) found"
                 % (len(buckets), len(dbs)))
    # One global bucket list that answered, plus every region whose database
    # reads answered. Zero here means nothing answered at all.
    answered = (0 if data.get("bucket_error") else 1) + _regions_answered(data)
    return Coverage(answered, "reads that answered", 0, errors,
                    " · ".join(notes))


def norm_cloudstore(raw: str, base: str) -> List[Finding]:
    """Exposed buckets and databases become findings.

    Whether the account-wide S3 block is on was recorded by the reading
    itself, because it changes what a public bucket policy means and because a
    normalizer receives the scan base, not the run directory -- a lookup here
    would have silently found nothing."""
    from squawk.analysis import storage_findings
    data = _report(raw, dict)
    if not isinstance(data, dict):
        return []
    out: List[Finding] = []
    for row in storage_findings(data):
        ident = "storage:%s:%s" % (row["key"], row["resource"])
        out.append(Finding(
            "cloudstore", ident, norm_severity(row["severity"]), row["title"],
            "aws:%s" % row.get("region", ""),
            {"what": row["why"], "remediation": row["fix"],
             "members": row.get("members", []), "rule": row["key"]}))
    return out


def _cov_cloudorg(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """What an estate read examined: accounts.

    A standalone account examines one and that is the whole estate, so it is a
    real result rather than a gap. An organization read that came back empty
    means the account list could not be had, which is a gap: not knowing how
    many accounts exist is different from there being one."""
    data = _report(raw, dict)
    accounts = _rows(data.get("accounts"))
    # Reads that answered, the way the other cloud stages count (R-20).
    # Counting ACCOUNTS made a refused account list -- the ordinary
    # member-account run -- examine zero and become a gap, and the page's
    # card for exactly that case never rendered (review 3, R-37).
    if data.get("standalone"):
        return Coverage(1, "reads that answered", 0, 0,
                        "not part of an organization — this account is the "
                        "whole estate")
    if data.get("org_error"):
        return Coverage(0, "reads that answered", 0, 1,
                        "the organization could not be read (%s), so how much "
                        "of the estate this covers is unknown"
                        % data["org_error"])
    if data.get("accounts_error"):
        return Coverage(1, "reads that answered", 0, 1,
                        "the organization answered and its account list was "
                        "refused (%s), so how many accounts it holds is "
                        "unknown" % data["accounts_error"])
    active = sum(1 for a in accounts
                 if str(a.get("status", "")).upper() == "ACTIVE")
    return Coverage(2, "reads that answered", 0, 0,
                    "this run read 1 of %d active account(s)" % active
                    if accounts else "the account list came back empty")


def norm_cloudorg(raw: str, base: str) -> List[Finding]:
    """A run that covers a fraction of an organization says so as a finding.

    Filed at `info`, because it is not a weakness in the estate -- it is a
    statement about this reading, and it belongs where the reader will see it
    rather than only in a caveat."""
    from squawk.analysis import org_findings
    data = _report(raw, dict)
    if not isinstance(data, dict):
        return []
    out: List[Finding] = []
    for row in org_findings(data):
        out.append(Finding(
            "cloudorg", "org:%s:%s" % (row["key"], row["resource"]),
            norm_severity(row["severity"]), row["title"], "aws:organization",
            {"what": row["why"], "remediation": row["fix"],
             "members": row.get("members", []), "rule": row["key"]}))
    return out


def _cov_cloudfront(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """What a front-door read examined: APIs and distributions."""
    data = _report(raw, dict)
    apis = sum(len(_rows((per or {}).get("apis")))
               for per in (data.get("regional") or {}).values()
               if isinstance(per, dict))
    dists = len(_rows(data.get("distributions")))
    errors = sum(len((per or {}).get("unreadable") or [])
                 for per in (data.get("regional") or {}).values()
                 if isinstance(per, dict))
    if data.get("distribution_error"):
        errors += 1
    enabled = data.get("regions_enabled") or []
    read = data.get("regions_read") or []
    unread = data.get("regions_unread") or []
    notes = []
    if enabled:
        notes.append("%d of %d enabled region(s) read" % (len(read), len(enabled)))
    if unread:
        notes.append("%s never reached within the budget"
                     % ", ".join(sorted(str(u) for u in unread)[:6]))
    notes.append("%d API(s) and %d distribution(s) found" % (apis, dists))
    answered = (0 if data.get("distribution_error") else 1) \
        + _regions_answered(data)
    return Coverage(answered, "reads that answered", 0, errors,
                    " · ".join(notes))


def norm_cloudfront(raw: str, base: str) -> List[Finding]:
    """Front doors become findings."""
    from squawk.analysis import frontdoor_findings
    data = _report(raw, dict)
    if not isinstance(data, dict):
        return []
    out: List[Finding] = []
    for row in frontdoor_findings(data):
        ident = "frontdoor:%s:%s" % (row["key"], row["resource"])
        out.append(Finding(
            "cloudfront", ident, norm_severity(row["severity"]), row["title"],
            "aws:%s" % row.get("region", ""),
            {"what": row["why"], "remediation": row["fix"],
             "members": row.get("members", []), "rule": row["key"]}))
    return out


def _cov_cloudcontain(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """What a container read examined: clusters and services."""
    data = _report(raw, dict)
    examined = errors = 0
    for _region, per in (data.get("regional") or {}).items():
        if not isinstance(per, dict):
            continue
        examined += len(_rows(per.get("eks"))) + len(_rows(per.get("ecs")))
        errors += len(per.get("unreadable") or [])
    enabled = data.get("regions_enabled") or []
    read = data.get("regions_read") or []
    notes = []
    if enabled:
        notes.append("%d of %d enabled region(s) read" % (len(read), len(enabled)))
    if data.get("truncated"):
        notes.append("a FLOOR, not a total — more clusters or services than "
                     "the %s examined in at least one region; raise "
                     "cloud_max_items in a profile" % data.get("limit"))
    notes.append("%d cluster(s) and service(s) found" % examined)
    return Coverage(_regions_answered(data), "regions read", 0, errors,
                    " · ".join(notes))


def _cov_clouddata(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """What a data-services read examined: topics, queues, secrets, repos."""
    data = _report(raw, dict)
    examined = errors = 0
    for _region, per in (data.get("regional") or {}).items():
        if not isinstance(per, dict):
            continue
        for key in ("topics", "queues", "secrets", "repositories"):
            examined += len(_rows(per.get(key)))
        errors += len(per.get("unreadable") or [])
    enabled = data.get("regions_enabled") or []
    read = data.get("regions_read") or []
    notes = []
    if enabled:
        notes.append("%d of %d enabled region(s) read" % (len(read), len(enabled)))
    if data.get("truncated"):
        notes.append("a FLOOR, not a total — more items than the %s examined "
                     "in at least one region; raise cloud_max_items in a "
                     "profile" % data.get("limit"))
    notes.append("%d topic(s), queue(s), secret(s) and repository(ies) found"
                 % examined)
    return Coverage(_regions_answered(data), "regions read", 0, errors,
                    " · ".join(notes))


def _cov_cloudanalyzer(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """What the analyzer read examined: analyzers, and their findings.

    The denominator is ANALYZERS, not findings. Zero findings from an active
    analyzer is a real negative -- AWS looked and found nothing outside the
    zone of trust -- while zero findings from zero analyzers is a question
    nobody asked, and the two must not read the same (I15)."""
    data = _report(raw, dict)
    examined = errors = 0
    for _region, per in (data.get("regional") or {}).items():
        if not isinstance(per, dict):
            continue
        examined += len(_rows(per.get("analyzers")))
        errors += len(per.get("unreadable") or [])
    enabled = data.get("regions_enabled") or []
    read = data.get("regions_read") or []
    notes = []
    if enabled:
        notes.append("%d of %d enabled region(s) read" % (len(read), len(enabled)))
    if not examined:
        notes.append("no active analyzer in any region read, so AWS has not "
                     "been asked this question at all — the hand-rolled "
                     "readers are the only answer on this page")
    if data.get("truncated"):
        notes.append("a FLOOR, not a total — an analyzer returned more "
                     "findings than the %d examined; raise cloud_max_items"
                     % (data.get("limit") or 0))
    notes.append("%d active external-access analyzer(s) found" % examined)
    # The regions whose list-analyzers answered. An account with no analyzer is
    # a real answer -- AWS has not been asked, which the note says -- and not a
    # gap that makes every run incomplete forever (review 2, R-20).
    return Coverage(examined=_regions_answered(data), unit="regions read",
                    skipped=0, errors=errors, note=" · ".join(notes))


def norm_cloudanalyzer(raw: str, base: str) -> List[Finding]:
    """AWS's own answer about external access becomes findings.

    Severity comes from the scale: a resource Access Analyzer calls PUBLIC is
    reachable by anyone, with whatever the resource's own authentication is as
    the guard left, which is `high`. One it calls external -- reachable by a
    named account or organization outside the zone of trust -- is `medium`,
    the same weight a `*` narrowed by an account key gets from the
    hand-rolled reader."""
    from squawk.analysis import analyzer_findings
    data = _report(raw, dict)
    if not isinstance(data, dict):
        return []
    out: List[Finding] = []
    for row in analyzer_findings(data):
        ident = "analyzer:%s:%s" % (row["key"], row["resource"])
        out.append(Finding(
            "cloudanalyzer", ident, norm_severity(row["severity"]), row["title"],
            "aws:%s" % row.get("region", ""),
            {"what": row["why"], "remediation": row["fix"],
             "members": row.get("members", []), "rule": row["key"]}))
    return out


def norm_cloudcontain(raw: str, base: str) -> List[Finding]:
    """Clusters and services the internet can reach become findings.

    Whether an ECS service that asks for a public address actually gets a
    routable one depends on its subnets, which live in the inventory reading —
    so that half is judged on the page where both are in scope. Judged here
    alone, the rule is stricter, which is the right way round for a missing
    input."""
    from squawk.analysis import container_findings
    data = _report(raw, dict)
    if not isinstance(data, dict):
        return []
    out: List[Finding] = []
    for row in container_findings(data):
        ident = "containers:%s:%s" % (row["key"], row["resource"])
        out.append(Finding(
            "cloudcontain", ident, norm_severity(row["severity"]), row["title"],
            "aws:%s" % row.get("region", ""),
            {"what": row["why"], "remediation": row["fix"],
             "members": row.get("members", []), "rule": row["key"]}))
    return out


def norm_clouddata(raw: str, base: str) -> List[Finding]:
    """Topics, queues and repositories anyone can use become findings."""
    from squawk.analysis import dataservice_findings
    data = _report(raw, dict)
    if not isinstance(data, dict):
        return []
    out: List[Finding] = []
    for row in dataservice_findings(data):
        ident = "data:%s:%s" % (row["key"], row["resource"])
        out.append(Finding(
            "clouddata", ident, norm_severity(row["severity"]), row["title"],
            "aws:%s" % row.get("region", ""),
            {"what": row["why"], "remediation": row["fix"],
             "members": row.get("members", []), "rule": row["key"]}))
    return out


# gitleaks says what it read on STDERR -- its report goes to stdout, so that is
# the only place the number is. Both lines are real output, captured from
# gitleaks 8.30.1 rather than guessed:
#
#     INF 314 commits scanned.
#     INF scanned ~7944170 bytes (7.94 MB) in 511ms
#
# `--no-git` prints only the second. A directory that is not a repository,
# scanned in repo scope, prints "0 commits scanned." and "scanned ~0 bytes" --
# which is the case that matters, because until now it read as 0 finding(s) and
# "No squawk. Nothing critical." on a real repository (the operator, 2026-09-12).
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_GITLEAKS_BYTES = re.compile(r"scanned ~(\d+) bytes")
_GITLEAKS_COMMITS = re.compile(r"(\d+) commits scanned")


def _cov_gitleaks(raw: str = "", stdout: str = "",
                  stderr: str = "") -> Coverage:
    """How much gitleaks actually read, in bytes, and over how many commits."""
    text = _ANSI.sub("", stderr or "")
    size = _GITLEAKS_BYTES.search(text)
    if not size:
        # Said nothing about what it read: unknown, not zero. Inventing a
        # denominator is the fabrication this refuses everywhere else.
        return NO_COVERAGE
    scanned = int(size.group(1))
    commits = _GITLEAKS_COMMITS.search(text)
    notes = []
    if commits:
        notes.append("%s commit(s) of history" % commits.group(1))
    if not scanned:
        # "a directory that is not a repository scanned in repo scope" was one
        # of the two explanations here, and it was the one that kept happening.
        # `stage_gitleaks` now decides on `.git` rather than on the scope
        # label, so that cause is gone and naming it would send a reader after
        # a thing that can no longer be true. What is left is what is left.
        notes.append("nothing was read — an empty tree, a repository with no "
                     "commits, or everything in it was excluded")
    return Coverage(scanned, "bytes", 0, 0, " · ".join(notes))


def _cov_skillaudit(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """How many agent skills the audit read.

    It publishes `scanned` and nothing read it, so a run over a directory with
    no SKILL.md at all reported `ok` with 0 findings and the page printed "No
    squawk. Nothing critical." -- a zero over an empty denominator, which is
    the substitution I15 exists to refuse. Found by running the service, which
    nobody had.
    """
    data = _report(raw, dict)
    scanned = data.get("scanned")
    if not isinstance(scanned, int):
        return NO_COVERAGE
    return Coverage(scanned, "skills", 0, 0,
                    "no SKILL.md or MCP config was found here, so nothing was "
                    "audited" if not scanned else "")


def _cov_selfaudit(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """How many instrument checks answered.

    The three states are the point: `unknown` is a check that ran and could not
    tell, and it is neither a pass nor a failure. It is reported as an error in
    the coverage so a reader sees the run is not a full answer.
    """
    data = _report(raw, dict)
    checks = _rows(data.get("checks"))
    if not checks:
        return NO_COVERAGE
    counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
    unknown = counts.get("unknown")
    return Coverage(len(checks), "checks", 0,
                    unknown if isinstance(unknown, int) else 0,
                    "%d check(s) ran and could not tell" % unknown
                    if isinstance(unknown, int) and unknown else "")


def _cov_recon(raw: str, stdout: str = "", stderr: str = "") -> Coverage:
    """How much of the host recon actually got an answer from.

    Discovery has the same silence problem as every other scanner and had no
    coverage entry at all, so "7 endpoint(s)" and "0 endpoint(s)" both arrived
    with no statement of how much was asked. The denominator is the HTTP probes
    that answered, over the probes attempted -- a host that dropped every
    request and a host with no web app running look identical from outside, and
    the numbers are what let a reader tell them apart.
    """
    data = _report(raw, dict)
    tried = data.get("requests")
    answered = data.get("requests_answered")
    if not isinstance(tried, int) or not isinstance(answered, int):
        return NO_COVERAGE            # an older reading, without the counts
    ports = data.get("ports_probed")
    listed = data.get("open_ports")
    note = ""
    if isinstance(ports, int) and ports:
        note = "%d of %d port(s) answered" % (
            len(listed) if isinstance(listed, list) else 0, ports)
    # Probes that were sent and not answered are said in the note, not put
    # in the `skipped` slot -- which prints as "(N skipped)" and, for the
    # Security Hub extractor, means passed controls not carried. Nothing was
    # skipped; the host dropped them (review 3, R-50).
    dropped = max(0, tried - answered)
    if dropped:
        note = "%s%s%d probe(s) sent and not answered" % (
            note, " · " if note else "", dropped)
    return Coverage(answered, "probe(s) answered", 0, 0, note)


COVERAGE: Dict[str, Callable[..., Coverage]] = {
    "gitleaks": _cov_gitleaks,
    "recon": _cov_recon,
    "selfaudit": _cov_selfaudit,
    "skillaudit": _cov_skillaudit,
    "zap": _cov_zap,
    "awscli": _cov_asff,
    "cloudinv": _cov_cloudinv,
    "cloudenable": _cov_cloudenable,
    "cloudiam": _cov_cloudiam,
    "cloudedge": _cov_cloudedge,
    "cloudstore": _cov_cloudstore,
    "cloudorg": _cov_cloudorg,
    "cloudfront": _cov_cloudfront,
    "cloudcontain": _cov_cloudcontain,
    "cloudanalyzer": _cov_cloudanalyzer,
    "clouddata": _cov_clouddata,
    "semgrep": _cov_semgrep,
    "bandit": _cov_bandit,
    "checkov": _cov_checkov,
    "trivy": _cov_trivy,
    "syft": _cov_syft,
}


def _checkov_blocks(raw: str) -> List[dict]:
    """checkov's report is a single dict on a single-framework tree and a LIST
    of dicts (one per framework) on a mixed one. Both are valid, so it must be
    read as either.

    This is separate from `_report` on purpose: `_report` is shape-strict by
    design (a scanner that changed its shape should degrade, not be quietly
    accepted), and applying it here with `dict` threw away every list-form
    report — checkov found 477 issues on a repo and Squawk showed zero, because
    the whole list was discarded before the block loop ran. Found by pointing
    the tool at TerraGoat, not by a fixture."""
    try:
        data = json.loads(raw) if raw and raw.strip() else []
    except (json.JSONDecodeError, ValueError):
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [b for b in data if isinstance(b, dict)]
    return []


def stage_coverage(tool: str, raw: str, stdout: str = "",
                   stderr: str = "") -> Coverage:
    """What a stage examined, from its report and -- for a tool that says so
    nowhere else -- from what it printed.

    Three sources because tools differ and none of them can be argued with:
    ZAP prints its crawl total on stdout, gitleaks prints what it scanned on
    stderr, and the rest put it in the report. Never raises."""
    fn = COVERAGE.get(tool)
    if fn is None:
        return NO_COVERAGE
    try:
        return fn(raw, stdout, stderr)
    except Exception:
        return NO_COVERAGE


def norm_gitleaks(raw: str, base: str) -> List[Finding]:
    out: List[Finding] = []
    for f in _rows(_report(raw, list)):
        rule = f.get("RuleID") or f.get("Rule") or "secret"
        rel = _rel(f.get("File", ""), base)
        fp = f.get("Fingerprint") or "%s:%s:%s" % (rule, rel, f.get("StartLine", ""))
        out.append(Finding("gitleaks", fp, "high",
                           "secret: %s" % rule, rel))
    return out


# Semgrep redacts the matched source line to a placeholder when the scan is not
# authenticated (no `semgrep login`). Storing that placeholder makes every
# finding read "evidence: requires login", which is worse than no evidence — it
# looks like a real matched line and is identical across unrelated findings.
_REDACTED_EVIDENCE = ("requires login", "requires semgrep login")


def _real_evidence(s: Optional[str]) -> str:
    """The evidence string, or empty if it is a scanner's redaction placeholder.
    The finding's path and line still locate it; a redaction stand-in must not
    pose as the matched code."""
    s = (s or "").strip()
    return "" if s.lower() in _REDACTED_EVIDENCE else s


def _source_line(base: Optional[str], rel: str, line, context: int = 0) -> str:
    """The offending source line from the scanned file, read at scan time while
    the target is on disk, so a finding can show the code that triggered it even
    when the scanner redacts its own snippet (semgrep does, unauthenticated).
    Read-only and best-effort: a missing file or an out-of-range line yields
    nothing rather than a guess."""
    try:
        n = int(line)
    except (TypeError, ValueError):
        return ""
    if n < 1 or not rel:
        return ""
    try:
        with open(os.path.join(base or "", rel), encoding="utf-8",
                  errors="replace") as fh:
            lines = fh.readlines()
    except (OSError, ValueError):
        return ""
    if n > len(lines):
        return ""
    lo, hi = max(0, n - 1 - context), min(len(lines), n + context)
    return "".join(lines[lo:hi]).rstrip("\n")[:400]


def _title(s: Optional[str], limit: int = 120) -> str:
    """A finding title trimmed to length at a word boundary, with an ellipsis
    when cut, so a truncated title reads as deliberate rather than as a string
    that broke off mid-word."""
    s = " ".join((s or "").split())
    if len(s) <= limit:
        return s
    cut = s[:limit].rsplit(" ", 1)[0]
    return (cut or s[:limit]).rstrip() + "…"


def norm_semgrep(raw: str, base: str) -> List[Finding]:
    out: List[Finding] = []
    data = _report(raw, dict)
    for r in _rows(data.get("results")):
        check = r.get("check_id", "rule")
        rel = _rel(r.get("path", ""), base)
        line = (r.get("start") or {}).get("line", "")
        sev = norm_severity((r.get("extra") or {}).get("severity"))
        ident = "%s:%s:%s" % (check, rel, line)
        msg = _title((r.get("extra") or {}).get("message") or check)
        extra = r.get("extra") or {}
        # Semgrep redacts the matched line when unauthenticated. Rather than send
        # the operator to a semgrep account (nothing here needs one), read the
        # offending line from the file we just scanned.
        ev = _real_evidence(extra.get("lines")) or _source_line(base, rel, line)
        out.append(Finding("semgrep", ident, sev, msg, rel,
                           {"description": msg,
                            "remediation": extra.get("fix") or "",
                            "reference": (extra.get("metadata") or {}).get("source", ""),
                            "rule": check, "line": line,
                            "evidence": ev[:400]}))
    return out


def norm_bandit(raw: str, base: str) -> List[Finding]:
    out: List[Finding] = []
    data = _report(raw, dict)
    for r in _rows(data.get("results")):
        test = r.get("test_id", "B000")
        rel = _rel(r.get("filename", ""), base)
        line = r.get("line_number", "")
        sev = norm_severity(r.get("issue_severity"))
        ident = "%s:%s:%s" % (test, rel, line)
        cwe = r.get("issue_cwe") or {}
        out.append(Finding("bandit", ident, sev,
                           _title(r.get("issue_text") or test), rel,
                           {"description": r.get("issue_text") or "",
                            "evidence": (r.get("code") or "").strip()[:400],
                            "reference": r.get("more_info") or "",
                            "cwe": str(cwe.get("id") or ""),
                            "confidence": r.get("issue_confidence") or "",
                            "rule": test, "line": line}))
    return out


def norm_checkov(raw: str, base: str) -> List[Finding]:
    out: List[Finding] = []
    for block in _checkov_blocks(raw):
        results = block.get("results") if isinstance(block, dict) else None
        if not isinstance(results, dict):
            continue
        for r in _rows(results.get("failed_checks")):
            cid = r.get("check_id", "CKV")
            # checkov reports file_path as "/terraform/x.tf" — relative to the
            # scanned directory, with a leading slash, NOT filesystem-absolute.
            # Passed straight to _rel it looked absolute and came back as
            # "../../../../terraform/x.tf", whose ../ depth depends on where the
            # evidence root sits — so the same finding got a different identity
            # on a different machine, breaking portable identity (I5). Strip the
            # leading slash and it is already repo-relative. Found on TerraGoat.
            raw_path = (r.get("file_path") or "").lstrip("/")
            rel = _rel(raw_path, base)
            resource = r.get("resource", "")
            ident = "%s:%s:%s" % (cid, rel, resource)
            # checkov ships the offending block as [[lineno, text], ...] and a
            # guideline URL. Both were dropped, leaving the finding with no why.
            code = ""
            cb = r.get("code_block")
            if isinstance(cb, list):
                for pair in cb:
                    if isinstance(pair, (list, tuple)) and len(pair) > 1:
                        code += str(pair[1])
            desc = (r.get("description") or r.get("short_description")
                    or r.get("check_name") or "")
            out.append(Finding("checkov", ident, "medium",
                               _title(r.get("check_name") or cid), rel,
                               {"description": desc,
                                "evidence": code.strip()[:400],
                                "reference": r.get("guideline") or "",
                                "rule": cid}))
    return out


def _trivy_findings(raw: str, base: str) -> List[Finding]:
    out: List[Finding] = []
    data = _report(raw, dict)
    for res in _rows(data.get("Results")):
        target = res.get("Target", "")
        for v in _rows(res.get("Vulnerabilities")):
            vid = v.get("VulnerabilityID", "CVE")
            pkg = v.get("PkgName", "")
            ver = v.get("InstalledVersion", "")
            sev = norm_severity(v.get("Severity"))
            ident = "%s:%s:%s" % (vid, pkg, ver)
            out.append(Finding("trivy", ident, sev,
                               "%s in %s %s" % (vid, pkg, ver),
                               _rel(target, base)))
        for m in _rows(res.get("Misconfigurations")):
            mid = m.get("ID", "MISC")
            sev = norm_severity(m.get("Severity"))
            ident = "%s:%s" % (mid, _rel(target, base))
            out.append(Finding("trivy", ident, sev,
                               _title(m.get("Title") or mid), _rel(target, base)))
        for s in _rows(res.get("Secrets")):
            rid = s.get("RuleID", "secret")
            ident = "%s:%s:%s" % (rid, _rel(target, base), s.get("StartLine", ""))
            out.append(Finding("trivy", ident, "high",
                               "secret: %s" % rid, _rel(target, base)))
    return out


def norm_trivy(raw: str, base: str) -> List[Finding]:
    return _trivy_findings(raw, base)


def norm_syft(raw: str, base: str) -> List[Finding]:
    # syft produces an inventory, not findings. We surface component count as
    # zero findings but keep the SBOM as evidence for grype to read.
    return []


def norm_grype(raw: str, base: str) -> List[Finding]:
    out: List[Finding] = []
    data = _report(raw, dict)
    for m in _rows(data.get("matches")):
        vuln = (m.get("vulnerability") or {})
        art = (m.get("artifact") or {})
        vid = vuln.get("id", "CVE")
        pkg = art.get("name", "")
        ver = art.get("version", "")
        sev = norm_severity(vuln.get("severity"))
        ident = "%s:%s:%s" % (vid, pkg, ver)
        fix = vuln.get("fix") or {}
        fixed_in = ", ".join(fix.get("versions") or [])
        out.append(Finding("grype", ident, sev,
                           "%s in %s %s" % (vid, pkg, ver), pkg,
                           {"description": vuln.get("description", ""),
                            "remediation": ("Upgrade %s to %s" % (pkg, fixed_in)
                                            if fixed_in else
                                            "No fixed version published yet"),
                            "reference": " ".join((vuln.get("urls") or [])[:3]),
                            "package": pkg, "installed": ver,
                            "fixed_in": fixed_in, "state": fix.get("state", "")}))
    return out


def norm_recon(raw: str, base: str) -> List[Finding]:
    """Discovered endpoints become info-level findings; each is a launchable
    DAST target. Identity strips the host (port + path) so the same app on a
    reverted snapshot IP stays the same row."""
    out: List[Finding] = []
    data = _report(raw, dict)
    for e in _rows(data.get("endpoints")):
        parsed = urlparse(e["url"])
        ident = "%s:%s" % (parsed.port or "", parsed.path or "/")
        label = e.get("app") or (e.get("title") or "web endpoint")
        title = "%s — HTTP %s%s" % (label, e.get("status", "?"),
                                    " · " + e["server"] if e.get("server") else "")
        out.append(Finding("recon", ident, "info", title, e["url"]))
    # A catch-all port is reported once, so the reader knows why the labeled
    # sub-paths are absent: they answered, with the same page as everything.
    for port, info in sorted((data.get("catch_all") or {}).items()):
        out.append(Finding("recon", "%s:catch-all" % port, "info",
                           "catch-all — every path on :%s answers HTTP %s with the "
                           "same page, so a path here is not an app"
                           % (port, info.get("status", "?")),
                           info.get("url", "")))
    return out


def norm_skillaudit(raw: str, base: str) -> List[Finding]:
    out: List[Finding] = []
    data = _report(raw, dict)
    for f in _rows(data.get("findings")):
        ast = f.get("ast", "AST00")
        name, sev = AST10.get(ast, ("Unknown", "info"))
        ident = "%s:%s:%s" % (ast, f.get("path", ""), f.get("marker", ""))
        title = "%s %s — %s" % (ast, name, f.get("detail", ""))
        out.append(Finding("skillaudit", ident, sev, title, f.get("path", "")))
    return out


def norm_selfaudit(raw: str, base: str) -> List[Finding]:
    """Only non-ok checks become findings. An "unknown" is reported as a finding
    too, at a lower severity: not knowing is a smaller problem than a confirmed
    gap, and a larger one than a pass."""
    out: List[Finding] = []
    data = _report(raw, dict)
    for c in _rows(data.get("checks")):
        if c.get("status") == "ok":
            continue
        unknown = c.get("status") == "unknown"
        title = c.get("title", "")
        if unknown:
            title = "Not determined — %s" % title
        out.append(Finding(
            "selfaudit", "selfaudit:%s" % c.get("check", "?"),
            norm_severity(c.get("severity")), title,
            "host:%s" % c.get("area", "host"),
            {"what": c.get("detail", ""), "remediation": c.get("fix", ""),
             "area": c.get("area", ""), "status": c.get("status", "")}))
    return out


_ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
_ZAP_CONF = {"3": "high", "2": "medium", "1": "low", "0": "false positive"}


def _text(html_ish):
    """ZAP ships description/solution/reference as HTML fragments. Strip the
    tags at parse time so stored evidence is prose, and let the renderer escape
    it once."""
    if not html_ish:
        return ""
    txt = re.sub(r"<br\s*/?>|</p>", "\n", str(html_ish))
    txt = re.sub(r"<[^>]+>", "", txt)
    for a, b in (("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&"), ("&quot;", chr(34))):
        txt = txt.replace(a, b)
    return re.sub(r"\n{3,}", "\n\n", txt).strip()


def norm_zap(raw: str, base: str) -> List[Finding]:
    """OWASP ZAP baseline JSON -> Findings. The identity key uses the request
    PATH and parameter, NOT the host — a target VM served at a different
    snapshot IP must diff as the same finding, not as total churn."""
    out: List[Finding] = []
    data = _report(raw, dict)
    for site in _rows(data.get("site")):
        for alert in _rows(site.get("alerts")):
            plugin = alert.get("pluginid", "0")
            sev = _ZAP_RISK.get(str(alert.get("riskcode", "0")), "info")
            name = _title(alert.get("alert") or alert.get("name") or "alert")
            instances = alert.get("instances") or [{}]
            for inst in instances:
                uri = inst.get("uri", "")
                path = urlparse(uri).path or "/"
                param = inst.get("param", "")
                ident = "%s:%s:%s" % (plugin, path, param)
                det = {"description": _text(alert.get("desc")),
                       "remediation": _text(alert.get("solution")),
                       "reference": _text(alert.get("reference")),
                       "cwe": str(alert.get("cweid") or "").strip(),
                       "wasc": str(alert.get("wascid") or "").strip(),
                       "confidence": _ZAP_CONF.get(
                           str(alert.get("confidence", "")), ""),
                       "risk": alert.get("riskdesc", ""),
                       "method": inst.get("method", ""), "param": param,
                       "evidence": (inst.get("evidence") or "")[:400],
                       "attack": (inst.get("attack") or "")[:200],
                       "other": _text(inst.get("otherinfo"))[:400]}
                out.append(Finding("zap", ident, sev, name, path, det))
    return out


_ASFF_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
             "LOW": "low", "INFORMATIONAL": "info"}


def norm_asff(raw: str, base: str) -> List[Finding]:
    """AWS Security Finding Format (Security Hub get-findings) -> Findings.
    Identity is control id : account : resource id, with no timestamps and no
    session values (credential rule 6), so a cloud finding diffs across
    rescans like a code finding. Passed controls are not findings; they are
    counted in coverage instead."""
    out: List[Finding] = []
    data = _report(raw, dict)
    for f in _rows(data.get("Findings")):
        comp = f.get("Compliance") or {}
        if str(comp.get("Status", "")).upper() == "PASSED":
            continue
        control = str(comp.get("SecurityControlId") or
                      str(f.get("GeneratorId", "")).rsplit("/", 1)[-1] or "finding")
        account = str(f.get("AwsAccountId", ""))
        resources = _rows(f.get("Resources"))
        res_id = str(resources[0].get("Id", "")) if resources else ""
        res_type = str(resources[0].get("Type", "")) if resources else ""
        label = str((f.get("Severity") or {}).get("Label", "")).upper()
        sev = _ASFF_SEV.get(label) or norm_severity(label)
        rec = (f.get("Remediation") or {}).get("Recommendation") or {}
        ident = "%s:%s:%s" % (control, account, res_id)
        out.append(Finding(
            "awscli", ident, sev, _title(f.get("Title") or control), res_id or account,
            {"description": str(f.get("Description", "")),
             "remediation": str(rec.get("Text", "")),
             "reference": str(rec.get("Url", "")),
             "rule": control, "region": str(f.get("Region", "")),
             "resource_type": res_type, "product": str(f.get("ProductName", "")),
             "status": str(comp.get("Status", "")),
             "resources": len(resources)}))
    return out


def rule_of(finding: dict) -> str:
    """The advisory a finding belongs to, which is what every view groups by.

    Most scanners put the rule first in the identity: `CKV_AWS_1:path`,
    `rule-id:path:line`, `10038:/path:param`. So the first segment is the
    group, and that is what Findings and Triage used.

    The self-audit is the exception. Its identity is `selfaudit:<check>`, so
    the first segment is the scanner's own name, a constant, and grouping on it
    collapsed every host check into a single row titled after whichever
    happened to come first: four different findings, one heading, three of them
    invisible. The general rule that fixes it without touching any identity —
    identities are the stable key and changing one to fix a display would make
    every existing finding look new — is that a first segment equal to the
    scanner's name is a prefix, not a rule.
    """
    ident = str(finding.get("identity", ""))
    parts = ident.split(":")
    scanner = str(finding.get("scanner", ""))
    if len(parts) > 1 and parts[0] == scanner and parts[1]:
        return parts[1]
    return parts[0] or ident


NORMALIZERS: Dict[str, Callable[[str, str], List[Finding]]] = {
    "awscli": norm_asff,
    "cloudinv": norm_cloudinv,
    "cloudenable": norm_cloudenable,
    "cloudiam": norm_cloudiam,
    "cloudedge": norm_cloudedge,
    "cloudstore": norm_cloudstore,
    "cloudorg": norm_cloudorg,
    "cloudfront": norm_cloudfront,
    "cloudcontain": norm_cloudcontain,
    "cloudanalyzer": norm_cloudanalyzer,
    "clouddata": norm_clouddata,
    "gitleaks": norm_gitleaks,
    "semgrep": norm_semgrep,
    "bandit": norm_bandit,
    "checkov": norm_checkov,
    "trivy": norm_trivy,
    "syft": norm_syft,
    "grype": norm_grype,
    "zap": norm_zap,
    "recon": norm_recon,
    "skillaudit": norm_skillaudit,
    "selfaudit": norm_selfaudit,
    "correlation": lambda raw, base: [],
}


__all__ = [
    'COVERAGE',
    'NORMALIZERS',
    'REPORT_SHAPES',
    '_ANSI',
    '_ASFF_SEV',
    '_GITLEAKS_BYTES',
    '_GITLEAKS_COMMITS',
    '_REDACTED_EVIDENCE',
    '_ZAP_CONF',
    '_ZAP_RISK',
    '_ZAP_TOTAL_URLS',
    '_checkov_blocks',
    '_cov_asff',
    '_cov_bandit',
    '_cov_checkov',
    '_cov_cloudanalyzer',
    '_cov_cloudcontain',
    '_cov_clouddata',
    '_cov_cloudedge',
    '_cov_cloudenable',
    '_cov_cloudfront',
    '_cov_cloudiam',
    '_cov_cloudinv',
    '_cov_cloudorg',
    '_cov_cloudstore',
    '_cov_gitleaks',
    '_cov_recon',
    '_cov_selfaudit',
    '_cov_semgrep',
    '_cov_skillaudit',
    '_cov_syft',
    '_cov_trivy',
    '_cov_zap',
    '_real_evidence',
    '_region_notes',
    '_regional_errors',
    '_regions_answered',
    '_rows_or_empty',
    '_source_line',
    '_text',
    '_title',
    '_trivy_findings',
    'function_count',
    'norm_asff',
    'norm_bandit',
    'norm_checkov',
    'norm_cloudanalyzer',
    'norm_cloudcontain',
    'norm_clouddata',
    'norm_cloudedge',
    'norm_cloudenable',
    'norm_cloudfront',
    'norm_cloudiam',
    'norm_cloudinv',
    'norm_cloudorg',
    'norm_cloudstore',
    'norm_gitleaks',
    'norm_grype',
    'norm_recon',
    'norm_selfaudit',
    'norm_semgrep',
    'norm_skillaudit',
    'norm_syft',
    'norm_trivy',
    'norm_zap',
    'report_unreadable',
    'rule_of',
    'stage_coverage',
]

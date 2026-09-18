"""SARIF 2.1.0 for one run.

The format everything else in this category speaks, and the reason to speak it
is not compatibility for its own sake: SARIF already has the vocabulary for the
one thing this tool insists on. A scanner that ran and read nothing is
`invocations[].executionSuccessful = false` with a notification saying what it
examined. A correlation that could not be evaluated is a result with
`kind = "notApplicable"` and `level = "none"` — present, counted, and not a
finding. Both survive the trip into GitHub code scanning, which is where a
reader of this output actually lives.

One SARIF `run` per scanner, not one per Squawk run. A SARIF run has exactly
one `tool.driver`, and collapsing five scanners into one driver is the same
flattening that loses which tool read what — the thing the ledger exists to
keep. The Squawk run id goes on every SARIF run as `automationDetails.id`, so
they regroup.

Nothing here reaches back into a scanner's raw output: it reads the manifest
and the normalised findings, which are the two things already scrubbed of
matched credentials.
"""
from typing import Any, Dict, List, Optional

from squawk.core import __version__, mask_account, redact_identifiers

__all__ = [
    'KIND_NOT_APPLICABLE',
    'LEVEL',
    'SARIF_SCHEMA',
    'SARIF_VERSION',
    '_artifact_location',
    '_correlation_results',
    '_driver',
    '_invocation',
    '_result_for',
    '_rules_for',
    '_scanner_runs',
    'sarif_document',
]

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

#: SARIF has four levels and this tool has six severities. The mapping is
#: lossy in one direction only: `critical` and `high` both become `error`,
#: because SARIF has nothing above error, and the original severity travels
#: in `properties.severity` so nothing is actually lost.
LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
    "unknown": "none",
}

#: What SARIF calls a rule that was not evaluated. The spec requires `level`
#: to be "none" once `kind` is anything but "fail", which is exactly the shape
#: this tool wants: counted, visible, and not a finding.
KIND_NOT_APPLICABLE = "notApplicable"


def _artifact_location(path: str) -> Dict[str, Any]:
    """A finding's location. Relative where the finding is relative, which is
    what a stable identity already guarantees; an absolute path or a URL is
    passed through as a URI so a DAST finding still points somewhere."""
    return {"uri": path or "unknown"}


def _result_for(finding: Dict[str, Any], rule_index: int) -> Dict[str, Any]:
    sev = (finding.get("severity") or "unknown").lower()
    detail = finding.get("detail") or {}
    out: Dict[str, Any] = {
        "ruleId": detail.get("rule") or finding.get("identity") or "squawk",
        "ruleIndex": rule_index,
        "level": LEVEL.get(sev, "none"),
        "kind": "fail",
        "message": {"text": redact_identifiers(finding.get("title") or "")},
        "locations": [{"physicalLocation": {
            "artifactLocation": _artifact_location(finding.get("path") or "")}}],
        "partialFingerprints": {"squawkIdentity/v1": finding.get("identity") or ""},
        "properties": {"severity": sev, "scanner": finding.get("scanner") or ""},
    }
    line = detail.get("line")
    if isinstance(line, int) and line > 0:
        out["locations"][0]["physicalLocation"]["region"] = {"startLine": line}
    return out


def _rules_for(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One descriptor per rule id, in first-seen order, so `ruleIndex` is
    stable within a document."""
    rules: List[Dict[str, Any]] = []
    seen: Dict[str, int] = {}
    for f in findings:
        detail = f.get("detail") or {}
        rid = detail.get("rule") or f.get("identity") or "squawk"
        if rid in seen:
            continue
        seen[rid] = len(rules)
        desc = redact_identifiers(detail.get("description") or f.get("title") or "")
        rule: Dict[str, Any] = {"id": rid, "name": rid,
                                "shortDescription": {"text": redact_identifiers(
                                    f.get("title") or rid)}}
        if desc:
            rule["fullDescription"] = {"text": desc}
        if detail.get("remediation"):
            rule["help"] = {"text": redact_identifiers(detail["remediation"])}
        if detail.get("reference"):
            rule["helpUri"] = detail["reference"]
        rules.append(rule)
    return rules


def _invocation(row: Dict[str, Any]) -> Dict[str, Any]:
    """What this stage did, in SARIF's own words.

    `executionSuccessful` is false for anything but `ok`, which is the point:
    a stage that was skipped, errored, or ran and read nothing must not present
    as a successful scan that found nothing. The denominator rides along as a
    notification rather than being dropped, because SARIF has nowhere else to
    put "examined 0 resources" and dropping it is the defect.
    """
    status = row.get("status") or "skipped"
    cov = row.get("coverage") or {}
    inv: Dict[str, Any] = {
        "executionSuccessful": status == "ok",
        "properties": {"squawkStatus": status},
    }
    text = redact_identifiers(row.get("detail") or "")
    if text:
        inv["toolExecutionNotifications"] = [{
            "level": "note" if status == "ok" else "warning",
            "message": {"text": text},
            "properties": {
                "examined": cov.get("examined"),
                "unit": cov.get("unit"),
                "skipped": cov.get("skipped"),
                "errors": cov.get("errors"),
            },
        }]
    return inv


def _driver(tool: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "name": tool,
        "informationUri": "https://github.com/ryayres-fox/squawk",
        "rules": rules,
        "properties": {"orchestratedBy": "squawk", "squawkVersion": __version__},
    }


def _correlation_results(corrs: List[Dict[str, Any]],
                         rule_index: int) -> List[Dict[str, Any]]:
    """A correlation, including the ones that could not be evaluated.

    This is the reason to emit SARIF at all. A rule whose member scanner was
    silent is `kind = notApplicable`, `level = none` — it appears in the
    document, with the sentence saying which leg was not read. Every other
    tool in this category renders the correlations that fired and is silent
    about the ones it could not check, which is the defect one layer up.
    """
    out: List[Dict[str, Any]] = []
    for c in corrs:
        state = c.get("state") or "unknown"
        sev = (c.get("severity") or "unknown").lower()
        evaluated = state not in ("unknown", "not-applicable")
        out.append({
            "ruleId": c.get("key") or "correlation",
            "ruleIndex": rule_index,
            "kind": "fail" if evaluated else KIND_NOT_APPLICABLE,
            "level": LEVEL.get(sev, "none") if evaluated else "none",
            "message": {"text": redact_identifiers(
                "%s — %s" % (c.get("title") or "", c.get("why") or ""))},
            "locations": [{"physicalLocation": {
                "artifactLocation": _artifact_location("correlation")}}],
            "properties": {
                "squawkState": state,
                "severity": sev,
                "members": [m for m in (c.get("members") or [])],
            },
        })
    return out


def _scanner_runs(man: Dict[str, Any],
                  findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_tool: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        by_tool.setdefault(f.get("scanner") or "squawk", []).append(f)

    runs: List[Dict[str, Any]] = []
    for row in man.get("ledger") or []:
        tool = row.get("tool") or "unknown"
        if tool == "correlation":
            continue
        mine = by_tool.pop(tool, [])
        rules = _rules_for(mine)
        index = {r["id"]: i for i, r in enumerate(rules)}
        results = []
        for f in mine:
            detail = f.get("detail") or {}
            rid = detail.get("rule") or f.get("identity") or "squawk"
            results.append(_result_for(f, index.get(rid, 0)))
        runs.append({
            "tool": {"driver": _driver(tool, rules)},
            "invocations": [_invocation(row)],
            "results": results,
            "automationDetails": {"id": "%s/%s" % (man.get("run_id") or "", tool)},
            "properties": {"squawkService": man.get("service") or "",
                           "squawkScope": man.get("scope") or "",
                           "notCovered": man.get("not_covered") or ""},
        })

    # Anything the ledger did not name, so a finding cannot vanish because its
    # stage row was missing. Silence is the failure mode this whole tool is
    # about; it would be absurd to reintroduce it in the exporter.
    for tool, mine in sorted(by_tool.items()):
        rules = _rules_for(mine)
        index = {r["id"]: i for i, r in enumerate(rules)}
        runs.append({
            "tool": {"driver": _driver(tool, rules)},
            "invocations": [{"executionSuccessful": True,
                             "properties": {"squawkStatus": "unledgered"}}],
            "results": [_result_for(
                f, index.get((f.get("detail") or {}).get("rule")
                             or f.get("identity") or "squawk", 0)) for f in mine],
            "automationDetails": {"id": "%s/%s" % (man.get("run_id") or "", tool)},
        })
    return runs


def sarif_document(man: Dict[str, Any],
                   findings: Optional[List[Dict[str, Any]]] = None
                   ) -> Dict[str, Any]:
    """One run as a SARIF 2.1.0 document."""
    findings = list(findings or [])
    runs = _scanner_runs(man, findings)

    corrs = man.get("correlations") or []
    if corrs:
        rules = [{"id": c.get("key") or "correlation",
                  "name": c.get("key") or "correlation",
                  "shortDescription": {"text": c.get("title") or ""},
                  "help": {"text": c.get("fix") or ""}} for c in corrs]
        seen: Dict[str, int] = {}
        uniq: List[Dict[str, Any]] = []
        for r in rules:
            rid = str(r["id"])
            if rid not in seen:
                seen[rid] = len(uniq)
                uniq.append(r)
        results = []
        for c in corrs:
            key = str(c.get("key") or "correlation")
            results.extend(_correlation_results([c], seen.get(key, 0)))
        runs.append({
            "tool": {"driver": _driver("squawk-correlation", uniq)},
            "invocations": [{"executionSuccessful": True}],
            "results": results,
            "automationDetails": {
                "id": "%s/correlation" % (man.get("run_id") or "")},
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": runs,
        "properties": {
            "squawkRun": man.get("run_id") or "",
            "squawkTarget": mask_account(man.get("target") or ""),
            "squawkService": man.get("service") or "",
            "squawkVersion": __version__,
        },
    }

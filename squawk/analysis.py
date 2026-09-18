"""What the evidence means: the differential, correlation, the squawk codes, the run score."""

import calendar
import json
import os
import re
import time
from typing import (
    Any,
    Callable,
    Dict,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
)

from squawk import probes as squawk_probes
from squawk.core import (
    DB_STALE_DAYS,
    LOG,
    SCANNERS,
    SEVERITY_ORDER,
    Finding,
    StageResult,
    _rows,
    as_text,
    mask_account,
    mask_key_id,
    norm_severity,
    redact_identifiers,
    result_kind,
    vuln_db_ages,
)
from squawk.decisions import current_decisions, summarize, verify_ledger
from squawk.evidence import (
    history_entries,
    list_runs,
    load_findings,
    load_verify,
    target_key,
    verify_retention,
    verify_runs,
)
from squawk.probes import (
    ANALYZER_KINDS,
    eni_owner,
    is_narrowed_public,
    is_unsettled_public,
)
from squawk.scanners import rule_of

# Pairs of scanners that read the SAME input, so a stark disagreement between
# them is a health signal about the toolchain rather than about the target. Only
# same-input pairs belong here: semgrep and bandit are both SAST but bandit is
# Python-only and semgrep is multi-language, so they legitimately differ and
# comparing their counts would cry wolf, the false alarm this tool refuses.
# trivy and grype both read the dependency set, so they should roughly agree.
DIFFERENTIAL_PAIRS = (
    ("trivy", "grype", "dependency CVEs"),
)


def scanner_differential(results: "List[StageResult]") -> List[dict]:
    """Where two scanners read the same input, a stark asymmetry is a free
    detection test: no fixture, and it renews itself every run because the
    scanners maintain themselves.

    Conservative on purpose. Only the zero-vs-many case is flagged: one tool
    finds a substantial number and its paired tool, having run cleanly, finds
    exactly zero. Normal tool variance (9 vs 7, different CVE databases) is NOT
    a signal and must never be reported, or the operator learns to ignore it.
    A pair where only one side ran is skipped: there is nothing to compare."""
    # One result per tool, or no comparison. A dict comprehension here would
    # silently keep the LAST stage when a tool runs twice in one service (say
    # trivy-fs and trivy-image), and a comparison against an arbitrary half of
    # a tool's output is worse than none. No current service does this; the
    # guard exists so the first one that does cannot corrupt the signal.
    seen: Dict[str, List[StageResult]] = {}
    for r in results:
        seen.setdefault(r.tool, []).append(r)
    out: List[dict] = []
    for a, b, domain in DIFFERENTIAL_PAIRS:
        if len(seen.get(a, [])) != 1 or len(seen.get(b, [])) != 1:
            continue                       # absent or ambiguous; nothing to compare
        ra, rb = seen[a][0], seen[b][0]
        if ra.status != "ok" or rb.status != "ok":
            continue                       # one did not run cleanly; nothing to compare
        na, nb = len(ra.findings), len(rb.findings)
        hi, lo, hi_t, lo_t = (na, nb, a, b) if na >= nb else (nb, na, b, a)
        if lo == 0 and hi >= 5:
            out.append({
                "domain": domain,
                "loud": hi_t, "loud_count": hi,
                "silent": lo_t,
                "note": "%s found %d %s; %s found 0 on the same input, one may "
                        "be degraded" % (hi_t, hi, domain, lo_t)})
            LOG.warning("DIFFERENTIAL %s found %d %s, %s found 0",
                        hi_t, hi, domain, lo_t)
    return out


class Correlation(NamedTuple):
    key: str                     # stable rule id, e.g. "public-unencrypted-store"
    title: str
    severity: str                # the lift; why the combination beats its parts
    requires: Tuple[str, ...]    # scanner KINDS whose absence makes this unknown
    rule: Callable[["CorrelationInput"], "List[dict]"]
    fix: str


class CorrelationInput(NamedTuple):
    findings: List[dict]                 # every finding in the run, as dicts
    ran_kinds: set                       # scanner kinds that ran cleanly (ok/gap)


def _by_resource(findings: List[dict], scanner: str) -> Dict[str, List[dict]]:
    """Group one scanner's findings by the resource in their identity. checkov
    identities are `check:file:resource`, so the resource is field 3."""
    out: Dict[str, List[dict]] = {}
    for f in findings:
        if f.get("scanner") != scanner:
            continue
        parts = f.get("identity", "").split(":")
        resource = parts[2] if len(parts) >= 3 else ""
        key = "%s:%s" % (f.get("path", ""), resource)
        out.setdefault(key, []).append(f)
    return out


def _rule_public_unencrypted(inp: "CorrelationInput") -> List[dict]:
    """A storage resource that is both publicly reachable AND unencrypted. Public
    encrypted data is a mistake; public unencrypted data is the mistake plus no
    fallback. Both facts are checkov findings on the same resource, joined on the
    resource in their identity."""
    PUBLIC = ("CKV_AWS_20", "CKV_AWS_53", "CKV_AWS_54", "CKV_AWS_56")   # public access
    # Encryption checks only. CKV_AWS_21 (versioning) was in this tuple at
    # first, which let a public bucket with encryption fine but versioning off
    # fire a finding titled "unencrypted", a false statement on the loudest
    # channel. The title must match the facts that fired it.
    CRYPTO = ("CKV_AWS_19", "CKV_AWS_145")
    out = []
    for resource, group in _by_resource(inp.findings, "checkov").items():
        ids = {f.get("identity", "").split(":")[0] for f in group}
        pub = [c for c in PUBLIC if c in ids]
        cry = [c for c in CRYPTO if c in ids]
        if pub and cry:
            members = [f for f in group
                       if f.get("identity", "").split(":")[0] in set(pub) | set(cry)]
            out.append({"resource": resource, "members": members,
                        "why": "public (%s) and unencrypted (%s) on the "
                               "same resource" % (",".join(pub), ",".join(cry))})
    return out


def _rule_secret_in_build(inp: "CorrelationInput") -> List[dict]:
    """A secret in the tree, and a container build in the same tree. If the build
    copies the secret's path (`COPY . .` is the common case) the credential
    ships in every image. Stated as a conditional because confirming the COPY
    target is a follow-on; the value is putting the two findings in front of the
    reader together, which no scanner does."""
    secrets = [f for f in inp.findings
               if f.get("scanner") == "gitleaks"
               or (f.get("scanner") == "bandit"
                   and f.get("identity", "").startswith("B105"))]
    dockerfiles = [f for f in inp.findings
                   if "dockerfile" in (f.get("path", "") + f.get("identity", "")).lower()]
    if secrets and dockerfiles:
        return [{"resource": "container build", "members": secrets[:1] + dockerfiles[:1],
                 "why": "a secret (%s) sits in a tree that builds a container "
                        "image; if the Dockerfile copies it, it ships in every "
                        "image" % secrets[0].get("path", "")}]
    return []


CORRELATIONS: Tuple[Correlation, ...] = (
    Correlation(
        "public-unencrypted-store",
        "Publicly reachable AND unencrypted storage",
        "high", ("iac",), _rule_public_unencrypted,
        "Make the resource private and enable encryption; either alone still "
        "leaves the other exposure."),
    Correlation(
        "secret-in-container-build",
        "Secret in a container build context",
        "high", ("secrets",), _rule_secret_in_build,
        "Move the secret out of the image (build arg, mounted secret, or runtime "
        "env) and rotate it; a secret in an image layer is public to anyone who "
        "pulls it."),
)


# What became of a stage that did not produce a usable read. The distinction is
# the tool's own thesis pointed inward: "no secrets scanner ran" was printed
# over a gitleaks that had run for fifteen minutes and been killed at its
# budget (the operator's run, 2026-09-14). A tool that ran and died is not a tool
# that was never there, and saying so is the same substitution this refuses
# everywhere else.
_TROUBLE = {
    "gap": "%s read nothing this run",
    "error": "%s ran and did not finish",
    "skipped": "%s did not run",
}


def _stage_trouble(result: "StageResult") -> str:
    """One stage's failure, in the words a reader needs."""
    shape = _TROUBLE.get(result.status, "%s did not report")
    return shape % result.tool


def _unanswered(kinds: List[str], unread: Dict[str, List[str]]) -> str:
    """Why a combination could not be evaluated at all — no members joined AND
    a required kind never answered. Names the stage and what became of it,
    rather than asserting that nothing ran."""
    bits = []
    for kind in kinds:
        who = " and ".join(unread.get(kind) or ["no %s scanner ran" % kind])
        bits.append("%s, so the %s side was never read" % (who, kind))
    return "; ".join(bits)


def _unread_caveat(kinds: List[str], unread: Dict[str, List[str]]) -> str:
    """What a fired correlation could not check, written into the finding that
    fired.

    A combination cites the members it joined. Naming the required kind that
    read nothing is the other half of the same sentence, and it is the half a
    reader cannot reconstruct: the finding is real, and one leg of it was never
    scanned."""
    bits = []
    for kind in kinds:
        who = " and ".join(unread.get(kind) or ["no %s scanner ran" % kind])
        bits.append("%s, so the %s leg of this rests on the members cited, "
                    "not on a scan" % (who, kind))
    return "; ".join(bits)


def correlate(findings: List[dict], results: "List[StageResult]") -> List[dict]:
    """Run every correlation rule over one run's findings. Returns correlation
    records: a fired combination, or an `unknown` when a required scanner kind
    did not run so the combination could not be evaluated.

    Three states, like everything else: fired (a combination, citing members),
    nothing (members present, no join, a real negative), and unknown (a member
    scanner was silent, so we cannot say)."""
    # Three cases, not two. A kind can be: in scope AND it produced output
    # (evaluate), in scope but silent (unknown: the scan should have run it and
    # did not), or NOT in this service's scope at all (not applicable, silent).
    # Without the third, a host audit reported "cannot evaluate
    # secret-in-container-build", which is a category error: a host audit never
    # runs a secrets scanner, so there is nothing to evaluate and nothing to
    # confess. Found on a live selfaudit run.
    # What each stage READ, not what its scanner is filed under: `trivy config`
    # is an IaC scan and `trivy fs` is a dependency scan, and the registry has
    # one kind for both (I16, review of 2026-09-12).
    scope_kinds = {result_kind(r.tool, r.mode) for r in results
                   if r.tool in SCANNERS}
    ran_kinds = {result_kind(r.tool, r.mode) for r in results
                 if r.status in ("ok", "gap") and r.tool in SCANNERS}
    # A fourth case, hiding inside "it ran". `gap` sits in `ran_kinds` on
    # purpose: a stage that ran and read nothing must not turn every
    # combination needing it into "unknown", because that trades a real finding
    # for a denominator. But a combination that FIRES while one of its required
    # kinds read nothing is answering a question it never asked. On a live
    # compliance run gitleaks read 0 bytes and secret-in-container-build fired
    # on bandit's B105 alone — a high finding that named no gap, so the reader
    # had every reason to think the secret half had been scanned. I1 holds
    # inside a correlation too, so the rule keeps firing and the finding
    # carries what it could not check (I16: a correlation states its
    # denominator).
    read_kinds = {result_kind(r.tool, r.mode) for r in results
                  if r.status == "ok" and r.tool in SCANNERS}
    unread: Dict[str, List[str]] = {}
    for r in results:
        kind = result_kind(r.tool, r.mode)
        if kind and kind not in read_kinds and r.status != "ok":
            named = unread.setdefault(kind, [])
            phrase = _stage_trouble(r)
            if phrase not in named:
                named.append(phrase)
    inp = CorrelationInput(findings, ran_kinds)
    out: List[dict] = []
    for corr in CORRELATIONS:
        if not all(k in scope_kinds for k in corr.requires):
            continue                       # not applicable to this kind of scan
        # The rule is evaluated whatever happened upstream, and the OUTCOME
        # decides the state. Gating evaluation on the required kinds threw away
        # real findings: on the operator's run gitleaks timed out, so `secrets`
        # left `ran_kinds`, and secret-in-container-build reported "cannot
        # evaluate" over a bandit B105 and a Dockerfile that were both still
        # sitting in the findings list. The same evidence with gitleaks at
        # `gap` instead of `error` fired a high finding — one word of stage
        # status, and a real combination appeared or vanished (2026-09-14).
        thin = [k for k in corr.requires if k in unread]
        hits = corr.rule(inp)
        if not hits:
            # Nothing joined. That is a real negative only if the question was
            # actually asked; otherwise it is unknown, which is the state this
            # whole section exists for.
            if thin:
                out.append({
                    "key": corr.key, "state": "unknown", "title": corr.title,
                    "why": "cannot evaluate: %s" % _unanswered(thin, unread),
                    "severity": "unknown", "members": [], "fix": corr.fix})
                LOG.info("CORRELATION unknown %s (%s)", corr.key, "/".join(thin))
            continue
        for hit in hits:
            member_ids = [m.get("identity", "") for m in hit.get("members", [])]
            why = hit["why"]
            if thin:
                why = "%s — %s" % (why, _unread_caveat(thin, unread))
                LOG.warning("CORRELATION %s fired with %s unread",
                            corr.key, "/".join(thin))
            out.append({
                "key": corr.key, "state": "fired", "title": corr.title,
                "severity": corr.severity, "why": why,
                "resource": hit.get("resource", ""),
                "members": member_ids, "unread": thin, "fix": corr.fix})
            LOG.warning("CORRELATION %s [%s] %s — members: %s",
                        corr.key, corr.severity, why, ", ".join(member_ids))
    return out


def correlation_findings(correlations: List[dict]) -> List[Finding]:
    """Fired correlations become Findings, so they inherit identity, evidence,
    history and ranking like any other. Identity is the rule key plus the
    resource, so the same combination on the same resource matches across runs."""
    out: List[Finding] = []
    for c in correlations:
        if c.get("state") != "fired":
            continue
        ident = "correlation:%s:%s" % (c["key"], c.get("resource", ""))
        out.append(Finding(
            "correlation", ident, norm_severity(c["severity"]), c["title"],
            "correlation:%s" % c.get("resource", ""),
            {"what": c["why"], "remediation": c["fix"],
             "members": c.get("members", []), "rule": c["key"],
             # Only when there is something to say. An always-present empty
             # key is noise in every evidence file that has no gap to report.
             **({"unread": c["unread"]} if c.get("unread") else {})}))
    return out



# --------------------------------------------------------------------------- #
# Cloud graph correlation — the combinations no single scanner reports.
#
# Everything above joins FINDINGS. That model does not reach a cloud account,
# and the reason is the whole point of this section:
#
#   A cloud toxic combination is a join over resources that individually
#   produce no finding at all.
#
# An instance having a public IP is not a finding. A security group allowing
# 443 is not a finding. An instance profile carrying AdministratorAccess is not
# a finding — plenty of build servers legitimately have one. Each is ordinary,
# and a scanner reporting any of them alone would be noise an operator learns
# to ignore. The combination is the finding, and no member of it is one.
#
# So these rules take a graph, not a finding list. They join resources, derive
# reachability rather than assuming it, and cite the path they walked — a
# verdict without a path is an assertion, and this tool does not make those.
# --------------------------------------------------------------------------- #

ANYWHERE = ("0.0.0.0/0", "::/0")

# Ports where "open to the entire internet" is almost never what was meant:
# remote administration and databases. HTTP and HTTPS are deliberately absent —
# a web server open to the world is the job, and a rule that flags it teaches
# the reader to skip this section.
SENSITIVE_PORTS = {
    22: "SSH", 23: "telnet", 445: "SMB", 3389: "RDP", 5985: "WinRM",
    5986: "WinRM/TLS", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    5432: "PostgreSQL", 5439: "Redshift", 6379: "Redis", 9200: "Elasticsearch",
    11211: "memcached", 27017: "MongoDB", 2375: "Docker API", 2379: "etcd",
    9000: "admin/console", 8500: "Consul",
}


class CloudGraph(NamedTuple):
    """One region's inventory, indexed for joining, plus what could not be read.

    `unreadable` is the load-bearing field. A rule that needs security groups
    must report unknown when the security-group read failed, never "nothing
    found" — a partial inventory has to poison the conclusions that depend on
    it, or the tool is back to reporting silence as clean."""
    region: str
    vpcs: Dict[str, dict]
    subnets: Dict[str, dict]
    route_tables: List[dict]
    igws: Dict[str, dict]
    groups: Dict[str, dict]
    enis: List[dict]
    instances: List[dict]
    profiles: Dict[str, dict]          # instance profile ARN -> {role, status}
    roles: Dict[str, dict]             # role name -> {policies, broad, status}
    unreadable: Dict[str, str]         # read key -> why it could not be read


def _index(rows: List[dict], key: str) -> Dict[str, dict]:
    return {str(r.get(key, "")): r for r in rows if r.get(key)}


def build_cloud_graph(data: dict, region: str) -> CloudGraph:
    """Index one region of an inventory read into a joinable graph."""
    res = _mapping(data.get("resources")).get(region) or {}
    reads = _mapping(data.get("reads")).get(region) or {}
    unreadable = {}
    for key, row in reads.items():
        if isinstance(row, dict) and row.get("status") in ("error", "unread"):
            unreadable[key] = str(row.get("detail") or row.get("status"))
    rows = lambda k: [r for r in _rows(res.get(k)) if isinstance(r, dict)]  # noqa: E731
    return CloudGraph(
        region=region,
        vpcs=_index(rows("vpcs"), "VpcId"),
        subnets=_index(rows("subnets"), "SubnetId"),
        route_tables=rows("route-tables"),
        igws=_index(rows("internet-gateways"), "InternetGatewayId"),
        groups=_index(rows("security-groups"), "GroupId"),
        enis=rows("network-interfaces"),
        instances=rows("instances"),
        profiles=data.get("instance_profiles") or {},
        roles=data.get("roles") or {},
        unreadable=unreadable)


def public_subnets(g: CloudGraph) -> Dict[str, str]:
    """Subnets that actually route to the internet, and the gateway proving it.

    DERIVED, not assumed. There is no `Public` field on a subnet: a subnet is
    public when the route table associated with it (or its VPC's main table,
    when nothing is associated explicitly) carries a default route to an
    attached internet gateway. `MapPublicIpOnLaunch` is not the test either —
    it hands out an address that may route nowhere. Getting this wrong in
    either direction is the difference between a real finding and a scare."""
    attached_igws = set()
    for igw_id, igw in g.igws.items():
        for att in _rows(igw.get("Attachments")):
            if str(att.get("State", "")).lower() in ("available", "attached"):
                attached_igws.add(igw_id)
    explicit: Dict[str, str] = {}
    main: Dict[str, str] = {}
    for rt in g.route_tables:
        gateway = ""
        for route in _rows(rt.get("Routes")):
            gw = str(route.get("GatewayId", ""))
            dest = (str(route.get("DestinationCidrBlock", ""))
                    or str(route.get("DestinationIpv6CidrBlock", "")))
            if gw in attached_igws and dest in ANYWHERE:
                gateway = gw
                break
        if not gateway:
            continue
        for assoc in _rows(rt.get("Associations")):
            if assoc.get("Main"):
                main[str(rt.get("VpcId", ""))] = gateway
            elif assoc.get("SubnetId"):
                explicit[str(assoc["SubnetId"])] = gateway
    out: Dict[str, str] = {}
    for subnet_id, subnet in g.subnets.items():
        if subnet_id in explicit:
            out[subnet_id] = explicit[subnet_id]
        elif str(subnet.get("VpcId", "")) in main:
            out[subnet_id] = main[str(subnet["VpcId"])]
    return out


def _world_open_ports(group: dict) -> List[Tuple[str, int, int]]:
    """Ingress rules on one group that admit the entire internet, as
    (protocol, from, to). `-1` is every protocol and every port, which is the
    widest rule AWS can express and is reported as such."""
    out = []
    for perm in _rows(group.get("IpPermissions")):
        cidrs = [c for c in (list(perm.get("IpRanges") or [])
                             + list(perm.get("Ipv6Ranges") or []))
                 if str(c) in ANYWHERE]
        if not cidrs:
            continue
        proto = str(perm.get("IpProtocol", ""))
        lo, hi = perm.get("FromPort"), perm.get("ToPort")
        if proto == "-1" or lo is None or hi is None:
            out.append(("all", 0, 65535))
            continue
        out.append((proto, int(lo), int(hi)))
    return out


def _named_exposed_ports(rules: List[Tuple[str, int, int]]) -> List[str]:
    """The sensitive ports a set of world-open rules actually admits, named.

    A rule opening 0-65535 admits every one of them, which is why the range is
    tested rather than the port number matched: a group open to the world on
    "all traffic" is the worst case, and reporting it as nothing because 22 was
    not literally written would invert the finding."""
    hit = []
    for port, name in sorted(SENSITIVE_PORTS.items()):
        for proto, lo, hi in rules:
            if proto in ("all", "tcp", "6") and lo <= port <= hi:
                hit.append("%d/%s" % (port, name))
                break
    return hit


def _instance_public_ip(g: CloudGraph, inst: dict) -> str:
    """The instance's public address, from the instance or from any interface
    attached to it. An instance with a secondary ENI carrying the public IP is
    exactly as reachable as one with it on the primary."""
    if inst.get("PublicIpAddress"):
        return str(inst["PublicIpAddress"])
    for eni in g.enis:
        if eni.get("InstanceId") == inst.get("InstanceId") and eni.get("PublicIp"):
            return str(eni["PublicIp"])
    return ""


def _role_for(g: CloudGraph, inst: dict) -> Tuple[str, dict]:
    arn = str(inst.get("InstanceProfileArn", ""))
    if not arn:
        return "", {}
    prof = g.profiles.get(arn) or {}
    role = str(prof.get("role", ""))
    if not role:
        return "", {"status": "unknown",
                    "detail": prof.get("detail", "the instance profile could not be read")}
    return role, (g.roles.get(role) or {"status": "unknown",
                                        "detail": "the role could not be read"})


# Protocols that carry a session someone can reach a service over. ICMP echo
# from anywhere is a ping, and UDP/53 to a resolver is a resolver; neither is a
# foothold, and counting them made an instance whose only world-open rule was
# ICMP a CRITICAL "reachable on world-open ports" (review R-8). They are still
# recorded -- an operator wants to know what else the group admits -- but they
# never make an instance reachable on their own. `-1` is every protocol, which
# includes TCP.
REACHABLE_PROTOCOLS = ("all", "tcp", "6")


def _instance_groups(g: CloudGraph, inst: dict) -> List[str]:
    """Every security group on an instance, including its secondary interfaces.

    `SecurityGroups` on the instance is the PRIMARY interface's groups. An
    instance whose public address sits on a second interface carrying the
    world-open group produced nothing at all, because the primary's groups were
    clean (review R-8). The ENI projection already keeps `Groups`, so this is a
    join over data the reading holds rather than another call."""
    ids = [str(gid) for gid in (inst.get("SecurityGroups") or [])]
    instance_id = str(inst.get("InstanceId", ""))
    if instance_id:
        for eni in g.enis:
            if str(eni.get("InstanceId", "")) != instance_id:
                continue
            ids.extend(str(gid) for gid in (eni.get("Groups") or []))
    seen, out = set(), []
    for gid in ids:
        if gid and gid not in seen:
            seen.add(gid)
            out.append(gid)
    return out


def _reachable_instances(g: CloudGraph) -> List[dict]:
    """Every running instance with a public address in a subnet that routes to
    an internet gateway, with the world-open ports its groups admit.

    Reachability needs a rule someone can connect over. Rules on other
    protocols are carried in `also` and said in the finding, never counted."""
    pub = public_subnets(g)
    out = []
    for inst in g.instances:
        if str(inst.get("State", "")).lower() != "running":
            continue
        ip = _instance_public_ip(g, inst)
        if not ip:
            continue
        subnet_id = str(inst.get("SubnetId", ""))
        gateway = pub.get(subnet_id, "")
        if not gateway:
            continue
        rules: List[Tuple[str, int, int]] = []
        also: List[Tuple[str, int, int]] = []
        open_groups: List[str] = []
        for gid in _instance_groups(g, inst):
            group = g.groups.get(gid)
            if not group:
                continue
            found = _world_open_ports(group)
            reachable = [r for r in found if r[0] in REACHABLE_PROTOCOLS]
            also.extend(r for r in found if r[0] not in REACHABLE_PROTOCOLS)
            if reachable:
                rules.extend(reachable)
                open_groups.append(gid)
        if not rules:
            continue
        out.append({"instance": inst, "ip": ip, "subnet": subnet_id,
                    "gateway": gateway, "groups": open_groups,
                    "rules": rules, "also": also,
                    "ports": _named_exposed_ports(rules)})
    return out


def _also_admits(hit: dict) -> str:
    """What else the groups admit from the whole internet, in a clause.

    Said, and not counted. An operator wants to know the group also answers
    pings; a scanner that turned that into "reachable on world-open ports" was
    reporting a foothold that is not one."""
    kinds = sorted({proto for proto, _lo, _hi in (hit.get("also") or [])})
    if not kinds:
        return ""
    return ("; the same group(s) also admit 0.0.0.0/0 on %s, which carries no "
            "session to reach a service over" % ", ".join(kinds))


def _rule_reachable_admin_port(g: CloudGraph) -> List[dict]:
    """A running instance, reachable from the internet, admitting the world on
    a port that administers or stores something.

    Three separate facts, none of them a finding alone: the address, the route,
    and the rule. Reported without needing to read IAM at all, so it still
    fires for the read-only identity that cannot list a role."""
    out = []
    for hit in _reachable_instances(g):
        if not hit["ports"]:
            continue
        inst = hit["instance"]
        out.append({
            "resource": "%s/%s" % (g.region, inst.get("InstanceId", "")),
            "members": [inst.get("InstanceId", ""), hit["subnet"], hit["gateway"]]
                       + hit["groups"],
            "why": "instance %s answers on %s, its subnet %s routes to %s, and "
                   "%s admits 0.0.0.0/0 on %s%s"
                   % (inst.get("InstanceId", ""), hit["ip"], hit["subnet"],
                      hit["gateway"], "/".join(hit["groups"]),
                      ", ".join(hit["ports"]), _also_admits(hit))})
    return out


def _rule_reachable_over_permitted(g: CloudGraph) -> List[dict]:
    """The four-legged one: reachable from the internet AND carrying a role
    that can do far more than read.

    This is a foothold with credentials already attached. Any one leg is
    ordinary — plenty of instances are public, plenty of roles are broad — and
    the combination is a path from the internet to the account."""
    out = []
    for hit in _reachable_instances(g):
        inst = hit["instance"]
        role, breadth = _role_for(g, inst)
        if not role or not breadth.get("broad"):
            continue
        ports = ", ".join(hit["ports"]) or "world-open ports"
        out.append({
            "resource": "%s/%s" % (g.region, inst.get("InstanceId", "")),
            "members": [inst.get("InstanceId", ""), hit["subnet"], hit["gateway"]]
                       + hit["groups"] + [role],
            "why": "instance %s answers on %s, its subnet %s routes to %s, %s "
                   "admits 0.0.0.0/0 on %s, and it carries role %s with %s%s"
                   % (inst.get("InstanceId", ""), hit["ip"], hit["subnet"],
                      hit["gateway"], "/".join(hit["groups"]), ports, role,
                      ", ".join(breadth["broad"]), _also_admits(hit))})
    return out


class CloudRule(NamedTuple):
    key: str
    title: str
    severity: str
    needs: Tuple[str, ...]        # inventory reads without which this is unknown
    rule: Callable[["CloudGraph"], List[dict]]
    fix: str
    # Rules this one makes redundant on the SAME resource. The four-leg rule
    # walks the same path as the reachability rule and then adds the role, so
    # reporting both would hand an operator two findings for one instance and
    # one fix list. Only ever declared where the surviving finding states
    # everything the superseded one would have said — a test asserts exactly
    # that, because a "supersedes" that quietly drops facts is a silent cap.
    supersedes: Tuple[str, ...] = ()


CLOUD_CORRELATIONS: Tuple[CloudRule, ...] = (
    CloudRule(
        "reachable-admin-port",
        "Reachable from the internet on an administrative or database port",
        "high",
        ("instances", "subnets", "route-tables", "internet-gateways",
         "security-groups"),
        _rule_reachable_admin_port,
        "Close the rule to 0.0.0.0/0 and reach the host through a bastion, SSM "
        "Session Manager or a VPN. If it must stay open, narrow the source to "
        "the addresses that need it."),
    CloudRule(
        "reachable-over-permitted",
        "Reachable from the internet AND carrying a role that can do far more "
        "than read",
        "critical",
        ("instances", "subnets", "route-tables", "internet-gateways",
         "security-groups"),
        _rule_reachable_over_permitted,
        "Two fixes, and both are worth making: close the world-open rule, and "
        "replace the broad policy on the role with the permissions the "
        "workload actually uses. Either alone still leaves the other half of "
        "the path.",
        supersedes=("reachable-admin-port",)),
)


def correlate_cloud(data: dict) -> List[dict]:
    """Run every cloud rule over every region that was read.

    Three states, the same three as everywhere else. Fired, with the path it
    walked. Nothing, which here is a real negative because the reads it needed
    succeeded. And unknown — when a read this rule depends on failed, or when
    the region was never reached at all. The third is why this function exists
    in this shape: `for region in regions_read` alone would silently answer for
    an account it only partly looked at."""
    out: List[dict] = []
    read = _names(data.get("regions_read"))
    unread = _names(data.get("regions_unread"))
    for region in read:
        g = build_cloud_graph(data, region)
        for rule in CLOUD_CORRELATIONS:
            missing = [k for k in rule.needs if k in g.unreadable]
            if missing:
                out.append({
                    "key": rule.key, "state": "unknown", "title": rule.title,
                    "region": region, "severity": "unknown", "members": [],
                    "resource": region, "fix": rule.fix,
                    "why": "cannot evaluate in %s: could not read %s (%s)"
                           % (region, ", ".join(missing),
                              g.unreadable[missing[0]])})
                LOG.info("CLOUD unknown %s in %s (no %s)", rule.key, region,
                         ",".join(missing))
                continue
            for hit in rule.rule(g):
                out.append({
                    "key": rule.key, "state": "fired", "title": rule.title,
                    "region": region, "severity": rule.severity,
                    "resource": hit["resource"], "members": hit["members"],
                    "why": hit["why"], "fix": rule.fix})
                LOG.warning("CLOUD %s [%s] %s", rule.key, rule.severity, hit["why"])
    # Where a rule superseded another on the same resource, drop the weaker
    # one. Two findings for one instance and one path is noise, and noise is
    # how a reader learns to skip the section that matters. Only fired records
    # are dropped: an `unknown` says a question could not be answered and no
    # other rule answers it for us.
    beaten = set()
    for rec in out:
        if rec.get("state") != "fired":
            continue
        for rule in CLOUD_CORRELATIONS:
            if rule.key == rec["key"]:
                for weaker in rule.supersedes:
                    beaten.add((weaker, rec["region"], rec["resource"]))
    out = [r for r in out
           if r.get("state") != "fired"
           or (r["key"], r["region"], r["resource"]) not in beaten]

    # A region never reached is not a region with nothing in it. Said once per
    # rule, naming the regions, rather than folded into a count that would read
    # as an answer for the whole account.
    for rule in CLOUD_CORRELATIONS:
        if unread:
            out.append({
                "key": rule.key, "state": "unknown", "title": rule.title,
                "region": ",".join(unread), "severity": "unknown", "members": [],
                "resource": "unread regions", "fix": rule.fix,
                "why": "cannot evaluate in %d of %d enabled region(s) — %s "
                       "were never read, so this answer does not cover them"
                       % (len(unread), len(data.get("regions_enabled") or unread),
                          ", ".join(unread))})
    return out


def _region_inventory(g: "CloudGraph") -> dict:
    """One region reduced to the numbers an operator reads first.

    Deliberately not a resource dump. The counts that matter are the ones with
    a security meaning attached — how many subnets actually route to the
    internet, how many groups admit the whole world, how many instances answer
    on a public address — because a list of four hundred resource ids is data
    and these are information."""
    pub = public_subnets(g)
    open_groups, risky_groups, open_ports = [], [], set()
    for gid, group in g.groups.items():
        rules = _world_open_ports(group)
        if not rules:
            continue
        open_groups.append(gid)
        named = _named_exposed_ports(rules)
        if named:
            # World-open on an administrative or database port. A group open
            # to everyone on 443 is a web server doing its job; keeping the
            # two counts apart is the same restraint the rules use, and for
            # the same reason -- a tile that reddens for every default VPC
            # teaches the reader to stop looking at it.
            risky_groups.append(gid)
            open_ports.update(named)
    running = [i for i in g.instances
               if str(i.get("State", "")).lower() == "running"]
    public_instances = [i for i in running if _instance_public_ip(g, i)]
    return {
        "region": g.region,
        "vpcs": len(g.vpcs),
        "subnets": len(g.subnets),
        "public_subnets": len(pub),
        "route_tables": len(g.route_tables),
        "igws": len(g.igws),
        "groups": len(g.groups),
        "world_open_groups": len(open_groups),
        "risky_open_groups": len(risky_groups),
        "world_open_ports": sorted(open_ports),
        "enis": len(g.enis),
        "instances": len(g.instances),
        "running": len(running),
        "public_instances": len(public_instances),
        "unreadable": sorted(g.unreadable),
    }


# The domains the Cloud page groups by. Each is a heading an operator already
# thinks in — "what is my network", "what is running", "who can do what" —
# rather than a list of API call names.
INVENTORY_DOMAINS = (
    ("network", "Network", ("vpcs", "subnets", "route_tables", "igws",
                            "groups")),
    ("exposure", "Exposure", ("public_subnets", "world_open_groups",
                              "risky_open_groups", "public_instances")),
    ("compute", "Compute", ("instances", "running", "enis")),
    ("access", "Access", ("roles", "broad_roles", "unevaluated_roles")),
)

# What each counted thing is called on screen, and whether a non-zero count is
# a neutral fact or something to look at. Exposure counts are not findings --
# a public subnet is ordinary -- but they are the denominator every cloud
# finding is drawn from, so they are shown in their own colour.
# ("label on screen", weight). Three weights, not a boolean:
#   ""     a plain fact -- how many VPCs there are is not good or bad
#   "note" the denominator exposure is drawn from. A default VPC's subnets all
#          route to the internet; that is ordinary AWS and reddening it would
#          make every account look on fire.
#   "warn" worth acting on today.
INVENTORY_LABELS = {
    "vpcs": ("VPCs", ""), "subnets": ("subnets", ""),
    "route_tables": ("route tables", ""), "igws": ("internet gateways", ""),
    "groups": ("security groups", ""),
    "public_subnets": ("subnets that route to the internet", "note"),
    "world_open_groups": ("groups open to 0.0.0.0/0", "note"),
    "risky_open_groups": ("groups open on an admin or database port", "warn"),
    "public_instances": ("instances answering on a public address", "warn"),
    "instances": ("EC2 instances", ""), "running": ("running", ""),
    "enis": ("network interfaces", ""),
    "roles": ("roles on instances", ""),
    "broad_roles": ("carrying more than read", "warn"),
    "unevaluated_roles": ("not fully readable", "note"),
}


def inventory_summary(data: dict) -> dict:
    """Aggregate one inventory read into what the Cloud page shows.

    Written because the first real run examined three hundred and eighteen
    resources across seventeen regions and the screen said "0 findings". That
    is true and it is useless: the operator asked what is out there, and the
    tool had the answer in a raw file and showed a zero. An inventory is worth
    seeing whether or not a rule fired on it."""
    regions = [r for r in _names(data.get("regions_read")) if isinstance(r, str)]
    per_region = [_region_inventory(build_cloud_graph(data, r)) for r in regions]
    totals: Dict[str, int] = {}
    for row in per_region:
        for key, value in row.items():
            if isinstance(value, int):
                totals[key] = totals.get(key, 0) + value
    ports: set = set()
    for row in per_region:
        ports.update(row["world_open_ports"])

    roles = _mapping(data.get("roles"))
    totals["roles"] = len(roles)
    totals["broad_roles"] = sum(1 for r in roles.values()
                                if isinstance(r, dict) and r.get("broad"))
    # A role with a policy nobody could open is not a role known to be
    # limited. Counted separately, and named in the caveats, because "0
    # carrying more than read" over roles that were never fully read is the
    # same claim as "no findings" over a scanner that never ran.
    totals["unevaluated_roles"] = sum(
        1 for r in roles.values()
        if isinstance(r, dict) and (r.get("unevaluated") or r.get("status") != "ok"))
    unreadable_roles = sum(1 for r in roles.values()
                           if isinstance(r, dict) and r.get("status") != "ok")
    broad_reasons: List[str] = []
    for role_name, row in sorted(roles.items()):
        if isinstance(row, dict):
            for reason in (row.get("broad") or []):
                broad_reasons.append("%s: %s" % (role_name, reason))

    enabled = [r for r in _names(data.get("regions_enabled")) if isinstance(r, str)]
    unread = [r for r in _names(data.get("regions_unread")) if isinstance(r, str)]
    domains = []
    for key, label, fields in INVENTORY_DOMAINS:
        # No zip: ruff wants an explicit `strict=`, which Python 3.9 does not
        # have, and the floor this tool runs on is 3.9.
        items: List[dict] = []
        total = 0
        for field in fields:
            count = totals.get(field, 0)
            total += count
            items.append({"key": field, "label": INVENTORY_LABELS[field][0],
                          "weight": INVENTORY_LABELS[field][1], "count": count})
        domains.append({"key": key, "label": label, "items": items,
                        "total": total})
    return {
        "account": as_text(data.get("account")),
        "read_as": as_text(data.get("read_as")),
        "read_at": as_text(data.get("read_at")),
        "api_calls": data.get("api_calls") or 0,
        "elapsed_seconds": data.get("elapsed_seconds") or 0,
        "regions_active": sum(1 for r in per_region
                              if not _is_untouched_default(r)
                              and (r["vpcs"] or r["instances"])),
        # A region read with a denial in it is neither "read" nor "never
        # reached". It had its own third answer and nothing on the page said
        # so, so "nothing was skipped" printed over regions where something
        # had been (review R-10).
        "regions_denied": sorted(r["region"] for r in per_region
                                 if r["unreadable"]),
        "regions_enabled": len(enabled),
        "regions_read": len(regions),
        "regions_unread": unread,
        "resources": sum(totals.get(k, 0) for k in
                         ("vpcs", "subnets", "route_tables", "igws", "groups",
                          "enis", "instances")),
        "totals": totals,
        "world_open_ports": sorted(ports),
        "unreadable_roles": unreadable_roles,
        "broad_reasons": broad_reasons,
        "domains": domains,
        "regions": per_region,
    }


def _is_untouched_default(row: dict) -> bool:
    """A region holding nothing but the default VPC AWS creates for you.

    One VPC, no instances, no interfaces, and no group admitting the world on
    anything that matters. Sixteen such rows in a seventeen-row table is not
    seventeen facts, it is one fact and sixteen repetitions -- and a table a
    reader scrolls past is a table that hides the row that mattered."""
    return (row["vpcs"] <= 1 and not row["instances"] and not row["enis"]
            and not row["risky_open_groups"] and row["groups"] <= 1
            and not row["unreadable"])                    # a denial keeps a row


def split_regions(summary: dict) -> Tuple[List[dict], List[dict]]:
    """(regions worth a row of their own, regions that are just a default VPC).

    The second list is not hidden -- it is summarised, and it carries a real
    observation of its own: an untouched default VPC in a region nothing runs
    in is a standing recommendation to remove, and a place where anything
    launched by accident lands on a public subnet."""
    # A region whose read was refused is a row of its own whatever its counts,
    # because the "Could not read" column has to have something to show. A
    # denied region folded into "16 regions hold nothing but the default VPC"
    # is a denial rendered as an absence.
    rows = [r for r in summary.get("regions", [])
            if r["vpcs"] or r["instances"] or r["world_open_groups"]
            or r["unreadable"]]
    kept = [r for r in rows if not _is_untouched_default(r)]
    default_only = [r for r in rows if _is_untouched_default(r)]
    kept.sort(key=lambda r: (-r["public_instances"], -r["risky_open_groups"],
                             -r["instances"], r["region"]))
    default_only.sort(key=lambda r: r["region"])
    return kept, default_only


# A reading older than this is described as what the estate WAS. Not a
# failure -- an estate changes, and a snapshot cannot know what happened after
# it was taken. Twelve hours because a working day either side of it is the
# span over which "I looked this morning" stops being true.
READING_STALE_HOURS = 12


def reading_age(summary: dict, now: "Optional[float]" = None) -> "Optional[float]":
    """Hours since this reading was taken, or None if it did not say."""
    stamp = as_text(summary.get("read_at"))
    if not stamp:
        return None
    try:
        taken = calendar.timegm(time.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        return None
    return max(0.0, ((now if now is not None else time.time()) - taken) / 3600.0)


def headline_facts(summary: dict) -> List[dict]:
    """The few numbers worth reading before any of the others.

    Each is {value, label, weight, note}. `weight` drives colour the same way
    the tiles do, and a fact that could not be established says so in its value
    rather than showing a zero -- an unknown and a zero are different answers
    and must not print the same (I1)."""
    t = summary.get("totals") or {}
    out: List[dict] = []
    active = summary.get("regions_active", 0)
    out.append({"key": "regions", "value": str(active),
                "label": "region(s) actually in use",
                "weight": "", "note": "of %d read" % summary.get("regions_read", 0)})
    out.append({"key": "instances", "value": str(t.get("running", 0)),
                "label": "running instances", "weight": "",
                "note": "%d interface(s)" % t.get("enis", 0)})
    out.append({"key": "reachable", "value": str(t.get("public_instances", 0)),
                "label": "reachable from the internet", "weight": "warn",
                "note": "public address, public subnet, open group"})
    out.append({"key": "open", "value": "%d of %d" % (t.get("risky_open_groups", 0),
                                                      t.get("groups", 0)),
                "label": "groups open to the world on a risky port",
                "weight": "warn", "note": "%d open on any port"
                                          % t.get("world_open_groups", 0)})
    # "instance roles", not "roles". This tile counts the roles attached to
    # exposed instances -- a deliberately bounded lookup, six of them on the
    # owner's account -- and the IAM section further down the same page counts
    # all 140 and says ten of them can grant themselves more. Both are true
    # and they read as a contradiction, because only one of the two said which
    # population it was over. The domain card beside it and the prose below it
    # both say "roles on instances"; the headline tile was the outlier
    # (validation run, 2026-09-12).
    if t.get("unevaluated_roles"):
        out.append({"key": "roles", "value": "\u2265%d" % t.get("broad_roles", 0),
                    "label": "instance roles carrying more than read",
                    "weight": "warn",
                    "note": "a FLOOR \u2014 %d of %d instance role(s) not "
                            "fully readable"
                            % (t["unevaluated_roles"], t.get("roles", 0))})
    else:
        out.append({"key": "roles", "value": str(t.get("broad_roles", 0)),
                    "label": "instance roles carrying more than read",
                    "weight": "warn",
                    "note": "every policy on %d instance role(s) read \u2014 "
                            "the IAM section below counts every role in the "
                            "account" % t.get("roles", 0)})
    unread = summary.get("regions_unread") or []
    denied = summary.get("regions_denied") or []
    # "Nothing was skipped" may only print when BOTH are zero. A region that
    # was reached and then refused a read is not a region that was skipped,
    # and it is not a region that was read either.
    if unread:
        note = ", ".join(unread[:3])
    elif denied:
        note = "none skipped, but %d had a read refused" % len(denied)
    else:
        note = "nothing was skipped"
    out.append({"key": "unread", "value": str(len(unread)) if unread else "\u2014",
                "label": "region(s) never read",
                "weight": "warn" if unread else "", "note": note})
    out.append({"key": "denied",
                "value": str(len(denied)) if denied else "\u2014",
                "label": "region(s) with a read that was refused",
                "weight": "warn" if denied else "",
                "note": ", ".join(denied[:3]) if denied
                else "every read in every region answered"})
    return out


def inventory_notes(summary: dict) -> List[str]:
    """What this run positively learned, separate from what it could not.

    "1 role carrying more than read" is a number; "app-role-2: inline policy
    inline-admin allows every action" is something a person can go and fix.
    Kept apart from the caveats on purpose -- one list is what is true, the
    other is what is unknown, and merging them makes both easier to skip."""
    out = []
    for reason in summary.get("broad_reasons", [])[:8]:
        out.append("%s — an instance carries this role." % reason)
    extra = len(summary.get("broad_reasons", [])) - 8
    if extra > 0:
        out.append("... and %d more role/policy pair(s); the evidence has the "
                   "full list." % extra)
    t = summary.get("totals") or {}
    if t.get("risky_open_groups"):
        out.append("%d security group(s) admit 0.0.0.0/0 on an administrative "
                   "or database port." % t["risky_open_groups"])
    return out


def inventory_caveats(summary: dict) -> List[str]:
    """What this inventory does NOT let you conclude, in the reader's words.

    A run that examined three hundred resources and found nothing is a real
    result only if the rules had something to run against. Every rule shipped
    so far is about an EC2 instance, so an account with no instances got a
    clean answer from checks that never had a subject -- true, and exactly the
    shape of statement this tool exists to refuse to make silently (I1)."""
    out = []
    t = summary.get("totals") or {}
    if not t.get("instances"):
        out.append("No EC2 instances were found in any region read. Every "
                   "combination shipped so far is about an instance, so none "
                   "of them had a subject — this is not the same as an account "
                   "with nothing dangerous in it.")
    elif not t.get("public_instances"):
        out.append("No instance answers on a public address, so the "
                   "reachability combinations had nothing to join.")
    if t.get("risky_open_groups") and not t.get("public_instances"):
        out.append("%d security group(s) admit 0.0.0.0/0 on an administrative "
                   "or database port with no instance currently reachable "
                   "behind them. That is latent, not live — the exposure is "
                   "waiting for whatever launches into it next."
                   % t["risky_open_groups"])
    if t.get("unevaluated_roles"):
        out.append("%d of %d role(s) on instances have at least one policy that "
                   "could not be read, so \u201c%d carrying more than read\u201d "
                   "is a floor. A role is only called limited when every policy "
                   "attached to it was actually opened."
                   % (t["unevaluated_roles"], t.get("roles", 0),
                      t.get("broad_roles", 0)))
    elif t.get("roles") and not t.get("broad_roles"):
        out.append("Every policy on all %d instance role(s) was read, and none "
                   "carries more than read — no wildcard action, and no "
                   "allow-everything-except written as NotAction, which is how "
                   "PowerUserAccess is written. That is a real negative, not an "
                   "absence of looking." % t["roles"])
    if summary.get("regions_unread"):
        out.append("%d region(s) were never read: %s. Nothing here covers them."
                   % (len(summary["regions_unread"]),
                      ", ".join(summary["regions_unread"][:8])))
    denied = summary.get("regions_denied") or []
    if denied:
        out.append("%d region(s) answered some reads and refused others: %s. "
                   "Every count above is short by whatever was in them."
                   % (len(denied), ", ".join(denied[:6])))
    _kept, default_only = split_regions(summary)
    if len(default_only) >= 3:
        out.append("%d region(s) contain nothing but the default VPC AWS "
                   "created there: %s. Nothing runs in them, and anything "
                   "launched into one lands on a subnet that routes straight "
                   "to the internet."
                   % (len(default_only),
                      ", ".join(r["region"] for r in default_only[:6])
                      + (" and %d more" % (len(default_only) - 6)
                         if len(default_only) > 6 else "")))
    out.append("This section is the networking and compute picture. Storage, "
               "the IAM graph, serverless, containers and data services are "
               "each read in a section of their own, so a count here is not a "
               "whole-account count.")
    out.extend(partial_caveat(summary))
    return out


# Account-wide services, in the order an operator would ask about them.
ACCOUNT_SERVICES = (
    ("cloudtrail", "CloudTrail", "records every API call made in the account"),
    ("root", "Root account", "MFA on the root user, and whether it has keys"),
    ("s3block", "S3 public access", "the account-wide block, above every bucket"),
    ("password", "Password policy", "the floor for any console user"),
)

def enablement_summary(data: dict) -> dict:
    """One row per service: its state across the account, and where it is not on.

    A regional service is rolled up with its denominator kept — "on in 1 of 17
    regions" is a different statement from "on", and this tool has no business
    printing the second when the first is true."""
    regional = _mapping(data.get("regional"))
    read = regions_seen(data)
    rows: List[dict] = []
    for key, label, what in ENABLEMENT_LABELS:
        per = [(region, (regional.get(region) or {}).get(key) or {})
               for region in read]
        on = [r for r, v in per if v.get("state") == "on"]
        partial = [r for r, v in per if v.get("state") == "partial"]
        unknown = [r for r, v in per if v.get("state") == "unknown"]
        off = [r for r, v in per if v.get("state") == "off"]
        state = _roll_up(len(on) + len(partial), len(per), len(unknown))
        detail = ""
        if per:
            detail = "%d of %d region(s)" % (len(on) + len(partial), len(per))
        sample = next((v.get("detail", "") for _r, v in per if v.get("detail")), "")
        # BOTH, never one or the other. The first version used `elif`, so a
        # service that was off in four regions and UNREADABLE in a fifth
        # reported only the four -- the region nobody could see vanished
        # behind the regions we could. Off and "could not tell" are answers to
        # different questions and both have to be said (measured against a
        # stub with a denied region, 2026-09-09).
        parts = []
        if off:
            parts.append("off in %s" % _named(off))
        if unknown:
            parts.append("could not tell in %s" % _named(unknown))
        note = " \u00b7 ".join(parts)
        rows.append({"key": key, "label": label, "what": what, "state": state,
                     "detail": detail, "note": note, "sample": sample,
                     "on": on, "off": off, "unknown": unknown,
                     "scope": "regional"})

    # The enablement reading uses `account` for the per-service map, and
    # every other reading uses it for the account id -- so this one is a
    # dict here and a string everywhere else, and a mixed-up file made it a
    # string here (review R-14).
    account = _mapping(data.get("account"))
    for key, label, what in ACCOUNT_SERVICES:
        row = _mapping(account.get(key))
        rows.append({"key": key, "label": label, "what": what,
                     "state": row.get("state", "unknown"),
                     "detail": "account-wide", "note": "",
                     "sample": row.get("detail", ""),
                     "on": [], "off": [], "unknown": [], "scope": "account"})
    return {
        "account": as_text(data.get("account_id")),
        "read_as": as_text(data.get("read_as")),
        "read_at": as_text(data.get("read_at")),
        "api_calls": data.get("api_calls") or 0,
        "elapsed_seconds": data.get("elapsed_seconds") or 0,
        "regions_read": len(read) - len(_names(data.get("regions_partial"))),
        "regions_partial": len(_names(data.get("regions_partial"))),
        "regions_enabled": len(_names(data.get("regions_enabled"))),
        "regions_unread": [r for r in _names(data.get("regions_unread"))
                           if isinstance(r, str)],
        "services": rows,
        "guardduty_features": _guardduty_features(regional, read),
    }


ENABLEMENT_LABELS = (
    ("guardduty", "GuardDuty", "watches for attacks in progress"),
    ("config", "AWS Config", "records what the account looked like, and when "
                             "it changed"),
    ("securityhub", "Security Hub", "aggregates control findings"),
    ("inspector", "Inspector", "scans workloads and images for known "
                               "vulnerabilities"),
    ("accessanalyzer", "Access Analyzer", "finds resources shared outside the "
                                          "account"),
)


def _roll_up(on: int, seen: int, unknown: int) -> str:
    """One word for a service across every region, without rounding a gap away.

    `on` here counts regions where it is on. A service on in every region we
    could READ, with one region we could not, is `partial` and not `on` -- the
    unread region is not evidence of anything, and calling the whole account
    covered on the strength of the regions that answered is the substitution
    this tool exists to refuse."""
    if seen == 0:
        return "unknown"
    if on == 0:
        return "unknown" if unknown == seen else "off"
    if on == seen and not unknown:
        return "on"
    return "partial"


def _named(regions: List[str], cap: int = 4) -> str:
    if len(regions) <= cap:
        return ", ".join(regions)
    return "%s and %d more" % (", ".join(regions[:cap]), len(regions) - cap)


def _guardduty_features(regional: dict, read: List[str]) -> dict:
    """Which GuardDuty features are on somewhere, and which are on nowhere.

    GuardDuty being "on" says nothing about whether it is looking at your
    runtime, your EKS audit logs or your S3 data events. The reference design
    the operator pointed at showed these as a strip of pills for exactly that
    reason: the headline hides the detail that decides what it can actually
    see."""
    on: set = set()
    off: set = set()
    for region in read:
        row = (regional.get(region) or {}).get("guardduty") or {}
        on.update(row.get("features_on") or [])
        off.update(row.get("features_off") or [])
    return {"on": sorted(on), "off": sorted(off - on)}


def watching_gaps(inventory: dict, enablement: dict) -> List[str]:
    """Where the account has something worth watching and nothing watching it.

    This is the join the whole plan is about, and it is only possible because
    both readings exist: exposure comes from the inventory, coverage from the
    enablement read. Neither alone can say it."""
    out: List[str] = []
    if not inventory or not enablement:
        return out
    active = {r["region"] for r in inventory.get("regions", [])
              if r["instances"] or r["risky_open_groups"] or r["public_instances"]}
    # A region whose reads were refused has zero instances and zero open groups
    # in the summary, so it fell out of `active` and GuardDuty being off there
    # went unsaid -- the region nobody could see treated as the region with
    # nothing in it (review R-10).
    denied = {r["region"] for r in inventory.get("regions", [])
              if r.get("unreadable")} - active
    if not active and not denied:
        return out
    by_key = {row["key"]: row for row in enablement.get("services", [])}
    for key, label in (("guardduty", "GuardDuty"), ("config", "AWS Config"),
                       ("securityhub", "Security Hub")):
        row = by_key.get(key)
        if not row:
            continue
        blind = sorted(active.intersection(row.get("off", [])))
        if blind:
            out.append("%s is off in %s, and %s running or exposed resources."
                       % (label, _named(blind),
                          "that region has" if len(blind) == 1
                          else "those regions have"))
        murky = sorted(active.intersection(row.get("unknown", [])))
        if murky:
            out.append("%s could not be read in %s, where resources are "
                       "running — that is unknown, not clear."
                       % (label, _named(murky)))
        unseen = sorted(denied.intersection(row.get("off", [])))
        if unseen:
            out.append("%s is off in %s, where part of the inventory could not "
                       "be read — whether there is anything there to watch is "
                       "unknown, so this is not covered by the line above."
                       % (label, _named(unseen)))
    return out


# --------------------------------------------------------------------------- #
# What changed between two readings.
#
# The ordering here is a claim about how people read: a count that moved is a
# QUESTION ("why are there three more subnets?") and a named thing that
# appeared or vanished is usually the ANSWER ("because subnet-0ab, subnet-0cd
# and subnet-0ef were created"). So named things come first and counts follow,
# rather than the other way round, which is how most tools show a diff and why
# most diffs need a second tool to interpret.
#
# And the third list is the one that makes the other two trustworthy. Two
# readings can only be compared where both actually looked. A region denied
# last time and read this time has not "changed" -- nothing is known about its
# past -- and saying "no change" there would be the same lie as reporting a
# scanner that never ran as a scanner that found nothing.
# --------------------------------------------------------------------------- #

# The field that names each kind of resource, so a thing can be tracked between
# readings rather than merely counted.
ID_FIELDS = (
    ("instances", "InstanceId", "instance"),
    ("security-groups", "GroupId", "security group"),
    ("vpcs", "VpcId", "VPC"),
    ("subnets", "SubnetId", "subnet"),
    ("internet-gateways", "InternetGatewayId", "internet gateway"),
    ("route-tables", "RouteTableId", "route table"),
)

# Counts worth following between readings, and whether a RISE is bad news.
TRACKED_COUNTS = (
    ("public_instances", "instances answering on a public address", True),
    ("risky_open_groups", "groups open to the world on a risky port", True),
    ("world_open_groups", "groups open to 0.0.0.0/0", True),
    ("broad_roles", "roles carrying more than read", True),
    ("unevaluated_roles", "roles not fully readable", True),
    ("public_subnets", "subnets that route to the internet", False),
    ("instances", "EC2 instances", False),
    ("running", "running instances", False),
    ("groups", "security groups", False),
    ("subnets", "subnets", False),
    ("vpcs", "VPCs", False),
    # These four are on the page and were not diffed. A real reading went from
    # 106 network interfaces to 107 and the comparison said "Nothing changed,
    # over readings that covered the same ground both times" — a positive claim
    # of no change, not an absence of news (the operator's run, 2026-09-15).
    #
    # `enis` and `roles` were blind on both paths: neither is in `ID_FIELDS`
    # either, so a new one appeared under no heading at all. `igws` and
    # `route_tables` were caught by name and not by count, which is half an
    # answer — a count that moved is a question and a named thing is the
    # answer, and this file says so a few lines down.
    ("enis", "network interfaces", False),
    ("roles", "roles on instances", False),
    ("igws", "internet gateways", False),
    ("route_tables", "route tables", False),
)


def _named_things(data: dict) -> Dict[Tuple[str, str], str]:
    """Every resource in a reading, as {(kind, id): region}."""
    out: Dict[Tuple[str, str], str] = {}
    resources = _mapping(data.get("resources"))
    for region, per in resources.items():
        if not isinstance(per, dict):
            continue
        for key, field, label in ID_FIELDS:
            for row in _rows(per.get(key)):
                ident = str(row.get(field, ""))
                if ident:
                    out[(label, ident)] = str(region)
    return out


def _comparable_regions(older: dict, newer: dict) -> Tuple[set, List[str]]:
    """Regions both readings actually read, and why the others cannot be
    compared. A region missing from either side is not unchanged."""
    old_read = {r for r in _names(older.get("regions_read")) if isinstance(r, str)}
    new_read = {r for r in _names(newer.get("regions_read")) if isinstance(r, str)}
    both = old_read & new_read
    why: List[str] = []
    only_new = sorted(new_read - old_read)
    only_old = sorted(old_read - new_read)
    if only_new:
        why.append("%s read this time but not last time — anything there is new "
                   "to the reading, not necessarily new to the account"
                   % _named(only_new))
    if only_old:
        why.append("%s read last time but not this time — nothing here covers "
                   "them now" % _named(only_old))
    # A read that failed on either side makes that region's detail untrustworthy
    # even when the region itself appears on both.
    for label, data in (("last time", older), ("this time", newer)):
        for region, per in _mapping(data.get("reads")).items():
            if region not in both or not isinstance(per, dict):
                continue
            broken = sorted(k for k, v in per.items()
                            if isinstance(v, dict)
                            and v.get("status") in ("error", "unread"))
            if broken:
                why.append("%s in %s: %s could not be read, so a difference "
                           "there would be a difference in what we could see"
                           % (region, label, ", ".join(broken)))
                both.discard(region)
    return both, why


def compare_readings(older: dict, newer: dict,
                     old_enable: "Optional[dict]" = None,
                     new_enable: "Optional[dict]" = None) -> dict:
    """Two inventory readings, and what is genuinely different between them."""
    both, incomparable = _comparable_regions(older, newer)
    old_named = {k: v for k, v in _named_things(older).items() if v in both}
    new_named = {k: v for k, v in _named_things(newer).items() if v in both}

    appeared = [{"kind": kind, "id": ident, "region": new_named[(kind, ident)]}
                for (kind, ident) in sorted(set(new_named) - set(old_named))]
    vanished = [{"kind": kind, "id": ident, "region": old_named[(kind, ident)]}
                for (kind, ident) in sorted(set(old_named) - set(new_named))]

    old_sum = inventory_summary(older)
    new_sum = inventory_summary(newer)
    moved = []
    for key, label, rise_is_bad in TRACKED_COUNTS:
        before = (old_sum.get("totals") or {}).get(key, 0)
        after = (new_sum.get("totals") or {}).get(key, 0)
        if before == after:
            continue
        delta = after - before
        moved.append({"key": key, "label": label, "before": before,
                      "after": after, "delta": delta,
                      "weight": "warn" if (rise_is_bad and delta > 0) else ""})

    watching = _enablement_changes(old_enable or {}, new_enable or {})
    apart = None
    old_at = reading_age({"read_at": as_text(older.get("read_at"))})
    new_at = reading_age({"read_at": as_text(newer.get("read_at"))})
    if old_at is not None and new_at is not None:
        apart = abs(old_at - new_at)
    return {
        "from": as_text(older.get("read_at")), "to": as_text(newer.get("read_at")),
        "apart_hours": apart,
        "appeared": appeared, "vanished": vanished, "moved": moved,
        "watching": watching, "incomparable": incomparable,
        "changes": len(appeared) + len(vanished) + len(moved) + len(watching),
    }


def _enablement_changes(older: dict, newer: dict) -> List[dict]:
    """A security service that changed state in a region.

    The single most important line this diff can produce. A detector switched
    off in a region is not a count moving — it is somebody's decision, or an
    accident, and either way it is the thing to say first."""
    out: List[dict] = []
    old_regional = _mapping(older.get("regional"))
    new_regional = _mapping(newer.get("regional"))
    for region in sorted(set(old_regional) & set(new_regional)):
        old_per = old_regional.get(region) or {}
        new_per = new_regional.get(region) or {}
        if not isinstance(old_per, dict) or not isinstance(new_per, dict):
            continue
        for key, label, _what in ENABLEMENT_LABELS:
            before = str((old_per.get(key) or {}).get("state", ""))
            after = str((new_per.get(key) or {}).get("state", ""))
            if not before or not after or before == after:
                continue
            if "unknown" in (before, after):
                # Not a change in the account -- a change in what we could see.
                # Reporting it as "GuardDuty turned off" would be a fabrication.
                out.append({"label": label, "region": region, "before": before,
                            "after": after, "weight": "",
                            "why": "what we could see changed, not necessarily "
                                   "the account"})
                continue
            out.append({"label": label, "region": region, "before": before,
                        "after": after,
                        "weight": "warn" if after == "off" else "",
                        "why": ""})
    return out


def diff_lines(diff: dict) -> List[str]:
    """The comparison as text, for the terminal."""
    if not diff:
        return []
    out = ["", "What changed since the last reading — %d change(s)%s"
           % (diff["changes"],
              (", %.1fh apart" % diff["apart_hours"])
              if diff.get("apart_hours") is not None else "")]
    for row in diff["watching"]:
        out.append("  %s in %s: %s → %s%s"
                   % (row["label"], row["region"], row["before"], row["after"],
                      (" (%s)" % row["why"]) if row["why"] else ""))
    for row in diff["appeared"][:10]:
        out.append("  appeared: %s %s in %s"
                   % (row["kind"], row["id"], row["region"]))
    for row in diff["vanished"][:10]:
        out.append("  vanished: %s %s in %s"
                   % (row["kind"], row["id"], row["region"]))
    extra = len(diff["appeared"]) + len(diff["vanished"]) - 20
    if extra > 0:
        out.append("  ... and %d more named change(s); the evidence has them all"
                   % extra)
    for row in diff["moved"]:
        out.append("  %s: %d → %d (%+d)"
                   % (row["label"], row["before"], row["after"], row["delta"]))
    if diff["incomparable"]:
        out.append("  could not be compared:")
        for why in diff["incomparable"]:
            out.append("    - %s" % why)
    if not diff["changes"] and not diff["incomparable"]:
        out.append("  Nothing changed, over readings that covered the same "
                   "ground both times.")
    return out


# How old an access key has to be before its age is part of the finding. Ninety
# days is the common rotation floor; the number is named here so a reader can
# see it rather than infer it from a verdict.
KEY_STALE_DAYS = 90


def _key_age_days(created: str, now: "Optional[float]" = None) -> "Optional[float]":
    stamp = as_text(created)[:19].replace(" ", "T").rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            made = calendar.timegm(time.strptime(stamp, fmt))
        except ValueError:
            continue
        return max(0.0, ((now if now is not None else time.time()) - made) / 86400.0)
    return None


def iam_findings(data: dict) -> List[dict]:
    """Users whose credentials are not guarded, and why.

    Two rules, and the same supersedes discipline as the reachability pair: a
    user with no MFA is worth saying; a user with no MFA who can also grant
    itself more is a different sentence, and printing both for one user would
    be two findings for one fix list."""
    out: List[dict] = []
    for user in _rows(data.get("users")):
        name = as_text(user.get("name"))
        mfa = user.get("mfa")
        keys = [k for k in _rows(user.get("keys"))
                if str(k.get("status", "")).lower() == "active"]
        escalation = [as_text(r) for r in (user.get("escalation") or [])]
        unreadable = [as_text(r) for r in (user.get("unreadable") or [])]

        if mfa is None:
            # Not "no MFA" -- we could not look. Different answer, said as one.
            out.append({"key": "credential-unreadable", "state": "unknown",
                        "user": name, "severity": "unknown",
                        "why": "could not read %s for %s, so whether this "
                               "credential is guarded is unknown"
                               % (", ".join(unreadable) or "MFA", name),
                        "members": [name], "fix": ""})
            continue
        if mfa:
            continue                      # guarded; nothing to say

        aged = []
        for key in keys:
            age = _key_age_days(key.get("created", ""))
            if age is not None and age >= KEY_STALE_DAYS:
                aged.append("%s is %d days old"
                            % (mask_key_id(key.get("id", "?")), int(age)))
        console = user.get("console")
        if not keys and console is False:
            # Nothing MFA would have guarded: no console password, no key. Said
            # here rather than skipped, because the tile counts this user among
            # those without a device and a count nothing explains is a count
            # nobody believes.
            #
            # This branch used to require no escalation as well, so a user with
            # no credential at all and a permissive policy fell past it into
            # credential-without-a-guard at CRITICAL: "has no MFA device, and
            # it can grant itself more". There is no credential for MFA to
            # guard, and the alarm was about one that does not exist (review
            # R-9). The permissions are still worth saying -- they are what
            # makes the first key someone creates matter -- so they are said
            # here, at the severity of a thing that has not happened yet.
            why = ("user %s has no MFA device, and also no console password "
                   "and no active access key — there is nothing for MFA to "
                   "guard" % name)
            if escalation:
                why += ("; it does carry %d permission(s) that would let it "
                        "grant itself more, which would start to matter the "
                        "day someone creates a key for it" % len(escalation))
            out.append({"key": "credential-nothing-to-guard", "state": "noted",
                        "user": name, "severity": "info", "why": why,
                        "members": [name], "escalation": escalation,
                        "fix": ("Take the permission away, or leave it and know "
                                "that creating a key for this user is the whole "
                                "of the change." if escalation else "")})
            continue
        if not keys and console is None:
            out.append({"key": "credential-unreadable", "state": "unknown",
                        "user": name, "severity": "unknown",
                        "why": "user %s has no MFA device and no access key, "
                               "and whether it has a console password could "
                               "not be read — so whether anything is exposed "
                               "here is unknown" % name,
                        "members": [name], "escalation": escalation, "fix": ""})
            continue

        members = [name] + [mask_key_id(k.get("id", "")) for k in keys]
        detail = "user %s has no MFA device" % name
        if console:
            detail += ", a console password"
        if keys:
            detail += " and %d active access key(s)" % len(keys)
        if aged:
            detail += " (%s)" % "; ".join(aged)

        if escalation:
            out.append({
                "key": "credential-without-a-guard", "state": "fired",
                "user": name, "severity": "critical",
                # The reasons are carried in `escalation`, not repeated here.
                # The panel lists them and the finding detail keeps them;
                # inlining them as well printed each one twice on screen.
                "why": "%s, and it can grant itself more — %d way(s)"
                       % (detail, len(escalation)),
                "members": members, "escalation": escalation,
                "fix": "Enable MFA on this user, rotate or remove its access "
                       "keys, and take away the permission that lets it change "
                       "its own access — the third is the one that makes the "
                       "first two matter."})
        else:
            out.append({
                "key": "credential-without-mfa", "state": "fired",
                "user": name, "severity": "high",
                "why": detail, "members": members, "escalation": [],
                "fix": "Enable MFA on this user, and rotate or remove access "
                       "keys it does not need."})
    return out


# A role reachable this widely is reachable by somebody who is not you.
OUTSIDE_REACH = ("anyone", "external")

# `federated` was one word for nine different doors. The page printed it beside
# every GitHub Actions role on the operator's account, and the difference between
# a trust pinned to ONE REPOSITORY and one pinned to the whole organization is
# the entire risk: the second lets any repository in the org assume the role.
# `_federated_reach` has computed which it is since the GitHub reader was
# written, and no view rendered it. A fix that reaches no screen is the same
# defect as not computing it (CHARTER, consistency rules).
PIN_WORDS = {
    "github-repository": "one repo",
    "github-organisation": "ANY repo in the org",
    "saml": "SAML",
    "saml-unpinned": "SAML, no audience condition",
    "oidc": "OIDC",
    "oidc-unpinned": "OIDC, no condition",
    "cognito": "Cognito, signed in",
    "cognito-guest": "Cognito GUESTS",
    "cognito-pool": "Cognito, one pool",
    "condition": "a condition",
    "nothing": "nothing",
}


def reach_words(role: dict) -> str:
    """How a role is reached, in the fewest words that stay true.

    The reach alone is the headline; what PINS it is the thing a reader needs
    and the page was throwing away. Only the widest way in is described,
    because a role is as reachable as its loosest statement."""
    reach = as_text(role.get("reach")) or "?"
    widest = [t for t in _rows(role.get("trust"))
              if as_text(t.get("reach")) == reach]
    pin = as_text(widest[0].get("pin")) if widest else ""
    word = PIN_WORDS.get(pin, "")
    return "%s · %s" % (reach, word) if word else reach

# Kinds where AWS calling a resource public means a credential or a key is
# usable by anyone, rather than data being readable by anyone. Assuming a role
# gives an outsider the account's own hands; using a key gives them every
# ciphertext it protects; reading a secret gives them whatever is in it. By the
# scale's own critical paragraph -- a verified path, with nothing left in the
# way, where every leg was read -- those are critical, and the IAM reader
# already files an administrative role reachable from outside that way
# (review 2, R-34).
PUBLIC_IS_A_CREDENTIAL = (
    "AWS::IAM::Role",
    "AWS::KMS::Key",
    "AWS::SecretsManager::Secret",
)


def role_findings(data: dict) -> List[dict]:
    """Roles that can grant themselves more AND can be assumed from outside.

    Either alone is ordinary. Plenty of deploy roles hold `iam:PassRole`, and
    plenty of roles are assumable by a federated provider — that is what they
    are for. The combination is a path from outside the account to more
    permission than the role was given, and no single check reports it because
    the two halves live in different documents: one in the role's policies, the
    other in its trust policy."""
    out: List[dict] = []
    for role in _rows(data.get("roles_with_escalation")):
        reach = as_text(role.get("reach"))
        if reach not in OUTSIDE_REACH:
            continue
        trust = [t for t in _rows(role.get("trust"))
                 if as_text(t.get("reach")) == reach]
        why = as_text(trust[0].get("why")) if trust else reach
        out.append({
            "key": "escalation-reachable-from-outside", "state": "fired",
            "role": as_text(role.get("name")), "severity":
                "critical" if reach == "anyone" else "high",
            "reach": reach, "why": why,
            "escalation": [as_text(r) for r in (role.get("escalation") or [])],
            "fix": "Narrow the trust policy so only the principal that should "
                   "assume this role can, and take away the permission that "
                   "lets it grant itself more. The trust policy is the half "
                   "that decides who reaches it."})
    # An already-administrative role reachable from outside is worse still: it
    # has nothing to escalate to because it is already everything.
    for role in _rows(data.get("roles_already_admin")):
        reach = as_text(role.get("reach"))
        if reach not in OUTSIDE_REACH:
            continue
        trust = [t for t in _rows(role.get("trust"))
                 if as_text(t.get("reach")) == reach]
        out.append({
            "key": "administrative-reachable-from-outside", "state": "fired",
            "role": as_text(role.get("name")), "severity": "critical",
            "reach": reach,
            "why": as_text(trust[0].get("why")) if trust else reach,
            "escalation": [as_text(r) for r in (role.get("why") or [])],
            "fix": "This role is administrative and can be assumed from "
                   "outside the account. Narrow the trust policy first; the "
                   "permissions are the blast radius, the trust policy is the "
                   "door."})
    # Inside the organization is a third answer, and it is not a finding of the
    # same kind. `OrganizationAccountAccessRole` exists in every account AWS
    # Organizations creates, carries AdministratorAccess, and trusts the
    # management account's root -- so with only two answers, every member
    # account of every organization opened on a CRITICAL about the role AWS put
    # there (review 2, R-25). It is still stated, because an organization is a
    # trust boundary somebody decided on and a reader should see it.
    for bucket, kind in ((data.get("roles_already_admin"), "administrative"),
                         (data.get("roles_with_escalation"), "able to grant "
                                                             "itself more")):
        for role in _rows(bucket):
            if as_text(role.get("reach")) != "organization":
                continue
            trust = [t for t in _rows(role.get("trust"))
                     if as_text(t.get("reach")) == "organization"]
            out.append({
                "key": "role-assumable-within-the-organization",
                "state": "fired", "role": as_text(role.get("name")),
                "severity": "low", "reach": "organization",
                "why": "%s, and assumable from %s. That is inside the "
                       "organization this account belongs to, which the "
                       "organization section of this page read in the same "
                       "run — not a grant to a third party"
                       % (kind.capitalize(),
                          as_text(trust[0].get("why")) if trust
                          else "another account in this organization"),
                "escalation": [as_text(r) for r in
                               (role.get("why") or role.get("escalation") or [])],
                "fix": "Nothing, if the organization is the boundary you "
                       "meant. Check the account it trusts is the one you "
                       "think, and that the organization's own accounts are "
                       "as tightly held as this one."})
    # The fourth reach. The organization answered and its account list was
    # refused -- the ordinary member-account run -- so a role trusting another
    # account is neither a sibling nor a stranger. With only those two to
    # choose from it was a stranger, at CRITICAL, under a 7700 saying the
    # exposure is live (review 3, R-37). Unknown is the state for a question
    # the reading could not answer.
    for bucket, kind in ((data.get("roles_already_admin"), "administrative"),
                         (data.get("roles_with_escalation"), "able to grant "
                                                             "itself more")):
        for role in _rows(bucket):
            if as_text(role.get("reach")) != "unsettled":
                continue
            trust = [t for t in _rows(role.get("trust"))
                     if as_text(t.get("reach")) == "unsettled"]
            out.append({
                "key": "role-trust-unsettled",
                "role": as_text(role.get("name")), "severity": "unknown",
                "reach": "unsettled",
                "why": "%s, and assumable from %s. Whether that is a sibling "
                       "inside this organization or a stranger outside it is "
                       "the question the organization read could not answer, "
                       "so this is unknown — not a critical, and not nothing"
                       % (kind.capitalize(),
                          as_text(trust[0].get("why")) if trust
                          else "an account whose place in this organization "
                               "could not be settled"),
                "escalation": [as_text(r) for r in
                               (role.get("why") or role.get("escalation") or [])],
                "fix": "Grant organizations:ListAccounts to the audit "
                       "identity, or confirm by hand whether the trusted "
                       "account is in this organization."})
    return out


def iam_summary(data: dict) -> dict:
    """The IAM graph as the page shows it."""
    findings = iam_findings(data)
    users = _rows(data.get("users"))
    counts = _mapping(data.get("counts"))
    no_mfa = [u for u in users if u.get("mfa") == 0]
    with_keys = [u for u in users
                 if any(str(k.get("status", "")).lower() == "active"
                        for k in _rows(u.get("keys")))]
    unreadable = [u for u in users if u.get("mfa") is None]
    roles_esc = _rows(data.get("roles_with_escalation"))
    admin_roles = _rows(data.get("roles_already_admin"))
    reach_counts: Dict[str, int] = {}
    for role in roles_esc + admin_roles:
        reach = as_text(role.get("reach")) or "unknown"
        reach_counts[reach] = reach_counts.get(reach, 0) + 1
    # What the policy reader set aside rather than raised. Counted and shown,
    # because a permission the tool decided not to alarm about is still a
    # decision the reader is entitled to see -- and because a number that
    # exists in the evidence and nowhere on the page is a number nobody can
    # check.
    set_aside = sum(len(p.get("self_service") or []) + len(p.get("scoped") or [])
                    for p in users + roles_esc + admin_roles)
    return {
        "account": as_text(data.get("account")),
        "read_at": as_text(data.get("read_at")),
        "api_calls": data.get("api_calls") or 0,
        "truncated": bool(data.get("truncated")),
        "role_findings": role_findings(data),
        "reach_counts": reach_counts,
        "limit": data.get("limit") or 0,
        "counts": {"users": counts.get("users", 0), "roles": counts.get("roles", 0),
                   "groups": counts.get("groups", 0),
                   "policies": counts.get("policies", 0),
                   "users_without_mfa": len(no_mfa),
                   "users_with_keys": len(with_keys),
                   "users_unreadable": len(unreadable),
                   "roles_that_can_escalate": len(roles_esc),
                   "roles_already_admin": len(admin_roles),
                   "roles_reachable_from_outside": sum(
                       1 for r in roles_esc + admin_roles
                       if as_text(r.get("reach")) in OUTSIDE_REACH),
                   "permissions_set_aside": set_aside},
        "findings": findings,
        "roles_with_escalation": roles_esc,
        "roles_already_admin": _rows(data.get("roles_already_admin")),
    }


def iam_caveats(summary: dict) -> List[str]:
    """What the IAM read does not settle."""
    out = []
    c = summary.get("counts") or {}
    if summary.get("truncated"):
        out.append("The graph read stopped at %d principals and the account "
                   "holds more, so every count here is a floor. Raise "
                   "cloud_max_principals in a profile to read further."
                   % summary.get("limit", 0))
    if c.get("permissions_set_aside"):
        out.append("%d permission(s) were read and deliberately not raised: "
                   "an IAM action scoped to the holder's own user, or "
                   "iam:PassRole limited to named roles. They are grants, and "
                   "they are not paths to more — which is why the same actions "
                   "on every resource are listed above and these are not."
                   % c["permissions_set_aside"])
    if c.get("users_unreadable"):
        out.append("%d user(s) had MFA or key data that could not be read, so "
                   "they are unknown rather than guarded."
                   % c["users_unreadable"])
    elif c.get("users"):
        out.append("MFA and access keys were read for all %d user(s). A user "
                   "not named above is genuinely guarded, not merely unchecked."
                   % c["users"])
    unknown_reach = (summary.get("reach_counts") or {}).get("unknown", 0)
    if unknown_reach:
        out.append("%d role(s) had a trust policy that could not be read, so "
                   "who can assume them is unknown — not nobody."
                   % unknown_reach)
    # `unsettled` had a count, a card and a severity, and no line here. The two
    # states are different questions and both end in "not settled safe": an
    # unknown reach is a trust policy nobody could read, an unsettled one is a
    # policy that read cleanly and names an account this run could not place
    # against the organization. Saying the first and staying quiet about the
    # second leaves the louder of the two undeclared.
    unsettled_reach = (summary.get("reach_counts") or {}).get("unsettled", 0)
    if unsettled_reach:
        out.append("%d role(s) trust an account this run could not place, so "
                   "who can assume them is unsettled, not settled safe."
                   % unsettled_reach)
    out.append("Escalation is judged from policy documents as written. It does "
               "not simulate a request, so a permissions boundary, an SCP or a "
               "resource policy could stop a path this names — and none of "
               "those are read here.")
    out.append("Federated and SSO identities are not IAM users and carry no "
               "access keys, so they do not appear above; their permissions "
               "arrive through the roles they assume.")
    out.extend(partial_caveat(summary))
    return out


def edge_findings(data: dict) -> List[dict]:
    """Front doors that need no other reading to judge.

    A Lambda function URL with `AuthType: NONE` is a public HTTP endpoint —
    that is what the setting means, and no context makes it otherwise. Whether
    an internet-facing load balancer is dangerous depends on the groups in
    front of it, which live in a different reading, so that judgement is made
    in `edge_gaps` where both are in scope."""
    out: List[dict] = []
    for region, per in _mapping(data.get("regional")).items():
        if not isinstance(per, dict):
            continue
        for fn in _rows(per.get("urls")):
            auth = as_text(fn.get("auth")).upper()
            name = as_text(fn.get("name"))
            if auth == "NONE":
                cors = fn.get("cors") or []
                wide = [c for c in cors if as_text(c) == "*"]
                out.append({
                    "key": "lambda-url-without-auth", "resource": name,
                    "region": as_text(region), "severity": "high",
                    "title": "Lambda function URL open to the internet with no "
                             "authentication",
                    "why": "function %s has a URL with AuthType NONE — anyone "
                           "who knows the address can invoke it%s"
                           % (name,
                              ", and its CORS policy allows any origin"
                              if wide else ""),
                    "members": [name],
                    "fix": "Set AuthType to AWS_IAM and grant only the callers "
                           "that need it, or put the function behind an API "
                           "Gateway or CloudFront distribution that "
                           "authenticates. If it is deliberately public, the "
                           "function itself has to treat every request as "
                           "untrusted."})
            elif auth == "UNKNOWN":
                out.append({
                    "key": "lambda-url-unreadable", "resource": name,
                    "region": as_text(region), "severity": "unknown",
                    "title": "Lambda function URL that could not be read",
                    "why": "function %s has a URL configuration that could not "
                           "be read (%s), so whether it requires "
                           "authentication is unknown"
                           % (name, as_text(fn.get("why"))),
                    "members": [name], "fix": ""})
    return out


def edge_gaps(inventory: dict, edge: dict) -> List[dict]:
    """Internet-facing load balancers, judged against the groups in front.

    Needs both readings: the load balancer comes from the edge read and the
    security group rules from the inventory. An internet-facing load balancer
    on 443 is a web application doing its job; one admitting the world on a
    database port is a different thing entirely, and neither reading can tell
    them apart alone."""
    out: List[dict] = []
    if not edge:
        return out
    # An absent inventory is not a clean edge. With no inventory at all this
    # returned nothing -- which is every run made before the inventory stage
    # existed and every run whose file was pruned -- while an ERRORED inventory
    # produced the unjudged record. Same missing input, two answers, and the
    # quieter one was reached by the more common route (review R-10).
    groups: Dict[str, dict] = {}
    for region, per in _mapping(inventory.get("resources")).items():
        if not isinstance(per, dict):
            continue
        for group in _rows(per.get("security-groups")):
            groups["%s/%s" % (region, group.get("GroupId", ""))] = group
    for region, per in _mapping(edge.get("regional")).items():
        if not isinstance(per, dict):
            continue
        for lb in _rows(per.get("load_balancers")):
            if as_text(lb.get("scheme")) != "internet-facing":
                continue
            ports: set = set()
            seen_group = False
            for gid in (lb.get("groups") or []):
                found = groups.get("%s/%s" % (region, gid))
                if found is None:
                    continue
                group = found
                seen_group = True
                ports.update(_named_exposed_ports(_world_open_ports(group)))
            name = as_text(lb.get("name"))
            if ports:
                out.append({
                    "key": "internet-facing-lb-on-a-risky-port",
                    "resource": name, "region": as_text(region),
                    "severity": "high",
                    "title": "Internet-facing load balancer admitting the world "
                             "on an administrative or database port",
                    "why": "load balancer %s is internet-facing and its "
                           "security group admits 0.0.0.0/0 on %s"
                           % (name, ", ".join(sorted(ports))),
                    "members": [name, *(lb.get("groups") or [])],
                    "fix": "Narrow the security group to the ports the "
                           "application actually serves. A load balancer on 443 "
                           "is the job; one on a database port is a path."})
            elif not (lb.get("groups") or []):
                # A network load balancer has no security groups at all, which
                # is not "nothing admits the world" -- it is a question this
                # reading cannot answer, because the listeners are what decide
                # and they are not read. Producing nothing said "clean" about a
                # load balancer nobody had looked at (review R-10).
                out.append({
                    "key": "internet-facing-lb-listeners-unread",
                    "resource": name, "region": as_text(region),
                    "severity": "unknown",
                    "title": "Internet-facing load balancer with no security "
                             "group, listeners not read",
                    "why": "load balancer %s is internet-facing and carries no "
                           "security group — a network load balancer, where "
                           "what is reachable is decided by its listeners and "
                           "the groups on the targets behind it. Neither is "
                           "read, so this is unknown, not clear" % name,
                    "members": [name], "fix": ""})
            elif not seen_group:
                out.append({
                    "key": "internet-facing-lb-unjudged", "resource": name,
                    "region": as_text(region), "severity": "unknown",
                    "title": "Internet-facing load balancer whose security "
                             "groups were not read",
                    "why": "load balancer %s is internet-facing and its "
                           "security groups were not in the inventory reading, "
                           "so what it admits is unknown" % name,
                    "members": [name], "fix": ""})
    return out


def edge_summary(data: dict) -> dict:
    """The edge as the page shows it."""
    regional = _mapping(data.get("regional"))
    read = regions_seen(data)
    functions = sum(edge_function_count(regional.get(r) or {}) for r in read)
    urls = [dict(u, region=r) for r in read
            for u in _rows((regional.get(r) or {}).get("urls"))]
    lbs = [dict(lb, region=r) for r in read
           for lb in _rows((regional.get(r) or {}).get("load_balancers"))]
    facing = [lb for lb in lbs if as_text(lb.get("scheme")) == "internet-facing"]
    open_urls = [u for u in urls if as_text(u.get("auth")).upper() == "NONE"]
    unreadable = [u for r in read
                  for u in ((regional.get(r) or {}).get("unreadable") or [])]
    return {
        "account": as_text(data.get("account")),
        "read_at": as_text(data.get("read_at")),
        "api_calls": data.get("api_calls") or 0,
        "truncated": bool(data.get("truncated")),
        "regions_read": len(read) - len(_names(data.get("regions_partial"))),
        "regions_partial": len(_names(data.get("regions_partial"))),
        "regions_enabled": len(_names(data.get("regions_enabled"))),
        "regions_unread": [r for r in _names(data.get("regions_unread"))
                           if isinstance(r, str)],
        "counts": {"functions": functions, "urls": len(urls),
                   "urls_without_auth": len(open_urls),
                   "load_balancers": len(lbs),
                   "internet_facing": len(facing)},
        "open_urls": open_urls, "internet_facing": facing,
        "unreadable": unreadable,
    }


def interface_owners(inventory: dict) -> List[Tuple[str, int]]:
    """What owns each network interface, counted.

    A hundred and three interfaces against seven instances is the largest
    unexplained number this tool can show an operator, and the answer costs
    nothing extra — it was in the response all along."""
    counts: Dict[str, int] = {}
    for _region, per in _mapping(inventory.get("resources")).items():
        if not isinstance(per, dict):
            continue
        for eni in _rows(per.get("network-interfaces")):
            owner = eni_owner(eni)
            counts[owner] = counts.get(owner, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


# What a database's reachability read can conclude. `unknown` is not a
# failure: it is what the inventory not being in scope actually means, and it
# is the answer the review asked for rather than the flag alone reported as
# "reachable from the internet" (R-6).
class DatabaseReach(NamedTuple):
    state: str          # "reachable", "not-reachable" or "unknown"
    why: str            # the path, or what is missing from it


def database_reachability(db: dict, graph: "Optional[CloudGraph]"
                          ) -> DatabaseReach:
    """Whether a publicly-accessible database can actually be reached.

    `PubliclyAccessible` is the console wizard's default and, on its own, says
    only that AWS gave the instance a public DNS name. Reaching it also needs a
    security group on it admitting 0.0.0.0/0 on its port, and one of its
    subnets routing to an attached internet gateway. Both were already in the
    evidence and neither was read, so a Postgres instance whose group admits
    only the application tier was "reachable from the internet with unencrypted
    storage" at CRITICAL -- on most accounts, since the flag is the default."""
    if graph is None:
        return DatabaseReach("unknown", "the inventory reading is not in scope "
                                        "here, so the group and the subnet "
                                        "behind this flag were not read")
    missing = [key for key in ("security-groups", "subnets", "route-tables")
               if key in graph.unreadable]
    if missing:
        return DatabaseReach("unknown", "%s could not be read in %s, so what is "
                                        "in front of this database is unknown"
                                        % (", ".join(missing), graph.region))

    port = db.get("port")
    port = int(port) if isinstance(port, int) else None
    admitting = []
    for gid in (db.get("groups") or []):
        group = graph.groups.get(as_text(gid))
        if group is None:
            return DatabaseReach("unknown",
                                 "security group %s is not in the inventory "
                                 "reading, so what it admits is unknown"
                                 % as_text(gid))
        for proto, lo, hi in _world_open_ports(group):
            if proto not in REACHABLE_PROTOCOLS:
                continue
            if port is None or lo <= port <= hi:
                admitting.append(as_text(gid))
                break

    pub = public_subnets(graph)
    routed = [(as_text(sub), pub[as_text(sub)])
              for sub in (db.get("subnets") or []) if as_text(sub) in pub]

    if not (db.get("subnets") or []):
        return DatabaseReach("unknown", "no subnet is recorded for this "
                                        "database, so whether it sits behind a "
                                        "route to the internet is unknown")
    if admitting and routed:
        return DatabaseReach(
            "reachable",
            "%s admits 0.0.0.0/0 on %s and its subnet %s routes to %s"
            % ("/".join(admitting), "port %d" % port if port else "every port",
               routed[0][0], routed[0][1]))
    if not admitting and not routed:
        return DatabaseReach("not-reachable", "no group on it admits the "
                                              "internet and no subnet of it "
                                              "routes to an internet gateway")
    if not admitting:
        return DatabaseReach("not-reachable", "its subnet %s routes to %s, and "
                                              "no group on it admits 0.0.0.0/0 "
                                              "on %s"
                             % (routed[0][0], routed[0][1],
                                "port %d" % port if port else "its port"))
    return DatabaseReach("not-reachable", "%s admits 0.0.0.0/0, and no subnet "
                                          "of it routes to an internet gateway"
                         % "/".join(admitting))


def bucket_policy_held_shut(bucket: dict) -> "Optional[bool]":
    """Whether this bucket's OWN public access block stops a public policy.

    True when BlockPublicPolicy and RestrictPublicBuckets are both on, False
    when the settings were read and they are not, None when they were not read
    -- and None takes the stricter branch, because "we did not look" is not
    "it is open".

    A reading written before the four booleans were kept holds a count here.
    Four means all four were on, which answers the question; anything else
    cannot distinguish the two that matter from the two that do not, so it is
    unknown rather than guessed."""
    block = bucket.get("block")
    if isinstance(block, dict):
        return all(bool(block.get(key))
                   for key in squawk_probes.POLICY_BLOCK_SETTINGS)
    if isinstance(block, bool):
        return None
    if isinstance(block, int):
        return True if block == 4 else None
    return None


def storage_findings(data: dict,
                     inventory: "Optional[dict]" = None) -> List[dict]:
    """Buckets and databases that are exposed, and what makes them so.

    The account-wide S3 block is passed in because it changes what a per-bucket
    answer MEANS. With `BlockPublicPolicy` and `RestrictPublicBuckets` on, a
    bucket policy saying "public" does not make the bucket public — reporting
    it as live exposure would be true about the policy and false about the
    world. It is still worth saying, at a severity that reflects what it is: a
    policy that would expose the bucket the day the account block came off."""
    out: List[dict] = []
    # Recorded by the reading itself. None means it was not known, and unknown
    # takes the stricter branch: a public policy is reported as public.
    blocked = data.get("account_block_on") is True
    for bucket in _rows(data.get("buckets")):
        name = as_text(bucket.get("name"))
        public = bucket.get("public")
        encrypted = bucket.get("encrypted")
        unreadable = [as_text(u) for u in (bucket.get("unreadable") or [])]
        if unreadable:
            out.append({
                "key": "bucket-unreadable", "resource": name,
                "region": as_text(bucket.get("region")), "severity": "unknown",
                "title": "Bucket whose exposure could not be read",
                "why": "bucket %s: %s — whether it is public or encrypted is "
                       "unknown, not fine" % (name, "; ".join(unreadable)),
                "members": [name], "fix": ""})
            continue
        if not public:
            continue
        # The bucket's OWN block holds a public policy shut exactly as the
        # account-wide one does. _bucket_facts read the four settings and
        # nothing consulted them, so a bucket with RestrictPublicBuckets on was
        # "reachable by anyone" at high (review R-6).
        held = "the account-wide S3 block" if blocked else (
            "this bucket's own public access block"
            if bucket_policy_held_shut(bucket) else "")
        if held:
            out.append({
                "key": "bucket-public-policy-blocked", "resource": name,
                "region": as_text(bucket.get("region")), "severity": "medium",
                "title": "Bucket whose policy is public, held shut by a public "
                         "access block",
                "why": "bucket %s has a policy that makes it public, and %s is "
                       "stopping that from taking effect. It is not exposed "
                       "today; it would be the day that block came off."
                       % (name, held),
                "members": [name],
                "fix": "Fix the bucket policy rather than relying on a public "
                       "access block to hold it shut."})
            continue
        if encrypted is False:
            out.append({
                "key": "bucket-public-unencrypted", "resource": name,
                "region": as_text(bucket.get("region")), "severity": "critical",
                "title": "Bucket that is public AND has no default encryption",
                "why": "bucket %s is public and has no default encryption — "
                       "public alone may be intended; public with no encryption "
                       "at rest is the mistake plus no fallback" % name,
                "members": [name],
                "fix": "Make the bucket private, and turn on default "
                       "encryption. Either alone still leaves the other."})
        else:
            out.append({
                "key": "bucket-public", "resource": name,
                "region": as_text(bucket.get("region")), "severity": "high",
                "title": "Bucket reachable by anyone",
                "why": "bucket %s is public — AWS evaluated its policy and "
                       "said so" % name,
                "members": [name],
                "fix": "Turn on the bucket's public access block, or remove "
                       "the statement in its policy that grants a public "
                       "principal."})

    for region, per in _mapping(data.get("databases")).items():
        if not isinstance(per, dict):
            continue
        for why_unreadable in (per.get("unreadable") or []):
            out.append({
                "key": "database-unreadable", "resource": as_text(region),
                "region": as_text(region), "severity": "unknown",
                "title": "Databases that could not be read",
                "why": "in %s: %s" % (region, as_text(why_unreadable)),
                "members": [], "fix": ""})
        graph = (build_cloud_graph(inventory, as_text(region))
                 if isinstance(inventory, dict) and inventory else None)
        for db in _rows(per.get("databases")):
            ident = as_text(db.get("id"))
            if not db.get("public"):
                continue
            engine = as_text(db.get("engine"))
            reach = database_reachability(db, graph)
            if reach.state == "unknown":
                out.append({
                    "key": "database-reachability-unknown", "resource": ident,
                    "region": as_text(region), "severity": "unknown",
                    "title": "Database flagged publicly accessible, "
                             "reachability unknown",
                    "why": "%s (%s) has PubliclyAccessible set, and %s. That "
                           "flag alone is the console's default; whether "
                           "anything can reach it is a different question and "
                           "this reading cannot answer it"
                           % (ident, engine, reach.why),
                    "members": [ident], "fix": ""})
                continue
            if reach.state == "not-reachable":
                out.append({
                    "key": "database-public-flag", "resource": ident,
                    "region": as_text(region), "severity": "low",
                    "title": "Database flagged publicly accessible, with "
                             "nothing admitting the internet",
                    "why": "%s (%s) has PubliclyAccessible set — the console "
                           "wizard's default — but %s. It is not reachable "
                           "today; the flag is what would let it become so"
                           % (ident, engine, reach.why),
                    "members": [ident],
                    "fix": "Turn the flag off anyway, so a later group or "
                           "route change cannot open it by accident."})
                continue
            if not db.get("encrypted"):
                out.append({
                    "key": "database-public-unencrypted", "resource": ident,
                    "region": as_text(region), "severity": "critical",
                    "title": "Database reachable from the internet with "
                             "unencrypted storage",
                    "why": "%s (%s) is publicly accessible, %s, and its "
                           "storage is not encrypted"
                           % (ident, engine, reach.why),
                    "members": [ident],
                    "fix": "Turn off public accessibility and reach it from "
                           "inside the VPC. Encryption at rest cannot be added "
                           "in place — it needs a snapshot restore — so plan "
                           "that separately."})
            else:
                out.append({
                    "key": "database-public", "resource": ident,
                    "region": as_text(region), "severity": "high",
                    "title": "Database reachable from the internet",
                    "why": "%s (%s) is publicly accessible and %s"
                           % (ident, engine, reach.why),
                    "members": [ident],
                    "fix": "Turn off public accessibility and reach it from "
                           "inside the VPC or through a bastion."})
    return out


def storage_summary(data: dict) -> dict:
    """Storage as the page shows it."""
    buckets = _rows(data.get("buckets"))
    dbs = [db for per in _mapping(data.get("databases")).values()
           if isinstance(per, dict) for db in _rows(per.get("databases"))]
    return {
        "account": as_text(data.get("account")),
        "read_at": as_text(data.get("read_at")),
        "api_calls": data.get("api_calls") or 0,
        "bucket_total": data.get("bucket_total") or 0,
        "bucket_limit": data.get("bucket_limit") or 0,
        "bucket_error": as_text(data.get("bucket_error")),
        "counts": {
            "buckets_examined": len(buckets),
            "buckets_public": sum(1 for b in buckets if b.get("public")),
            "buckets_unencrypted": sum(1 for b in buckets
                                       if b.get("encrypted") is False),
            "buckets_unreadable": sum(1 for b in buckets if b.get("unreadable")),
            "databases": len(dbs),
            "databases_public": sum(1 for d in dbs if d.get("public")),
            "databases_unencrypted": sum(1 for d in dbs
                                         if not d.get("encrypted"))},
        "regions_read": len(_names(data.get("regions_read"))),
        "regions_enabled": len(_names(data.get("regions_enabled"))),
    }


def storage_caveats(summary: dict, blocked: bool) -> List[str]:
    out = []
    total = summary.get("bucket_total", 0)
    examined = _mapping(summary.get("counts")).get("buckets_examined", 0)
    if summary.get("bucket_error"):
        out.append("The bucket list could not be read (%s), so nothing here "
                   "covers S3 at all." % summary["bucket_error"])
    elif total and examined < total:
        out.append("%d of %d bucket(s) were examined — the rest were not "
                   "looked at, so this is a floor. Raise cloud_max_buckets in "
                   "a profile." % (examined, total))
    elif total:
        out.append("Every one of the %d bucket(s) in the account was examined."
                   % total)
    if blocked:
        out.append("The account-wide S3 block is fully on, so no bucket policy "
                   "can make a bucket public while it stays that way. A public "
                   "policy is still reported, because the block is a setting "
                   "somebody can change.")
    out.append("Object contents are never read — only the settings that decide "
               "who could read them. An empty public bucket and a full one "
               "look the same here.")
    out.append("Whether a database is reachable is derived from the inventory "
               "reading: a group on it admitting 0.0.0.0/0 on its port, and a "
               "subnet of it routing to an attached internet gateway. "
               "PubliclyAccessible on its own is the console wizard's default "
               "and is reported as a note. Where the inventory is not in scope "
               "— the findings list the CLI prints — reachability is unknown "
               "rather than assumed either way.")
    out.append("Bucket ACLs and per-object permissions are not read; a bucket "
               "AWS does not call public can still have an object granted to "
               "everyone.")
    out.extend(partial_caveat(summary))
    return out


# --------------------------------------------------------------------------- #
# Access Analyzer: AWS's answer, beside the reader's.
# --------------------------------------------------------------------------- #

def analyzer_summary(data: dict) -> dict:
    """The analyzer reading as the page shows it."""
    regional = _mapping(data.get("regional"))
    seen = regions_seen(data)
    analyzers = [dict(a, region=r) for r in seen
                 for a in _rows(_mapping(regional.get(r)).get("analyzers"))]
    findings = [dict(f, region=r) for r in seen
                for f in _rows(_mapping(regional.get(r)).get("findings"))
                if not f.get("truncated")]
    unreadable = [as_text(w) for r in seen
                  for w in (_mapping(regional.get(r)).get("unreadable") or [])]
    other = [dict(a, region=r) for r in seen
             for a in _rows(_mapping(regional.get(r)).get("other_analyzers"))]
    def scope_of(row):
        # Older readings have no `scope`; public/not-public is what they knew.
        return as_text(row.get("scope")) or (
            "public" if row.get("public") else "external")

    public = [f for f in findings if scope_of(f) == "public"]
    own = [f for f in findings if scope_of(f) == "own-federation"]
    external = [f for f in findings if scope_of(f) == "external"]
    return {
        "account": as_text(data.get("account")),
        "read_at": as_text(data.get("read_at")),
        "api_calls": data.get("api_calls") or 0,
        "truncated": bool(data.get("truncated")),
        "limit": data.get("limit") or 0,
        "analyzers": analyzers,
        "other_analyzers": other,
        "findings": findings,
        "unreadable": unreadable,
        "regions_read": len(_names(data.get("regions_read"))),
        "regions_partial": len(_names(data.get("regions_partial"))),
        "regions_enabled": len(_names(data.get("regions_enabled"))),
        "regions_unread": _names(data.get("regions_unread")),
        "counts": {
            "analyzers": len(analyzers),
            "findings": len(findings),
            "public": len(public),
            "external": len(external),
            "own_federation": len(own),
            "kinds": len({as_text(f.get("kind")) for f in findings}),
        },
    }


def analyzer_findings(data: dict) -> List[dict]:
    """What AWS says is reachable from outside this account.

    Not a second opinion about the same computation -- it IS the computation,
    done by the service that owns the semantics. The hand-rolled readers cannot
    see an SCP or a resource control policy and say so; this can."""
    out: List[dict] = []
    regional = _mapping(data.get("regional"))
    for region in regions_seen(data):
        per = _mapping(regional.get(region))
        for why in (per.get("unreadable") or []):
            out.append({
                "key": "analyzer-unreadable", "resource": as_text(region),
                "region": as_text(region), "severity": "unknown",
                "title": "Access Analyzer findings that could not be read",
                "why": "in %s: %s — what AWS says about external access here "
                       "is unknown, not none" % (region, as_text(why)),
                "members": [], "fix": ""})
        for row in _rows(per.get("findings")):
            if row.get("truncated"):
                continue
            name = as_text(row.get("name")) or as_text(row.get("resource"))
            who = ", ".join("%s %s" % (k, v) for k, v in
                            sorted(_mapping(row.get("principal")).items()))[:120]
            conditions = _names(row.get("conditions"))
            scope = as_text(row.get("scope")) or (
                "public" if row.get("public") else "external")
            if scope == "own-federation":
                # The analyzer's zone of trust is the account, so a federated
                # principal is outside it by definition -- which makes every
                # IRSA role, every GitHub Actions role and every SSO role in
                # the account an "external access" finding. In field use that was dozens at medium,
                # including the SSO role the
                # operator was running as (review 2, R-23).
                out.append({
                    "key": "analyzer-own-federation", "resource": name,
                    "region": as_text(region), "severity": "low",
                    "title": "%s is assumable through this account's own "
                             "identity federation"
                             % (as_text(row.get("kind")) or "This resource"),
                    "why": "Access Analyzer reports %s as reachable from "
                           "outside the account because it trusts %s. That is "
                           "how the federation works, not a grant to a third "
                           "party — what decides whether it is safe is the "
                           "condition on the claim, which is read in the "
                           "identity section of this page"
                           % (as_text(row.get("resource")),
                              as_text(row.get("federation"))
                              or "a provider this account created"),
                    "members": [name],
                    "fix": "Check the trust policy's condition pins what it "
                           "should — the repository for GitHub Actions, the "
                           "service account for EKS."})
            elif scope == "public":
                # What being public GRANTS decides the weight. A public bucket
                # or repository is its contents, reachable -- bad, and often
                # the point of the resource. A public role is the account's
                # own hands: anyone on the internet can assume it and act as
                # it. A public key is every ciphertext it protects.
                #
                # The table said high because "the resource's own
                # authentication is the guard left", and for these kinds there
                # is no guard left -- that is what AWS means by public. The IAM
                # reader already files an administrative role reachable from
                # outside as CRITICAL, so one fact on one page carried two
                # severities from two stages (review 2, R-34).
                kind = as_text(row.get("kind"))
                title = ("%s is reachable by anyone, and AWS says so"
                         % (kind or "This resource"))
                said = ("Access Analyzer reports %s as PUBLIC: %s. This is "
                        "AWS's own evaluation of the policy, conditions "
                        "included — not a reading of the policy text."
                        % (as_text(row.get("resource")),
                           ", ".join(_names(row.get("actions"))[:4])
                           or "any action it grants"))
                fix = ("Remove the statement that grants a public principal, "
                       "or narrow it to the accounts that need it.")
                # Two findings, not one with a conditional key: the severity
                # table is read out of these literals, and a key that is an
                # expression reads as one rule carrying two levels.
                if kind in PUBLIC_IS_A_CREDENTIAL:
                    out.append({
                        "key": "analyzer-public-credential", "resource": name,
                        "region": as_text(region), "severity": "critical",
                        "title": title,
                        "why": said + " Public here is not data reachable from "
                               "outside: it is a credential or a key anyone can "
                               "use, so there is nothing left in the way.",
                        "members": [name], "fix": fix})
                else:
                    out.append({
                        "key": "analyzer-public", "resource": name,
                        "region": as_text(region), "severity": "high",
                        "title": title, "why": said,
                        "members": [name], "fix": fix})
            else:
                out.append({
                    "key": "analyzer-external", "resource": name,
                    "region": as_text(region), "severity": "medium",
                    "title": "%s grants access outside this account"
                             % (as_text(row.get("kind")) or "This resource"),
                    "why": "Access Analyzer reports %s as reachable by %s%s. "
                           "Outside the account is not the same as public, and "
                           "this is AWS's evaluation rather than a reading of "
                           "the policy text"
                           % (as_text(row.get("resource")), who or "a principal "
                              "outside the zone of trust",
                              " (conditions: %s)" % ", ".join(conditions)
                              if conditions else ""),
                    "members": [name],
                    "fix": "Confirm the grant is intended. If it is, record it "
                           "as an archive rule in the analyzer so it stops "
                           "appearing here."})
    return out


def analyzer_caveats(summary: dict) -> List[str]:
    """What AWS's answer does and does not settle."""
    out: List[str] = []
    counts = _mapping(summary.get("counts"))
    other = _rows(summary.get("other_analyzers"))
    if other:
        # An account can run an analyzer and still not have been asked this
        # question. `ListFindings` answers external access only; the
        # unused-access and internal-access kinds answer something else, and
        # asking them is rejected outright (FIELD_VALIDATION_FAILED).
        out.append("%d active analyzer(s) here answer a different question and "
                   "are not read by this section: %s. Access Analyzer's "
                   "unused-access and internal-access kinds are about "
                   "permissions nobody uses, not about who can reach a "
                   "resource from outside."
                   % (len(other),
                      ", ".join(sorted({"%s (%s)" % (as_text(a.get("name")),
                                                     as_text(a.get("kind")))
                                        for a in other}))[:200]))
    if not counts.get("analyzers"):
        out.append("No active EXTERNAL-ACCESS Access Analyzer in any region "
                   "read, so AWS has "
                   "not been asked this question at all. Everything this page "
                   "says about who can reach a resource from outside comes "
                   "from reading policy documents here — which cannot see a "
                   "service control policy, a resource control policy or a "
                   "permissions boundary. An analyzer is free and answers all "
                   "three.")
        return out
    out.append("%d active analyzer(s) answered. Access Analyzer evaluates the "
               "policy the way IAM does, conditions included, so where it and "
               "the policy readers on this page disagree, this is the answer "
               "to trust." % counts.get("analyzers", 0))
    out.append("An analyzer reports on the resource types AWS supports for it, "
               "and on nothing else. A resource kind absent from the list "
               "above was not analyzed rather than found clean.")
    if summary.get("unreadable"):
        out.append("%d Access Analyzer read(s) failed, so what it says about "
                   "those is unknown, not none." % len(summary["unreadable"]))
    out.extend(partial_caveat(summary))
    return out


# The kinds the readers on this page judge, by the panel the analyzer probe
# files each finding under. A finding about any other kind is AWS's answer
# alone, and is said to be, not compared.
JUDGED_PANELS = ("roles", "buckets", "topics", "queues", "repositories")


def _judged(pair: object) -> "Tuple[str, str]":
    """A hand-rolled claim as (panel, name). A bare name is a role, which is
    what the first version of this comparison took."""
    if isinstance(pair, (list, tuple)) and len(pair) == 2:
        return as_text(pair[0]), as_text(pair[1])
    return "roles", as_text(pair)


def _shown(pair: "Tuple[str, str]") -> str:
    """How a compared resource is named on the card."""
    noun = {"buckets": "bucket", "topics": "topic", "queues": "queue",
            "repositories": "repository"}.get(pair[0])
    return "%s %s" % (noun, pair[1]) if noun else pair[1]


def analyzer_agreement(analyzer: dict,
                       hand_rolled: "Sequence[object]") -> dict:
    """Where AWS and the readers on this page agree, and where they do not.

    `hand_rolled` is what the policy readers called reachable from outside:
    (panel, name) pairs for roles, buckets, topics, queues and repositories,
    or bare role names. The first version compared role names against every
    kind the analyzer reports, keyed on a name that was the whole ARN for
    anything without a slash, and set the account's own federation aside on
    AWS's side only -- so a bucket both readers flagged was "a disagreement"
    and "the answer to trust", and a GitHub role this page reads as reachable
    by anyone was blamed on an SCP (review 2, R-24; review 3, R-38).

    Compared by (kind, name) now, over the kinds this page judges. Both halves
    are shown, always: a disagreement is the most interesting thing on the
    page, and hiding either would waste it."""
    summary = analyzer_summary(analyzer)
    ours = {_judged(p) for p in hand_rolled}
    ours.discard(("roles", ""))
    named: set = set()
    outside: set = set()
    own: set = set()
    unjudged: List[str] = []
    for f in _rows(summary.get("findings")):
        kind = as_text(f.get("kind"))
        # The kind decides the panel, the way the probe decided it; an
        # evidence file that carries a different panel is not the authority.
        pair = (ANALYZER_KINDS.get(kind, as_text(f.get("panel"))),
                as_text(f.get("name")))
        if not pair[1]:
            continue
        named.add(pair)
        scope = as_text(f.get("scope")) or (
            "public" if f.get("public") else "external")
        if scope == "own-federation":
            own.add(pair)
        elif pair[0] not in JUDGED_PANELS:
            unjudged.append("%s %s" % (kind or "?", pair[1]))
        else:
            outside.add(pair)
    return {
        "both": sorted(_shown(p) for p in ours & named),
        # What AWS says is outside, on a kind this page judges, that the
        # readers here did not name.
        "aws_only": sorted(_shown(p) for p in outside - ours),
        # What the readers here name that AWS did not name at all -- not as
        # public, not as external, and not as the account's own federation.
        "ours_only": sorted(_shown(p) for p in ours - named),
        # The account's own federation that the IAM reader reads as reachable
        # by ANYONE. AWS is right that the provider is this account's; this
        # page is right that nothing pins which identity it admits. It used
        # to land in `ours_only`, and the card blamed an SCP for a path the
        # same page had called a live critical (review 3, R-38).
        "own_unpinned": sorted(_shown(p) for p in ours & own),
        "asked": bool(_rows(summary.get("analyzers"))),
        "own_federation": (_mapping(summary.get("counts"))
                           .get("own_federation") or 0),
        "unjudged": sorted(set(unjudged)),
    }


def org_summary(data: dict) -> dict:
    """How much of the estate one run covers.

    The fraction is the point. "319 resources" reads as a statement about the
    estate; "319 resources in 1 of 47 accounts" is the same number and a
    different claim, and only the second one is true."""
    accounts = _rows(data.get("accounts"))
    active = [a for a in accounts if as_text(a.get("status")).upper() == "ACTIVE"]
    this = as_text(data.get("account"))
    reaching = _mapping(data.get("profiles_reaching"))
    reachable_ids = {as_text(v) for v in reaching.values()}
    reachable_ids.add(this)
    known = {as_text(a.get("id")) for a in active}
    unread = sorted(known - reachable_ids)
    org = _mapping(data.get("organization"))
    return {
        "account": this,
        "read_at": as_text(data.get("read_at")),
        "api_calls": data.get("api_calls") or 0,
        "standalone": bool(data.get("standalone")),
        "org_error": as_text(data.get("org_error")),
        "accounts_error": as_text(data.get("accounts_error")),
        "org_id": as_text(org.get("id")),
        "is_management": as_text(org.get("management_account")) == this,
        "accounts_total": len(active),
        "accounts_reachable": len(reachable_ids & known) if known else 0,
        "accounts_unread": unread,
        "profiles_reaching": {as_text(k): as_text(v) for k, v in reaching.items()},
        "profiles_unreachable": [as_text(p) for p in
                                 _names(data.get("profiles_unreachable"))],
        "profiles_error": as_text(data.get("profiles_error")),
        "profiles_running_a_command": [as_text(p) for p in
                                       _names(data.get("profiles_running_a_command"))],
        "profiles_config_error": as_text(data.get("profiles_config_error")),
        "profiles_probed": bool(data.get("profiles_probed")),
        "profiles_asked": [as_text(p) for p in (data.get("profiles_asked") or [])],
        "names": {as_text(a.get("id")): as_text(a.get("name")) for a in active},
    }


def _recorder_caveats(summary: dict) -> List[str]:
    """What the read-only recorder cannot see, said where a reader sees it.

    `TestEveryCloudCallIsARead` asserts over every argv the ten stages build,
    which is a real control and is not the same as read-only. A
    `credential_process` in the CLI config runs whatever command it names
    before a request is signed (review 2, R-33)."""
    out: List[str] = []
    ran = [p for p in summary.get("profiles_running_a_command") or [] if p]
    if ran:
        out.append(
            "%d of the profile(s) this run asked resolve through a "
            "credential_process: %s. Asking one who it is RUNS that command on "
            "this machine — the read-only guarantee is over the commands "
            "Squawk builds, and a credential_process is a command the AWS CLI "
            "runs for it. Read those lines before trusting this run's own "
            "footprint." % (len(ran), ", ".join(ran[:6])))
    if summary.get("profiles_config_error"):
        out.append("Whether a profile resolves through a credential_process "
                   "could not be checked: %s."
                   % summary["profiles_config_error"])
    return out


def _profile_caveats(summary: dict) -> List[str]:
    """What the run did, or did not do, with the local CLI profiles.

    Three answers and not two: not asked at all, asked and the list failed, or
    asked and here is who was asked. Folding the first into the second read as
    a failure that never happened (review R-12)."""
    out: List[str] = []
    if not summary.get("profiles_probed"):
        # Not run is a different answer from run and found nothing. Asking
        # every local profile who it is assumes a role for a role_arn profile
        # and runs the configured command for a credential_process one, so it
        # waits for its own acknowledgement.
        out.append("The local AWS CLI profiles were not asked who they reach: "
                   "%s. Which accounts this machine can get to is unknown here "
                   "— not none." % (summary.get("profiles_error")
                                    or "not enabled"))
        return out
    if summary.get("profiles_error"):
        out.append("The profile list could not be read (%s), so which accounts "
                   "this machine reaches is unknown — not none."
                   % summary["profiles_error"])
    elif summary.get("profiles_asked"):
        out.append("%d local profile(s) were asked who they reach, by name: "
                   "%s. Each was one sts:GetCallerIdentity, and nothing else "
                   "was run under any of them."
                   % (len(summary["profiles_asked"]),
                      ", ".join(summary["profiles_asked"][:6])))
    if summary.get("profiles_unreachable"):
        out.append("%d configured profile(s) could not say who they are — an "
                   "expired session, most likely. They may reach accounts not "
                   "counted above." % len(summary["profiles_unreachable"]))
    return out


def org_caveats(summary: dict) -> List[str]:
    """What reading one account does not tell you about an organization."""
    out: List[str] = []
    # Said on every path, including the two that return early. Whether the tool
    # looked at the local profiles is a fact about the run, and a standalone
    # account is exactly where "this is the whole estate" is a claim worth
    # qualifying.
    profiles = _profile_caveats(summary) + _recorder_caveats(summary)
    if summary.get("standalone"):
        out.append("This account is not part of an AWS Organization, so it is "
                   "the whole estate and every count on this page covers all "
                   "of it. A trust or a grant narrowed to an organization "
                   "admits principals this account has no relation to, and is "
                   "reported as outside.")
        return out + profiles
    if summary.get("org_error"):
        out.append("The organization could not be read (%s), so whether this "
                   "account is one of many is unknown. Every count below "
                   "covers this account and nothing is known about any other."
                   % summary["org_error"])
        return out + profiles
    total = summary.get("accounts_total", 0)
    reachable = summary.get("accounts_reachable", 0)
    if summary.get("accounts_error"):
        # The ordinary member-account run: the organization answered and its
        # account list was refused. Said here because every trust and grant
        # naming another account is then a question rather than an answer.
        out.append("The organization answered and its account list did not "
                   "(%s). A trust or a grant naming another account is "
                   "reported as unsettled — neither a sibling nor a stranger "
                   "— until the list can be read."
                   % summary["accounts_error"])
    if total > 1:
        out.append("This organization has %d active account(s). This run read "
                   "%d of them, so every count on this page is about %s of the "
                   "estate — not the estate."
                   % (total, 1, "one account" if total > 1 else "all"))
        unread = summary.get("accounts_unread") or []
        if unread:
            out.append("%d account(s) have no configured profile on this "
                       "machine, so nothing here covers them. Unread is not "
                       "clean." % len(unread))
        if reachable > 1:
            out.append("%d account(s) ARE reachable from this machine with "
                       "profiles you already have — run Squawk again with "
                       "AWS_PROFILE set to each to cover them." % reachable)
    if summary.get("is_management"):
        out.append("This is the organization's management account. It is the "
                   "one place where a misconfiguration reaches every other "
                   "account, and also the account least likely to run the "
                   "workloads people worry about.")
    out.extend(profiles)
    out.extend(partial_caveat(summary))
    return out


def org_findings(data: dict) -> List[dict]:
    """The estate-level fact worth carrying as a finding.

    One only, and it is about coverage rather than configuration: a run that
    covers a fraction of an organization must not be filed as a clean estate.
    That is I1 at the scale above the one it was written for."""
    summary = org_summary(data)
    if summary["standalone"] or summary["org_error"]:
        return []
    unread = summary.get("accounts_unread") or []
    if not unread:
        return []
    return [{
        "key": "organization-mostly-unread", "state": "fired",
        "resource": summary.get("org_id") or "organization",
        "severity": "info",
        "title": "Most of this organization was not read",
        "why": "%d of %d active account(s) in this organization have no "
               "configured profile on this machine, so this run covers one "
               "account. A clean result here is a clean result about one "
               "account." % (len(unread), summary["accounts_total"]),
        "members": [], 
        "fix": "Configure a read-only profile for each account you are "
               "responsible for and run Squawk once per account, or say "
               "explicitly which accounts are out of scope so the gap is a "
               "decision rather than an oversight."}]


def frontdoor_findings(data: dict) -> List[dict]:
    """Ways in from the internet that ask nothing of the caller.

    An API with a route whose authorization is NONE and which requires no API
    key is open to anyone who has the URL. That is the setting saying so, not
    an inference — and it is the finding an account with no public instances,
    no function URLs and no internet-facing load balancers can still have."""
    out: List[dict] = []
    for region, per in _mapping(data.get("regional")).items():
        if not isinstance(per, dict):
            continue
        for why in (per.get("unreadable") or []):
            out.append({
                "key": "frontdoor-unreadable", "resource": as_text(region),
                "region": as_text(region), "severity": "unknown",
                "title": "APIs that could not be read",
                "why": "in %s: %s — whether there is a front door here is "
                       "unknown, not no" % (region, as_text(why)),
                "members": [], "fix": ""})
        for api in _rows(per.get("apis")):
            name = as_text(api.get("name")) or as_text(api.get("id"))
            open_routes = [as_text(r) for r in (api.get("open_routes") or [])]
            if api.get("unreadable"):
                out.append({
                    "key": "api-routes-unreadable", "resource": name,
                    "region": as_text(region), "severity": "unknown",
                    "title": "API whose routes could not be read",
                    "why": "%s: %s — whether it authenticates anything is "
                           "unknown" % (name, as_text(api.get("unreadable"))),
                    "members": [name], "fix": ""})
                continue
            if not open_routes:
                continue
            stages = api.get("stages")
            if api.get("stages_unreadable"):
                out.append({
                    "key": "api-stages-unreadable", "resource": name,
                    "region": as_text(region), "severity": "unknown",
                    "title": "API whose deployed stages could not be read",
                    "why": "%s has %d route(s) requiring no authentication, "
                           "and whether any of them is DEPLOYED could not be "
                           "read: %s. An undeployed API answers nothing; this "
                           "one is unknown, not open and not closed"
                           % (name, len(open_routes),
                              as_text(api.get("stages_unreadable"))),
                    "members": [name, *open_routes[:4]], "fix": ""})
                continue
            if isinstance(stages, list) and not stages:
                # No stage means no endpoint that answers. The routes are real
                # and the door is not built yet, and calling it a front door at
                # high was the alarm crying wolf on an API nobody deployed
                # (review 2, R-32).
                out.append({
                    "key": "api-not-deployed", "resource": name,
                    "region": as_text(region), "severity": "low",
                    "title": "API with unauthenticated routes and no deployed "
                             "stage",
                    "why": "%s has %d of its %d route(s) requiring no "
                           "authentication, and NO deployed stage — so there "
                           "is no endpoint answering for them today. It is "
                           "what the API becomes the moment somebody deploys "
                           "it, which is one click"
                           % (name, len(open_routes), api.get("routes") or 0),
                    "members": [name, *open_routes[:4]],
                    "fix": "Authenticate the routes before the stage exists, "
                           "or delete the API if it was abandoned."})
                continue
            if api.get("private"):
                # Reachable only from inside a VPC. An open method there is
                # worth knowing and is not a door onto the internet, and
                # reporting it as one would be the alarm crying wolf on a
                # correct design.
                out.append({
                    "key": "private-api-open-route", "resource": name,
                    "region": as_text(region), "severity": "low",
                    "title": "Private API with routes that authenticate nothing",
                    "why": "%s is a PRIVATE API — reachable only from inside a "
                           "VPC — and %d of its %d route(s) require no "
                           "authentication and no API key. Anyone who reaches "
                           "the VPC reaches these."
                           % (name, len(open_routes), api.get("routes") or 0),
                    "members": [name],
                    "fix": "Authenticate the routes anyway, if what they do "
                           "matters. Network position is not authorisation."})
                continue
            if not api.get("default_endpoint_open"):
                out.append({
                    "key": "api-open-route-custom-domain", "resource": name,
                    "region": as_text(region), "severity": "medium",
                    "title": "API with unauthenticated routes, reachable only "
                             "through its custom domain",
                    "why": "%s has %d route(s) requiring no authentication. "
                           "Its default execute-api endpoint is turned off, so "
                           "it is reachable only through whatever domain "
                           "fronts it — which is a narrower door, not a closed "
                           "one." % (name, len(open_routes)),
                    "members": [name, *open_routes[:4]],
                    "fix": "Authenticate the routes, or confirm the fronting "
                           "domain is doing it."})
                continue
            out.append({
                "key": "api-open-to-the-internet", "resource": name,
                "region": as_text(region), "severity": "high",
                "title": "API open to the internet with routes that "
                         "authenticate nothing",
                "why": "%s answers on %s and API Gateway authenticates none "
                       "of %d of its %d route(s) — no authorizer, no API key: "
                       "%s"
                       % (name, as_text(api.get("endpoint")) or "its public "
                          "endpoint", len(open_routes), api.get("routes") or 0,
                          ", ".join(open_routes[:4])),
                "members": [name, *open_routes[:4]],
                "fix": "Put an authorizer on the routes, require an API key, "
                       "or turn off the default execute-api endpoint and front "
                       "the API with something that authenticates. If this is "
                       "a webhook receiver, check that the handler verifies "
                       "the sender's signature — that is authentication API "
                       "Gateway cannot see and cannot do. If it is "
                       "deliberately public, the handler has to treat every "
                       "request as untrusted."})

    if as_text(data.get("distribution_error")):
        out.append({
            "key": "cloudfront-unreadable", "resource": "cloudfront",
            "region": "global", "severity": "unknown",
            "title": "CloudFront distributions could not be read",
            "why": as_text(data["distribution_error"]),
            "members": [], "fix": ""})
    for dist in _rows(data.get("distributions")):
        if not dist.get("enabled"):
            continue
        domain = as_text(dist.get("domain"))
        if not as_text(dist.get("waf")):
            out.append({
                "key": "cloudfront-without-waf", "resource": domain,
                "region": "global", "severity": "low",
                "title": "Internet-facing distribution with no web ACL",
                "why": "%s serves the internet and has no WAF web ACL "
                       "attached" % domain,
                "members": [domain],
                "fix": "Attach a web ACL if this fronts anything that takes "
                       "input. A distribution serving only static assets may "
                       "not need one — that is a decision, and this is the "
                       "prompt to make it."})
        plain = [as_text(p) for p in (dist.get("plain_origins") or [])]
        if plain:
            out.append({
                "key": "cloudfront-plaintext-origin", "resource": domain,
                "region": "global", "severity": "medium",
                "title": "Distribution that reaches its origin over plain HTTP",
                "why": "%s fetches from %s without requiring HTTPS, so the hop "
                       "between CloudFront and the origin is unencrypted"
                       % (domain, "; ".join(plain[:3])),
                "members": [domain],
                "fix": "Set the origin protocol policy to https-only. "
                       "match-viewer means a plain-HTTP request from a viewer "
                       "becomes a plain-HTTP request to the origin."})
    return out


def frontdoor_summary(data: dict) -> dict:
    """Front doors as the page shows them."""
    read = regions_seen(data)
    apis = [dict(a, region=r) for r in read
            for a in _rows(_mapping(data.get("regional")).get(r, {}).get("apis"))]
    public = [a for a in apis
              if a.get("default_endpoint_open") and not a.get("private")]
    open_apis = [a for a in apis if a.get("open_routes")]
    dists = _rows(data.get("distributions"))
    live = [d for d in dists if d.get("enabled")]
    return {
        "account": as_text(data.get("account")),
        "read_at": as_text(data.get("read_at")),
        "api_calls": data.get("api_calls") or 0,
        "regions_read": len(read) - len(_names(data.get("regions_partial"))),
        "regions_partial": len(_names(data.get("regions_partial"))),
        "regions_enabled": len(_names(data.get("regions_enabled"))),
        "regions_unread": [r for r in _names(data.get("regions_unread"))
                           if isinstance(r, str)],
        "counts": {"apis": len(apis), "apis_public": len(public),
                   "apis_with_open_routes": len(open_apis),
                   "distributions": len(dists),
                   "distributions_enabled": len(live),
                   "distributions_without_waf": sum(
                       1 for d in live if not as_text(d.get("waf")))},
        "apis": apis, "distributions": dists,
    }


def frontdoor_caveats(summary: dict) -> List[str]:
    out: List[str] = []
    c = summary.get("counts") or {}
    if not c.get("apis") and not c.get("distributions"):
        out.append("No API Gateway API and no CloudFront distribution exists "
                   "in any region read. With no public instance, no function "
                   "URL and no internet-facing load balancer either, this "
                   "account has no front door that Squawk can see.")
    if summary.get("regions_unread"):
        out.append("%d region(s) were never reached, so an API there would not "
                   "appear above." % len(summary["regions_unread"]))
    out.append("A route with no authorizer may still be authenticated by the "
               "handler behind it. Webhook receivers commonly verify an HMAC "
               "signature from the sender — GitHub, Stripe and Slack all work "
               "that way — and API Gateway knows nothing about it. This says "
               "the GATEWAY is not authenticating; it cannot say the handler "
               "is not. Reading one of those handlers is the check this "
               "cannot do for you.")
    out.append("An authorizer is counted as authentication whatever it does. A "
               "Lambda authorizer that returns Allow for everything reads the "
               "same here as one that checks a token.")
    out.append("Resource policies on REST APIs are not read, so an API that "
               "looks open may be restricted to a VPC endpoint or an address "
               "range by a policy this does not see.")
    out.extend(partial_caveat(summary))
    return out


# --------------------------------------------------------------------------- #
# What is behind a number.
#
# A count is a claim, and a claim a reader cannot check is one they have to
# take on trust. Every figure on the Cloud page names the resources it counted,
# and clicking it shows them -- from the SAME saved reading, never a fresh
# query, so the list and the number can never disagree.
#
# Each entry is (title, which evidence file, how to pull the rows). Rows are
# uniform -- name, where, note -- because a reader learning one table has
# learned all of them.
# --------------------------------------------------------------------------- #

def partial_caveat(summary: dict) -> List[str]:
    """The sentence for regions a stage entered and did not finish.

    Read, partial and unread are three answers, and the page used to have two.
    A region whose loop broke on the clock was counted as read while also being
    named as never reached -- both at once, in one payload (review R-13)."""
    partial = summary.get("regions_partial")
    count = (partial if isinstance(partial, int) and not isinstance(partial, bool)
             else len(_names(partial)))
    if not count:
        return []
    return ["%d region(s) were entered and not finished before the budget ran "
            "out, so their counts here are a floor and not a total. They are "
            "neither the regions that were read nor the ones never reached — "
            "raise cloud_inventory_budget in a profile to finish them." % count]


def regions_seen(data: dict) -> List[str]:
    """Every region a stage got an answer from, complete or not.

    A region the stage entered and did not finish is in `regions_partial` and
    not in `regions_read`, because it was not read to the end. Its rows are
    still real, so anything that GATHERS rows walks both -- dropping them would
    turn a clock running out into resources that do not exist, which is the
    silent cap this tool refuses (I12). Anything that COUNTS coverage reports
    the three numbers separately."""
    read = [r for r in _names(data.get("regions_read")) if isinstance(r, str)]
    partial = [r for r in _names(data.get("regions_partial"))
               if isinstance(r, str)]
    return sorted(set(read) | set(partial))


def _names(value: object) -> List[str]:
    """The strings in a parsed list, and nothing else.

    `_rows`' sibling, for the lists that hold names rather than records:
    region lists, profile lists, reason lists. `(data.get(k) or [])` reads as
    a guard and is not one -- a value of `1` sails past `or` and raises on the
    first iteration, and a string iterates into single characters, which is
    worse than raising because it is quiet (review R-14)."""
    if not isinstance(value, (list, tuple)):
        return []
    return [v for v in value if isinstance(v, str)]


def _mapping(value: object) -> Dict[str, Any]:
    """A dict from whatever came off disk. Same reasoning as `_names`:
    `(data.get(k) or {})` admits a list, and `.items()` raises on it.

    Values are `Any` and that is the honest type: they came off disk and the
    reader has to check them itself, which is what every caller does one level
    down with `_rows`, `_names`, `_mapping` or `as_text`."""
    return value if isinstance(value, dict) else {}


def _row(name: object, where: object = "", note: object = "",
         **extra: object) -> dict:
    """One row behind a number. `extra` carries the numeric field a summed
    tile adds up (DRILL_SUMS); the table itself renders only the three."""
    row: Dict[str, object] = {"name": as_text(name), "where": as_text(where),
                              "note": as_text(note)}
    row.update(extra)
    return row


def _inv_resources(data: dict, key: str) -> List[Tuple[str, dict]]:
    """(region, resource) for one kind, across every region read."""
    out = []
    for region, per in _mapping(data.get("resources")).items():
        if isinstance(per, dict):
            for row in _rows(per.get(key)):
                out.append((as_text(region), row))
    return out


def _d_simple(key: str, field: str, note_field: str = ""):
    def extract(data: dict) -> List[dict]:
        return [_row(row.get(field), region,
                     row.get(note_field) if note_field else "")
                for region, row in _inv_resources(data, key)]
    return extract


def _d_public_subnets(data: dict) -> List[dict]:
    out = []
    for region in _names(data.get("regions_read")):
        graph = build_cloud_graph(data, as_text(region))
        for subnet, gateway in sorted(public_subnets(graph).items()):
            out.append(_row(subnet, region, "routes to %s" % gateway))
    return out


def _d_open_groups(risky_only: bool):
    def extract(data: dict) -> List[dict]:
        out = []
        for region in _names(data.get("regions_read")):
            graph = build_cloud_graph(data, as_text(region))
            for gid, group in sorted(graph.groups.items()):
                rules = _world_open_ports(group)
                if not rules:
                    continue
                named = _named_exposed_ports(rules)
                if risky_only and not named:
                    continue
                out.append(_row(gid, region,
                                ("admits 0.0.0.0/0 on %s" % ", ".join(named))
                                if named else "admits 0.0.0.0/0"))
        return out
    return extract


def _d_instances(running_only: bool = False, public_only: bool = False):
    def extract(data: dict) -> List[dict]:
        out = []
        for region in _names(data.get("regions_read")):
            graph = build_cloud_graph(data, as_text(region))
            pub = public_subnets(graph)
            for inst in graph.instances:
                state = as_text(inst.get("State"))
                if running_only and state.lower() != "running":
                    continue
                address = _instance_public_ip(graph, inst)
                if public_only and not (address and pub.get(
                        as_text(inst.get("SubnetId")))):
                    continue
                notes = [state]
                if address:
                    notes.append("public address")
                if as_text(inst.get("SubnetId")) in pub:
                    notes.append("public subnet")
                out.append(_row(inst.get("InstanceId"), region,
                                ", ".join(n for n in notes if n)))
        return out
    return extract


def _d_interfaces(data: dict) -> List[dict]:
    counts: Dict[Tuple[str, str], int] = {}
    for region, eni in _inv_resources(data, "network-interfaces"):
        counts[(eni_owner(eni), region)] = counts.get((eni_owner(eni), region), 0) + 1
    return [_row(owner, region, "%d interface(s)" % n)
            for (owner, region), n in sorted(counts.items(),
                                             key=lambda kv: -kv[1])]


def _d_roles(broad_only: bool = False, unevaluated_only: bool = False):
    def extract(data: dict) -> List[dict]:
        out = []
        for name, row in sorted(_mapping(data.get("roles")).items()):
            if not isinstance(row, dict):
                continue
            broad = [as_text(b) for b in (row.get("broad") or [])]
            unevaluated = [as_text(u) for u in (row.get("unevaluated") or [])]
            if broad_only and not broad:
                continue
            if unevaluated_only and not unevaluated:
                continue
            note = ("; ".join(broad or unevaluated)
                    or "nothing broader than read")
            out.append(_row(name, "instance role", note))
        return out
    return extract


def _d_regions(which: str):
    def extract(data: dict) -> List[dict]:
        if which == "active":
            return [_row(r["region"], "", "%d VPC(s), %d instance(s)"
                         % (r["vpcs"], r["instances"]))
                    for r in inventory_summary(data)["regions"]
                    if not _is_untouched_default(r) and (r["vpcs"] or r["instances"])]
        if which == "denied":
            return [_row(r["region"], "", "; ".join(r["unreadable"]))
                    for r in inventory_summary(data)["regions"]
                    if r["unreadable"]]
        return [_row(r, "", "never read within the budget")
                for r in _names(data.get("regions_unread"))]
    return extract


def _d_services(state: str):
    def extract(data: dict) -> List[dict]:
        out = []
        for row in enablement_summary(data)["services"]:
            for region in row.get(state) or []:
                out.append(_row(row["label"], region, state))
        return out
    return extract


def _d_buckets(public_only: bool = False, unencrypted_only: bool = False):
    def extract(data: dict) -> List[dict]:
        out = []
        for bucket in _rows(data.get("buckets")):
            if public_only and not bucket.get("public"):
                continue
            if unencrypted_only and bucket.get("encrypted") is not False:
                continue
            notes = []
            if bucket.get("public"):
                notes.append("public policy")
            if bucket.get("encrypted") is False:
                notes.append("no default encryption")
            if bucket.get("unreadable"):
                notes.append("could not read: %s"
                             % "; ".join(as_text(u) for u in bucket["unreadable"]))
            out.append(_row(bucket.get("name"), bucket.get("region"),
                            ", ".join(notes) or "private, encrypted"))
        return out
    return extract


def _d_databases(public_only: bool = False, unencrypted_only: bool = False):
    def extract(data: dict) -> List[dict]:
        out = []
        for region, per in _mapping(data.get("databases")).items():
            if not isinstance(per, dict):
                continue
            for db in _rows(per.get("databases")):
                if public_only and not db.get("public"):
                    continue
                if unencrypted_only and db.get("encrypted"):
                    continue
                notes = [as_text(db.get("engine"))]
                notes.append("publicly accessible" if db.get("public")
                             else "not publicly accessible")
                notes.append("encrypted" if db.get("encrypted")
                             else "storage NOT encrypted")
                out.append(_row(db.get("id"), region, ", ".join(notes)))
        return out
    return extract


def edge_functions(per: dict) -> List[dict]:
    """The functions in one region of an edge reading.

    A reading written before the list was kept holds a COUNT here instead of
    the functions. That is why the "Lambda functions" tile expanded to one row
    reading "18 function(s)" rather than to eighteen functions: the members
    were never in the evidence to expand to. Both shapes are read, and the old
    one says what it is rather than rendering as no functions at all (I14)."""
    value = per.get("functions")
    return _rows(value) if isinstance(value, list) else []


def edge_function_count(per: dict) -> int:
    """How many functions one region holds, from either shape of reading."""
    value = per.get("functions")
    if isinstance(value, list):
        return len(value)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _d_functions(with_url: bool = False, open_url: bool = False):
    def extract(data: dict) -> List[dict]:
        out = []
        for region, per in _mapping(data.get("regional")).items():
            if not isinstance(per, dict):
                continue
            urls = _rows(per.get("urls"))
            if with_url or open_url:
                for fn in urls:
                    auth = as_text(fn.get("auth")).upper()
                    if open_url and auth != "NONE":
                        continue
                    out.append(_row(fn.get("name"), region,
                                    "URL auth %s" % (auth or "unknown")))
            else:
                named = {as_text(u.get("name")) for u in urls}
                rows = edge_functions(per)
                if not rows:
                    # An older reading counted them and did not keep them.
                    # Saying so beats an empty list, which reads as none.
                    count = edge_function_count(per)
                    if count:
                        out.append(_row(
                            "%d function(s), not listed" % count, region,
                            "this reading recorded how many, not which — "
                            "rerun the stage to expand this number"))
                    continue
                for fn in rows:
                    name = as_text(fn.get("name"))
                    out.append(_row(name, region, "%s%s" % (
                        "in a VPC" if fn.get("in_vpc") else "not in a VPC",
                        ", has a function URL" if name in named else "")))
        return out
    return extract


def _d_ecs_tasks(data: dict) -> List[dict]:
    """The services behind a running-task count.

    Squawk reads ECS services, not individual tasks, so this is the one number
    on the page whose rows do not correspond to it one for one. Each row
    carries its own `running` count, which is what DRILL_SUMS adds up and what
    the detail view tells the reader it is doing."""
    out = []
    for region, per in _mapping(data.get("regional")).items():
        if not isinstance(per, dict):
            continue
        for row in _rows(per.get("ecs")):
            out.append(_row(row.get("name"), region, _ecs_note(row),
                            running=int(row.get("running") or 0)))
    return out


def _d_iam_roles(data: dict) -> List[dict]:
    """Every role the IAM stage read.

    The IAM panel's "roles" tile used the key `roles`, which CLOUD_DRILL owns
    for the INVENTORY reading's roles-on-instances list. So a count of every
    role in the account expanded to the handful attached to an EC2 instance,
    under a heading that said so. One key, two panels, two meanings."""
    out = []
    for role in _rows(data.get("roles")):
        paths = int(role.get("escalation") or 0)
        if role.get("admin"):
            note = "already administrative"
        elif paths:
            note = "%d escalation path(s)" % paths
        else:
            note = "no escalation path found"
        out.append(_row(role.get("name"),
                        "assumable: %s" % (as_text(role.get("reach")) or "?"),
                        note))
    return out


def _d_unreadable(data: dict) -> List[dict]:
    """Every read that failed, per region — the members of the "reads that
    failed" count. That tile carried no drill key at all, so it rendered as
    plain text: the one number on the page whose members a reader most needs,
    and the only one they could not open (I14)."""
    out = []
    for region, per in _mapping(data.get("regional")).items():
        if not isinstance(per, dict):
            continue
        for why in (per.get("unreadable") or []):
            out.append(_row(as_text(why), region, "not read"))
    return out


def _d_balancers(facing_only: bool = False):
    def extract(data: dict) -> List[dict]:
        out = []
        for region, per in _mapping(data.get("regional")).items():
            if not isinstance(per, dict):
                continue
            for lb in _rows(per.get("load_balancers")):
                if facing_only and as_text(lb.get("scheme")) != "internet-facing":
                    continue
                out.append(_row(lb.get("name"), region,
                                "%s, %s" % (as_text(lb.get("scheme")),
                                            as_text(lb.get("type")))))
        return out
    return extract


def _d_apis(public_only: bool = False, open_only: bool = False):
    def extract(data: dict) -> List[dict]:
        out = []
        for region, per in _mapping(data.get("regional")).items():
            if not isinstance(per, dict):
                continue
            for api in _rows(per.get("apis")):
                if public_only and (api.get("private")
                                    or not api.get("default_endpoint_open")):
                    continue
                open_routes = [as_text(r) for r in (api.get("open_routes") or [])]
                if open_only and not open_routes:
                    continue
                note = "%d of %d route(s) with no authorizer and no API key" % (
                    len(open_routes), api.get("routes") or 0)
                if open_routes:
                    note += ": " + ", ".join(open_routes[:6])
                if api.get("private"):
                    note = "PRIVATE — " + note
                out.append(_row(api.get("name"), region, note))
        return out
    return extract


def _d_distributions(no_waf: bool = False):
    def extract(data: dict) -> List[dict]:
        out = []
        for dist in _rows(data.get("distributions")):
            if no_waf and as_text(dist.get("waf")):
                continue
            notes = ["enabled" if dist.get("enabled") else "disabled"]
            notes.append("web ACL attached" if as_text(dist.get("waf"))
                         else "no web ACL")
            out.append(_row(dist.get("domain"), "global", ", ".join(notes)))
        return out
    return extract


def _d_users(no_mfa: bool = False, with_key: bool = False):
    def extract(data: dict) -> List[dict]:
        out = []
        for user in _rows(data.get("users")):
            keys = [k for k in _rows(user.get("keys"))
                    if as_text(k.get("status")).lower() == "active"]
            if no_mfa and user.get("mfa"):
                continue
            if with_key and not keys:
                continue
            notes = []
            if user.get("mfa") is None:
                notes.append("MFA unreadable")
            elif user.get("mfa"):
                notes.append("MFA on")
            else:
                notes.append("no MFA device")
            if user.get("console"):
                notes.append("console password")
            if keys:
                notes.append("%d active key(s)" % len(keys))
            out.append(_row(user.get("name"), "IAM user", ", ".join(notes)))
        return out
    return extract


def _d_esc_roles(admin: bool = False, outside: bool = False,
                 wanted: str = ""):
    """Roles from the IAM reading, optionally narrowed by how they are reached.

    `outside` keeps the two reaches that are outright outside the account;
    `wanted` keeps one named reach. The second exists because `unsettled` is
    neither outside nor inside — it is a trusted account this run could not
    place — so it belongs to neither of the other two sets and had nothing
    behind its number (I12)."""
    def extract(data: dict) -> List[dict]:
        key = "roles_already_admin" if admin else "roles_with_escalation"
        out = []
        for role in _rows(data.get(key)):
            reach = as_text(role.get("reach"))
            if outside and reach not in OUTSIDE_REACH:
                continue
            if wanted and reach != wanted:
                continue
            reasons = [as_text(r) for r in
                       (role.get("why") if admin else role.get("escalation")) or []]
            out.append(_row(role.get("name"), "assumable: %s" % (reach or "?"),
                            "; ".join(reasons[:2])))
        return out
    return extract


def _d_analyzer(scope: str = ""):
    """Access Analyzer findings, as the page's rows."""
    def extract(data: dict) -> List[dict]:
        out = []
        regional = _mapping(data.get("regional"))
        for region in regions_seen(data):
            for row in _rows(_mapping(regional.get(region)).get("findings")):
                if row.get("truncated"):
                    continue
                got = as_text(row.get("scope")) or (
                    "public" if row.get("public") else "external")
                if scope and got != scope:
                    continue
                who = ", ".join(sorted(_mapping(row.get("principal")).values()))
                out.append(_row(
                    as_text(row.get("name")) or as_text(row.get("resource")),
                    region,
                    "%s · %s%s" % (as_text(row.get("kind")) or "?",
                                   "public" if got == "public"
                                   else (as_text(row.get("federation"))
                                         if got == "own-federation"
                                         else who or "outside the zone of trust"),
                                   " · conditions: %s"
                                   % ", ".join(_names(row.get("conditions")))
                                   if _names(row.get("conditions")) else "")))
        return out
    return extract


def _d_accounts(unread_only: bool = False):
    def extract(data: dict) -> List[dict]:
        summary = org_summary(data)
        unread = set(_names(summary.get("accounts_unread")))
        reaching = {v: k for k, v in _mapping(summary.get("profiles_reaching")).items()}
        out = []
        for ident, name in sorted((summary.get("names") or {}).items()):
            if unread_only and ident not in unread:
                continue
            if ident in unread:
                note = "no configured profile on this machine"
            elif ident in reaching:
                note = "reachable with profile %s" % reaching[ident]
            else:
                note = "this account"
            out.append(_row(name or ident, mask_account(ident), note))
        return out
    return extract


def _d_regional(key: str, keep=None, note=None):
    """Rows from one per-region list in a stage's evidence."""
    def extract(data: dict) -> List[dict]:
        out = []
        for region, per in _mapping(data.get("regional")).items():
            if not isinstance(per, dict):
                continue
            for row in _rows(per.get(key)):
                if keep and not keep(row):
                    continue
                out.append(_row(row.get("name"), region,
                                note(row) if note else ""))
        return out
    return extract


def _d_messaging_public(data: dict) -> List[dict]:
    out = []
    for region, per in _mapping(data.get("regional")).items():
        if not isinstance(per, dict):
            continue
        for key, label in (("topics", "SNS topic"), ("queues", "SQS queue")):
            for row in _rows(per.get(key)):
                reasons = [as_text(r) for r in (row.get("public") or [])]
                if reasons:
                    out.append(_row("%s %s" % (label, as_text(row.get("name"))),
                                    region, "; ".join(reasons[:2])))
    return out


def _eks_note(row: dict) -> str:
    bits = []
    bits.append("public endpoint" if row.get("public") else "private endpoint")
    cidrs = [as_text(c) for c in (row.get("public_cidrs") or [])]
    if row.get("public"):
        bits.append("from %s" % (", ".join(cidrs[:3]) or "anywhere"))
    logs = [as_text(x) for x in (row.get("logging") or [])]
    bits.append("logs: %s" % (", ".join(logs[:4]) if logs else "none"))
    return ", ".join(bits)


def _ecs_note(row: dict) -> str:
    bits = ["cluster %s" % as_text(row.get("cluster")),
            as_text(row.get("launch")) or "?",
            "%s running" % (row.get("running") or 0)]
    if row.get("public_ip"):
        bits.append("assigns public addresses")
    return ", ".join(b for b in bits if b)


# key -> (title, evidence file, extractor)
CLOUD_DRILL: Dict[str, Tuple[str, str, Callable[[dict], List[dict]]]] = {
    "vpcs": ("VPCs", "cloud-inventory.json", _d_simple("vpcs", "VpcId", "CidrBlock")),
    "subnets": ("Subnets", "cloud-inventory.json",
                _d_simple("subnets", "SubnetId", "VpcId")),
    "route_tables": ("Route tables", "cloud-inventory.json",
                     _d_simple("route-tables", "RouteTableId", "VpcId")),
    "igws": ("Internet gateways", "cloud-inventory.json",
             _d_simple("internet-gateways", "InternetGatewayId")),
    "groups": ("Security groups", "cloud-inventory.json",
               _d_simple("security-groups", "GroupId", "GroupName")),
    "public_subnets": ("Subnets that route to the internet",
                       "cloud-inventory.json", _d_public_subnets),
    "world_open_groups": ("Groups open to 0.0.0.0/0", "cloud-inventory.json",
                          _d_open_groups(False)),
    "risky_open_groups": ("Groups open to the world on a risky port",
                          "cloud-inventory.json", _d_open_groups(True)),
    "instances": ("EC2 instances", "cloud-inventory.json", _d_instances()),
    "running": ("Running instances", "cloud-inventory.json",
                _d_instances(running_only=True)),
    "public_instances": ("Instances answering on a public address",
                         "cloud-inventory.json",
                         _d_instances(running_only=True, public_only=True)),
    "enis": ("What owns the network interfaces", "cloud-inventory.json",
             _d_interfaces),
    "roles": ("Roles on instances", "cloud-inventory.json", _d_roles()),
    "broad_roles": ("Instance roles carrying more than read",
                    "cloud-inventory.json", _d_roles(broad_only=True)),
    "unevaluated_roles": ("Instance roles not fully readable",
                          "cloud-inventory.json", _d_roles(unevaluated_only=True)),
    "regions_active": ("Regions actually in use", "cloud-inventory.json",
                       _d_regions("active")),
    "regions_unread": ("Regions never read", "cloud-inventory.json",
                       _d_regions("unread")),
    "regions_denied": ("Regions with a read that was refused",
                       "cloud-inventory.json", _d_regions("denied")),
    "services_off": ("Services that are off, by region",
                     "cloud-enablement.json", _d_services("off")),
    "services_unknown": ("Services that could not be read, by region",
                         "cloud-enablement.json", _d_services("unknown")),
    "services_on": ("Services that are on, by region", "cloud-enablement.json",
                    _d_services("on")),
    "buckets": ("S3 buckets", "cloud-storage.json", _d_buckets()),
    "buckets_public": ("Buckets with a public policy", "cloud-storage.json",
                       _d_buckets(public_only=True)),
    "buckets_unencrypted": ("Buckets with no default encryption",
                            "cloud-storage.json",
                            _d_buckets(unencrypted_only=True)),
    "databases": ("Databases", "cloud-storage.json", _d_databases()),
    "databases_public": ("Publicly accessible databases", "cloud-storage.json",
                         _d_databases(public_only=True)),
    "databases_unencrypted": ("Databases with unencrypted storage",
                              "cloud-storage.json",
                              _d_databases(unencrypted_only=True)),
    "functions": ("Lambda functions, by region", "cloud-edge.json",
                  _d_functions()),
    "function_urls": ("Functions with a URL", "cloud-edge.json",
                      _d_functions(with_url=True)),
    "urls_without_auth": ("Function URLs with no authentication",
                          "cloud-edge.json", _d_functions(open_url=True)),
    "load_balancers": ("Load balancers", "cloud-edge.json", _d_balancers()),
    "internet_facing": ("Internet-facing load balancers", "cloud-edge.json",
                        _d_balancers(facing_only=True)),
    "apis": ("API Gateway APIs", "cloud-frontdoor.json", _d_apis()),
    "apis_public": ("APIs reachable from the internet", "cloud-frontdoor.json",
                    _d_apis(public_only=True)),
    "apis_with_open_routes": ("APIs with routes API Gateway does not "
                              "authenticate", "cloud-frontdoor.json",
                              _d_apis(open_only=True)),
    "distributions": ("CloudFront distributions", "cloud-frontdoor.json",
                      _d_distributions()),
    "distributions_without_waf": ("Distributions with no web ACL",
                                  "cloud-frontdoor.json",
                                  _d_distributions(no_waf=True)),
    "users": ("IAM users", "cloud-iam.json", _d_users()),
    "users_without_mfa": ("IAM users with no MFA device", "cloud-iam.json",
                          _d_users(no_mfa=True)),
    "users_with_keys": ("IAM users with an active access key", "cloud-iam.json",
                        _d_users(with_key=True)),
    "roles_that_can_escalate": ("Roles that can grant themselves more",
                                "cloud-iam.json", _d_esc_roles()),
    "roles_already_admin": ("Roles that are already administrative",
                            "cloud-iam.json", _d_esc_roles(admin=True)),
    "roles_reachable_from_outside": ("Roles assumable from outside the account",
                                     "cloud-iam.json", _d_esc_roles(outside=True)),
    # `unsettled` is neither outside nor inside, so neither of the sets above
    # holds it and its count opened nothing. The card listed at most eight and
    # said nothing about the rest.
    "roles_trust_unsettled": ("Roles assumable from an account this run could "
                              "not place", "cloud-iam.json",
                              _d_esc_roles(wanted="unsettled")),
    "eks_clusters": ("EKS clusters", "cloud-containers.json",
                     _d_regional("eks", note=_eks_note)),
    "eks_public": ("EKS clusters with a public API endpoint",
                   "cloud-containers.json",
                   _d_regional("eks", keep=lambda r: r.get("public"),
                               note=_eks_note)),
    "eks_without_logs": ("EKS clusters with no control-plane logging",
                         "cloud-containers.json",
                         _d_regional("eks", keep=lambda r: not r.get("logging"),
                                     note=_eks_note)),
    "ecs_services": ("ECS services", "cloud-containers.json",
                     _d_regional("ecs", note=_ecs_note)),
    "ecs_public": ("ECS services assigning public addresses",
                   "cloud-containers.json",
                   _d_regional("ecs", keep=lambda r: r.get("public_ip"),
                               note=_ecs_note)),
    # The tile counts tasks; Squawk reads services. The rows are the services
    # and each carries its own running count, which is what DRILL_SUMS declares
    # and the detail view says out loud.
    "ecs_tasks": ("Services running those tasks",
                  "cloud-containers.json", _d_ecs_tasks),
    "iam_roles": ("Roles in this account", "cloud-iam.json", _d_iam_roles),
    "frontdoor_regions_unread": ("Regions the front-door read never reached",
                                 "cloud-frontdoor.json", _d_regions("unread")),
    "edge_unreadable": ("Reads that failed", "cloud-edge.json", _d_unreadable),
    "topics": ("SNS topics", "cloud-dataservices.json",
               _d_regional("topics",
                           note=lambda r: "encrypted" if r.get("encrypted")
                           else "not encrypted")),
    "queues": ("SQS queues", "cloud-dataservices.json",
               _d_regional("queues",
                           note=lambda r: "encrypted" if r.get("encrypted")
                           else "not encrypted")),
    "messaging_public": ("Topics and queues usable by any AWS principal",
                         "cloud-dataservices.json", _d_messaging_public),
    "secrets": ("Secrets", "cloud-dataservices.json",
                _d_regional("secrets",
                            note=lambda r: "%s, %s" % (
                                "rotates" if r.get("rotation") else "no rotation",
                                "customer key" if r.get("customer_key")
                                else "AWS-managed key"))),
    "repositories": ("Container repositories", "cloud-dataservices.json",
                     _d_regional("repositories",
                                 note=lambda r: "%s, %s" % (
                                     "scan on push" if r.get("scan_on_push")
                                     else "no scan on push",
                                     "mutable tags" if r.get("mutable")
                                     else "immutable tags"))),
    "repositories_public": ("Repositories any principal can pull",
                            "cloud-dataservices.json",
                            _d_regional("repositories",
                                        keep=lambda r: r.get("public"),
                                        note=lambda r: "; ".join(
                                            as_text(x) for x in
                                            (r.get("public") or [])[:2]))),
    "analyzers": ("Active Access Analyzers", "cloud-analyzer.json",
                  _d_regional("analyzers",
                              note=lambda r: as_text(r.get("kind")))),
    "analyzer_findings": ("Resources AWS says are reachable from outside",
                          "cloud-analyzer.json", _d_analyzer()),
    "analyzer_public": ("Resources AWS says anyone can reach",
                        "cloud-analyzer.json", _d_analyzer(scope="public")),
    "analyzer_external": ("Resources AWS says a named outsider can reach",
                          "cloud-analyzer.json",
                          _d_analyzer(scope="external")),
    "analyzer_own_federation": ("Roles this account's own federation can assume",
                                "cloud-analyzer.json",
                                _d_analyzer(scope="own-federation")),
    "accounts_total": ("Accounts in this organization", "cloud-org.json",
                       _d_accounts()),
    "accounts_unread": ("Accounts with no configured profile here",
                        "cloud-org.json", _d_accounts(unread_only=True)),
}


# A tile whose number is not the number of rows behind it, and the field the
# rows carry that adds up to it. There is exactly one: Squawk reads ECS
# services, not individual tasks, so "running tasks" expands to the services
# running them. Declaring it here is what lets the conformance test hold every
# OTHER number to strict equality instead of having no rule at all.
DRILL_SUMS = {"ecs_tasks": "running"}


def cloud_drill(key: str, data: dict) -> List[dict]:
    """The rows behind one number, from the reading that produced it."""
    entry = CLOUD_DRILL.get(key)
    if not entry or not isinstance(data, dict):
        return []
    try:
        return entry[2](data)
    except Exception as exc:
        # A drill-down that raises must not take a page down. The number stays
        # true; what is lost is the detail, and that is said rather than shown
        # as an empty list, which would read as "nothing behind it".
        LOG.warning("DRILL %s failed: %s", key, exc)
        return [_row("could not be listed", "", str(exc)[:160])]


def container_findings(data: dict, inventory: "Optional[dict]" = None) -> List[dict]:
    """Clusters and services the internet can reach.

    A Kubernetes API server reachable from `0.0.0.0/0` is the control plane of
    the cluster on the public internet — not a subtlety, and not something any
    network view shows, because the endpoint is AWS-managed and sits outside
    the VPC the cluster runs in."""
    out: List[dict] = []
    for region, per in _mapping(data.get("regional")).items():
        if not isinstance(per, dict):
            continue
        for why in (per.get("unreadable") or []):
            out.append({
                "key": "containers-unreadable", "resource": as_text(region),
                "region": as_text(region), "severity": "unknown",
                "title": "Container services that could not be read",
                "why": "in %s: %s — whether there is a cluster here is "
                       "unknown, not no" % (region, as_text(why)),
                "members": [], "fix": ""})
        for cluster in _rows(per.get("eks")):
            name = as_text(cluster.get("name"))
            cidrs = [as_text(c) for c in (cluster.get("public_cidrs") or [])]
            if cluster.get("public") and (not cidrs or "0.0.0.0/0" in cidrs):
                out.append({
                    # High, not critical, and the reason is the scale rather
                    # than the blast radius: Kubernetes authentication is a
                    # guard, and `critical` is reserved for a path with no
                    # guard left. The same reading puts SSH on 22 open to the
                    # world at high, and the review's whole complaint was that
                    # the same fact carried different weights (R-16).
                    "key": "eks-api-open-to-the-world", "resource": name,
                    "region": as_text(region), "severity": "high",
                    "title": "Kubernetes API server reachable from anywhere",
                    "why": "cluster %s has a public endpoint with no address "
                           "restriction — the control plane answers the whole "
                           "internet, and only Kubernetes authentication is "
                           "between a caller and the cluster" % name,
                    "members": [name],
                    "fix": "Set publicAccessCidrs to the addresses that "
                           "administer this cluster, or turn the public "
                           "endpoint off and reach it privately."})
            elif cluster.get("public"):
                out.append({
                    "key": "eks-api-public-but-restricted", "resource": name,
                    "region": as_text(region), "severity": "low",
                    "title": "Kubernetes API server public, restricted by "
                             "address",
                    "why": "cluster %s has a public endpoint restricted to %s"
                           % (name, ", ".join(cidrs[:4])),
                    "members": [name],
                    "fix": "Nothing urgent. Confirm the list is still the set "
                           "of places that administer this cluster."})
            if not cluster.get("logging"):
                out.append({
                    "key": "eks-without-control-plane-logs", "resource": name,
                    "region": as_text(region), "severity": "low",
                    "title": "Kubernetes cluster with no control-plane logging",
                    "why": "cluster %s records none of the API server, audit "
                           "or authenticator logs — if something happens "
                           "there, nothing will say what" % name,
                    "members": [name],
                    "fix": "Enable at least the api and audit log types."})

        public_subnet_ids: set = set()
        unroutable: List[str] = []
        if inventory:
            graph = build_cloud_graph(inventory, as_text(region))
            public_subnet_ids = set(public_subnets(graph))
            # A denied read is not an empty answer. `public_subnets` over a
            # graph whose subnets or route tables were refused returns nothing,
            # and reading nothing as "private subnet" dropped a service that
            # assigns public addresses entirely (review R-10). The denial was
            # recorded in `unreadable` all along and this never looked.
            unroutable = [key for key in ("subnets", "route-tables")
                          if key in graph.unreadable]
        for svc in _rows(per.get("ecs")):
            if not svc.get("public_ip"):
                continue
            name = as_text(svc.get("name"))
            subnets = [as_text(s) for s in (svc.get("subnets") or [])]
            landing = sorted(set(subnets) & public_subnet_ids)
            if inventory and unroutable and not landing:
                out.append({
                    "key": "ecs-service-reachability-unknown", "resource": name,
                    "region": as_text(region), "severity": "unknown",
                    "title": "ECS service that takes a public address, "
                             "reachability unknown",
                    "why": "service %s assigns public IPs to its tasks, and %s "
                           "could not be read in %s — whether those addresses "
                           "route anywhere is unknown, not no"
                           % (name, " and ".join(unroutable), region),
                    "members": [name, *subnets], "fix": ""})
                continue
            if inventory and not landing:
                # It asks for a public address but its subnets do not route to
                # an internet gateway, so it does not get one that works.
                continue
            # Judged like an instance, which is what step 6 did for EC2: an
            # address and a route are two legs, and the third is a rule
            # somebody can connect over. An instance in this position with no
            # world-open TCP rule produces nothing, and this produced HIGH --
            # the same fact, two weights (R-16).
            admits, guarded, rules = [], True, []
            if inventory and graph is not None:
                for gid in (svc.get("groups") or []):
                    group = graph.groups.get(as_text(gid))
                    if group is None:
                        guarded = False        # not in the reading: unknown
                        continue
                    open_rules = _world_open_ports(group)
                    if any(proto in REACHABLE_PROTOCOLS
                           for proto, _lo, _hi in open_rules):
                        admits.append(as_text(gid))
                        rules.extend(open_rules)
                if guarded and not admits:
                    out.append({
                        "key": "ecs-service-public-address-no-open-rule",
                        "resource": name, "region": as_text(region),
                        "severity": "low",
                        "title": "ECS service whose tasks take a public "
                                 "address, with nothing admitting the internet",
                        "why": "service %s assigns public IPs to its tasks in "
                               "%s, and no security group on it admits "
                               "0.0.0.0/0 over a protocol anyone can connect "
                               "on. The address is what would matter the day a "
                               "rule opened" % (name, ", ".join(landing)),
                        "members": [name, *subnets],
                        "fix": "Turn assignPublicIp off anyway, so a later "
                               "group change cannot open it by accident."})
                    continue
            # Judged like an instance means judged by the SAME rule. An
            # instance needs a sensitive port or a broad role; a world-open
            # rule on 443 alone is the job and produces nothing. This fired
            # HIGH on any world-open TCP rule, so a web service on Fargate
            # behind the group every web service has was high while the
            # identical thing on EC2 was nothing (review 2, R-29).
            # `guarded` false means a group on this service is not in the
            # reading, and a missing input must not soften a verdict -- the
            # same rule the no-inventory path already keeps. Only a service
            # whose groups were ALL read can be let down to low.
            exposed = _named_exposed_ports(rules)
            if inventory and guarded and admits and not exposed:
                out.append({
                    "key": "ecs-service-public-address-ordinary-ports",
                    "resource": name, "region": as_text(region),
                    "severity": "low",
                    "title": "ECS service whose tasks take a public address, "
                             "on the ports a web service uses",
                    "why": "service %s assigns public IPs to its tasks in %s, "
                           "and %s admits 0.0.0.0/0 — but on no administrative "
                           "or database port. An instance in the same position "
                           "produces nothing here; what is left is the task's "
                           "own listener, which this does not read"
                           % (name, ", ".join(landing) or as_text(region),
                              "/".join(admits)),
                    "members": [name, *subnets, *admits],
                    "fix": "Nothing, if a public listener is the job. Put it "
                           "behind a load balancer if it is not."})
                continue
            out.append({
                "key": "ecs-service-with-a-public-address", "resource": name,
                "region": as_text(region), "severity": "high",
                "title": "ECS service whose tasks take a public address",
                "why": "service %s in cluster %s assigns public IPs to its "
                       "tasks%s%s — each running task is on the internet with "
                       "only its security group in between"
                       % (name, as_text(svc.get("cluster")),
                          (" in %s" % ", ".join(landing)) if landing else "",
                          (", and %s admits 0.0.0.0/0 on %s"
                           % ("/".join(admits), ", ".join(exposed)))
                          if exposed else ""),
                "members": [name, *subnets],
                "fix": "Run the tasks in private subnets behind a load "
                       "balancer or a NAT gateway. assignPublicIp ENABLED is "
                       "usually there because the tasks need to reach out, "
                       "and a NAT gateway does that without letting anything "
                       "reach in."})
    return out


def container_summary(data: dict) -> dict:
    regional = _mapping(data.get("regional"))
    read = regions_seen(data)
    eks = [dict(c, region=r) for r in read
           for c in _rows((regional.get(r) or {}).get("eks"))]
    ecs = [dict(s, region=r) for r in read
           for s in _rows((regional.get(r) or {}).get("ecs"))]
    return {
        "account": as_text(data.get("account")),
        "read_at": as_text(data.get("read_at")),
        "api_calls": data.get("api_calls") or 0,
        "regions_read": len(read) - len(_names(data.get("regions_partial"))),
        "regions_partial": len(_names(data.get("regions_partial"))),
        "regions_enabled": len(_names(data.get("regions_enabled"))),
        "regions_unread": [r for r in _names(data.get("regions_unread"))
                           if isinstance(r, str)],
        "truncated": bool(data.get("truncated")),
        "limit": data.get("limit") or 0,
        "counts": {
            "eks_clusters": len(eks),
            "eks_public": sum(1 for c in eks if c.get("public")),
            "eks_without_logs": sum(1 for c in eks if not c.get("logging")),
            "ecs_services": len(ecs),
            "ecs_public": sum(1 for s in ecs if s.get("public_ip")),
            "ecs_tasks": sum(int(s.get("running") or 0) for s in ecs)},
        "eks": eks, "ecs": ecs,
    }


def dataservice_findings(data: dict) -> List[dict]:
    """Topics, queues and repositories anyone can use.

    A resource policy admitting `*` is reachable by any AWS principal on
    earth, and it shows up in no network view at all — there is no subnet, no
    security group and no route table between a caller and an SNS topic."""
    out: List[dict] = []
    for region, per in _mapping(data.get("regional")).items():
        if not isinstance(per, dict):
            continue
        for why in (per.get("unreadable") or []):
            out.append({
                "key": "dataservice-unreadable", "resource": as_text(region),
                "region": as_text(region), "severity": "unknown",
                "title": "Data services that could not be read",
                "why": "in %s: %s" % (region, as_text(why)),
                "members": [], "fix": ""})
        for kind, label in (("topics", "SNS topic"), ("queues", "SQS queue")):
            for row in _rows(per.get(kind)):
                reasons = [as_text(r) for r in (row.get("public") or [])]
                if not reasons:
                    continue
                name = as_text(row.get("name"))
                # A grant to an account the organization read could not
                # place is a question, not a high (review 3, R-37).
                unsettled = [r for r in reasons if is_unsettled_public(r)]
                if unsettled:
                    out.append({
                        "key": "messaging-reach-unsettled", "resource": name,
                        "region": as_text(region), "severity": "unknown",
                        "title": "%s granted to an account this run could "
                                 "not place" % label,
                        "why": "%s %s: %s. Inside this organization or outside "
                               "it is the question the organization read "
                               "could not answer, so this is unknown"
                               % (label, name, "; ".join(unsettled[:2])),
                        "members": [name], "fix": ""})
                reasons = [r for r in reasons if not is_unsettled_public(r)]
                if not reasons:
                    continue
                narrowed = all(is_narrowed_public(r) for r in reasons)
                out.append({
                    "key": "messaging-open-to-any-principal", "resource": name,
                    "region": as_text(region),
                    "severity": "medium" if narrowed else "high",
                    "title": "%s usable by any AWS principal" % label,
                    "why": "%s %s: %s. There is no subnet, no security group "
                           "and no route table between a caller and this — the "
                           "policy is the whole control."
                           % (label, name, "; ".join(reasons[:2])),
                    "members": [name],
                    "fix": "Name the principals that should publish or consume, "
                           "or add a condition on the source account, "
                           "organization or ARN."})
        for repo in _rows(per.get("repositories")):
            reasons = [as_text(r) for r in (repo.get("public") or [])]
            name = as_text(repo.get("name"))
            if as_text(repo.get("policy_unreadable")):
                out.append({
                    "key": "registry-policy-unreadable", "resource": name,
                    "region": as_text(region), "severity": "unknown",
                    "title": "Container repository whose policy could not be "
                             "read",
                    "why": "repository %s: %s — whether anyone outside this "
                           "account can pull from it is unknown, not no"
                           % (name, as_text(repo.get("policy_unreadable"))),
                    "members": [name], "fix": ""})
                continue
            unsettled = [r for r in reasons if is_unsettled_public(r)]
            if unsettled:
                out.append({
                    "key": "registry-reach-unsettled", "resource": name,
                    "region": as_text(region), "severity": "unknown",
                    "title": "Container repository shared with an account "
                             "this run could not place",
                    "why": "repository %s: %s. Inside this organization or "
                           "outside it is the question the organization read "
                           "could not answer, so this is unknown"
                           % (name, "; ".join(unsettled[:2])),
                    "members": [name], "fix": ""})
            reasons = [r for r in reasons if not is_unsettled_public(r)]
            if reasons:
                # The same split the messaging branch makes. Before it existed
                # this branch had no narrowed case at all, so a repository
                # scoped to the organization -- the normal way to share a base
                # image -- was "readable by any AWS principal" at high (R-7).
                narrowed = all(is_narrowed_public(r) for r in reasons)
                out.append({
                    "key": "registry-open-to-any-principal", "resource": name,
                    "region": as_text(region),
                    "severity": "medium" if narrowed else "high",
                    "title": "Container repository readable by any AWS "
                             "principal",
                    "why": "repository %s: %s — images are the build, and a "
                           "build often carries more than its author meant"
                           % (name, "; ".join(reasons[:2])),
                    "members": [name],
                    "fix": "Name the accounts that should pull, or remove the "
                           "repository policy and rely on IAM."})
    return out


def dataservice_summary(data: dict) -> dict:
    regional = _mapping(data.get("regional"))
    read = regions_seen(data)
    def gather(key):
        return [dict(x, region=r) for r in read
                for x in _rows((regional.get(r) or {}).get(key))]
    topics, queues = gather("topics"), gather("queues")
    secrets, repos = gather("secrets"), gather("repositories")
    return {
        "account": as_text(data.get("account")),
        "read_at": as_text(data.get("read_at")),
        "api_calls": data.get("api_calls") or 0,
        "truncated": bool(data.get("truncated")),
        "regions_read": len(read) - len(_names(data.get("regions_partial"))),
        "regions_partial": len(_names(data.get("regions_partial"))),
        "regions_enabled": len(_names(data.get("regions_enabled"))),
        "regions_unread": [r for r in _names(data.get("regions_unread"))
                           if isinstance(r, str)],
        "counts": {
            "topics": len(topics),
            "topics_public": sum(1 for t in topics if t.get("public")),
            "queues": len(queues),
            "queues_public": sum(1 for q in queues if q.get("public")),
            "queues_unencrypted": sum(1 for q in queues
                                      if not q.get("encrypted")),
            "secrets": len(secrets),
            "secrets_without_rotation": sum(1 for s in secrets
                                            if not s.get("rotation")),
            "repositories": len(repos),
            "repositories_public": sum(1 for r in repos if r.get("public")),
            "repositories_unreadable": sum(
                1 for r in repos if as_text(r.get("policy_unreadable"))),
            "repositories_mutable": sum(1 for r in repos if r.get("mutable")),
            "repositories_without_scan": sum(1 for r in repos
                                             if not r.get("scan_on_push"))},
        "topics": topics, "queues": queues, "secrets": secrets,
        "repositories": repos,
    }


def dataservice_caveats(summary: dict) -> List[str]:
    out: List[str] = []
    c = summary.get("counts") or {}
    if summary.get("truncated"):
        out.append("More items exist in at least one region than were "
                   "examined, so these counts are a floor. Raise "
                   "cloud_max_items in a profile.")
    if c.get("repositories_unreadable"):
        out.append("%d repository(ies) had a policy that could not be read, so "
                   "whether anyone outside this account can pull from them is "
                   "unknown rather than no." % c["repositories_unreadable"])
    if c.get("secrets_without_rotation"):
        out.append("%d secret(s) have no automatic rotation. That is a policy "
                   "question rather than an exposure — a secret nobody can "
                   "read is not urgent because it is old — so it is counted "
                   "and not raised as a finding."
                   % c["secrets_without_rotation"])
    if c.get("repositories_mutable"):
        out.append("%d repository(ies) allow tags to be overwritten, so a tag "
                   "you deployed is not proof of the image that ran. Not a "
                   "finding on its own; it is what makes one hard to "
                   "investigate." % c["repositories_mutable"])
    out.append("Secret VALUES are never read — only whether a secret exists, "
               "whether it rotates, and what key protects it.")
    out.append("A queue or topic with no resource policy is governed by IAM "
               "alone, which this reads elsewhere. No policy is not the same "
               "as no access.")
    out.extend(partial_caveat(summary))
    return out


def cloud_correlations(results: "List[StageResult]", run_dir: str) -> List[dict]:
    """Every cloud graph record for a run, read back from the inventory stage's
    own evidence.

    The rules run in the normalizer, because that is where the graph is, and a
    normalizer may only return findings — so the rules' UNKNOWNS had nowhere to
    go and were computed, logged, and dropped. Measured on a live-shaped run
    (2026-09-08): a region whose security-group read was denied appeared
    nowhere but the raw file, and the run reported one finding and no doubt.
    That is precisely the silence this tool exists to refuse, produced by the
    part of it that refuses silence.

    So the records come back here and join the correlation panel, where the
    other three-state answers already live: fired ones alongside their finding,
    and unknowns as the questions this run could not answer."""
    out: List[dict] = []
    for res in results:
        if res.tool not in ("cloudinv",) or not res.raw_file:
            continue
        # A StageResult carries its raw path RELATIVE to the run directory, so
        # the evidence stays portable when a run is copied. Reading it back
        # therefore needs the run directory, and joining without it silently
        # found nothing at all -- the first version of this function returned
        # an empty list on every real run and the tests, which built records
        # directly, all passed.
        path = os.path.join(run_dir, res.raw_file)
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            LOG.warning("CLOUD could not re-read %s: %s", path, exc)
            continue
        if isinstance(data, dict):
            out.extend(correlate_cloud(data))
    return out


def cloud_findings(records: List[dict]) -> List[Finding]:
    """Fired cloud combinations become Findings, so they inherit identity,
    evidence, history and ranking like anything else. Identity is the rule key
    plus region and resource — no address, no timestamp, no session value, so
    the same instance re-read tomorrow diffs to nothing (credential rule 6)."""
    out: List[Finding] = []
    for c in records:
        if c.get("state") != "fired":
            continue
        ident = "cloud:%s:%s" % (c["key"], c.get("resource", ""))
        out.append(Finding(
            "cloudinv", ident, norm_severity(c["severity"]), c["title"],
            "aws:%s" % c.get("region", ""),
            {"what": c["why"], "remediation": c["fix"],
             "members": c.get("members", []), "rule": c["key"],
             "region": c.get("region", "")}))
    return out


# --------------------------------------------------------------------------- #
# Squawk codes.
#
# Aircraft squawk a transponder code when something is wrong, and the three
# emergency codes map onto this tool almost exactly:
#
#   7700  general emergency        — a critical exposure is live
#   7600  lost communications      — a scanner or target went silent
#   7500  unlawful interference    — evidence of an active attack
#
# 7600 is the one this whole tool is built around. "Radio failure" is precisely
# the governing rule: a scanner that did not run must never look like a scanner
# that found nothing. A quiet run is not a clean run, and the alarm says so.
# --------------------------------------------------------------------------- #

SQUAWK_CODES = {
    "7700": ("general emergency", "a critical exposure is live"),
    "7600": ("lost communications", "something went silent — you are not being told"),
    "7500": ("unlawful interference", "evidence of an active attack"),
}

# Scopes where a critical finding is about something that is actually running.
# A cloud read is the live configuration of a live account; a DAST probe is a
# live app; a host audit is this machine. Everything else — a repository, a
# directory, a container image — is a reading of what was WRITTEN, and whether
# it is deployed anywhere is a question that run never asked.
LIVE_SCOPES = ("aws", "url", "host")

# So 7700 over a static scan says what it actually found. The `high` branch
# below already had this right — it is explicitly `scope == "url"` and says
# "reachable now, not theoretical" — and the `critical` branch, which is the
# loudest line this tool prints, did not. On a preflight of a Terraform
# repository it announced "a critical exposure is live" over 38 trivy findings
# about security-group rules in `.tf` files and 3 about plain HTTP in an ALB
# definition (the operator's run, 2026-09-14). Every finding was real and nothing
# had been checked for reachability. An alarm that overstates is the same
# failure as one that understates, and it costs more: a reader who learns to
# discount 7700 has lost the loudest channel there is.
STATIC_EMERGENCY = ("a critical weakness is in what was scanned — nothing here "
                    "checked whether it is deployed")

# And the third case: 7700 raised on HIGH findings because the app is running.
# The alarm is right and the word `critical` is not — the `why` beside it
# already says "reachable now, not theoretical", which is what earned the
# emergency, so this only has to stop contradicting it.
LIVE_HIGH_EMERGENCY = "a high exposure is live"

# Titles that indicate an attack in progress rather than a weakness at rest.
# Cloud providers name these directly (GuardDuty, Defender), which is where most
# 7500s will come from once cloud ingest lands.
# Scanner kinds that can witness an attack in progress rather than a weakness at
# rest. Static analysis (sast/iac/sca/sbom/secrets) describes what COULD go
# wrong; only a dynamic probe sees what IS going wrong. Cloud threat-intel kinds
# join this set when that ingest lands.
# Only a scanner that watches something running can witness an attack. `cloud`
# is the one that genuinely does: GuardDuty and Defender findings arriving
# through Security Hub say an attack HAPPENED, and ATTACK_MARKERS is their
# vocabulary. `dast` stays because a probe can occasionally find a live
# backdoor on an already-compromised app, but scoping to dast alone made the
# alarm unfirable the moment its markers stopped matching prose: the code that
# reports an attack could no longer see the only source that reports attacks.
WITNESS_KINDS = ("cloud", "dast")

# The vocabulary of threat-detection finding TYPES, not of prose. Each token is
# matched at a word boundary (see `_looks_like_an_attack`), because the earlier
# substring test fired 7500 -- "evidence of an active attack" -- on ordinary control findings in
# field use, for one reason:
#
#     "c2" is a substring of "ec2".
#
# So "EC2 subnets should not automatically assign public IP addresses" read as
# command-and-control traffic, and so did every finding whose resource ARN
# contained ":ec2:", which is most of them. That is the loudest wrong answer
# this tool can give, and it gave it on the first live estate it ever saw.
#
# "c2" is gone. GuardDuty writes C&CActivity, not c2, so the token bought
# nothing and cost the alarm its credibility. The rest are taken from the
# actual GuardDuty finding-type vocabulary.
ATTACK_MARKERS = ("bruteforce", "brute force", "unauthorizedaccess", "malicious",
                  "c&cactivity", "command and control", "cryptocurrency",
                  "cryptomining", "exfiltration", "under attack", "compromised",
                  "backdoor", "trojan")

# `\b` will not do on its own: several markers end or begin with a
# non-word character ("c&cactivity", "brute force"), where a `\b` on that side
# never matches. So each side is a boundary only where the marker's own edge is
# a word character, built once at import rather than per finding.
def _boundary(mark: str) -> "re.Pattern":
    left = r"\b" if mark[:1].isalnum() else ""
    right = r"\b" if mark[-1:].isalnum() else ""
    return re.compile(left + re.escape(mark) + right)


_ATTACK_RE = {}


# A finding that carries a compliance status is a CONTROL EVALUATION: a
# statement about how a resource is configured, at rest, right now. It is a
# category error for one to be an incident, however its author worded it --
# "should not allow data exfiltration" is a policy, not an attack. This is the
# structural half of the 7500 gate, and it is the half that does not depend on
# anybody's choice of words.
_ATTACK_RE.update({m: _boundary(m) for m in ATTACK_MARKERS})


def _is_control_evaluation(finding: dict) -> bool:
    det = finding.get("detail") or {}
    return bool(str(det.get("status", "")).strip())


def _looks_like_an_attack(finding: dict) -> bool:
    """Whether a finding's TYPE says an attack happened.

    Matched at word boundaries against the classification fields only -- the
    title, the rule id, the finding type -- never the description, which is
    prose about what an attacker COULD do. ZAP writes "a malicious page loaded
    by the victim's user agent" into a CORS advisory; that is a weakness at
    rest being explained, not an incident being reported.

    Word boundaries rather than `in`, because `in` cannot tell "c2" from the
    "c2" inside "ec2" and did not."""
    det = finding.get("detail") or {}
    hay = " ".join([str(finding.get("title", "")), str(det.get("rule", "")),
                    str(det.get("type", ""))]).lower()
    return any(_ATTACK_RE[mark].search(hay) for mark in ATTACK_MARKERS)


def _detail_list(findings: List[dict], cap: int = 4) -> List[str]:
    """The finding lines under a squawk code: one per distinct title, with a
    count and where it was seen, and the truncation said out loud.

    Four identical lines reading "CORS Misconfiguration" tell a reader nothing
    about what to do, and printing four of five with no note is a silent cap,
    which the charter forbids (I12)."""
    groups: Dict[str, List[dict]] = {}
    for f in findings:
        groups.setdefault(str(f.get("title", "")) or "(untitled)", []).append(f)
    lines = []
    for title, rows in sorted(groups.items(),
                              key=lambda kv: (-len(kv[1]), kv[0]))[:cap]:
        where = sorted({str(r.get("path", "")) for r in rows if r.get("path")})
        tail = ""
        if len(rows) > 1:
            tail = " x%d" % len(rows)
        if where:
            shown = ", ".join(where[:2])
            if len(where) > 2:
                shown += " and %d more" % (len(where) - 2)
            tail += " — %s" % shown
        lines.append("%s%s" % (title, tail))
    if len(groups) > cap:
        lines.append("... and %d more distinct finding(s); the full list is on "
                     "the Findings page" % (len(groups) - cap))
    return lines


def _ledger_trouble(row: dict) -> str:
    """One ledger row's failure, in the words a reader needs.

    "did not report" was the one phrase for every row that was not `ok`, so a
    stage refused one read of three reported two thirds of an answer under a
    line saying it reported nothing (review 3, R-44). The same verbs `_TROUBLE`
    keeps apart for a correlation, plus the one a partial read needs."""
    tool = as_text(row.get("tool")) or "?"
    status = as_text(row.get("status"))
    if status == "skipped":
        return "%s did not run" % tool
    if status == "error":
        return "%s ran and did not finish" % tool
    examined = _mapping(row.get("coverage")).get("examined")
    if isinstance(examined, bool) or not isinstance(examined, int):
        return "%s did not run" % tool
    if examined > 0:
        return "%s reported, with a read refused" % tool
    return "%s read nothing" % tool


def comparable_runs(root: str, man: dict) -> "Tuple[List[dict], Optional[int]]":
    """Every run of the same target the same way, and where this one sits.

    `None` for the position when this run is not among them, which is what a
    caller has to be able to tell apart from "first". A first run has nothing
    behind it, so the check that compares scanners against the previous run
    cannot run at all -- and the CLI said "every source that reported last time
    reported again" anyway. That is a claim about a comparison that never
    happened, on the first run of a target, which is exactly when a reader has
    least reason to doubt it (the operator's first `cargo` run, 2026-09-15)."""
    same = sorted((m for m in list_runs(root) if target_key(m) == target_key(man)),
                  key=lambda m: m["run_id"])
    ids = [m["run_id"] for m in same]
    here = man.get("run_id")
    return same, (ids.index(here) if here in ids else None)


def squawk_check(root: str, man: dict) -> List[dict]:
    """Evaluate the squawk rules over one run. Returns the codes raised, worst
    first. An empty list means nothing squawked — which is only meaningful
    because 7600 fires when the tool could not see, so silence here is a
    checked fact rather than an absence of news."""
    raised: List[dict] = []
    findings = load_findings(man["_dir"])
    ledger = man.get("ledger", [])

    # --- 7500: unlawful interference ---------------------------------------
    # Only a scanner that observes running behaviour can witness an attack in
    # progress. A static scanner reports a weakness at rest by definition, so
    # its findings never count toward 7500 no matter what words are in the check
    # name — "does not allow data exfiltration" is a policy check, not an
    # incident. Without this scope, every realistic IaC scan false-fired the
    # loudest alarm (measured: 53 checkov checks on TerraGoat tripped it).
    attacks = []
    for f in findings:
        sc = SCANNERS.get(f.get("scanner", ""))
        if not sc or sc.kind not in WITNESS_KINDS:
            continue
        # Match the classification, never the explanation. A scanner's
        # description is prose about what an attacker COULD do, and ZAP writes
        # "a malicious page loaded by the victim's user agent" into its CORS
        # advisory, which fired this alarm on five weaknesses at rest against
        # Juice Shop. The words in ATTACK_MARKERS are a finding TYPE vocabulary
        # (GuardDuty's UnauthorizedAccess, CryptoCurrency, Backdoor), so they
        # belong against the title and the rule id and nowhere else.
        # Two gates, and the first one does not read words at all. A control
        # evaluation is a weakness at rest by definition, so it is excluded
        # before any matching happens; then the type vocabulary is matched at
        # word boundaries. Either gate alone would have stopped the false 7500s measured in field
        # use; both are here because they
        # fail differently and a false "you are under attack" is the most
        # expensive thing this tool can print.
        if _is_control_evaluation(f):
            continue
        if _looks_like_an_attack(f):
            attacks.append(f)
    if attacks:
        raised.append({
            "code": "7500",
            "why": "%d finding(s) describe an attack in progress, not a weakness "
                   "at rest" % len(attacks),
            "detail": _detail_list(attacks)})

    # --- 7700: general emergency -------------------------------------------
    crit = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]
    if crit:
        raised.append({
            "code": "7700",
            "why": "%d critical finding(s) in this run" % len(crit),
            # The strapline travels with the alarm, because only the raiser
            # knows what was read. Absent, both renderers fall back to the
            # code's own words.
            "meaning": (None if man.get("scope") in LIVE_SCOPES
                        else STATIC_EMERGENCY),
            "detail": _detail_list(crit)})
    elif high and man.get("scope") == "url":
        raised.append({
            "code": "7700",
            "why": "%d high finding(s) against a RUNNING app — reachable now, "
                   "not theoretical" % len(high),
            # This branch earns 7700 on HIGH findings, because reachable now
            # beats a theoretical critical — and then it inherited the code's
            # own words, which say critical. A live probe of Juice Shop printed
            # "4 high finding(s) against a RUNNING app" and "(a critical
            # exposure is live)" four lines apart (the operator, 2026-09-16). The
            # scope half was right and the severity half was not: the earlier
            # pass set a strapline on the critical branch and left this one on
            # the fallback.
            "meaning": LIVE_HIGH_EMERGENCY,
            "detail": _detail_list(high)})

    # --- 7600: lost communications -----------------------------------------
    silent: List[str] = []

    # a stage that errored, or examined nothing, produced no real result; its
    # zero is not a clean scan. Both feed the lost-communications signal.
    for row in ledger:
        if row.get("status") in ("error", "gap", "skipped"):
            silent.append("%s (%s)" % (_ledger_trouble(row),
                                       row.get("detail", "")))

    # a scanner that reported in the previous comparable run and not in this one
    same, pos = comparable_runs(root, man)
    if pos is not None:
        if pos > 0:
            gapped_now = {row.get("tool") for row in ledger
                          if row.get("status") == "gap"}
            gone = sorted(same[pos - 1].get("_ok_tools", set())
                          - man.get("_ok_tools", set()) - gapped_now)
            for tool in gone:
                silent.append("%s reported last run and not this one" % tool)

    # a vulnerability database old enough to under-report
    for name, age, note in vuln_db_ages():
        if age is None:
            silent.append("%s has no vulnerability database (%s)" % (name, note))
        elif age > DB_STALE_DAYS:
            silent.append("%s vulnerability database is %d days old" % (name, age))

    if silent:
        raised.append({
            "code": "7600",
            "why": "%d source(s) did not fully report — a result from fewer "
                   "scanners is a floor, not a clean scan" % len(silent),
            "detail": silent[:5]})

    order = {"7500": 0, "7700": 1, "7600": 2}
    return sorted(raised, key=lambda r: order.get(r["code"], 9))


def squawk_lines(raised: List[dict]) -> List[str]:
    """Plain-text rendering for the CLI, with the account id masked.

    The masking happens HERE and not in `squawk_check`, and the difference
    matters: the record keeps the real ARN, because an operator cannot act on
    a masked one, and the evidence directory is theirs and owner-only. What
    gets masked is the thing that leaves the machine.

    An alarm's detail lines name the resources that raised it, and for a cloud
    finding a resource is an ARN with the account id in the middle. Those lines
    are the ones people paste into a thread, and they went out with all twelve
    digits while the header two lines above them was masked (measured on a real
    account, 2026-09-08)."""
    out = []
    for r in raised:
        name, meaning = SQUAWK_CODES[r["code"]]
        meaning = r.get("meaning") or meaning
        out.append("SQUAWK %s — %s: %s"
                   % (r["code"], name, redact_identifiers(r["why"])))
        for d in r["detail"]:
            out.append("    %s" % redact_identifiers(d))
        out.append("    (%s)" % meaning)
    return out


# Severity weights for the run score behind the trend line. The gaps between
# tiers are wide on purpose: one critical must outweigh a pile of lows, so the
# rating tracks exposure, not raw count.
TREND_WEIGHT = {"critical": 10000, "high": 1000, "medium": 100,
                "low": 10, "info": 1, "unknown": 1}


def _run_score(man: dict) -> int:
    sv = man.get("severities", {})
    return sum(TREND_WEIGHT.get(s, 1) * int(n) for s, n in sv.items())


def _run_incomplete(man: dict) -> bool:
    """True if this run could not fully look — a stage gapped or errored, a
    stage ran and examined nothing, or there is no ledger at all. A run with no
    record of what ran has no evidence it looked at anything, and must not be
    drawn as clean. Such a run's low score is a floor, not a reading."""
    if not man.get("ledger"):
        return True
    for row in man.get("ledger", []):
        # "skipped" is what runs written before 2026-09-07 recorded for a
        # scanner that was not installed. It never looked; it reads as a gap.
        if row.get("status") in ("gap", "error", "skipped"):
            return True
        cov = row.get("coverage")
        if cov and cov.get("examined") == 0:
            return True
    return False


# --------------------------------------------------------------------------- #
# Verification — the run chain and the decisions ledger, in one answer.
# --------------------------------------------------------------------------- #

VERIFY_EXIT_OK = 0
VERIFY_EXIT_FAILED = 1
VERIFY_EXIT_UNVERIFIABLE = 3


def verify_root(root: str, progress: Optional[Callable[[dict], None]] = None) -> dict:
    """Everything in one evidence root: the retention record's own chain, then
    every run against its digest, the chain and the previous verify, then the
    decisions ledger. Pure — it prints nothing and writes nothing, so the CLI
    and the web page cannot disagree about the answer.

    The previous verify is read first because it is what closes the holes a
    hash chain has on its own: nothing vouches for the newest line of a ledger
    or the newest run's digest, and nothing remembers a run that was simply
    deleted along with every mention of it. A recorded verify does both."""
    last = load_verify(root) or {}
    retention = verify_retention(root, str((last.get("retention") or {}).get("head", "")))
    runs = verify_runs(root, previous=last, progress=progress)
    ledger = verify_ledger(root, str((last.get("ledger") or {}).get("head", "")))
    report = {"root": root,
              "at": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
              "previous_at": last.get("at", ""),
              "runs": runs["runs"], "counts": runs["counts"],
              "total": runs["total"], "dropped": runs["dropped"],
              "pruned_runs": runs["pruned_runs"], "digests": runs["digests"],
              "failed": runs["failed"], "unverifiable": runs["unverifiable"],
              "ledger": ledger, "retention": retention}
    report["status"], report["exit"], report["summary"] = _verify_verdict(report)
    return report


def _verify_verdict(report: dict) -> Tuple[str, int, str]:
    """One word, one exit code, one sentence. Three states, never two: a run
    that could not be checked is `unverifiable`, which is neither a pass nor a
    failure and never reads as either."""
    ledger = report.get("ledger", {})
    retention = report.get("retention", {})
    pruned = report.get("pruned_runs") or []
    drops = [r for r in pruned if r.get("kind") == "drop"]
    trims = [r for r in pruned if r.get("kind") == "trim"]
    relied = ""
    if drops or trims:
        relied = " Retention removed %d run(s) and trimmed %d, each listed above" \
                 " — a record, not a proof." % (len(drops), len(trims))
    if report["failed"] or ledger.get("state") == "broken" \
            or retention.get("state") == "broken":
        parts = []
        for state in ("altered", "missing", "extra", "chain broken"):
            n = report["counts"].get(state, 0)
            if n:
                parts.append("%d %s" % (n, state))
        if ledger.get("state") == "broken":
            parts.append("the decisions ledger broken (%s)"
                         % ledger.get("detail", "no detail"))
        if retention.get("state") == "broken":
            parts.append("the retention record broken (%s)"
                         % retention.get("detail", "no detail"))
        return ("failed", VERIFY_EXIT_FAILED,
                "%d run(s) checked; %s.%s" % (report["total"], ", ".join(parts), relied))
    if report["unverifiable"] or ledger.get("state") == "unverifiable" \
            or retention.get("state") == "unverifiable":
        bits = []
        rows = report.get("runs") or []
        legacy = sum(1 for r in rows if r["state"] == "unverifiable"
                     and "schema" in r.get("detail", ""))
        unfinished = sum(1 for r in rows if r["state"] == "unverifiable"
                         and r.get("detail", "").startswith("unfinished"))
        other = report["unverifiable"] - legacy - unfinished
        if legacy:
            bits.append("%d run(s) were written before digests carried file "
                        "hashes" % legacy)
        if unfinished:
            bits.append("%d run(s) never finished and could not be checked" % unfinished)
        if other:
            bits.append("%d run(s) could not be checked" % other)
        if ledger.get("state") == "unverifiable":
            bits.append(ledger.get("detail", "the ledger could not be checked"))
        if retention.get("state") == "unverifiable":
            bits.append("the retention record: %s"
                        % retention.get("detail", "could not be checked"))
        return ("unverifiable", VERIFY_EXIT_UNVERIFIABLE,
                "%d of %d run(s) verified; %s.%s"
                % (report["counts"].get("ok", 0), report["total"], "; ".join(bits),
                   relied))
    if not report["total"]:
        return ("unverifiable", VERIFY_EXIT_UNVERIFIABLE,
                "No runs in this evidence root, so nothing was verified.")
    return ("ok", VERIFY_EXIT_OK,
            "%d run(s) verified unaltered since they were written; %s.%s"
            % (report["total"], ledger.get("detail", "no decisions recorded"), relied))


def verify_state(root: str) -> dict:
    """What the pages show: the last recorded verify, or the fact that there has
    never been one. Never verified is shown as never verified, not as ok."""
    doc = load_verify(root)
    if not doc:
        return {"status": "never", "at": "", "summary": "never verified",
                "total": 0}
    return {"status": doc.get("status", "unverifiable"), "at": doc.get("at", ""),
            "summary": doc.get("summary", ""), "total": doc.get("total", 0)}


__all__ = [
    'ACCOUNT_SERVICES',
    'ANYWHERE',
    'ATTACK_MARKERS',
    'CLOUD_CORRELATIONS',
    'CLOUD_DRILL',
    'CORRELATIONS',
    'DIFFERENTIAL_PAIRS',
    'DRILL_SUMS',
    'ENABLEMENT_LABELS',
    'ESTATE_PER_PAGE',
    'ESTATE_SORTS',
    'ESTATE_STATUSES',
    'ID_FIELDS',
    'INVENTORY_DOMAINS',
    'INVENTORY_LABELS',
    'JUDGED_PANELS',
    'KEY_STALE_DAYS',
    'LIVE_HIGH_EMERGENCY',
    'LIVE_SCOPES',
    'OUTSIDE_REACH',
    'PIN_WORDS',
    'PUBLIC_IS_A_CREDENTIAL',
    'REACHABLE_PROTOCOLS',
    'READING_STALE_HOURS',
    'SENSITIVE_PORTS',
    'SQUAWK_CODES',
    'STATIC_EMERGENCY',
    'TRACKED_COUNTS',
    'TREND_WEIGHT',
    'VERIFY_EXIT_FAILED',
    'VERIFY_EXIT_OK',
    'VERIFY_EXIT_UNVERIFIABLE',
    'WITNESS_KINDS',
    '_ATTACK_RE',
    '_TROUBLE',
    'CloudGraph',
    'CloudRule',
    'Correlation',
    'CorrelationInput',
    'DatabaseReach',
    '_also_admits',
    '_boundary',
    '_by_resource',
    '_comparable_regions',
    '_d_accounts',
    '_d_analyzer',
    '_d_apis',
    '_d_balancers',
    '_d_buckets',
    '_d_databases',
    '_d_distributions',
    '_d_ecs_tasks',
    '_d_esc_roles',
    '_d_functions',
    '_d_iam_roles',
    '_d_instances',
    '_d_interfaces',
    '_d_messaging_public',
    '_d_open_groups',
    '_d_public_subnets',
    '_d_regional',
    '_d_regions',
    '_d_roles',
    '_d_services',
    '_d_simple',
    '_d_unreadable',
    '_d_users',
    '_detail_list',
    '_ecs_note',
    '_eks_note',
    '_enablement_changes',
    '_guardduty_features',
    '_index',
    '_instance_groups',
    '_instance_public_ip',
    '_inv_resources',
    '_is_control_evaluation',
    '_is_untouched_default',
    '_judged',
    '_key_age_days',
    '_ledger_trouble',
    '_looks_like_an_attack',
    '_mapping',
    '_named',
    '_named_exposed_ports',
    '_named_things',
    '_names',
    '_profile_caveats',
    '_reachable_instances',
    '_recorder_caveats',
    '_region_inventory',
    '_role_for',
    '_roll_up',
    '_row',
    '_row_status',
    '_rule_public_unencrypted',
    '_rule_reachable_admin_port',
    '_rule_reachable_over_permitted',
    '_rule_secret_in_build',
    '_run_incomplete',
    '_run_score',
    '_sev_rank',
    '_shown',
    '_stage_trouble',
    '_unanswered',
    '_unread_caveat',
    '_verify_verdict',
    '_world_open_ports',
    'analyzer_agreement',
    'analyzer_caveats',
    'analyzer_findings',
    'analyzer_summary',
    'apply_estate_query',
    'bucket_policy_held_shut',
    'build_cloud_graph',
    'cloud_correlations',
    'cloud_drill',
    'cloud_findings',
    'comparable_runs',
    'compare_readings',
    'container_findings',
    'container_summary',
    'correlate',
    'correlate_cloud',
    'correlation_findings',
    'database_reachability',
    'dataservice_caveats',
    'dataservice_findings',
    'dataservice_summary',
    'diff_lines',
    'edge_findings',
    'edge_function_count',
    'edge_functions',
    'edge_gaps',
    'edge_summary',
    'enablement_summary',
    'estate_rows',
    'frontdoor_caveats',
    'frontdoor_findings',
    'frontdoor_summary',
    'headline_facts',
    'iam_caveats',
    'iam_findings',
    'iam_summary',
    'interface_owners',
    'inventory_caveats',
    'inventory_notes',
    'inventory_summary',
    'org_caveats',
    'org_findings',
    'org_summary',
    'partial_caveat',
    'public_subnets',
    'reach_words',
    'reading_age',
    'regions_seen',
    'role_findings',
    'scanner_differential',
    'split_regions',
    'squawk_check',
    'squawk_lines',
    'storage_caveats',
    'storage_findings',
    'storage_summary',
    'verify_root',
    'verify_state',
    'watching_gaps',
]


# --------------------------------------------------------------------------- #
# The estate: every open finding across every live target, in one model.
#
# Every findings view before this was one run. The question a security engineer
# actually asks — "where is this rule failing across everything I look after" —
# had no page, and the Overview's own totals could not link to their proof
# because the proof had nowhere to live.
#
# Two pure functions, so the shape can be tested without parsing HTML: one
# builds the rows, one filters and pages them.
# --------------------------------------------------------------------------- #

ESTATE_PER_PAGE = 50
ESTATE_SORTS = ("severity", "instances", "targets", "first_seen", "last_seen")
ESTATE_STATUSES = ("open", "regressed", "decided", "undecided", "partial")


def estate_rows(root: str, live: Dict[str, dict]) -> List[dict]:
    """One row per (scanner, rule) across every live target's newest run.

    Grouped by the same key the Findings and Triage pages use, so the three
    never disagree about what one advisory is. The same identity in two targets
    stays two instances under one row: merging them would claim the two are the
    same finding, and they are the same *rule* on different machines."""
    by_rule: Dict[Tuple[str, str], dict] = {}
    for man in live.values():
        target = str(man.get("target", ""))
        run_id = str(man.get("run_id", ""))
        decided = current_decisions(root, target)
        timeline, _persisted = history_entries(root, man)
        incomplete = _run_incomplete(man)
        for f in load_findings(man["_dir"]):
            key = (str(f.get("scanner", "")), rule_of(f))
            row = by_rule.setdefault(key, {
                "scanner": key[0], "rule": key[1], "title": str(f.get("title", "")),
                "severity": f.get("severity", "unknown"), "instances": 0,
                "targets": {}, "states": [], "regressed": 0,
                "first_seen": "", "last_seen": "", "paths": set(),
                "identities": set(), "incomplete": False})
            row["instances"] += 1
            row["paths"].add(str(f.get("path", "")))
            row["identities"].add(str(f.get("identity", "")))
            if _sev_rank(f.get("severity")) < _sev_rank(row["severity"]):
                row["severity"] = f.get("severity", "unknown")
                row["title"] = str(f.get("title", ""))
            tgt = row["targets"].setdefault(
                target, {"run_id": run_id, "instances": 0, "regressed": 0,
                         "incomplete": incomplete,
                         "label": str(man.get("service_label", ""))})
            tgt["instances"] += 1
            row["incomplete"] = row["incomplete"] or incomplete
            row["states"].append(decided.get((str(f.get("scanner", "")),
                                              str(f.get("identity", "")))))
            tl = timeline.get((str(f.get("scanner", "")), str(f.get("identity", "")))) or {}
            if tl.get("status") == "regressed":
                row["regressed"] += 1
                tgt["regressed"] += 1
            for field, keep_min in (("first_seen", True), ("last_seen", False)):
                val = str(tl.get(field) or "")
                cur = row[field]
                if val and (not cur or (val < cur if keep_min else val > cur)):
                    row[field] = val
    out = []
    for row in by_rule.values():
        row["decision"] = summarize(row["states"])
        row["paths"] = sorted(p for p in row["paths"] if p)
        row["identities"] = sorted(row["identities"])
        del row["states"]
        out.append(row)
    return out


def _sev_rank(sev) -> int:
    try:
        return SEVERITY_ORDER.index(str(sev))
    except ValueError:
        return len(SEVERITY_ORDER)


def _row_status(row: dict) -> List[str]:
    """Every status word that applies to a row, so a filter can match any."""
    words = []
    state = (row.get("decision") or {}).get("status", "open")
    if row.get("regressed"):
        words.append("regressed")
    if state == "open":
        words.extend(["open", "undecided"])
    elif state == "partial":
        # Reviewed 3 of 5 is not "decided": the summary refuses to call it
        # that, and a filter that did would hide the two nobody has looked at.
        words.append("partial")
    else:
        words.append("decided")
        words.append(state)
    return words


def apply_estate_query(rows: List[dict], sev: Optional[str] = None,
                       scanner: Optional[str] = None, target: Optional[str] = None,
                       status: Optional[str] = None, q: Optional[str] = None,
                       sort: Optional[str] = None, page: int = 1,
                       per_page: int = ESTATE_PER_PAGE) -> dict:
    """Filter, sort and page the rows, and say exactly what was done.

    The result carries the numbers the page has to print: how many rows matched,
    which slice is shown, how many pages there are, and whether the sort asked
    for was understood. Nothing is capped silently (I12) — a filter leaving
    twelve thousand rows says twelve thousand."""
    # A value no row could ever match is said out loud, the way an unknown
    # sort already is. Without this, ?sev=critcal showed "0 of 0 rows" under a
    # chip, which reads as "nothing critical" rather than "you misspelt it".
    # `sev` takes one severity or several, comma-separated: the Overview's
    # "critical & high" tile counts both and has to land on both, or the number
    # it shows is not the number its proof shows. It linked to critical alone
    # for a day, and 102 landed on 15.
    sevs = [x.strip() for x in (sev or "").split(",") if x.strip()]
    unknown: List[str] = []
    for x in sevs:
        if x not in SEVERITY_ORDER:
            unknown.append("sev=%s is not a severity" % x)
    if status and status not in ESTATE_STATUSES:
        unknown.append("status=%s is not a status" % status)
    if scanner and rows and scanner not in {r.get("scanner") for r in rows}:
        unknown.append("scanner=%s is not on any row" % scanner)
    if target and rows and target not in {t for r in rows for t in r.get("targets", {})}:
        unknown.append("target=%s is not a live target" % target)
    matched = []
    for row in rows:
        if sevs and row.get("severity") not in sevs:
            continue
        if scanner and row.get("scanner") != scanner:
            continue
        if target and target not in row.get("targets", {}):
            continue
        if status and status not in _row_status(row):
            continue
        if q:
            needle = q.lower()
            hay = " ".join([str(row.get("title", "")), str(row.get("rule", "")),
                            " ".join(row.get("identities", [])),
                            " ".join(row.get("paths", []))]).lower()
            if needle not in hay:
                continue
        matched.append(row)

    asked = sort or ""
    key = asked if asked in ESTATE_SORTS else "severity"
    fell_back = bool(asked) and asked not in ESTATE_SORTS
    if key == "severity":
        matched.sort(key=lambda r: (_sev_rank(r["severity"]), -r["instances"],
                                    r["scanner"], r["rule"]))
    elif key == "instances":
        matched.sort(key=lambda r: (-r["instances"], r["scanner"], r["rule"]))
    elif key == "targets":
        matched.sort(key=lambda r: (-len(r["targets"]), r["scanner"], r["rule"]))
    else:                                   # first_seen / last_seen, oldest first
        matched.sort(key=lambda r: (str(r.get(key) or "~"), r["scanner"], r["rule"]))

    total = len(matched)
    pages = max(1, (total + per_page - 1) // per_page)
    # A page past the end is the last page, said out loud rather than an empty
    # table that reads as "nothing matched".
    wanted = page
    page = max(1, min(page, pages))
    start = (page - 1) * per_page
    shown = matched[start:start + per_page]
    return {"rows": shown, "total": total, "page": page, "pages": pages,
            "per_page": per_page, "clamped": wanted != page,
            "first": start + 1 if shown else 0, "last": start + len(shown),
            "instances": sum(r["instances"] for r in matched),
            "targets": len({t for r in matched for t in r["targets"]}),
            "sort": key, "sort_fell_back": fell_back, "unknown_filters": unknown}

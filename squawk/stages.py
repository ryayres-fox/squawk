"""How each scanner is invoked, the stage and service registries, and the safety rails."""

import ipaddress
import json
import os
import socket
from typing import Callable, Dict, List, NamedTuple, Optional, Tuple, Union
from urllib.parse import urlparse

from squawk.core import (
    LOG,
    PROFILE_KEYS,
    RunContext,
    _report,
    env,
    redact_identifiers,
    run_cmd,
    tool_path,
)
from squawk.probes import (
    aws_analyzer,
    aws_containers,
    aws_dataservices,
    aws_edge,
    aws_enablement,
    aws_frontdoor,
    aws_iam_graph,
    aws_inventory,
    aws_organization,
    aws_storage,
    recon_probe,
    self_audit,
    skill_audit,
)


def stage_gitleaks(ctx: RunContext) -> Tuple[List[str], int]:
    src = ctx.target
    cmd = ["gitleaks", "detect", "--source", src, "--report-format", "json",
           "--report-path", "-", "--redact", "--exit-code", "0"]
    # `--no-git` was decided by SCOPE alone, and scope is what the operator
    # ASKED for; `.git` is what is actually there. Pointed at a directory that
    # holds repositories rather than being one -- "GitHub Repos/acme-platform" on
    # the operator's machine -- gitleaks was told to walk a git history that does
    # not exist, reported "0 commits scanned · scanned ~0 bytes", and found
    # nothing. Reproduced against gitleaks 8.30.1: a synthetic `ghp_`-shaped
    # token in that tree is MISSED entirely without this and found with it.
    #
    # The gap machinery caught the zero denominator and said so, which is why
    # it was never a silent false clean. It was still a permanent one: every
    # run of that target lost the secrets scanner, and the scan the operator
    # asked for never happened.
    #
    # `exists`, not `isdir`: in a worktree or a submodule `.git` is a FILE
    # holding a gitdir pointer, and treating those as not-a-repository would
    # throw away the history this is here to read.
    #
    # And WALKED UP, not checked at the target alone. A repo-scope target that
    # is a subdirectory of a checkout has no `.git` of its own, and gitleaks
    # in git mode finds the repository from a subdirectory by itself -- so the
    # check sent every `--repo path/to/subdir` run into `--no-git`, and a
    # secret removed from the tree and left in history was missed under a
    # coverage line that read as though the history had been scanned
    # (review 3, R-43).
    if ctx.scope != "repo" or not _inside_a_repository(src):
        cmd.append("--no-git")
    return cmd, 900


def _inside_a_repository(path: str) -> bool:
    """Whether `path` is a git checkout or sits inside one."""
    here = os.path.abspath(path)
    while True:
        if os.path.exists(os.path.join(here, ".git")):
            return True
        parent = os.path.dirname(here)
        if parent == here:
            return False
        here = parent


def stage_semgrep(ctx: RunContext) -> Tuple[List[str], int]:
    return ["semgrep", "--config", "auto", "--json", "--quiet", ctx.target], 1200


def stage_bandit(ctx: RunContext) -> Tuple[List[str], int]:
    return ["bandit", "-r", ctx.target, "-f", "json", "-q"], 600


def stage_checkov(ctx: RunContext) -> Tuple[List[str], int]:
    # `--compact` and `--quiet` are documented as "in case of CLI output" and
    # this asks for JSON, so they never did anything here -- and one of them is
    # what a checkov on the operator's machine refused, which cost the whole IaC
    # half of a compliance run (2026-09-12). A flag that changes nothing about
    # the answer is a flag that can only fail.
    return ["checkov", "-d", ctx.target, "-o", "json"], 900


def stage_trivy_config(ctx: RunContext) -> Tuple[List[str], int]:
    return ["trivy", "config", "-f", "json", "-q", ctx.target], 900


def stage_trivy_fs(ctx: RunContext) -> Tuple[List[str], int]:
    return ["trivy", "fs", "-f", "json", "-q", ctx.target], 900


def stage_trivy_image(ctx: RunContext) -> Tuple[List[str], int]:
    return ["trivy", "image", "-f", "json", "-q", ctx.target], 900


def stage_syft(ctx: RunContext) -> Tuple[List[str], int]:
    # syft scans a directory path or an image name identically by position.
    return ["syft", "-q", "-o", "syft-json", ctx.target], 900


def stage_grype(ctx: RunContext) -> Tuple[List[str], int]:
    sbom = ctx.artifacts.get("sbom")
    if not sbom:
        return [], 0  # signals "skipped — no SBOM to read"
    return ["grype", "-q", "-o", "json", "sbom:%s" % sbom], 900


ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"


# ZAP flags that decide whether a scan sees the app at all.
#
# -j runs the AJAX spider alongside the traditional one. Without it, a
# JavaScript single-page app is a shell of static HTML to the crawler: it finds
# almost no endpoints, so the active scanner has almost no parameter to inject
# into. Measured against Juice Shop without -j: 91 findings and not one SQLi or
# XSS, on an app built to be full of both, because the crawl never reached the
# REST API the injectable parameters live behind.
#
# -T is NOT a cap on the scan. ZAP's own help: "max time in minutes to wait for
# ZAP to start and the passive scan to run". This comment used to claim it
# bounded the whole scan so an active scan could not run unbounded, which was a
# control that did not exist. The real bound is the subprocess timeout below,
# and hitting that kills the container before it writes its report, so the
# timeout is set above what a crawl of this shape needs rather than at it.
# The built-in budgets come from the profile table, so a profile and the code
# agree on one number; a profile (squawk.toml) overrides them per service, per
# target or per tool, and the run prints what it changed.
ZAP_SPIDER_MINS = str(PROFILE_KEYS["zap_spider_minutes"].builtin)        # -m: spider budget
ZAP_ACTIVE_SPIDER_MINS = str(PROFILE_KEYS["zap_active_spider_minutes"].builtin)
ZAP_STARTUP_WAIT = str(PROFILE_KEYS["zap_startup_wait"].builtin)         # -T: not a cap

# Which profile settings each stage reads besides its timeout, so the run's
# Profile block and `config show` list exactly the knobs that reach argv.
STAGE_KNOBS: Dict[str, Tuple[str, ...]] = {
    "securityhub-findings": ("cloud_max_findings",),
    "cloud-inventory": ("cloud_inventory_budget", "cloud_call_timeout"),
    "cloud-enablement": ("cloud_inventory_budget", "cloud_call_timeout"),
    "cloud-iam": ("cloud_max_principals", "cloud_call_timeout"),
    "cloud-edge": ("cloud_max_functions", "cloud_call_timeout"),
    "cloud-storage": ("cloud_max_buckets", "cloud_call_timeout"),
    "cloud-containers": ("cloud_max_items", "cloud_call_timeout"),
    "cloud-dataservices": ("cloud_max_items", "cloud_call_timeout"),
    "cloud-org": ("cloud_call_timeout",),
    "cloud-frontdoor": ("cloud_inventory_budget", "cloud_call_timeout"),
    "zap-baseline": ("zap_spider_minutes", "zap_memory_mb"),
    "zap-active": ("zap_active_spider_minutes", "zap_startup_wait", "zap_memory_mb"),
}


# Where ZAP looks for JVM arguments of its own, inside the official image.
ZAP_JVM_PROPS = "/home/zap/.ZAP/.ZAP_JVM.properties"


def memory_args(ctx: RunContext, tool: str) -> List[str]:
    """`docker run` flags setting ZAP's Java heap, or none.

    Not a container limit. ZAP's launcher takes a quarter of the memory it
    believes it has, and in a container under cgroup v2 it reads the *host's*
    memory — so `docker -m` changes nothing about how much ZAP asks for, and
    was measured to break this image's baseline scan outright (rc=3 in 40
    seconds at 2048m and at 4096m, heap set or not, larger /dev/shm or not,
    where the same scan with no cap passes). What ZAP does honour is the JVM
    properties file it reads at start-up, so that is what this writes: one
    line, `-Xmx<N>m`, mounted read-only. It lands in the run's own raw
    directory, so the evidence records the heap the probe ran under.

    Measured 2026-09-08 against Juice Shop: no setting gives `-Xmx1983m` on an
    8 GB machine; `zap_memory_mb = 1024` gives `-Xmx1024m` and the same scan
    passes with the same findings."""
    prof = getattr(ctx, "profile", None)
    if prof is None:
        return []
    value = prof.setting(getattr(ctx, "service", ""), ctx.target, tool,
                         "zap_memory_mb", None).value
    if not isinstance(value, int) or isinstance(value, bool):
        return []
    raw_dir = os.path.dirname(ctx.raw_path) or "."
    path = os.path.join(raw_dir, "zap-jvm.properties")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("-Xmx%dm\n" % value)
    except OSError:
        return []            # no heap set rather than a mount of nothing
    return ["-v", "%s:%s:ro" % (path, ZAP_JVM_PROPS)]


def knob(ctx: RunContext, tool: str, key: str) -> str:
    """A stage's budget as an argv string: the profile's value for this
    service, target and tool, or the built-in. A fixture that is not a
    RunContext carries no profile and gets the built-in."""
    builtin = PROFILE_KEYS[key].builtin
    prof = getattr(ctx, "profile", None)
    if prof is None or builtin is None:
        return str(builtin)
    return str(prof.setting(getattr(ctx, "service", ""), ctx.target, tool, key,
                            builtin).value)


def container_name(stage: str, ctx: RunContext) -> str:
    """The name every container Squawk starts runs under, so stopping Squawk
    can stop it by name. Killing the `docker run` client after its grace
    period does not stop the container — it detaches it — and a ZAP scan that
    was "stopped" that way kept attacking the target. Measured, not assumed:
    the client died, `docker ps` still listed the container."""
    run_id = os.path.basename(str(getattr(ctx, "run_dir", "") or "").rstrip("/")) or "run"
    safe = "".join(c if c.isalnum() or c in "_.-" else "-" for c in run_id)
    return "squawk-%s-%s" % (stage, safe)


def stage_zap_baseline(ctx: RunContext) -> Tuple[List[str], int]:
    # The ZAP baseline scan against a RUNNING app: it spiders, then runs the
    # PASSIVE scan rules on what it saw. zap-baseline.py does not run the active
    # scanner, so injectable flaws (SQLi, XSS) are out of scope by design; active
    # testing is zap-full-scan.py, a separate and heavier stage. It writes its
    # JSON report to a file (-J), so this stage is marked writes_report and the
    # runner reads that file.
    #
    # Distros (Kali included) ship ZAP without the zap-baseline.py wrapper, which
    # only comes with the ZAP Docker image / full release. So prefer the native
    # script if it happens to be on PATH, and otherwise run the official image
    # over host networking (so the container's 127.0.0.1 is the host's target)
    # with the run's raw dir mounted as ZAP's working dir for the report.
    args = ["-m", knob(ctx, "zap", "zap_spider_minutes"), "-j", "-I"]
    if tool_path("zap-baseline.py"):
        return (["zap-baseline.py", "-t", ctx.target, "-J", ctx.raw_path,
                 *args], 2400)
    raw_dir = os.path.dirname(ctx.raw_path) or "."
    report = os.path.basename(ctx.raw_path)
    return (["docker", "run", "--rm", "--network", "host",
             "--name", container_name("zap-baseline", ctx),
             *memory_args(ctx, "zap"),
             "-v", "%s:/zap/wrk:rw" % raw_dir, ZAP_IMAGE,
             "zap-baseline.py", "-t", ctx.target, "-J", report,
             *args], 2400)


def stage_zap_active(ctx: RunContext) -> Tuple[List[str], int]:
    # The ZAP full scan: spider, then the ACTIVE scanner, which sends real
    # attack traffic (injection, traversal, command-execution probes) at a
    # RUNNING app. This is the stage that can find what a passive baseline
    # cannot: SQLi, XSS and their kin. It runs only under the url scope behind
    # dast_target_ok, so it never aims at an address you do not own. Same
    # native-or-image choice as the baseline stage.
    args = ["-m", knob(ctx, "zap", "zap_active_spider_minutes"), "-j",
            "-T", knob(ctx, "zap", "zap_startup_wait"), "-I"]
    if tool_path("zap-full-scan.py"):
        return (["zap-full-scan.py", "-t", ctx.target, "-J", ctx.raw_path,
                 *args], 5400)
    raw_dir = os.path.dirname(ctx.raw_path) or "."
    report = os.path.basename(ctx.raw_path)
    return (["docker", "run", "--rm", "--network", "host",
             "--name", container_name("zap-active", ctx),
             *memory_args(ctx, "zap"),
             "-v", "%s:/zap/wrk:rw" % raw_dir, ZAP_IMAGE,
             "zap-full-scan.py", "-t", ctx.target, "-J", report,
             *args], 5400)


def stage_securityhub(ctx: RunContext) -> Tuple[List[str], int]:
    # Read the findings the account already holds, as the identity in the AWS
    # credential chain. No credential touches argv (credential rule 1): the
    # CLI reads AWS_PROFILE / ~/.aws itself, and the region comes from the
    # profile. Active findings still open.
    #
    # BOUNDED, and that is the whole point. Unbounded, the CLI paginates a
    # hundred findings at a time until it has every one the account holds:
    # measured on a large estate that ran past its budget and would
    # have produced nothing, because a stage killed at its budget throws its
    # output away. `--max-items` stops it, and the CLI's own documentation is
    # explicit that when there is more it returns a NextToken — so the answer
    # comes back in seconds carrying the proof that it is a floor.
    filters = json.dumps({
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"},
                           {"Value": "NOTIFIED", "Comparison": "EQUALS"}]})
    return (["aws", "securityhub", "get-findings", "--output", "json",
             "--filters", filters,
             "--max-items", knob(ctx, "awscli", "cloud_max_findings")], 600)


# A stage spec binds a tool, a display mode, its command builder, and any
# artifact it produces for a downstream stage.
class StageSpec(NamedTuple):
    tool: str
    mode: str
    build: Callable[[RunContext], Tuple[List[str], int]]
    produces: Optional[str] = None      # artifact key, e.g. "sbom"
    requires: Optional[str] = None      # artifact key it needs upstream
    writes_report: bool = False         # stage writes its report to ctx.raw_path
    # An internal stage returns the raw JSON, or (json, status, detail) to
    # declare its own outcome — "I could not look" instead of an empty result.
    internal: Optional[Callable[["RunContext"], "Union[str, Tuple[str, str, str]]"]] = None


def stage_recon(_ctx: RunContext) -> Tuple[List[str], int]:
    return [], 0  # internal stage; the runner calls spec.internal instead


STAGES: Dict[str, StageSpec] = {
    "recon": StageSpec("recon", "discover", stage_recon, internal=recon_probe),
    "skillaudit": StageSpec("skillaudit", "AST10", stage_recon, internal=skill_audit),
    "selfaudit": StageSpec("selfaudit", "host", stage_recon, internal=self_audit),
    "gitleaks": StageSpec("gitleaks", "detect", stage_gitleaks),
    "semgrep": StageSpec("semgrep", "auto", stage_semgrep),
    "bandit": StageSpec("bandit", "recursive", stage_bandit),
    "checkov": StageSpec("checkov", "directory", stage_checkov),
    "trivy-config": StageSpec("trivy", "config", stage_trivy_config),
    "trivy-fs": StageSpec("trivy", "fs", stage_trivy_fs),
    "trivy-image": StageSpec("trivy", "image", stage_trivy_image),
    "syft": StageSpec("syft", "sbom", stage_syft, produces="sbom"),
    "grype": StageSpec("grype", "cve", stage_grype, requires="sbom"),
    "zap-baseline": StageSpec("zap", "baseline", stage_zap_baseline,
                              writes_report=True),
    "zap-active": StageSpec("zap", "active", stage_zap_active,
                            writes_report=True),
    "securityhub-findings": StageSpec("awscli", "securityhub", stage_securityhub),
    "cloud-inventory": StageSpec("cloudinv", "inventory", stage_recon,
                                 internal=aws_inventory),
    "cloud-enablement": StageSpec("cloudenable", "watching", stage_recon,
                                  internal=aws_enablement),
    "cloud-iam": StageSpec("cloudiam", "identity", stage_recon,
                           internal=aws_iam_graph),
    "cloud-edge": StageSpec("cloudedge", "edge", stage_recon,
                            internal=aws_edge),
    "cloud-storage": StageSpec("cloudstore", "storage", stage_recon,
                               internal=aws_storage),
    "cloud-containers": StageSpec("cloudcontain", "containers", stage_recon,
                                  internal=aws_containers),
    "cloud-dataservices": StageSpec("clouddata", "data services", stage_recon,
                                    internal=aws_dataservices),
    "cloud-org": StageSpec("cloudorg", "estate", stage_recon,
                           internal=aws_organization),
    "cloud-frontdoor": StageSpec("cloudfront", "frontdoor", stage_recon,
                                 internal=aws_frontdoor),
    "cloud-analyzer": StageSpec("cloudanalyzer", "external access", stage_recon,
                                internal=aws_analyzer),
}


# --------------------------------------------------------------------------- #
# Services — the kiosk. A service is an ordered list of stages plus the scope
# it runs against and an explicit statement of what it does NOT cover.
# --------------------------------------------------------------------------- #


class Service(NamedTuple):
    key: str
    label: str
    scope: str                      # repo | dir | image
    stages: Tuple[str, ...]
    rough_time: str
    not_covered: str


SERVICES: Dict[str, Service] = {
    "preflight": Service(
        "preflight", "Pre-flight check", "repo",
        ("gitleaks", "semgrep", "bandit", "checkov", "trivy-config"),
        "~60s", "No SBOM/CVE scan, no DAST, no cloud config."),
    "contraband": Service(
        "contraband", "Contraband sweep", "repo", ("gitleaks",),
        "~15s", "Secrets only. No code, dependency, or IaC analysis."),
    "customs": Service(
        "customs", "Customs manifest", "repo", ("syft", "grype"),
        "~70s", "Dependencies only. No source, secret, or IaC analysis."),
    "compliance": Service(
        "compliance", "Compliance audit", "repo", ("checkov", "trivy-config"),
        "~50s", "IaC/config only. No source, secret, or dependency analysis."),
    "baggage": Service(
        "baggage", "Baggage check", "dir",
        ("gitleaks", "semgrep", "bandit", "trivy-fs", "syft", "grype"),
        "~90s", "No git history (dir scope). No IaC policy, no DAST."),
    "cargo": Service(
        "cargo", "Cargo scan", "image", ("trivy-image", "syft", "grype"),
        "~90s", "Image only. No source, secret, or IaC analysis of the build."),
    "skillaudit": Service(
        "skillaudit", "Skill audit", "dir", ("skillaudit",),
        "~15s", "Static AST10 checks on agent skills (SKILL.md) and MCP configs "
        "only. Cannot see runtime behaviour — AST01 malicious execution, AST06 "
        "isolation, and AST08/10 are partial. Maps to the OWASP Agentic Skills "
        "Top 10 (v1.0 2026)."),
    "selfaudit": Service(
        "selfaudit", "Instrument check", "host", ("selfaudit",),
        "~5s", "Audits the machine running the scans, not any target: logging, "
        "evidence permissions and free space, clock synchronisation, host audit "
        "trail, privilege, PATH and code integrity, database freshness. It "
        "cannot tell you the host is uncompromised. It checks the conditions "
        "that make a finding trustworthy, not the absence of an intruder."),
    "recon": Service(
        "recon", "Target recon", "url", ("recon",),
        "~20s", "Discovery only — finds reachable web apps on the target and "
        "offers each as a DAST target. Sends no attacks; a private target you "
        "own is still required."),
    "liveprobe": Service(
        "liveprobe", "Live app probe", "url", ("zap-baseline",),
        "~5-10min", "Passive DAST baseline of a RUNNING app: it crawls, with "
        "the AJAX spider so a single-page app is more than its static shell, "
        "and reads the responses for misconfiguration and information "
        "disclosure. It does not attack, so injectable flaws (SQLi, XSS) and "
        "business logic are not tested — their absence here is a coverage "
        "limit, not a clean result. The URL count on the run says how much of "
        "the app it reached. Point it at a target you own on a private network."),
    "activeprobe": Service(
        "activeprobe", "Active app probe", "url", ("zap-active",),
        "~20-60min", "Active DAST of a RUNNING app: ZAP's active scanner sends "
        "real attack traffic (injection, traversal, command-execution probes) "
        "to find what a passive baseline cannot — SQLi, XSS and their kin. "
        "Unauthenticated, no business logic, and no authenticated area, so "
        "anything behind a login is untested. It is only as good as its crawl: "
        "check the URL count on the run, because an injectable parameter the "
        "crawl never reached cannot be attacked, and finding none of them is "
        "then a coverage limit rather than a clean result. It attacks, so it "
        "runs only against a private address, or a public one you have "
        "acknowledged with SQUAWK_DAST_ACK. It cannot tell whether you own "
        "the target; nothing can. That part is on you."),
    "cloudinventory": Service(
        "cloudinventory", "Cloud inventory (AWS)", "aws",
        ("cloud-org", "cloud-inventory", "cloud-enablement",
         "cloud-iam", "cloud-edge", "cloud-frontdoor", "cloud-storage",
         "cloud-containers", "cloud-dataservices", "cloud-analyzer"),
        "~14-45 min",
        # What a scan says it does not cover is the sentence a reader trusts
        # to decide what a quiet answer means, so it is part of the product.
        # It has drifted twice. The first repair (2026-09-09) wrote this
        # comment and did not change the sentence below it, which went on
        # naming ECS, EKS, SNS/SQS and Secrets Manager as unread through two
        # releases that read all four -- caught in field use 2026-09-10.
        # It is now held by TestCoverageProseMatchesWhatIsRead, which reads
        # the services the probes actually call and fails any sentence here
        # that denies reading one of them. Add a probe, and this text has to
        # keep up or the suite goes red.
        "One account \u2014 whichever the credential chain resolves to \u2014 in "
        "every enabled region the budget reaches. DynamoDB, EFS and Redshift "
        "are not read, so a data store of one of those kinds would not appear. "
        "Which services are watching is read per region; whether they are "
        "configured well is not. The IAM graph is read as written: no request "
        "is simulated, so a permissions boundary or an SCP could stop a path "
        "named here. Object contents, message bodies and secret values are "
        "never read \u2014 only the settings that decide who could read them. "
        "Where the account runs an AWS Access Analyzer, its findings are read "
        "and shown beside the policy readers here; where it runs none, those "
        "readers are the only answer and say so."),
    "cloudaws": Service(
        "cloudaws", "AWS Security Hub", "aws", ("securityhub-findings",),
        "~1-3min", "Reads the findings the account already holds in Security Hub, "
        "as the read-only identity in your AWS credential chain. Squawk never "
        "stores a credential and never passes one on the command line. It does "
        "not scan resources itself: if Security Hub is off in the profile's "
        "region, the run reads as a gap, not clean. Requires SQUAWK_CLOUD_ACK=1, "
        "because it queries a live estate."),
}


def cloud_target_ok() -> Tuple[bool, str]:
    """Querying a live estate is a deliberate act: it needs SQUAWK_CLOUD_ACK=1,
    the same shape as the DAST private-target rail (credential rule 8)."""
    if env("CLOUD_ACK"):
        return True, "SQUAWK_CLOUD_ACK set"
    return False, ("set SQUAWK_CLOUD_ACK=1 to acknowledge that this reads a live AWS "
                   "account, as the identity in your credential chain")


def aws_identity(timeout: int = 20) -> Tuple[Optional[dict], str]:
    """Who the AWS credential chain resolves to, or why not. Squawk never
    holds the credential; it asks the CLI, which reads AWS_PROFILE / ~/.aws
    itself (credential rules 1 and 3)."""
    if not tool_path("aws"):
        return None, "aws CLI not installed"
    code, out, err = run_cmd(["aws", "sts", "get-caller-identity", "--output", "json"],
                             None, timeout)
    if code != 0:
        # Redacted before it is returned, for the same reason as `_aws_json`:
        # this string becomes a detail that is written into evidence, and an
        # STS error under SSO carries the operator's address (review R-3).
        lines = (err or out or "sts get-caller-identity failed").strip().splitlines()
        text = lines[-1] if lines else "sts get-caller-identity failed"
        return None, redact_identifiers(text)[:200]
    data = _report(out, dict)
    if not data.get("Account"):
        return None, "no Account in the identity response"
    return ({"Account": str(data["Account"]), "Arn": str(data.get("Arn", "")),
             "UserId": str(data.get("UserId", ""))}, "")


# Managed policies that can write, and the permission-set names built from
# them. A role called AdministratorAccess-<account> or
# AWSReservedSSO_PowerUserAccess_<hash> is an SSO permission set wearing its
# policy's name.
WRITE_CAPABLE = ("AdministratorAccess", "PowerUserAccess")
READ_ONLY_POLICIES = ("SecurityAudit", "ViewOnlyAccess", "ReadOnlyAccess",
                      "AWSSecurityHubReadOnlyAccess")


def _role_or_user(arn: str) -> Tuple[str, str]:
    """("role", name) or ("user", name) from an ARN, or ("", "")."""
    tail = arn.rsplit(":", 1)[-1]
    if tail.startswith("assumed-role/"):
        return "role", tail.split("/")[1] if "/" in tail else ""
    if tail.startswith("role/"):
        return "role", tail.split("/", 1)[1]
    if tail.startswith("user/"):
        return "user", tail.rsplit("/", 1)[-1]
    return "", ""


def _attached_policies(kind: str, name: str, timeout: int) -> Optional[List[str]]:
    """Every policy on the identity — managed and inline — or None when it
    cannot look. Read-only calls, and a failure is "could not tell"."""
    if kind not in ("role", "user") or not name:
        return None
    got: List[str] = []
    for verb, key, field in (("list-attached-%s-policies" % kind, "AttachedPolicies",
                              "PolicyName"),
                             ("list-%s-policies" % kind, "PolicyNames", "")):
        code, out, _err = run_cmd(
            ["aws", "iam", verb, "--%s-name" % kind, name, "--output", "json"],
            None, timeout)
        if code != 0:
            return None
        data = _report(out, dict)
        rows = data.get(key) or []
        got.extend([str(r.get(field, "")) for r in rows] if field else
                   [str(r) for r in rows])
    return got


def aws_identity_readonly(arn: str, timeout: int = 20) -> Tuple[str, str]:
    """Can the identity Squawk is about to read as also write? Three states,
    never a boolean (PRODUCT credential rule 2).

    `ok` when every policy on it is one of the read-only managed ones and
    there are no inline policies. `gap` when something write-capable is
    attached, or — when the identity cannot list its own policies — when its
    own name is a write-capable permission set, which is what an SSO role
    called `AdministratorAccess-<account>` is. `unknown` when neither can be
    established, said as "could not tell" rather than guessed either way.

    The detail always names what the answer is based on, because a policy list
    and a role's name are not the same quality of evidence."""
    kind, name = _role_or_user(arn)
    if not kind:
        return "unknown", "the ARN is not a role or user, so its policies cannot be read"
    policies = _attached_policies(kind, name, timeout)
    if policies is not None:
        writeable = [p for p in policies
                     if any(w in p for w in WRITE_CAPABLE) or p.endswith("FullAccess")]
        if writeable:
            return "gap", ("%s %s carries %s — this identity can write; Squawk only "
                           "reads, but the credential rules ask for a read-only one"
                           % (kind, name, ", ".join(sorted(writeable))))
        unknown_named = [p for p in policies if p not in READ_ONLY_POLICIES]
        if unknown_named:
            return "unknown", ("%s %s carries %s, which is not one of the read-only "
                               "managed policies and was not read further"
                               % (kind, name, ", ".join(sorted(unknown_named))))
        if not policies:
            return "unknown", "%s %s has no attached or inline policy to judge" % (kind, name)
        return "ok", "%s %s carries only %s" % (kind, name, ", ".join(sorted(policies)))
    # Could not list them — fall back to the name, and say that is what it is.
    named = [w for w in WRITE_CAPABLE if w in name]
    if named:
        return "gap", ("%s %s could not list its own policies; its NAME says %s, "
                       "which writes. Squawk only reads, but the credential rules "
                       "ask for a read-only identity" % (kind, name, named[0]))
    return "unknown", ("%s %s could not list its own policies, so whether it can "
                       "write is not established" % (kind, name))


def dast_target_ok(url: str) -> Tuple[bool, str]:
    """DAST sends real attack traffic, so this refuses a public address unless
    SQUAWK_DAST_ACK is set — the same 'small, local, deliberate' stance as the
    loopback bind guard. Aiming an active scan at something you do not own is
    the one-line mistake this rail exists to stop.

    What it checks is the **resolved address**, not the name: a hostname that
    answers with a public A record is refused, and one that answers with
    `127.0.0.1` is allowed. Decimal and hexadecimal spellings of an address
    normalise, a URL with a port is handled, and a name that does not resolve
    fails closed.

    What it does **not** check is ownership, because nothing can. A private
    address is not an owned address: every RFC1918 host inside a corporate
    network passes this with no acknowledgement at all, and aiming
    `zap-full-scan` at one of those is the likelier real mistake. This rail
    narrows the blast radius; it does not confer permission. Said plainly
    because the docstring used to claim "a target you own", which is not
    something the code can know (review, 2026-09-18).

    `169.254.169.254` passes as link-local. That is the cloud metadata
    endpoint, and it is deliberate: the self-audit reads it, and a scan of a
    host inside a VPC may legitimately reach it.
    """
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname
    if not host:
        return False, "no host in target URL"
    if host == "localhost":
        return True, "localhost"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except OSError:
            return False, "could not resolve %s" % host
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True, "%s is private" % ip
    if env("DAST_ACK"):
        return True, "%s is public — allowed by SQUAWK_DAST_ACK" % ip
    LOG.warning("REFUSED dast target: %s resolves to public %s", host, ip)
    return (False, "%s is a public address. DAST is refused unless you own it; "
            "set SQUAWK_DAST_ACK=1 to override." % ip)


def probes_a_named_port(service: "Service") -> bool:
    """Does this service point an outside scanner at one address?

    Recon must never be held to this: discovering what is listening is its
    whole job, and it reports an unreachable host itself — *no reachable port
    on X, nothing was scanned*. Its stage runs in-process and knows how to say
    that. An external scanner does not: pointed at a closed port it starts up,
    fails to connect, and leaves a run that reads as a scanner gone quiet."""
    return any(STAGES[key].internal is None for key in service.stages)


def dast_target_live(url: str, timeout: float = 4.0) -> Tuple[bool, str]:
    """Is anything listening at the target? A DAST probe against a closed port
    is thirty seconds of ZAP starting up, a spider that cannot connect, and a
    run that says a scanner went silent without saying why.

    That happened on the operator's box (2026-09-08): Juice Shop was down, three
    probes failed in under half a minute each, and the evidence that named the
    cause — `Job spider failed to access URL … Connection refused` — was one
    line at the bottom of a log nobody had reason to open. The run should
    refuse before it starts, the way it already refuses a directory target
    that is no longer on disk."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname
    if not host:
        return False, "no host in target URL"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "%s:%d is listening" % (host, port)
    except OSError as exc:
        LOG.warning("REFUSED dast target: nothing listening on %s:%d (%s)",
                    host, port, exc)
        return (False, "nothing is listening on %s:%d (%s). A probe against a "
                "closed port scans nothing and records a run that looks like a "
                "scanner going quiet — bring the target up and run it again."
                % (host, port, exc.strerror or exc.__class__.__name__))


__all__ = [
    'READ_ONLY_POLICIES',
    'SERVICES',
    'STAGES',
    'STAGE_KNOBS',
    'WRITE_CAPABLE',
    'ZAP_ACTIVE_SPIDER_MINS',
    'ZAP_IMAGE',
    'ZAP_JVM_PROPS',
    'ZAP_SPIDER_MINS',
    'ZAP_STARTUP_WAIT',
    'Service',
    'StageSpec',
    '_attached_policies',
    '_inside_a_repository',
    '_role_or_user',
    'aws_identity',
    'aws_identity_readonly',
    'cloud_target_ok',
    'container_name',
    'dast_target_live',
    'dast_target_ok',
    'knob',
    'memory_args',
    'probes_a_named_port',
    'stage_bandit',
    'stage_checkov',
    'stage_gitleaks',
    'stage_grype',
    'stage_recon',
    'stage_securityhub',
    'stage_semgrep',
    'stage_syft',
    'stage_trivy_config',
    'stage_trivy_fs',
    'stage_trivy_image',
    'stage_zap_active',
    'stage_zap_baseline',
]

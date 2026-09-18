"""Running a service: stages, coverage, contamination, and writing the evidence."""

import json
import logging
import logging.handlers
import os
import re
import time
from typing import Callable, Dict, List, Optional, Tuple

from squawk.analysis import (
    cloud_correlations,
    correlate,
    correlation_findings,
    scanner_differential,
)
from squawk.core import (
    LOG,
    SCANNERS,
    SEVERITY_ORDER,
    STOP_REQUESTED,
    Coverage,
    Finding,
    Profile,
    RunContext,
    RunInterrupted,
    StageResult,
    fingerprint,
    human_seconds,
    is_contaminated,
    load_profile,
    run_cmd,
    tool_path,
)
from squawk.evidence import (
    HISTORY_FILE,
    SCHEMA_VERSION,
    chain_fields,
    hash_run_files,
    history_document,
    list_runs,
    record_aborted_run,
    remediation_timeline,
    seal_run,
    write_digest,
)
from squawk.scanners import NORMALIZERS, report_unreadable, stage_coverage
from squawk.stages import (
    SERVICES,
    STAGE_KNOBS,
    STAGES,
    ZAP_JVM_PROPS,
    Service,
    StageSpec,
)

# --------------------------------------------------------------------------- #
# Run engine
# --------------------------------------------------------------------------- #


def profile_for(evidence_root: str, explicit: Optional[str] = None) -> Profile:
    """The profile a run would use, loaded and checked against the
    registries — a section for a service or a scanner that does not exist is
    refused by name, before any stage runs. Raises ProfileError."""
    prof = load_profile(evidence_root, explicit)
    prof.check_names(SERVICES, SCANNERS)
    return prof


# `prog: error: <why>` is argparse's own shape, and checkov, semgrep, bandit
# and the rest of the Python scanners are built on it. Kept narrow on purpose:
# a line has to name a program and then say `error:` to count, so a scanner
# that merely mentions the word in passing does not hijack the summary.
_REFUSAL = re.compile(r"^(?P<prog>[\w.-]+): error: (?P<why>.+)$")
_UNRECOGNISED = re.compile(r"unrecognized arguments: (?P<args>.+)$")

# Where a tool reads arguments that did not come from the command line. Named
# so the sentence can point at the file rather than leave a reader hunting.
_OWN_CONFIG = {
    "checkov": "a .checkov.yaml or .checkov.yml in the scanned tree, whose "
               "keys checkov turns into command-line arguments",
}

# And what to do about it. Naming the cause left the reader with a diagnosis
# and no move: the operator's own repository lost checkov on every run of
# `preflight` and `compliance`, which is two services down to a coverage gap
# until somebody works out the remedy. Measured against checkov 3.2.459 on
# 2026-09-12: `--config-file` does NOT override the tree's own file, and the
# working directory makes no difference — checkov reads it from the directory
# being scanned. So there is no flag Squawk can add, and adding one that
# silently overrode the operator's configuration would be the wrong fix even
# if it existed. The file is the remedy, so the file is what the line names.
_OWN_CONFIG_FIX = {
    "checkov": "checkov reads that file from the scanned tree whatever this "
               "run passes — --config-file does not override it — so the keys "
               "in it have to be ones checkov itself accepts, or the file has "
               "to go",
}


def _refusal(err: str, cmd: "Optional[List[str]]" = None) -> str:
    """The line where a tool says it would not take the command, or "".

    Read from the END, because a usage banner comes first and the reason last.

    And it says WHOSE arguments were refused. A checkov on a working repository
    refused eleven flags Squawk has never built -- they came from a
    `.checkov.yaml` in the tree being scanned, which checkov reads itself and
    turns into argv (reproduced against checkov 3.2.459, 2026-09-12). The
    message read as though this tool had passed them, and the first thing a
    reader would have done is go looking through code that does not contain
    them.
    """
    for line in reversed((err or "").strip().splitlines()):
        found = _REFUSAL.match(line.strip())
        if not found:
            continue
        prog, why = found.group("prog"), found.group("why")
        args = _UNRECOGNISED.search(why)
        if args and cmd and not _ours(args.group("args"), cmd):
            where = _OWN_CONFIG.get(prog)
            fix = _OWN_CONFIG_FIX.get(prog)
            return ("%s refused arguments this run did not pass: %s  ·  the "
                    "command was `%s`, so they reached it from %s%s"
                    % (prog, args.group("args"), " ".join(cmd),
                       where or "configuration the tool read itself",
                       ("  ·  %s" % fix) if fix else ""))
        return "%s refused the command: %s" % (prog, why)
    return ""


def _ours(refused: str, cmd: "List[str]") -> bool:
    """Whether any refused argument is one this run actually built.

    A flag can be refused as `--x=1` and passed as `--x 1`, so the comparison
    is on the flag rather than the whole token."""
    passed = {token.split("=", 1)[0] for token in cmd}
    return any(token.split("=", 1)[0] in passed
               for token in refused.split() if token.startswith("-"))


def _heap_set(cmd: object) -> str:
    """The ZAP heap a built command sets, or "" when it sets none."""
    if not isinstance(cmd, list):
        return ""
    for arg in cmd:
        text = str(arg)
        if text.endswith("%s:ro" % ZAP_JVM_PROPS):
            path = text.split(":")[0]
            try:
                with open(path, encoding="utf-8") as fh:
                    return fh.readline().strip()
            except OSError:
                return ""
    return ""


def _as_int(value: object, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def stage_rows(service: Service, target: str, base: str, profile: Profile) -> List[dict]:
    """What each stage of a service would run with, without running it: the
    command, the built-in timeout and the knobs the stage reads. `config
    show` prints these; the run writes the real ones."""
    ctx = RunContext(target, service.scope, os.path.join(base, "<run>"), base,
                     service=service.key, profile=profile)
    rows: List[dict] = []
    for key in service.stages:
        spec = STAGES[key]
        if spec.internal is not None:
            rows.append({"stage": key, "tool": spec.tool, "internal": True})
            continue
        ctx.raw_path = os.path.join("<run>", "raw", "%s.json" % key)
        try:
            cmd, timeout = spec.build(ctx)
        except Exception:                 # a builder that needs a live artifact
            cmd, timeout = [], 0
        rows.append({"stage": key, "tool": spec.tool,
                     "knobs": STAGE_KNOBS.get(key, ()),
                     "timeout_builtin": timeout or None, "command": cmd})
    return rows


def run_id(scope: str) -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    suffix = "" if scope == "repo" else "-%s" % scope
    return stamp + suffix


def claim_run_dir(evidence_root: str, scope: str) -> Tuple[str, str]:
    """A run id and a directory that are this run's alone.

    Run ids are second-granular, so two runs of one scope started in the same
    second used to get the same directory: both wrote into it, both reported
    success, and the second's evidence overwrote the first's with nothing to
    say so. The directory is claimed with an exclusive mkdir, which is atomic,
    and a collision takes the next suffix — `-2`, `-3` — which sorts after the
    original, so the chain order stays the order of writing. Every reader of
    a run id parses only its leading timestamp."""
    base = run_id(scope)
    for n in range(1, 1000):
        rid = base if n == 1 else "%s-%d" % (base, n)
        run_dir = os.path.join(evidence_root, rid)
        try:
            os.mkdir(run_dir)
        except FileExistsError:
            continue
        return rid, run_dir
    raise RuntimeError("could not claim a run directory under %s" % evidence_root)


# Below this, the gap between a stage's budget and its elapsed is the ordinary
# cost of stopping a child -- SIGTERM, the grace period, SIGKILL. Above it, the
# scanner did not let go, and the run says so rather than printing the budget as
# though it were the truth.
STOP_SLACK_SECONDS = 2.0


# Which scanner's coverage extractor reads a given chained artifact. The SBOM
# is syft's own output, so syft's extractor is the one that already knows how
# to count it -- a second parser here would be a second thing to keep current.
ARTIFACT_TOOLS = {"sbom": "syft"}

# What a borrowed denominator is called on the stage line, so a reader can
# see the number did not come from the tool that printed it.
ARTIFACT_LABEL = "SBOM"


def _upstream_coverage(ctx: "RunContext", key: str) -> "Optional[Coverage]":
    """What the artifact a chained stage read actually covered, or None.

    grype's denominator is not in grype's own report: it is the SBOM syft
    wrote. That mattered first for the empty case -- syft gaps when it
    catalogues nothing, grype then matched no CVEs against a package list of
    length zero and reported `ok`, and a chain launders the gap unless the
    upstream denominator travels with the artifact.

    It matters the same way when the SBOM is full. A real run printed

        syft   ok 0 finding(s) across 759 packages
        grype  ok 18 finding(s) -- tool publishes no coverage

    one line apart (2026-09-15). grype examined those 759 packages. The number
    was sitting in the file it had just read, and the stage that found 18 CVEs
    in them was the one line on the page with no denominator at all.
    """
    path = (getattr(ctx, "artifacts", None) or {}).get(key)
    tool = ARTIFACT_TOOLS.get(key, "")
    if not path or not tool:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
    except OSError:
        return None
    cov = stage_coverage(tool, body)
    # An upstream that publishes no denominator of its own cannot lend one, and
    # an unknown upstream is not an empty one (I1).
    return cov if cov.examined is not None else None


def _apply_coverage(tool: str, out: str, findings: list, status: str,
                    detail: str, stdout: str = "", stderr: str = "",
                    inherited: "Optional[Coverage]" = None
                    ) -> "Tuple[str, str, Optional[Coverage]]":
    """Fold coverage into a stage's verdict.

    The rule is the whole point of Phase 1: a scan that found nothing AND
    examined nothing is not clean, it is empty. It becomes a gap naming the
    denominator, so a zero over zero can never again read as a zero over a real
    tree. A tool that publishes no coverage (examined is None) is left alone —
    unknown is honest, and inventing a denominator to gate on would be the same
    fabrication this refuses everywhere else.

    `inherited` is the exception, and it is not an invention: a stage that reads
    an artifact another stage wrote covered exactly what that artifact holds.
    grype publishes nothing about what it examined, and it examines the SBOM it
    was handed, which syft already counted."""
    cov = stage_coverage(tool, out, stdout, stderr)
    if (cov.examined is None and inherited is not None
            and inherited.examined is not None):
        cov = inherited._replace(
            note=("from the %s this stage read" % ARTIFACT_LABEL)
            if not inherited.note else
            "%s, from the %s this stage read" % (inherited.note, ARTIFACT_LABEL))
    if status == "ok" and not findings and cov.examined == 0:
        note = (" — %s" % cov.note) if cov.note else ""
        return ("gap",
                "0 findings, but examined 0 %s%s — not a clean result"
                % (cov.unit or "units", note),
                cov)
    # Otherwise annotate the count with the denominator when we have one.
    if status == "ok" and cov.examined is not None:
        detail = "%s across %d %s" % (detail, cov.examined, cov.unit)
    # And with what the denominator does not include. A coverage note used to
    # be written into the manifest and shown nowhere but the gap message, so
    # "this count is a floor" and "N passed controls are not carried here"
    # were recorded and never read (2026-09-08). A caveat nobody sees is the
    # silent cap this tool exists to refuse (I12).
    if status == "ok" and cov.note:
        detail = "%s — %s" % (detail, cov.note)
    # The tool's own error channel: files it could not parse, rules it dropped.
    # A count that ignores them overstates coverage. "Examined 200 files" when
    # 12 failed to parse is a different, weaker claim. Surfaced, not swallowed.
    notes = []
    if cov.errors:
        notes.append("%d unreadable" % cov.errors)
    if cov.skipped:
        notes.append("%d skipped" % cov.skipped)
    if notes and status in ("ok", "gap"):
        detail = "%s (%s)" % (detail, ", ".join(notes))
        LOG.info("COVERAGE %s %s", tool, ", ".join(notes))
    return (status, detail, cov)


def _run_one_stage(spec: StageSpec, ctx: RunContext, raw_file: str,
                   base: str, run_dir: str,
                   progress: Optional[Callable[[dict], None]] = None) -> StageResult:
    """Run a single stage and return its result. No I/O to the caller's lists —
    that (and progress reporting) is done once, by execute_service."""
    sc = SCANNERS[spec.tool]
    rel_raw = os.path.relpath(raw_file, run_dir)

    # Internal stages run in-process — no binary, no subprocess.
    if spec.internal is not None:
        ctx.raw_path = raw_file
        forced_status, forced_detail = "", ""
        # An internal stage runs in-process, so it has no subprocess bound and
        # no budget — but it still takes real time (recon against a host with
        # many ports is not instant), and an operator watching it deserves the
        # same "this is moving" as any other stage.
        started = time.monotonic()
        try:
            result = spec.internal(ctx)
            # An internal stage may return either the raw JSON, or a
            # (json, status, detail) triple to declare its own outcome — so it
            # can say "I could not look" instead of reporting an empty result.
            if isinstance(result, tuple):
                out, forced_status, forced_detail = result
            else:
                out = result
            err_detail = ""
        except Exception as exc:  # an internal probe must not crash the run
            out, err_detail = "", str(exc)[:120]
        with open(raw_file, "w", encoding="utf-8") as fh:
            fh.write(out)
        findings = NORMALIZERS[spec.tool](out, base)
        kept = [f for f in findings if not is_contaminated(f.path)]
        status = "error" if err_detail else (forced_status or "ok")
        detail = err_detail or forced_detail or "%d finding(s)" % len(kept)
        drift = report_unreadable(spec.tool, out) if not findings else None
        if drift and status == "ok":
            status = "error"
            detail = "unreadable report — %s" % drift
            LOG.warning("DRIFT %s produced a report we could not read: %s",
                        spec.tool, drift)
        status, detail, cov = _apply_coverage(spec.tool, out, kept, status, detail)
        if status == "gap":
            LOG.warning("GAP %s %s", spec.tool, detail)
        return StageResult(spec.tool, spec.mode, status, detail, rel_raw, kept,
                           len(findings) - len(kept), cov,
                           {"internal": True,
                            "elapsed": round(time.monotonic() - started, 1)})

    # A stage that could not run is a GAP, never a skip. "skipped" read as
    # neutral to everything downstream: a run whose every scanner was missing
    # showed a blue "clean" pill on the Overview, "a clean result only because
    # it looked" on Findings, and "No squawk" on the CLI — while the Scan tile
    # promised the missing scanner would be recorded as a coverage gap. The
    # ledger is where that promise is kept, so it is kept here.
    if not tool_path(sc.binary):
        LOG.warning("GAP %s: %s is not installed, the stage could not run",
                    spec.tool, sc.binary)
        return StageResult(spec.tool, spec.mode, "gap",
                           "%s is not installed — this stage could not run"
                           % sc.binary, None, [], 0)
    if spec.requires and spec.requires not in ctx.artifacts:
        LOG.warning("GAP %s: no %s to read", spec.tool, spec.requires)
        return StageResult(spec.tool, spec.mode, "gap",
                           "no %s to read — the stage that produces it did not"
                           % spec.requires, None, [], 0)

    ctx.raw_path = raw_file              # a writes_report stage targets this
    cmd, timeout = spec.build(ctx)
    if not cmd:
        LOG.warning("GAP %s: nothing to run against", spec.tool)
        return StageResult(spec.tool, spec.mode, "gap",
                           "no %s to read — nothing to run against"
                           % (spec.requires or "input"), None, [], 0)

    # The budget this stage runs under, and where it came from. The profile's
    # stage_timeout replaces the builder's; its extra_args are appended, never
    # substituted, so a profile can add a rule pack but not take a flag away.
    # The command itself is recorded: "what ran" is the argv, not a summary.
    builtin_timeout, timeout_from = timeout, "built-in"
    extra: List[str] = []
    if ctx.profile is not None:
        st = ctx.profile.setting(ctx.service, ctx.target, spec.tool,
                                 "stage_timeout", timeout)
        timeout, timeout_from = _as_int(st.value, timeout), st.section
        extra = ctx.profile.extra_args(spec.tool)
        if extra:
            cmd = [*cmd, *extra]
    ran = {"command": list(cmd), "timeout": timeout, "timeout_from": timeout_from,
           "timeout_builtin": builtin_timeout, "extra_args": extra}
    # Announce the budget before the wait, not after it. A scanner publishes no
    # progress of its own, so the honest thing to show an operator watching a
    # forty-minute probe is the time it has taken against the bound it is
    # actually running under — never a percentage, which would be a denominator
    # nobody measured.
    if progress:
        progress({"phase": "budget", "tool": spec.tool, "mode": spec.mode,
                  "timeout": timeout, "timeout_from": timeout_from})

    # `monotonic`, because that is the clock the budget is measured against.
    # `subprocess` computes its timeout deadline with `time.monotonic`, which on
    # darwin is `mach_absolute_time()` and does not advance while the machine is
    # asleep. This was `time.time()`, which does. A laptop that slept overnight
    # mid-run reported "timed out after 7200s · and it took a further 9h 29m to
    # stop, so the stage ran 11h 29m in all" — the stage had not overrun by a
    # second, and the line said the timeout control had failed (the operator's run
    # of 2026-09-14). Comparing an elapsed on one clock against a budget on
    # another is a claim about a control that was never measured.
    started = time.monotonic()
    code, out, err = run_cmd(cmd, cwd=None, timeout=timeout)
    ran["elapsed"] = round(time.monotonic() - started, 1)
    # Everything the scanner said on stderr, kept as evidence rather than the
    # first line of it. A ZAP probe failed on the operator's box in 25 seconds
    # (2026-09-08) and the run held one line — enough to know it failed,
    # nowhere near enough to say why, and the machine that could answer was
    # not the machine that could reproduce it. The file is hashed into the
    # digest and sealed with the run like any other evidence.
    if err.strip():
        # Read from the text, not from the file, so a refusal is still known
        # when the file could not be written (review 3, R-51).
        ran["refusal"] = _refusal(err, cmd)
        err_file = os.path.splitext(raw_file)[0] + ".err"
        try:
            with open(err_file, "w", encoding="utf-8") as fh:
                fh.write(err)
            ran["stderr"] = os.path.relpath(err_file, run_dir)
            ran["stderr_lines"] = len(err.strip().splitlines())
        except OSError:
            pass
    stdout = ""
    if spec.writes_report:
        # The scanner wrote its own report to raw_file; read it back. Its
        # stdout is kept beside the report rather than dropped: ZAP prints the
        # one crawl denominator it publishes — `Total of N URLs` — there and
        # nowhere else, and for weeks it was discarded on this line while the
        # coverage extractor guessed from where the alerts were seen.
        stdout = out
        if stdout.strip():
            log_file = os.path.splitext(raw_file)[0] + ".log"
            with open(log_file, "w", encoding="utf-8") as fh:
                fh.write(stdout)
        try:
            with open(raw_file, encoding="utf-8") as fh:
                out = fh.read()
        except OSError:
            out = ""
    else:
        with open(raw_file, "w", encoding="utf-8") as fh:
            fh.write(out)

    if spec.produces == "sbom" and out.strip():
        ctx.artifacts["sbom"] = raw_file    # syft's stdout IS the SBOM

    findings = NORMALIZERS[spec.tool](out, base)
    kept = [f for f in findings if not is_contaminated(f.path)]
    excluded = len(findings) - len(kept)

    # non-zero exit with no parseable output is an error; a non-zero exit that
    # still produced findings is normal for scanners that signal via exit code.
    drift = report_unreadable(spec.tool, out) if not findings else None
    if code != 0 and not findings and err.strip() and not out.strip():
        status, detail = "error", err.strip().splitlines()[0][:120]
    elif drift:
        # The scanner ran and produced output we could not understand. Reporting
        # that as "0 findings" is the exact substitution this tool refuses to
        # make everywhere else.
        status, detail = "error", "unreadable report — %s" % drift
        LOG.warning("DRIFT %s produced a report we could not read: %s",
                    spec.tool, drift)
    else:
        status = "ok"
        detail = "%d finding(s)" % len(kept)
        if excluded:
            detail += " (%d excluded)" % excluded
    status, detail, cov = _apply_coverage(
        spec.tool, out, kept, status, detail, stdout, err,
        inherited=_upstream_coverage(ctx, spec.requires) if spec.requires else None)
    # A stage that died with a heap set by the operator must say so: ZAP's own
    # message is about a summary file and says nothing about memory, and the
    # operator chose that number. Measured 2026-09-08 — a heap too small fails
    # in well under a minute, which is how it reads on the run.
    if status in ("error", "gap"):
        # A stage killed at its budget should name the budget. The operator's
        # first real Security Hub read hit the built-in ten minutes and said
        # only "timed out after 600s" — true, and it left the reader to work
        # out that the number is a setting (2026-09-08).
        if detail.startswith("timed out after"):
            # Scoped to the SCANNER, not the service. `[services.preflight]`
            # applies to every stage in it, so a run where two stages time out
            # printed two different values for one key — gitleaks asking for
            # 5400 and semgrep for 7200, in the same block, both writing
            # `[services.preflight] stage_timeout` (the operator's run,
            # 2026-09-14). Following either gave bandit ninety minutes to do
            # seven seconds of work, and following both is impossible.
            # `[scanners.<tool>]` is the most specific table a profile has and
            # wins over the service, so it raises the one stage that asked.
            detail = ("%s  ·  that is stage_timeout; raise it in a profile "
                      "([scanners.%s] stage_timeout = %d) if the target needs "
                      "longer" % (detail, spec.tool, timeout * 6))
            # And how long it ACTUALLY took. A semgrep given twenty minutes
            # reported "timed out after 1200s" beside an elapsed of 27m 04s --
            # seven minutes past the budget the same line had just named (the
            # owner, 2026-09-12). Reproduced at three seconds: a scanner that
            # ignores SIGTERM costs the grace period, and one that does not die
            # costs more. The budget bounds the SCAN; stopping is extra, and a
            # line that prints the budget as though it were the elapsed is a
            # claim about a control that did not hold.
            took = ran.get("elapsed")
            elapsed = took if isinstance(took, (int, float)) else 0.0
            over = elapsed - timeout
            if over >= STOP_SLACK_SECONDS:
                detail = ("%s  ·  and it took a further %s to stop, so the "
                          "stage ran %s in all"
                          % (detail, human_seconds(round(over)),
                             human_seconds(round(elapsed))))
        # A tool that REFUSED the command names what it refused, and it does
        # it on the last line. The detail is the first line of stderr, so a
        # checkov that would not take a flag reported its usage banner --
        # "usage: checkov [-h] [-v] [--support] ..." -- and the sentence that
        # says which flag was in the 38th line of a file the reader had to go
        # open (the operator, 2026-09-12). argparse is what most of these are
        # built on, and `prog: error: ...` is its convention.
        refusal = str(ran.get("refusal") or "")
        if refusal:
            detail = refusal
        # The detail is otherwise the FIRST line of stderr, which is a poor
        # summary when a scanner is verbose: with ZAP's `-d` on, the first line
        # is a debug message and the run read "zap did not report (Trigger
        # hook: cli_opts, args: 1)" (the operator, 2026-09-08). Point at the rest,
        # which is kept, rather than let one line stand for all of it.
        lines = ran.get("stderr_lines")
        more = (lines - 1) if isinstance(lines, int) else 0
        if more > 0 and ran.get("stderr"):
            detail = "%s  ·  %d more line(s) in %s" % (detail, more, ran["stderr"])
        heap = _heap_set(ran["command"])
        if heap:
            detail = ("%s  ·  ZAP ran with %s, from zap_memory_mb"
                      % (detail, heap))
    if status == "gap":
        LOG.warning("GAP %s %s", spec.tool, detail)
    return StageResult(spec.tool, spec.mode, status, detail, rel_raw, kept,
                       excluded, cov, ran)


def execute_service(service: Service, target: str, evidence_root: str,
                    base: str, progress: Optional[Callable[[dict], None]] = None,
                    profile: Optional[Profile] = None) -> Dict[str, object]:
    """Run a service and write its evidence. If the run is interrupted — a
    Ctrl-C, a server stop, a crash in a stage — the run directory it had
    already created is written up as aborted, under its target, rather than
    left as a nameless directory that no page can see."""
    seen: Dict[str, str] = {}

    def _capture(ev: dict) -> None:
        if ev.get("phase") == "run":
            seen["run_dir"] = str(ev.get("run_dir", ""))
        if progress:
            progress(ev)

    try:
        return _execute_service_inner(service, target, evidence_root, base,
                                      progress=_capture, profile=profile)
    except BaseException as exc:
        if seen.get("run_dir"):
            record_aborted_run(seen["run_dir"],
                               "interrupted: %s" % (str(exc) or type(exc).__name__))
        raise


def _execute_service_inner(service: Service, target: str, evidence_root: str,
                           base: str,
                           progress: Optional[Callable[[dict], None]] = None,
                           profile: Optional[Profile] = None) -> Dict[str, object]:
    # The profile is read before the run directory exists, so a profile that
    # is refused leaves no run behind — not even an aborted one.
    if profile is None:
        profile = profile_for(evidence_root)
    os.makedirs(evidence_root, exist_ok=True)
    rid, run_dir = claim_run_dir(evidence_root, service.scope)
    raw_dir = os.path.join(run_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    # What this run is for, recorded before any stage runs, so an interrupted
    # run can still be attributed to its target and recorded as aborted.
    with open(os.path.join(run_dir, "started.json"), "w", encoding="utf-8") as fh:
        json.dump({"run_id": rid, "service": service.key,
                   "service_label": service.label, "scope": service.scope,
                   "target": target, "not_covered": service.not_covered,
                   "started_at": time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())}, fh)
    if progress:
        progress({"phase": "run", "run_dir": run_dir, "run_id": rid})
    # Owner-only, explicitly, rather than whatever the ambient umask allows.
    # The evidence root is already 0700, and under `umask 000` the run
    # directories inside it were created 0777 — world-writable directories
    # holding findings.json, protected only by the parent's mode. That is one
    # permission change away from evidence anyone can edit, and evidence that
    # can be edited is not evidence. Measured in a container, not assumed.
    for d in (run_dir, raw_dir):
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass                      # reported by the host self-audit instead

    LOG.info("run start: id=%s service=%s scope=%s target=%s",
             rid, service.key, service.scope, target)
    ctx = RunContext(target, service.scope, run_dir, base,
                     service=service.key, profile=profile)
    results: List[StageResult] = []
    ledger_rows: List[str] = ["tool\tmode\tstatus\tdetail\tevidence"]
    total = len(service.stages)

    for idx, stage_key in enumerate(service.stages, 1):
        if STOP_REQUESTED.is_set():
            raise RunInterrupted()
        spec = STAGES[stage_key]
        raw_file = os.path.join(raw_dir, "%s.json" % stage_key)
        if progress:
            progress({"phase": "start", "i": idx, "n": total,
                      "tool": spec.tool, "mode": spec.mode})

        res = _run_one_stage(spec, ctx, raw_file, base, run_dir, progress=progress)
        results.append(res)
        ledger_rows.append("%s\t%s\t%s\t%s\t%s" % (
            res.tool, res.mode, res.status, res.detail, res.raw_file or "-"))
        LOG.log(logging.WARNING if res.status == "error" else logging.INFO,
                "stage: run=%s tool=%s mode=%s status=%s detail=%s",
                rid, res.tool, res.mode, res.status, res.detail)
        if progress:
            progress({"phase": "done", "i": idx, "n": total, "tool": res.tool,
                      "mode": res.mode, "status": res.status, "detail": res.detail,
                      "elapsed": (res.ran or {}).get("elapsed")})

    # Correlate across the run's findings before writing evidence, so the
    # correlations are findings like any other and inherit identity and history.
    all_findings = [_finding_dict(f) for r in results for f in r.findings]
    correlations = correlate(all_findings, results)
    corr_finds = correlation_findings(correlations)
    # The cloud graph rules already ran, inside the inventory stage's
    # normalizer, and turned into findings there. Their unknowns did not — a
    # region whose security groups could not be read is a question this run
    # failed to answer, and it belongs on the same panel as every other
    # question this run failed to answer, not in the raw file alone.
    correlations.extend(cloud_correlations(results, run_dir))
    # Always append the stage, fired or not. When it was appended only on a
    # hit, fixing a toxic combination removed "correlation" from the ledger and
    # the went-quiet check raised a false 7600, the loudest wrong answer, for
    # doing the right thing. Reproduced live before this line existed.
    n_unknown = sum(1 for c in correlations if c.get("state") == "unknown")
    corr_detail = "%d correlation(s)" % len(corr_finds)
    if n_unknown:
        corr_detail += ", %d not evaluable" % n_unknown
    results.append(StageResult("correlation", "join", "ok", corr_detail,
                               None, corr_finds, 0, None))

    _write_evidence(run_dir, service, target, results, ledger_rows,
                    correlations=correlations, profile=profile)
    return {"run_id": rid, "run_dir": run_dir, "results": results}


def _collect_identities(results: List[StageResult]) -> Dict[str, List[str]]:
    by_scanner: Dict[str, List[str]] = {}
    for r in results:
        if r.status != "ok":
            continue
        by_scanner.setdefault(r.tool, [])
        by_scanner[r.tool].extend(f.identity for f in r.findings)
    # de-dupe, stable
    return {k: sorted(set(v)) for k, v in by_scanner.items()}


# --------------------------------------------------------------------------- #
# Correlation: the thing a platform sells, done locally
#
# A scanner reports a finding. A platform joins findings across layers into a
# path: a secret, a public bucket and a reachable service are three findings and
# one incident. Squawk already holds every finding from a run in one place with
# stable identities, so the join is a local operation. See CORRELATION-DESIGN.md.
#
# The novel part is not the join, which graph tools do. It is that a correlation
# states its denominator: if a member scanner did not run, the rule reports
# `unknown` rather than silently not firing, so a toxic combination is never
# missed because half of it was never looked for. That is charter I1 one layer
# up, and it is the part no platform shows you.
# --------------------------------------------------------------------------- #


def _finding_dict(f: "Finding") -> dict:
    """A Finding as the plain dict the evidence and correlation layers use."""
    return {"scanner": f.scanner, "identity": f.identity, "severity": f.severity,
            "title": f.title, "path": f.path, "detail": f.detail or {}}


def _write_evidence(run_dir: str, service: Service, target: str,
                    results: List[StageResult], ledger_rows: List[str],
                    correlations: Optional[List[dict]] = None,
                    profile: Optional[Profile] = None) -> None:
    identities = _collect_identities(results)
    # What the run ran under: every value the profile changed, with the
    # built-in it replaced and the section it came from (I12).
    #
    # A stage that could not run has no budget row here, because no budget
    # was applied to it — the CLI prints what the run *would* use before it
    # starts, this records what it *did*, and a gap row's Budget cell on the
    # run page reads "—" beside its reason. Reporting a budget for a stage
    # that never ran would be the same substitution this tool refuses
    # everywhere else.
    if profile is None:
        profile = Profile("", "built-in", {})
    by_stage: Dict[str, StageResult] = {}
    for i, key in enumerate(service.stages):     # results follow the stage order
        if i < len(results):
            by_stage[key] = results[i]
    prof_rows = [{"stage": key, "tool": STAGES[key].tool,
                  "knobs": STAGE_KNOBS.get(key, ()),
                  "internal": STAGES[key].internal is not None,
                  "timeout_builtin": ((by_stage[key].ran or {}).get("timeout_builtin")
                                      if key in by_stage else None)}
                 for key in service.stages]
    prof_summary = profile.summary(service.key, target, prof_rows)
    prof_summary.pop("settings", None)   # derivable; the ledger rows carry each budget
    total = sum(len(r.findings) for r in results)
    excluded_total = sum(r.excluded for r in results)

    severities: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        for f in r.findings:
            severities[f.severity] = severities.get(f.severity, 0) + 1

    fingerprints = {tool: fingerprint(ids) for tool, ids in identities.items()}
    differential = scanner_differential(results)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "run_id": os.path.basename(run_dir),
        "service": service.key,
        "service_label": service.label,
        "scope": service.scope,
        "target": target,
        "tools_requested": list(service.stages),
        "not_covered": service.not_covered,
        "counts": {"total": total, "excluded": excluded_total},
        "severities": severities,
        "differential": differential,
        "correlations": correlations or [],
        "profile": prof_summary,
        "ledger": [
            {"tool": r.tool, "mode": r.mode, "status": r.status,
             "detail": r.detail, "evidence": r.raw_file,
             "coverage": ({"examined": r.coverage.examined,
                           "unit": r.coverage.unit,
                           "skipped": r.coverage.skipped,
                           "errors": r.coverage.errors,
                           "note": r.coverage.note}
                          if r.coverage else None),
             "ran": r.ran}
            for r in results
        ],
    }
    all_findings = [_finding_dict(f) for r in results for f in r.findings]

    with open(os.path.join(run_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    with open(os.path.join(run_dir, "identities.json"), "w", encoding="utf-8") as fh:
        json.dump(identities, fh, indent=2)
    with open(os.path.join(run_dir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(all_findings, fh, indent=2)
    with open(os.path.join(run_dir, ".ledger.tsv"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(ledger_rows) + "\n")

    # The target's remediation timeline as of this run, persisted: what is
    # open, what was resolved and when, what came back. It is reconstructed
    # from the run evidence just written (this run included), so it is a
    # record of what the tool reported on this date, not a second source of
    # truth: a page can recompute it and must get the same answer.
    root = os.path.dirname(os.path.abspath(run_dir))
    rid = os.path.basename(run_dir)
    me = next((m for m in list_runs(root) if m["run_id"] == rid), None)
    if me is not None:
        entries = remediation_timeline(root, me)
        with open(os.path.join(run_dir, HISTORY_FILE), "w", encoding="utf-8") as fh:
            json.dump(history_document(rid, entries), fh, indent=2)

    # The digest is written LAST and covers every other file in the run, plus
    # the run that came before it anywhere in the store. Written last because a
    # hash of a file that is still to be written is a hash of nothing, and the
    # whole claim here is that the digest covers the finished run.
    digest = {
        "schema_version": SCHEMA_VERSION,
        "run_id": os.path.basename(run_dir),
        "service": service.key,
        "scope": service.scope,
        "total": total,
        "excluded": excluded_total,
        "severities": severities,
        "per_scanner": {t: len(ids) for t, ids in identities.items()},
        "fingerprints": fingerprints,
        "files": hash_run_files(run_dir),
    }
    digest.update(chain_fields(root, rid))
    write_digest(run_dir, digest)
    seal_run(run_dir)


__all__ = [
    'ARTIFACT_LABEL',
    'ARTIFACT_TOOLS',
    'STOP_SLACK_SECONDS',
    '_OWN_CONFIG',
    '_OWN_CONFIG_FIX',
    '_REFUSAL',
    '_UNRECOGNISED',
    '_apply_coverage',
    '_as_int',
    '_collect_identities',
    '_execute_service_inner',
    '_finding_dict',
    '_heap_set',
    '_ours',
    '_refusal',
    '_run_one_stage',
    '_upstream_coverage',
    '_write_evidence',
    'claim_run_dir',
    'execute_service',
    'profile_for',
    'run_id',
    'stage_rows',
]

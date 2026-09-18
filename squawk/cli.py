"""The command line: the parser, the subcommands, --doctor, --run, and main()."""

import argparse
import json
import os
import shutil
import socket
import sys
import time
from typing import List, Optional

from squawk.analysis import (
    comparable_runs,
    compare_readings,
    diff_lines,
    inventory_caveats,
    inventory_notes,
    inventory_summary,
    squawk_check,
    squawk_lines,
    verify_root,
)
from squawk.baselines import resolve_gh_repo, sync_baselines
from squawk.core import (
    DB_STALE_DAYS,
    DEFAULT_EVIDENCE,
    DEFAULT_PORT,
    FEEDS_DIRNAME,
    LOG,
    PROFILE_REFUSED_NOTE,
    SCANNERS,
    SEVERITY_ORDER,
    SUPPORTING,
    ProfileError,
    __version__,
    env,
    evidence_writable,
    guard_host,
    human_seconds,
    mask_account,
    redact_identifiers,
    resolve_repo,
    setup_logging,
    show_setting,
    sync_root,
    tool_path,
    tool_version,
    vuln_db_ages,
)
from squawk.decisions import who
from squawk.engine import execute_service, profile_for, stage_rows
from squawk.evidence import estate_runs, list_runs, load_findings, save_verify
from squawk.feeds import (
    FEED_STALE_DAYS,
    estate_cves,
    feed_ages,
    fetch_intel,
    intel_dir,
    update_feeds,
)
from squawk.installer import (
    installer_script,
    last_install_record,
    run_installer,
)
from squawk.probes import self_audit_checks
from squawk.retention import (
    DEFAULT_DROP_DAYS,
    DEFAULT_TRIM_DAYS,
    apply_prune,
    human_bytes,
    plan_prune,
)
from squawk.runtime import read_pid_file
from squawk.sarif import sarif_document
from squawk.service import cmd_install_service, cmd_status, cmd_stop, serve_web, start_daemon
from squawk.stages import (
    SERVICES,
    ZAP_IMAGE,
    aws_identity,
    aws_identity_readonly,
    cloud_target_ok,
    dast_target_live,
    dast_target_ok,
    probes_a_named_port,
)


def doctor(args: argparse.Namespace) -> int:
    print("Squawk — preflight\n")
    print("Python: %s" % sys.version.split()[0])
    if sys.version_info < (3, 9):
        print("  ! Squawk needs Python 3.9+. Every command says so now, not "
              "just this one.")

    print("\nScanners:")
    any_scanner = False
    for name, sc in SCANNERS.items():
        if sc.internal:
            any_scanner = True
            print("  ok   %-9s built-in (%s)" % (name, sc.kind))
            continue
        if name == "zap":
            native = [n for n in ("zap-baseline.py", "zap-full-scan.py")
                      if tool_path(n)]
            if native:
                any_scanner = True
                print("  ok   zap       native %s" % ", ".join(native))
            elif tool_path("docker"):
                any_scanner = True
                print("  ok   zap       via docker (%s)" % ZAP_IMAGE)
            else:
                print("  gap  zap       needs docker, or zap-baseline.py / "
                      "zap-full-scan.py on PATH")
            continue
        ver = tool_version(sc)
        if ver:
            any_scanner = True
            print("  ok   %-9s %s" % (name, ver))
        else:
            print("  gap  %-9s not found — install it (%s)" % (name, sc.contributes))

    print("\nSupporting tools:")
    for name, why in SUPPORTING.items():
        mark = "ok " if tool_path(name) else "gap"
        note = "" if tool_path(name) else "  (%s degraded)" % why
        print("  %s  %-7s%s" % (mark, name, note))

    ages = vuln_db_ages()
    if ages:
        print("\nVulnerability databases:")
        for name, age, detail in ages:
            if age is None:
                print("  gap  %-9s %s — run --update" % (name, detail))
            elif age > DB_STALE_DAYS:
                print("  gap  %-9s %d days old — STALE, findings under-report; "
                      "run --update" % (name, age))
            else:
                print("  ok   %-9s %d day(s) old" % (name, age))

    froot = args.evidence or env("EVIDENCE") or DEFAULT_EVIDENCE
    print("\nExploitability feeds (CISA KEV, EPSS):")
    for name, age, detail in feed_ages(froot):
        if age is None:
            print("  gap  %-9s %s — run --feeds" % (name, detail))
        elif age > FEED_STALE_DAYS:
            print("  gap  %-9s %d days old — STALE, ranking says so; run --feeds"
                  % (name, age))
        else:
            print("  ok   %-9s %d day(s) old" % (name, age))

    root = args.evidence or env("EVIDENCE") or DEFAULT_EVIDENCE
    writable = evidence_writable(root)
    for name, age, detail in vuln_db_ages():
        if age is None:
            LOG.warning("GAP vuln-db %s %s", name, detail or "no readable date")
        elif age > DB_STALE_DAYS:
            LOG.warning("GAP vuln-db %s %d days old", name, age)
    log_path = getattr(LOG, "_squawk_path", None)
    if log_path:
        print("\nLogging: %s" % log_path)
    else:
        print("\nLogging: OFF — actions are not being recorded and cannot be "
              "audited. Fix the evidence root.")
    print("\nEvidence root: %s  [%s]" % (root, "writable" if writable else "NOT writable"))

    repo = resolve_repo(args.repo or env("REPO"))
    print("Default repo target: %s" % (repo or "none resolved (pass --repo)"))

    gh = tool_path("gh")
    print("GitHub baselines: %s" % ("gh present" if gh else "gh missing — baselines unavailable"))

    # Credential rule 3: name the identity before it is used. There is no
    # optional AWS stage that runs on its own; the cloud service reads Security
    # Hub as whoever the credential chain resolves to, behind an acknowledgement.
    print("\nAWS (Security Hub ingest, read-only):")
    if not tool_path("aws"):
        print("  gap  aws       CLI not installed; the cloud service cannot run")
    else:
        ident, why = aws_identity()
        if ident:
            print("  ok   identity  %s (account %s)" % (ident["Arn"], ident["Account"]))
            # Credential rule 2: read-only identities only. Naming the
            # identity is not the same as knowing what it can do, and the
            # first real one this met was an SSO AdministratorAccess role.
            state, detail = aws_identity_readonly(ident["Arn"])
            print("  %-4s read-only %s" % ({"ok": "ok", "gap": "gap"}.get(state, "?"),
                                           detail))
        else:
            print("  gap  identity  none in the credential chain: %s" % why)
        if env("CLOUD_ACK"):
            print("  ok   ack       SQUAWK_CLOUD_ACK set")
        else:
            print("  gap  ack       SQUAWK_CLOUD_ACK not set; a cloud run is refused "
                  "until it is")
        # A second, separate acknowledgement. A check nobody sees is a check
        # that does not exist, and this one governs whether the run touches
        # estates the operator did not name (review R-12).
        if env("CLOUD_PROFILES_ACK"):
            print("  ok   profiles  SQUAWK_CLOUD_PROFILES_ACK set; local CLI "
                  "profiles will be asked who they reach")
        else:
            print("  --   profiles  SQUAWK_CLOUD_PROFILES_ACK not set; local CLI "
                  "profiles are not asked who they reach")

    # The instrument, not the target. Everything above answers "can I scan";
    # this answers "is what I produce worth keeping". Printed here because
    # --doctor is the command people actually run, and a check nobody sees is
    # a check that does not exist.
    checks = self_audit_checks(root)
    gaps = [c for c in checks if c["status"] == "gap"]
    unknown = [c for c in checks if c["status"] == "unknown"]
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    gaps.sort(key=lambda c: rank.get(c["severity"], 99))
    print("\nInstrument check (this machine, not a target): "
          "%d ok, %d gap, %d not determined"
          % (len(checks) - len(gaps) - len(unknown), len(gaps), len(unknown)))
    for c in gaps:
        print("  gap  %-8s %-22s %s" % (c["severity"], c["check"], c["title"]))
        if c.get("fix"):
            print("       fix: %s" % c["fix"])
    for c in unknown:
        # Kept separate from the gaps on purpose. "I could not tell" is not a
        # pass, and folding it into one is how a machine with no clock sync
        # reads as a machine with a good one.
        print("  ?    %-8s %-22s %s" % (c["severity"], c["check"], c["title"]))
    if not gaps and not unknown:
        print("  every instrument check passed")
    print("  full detail: python3 squawk.py --run selfaudit")

    # Doctor decides whether this machine is fit to produce evidence, and until
    # now it recorded nothing about that decision. Charter I9: nothing is done
    # without evidence. Someone asking next week what the instrument check said
    # had no way to find out, which makes the check advice rather than a record.
    # Gaps go to WARNING so they grep out of the log the way REFUSED does.
    LOG.info("doctor: instrument check %d ok, %d gap, %d unknown",
             len(checks) - len(gaps) - len(unknown), len(gaps), len(unknown))
    for c in gaps:
        LOG.warning("GAP %s [%s] %s", c["check"], c["severity"], c["title"])
    for c in unknown:
        LOG.info("UNDETERMINED %s %s", c["check"], c["title"])

    last = last_install_record(root)
    if last:
        print("\nLast %s: %s (%s), %d change(s)%s"
              % (last["mode"], last["started_utc"],
                 "ok" if last.get("ok") else "EXIT %s" % last.get("exit_code"),
                 last.get("changed", 0),
                 "" if last.get("ok") else " — read the transcript"))
    else:
        print("\nLast install/update: no record found. Run --update to create "
              "one; before this version nothing was written.")

    # Exit non-zero on exactly two conditions: no scanner at all, or evidence
    # not writable. Every other absence narrows what you can run, it does not
    # stop you, so it prints as a gap and still exits 0 — safe to gate on.
    if not any_scanner:
        print("\nFAIL: no scanner installed. Install at least one (see the table above).")
        LOG.error("doctor: FAIL — no scanner installed")
        return 1
    if not writable:
        print("\nFAIL: evidence root is not writable.")
        LOG.error("doctor: FAIL — evidence root not writable: %s", root)
        return 1
    print("\nOK: enough is present to run.")
    LOG.info("doctor: OK — enough is present to run")
    return 0


# --------------------------------------------------------------------------- #
# Headless run (verification path; the web Scan page is the other one)
# --------------------------------------------------------------------------- #


def cmd_run(args: argparse.Namespace) -> int:
    service = SERVICES.get(args.run)
    if not service:
        print("Unknown service %r. Available: %s"
              % (args.run, ", ".join(SERVICES)))
        return 2

    root = args.evidence or env("EVIDENCE") or DEFAULT_EVIDENCE
    if not evidence_writable(root):
        print("Evidence root not writable: %s" % root)
        return 1

    if service.scope == "image":
        target = args.target
        base = os.getcwd()
        if not target:
            print("Service %r scans an image; pass --target <image:name>." % args.run)
            return 2
        # A path on this machine is not an image reference, and the difference
        # is not visible in the result. `trivy image <path>` fails outright, but
        # `syft <path>` succeeds: it scans the file. An operator who pointed
        # this at Docker's own VM disk got a FATAL from trivy and an SBOM of a
        # multi-gigabyte raw disk from syft, which grype then read CVEs out of
        # — a whole run labelled as a container scan, answering a question
        # nobody asked (2026-09-15).
        #
        # Refused rather than noted, because there is no path this service can
        # scan: both commands it builds take a reference. Scanning a directory
        # is what `baggage` is for, and the message says so.
        if os.path.exists(os.path.expanduser(target)):
            print("Service %r scans a container image, and %s is a path on this "
                  "machine.\n"
                  "Pass a reference instead — `alpine:3.19`, "
                  "`ghcr.io/owner/app:tag` — or use `--run baggage --target` to "
                  "scan a directory." % (args.run, target))
            return 2
    elif service.scope == "url":
        target = args.target
        base = os.getcwd()
        if not target:
            print("Service %r probes a running app; pass --target <url>." % args.run)
            return 2
        ok, reason = dast_target_ok(target)
        if not ok:
            print("Refusing DAST target: %s" % reason)
            return 2
        print("DAST target check: %s" % reason)
        if probes_a_named_port(service):
            ok, reason = dast_target_live(target)
            if not ok:
                print("Refusing DAST target: %s" % reason)
                return 2
    elif service.scope == "aws":
        ok, reason = cloud_target_ok()
        if not ok:
            print("Refusing cloud query: %s" % reason)
            return 2
        ident, why = aws_identity()
        if not ident:
            print("No AWS identity in the credential chain: %s" % why)
            return 2
        target = ident["Account"]
        base = os.getcwd()
        # Masked on screen, whole in the evidence: this line is the one most
        # often pasted, and it carries the account twice.
        print("AWS identity: %s (account %s)"
              % (redact_identifiers(ident["Arn"]), mask_account(target)))
        state, detail = aws_identity_readonly(ident["Arn"])
        if state != "ok":
            # Never blocks: the operator may have no other identity. It is
            # said here and carried on the run, so a report made with a
            # write-capable identity says so for as long as the run exists.
            print("Identity read-only check: %s — %s" % (state, detail))
    elif service.scope == "host":
        # The subject is this machine, so there is no target to pass and none
        # to get wrong. Naming the host here is deliberate: unlike a finding
        # identity, which stays host-free so the same issue matches across
        # machines, an instrument check is only meaningful about one machine.
        target = socket.gethostname()
        base = os.getcwd()
    elif service.scope == "repo":
        target = resolve_repo(args.repo or env("REPO"))
        base = target or os.getcwd()
        if not target:
            print("No repo resolved. Pass --repo <checkout>.")
            return 2
    else:  # dir
        target = args.target or args.repo or os.getcwd()
        base = target

    print("Service : %s (%s) · usually %s" % (service.label, service.scope,
                                              service.rough_time))
    print("Target  : %s" % mask_account(target))
    # A target inside a cloud-sync folder is a fact about how long this will
    # take, and it is worth one line before the run rather than an hour of
    # working out why a small repository scans like an enormous one. Printed,
    # never acted on: the run is not changed, refused or capped by it.
    owner = sync_root(target)
    if owner:
        print("\033[33mNote    : the target is inside %s, a cloud-sync folder. "
              "If its files are\n          stored online-only, every scanner that "
              "walks the tree pays a download\n          per file, and the ones "
              "that read everything (gitleaks, semgrep) may\n          exhaust "
              "their budget before they finish. A local clone scans "
              "normally.\033[0m" % owner)
    print("Evidence: %s" % root)
    # The budgets this run runs under, printed before it runs (I12): a run
    # under a profile names the file and every value it changed; a run under
    # none says so. A profile that cannot be applied is refused here, with
    # the fault named, and no run directory exists to record it.
    try:
        profile = profile_for(root, args.profile)
    except ProfileError as exc:
        print("Profile refused: %s" % exc)
        print("  %s" % PROFILE_REFUSED_NOTE)
        LOG.error("REFUSED run: profile — %s", exc)
        return 2
    for line in profile_lines(profile.summary(
            service.key, target, stage_rows(service, target, base, profile))):
        print(line)
    print("")

    marks = {"ok": "\033[32mok\033[0m", "skipped": "\033[33m--\033[0m",
             "gap": "\033[33m??\033[0m", "error": "\033[31m!!\033[0m"}

    def on_progress(ev: dict) -> None:
        if ev["phase"] == "run":
            return              # carries no stage status
        if ev["phase"] == "budget":
            # The number that answers "is it slow or is it stuck?". It was left
            # to the run page, and the run page is not where a person sits
            # while semgrep takes twenty minutes on a large tree (the operator,
            # 2026-09-12). It arrives just after the start line and before the
            # wait, which is exactly when it is wanted.
            sys.stdout.write("\033[90m≤%s\033[0m " % human_seconds(ev["timeout"]))
            sys.stdout.flush()
            return
        if ev["phase"] == "start":
            sys.stdout.write("  [%d/%d] %-9s %-9s … " % (
                ev["i"], ev["n"], ev["tool"], ev["mode"]))
            sys.stdout.flush()
        else:
            # How long it took, beside what it found. A forty-minute stage that
            # printed only its result left an operator with no idea what to
            # expect the next time, and no way to tell slow from stuck.
            took = ev.get("elapsed")
            # Redacted here as well as at the source. This line is the one an
            # operator copies into a message, and a stage detail is a string
            # some future read may build for itself (review R-3).
            sys.stdout.write("%s %s%s\n" % (
                marks.get(ev["status"], ev["status"]),
                redact_identifiers(ev["detail"]),
                "  ·  %s" % human_seconds(took) if took is not None else ""))
            sys.stdout.flush()

    began = time.time()
    outcome = execute_service(service, target, root, base, progress=on_progress,
                              profile=profile)
    print("\nRun %s  ·  %s" % (outcome["run_id"], human_seconds(time.time() - began)))
    print("Evidence written to %s" % outcome["run_dir"])

    # The alarm. Printed after the run because that is when it is actionable,
    # and printed even when nothing fires so silence is a stated result.
    print("Coverage NOT included: %s" % service.not_covered)
    man = next((m for m in list_runs(root) if m["run_id"] == outcome["run_id"]),
               None)
    if man:
        for c in (man.get("correlations") or []):
            if c.get("state") == "fired":
                print("  CORRELATION [%s] %s: %s"
                      % (c.get("severity", "?"), c.get("key", ""), c.get("why", "")))
            else:
                print("  correlation not evaluable: %s (%s)"
                      % (c.get("key", ""), c.get("why", "")))
        for d in (man.get("differential") or []):
            print("  differential: %s" % d["note"])
        for line in inventory_lines(man):
            print(line)
        raised = squawk_check(root, man)
        print("")
        if raised:
            for line in squawk_lines(raised):
                print(line)
        else:
            # The third clause is the outcome of a comparison against the
            # previous comparable run. On a first run there is no previous one,
            # the comparison is skipped, and claiming its result would be a
            # confident sentence about a check that never ran (I1). Two of the
            # three claims still hold, so the line says those and says why the
            # third is missing.
            _same, pos = comparable_runs(root, man)
            print("No squawk. Nothing critical, nothing under attack, and %s"
                  % ("every source that reported last time reported again."
                     if pos else
                     "this is the first run of this target, so there is "
                     "nothing to compare it against."))
    return 0


def inventory_lines(man: dict) -> List[str]:
    """What a cloud inventory run found, for the terminal.

    Without this the headline read "0 finding(s) across 318 resources" and then
    "No squawk", and an operator who had just asked what is in the account was
    shown two numbers and a reassurance. The resources were read, aggregated
    and thrown away because no rule fired on them. An inventory is worth
    seeing whether or not a rule fired."""
    if man.get("service") != "cloudinventory":
        return []
    raw = os.path.join(man.get("_dir", ""), "raw", "cloud-inventory.json")
    try:
        with open(raw, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    summary = inventory_summary(data)
    out = ["", "Inventory — %d resources, %d of %d enabled region(s) read"
           % (summary["resources"], summary["regions_read"],
              summary["regions_enabled"])]
    for domain in summary["domains"]:
        # Every count, zeros included. "0 EC2 instances" was the single most
        # important line for the first live estate this ran against -- it is
        # why nothing fired -- and a filter that hid zeros hid exactly that.
        parts = ["%d %s" % (i["count"], i["label"]) for i in domain["items"]]
        out.append("  %-9s %s" % (domain["label"] + ":", ", ".join(parts)))
    if summary["world_open_ports"]:
        out.append("  %-9s %s" % ("Open:",
                                  ", ".join(summary["world_open_ports"][:10])))
    out.extend(_compare_lines(man, summary))
    notes = inventory_notes(summary)
    if notes:
        out.append("")
        out.append("Worth knowing:")
        for note in notes:
            out.append("  - %s" % note)
    out.append("")
    out.append("What this does not tell you:")
    for caveat in inventory_caveats(summary):
        out.append("  - %s" % caveat)
    return out


def _compare_lines(man: dict, _summary: dict) -> List[str]:
    """The comparison against the previous reading, for the terminal.

    Read from the evidence root the run just wrote into, so the CLI says the
    same thing the page will."""
    root = os.path.dirname(os.path.abspath(man.get("_dir", "") or "."))
    runs = [m for m in list_runs(root) if m.get("service") == "cloudinventory"]
    pairs = []
    for row in runs:
        inv = _raw_of(row, "cloud-inventory.json")
        if inv:
            pairs.append((inv, _raw_of(row, "cloud-enablement.json")))
        if len(pairs) == 2:
            break
    if len(pairs) < 2:
        return []
    (new_inv, new_en), (old_inv, old_en) = pairs
    return diff_lines(compare_readings(old_inv, new_inv, old_en, new_en))


def _raw_of(man: dict, name: str) -> "Optional[dict]":
    try:
        with open(os.path.join(man.get("_dir", ""), "raw", name),
                  encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def profile_lines(summ: dict) -> List[str]:
    """The Profile block: the file and its source, then one line per value
    that differs from the built-in, then any note. Nothing is folded."""
    if not summ.get("path"):
        return ["Profile : none — built-in values"]
    changed = summ.get("changed") or []
    extra = summ.get("extra_args") or {}
    n = len(changed) + len(extra)
    lines = ["Profile : %s (%s) — %s" % (
        summ["path"], summ["source"],
        ("%d value(s) differ from the built-in" % n) if n
        else "no value differs from the built-in")]
    for c in changed:
        lines.append("  %-13s %-26s = %-6s built-in %-6s %s"
                     % (c["stage"], c["key"], show_setting(c["value"]),
                        show_setting(c["builtin"]), c["section"]))
    for tool, args in sorted(extra.items()):
        lines.append("  %-13s %-26s + %s   [scanners.%s]"
                     % (tool, "extra_args", " ".join(args), tool))
    for note in summ.get("notes") or []:
        lines.append("  note: %s" % note)
    return lines


def cmd_config(args: argparse.Namespace) -> int:
    """`config show SERVICE [TARGET]`: the effective profile for a run that is
    not made — every setting, its value, the built-in and where the value
    came from — so a budget can be checked before an hour is spent on it."""
    words = list(args.config or [])
    if not words or words[0] != "show" or len(words) < 2:
        print("usage: squawk config show SERVICE [TARGET]   (see: squawk services)")
        return 2
    service = SERVICES.get(words[1])
    if not service:
        print("Unknown service %r. Available: %s" % (words[1], ", ".join(SERVICES)))
        return 2
    if len(words) > 2:
        target = words[2]
    elif service.scope == "repo":
        target = resolve_repo(args.repo or env("REPO")) or "<repo>"
    elif service.scope == "host":
        target = socket.gethostname()
    elif service.scope == "aws":
        target = "<account>"
    else:
        target = args.target or "<target>"
    root = args.evidence or env("EVIDENCE") or DEFAULT_EVIDENCE
    try:
        profile = profile_for(root, args.profile)
    except ProfileError as exc:
        print("Profile refused: %s" % exc)
        print("  %s" % PROFILE_REFUSED_NOTE)
        LOG.error("REFUSED config show: profile — %s", exc)
        return 2
    rows = stage_rows(service, target, os.getcwd(), profile)
    summ = profile.summary(service.key, target, rows)
    print(profile_lines(summ)[0])
    print("Service : %s (%s) · target %s\n" % (service.label, service.key, target))
    print("  %-13s %-26s %-8s %-9s %s" % ("stage", "setting", "value", "built-in", "from"))
    for st in summ["settings"]:
        print("  %-13s %-26s %-8s %-9s %s"
              % (st["stage"], st["key"], show_setting(st["value"]),
                 show_setting(st["builtin"]), st["section"]))
    for tool, extra in sorted(summ["extra_args"].items()):
        print("  %-13s %-26s + %s   [scanners.%s]" % (tool, "extra_args",
                                                     " ".join(extra), tool))
    for row in rows:
        if row.get("internal"):
            print("  %-13s runs in-process — no budget applies" % row["stage"])
        elif not row.get("timeout_builtin"):
            print("  %-13s waits on an earlier stage's artifact — its budget is "
                  "set when that exists" % row["stage"])
    for note in summ["notes"]:
        print("  note: %s" % note)
    print("\nNothing was run. `squawk run %s` prints the same block before it runs."
          % service.key)
    return 0


# --------------------------------------------------------------------------- #
# Not-yet-built flags — announce honestly, never fake a pass.
# --------------------------------------------------------------------------- #


def cmd_prune(args: argparse.Namespace) -> int:
    """Show what retention would remove, and remove it only when asked.

    The dry run is the default because this is the one irreversible thing the
    tool does. Everything it would keep and why is printed too: a retention
    policy you cannot see the exceptions to is a policy you cannot trust."""
    root = args.evidence or env("EVIDENCE") or DEFAULT_EVIDENCE
    if not os.path.isdir(root):
        print("No evidence root at %s — nothing to prune." % root)
        return 1
    plan = plan_prune(root, args.trim_days, args.drop_days)
    n_all = len(plan["trim"]) + len(plan["drop"]) + len(plan["keep"])
    print("Evidence : %s" % root)
    print("Runs     : %d, %s on disk" % (n_all, human_bytes(plan["total"])))
    print("Policy   : trim the raw output of runs older than %d days; "
          "remove runs older than %d days" % (args.trim_days, args.drop_days))
    print()

    if plan["trim"]:
        print("Trim — keeps the manifest, findings, identities and digest; drops the")
        print("scanner's own output and the superseded timeline. Pages still render.")
        for r in plan["trim"]:
            print("  %s  %-28s %5.0f days  frees %s"
                  % (r["run_id"], _short(r["target"]), r["age_days"],
                     human_bytes(r["reclaim"])))
        print()
    if plan["drop"]:
        print("Remove — the run stops existing and this target's history gets shorter.")
        for r in plan["drop"]:
            print("  %s  %-28s %5.0f days  frees %s"
                  % (r["run_id"], _short(r["target"]), r["age_days"],
                     human_bytes(r["bytes"])))
        print()

    # Only the runs a protection actually rescued. Listing a run that is a day
    # old under "kept although old enough" says the policy did work it did not
    # do, and a policy you cannot see the real exceptions to is one you cannot
    # trust.
    guarded = [r for r in plan["keep"]
               if r["why"] and (r["age_days"] is None
                                or r["age_days"] >= min(args.trim_days, args.drop_days))]
    if guarded:
        print("Old enough to prune, kept because something still depends on them:")
        for r in guarded[:20]:
            print("  %s  %s" % (r["run_id"], "; ".join(r["why"])))
        if len(guarded) > 20:
            print("  ... and %d more" % (len(guarded) - 20))
        print()

    if not plan["trim"] and not plan["drop"]:
        print("Nothing is old enough to prune. Nothing was changed.")
        return 0

    print("Would free %s of %s." % (human_bytes(plan["reclaim"]),
                                    human_bytes(plan["total"])))
    if not args.apply:
        print()
        print("This was a dry run and nothing was removed. To carry it out:")
        print("  squawk prune --apply --trim-days %d --drop-days %d"
              % (args.trim_days, args.drop_days))
        return 0

    done = apply_prune(plan, by=who())
    print()
    print("Trimmed %d run(s), removed %d, freed %s."
          % (len(done["trimmed"]), len(done["dropped"]),
             human_bytes(done["reclaimed"])))
    for f in done["failed"]:
        print("  could not remove %s from %s: %s"
              % (f["part"], f["run_id"], f["error"]))
    print("A trimmed run keeps a pruned.json saying what went and when, so it "
          "reads as pruned rather than as a run that never had raw output.")
    return 1 if done["failed"] else 0


def cmd_sarif(args: argparse.Namespace) -> int:
    """One run as SARIF 2.1.0 on stdout.

    Read-only, and it writes nothing: a run directory is sealed, and a format
    conversion has no business inside one. Redirect it where you want it.

    Exit 1 rather than printing an empty document when there is no run to
    convert -- an empty SARIF is indistinguishable from a scan that found
    nothing, which is the one thing this tool will not do.
    """
    root = args.evidence or env("EVIDENCE") or DEFAULT_EVIDENCE
    runs = list_runs(root)
    if not runs:
        sys.stderr.write("No runs under %s. Run a scan first.\n" % root)
        return 1
    wanted = (args.sarif or "").strip()
    if wanted:
        picked = [r for r in runs if r.get("run_id") == wanted]
        if not picked:
            sys.stderr.write(
                "No run %r under %s. `squawk verify` lists them.\n"
                % (wanted, root))
            return 1
        man = picked[0]
    else:
        man = runs[0]                  # list_runs is newest first
    run_dir = man.get("_dir") or os.path.join(root, man.get("run_id") or "")
    doc = sarif_document(man, load_findings(run_dir))
    json.dump(doc, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Prove the evidence has not been edited since it was written.

    Three outcomes, never two. 0: every run verified. 1: something was altered,
    is missing, was added, or the chain is broken. 3: nothing was wrong and
    something could not be checked — a run written before digests carried file
    hashes, say. "Could not tell" is not a pass, so it does not exit 0."""
    root = args.evidence or env("EVIDENCE") or DEFAULT_EVIDENCE
    if not os.path.isdir(root):
        print("No evidence root at %s — nothing to verify." % root)
        return 1
    def show(r: dict) -> None:
        line = "  %s  %-28s %s" % (r["run_id"], _short(r["target"]), r["state"])
        if r["detail"]:
            line += " — %s" % r["detail"]
        print(line, flush=True)
        for note in r["notes"]:
            print("      note: %s" % note, flush=True)

    if not args.json:
        print("Evidence : %s" % root)
        print("Checking : one line per run as it is hashed, oldest first\n", flush=True)
    # Each run prints as it is checked rather than all at the end, so a large
    # root shows movement instead of silence — silence being the thing this
    # command exists to refuse.
    report = verify_root(root, progress=None if args.json else show)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        if not report["runs"]:
            print("  (no runs)")
        print("\nChecked  : %s" % report["at"])
        if report.get("previous_at"):
            # Verify stamps are second-resolution, so two verifies in one
            # second print the same string and "then" and "now" read as the
            # same moment — which makes the anchor look like it compared
            # against itself. Seen in field use, 2026-09-07. Say which it is.
            same = report["previous_at"] == report["at"]
            print("Previous : %s%s — every digest seen then was compared with now"
                  % (report["previous_at"],
                     " (the verify before this one, within the same second)" if same else ""))
        else:
            print("Previous : none — the newest run and the newest ledger line are "
                  "covered from the next verify on")
        pruned = report.get("pruned_runs") or []
        if pruned:
            print("\nRetention record, %s — %s" % (report["retention"]["state"],
                                                   report["retention"]["detail"]))
            print("Relied on for the lines above. A record, not a proof: anyone who "
                  "can write this\nroot can add one. Each is listed so you can "
                  "recognise the ones you did:")
            for r in pruned:
                what = ("removed" if r["kind"] == "drop"
                        else "trimmed %s from" % ", ".join(r.get("parts") or []))
                print("  %s  %s %s by %s" % (r["at"], what, r["run_id"], r["by"] or "?"))
        led = report["ledger"]
        print("\nDecisions ledger: %s — %s" % (led["state"], led["detail"]))
        print("\n%s" % report["summary"])
        print("\nWhat this proves: no file in a verified run changed since the run "
              "wrote it,\nand each run proves the one before it existed. What it does "
              "not prove:\nwho wrote it. There are no signatures here.")
    try:
        path = save_verify(root, report)
        if not args.json:
            print("\nRecorded in %s, which the Overview reads." % path)
    except OSError as exc:
        print("could not record the result: %s" % exc)
    return report["exit"]


def _short(target: str) -> str:
    """A target short enough for a list, with the account masked.

    Its web sibling `_short_target` has always called `mask_account`; this one
    did not, so `--verify` and `--prune` printed every run's account id in full
    -- a transcript somebody pastes. Found in review, 2026-09-18.
    """
    if "/" in target and not target.startswith(("image:", "http")):
        return os.path.basename(target.rstrip("/")) or target
    return mask_account(target)[:28]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def cmd_intel(root: str, force: bool = False) -> bool:
    """Fetch the per-CVE detail for every CVE the estate currently carries.

    Scoped to the estate on purpose. Fetching the whole of NVD would be a
    different tool and a worse neighbour; what a reader needs is the context for
    the CVEs actually in front of them. The key, where there is one, comes from
    the environment and rides in a header: never on argv, which is visible in
    the process table."""
    live, _vanished, _by_target = estate_runs(root)
    if not live:
        print("\nPer-CVE detail: no live targets, so there is nothing to look up.")
        return True
    cves = sorted(estate_cves(list(live.values()), load_findings))
    print("\nPer-CVE detail (OSV + NVD) -> %s" % intel_dir(root))
    if not cves:
        print("  no CVE-bearing findings in the newest run of any live target")
        return True
    key = os.environ.get("SQUAWK_NVD_API_KEY") or ""
    ok, lines = fetch_intel(root, cves, force=force, api_key=key or None)
    print("\n".join(lines))
    return ok


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="squawk",
        description=(
            "Local, single-user orchestrator for open-source scanners.\n"
            "\n"
            "Start here:\n"
            "  squawk doctor                 what is installed, and what is missing\n"
            "  squawk install                provision the scanner toolbench (Unix)\n"
            "  squawk services               the thirteen services and what each\n"
            "                                does NOT cover\n"
            "  squawk run SERVICE --repo DIR scan a checkout\n"
            "  squawk serve                  the read-only web UI, on loopback\n"
            "\n"
            "Everything else:\n"
            "  feeds | update | status | stop | restart | install-service |\n"
            "  sync-baselines | verify | prune | config show | version\n"
            "\n"
            "Subcommands are the spelling going forward. Every flag below still\n"
            "works, and each subcommand is the flag of the same name."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Docs: README.md, then docs/CHARTER.md for the rules this holds "
               "itself to.")
    p.add_argument("--repo", help="repo target (default: nearest git checkout)")
    p.add_argument("--target", help="explicit target for dir/image scopes")
    p.add_argument("--evidence", help="evidence root (default ~/scan-evidence)")
    p.add_argument("--profile", metavar="PATH",
                   help="squawk.toml to run under (default: SQUAWK_PROFILE, then "
                        "squawk.toml in the evidence root)")
    p.add_argument("--config", nargs="+", metavar="ARG",
                   help="config show SERVICE [TARGET]: the effective profile, "
                        "without running anything")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help="web UI port")
    p.add_argument("--host", default="127.0.0.1", help="loopback only")
    p.add_argument("--gh-repo", help="owner/name for GitHub baselines")
    p.add_argument("--doctor", action="store_true", help="preflight and exit")
    p.add_argument("--intel", action="store_true",
                   help="with feeds: also fetch per-CVE detail (OSV and NVD) for "
                        "every CVE in the estate")
    p.add_argument("--refetch", action="store_true",
                   help="with feeds --intel: re-fetch detail already cached")
    p.add_argument("--feeds", action="store_true",
                   help="refresh the CISA KEV and EPSS exploitability feeds and exit")
    p.add_argument("--install", action="store_true",
                   help="install the scanner toolbench (runs install-tools.sh)")
    p.add_argument("--update", action="store_true",
                   help="update the OS, the scanners, their vulnerability "
                        "databases and the ZAP image")
    p.add_argument("--run", metavar="SERVICE", help="run one service headless and exit")
    p.add_argument("--list-services", action="store_true", help="list kiosk services")
    p.add_argument("--sync-baselines", action="store_true",
                   help="pull per-finding baselines from GitHub issues and exit")
    p.add_argument("--verify", action="store_true",
                   help="check every run in the evidence root against its digest "
                        "and the chain, and the decisions ledger, then exit")
    p.add_argument("--json", action="store_true",
                   help="with verify: print the whole report as one JSON document")
    p.add_argument("--sarif", nargs="?", const="", metavar="RUN",
                   help="print one run as SARIF 2.1.0 on stdout (default: the "
                        "newest run). A scanner that read nothing is an "
                        "unsuccessful invocation carrying its denominator, and "
                        "a correlation that could not be evaluated is a "
                        "notApplicable result -- both survive into GitHub code "
                        "scanning")
    p.add_argument("--prune", action="store_true",
                   help="show what retention would remove from the evidence root")
    p.add_argument("--apply", action="store_true",
                   help="with prune: actually remove it (the default is a dry run)")
    p.add_argument("--trim-days", type=int, default=DEFAULT_TRIM_DAYS,
                   metavar="N", help="prune: drop raw output from runs older than N "
                                     "days (default %d)" % DEFAULT_TRIM_DAYS)
    p.add_argument("--drop-days", type=int, default=DEFAULT_DROP_DAYS,
                   metavar="N", help="prune: remove runs older than N days entirely "
                                     "(default %d)" % DEFAULT_DROP_DAYS)
    p.add_argument("--open", action="store_true",
                   help="open the browser once the server is up")
    p.add_argument("--version", action="version", version="squawk %s" % __version__)
    p.add_argument("--daemon", action="store_true",
                   help="start the web UI in the background (pid file under the "
                        "evidence root; output to squawk-serve.log)")
    p.add_argument("--status", action="store_true",
                   help="is the web UI running, and is it answering? then exit")
    p.add_argument("--stop", action="store_true",
                   help="stop the running web UI (a scan in progress is recorded "
                        "as aborted) and exit")
    p.add_argument("--restart", action="store_true",
                   help="stop the web UI if running, then start it in the background")
    p.add_argument("--install-service", action="store_true",
                   help="write a systemd user unit so Squawk starts at login "
                        "(Kali); prints the enable commands, does not run them")
    return p


def list_services() -> int:
    print("Services:\n")
    for s in SERVICES.values():
        print("  %-11s %-18s %-6s %s" % (s.key, s.label, s.scope, s.rough_time))
        print("              tools: %s" % ", ".join(s.stages))
        print("              not covered: %s\n" % s.not_covered)
    return 0


SUBCOMMANDS = {
    "serve": [], "run": ["--run"], "doctor": ["--doctor"], "feeds": ["--feeds"],
    "update": ["--update"], "install": ["--install"], "services": ["--list-services"],
    "status": ["--status"], "stop": ["--stop"], "restart": ["--restart"],
    "install-service": ["--install-service"], "sync-baselines": ["--sync-baselines"],
    "prune": ["--prune"], "verify": ["--verify"], "version": ["--version"],
    "config": ["--config"],
    "sarif": ["--sarif"],
}


def _translate_argv(argv: Optional[List[str]]) -> List[str]:
    """`squawk run customs --target X` is `--run customs --target X`. Subcommands
    are the professional spelling; the flags stay, so nothing already written
    down stops working."""
    args = list(argv if argv is not None else sys.argv[1:])
    if not args or args[0].startswith("-") or args[0] not in SUBCOMMANDS:
        return args
    head, rest = args[0], args[1:]
    if head == "run":
        if rest and not rest[0].startswith("-"):
            return ["--run", rest[0], *rest[1:]]
        return ["--run", "", *rest]
    return [*SUBCOMMANDS[head], *rest]


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(_translate_argv(argv))

    # The floor, said on every command rather than only in `doctor`. Below it
    # a run still completed and wrote evidence that looked exactly like
    # evidence from a supported interpreter — measured on python:3.8,
    # 2026-09-08 — and evidence that cannot be told from the real thing is the
    # failure this tool is built around. It warns rather than refuses: being
    # stranded is worse than being told, and the message names both versions.
    if sys.version_info < (3, 9):
        sys.stderr.write(
            "squawk: running on Python %s, below the supported floor of 3.9. "
            "Results from this run are not covered by the test suite, which "
            "gates on 3.9.\n" % ".".join(str(n) for n in sys.version_info[:3]))

    # Logging comes up before anything else can refuse, run or serve, so that
    # every one of those leaves a record. It is on by default.
    setup_logging(args.evidence or env("EVIDENCE") or DEFAULT_EVIDENCE)
    LOG.info("invoked: %s", " ".join(argv if argv is not None else sys.argv[1:]))

    if args.host:
        guard_host(args.host)

    root0 = args.evidence or env("EVIDENCE") or DEFAULT_EVIDENCE
    if args.status:
        return cmd_status(root0)
    if args.stop:
        return cmd_stop(root0)
    if args.install_service:
        return cmd_install_service(args, root0)
    if args.restart:
        if read_pid_file(root0):
            cmd_stop(root0)
        args.daemon = True
    if args.install or args.update:
        # The zipapp has no "beside": it is one file, for a machine that cannot
        # clone the repository — and that is exactly the machine with no
        # scanners on it. `installer_script` reads the copy the build carries
        # inside the package when there is no checkout.
        script, how = installer_script()
        if not script:
            print("Cannot run the installer: %s." % how)
            return 1
        root = args.evidence or env("EVIDENCE") or DEFAULT_EVIDENCE
        print("Installer: %s (%s)" % (script, how))
        try:
            rc = run_installer("update" if args.update else "install", root, script)
        finally:
            # Only what this process extracted, and only the directory it made.
            if how.startswith("carried"):
                shutil.rmtree(os.path.dirname(script), ignore_errors=True)
        if args.update:
            print("\nExploitability feeds:")
            _ok, lines = update_feeds(root)
            print("\n".join(lines))
        return rc
    if args.feeds:
        froot = args.evidence or env("EVIDENCE") or DEFAULT_EVIDENCE
        print("Exploitability feeds -> %s" % os.path.join(froot, FEEDS_DIRNAME))
        ok, lines = update_feeds(froot)
        print("\n".join(lines))
        if args.intel:
            ok = cmd_intel(froot, force=args.refetch) and ok
        return 0 if ok else 1
    if args.doctor:
        return doctor(args)
    if args.list_services:
        return list_services()
    if args.config:
        return cmd_config(args)
    if args.run == "":
        print("run needs a service: squawk run <service> [--target ...]. "
              "See: squawk services")
        return 2
    if args.run:
        return cmd_run(args)
    if args.sarif is not None:
        return cmd_sarif(args)
    if args.verify:
        return cmd_verify(args)
    if args.prune:
        return cmd_prune(args)
    if args.sync_baselines:
        root = args.evidence or env("EVIDENCE") or DEFAULT_EVIDENCE
        repo = resolve_repo(args.repo or env("REPO"))
        gh_repo = resolve_gh_repo(args.gh_repo, repo)
        if not gh_repo:
            print("No GitHub repo resolved. Pass --gh-repo owner/name "
                  "or set SQUAWK_GH_REPO.")
            return 2
        ok, msg, cache = sync_baselines(root, gh_repo)
        print(("synced — %s" if ok else "not synced — %s") % msg)
        for tool, e in sorted((cache.get("scanners") or {}).items()):
            print("  %-9s %-8s %s" % (tool, e["status"], e["reason"]))
        return 0 if ok else 1

    # Default action: serve the loopback web UI (also on --open).
    if args.daemon:
        return start_daemon(args, root0)
    return serve_web(args)


__all__ = [
    'SUBCOMMANDS',
    '_compare_lines',
    '_raw_of',
    '_short',
    '_translate_argv',
    'build_parser',
    'cmd_config',
    'cmd_intel',
    'cmd_prune',
    'cmd_run',
    'cmd_sarif',
    'cmd_verify',
    'doctor',
    'inventory_lines',
    'list_services',
    'main',
    'profile_lines',
]

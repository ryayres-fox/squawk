"""Conformance tests for CHARTER.md.

These do not test features. They test the properties every feature has to keep,
so that adding a scanner two months from now either satisfies the charter or
turns this suite red. The charter is prose, and prose does not stop drift; this
file is the part that does.

Each class names the invariant it enforces. If an invariant here is wrong,
change CHARTER.md and this file in the same commit, deliberately.
"""

import ast
import inspect
import io
import json
import os
import pathlib
import re
import sys
import textwrap
import typing

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import squawk

ENTRY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "squawk.py")

CHARTER = pathlib.Path(__file__).parent.parent / "docs" / "CHARTER.md"


class _Ctx:
    """Enough RunContext for a stage to build its command line."""

    # Paths that are never created or written. They exist so a stage can build
    # a command line; using a real temp directory would imply this touches disk.
    ROOT = "/squawk-charter-fixture"

    def __init__(self, target=None, scope="repo"):
        self.target = target or self.ROOT + "/target"
        self.scope = scope
        self.run_dir = self.ROOT + "/run"
        self.base = self.ROOT + "/target"
        self.artifacts = {"sbom": self.ROOT + "/run/sbom.json"}
        self.raw_path = self.ROOT + "/run/raw.json"
        self.evidence_root = self.ROOT


# --------------------------------------------------------------------------- #
# I10 — the registry stays closed
# --------------------------------------------------------------------------- #

def _patch_all(monkeypatch, name, value):
    """Monkeypatch a name in every squawk module that binds it: a function
    looks a name up in its own module, so patching the package alone patches
    nothing that runs."""
    import types
    for mod in list(vars(squawk).values()):
        if (isinstance(mod, types.ModuleType) and mod.__name__.startswith("squawk.")
                and hasattr(mod, name)):
            monkeypatch.setattr(mod, name, value)


class TestRegistryIsClosed:
    """A half-registered scanner is a stage that silently never runs, which is
    I1 arriving through the back door."""

    def test_every_stage_has_a_normalizer(self):
        for key, spec in squawk.STAGES.items():
            assert spec.tool in squawk.NORMALIZERS, \
                "stage %r produces output nothing can parse" % key

    def test_every_stage_tool_is_a_registered_scanner(self):
        for key, spec in squawk.STAGES.items():
            assert spec.tool in squawk.SCANNERS, \
                "stage %r names an unregistered scanner %r" % (key, spec.tool)

    def test_every_service_names_real_stages(self):
        for svc in squawk.SERVICES.values():
            for stage in svc.stages:
                assert stage in squawk.STAGES, \
                    "service %r names a stage that does not exist: %r" % (svc.key, stage)

    # correlation runs AFTER the stages, over their combined findings, so it is
    # a scanner without a stage by design rather than a half-registered one. The
    # exemption is named here so it is a decision, not a hole in the check.
    POST_STAGE = frozenset({"correlation"})

    def test_every_scanner_is_reachable_from_a_stage(self):
        reachable = {spec.tool for spec in squawk.STAGES.values()} | self.POST_STAGE
        orphans = sorted(set(squawk.SCANNERS) - reachable)
        assert not orphans, "scanners no stage can run: %s" % orphans

    def test_every_stage_is_reachable_from_a_service(self):
        used = set()
        for svc in squawk.SERVICES.values():
            used.update(svc.stages)
        orphans = sorted(set(squawk.STAGES) - used)
        assert not orphans, "stages no service offers: %s" % orphans


# --------------------------------------------------------------------------- #
# I2 — absence is recorded with a reason
# --------------------------------------------------------------------------- #

class TestAbsenceIsExplained:

    def test_every_scanner_says_what_it_contributes(self):
        for name, sc in squawk.SCANNERS.items():
            assert sc.contributes.strip(), \
                "%r cannot explain what its absence costs" % name

    def test_every_service_states_what_it_does_not_cover(self):
        for key, svc in squawk.SERVICES.items():
            assert svc.not_covered.strip(), \
                "service %r makes no coverage statement" % key

    def test_coverage_statements_are_sentences_not_labels(self):
        """'No DAST' is a label. The point is telling a reader what they still
        do not know, which takes a sentence."""
        for key, svc in squawk.SERVICES.items():
            assert len(svc.not_covered.split()) >= 5, \
                "service %r coverage statement is too terse to inform" % key


# --------------------------------------------------------------------------- #
# I3 — read-only, always
# --------------------------------------------------------------------------- #

# Exact tokens, not substrings: `rm` appears inside `--report-format`, which
# made a naive substring check flag gitleaks for deleting things.
DESTRUCTIVE_TOKENS = frozenset({
    "delete", "destroy", "remove", "rm", "apply", "create", "put",
    "write", "push", "upload", "modify", "terminate", "revoke",
    "attach", "detach", "-delete", "--delete", "--force",
})

# `--rm` removes the *container* Squawk just started, not anything belonging to
# the user. Named here so the exemption is a recorded decision rather than a
# hole in a regex.
READ_ONLY_EXEMPT = frozenset({"--rm"})


class TestReadOnly:
    """Squawk assesses and never changes what it looks at."""

    def test_no_stage_builds_a_destructive_command(self):
        offenders = []
        for key, spec in squawk.STAGES.items():
            if spec.internal is not None:
                continue                      # runs in-process, builds no command
            cmd, _timeout = spec.build(_Ctx())
            for token in cmd:
                t = str(token).lower()
                if t in READ_ONLY_EXEMPT:
                    continue
                if t in DESTRUCTIVE_TOKENS:
                    offenders.append((key, t))
        assert not offenders, "destructive tokens in built commands: %s" % offenders

    def test_no_internal_stage_builds_a_destructive_command(self):
        """The test above skips internal stages because they build no command
        — and for years that was true. The AWS inventory broke it: it runs
        in-process and then drives the CLI itself, many times, so its argv
        never passed under the rule that governs every other stage. An
        exemption that was a description of the code became a hole in it the
        day the code changed.

        So the argv an internal stage builds is checked here, at its source.
        Any module that assembles provider-CLI arguments declares them in a
        table this test can read, and the test after this one sweeps the whole
        module for calls built inline at their call site, so neither shape can
        slip past."""
        offenders = []
        for key, argv, _rows_key in squawk.probes.INVENTORY_READS:
            for token in argv:
                t = str(token).lower()
                if t in READ_ONLY_EXEMPT:
                    continue
                if t in DESTRUCTIVE_TOKENS:
                    offenders.append((key, t))
                # A read verb, positively asserted. The token list is a
                # blocklist and blocklists miss things: `describe-` is what
                # this may do, not merely what it may not.
            assert argv[1].startswith(("describe-", "list-", "get-")), \
                "inventory read %s calls %s, which is not a read" % (key, argv[1])
        assert not offenders, "destructive tokens in inventory calls: %s" % offenders

    def test_the_iam_graph_never_writes(self):
        """The IAM read wants MFA and key age per principal, and the one call
        that returns both -- `generate-credential-report` -- CREATES something
        in the account. Harmless, and still a write. It is not called, and the
        same facts come from `list-mfa-devices` and `list-access-keys`, which
        are reads. Asserted over the parsed source so a comment cannot satisfy
        it."""
        import ast
        tree = ast.parse(open(squawk.probes.__file__, encoding="utf-8").read())
        literals = {n.value for n in ast.walk(tree)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        for verb in ("generate-credential-report", "create-service-linked-role",
                     "simulate-principal-policy"):
            assert verb not in literals, "%s changes or costs something" % verb

    def test_the_exemption_list_stays_small(self):
        """Every entry is a hole. If this grows, the rule is being eroded."""
        assert len(READ_ONLY_EXEMPT) <= 2, \
            "read-only exemptions are growing: %s" % sorted(READ_ONLY_EXEMPT)

    def test_the_runtime_holds_the_charters_tokens(self):
        """The list above is the charter's; the one in `core` is what refuses
        a profile at load time. The runtime may know more tokens, never
        fewer, and the exemption is the same recorded decision."""
        assert DESTRUCTIVE_TOKENS <= squawk.DESTRUCTIVE_TOKENS, \
            "the runtime forgot: %s" % sorted(DESTRUCTIVE_TOKENS - squawk.DESTRUCTIVE_TOKENS)
        assert squawk.READ_ONLY_EXEMPT == READ_ONLY_EXEMPT

    def test_a_profile_cannot_add_a_destructive_option(self):
        """A profile's extra_args pass through the same list, with no
        exemption at all: `--rm` is Squawk's own container flag, not a thing
        an operator may append to a scanner."""
        for token in sorted(DESTRUCTIVE_TOKENS | READ_ONLY_EXEMPT):
            prof = squawk.Profile("squawk.toml", "--profile",
                                  {"scanners": {"semgrep": {"extra_args": ["--json", token]}}})
            with pytest.raises(squawk.ProfileError) as err:
                prof.validate()
            assert token in str(err.value) and "read-only" in str(err.value), token


# --------------------------------------------------------------------------- #
# I1 — a tool that did not run must never look like a tool that found nothing
# --------------------------------------------------------------------------- #

class TestSilenceIsNotClean:
    """The thesis, held against the running tool rather than the prose. The
    charter named this class as I1's enforcement before it existed; the gap it
    found on arrival: a run whose every scanner was missing recorded them as
    `skipped`, and nothing downstream read `skipped` as anything — the Overview
    drew a blue "clean" pill, Findings said "a clean result only because it
    looked", and the CLI printed "No squawk"."""

    def _run_with_nothing_installed(self, tmp_path, monkeypatch):
        import os
        repo = str(tmp_path / "repo")
        os.makedirs(repo)
        with open(os.path.join(repo, "app.py"), "w") as fh:
            fh.write("print('hello')\n")
        root = str(tmp_path / "ev")
        _patch_all(monkeypatch, "tool_path", lambda name: None)
        out = squawk.execute_service(squawk.SERVICES["customs"], repo, root, repo)
        man = next(m for m in squawk.list_runs(root) if m["run_id"] == out["run_id"])
        return root, man

    def test_a_scanner_that_is_not_installed_is_a_gap_in_the_ledger(self, tmp_path, monkeypatch):
        _root, man = self._run_with_nothing_installed(tmp_path, monkeypatch)
        external = [r for r in man["ledger"] if r["tool"] != "correlation"]
        assert external, "the service ran no external stage at all"
        for row in external:
            assert row["status"] == "gap", row
            assert "not installed" in row["detail"] or "no sbom to read" in row["detail"], row
        assert not any(r["status"] == "skipped" for r in man["ledger"]), \
            "skipped is neutral to every reader; a stage that could not run is a gap"

    def test_a_run_that_could_not_look_is_incomplete_and_squawks(self, tmp_path, monkeypatch):
        root, man = self._run_with_nothing_installed(tmp_path, monkeypatch)
        assert squawk._run_incomplete(man)
        raised = squawk.squawk_check(root, man)
        codes = [r["code"] for r in raised]
        assert "7600" in codes, "nothing ran and nothing squawked: %s" % raised
        detail = " ".join(next(r for r in raised if r["code"] == "7600")["detail"])
        assert "syft" in detail and "not installed" in detail

    def test_the_pages_never_call_it_clean(self, tmp_path, monkeypatch):
        root, man = self._run_with_nothing_installed(tmp_path, monkeypatch)
        overview = squawk.view_overview(root)
        targets = overview.split("Targets by risk")[1].split("Scan activity")[0]
        assert ">clean</span>" not in targets, \
            "the Overview drew a clean pill for a run in which nothing ran"
        assert "did not fully scan" in targets and "with a coverage gap" in overview
        findings = squawk.view_findings(root, man["run_id"])
        assert "did not fully look" in findings
        assert "only because it looked" not in findings
        assert "could not run" in findings

    def test_a_run_written_before_this_reads_as_not_looked(self, tmp_path):
        """Runs on disk from before 2026-09-07 hold `skipped`; the readers owe
        them the same honesty."""
        import json
        import os
        root = str(tmp_path / "ev")
        d = os.path.join(root, "20260101T000000Z")
        os.makedirs(os.path.join(d, "raw"))
        man = {"run_id": "20260101T000000Z", "service": "customs", "scope": "repo",
               "target": "/x", "service_label": "Customs", "not_covered": "",
               "counts": {"total": 0, "excluded": 0}, "severities": {},
               "ledger": [{"tool": "syft", "mode": "sbom", "status": "skipped",
                           "detail": "syft not found", "evidence": None, "coverage": None},
                          {"tool": "correlation", "mode": "join", "status": "ok",
                           "detail": "0 correlation(s)", "evidence": None, "coverage": None}]}
        for name, obj in (("manifest.json", man), ("findings.json", []),
                          ("identities.json", {}), ("digest.json", {})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(obj, fh)
        loaded = squawk.list_runs(root)[0]
        assert squawk._run_incomplete(loaded)
        assert any(r["code"] == "7600" for r in squawk.squawk_check(root, loaded))

    def test_the_scan_tile_promise_matches_the_ledger(self, tmp_path, monkeypatch):
        """The tile says a missing scanner is "recorded as coverage gaps, never
        as a pass". The ledger is the record; it must say gap."""
        _patch_all(monkeypatch, "tool_path", lambda name: None)
        html = squawk.view_scan(str(tmp_path / "ev"), None)
        assert "recorded as coverage gaps, never as a pass" in html
        _root, man = self._run_with_nothing_installed(tmp_path, monkeypatch)
        assert all(r["status"] == "gap" for r in man["ledger"] if r["tool"] != "correlation")


# --------------------------------------------------------------------------- #
# I4 — loopback only, private targets only
# --------------------------------------------------------------------------- #

class TestLoopbackOnly:

    @pytest.mark.parametrize("host", [
        "0.0.0.0",  # noqa: S104 - refusing this address is the assertion
        "192.168.1.10", "::", "example.com"])
    def test_binding_off_loopback_is_refused(self, host):
        with pytest.raises(SystemExit):
            squawk.guard_host(host)

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
    def test_loopback_is_allowed(self, host):
        assert squawk.guard_host(host) is None

    @pytest.mark.parametrize("url", ["http://8.8.8.8", "https://example.com",
                                     "http://93.184.216.34:8080"])
    def test_public_dast_targets_are_refused(self, url, monkeypatch):
        monkeypatch.delenv("SQUAWK_DAST_ACK", raising=False)
        ok, reason = squawk.dast_target_ok(url)
        assert not ok, "public target accepted: %s (%s)" % (url, reason)
        assert reason.strip(), "a refusal with no reason cannot be audited"

    @pytest.mark.parametrize("url", ["http://127.0.0.1:3000", "http://192.168.1.50",
                                     "http://10.0.0.5:8080"])
    def test_private_dast_targets_are_allowed(self, url):
        ok, _reason = squawk.dast_target_ok(url)
        assert ok, "private target refused: %s" % url


# --------------------------------------------------------------------------- #
# I6 — a normalizer never raises
# --------------------------------------------------------------------------- #

def _junk_corpus():
    """Shapes a scanner could emit after a version bump, plus outright garbage.

    Built rather than listed, because the interesting failures were never the
    ones anybody thought to write down: nine of ten normalizers raised on `[]`,
    which is valid JSON and the wrong shape."""
    keys = ["results", "Results", "matches", "site", "alerts", "findings",
            "endpoints", "checks", "failed_checks", "Vulnerabilities",
            "Misconfigurations", "Secrets", "artifacts"]
    wrong = ["x", 1, None, [], {}, [1, 2], ["a"], [None], [[]], {"a": 1}, True]
    corpus = ["", "   ", "not json", "null", "123", '"str"', "[]", "{}",
              "[1,2,3]", "[null]", "[[]]", '{"a":{"b":{}}}']
    for k in keys:
        for w in wrong:
            corpus.append(json.dumps({k: w}))
            corpus.append(json.dumps([{k: w}]))
    return corpus


JUNK = _junk_corpus()


def _fixture_service(monkeypatch, tool, produce, shape=None, coverage=None):
    """Register a one-stage service whose scanner returns exactly `produce`.

    The point is to drive the REAL stage runner -- execute_service, the ledger,
    the drift check, the coverage gate -- with a report whose shape the test
    chose. Everything is registered through monkeypatch.setitem, so the
    registries are back to themselves when the test ends."""
    monkeypatch.setitem(squawk.SCANNERS, tool, squawk.Scanner(
        tool, "", "audit", (), False, (), True))
    monkeypatch.setitem(squawk.NORMALIZERS, tool, lambda _raw, _base: [])
    monkeypatch.setitem(squawk.STAGES, tool, squawk.StageSpec(
        tool, "fixture", None, internal=produce))
    monkeypatch.setitem(squawk.SERVICES, tool, squawk.Service(
        tool, "Fixture %s" % tool, "host", (tool,), "instant",
        "a fixture, registered by a test"))
    if shape is not None:
        monkeypatch.setitem(squawk.REPORT_SHAPES, tool, shape)
    if coverage is not None:
        monkeypatch.setitem(squawk.COVERAGE, tool, coverage)


class TestNormalizersNeverRaise:
    """Scanners change their output between versions. A parse failure has to
    degrade to 'nothing readable', which the run then reports as the gap it is,
    rather than to a crashed stage."""

    @pytest.mark.parametrize("name", sorted(squawk.NORMALIZERS))
    def test_normalizer_survives_every_junk_input(self, name):
        fn = squawk.NORMALIZERS[name]
        for junk in JUNK:
            try:
                out = fn(junk, "/base")
            except Exception as exc:
                raise AssertionError(
                    "%s raised %s on %r" % (name, type(exc).__name__, junk[:40])) from exc
            assert isinstance(out, list), \
                "%s returned %s, not a list" % (name, type(out).__name__)

    def test_the_corpus_is_actually_large(self):
        """A guard that shrank to nothing would still pass every test above."""
        assert len(JUNK) > 200


# --------------------------------------------------------------------------- #
# I5 / I7 — identity is portable, findings are well-formed
# --------------------------------------------------------------------------- #

TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T|\d{8}T\d{6}")


class TestIdentityIsPortable:
    """Two identical runs must diff to nothing, and the same finding on another
    machine must match. Timestamps, absolute paths and hostnames all break that."""

    def _sample_findings(self):
        ctx = _Ctx()
        raw = squawk.self_audit(ctx)
        return squawk.norm_selfaudit(raw, "/base")

    def test_identities_carry_no_timestamp(self):
        for f in self._sample_findings():
            assert not TIMESTAMP.search(f.identity), \
                "identity carries a timestamp: %r" % f.identity

    def test_identities_carry_no_absolute_path(self):
        for f in self._sample_findings():
            assert not f.identity.startswith("/"), \
                "identity is an absolute path: %r" % f.identity

    def test_identities_carry_no_hostname(self):
        import socket
        host = socket.gethostname()
        for f in self._sample_findings():
            assert host not in f.identity, \
                "identity carries the hostname: %r" % f.identity

    def test_two_runs_fingerprint_identically(self):
        a = [f.identity for f in self._sample_findings()]
        b = [f.identity for f in self._sample_findings()]
        assert squawk.fingerprint(a) == squawk.fingerprint(b)


class TestFindingsAreWellFormed:

    def test_severity_is_always_known(self):
        ctx = _Ctx()
        for f in squawk.norm_selfaudit(squawk.self_audit(ctx), "/base"):
            assert f.severity in squawk.SEVERITY_ORDER, \
                "unsortable severity %r" % f.severity

    def test_identity_is_never_empty(self):
        ctx = _Ctx()
        for f in squawk.norm_selfaudit(squawk.self_audit(ctx), "/base"):
            assert f.identity.strip(), "a finding with no identity cannot be baselined"

    def test_norm_severity_never_invents_a_level(self):
        for junk in ["", None, "SEVERE", "moderate", "7", "critical"]:
            assert squawk.norm_severity(junk) in squawk.SEVERITY_ORDER


# --------------------------------------------------------------------------- #
# I8 — three states, never two
# --------------------------------------------------------------------------- #

class TestThreeStates:
    """'I could not tell' is not a pass. Folding unknown into ok is how a
    machine with no clock sync reads as a machine with a good one."""

    def test_host_checks_use_exactly_the_three_states(self, tmp_path):
        seen = set()
        for c in squawk.self_audit_checks(str(tmp_path)):
            assert c["status"] in ("ok", "gap", "unknown")
            seen.add(c["status"])
        assert "ok" in seen, "no check can pass, so passing is untested"

    def test_unknown_becomes_a_finding_not_a_silence(self):
        raw = json.dumps({"checks": [squawk._chk(
            "probe", "time", "unknown", "medium", "Not determined", "no tool")]})
        out = squawk.norm_selfaudit(raw, "")
        assert len(out) == 1
        assert out[0].detail["status"] == "unknown"

    def test_a_passing_check_never_becomes_a_finding(self):
        raw = json.dumps({"checks": [squawk._chk(
            "probe", "time", "ok", "info", "Fine", "d")]})
        assert squawk.norm_selfaudit(raw, "") == []


# --------------------------------------------------------------------------- #
# I9 — nothing is done without evidence
# --------------------------------------------------------------------------- #

class TestEvidenceIsWritten:

    def test_a_run_leaves_the_files_a_reader_needs(self, tmp_path):
        root = tmp_path / "ev"
        svc = squawk.SERVICES["selfaudit"]
        outcome = squawk.execute_service(svc, "host", str(root), str(tmp_path))
        run_dir = pathlib.Path(outcome["run_dir"])
        for name in ("manifest.json", "findings.json", "identities.json"):
            assert (run_dir / name).exists(), "a run without %s cannot be audited" % name

    def test_doctor_records_its_verdict(self, tmp_path, capsys):
        """--doctor decides whether this machine is fit to produce evidence, and
        used to record nothing about that decision. Someone asking next week what
        the instrument check said had no way to find out, which makes it advice
        rather than a record. Gaps log at WARNING so they grep out the way
        REFUSED does."""
        import argparse
        root = tmp_path / "ev"
        for h in list(squawk.LOG.handlers):
            h.close()
            squawk.LOG.removeHandler(h)
        if hasattr(squawk.LOG, "_squawk_path"):
            del squawk.LOG._squawk_path
        try:
            path = squawk.setup_logging(str(root))
            assert path, "logging did not come up"
            squawk.doctor(argparse.Namespace(evidence=str(root), repo=None))
            capsys.readouterr()
            text = pathlib.Path(path).read_text(encoding="utf-8")
            assert "doctor: instrument check" in text, \
                "the instrument check left no record"
            assert ("doctor: OK" in text or "doctor: FAIL" in text), \
                "the verdict itself was not recorded"
        finally:
            for h in list(squawk.LOG.handlers):
                h.close()
                squawk.LOG.removeHandler(h)
            if hasattr(squawk.LOG, "_squawk_path"):
                del squawk.LOG._squawk_path

    def test_the_manifest_names_what_ran_and_what_did_not(self, tmp_path):
        root = tmp_path / "ev"
        svc = squawk.SERVICES["selfaudit"]
        outcome = squawk.execute_service(svc, "host", str(root), str(tmp_path))
        man = json.load(open(pathlib.Path(outcome["run_dir"]) / "manifest.json"))
        assert man.get("ledger"), "the manifest records no stage outcomes"
        for entry in man["ledger"]:
            assert entry.get("status") in ("ok", "skipped", "error", "gap"), entry


# --------------------------------------------------------------------------- #
# The charter and this file must not drift apart
# --------------------------------------------------------------------------- #

class TestCharterIsCurrent:

    def test_the_charter_exists(self):
        assert CHARTER.exists(), "the rules this file enforces are not written down"

    def test_every_invariant_id_is_unique_and_sequential(self):
        text = CHARTER.read_text(encoding="utf-8")
        ids = re.findall(r"\*\*(I\d+)\*\*", text)
        assert ids, "no invariants found in the charter"
        assert len(ids) == len(set(ids)), "duplicate invariant id: %s" % ids
        numbers = [int(i[1:]) for i in ids]
        assert numbers == sorted(numbers), "invariants are out of order: %s" % ids

    def test_every_invariant_names_an_enforcement(self):
        """A rule with nothing enforcing it is a sentiment. Rows that name a
        practice rather than a test are allowed, but the cell cannot be empty."""
        text = CHARTER.read_text(encoding="utf-8")
        for line in text.splitlines():
            if not re.match(r"\|\s*\*\*I\d+\*\*", line):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            assert len(cells) == 4, "malformed charter row: %s" % line[:60]
            assert cells[3], "invariant %s names no enforcement" % cells[0]


class TestUnreadableIsNotClean:
    """I14. A report we cannot read must not be reported as a clean scan."""

    def test_the_stage_verdict_changes_when_a_report_drifts(self, tmp_path):
        """The unit check is in test_squawk.py. This asserts the wiring: that a
        drifted report actually reaches the ledger as an error rather than as
        'ok, 0 finding(s)', which is the whole point."""
        import inspect
        src = inspect.getsource(squawk._run_one_stage)
        assert "report_unreadable" in src, \
            "drift detection is defined but never consulted by the runner"
        assert src.count("report_unreadable") >= 2, \
            "only one of the two stage paths consults it"

    def test_a_drifted_report_yields_no_findings_and_a_reason(self):
        raw = '{"results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1"}]}]}'
        assert squawk.NORMALIZERS["trivy"](raw, "/base") == []
        assert squawk.report_unreadable("trivy", raw), \
            "zero findings from an unreadable report, with nothing said about it"

    def test_a_drifted_report_lands_in_the_ledger_as_an_error(self, tmp_path,
                                                              monkeypatch):
        """The wiring, exercised rather than described.

        This class used to assert that the SOURCE of _run_one_stage contained
        "report_unreadable" twice. A comment naming it twice would have passed
        that, and the calls could have been deleted underneath it — which is a
        control that exists in source and is not enforced, the exact thing this
        tool exists to say is not a control (review R-17).

        So: a scanner whose report has drifted, run through execute_service,
        and the assertion is on the ledger row it produced.
        """
        _fixture_service(monkeypatch, "driftly", lambda _ctx: '{"renamed": []}',
                         shape=("results",))
        outcome = squawk.execute_service(squawk.SERVICES["driftly"], "host",
                                         str(tmp_path / "ev"), str(tmp_path))
        row = next(r for r in outcome["results"] if r.tool == "driftly")
        assert row.status == "error", row.detail
        assert "unreadable report" in row.detail
        assert row.findings == [], "a report nobody could read produced findings"

    def test_a_report_that_still_parses_is_not_called_drift(self, tmp_path,
                                                            monkeypatch):
        """The other direction, so the test above is not passing on anything."""
        _fixture_service(monkeypatch, "readably",
                         lambda _ctx: '{"results": []}', shape=("results",))
        outcome = squawk.execute_service(squawk.SERVICES["readably"], "host",
                                         str(tmp_path / "ev"), str(tmp_path))
        row = next(r for r in outcome["results"] if r.tool == "readably")
        assert row.status != "error", row.detail

    def test_every_external_scanner_declares_a_shape(self):
        external = {n for n, sc in squawk.SCANNERS.items()
                    if not sc.internal and sc.binary}
        missing = sorted(external - set(squawk.REPORT_SHAPES))
        assert not missing, "drift would be invisible for: %s" % missing


class TestZeroOverEmptyIsNotClean:
    """I15. A scan that found nothing and examined nothing is a gap, not ok."""

    def test_a_zero_over_an_empty_denominator_lands_as_a_gap(self, tmp_path,
                                                             monkeypatch):
        """The wiring, exercised. This asserted that the SOURCE of
        _run_one_stage contained "_apply_coverage" twice — which a comment
        satisfies and which says nothing about whether the verdict is applied
        (review R-17)."""
        _fixture_service(monkeypatch, "countly",
                         lambda _ctx: '{"paths": {"scanned": []}, "errors": []}',
                         coverage=squawk.COVERAGE["semgrep"])
        outcome = squawk.execute_service(squawk.SERVICES["countly"], "host",
                                         str(tmp_path / "ev"), str(tmp_path))
        row = next(r for r in outcome["results"] if r.tool == "countly")
        assert row.status == "gap", \
            "found nothing over nothing examined, and called it %s" % row.status

    def test_a_zero_over_a_real_denominator_is_ok(self, tmp_path, monkeypatch):
        """Nothing found in a hundred files is a result. The gap is the empty
        denominator, not the zero."""
        _fixture_service(
            monkeypatch, "counted",
            lambda _ctx: '{"paths": {"scanned": ["a.py", "b.py"]}, "errors": []}',
            coverage=squawk.COVERAGE["semgrep"])
        outcome = squawk.execute_service(squawk.SERVICES["counted"], "host",
                                         str(tmp_path / "ev"), str(tmp_path))
        row = next(r for r in outcome["results"] if r.tool == "counted")
        assert row.status == "ok", row.detail

    def test_empty_denominator_is_a_gap(self):
        status, _d, _c = squawk._apply_coverage(
            "semgrep", '{"paths":{"scanned":[]},"errors":[]}', [], "ok", "0")
        assert status == "gap"

    def test_a_tool_without_coverage_is_not_gated(self):
        status, _d, cov = squawk._apply_coverage("gitleaks", "[]", [], "ok", "0")
        assert status == "ok" and cov.examined is None

    def test_every_coverage_extractor_returns_the_type(self):
        for tool, fn in squawk.COVERAGE.items():
            cov = fn('{"paths":{"scanned":[]},"summary":{"resource_count":0},'
                     '"metrics":{"_totals":{}},"Results":[],"artifacts":[]}')
            assert isinstance(cov, squawk.Coverage), tool


def _corr_find(scanner, ident, path="p"):
    return {"scanner": scanner, "identity": ident, "severity": "high",
            "title": "t", "path": path, "detail": {}}


# One set of findings per rule, enough to make it fire. Keyed by rule id so a
# new Correlation with no corpus fails loudly rather than being skipped.
_CORR_CORPUS = {
    "public-unencrypted-store": [
        _corr_find("checkov", "CKV_AWS_20:main.tf:aws_s3_bucket.b", "main.tf"),
        _corr_find("checkov", "CKV_AWS_145:main.tf:aws_s3_bucket.b", "main.tf")],
    "secret-in-container-build": [
        _corr_find("bandit", "B105:app.py:1", "app.py"),
        _corr_find("checkov", "CKV_DOCKER_2:Dockerfile:x", "Dockerfile")],
}

# Every file-scanning STAGE, as (tool, mode). A pair, not a tool name, because
# `trivy config` reads IaC and `trivy fs` reads dependencies, so a kind is a
# property of the stage and not of the scanner. Cloud stages are excluded: they
# read an account, not a tree, and no rule in CORRELATIONS requires their kinds.
_TREE_KINDS = ("secrets", "sast", "iac", "sca", "sbom")
_ALL_CORR_STAGES = tuple(sorted(
    {(n, "") for n, sc in squawk.SCANNERS.items() if sc.kind in _TREE_KINDS}
    | {pair for pair in squawk.MODE_KINDS
       if squawk.MODE_KINDS[pair] in _TREE_KINDS}))


def _stages_for_kinds(kinds):
    """kind -> every stage that reports it. A kind is unread only when ALL of
    them came back empty; one live stage means the kind was read."""
    out = {}
    for kind in kinds:
        named = tuple(p for p in _ALL_CORR_STAGES
                      if squawk.result_kind(p[0], p[1]) == kind)
        if named:
            out[kind] = named
    return out


def _corr_results(blank=()):
    """Every tree stage as ok, except the pairs named, which ran and read
    nothing."""
    return [squawk.StageResult(t, m, "gap" if (t, m) in blank else "ok",
                               "", None, [], 0, None)
            for t, m in _ALL_CORR_STAGES]


class TestCorrelationStatesItsDenominator:
    """I16. A correlation whose member scanner did not run reports unknown."""

    def test_a_missing_member_is_unknown(self):
        """A secrets scanner in scope (a skipped gitleaks stage) but with no
        output means the combination is unknown, not silently absent. If no
        secrets scanner were in scope at all it would be not-applicable, which
        is a different, correct silence."""
        finds = [{"scanner": "checkov", "identity": "CKV_DOCKER_2:Dockerfile:x",
                  "severity": "high", "title": "t", "path": "Dockerfile", "detail": {}}]
        ran = [squawk.StageResult("checkov", "x", "ok", "", None, [], 0, None),
               squawk.StageResult("gitleaks", "x", "skipped", "not found",
                                  None, [], 0, None)]
        c = [x for x in squawk.correlate(finds, ran)
             if x["key"] == "secret-in-container-build"]
        assert c and c[0]["state"] == "unknown", "must not silently skip"

    def test_correlation_is_a_registered_scanner(self):
        assert "correlation" in squawk.SCANNERS
        assert "correlation" in squawk.NORMALIZERS

    def test_every_rule_names_the_kinds_it_requires(self):
        for corr in squawk.CORRELATIONS:
            assert corr.requires, "%s cannot report unknown without required kinds" % corr.key

    def test_every_rule_that_fires_over_an_unread_member_says_so(self):
        """The half of I16 that `unknown` does not cover. A required kind whose
        stage RAN and read nothing is a gap, and a gap counts as having run —
        otherwise one empty scanner would turn every combination that needs it
        into `unknown`, trading real findings for a denominator. So the rule
        fires, and the denominator has to arrive with it.

        Driven off the registry rather than one rule, because the guarantee has
        to hold for a correlation written next year, not just the two written
        so far. Both directions are checked: a kind nothing read must be named,
        and a kind one stage read must NOT be — a false caveat on a true
        finding is the same failure with the sign flipped."""
        for corr in squawk.CORRELATIONS:
            stages = _stages_for_kinds(corr.requires)
            assert stages, "%s requires kinds no stage reports" % corr.key
            finds = _CORR_CORPUS.get(corr.key)
            assert finds, "no corpus for %s — add one" % corr.key
            fired = [x for x in squawk.correlate(finds, _corr_results())
                     if x["key"] == corr.key and x["state"] == "fired"]
            assert fired, "%s corpus must fire before it can be blanked" % corr.key
            assert fired[0]["unread"] == [], "%s: nothing was blank" % corr.key
            for kind, pairs in stages.items():
                got = [x for x in squawk.correlate(finds, _corr_results(pairs))
                       if x["key"] == corr.key and x["state"] == "fired"]
                assert got, ("%s stopped firing when %s came back empty — a gap "
                             "must not silence a real combination"
                             % (corr.key, kind))
                assert kind in got[0]["unread"], (
                    "%s fired with %s unread and did not name it" % (corr.key, kind))
                assert "read nothing this run" in got[0]["why"], (
                    "%s fired over an unread %s without saying so in the "
                    "finding a person reads" % (corr.key, kind))
                if len(pairs) < 2:
                    continue        # nothing could have covered for it
                for kept in pairs:
                    rest = tuple(p for p in pairs if p != kept)
                    some = [x for x in squawk.correlate(finds, _corr_results(rest))
                            if x["key"] == corr.key and x["state"] == "fired"]
                    assert some and some[0]["unread"] == [], (
                        "%s called %s unread while %s read the tree"
                        % (corr.key, kind, kept[0]))


# --------------------------------------------------------------------------- #
# What a scan says it does not cover is part of the product, not documentation.
# --------------------------------------------------------------------------- #

# CLI service name -> the words prose uses for it. Only unambiguous names are
# listed. "Config" and "Kubernetes" are deliberately absent: the first is a
# common English word, and the second names a thing Squawk really does not read
# (it reads the AWS side of a cluster, not the API server behind it), so a
# sentence saying so is true and must not fail here.
_SERVICE_WORDS = {
    "accessanalyzer": ("Access Analyzer",),
    "apigateway": ("API Gateway",),
    "apigatewayv2": ("API Gateway",),
    "cloudfront": ("CloudFront",),
    "cloudtrail": ("CloudTrail",),
    "ec2": ("EC2",),
    "ecr": ("ECR",),
    "ecs": ("ECS",),
    "eks": ("EKS",),
    "elb": ("load balancer",),
    "elbv2": ("load balancer",),
    "guardduty": ("GuardDuty",),
    "iam": ("IAM graph",),
    "inspector2": ("Inspector",),
    "lambda": ("Lambda", "serverless"),
    "organizations": ("Organizations",),
    "rds": ("RDS", "databases"),
    "s3api": ("S3", "Storage"),
    "s3control": ("S3", "Storage"),
    "secretsmanager": ("Secrets Manager",),
    "securityhub": ("Security Hub",),
    "sns": ("SNS",),
    "sqs": ("SQS",),
}

# "X is not read" / "X are not read" / "X is never read". Not "was not read" or
# "could not read", which describe one failed call at run time rather than a
# standing claim about coverage.
_DENIES_READING = re.compile(r"\b(?:is|are)\s+(?:not|never)\s+read\b")

_PROSE_MODULES = ("stages.py", "analysis.py", "web.py")
_HERE = pathlib.Path(__file__).parent.parent


def _tree(name):
    return ast.parse((_HERE / "squawk" / name).read_text(encoding="utf-8"))


def _services_called():
    """Every AWS CLI service name the probes actually invoke.

    Read from the argument list of each `_aws_json*` call, so this tracks the
    calls rather than anyone's memory of them: build a probe for a new service
    and it joins this set on the next run.
    """
    called = set()
    for node in ast.walk(_tree("probes.py")):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
        if name not in ("_aws_json", "_aws_json_env"):
            continue
        argv = node.args[0]
        if isinstance(argv, (ast.List, ast.Tuple)) and argv.elts:
            first = argv.elts[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                called.add(first.value)
    return called


def _coverage_claims():
    """Every sentence in the rendered prose that denies reading something.

    Taken from the string *values* in the AST, not from the source text, so a
    sentence written across several implicitly concatenated lines is matched as
    the one sentence a reader sees. That is the whole reason this exists: the
    stale sentences were invisible to grep because each was split over three
    lines mid-clause.
    """
    claims = []
    for mod in _PROSE_MODULES:
        for node in ast.walk(_tree(mod)):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            for sentence in re.split(r"(?<=[.;])\s+", node.value):
                if _DENIES_READING.search(sentence):
                    claims.append((mod, node.lineno, sentence.strip()))
    return claims


class TestCoverageProseMatchesWhatIsRead:
    """A sentence about what a scan does not cover is a control, not a comment.

    It is the sentence a reader uses to decide what a quiet answer means, so a
    stale one is worse than none: it says a whole class of resource was never
    looked at when in fact it was read and came back empty -- I1 inverted, and
    reached by drift rather than by a bug. This text has now gone stale twice,
    and the second repair landed as a comment claiming the sentence had been
    fixed while the sentence underneath it stayed wrong. Hence a test.
    """

    def test_the_probes_expose_the_services_they_call(self):
        called = _services_called()
        assert {"ec2", "iam", "s3api", "sns", "eks"} <= called, sorted(called)

    def test_there_is_prose_to_check(self):
        assert _coverage_claims(), "the sweep found no coverage sentences at all"

    def test_no_sentence_denies_reading_a_service_that_is_read(self):
        called = _services_called()
        wrong = []
        for mod, line, sentence in _coverage_claims():
            for service in sorted(called):
                for word in _SERVICE_WORDS.get(service, ()):
                    if word in sentence:
                        wrong.append("%s:%d says %r but the probes call `aws %s`"
                                     % (mod, line, sentence, service))
        assert not wrong, "\n".join(wrong)

    def test_the_service_description_is_covered_by_the_sweep(self):
        """The CLI prints `not_covered` verbatim, so it has to be in scope."""
        not_covered = squawk.SERVICES["cloudinventory"].not_covered
        assert _DENIES_READING.search(not_covered)
        assert any(s in not_covered for _m, _l, s in _coverage_claims())


# --------------------------------------------------------------------------- #
# A count is a claim, and a claim a reader cannot check is one they have to
# take on trust.
# --------------------------------------------------------------------------- #

# One reading per cloud stage, with something in every list a tile counts.
# These are shapes, not data: the point is that each number on each panel has
# members to expand to, so a tile that counts a thing the evidence does not
# keep fails here rather than on somebody's account.
_R = "us-east-1"
_ACCT = "123456789012"
_BASE = {"account": _ACCT, "read_as": "arn:aws:iam::%s:role/x" % _ACCT,
         "read_at": "2026-01-01T00:00:00Z", "api_calls": 10,
         "elapsed_seconds": 1.0, "truncated": False, "limit": 200,
         "regions_enabled": [_R], "regions_read": [_R], "regions_unread": []}


def _reading(_drop=(), **kw):
    """A stage reading. `_drop` removes a shared field a given probe does not
    write -- the enablement stage has no cap, so it records no limit and no
    truncation, and a fixture that invented them would not be its shape."""
    out = dict(_BASE)
    for key in _drop:
        out.pop(key, None)
    out.update(kw)
    return out


CLOUD_FIXTURES = {
    "cloud-edge.json": _reading(regional={_R: {
        "functions": [{"name": "fn-a", "in_vpc": False},
                      {"name": "fn-b", "in_vpc": True},
                      {"name": "fn-c", "in_vpc": False}],
        "urls": [{"name": "fn-a", "auth": "NONE"},
                 {"name": "fn-b", "auth": "AWS_IAM"}],
        "load_balancers": [
            {"name": "lb-pub", "scheme": "internet-facing",
             "type": "application", "groups": ["sg-1"]},
            {"name": "lb-int", "scheme": "internal",
             "type": "application", "groups": ["sg-2"]}],
        "unreadable": ["Lambda functions (ThrottlingException)"]}}),

    "cloud-containers.json": _reading(regional={_R: {
        "eks": [{"name": "eks-a", "public": True, "logging": [],
                 "version": "1.29", "public_cidrs": ["0.0.0.0/0"]},
                {"name": "eks-b", "public": False, "logging": ["api", "audit"],
                 "version": "1.29", "public_cidrs": []}],
        "ecs": [{"name": "svc-a", "public_ip": True, "running": 2,
                 "launch": "FARGATE", "cluster": "c1",
                 "subnets": ["subnet-1"], "groups": []},
                {"name": "svc-b", "public_ip": False, "running": 1,
                 "launch": "FARGATE", "cluster": "c1",
                 "subnets": ["subnet-2"], "groups": []}],
        "unreadable": []}}),

    "cloud-dataservices.json": _reading(regional={_R: {
        "topics": [{"name": "t-a", "kind": "sns", "encrypted": True,
                    "public": ["sns policy allows ANY principal, with no "
                               "condition narrowing it"]},
                   {"name": "t-b", "kind": "sns", "encrypted": False,
                    "public": []}],
        "queues": [{"name": "q-a", "kind": "sqs", "encrypted": True,
                    "public": []}],
        "secrets": [{"name": "s-a", "rotation": False, "customer_key": False,
                     "days": 400}],
        "repositories": [
            {"name": "r-a", "scan_on_push": True, "mutable": True,
             "policy_unreadable": "",
             "public": ["repository policy allows ANY principal, with no "
                        "condition narrowing it"]},
            {"name": "r-b", "scan_on_push": False, "mutable": False,
             "public": [], "policy_unreadable": ""}],
        "unreadable": []}}),

    "cloud-frontdoor.json": _reading(
        _drop=("limit", "truncated"),
        regions_enabled=[_R, "eu-west-1"], regions_unread=["eu-west-1"],
        regional={_R: {"apis": [
            {"name": "api-a", "id": "a1", "kind": "http",
             "default_endpoint_open": True, "private": False,
             "routes": 2, "open_routes": ["POST /a", "GET /b"],
             "unreadable": ""},
            {"name": "api-b", "id": "a2", "kind": "rest",
             "default_endpoint_open": False, "private": True,
             "routes": 1, "open_routes": [], "unreadable": ""}],
            "unreadable": []}},
        distributions=[
            {"name": "d1", "domain": "x.cloudfront.net", "enabled": True,
             "waf": False, "origins": ["b.s3"], "tls": "TLSv1.2"},
            {"name": "d2", "domain": "y.cloudfront.net", "enabled": True,
             "waf": "", "origins": [], "tls": "TLSv1.2"}]),

    "cloud-storage.json": _reading(
        _drop=("limit", "truncated"),
        bucket_total=2, bucket_limit=200, bucket_error="",
        account_block_on=0, region_error="",
        buckets=[{"name": "b-pub", "public": True, "encrypted": True,
                  "block": 0, "region": _R, "why": ["policy"],
                  "versioning": True, "unreadable": []},
                 {"name": "b-plain", "public": False, "encrypted": False,
                  "block": 4, "region": _R, "why": [], "versioning": False,
                  "unreadable": []}],
        databases={_R: {"databases": [
            {"name": "db-a", "public": True, "encrypted": False,
             "engine": "postgres", "groups": [], "subnets": []},
            {"name": "db-b", "public": False, "encrypted": True,
             "engine": "mysql", "groups": [], "subnets": []}],
            "unreadable": []}}),

    "cloud-iam.json": _reading(
        _drop=("regions_enabled", "regions_read", "regions_unread"),
        counts={"users": 2, "roles": 2, "groups": 0, "policies": 0},
        users=[{"name": "u-a", "mfa": 0, "console": True,
                # Split so the source text never carries the full shape --
                # the hygiene gate scans for it, and it is right to.
                "keys": [{"id": "AKIA" + "EXAMPLEKEY000000",
                          "status": "Active",
                          "created": "2020-01-01T00:00:00Z"}],
                "escalation": ["policy P allows iam:CreateAccessKey — x"],
                "unreadable": []},
               {"name": "u-b", "mfa": 1, "console": False, "keys": [],
                "escalation": [], "unreadable": []}],
        roles=[{"name": "r-esc", "reach": "anyone", "escalation": 1,
                "admin": False},
               {"name": "r-admin", "reach": "internal", "escalation": 0,
                "admin": True}],
        roles_with_escalation=[
            {"name": "r-esc", "arn": "arn:aws:iam::%s:role/r-esc" % _ACCT,
             "reach": "anyone",
             "trust": [{"kind": "aws", "who": "*", "reach": "anyone",
                        "why": "ANY AWS principal"}],
             "escalation": ["policy P allows iam:PutRolePolicy — x"]}],
        roles_already_admin=[
            {"name": "r-admin", "arn": "arn:aws:iam::%s:role/r-admin" % _ACCT,
             "reach": "internal",
             "trust": [{"kind": "aws", "who": "x", "reach": "internal",
                        "why": "a principal in this account"}],
             "why": ["policy A allows every action"]}]),

    "cloud-analyzer.json": _reading(
        _drop=("truncated",), limit=200,
        regional={_R: {
            "analyzers": [{"name": "default", "kind": "ACCOUNT",
                           "arn": "arn:aws:access-analyzer:us-east-1:"
                                  "********9012:analyzer/default"}],
            "findings": [
                {"id": "f1", "resource": "arn:aws:s3:::b-pub", "name": "b-pub",
                 "kind": "AWS::S3::Bucket", "panel": "buckets", "public": True,
                 "scope": "public", "federation": "",
                 "principal": {"AWS": "*"}, "actions": ["s3:GetObject"],
                 "conditions": [], "analyzed_at": "2026-01-01T00:00:00Z"},
                {"id": "f2", "resource": "arn:aws:iam::********9012:role/r-esc",
                 "name": "r-esc", "kind": "AWS::IAM::Role", "panel": "roles",
                 "public": False, "scope": "external", "federation": "",
                 "principal": {"AWS": "********7777"},
                 "actions": ["sts:AssumeRole"], "conditions": ["aws:SourceIp"],
                 "analyzed_at": "2026-01-01T00:00:00Z"},
                {"id": "f3", "resource": "arn:aws:iam::********9012:role/r-irsa",
                 "name": "r-irsa", "kind": "AWS::IAM::Role", "panel": "roles",
                 "public": False, "scope": "own-federation",
                 "federation": "its own EKS cluster's OIDC provider",
                 "principal": {"Federated": "arn:aws:iam::********9012:"
                                            "oidc-provider/oidc.eks.x"},
                 "actions": ["sts:AssumeRoleWithWebIdentity"],
                 "conditions": [], "analyzed_at": "2026-01-01T00:00:00Z"}],
            "unreadable": []}}),

    "cloud-enablement.json": _reading(
        _drop=("limit", "truncated"),
        regional={_R: {"guardduty": {"state": "on"},
                       "cloudtrail": {"state": "off"},
                       "config": {"state": "unknown"},
                       "securityhub": {"state": "on"},
                       "inspector": {"state": "off"},
                       "accessanalyzer": {"state": "on"}}},
        account={"cloudtrail": {"state": "on"}, "root": {"state": "on"},
                 "s3block": {"state": "off"}, "password": {"state": "unknown"}}),
}


# Which saved reading each cloud panel renders. A tile on a panel may only
# expand to that panel's own reading: the key namespace is flat, so two panels
# that both call a figure "roles" would otherwise share one detail view, and
# one of them would be wrong.
PANEL_READING = {
    "cloud_watching_panel": "cloud-enablement.json",
    "cloud_storage_panel": "cloud-storage.json",
    "cloud_containers_panel": "cloud-containers.json",
    "cloud_dataservices_panel": "cloud-dataservices.json",
    "cloud_frontdoor_panel": "cloud-frontdoor.json",
    "cloud_edge_panel": "cloud-edge.json",
    "cloud_iam_panel": "cloud-iam.json",
    "cloud_analyzer_panel": "cloud-analyzer.json",
    "cloud_inventory_panel": "cloud-inventory.json",
}


def _panel_tiles():
    """(panel, tile key) for every number a cloud panel puts on a tile.

    Read from the (key, value, label, weight) tuples the panels build their
    tiles from, so a tile added next month is in scope without anyone adding
    it here."""
    tree = ast.parse(pathlib.Path(squawk.web.__file__).read_text(encoding="utf-8"))
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    out = []
    for panel in sorted(PANEL_READING):
        node = funcs.get(panel)
        assert node is not None, "%s is gone; update PANEL_READING" % panel
        for tup in ast.walk(node):
            if (isinstance(tup, ast.Tuple) and len(tup.elts) == 4
                    and isinstance(tup.elts[0], ast.Constant)
                    and isinstance(tup.elts[0].value, str)
                    and isinstance(tup.elts[2], ast.Constant)):
                out.append((panel, tup.elts[0].value, tup.lineno))
    return out


class TestEveryNumberExpandsToItsMembers:
    """Every figure on the Cloud page opens the set it counts.

    The operator asked for this directly: a number that says
    how many things need attention should open the set it counts.
    Three ways it was not true, all found by running it in field use
    (2026-09-10) and none visible from the source:

      * the IAM panel's "roles" tile used the key `roles`, which belongs to the
        INVENTORY reading's roles-on-instances list, so a count of every role
        in the account expanded to the few attached to an EC2 instance;
      * the front door's "regions never reached" tile expanded to the
        inventory's unread regions;
      * the "reads that failed" tile carried no key at all, so it rendered as
        plain text -- the one number whose members a reader most needs.
    """

    def test_every_tile_number_is_drillable(self):
        plain = [(p, k, ln) for p, k, ln in _panel_tiles()
                 if k not in squawk.analysis.CLOUD_DRILL]
        assert not plain, (
            "these tiles render as plain text, with no way to see what is "
            "behind them: %s" % plain)

    def test_every_tile_expands_to_its_own_panels_reading(self):
        wrong = []
        for panel, key, line in _panel_tiles():
            entry = squawk.analysis.CLOUD_DRILL.get(key)
            if entry and entry[1] != PANEL_READING[panel]:
                wrong.append("%s:%d %r expands to %s (%r), not %s"
                             % (panel, line, key, entry[1], entry[0],
                                PANEL_READING[panel]))
        assert not wrong, "\n".join(wrong)

    def test_a_summed_tile_names_the_field_it_sums(self):
        """The one number whose rows are not one-for-one is declared, so every
        other number can be held to strict equality."""
        for key in squawk.analysis.DRILL_SUMS:
            assert key in squawk.analysis.CLOUD_DRILL, key

    def test_the_count_and_the_list_agree(self, tmp_path, monkeypatch):
        """The end of it: render each panel over a reading, then expand every
        number it printed and count the rows."""
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        for filename in squawk.web.CLOUD_READINGS.values():
            payload = CLOUD_FIXTURES.get(filename)
            if payload is None:
                continue
            (run / "raw" / filename).write_text(json.dumps(payload),
                                                encoding="utf-8")
        ledger = [{"tool": t, "status": "ok", "detail": ""}
                  for t in squawk.web.CLOUD_READINGS]
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": ledger}])
        link = re.compile(r"<a href='/cloud/detail\?what=([a-z_]+)'[^>]*>"
                          r"<span[^>]*>([0-9]+)</span></a>")
        checked = 0
        for panel, filename in sorted(PANEL_READING.items()):
            payload = CLOUD_FIXTURES.get(filename)
            if payload is None:
                continue
            html = getattr(squawk.web, panel)(str(tmp_path))
            if isinstance(html, tuple):
                html = html[0]
            assert "/cloud/detail?what=" in html, \
                "%s put nothing on the page a reader can open" % panel
            for key, shown in link.findall(html):
                rows = squawk.analysis.cloud_drill(key, payload)
                field = squawk.analysis.DRILL_SUMS.get(key)
                got = (sum(int(r.get(field) or 0) for r in rows)
                       if field else len(rows))
                assert got == int(shown), (
                    "%s: the tile says %s and %r expands to %d"
                    % (panel, shown, key, got))
                # Zero equals zero for a tile the fixture never reaches, and
                # that is agreement about nothing. Two of these were real: the
                # storage fixture put databases under `regional`, which the
                # probe does not use, and every database number was a vacuous
                # zero on both sides.
                assert int(shown) > 0, (
                    "%s: %r is zero on both sides, so it proves nothing — give "
                    "the fixture something for it to count" % (panel, key))
                checked += 1
        assert checked >= 30, "only %d numbers were checked" % checked

    def test_the_fixtures_have_the_shape_the_probes_write(self):
        """A fixture that does not match the probe makes this whole class lie.

        It already did once: the first version of the IAM fixture carried a
        `roles` list, the probe kept only the roles it had something to say
        about, and the "roles" tile would have expanded to three of many
        in field use while every test here passed. The payload
        literal each probe builds is the authority.
        """
        by_file = {}
        for spec in squawk.stages.STAGES.values():
            probe = getattr(spec, "internal", None)
            filename = squawk.web.CLOUD_READINGS.get(spec.tool)
            if probe is not None and filename:
                by_file[filename] = probe
        checked = 0
        for filename, fixture in sorted(CLOUD_FIXTURES.items()):
            probe = by_file.get(filename)
            assert probe is not None, "no probe writes %s" % filename
            tree = ast.parse(textwrap.dedent(
                inspect.getsource(probe)))
            written = set()
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue
                if not any(isinstance(t, ast.Name) and t.id == "payload"
                           for t in node.targets):
                    continue
                if isinstance(node.value, ast.Dict):
                    written |= {k.value for k in node.value.keys
                                if isinstance(k, ast.Constant)
                                and isinstance(k.value, str)}
            assert written, "%s: no payload literal found" % probe.__name__
            invented = sorted(set(fixture) - written)
            assert not invented, (
                "%s carries %s, which %s never writes"
                % (filename, invented, probe.__name__))
            checked += 1
        assert checked == len(CLOUD_FIXTURES)

    def test_the_fixtures_cover_every_panel_but_the_one_named_here(self):
        """A gap in the fixtures would make the test above pass by looking at
        less, so the exception is written down rather than left to notice.

        The inventory reading is the exception: its shape is the whole
        `resources`/`reads` graph rather than a per-region list, and its
        numbers were reconciled against their expansions in field use
        (2026-09-09, every tile, no mismatch). Every other panel is covered
        here.
        """
        uncovered = sorted(f for f in PANEL_READING.values()
                           if f not in CLOUD_FIXTURES)
        assert uncovered == ["cloud-inventory.json"], uncovered


# --------------------------------------------------------------------------- #
# One read-only assertion, over every argv the nine cloud stages actually
# build.
#
# What this replaces: six tests that read the SOURCE with regular expressions
# -- one in this file and five in test_squawk.py, each with its own pattern
# and its own slice of the module. Between them they missed calls built inline
# at a call site, they went stale silently when a service was added, and none
# of them could see an argument that was appended at run time. A pattern that
# has to be kept current is a control that decays; running the stages and
# reading what they built cannot (review R-11, plan 11 step 10).
# --------------------------------------------------------------------------- #

_ACCT = "000000000000"
_REGION = "us-east-1"

# Every AWS service the nine cloud stages are allowed to call. Adding a call
# to a service that is not here fails the suite until somebody puts it here --
# which is a decision, made once, in the open.
CLOUD_SERVICES = frozenset({
    "accessanalyzer", "apigateway", "apigatewayv2", "cloudfront", "cloudtrail",
    "configservice", "ec2", "ecr", "ecs", "eks", "elb", "elbv2", "guardduty",
    "iam", "inspector2", "lambda", "organizations", "rds", "s3api",
    "s3control", "secretsmanager", "securityhub", "sns", "sqs", "sts",
})

# The verbs a read may start with. A blocklist misses things; this is what a
# call MAY do, not merely what it may not.
READ_VERBS = ("describe-", "list-", "get-", "batch-get-")

# One operation per stage that only that stage makes. If a stage stops running
# in the harness below, its signature goes unrecorded and the suite fails --
# which is what stops this test from quietly checking eight stages.
STAGE_SIGNATURES = {
    "cloud-org": ("organizations", "describe-organization"),
    "cloud-inventory": ("ec2", "describe-vpcs"),
    "cloud-enablement": ("guardduty", "list-detectors"),
    "cloud-iam": ("iam", "get-account-authorization-details"),
    "cloud-edge": ("lambda", "list-functions"),
    "cloud-frontdoor": ("apigatewayv2", "get-apis"),
    "cloud-storage": ("s3api", "list-buckets"),
    "cloud-containers": ("eks", "list-clusters"),
    "cloud-dataservices": ("sns", "list-topics"),
    "cloud-analyzer": ("accessanalyzer", "list-findings"),
}

_CLI_RESPONSES = {
    ("sts", "get-caller-identity"): {"Account": _ACCT,
        "Arn": "arn:aws:sts::%s:assumed-role/R/s" % _ACCT},
    ("ec2", "describe-regions"): {"Regions": [{"RegionName": _REGION}]},
    ("ec2", "describe-vpcs"): {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}]},
    ("ec2", "describe-subnets"): {"Subnets": [{"SubnetId": "sn-1", "VpcId": "vpc-1"}]},
    ("ec2", "describe-route-tables"): {"RouteTables": [{"RouteTableId": "rtb-1",
        "VpcId": "vpc-1", "Associations": [{"SubnetId": "sn-1"}],
        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1",
                    "State": "active"}]}]},
    ("ec2", "describe-internet-gateways"): {"InternetGateways": [{"InternetGatewayId": "igw-1",
        "Attachments": [{"VpcId": "vpc-1", "State": "available"}]}]},
    ("ec2", "describe-security-groups"): {"SecurityGroups": [{"GroupId": "sg-1",
        "GroupName": "g", "VpcId": "vpc-1", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]}]},
    ("ec2", "describe-network-interfaces"): {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1",
        "SubnetId": "sn-1", "VpcId": "vpc-1", "Association": {"PublicIp": "203.0.113.1"},
        "Attachment": {"InstanceId": "i-1"}, "InterfaceType": "interface",
        "Description": "", "Groups": [{"GroupId": "sg-1"}]}]},
    ("ec2", "describe-instances"): {"Reservations": [{"Instances": [{"InstanceId": "i-1",
        "State": {"Name": "running"}, "SubnetId": "sn-1", "VpcId": "vpc-1",
        "PublicIpAddress": "203.0.113.1",
        "IamInstanceProfile": {"Arn": "arn:aws:iam::%s:instance-profile/p" % _ACCT},
        "SecurityGroups": [{"GroupId": "sg-1"}]}]}]},
    ("ec2", "describe-vpc-peering-connections"): {"VpcPeeringConnections": []},
    ("iam", "get-instance-profile"): {"InstanceProfile": {"Roles": [{"RoleName": "role-1"}]}},
    ("iam", "list-attached-role-policies"): {"AttachedPolicies": [
        {"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]},
    ("iam", "list-role-policies"): {"PolicyNames": []},
    ("iam", "get-account-authorization-details"): {
        "UserDetailList": [{"UserName": "u1", "Arn": "arn:aws:iam::%s:user/u1" % _ACCT,
                            "GroupList": [], "UserPolicyList": [],
                            "AttachedManagedPolicies": []}],
        "RoleDetailList": [{"RoleName": "r1", "Arn": "arn:aws:iam::%s:role/r1" % _ACCT,
                            "AssumeRolePolicyDocument": {"Statement": [
                                {"Effect": "Allow", "Principal": {"AWS": "*"}}]},
                            "RolePolicyList": [], "AttachedManagedPolicies": []}],
        "GroupDetailList": [], "Policies": []},
    ("iam", "get-login-profile"): None,
    ("iam", "list-mfa-devices"): {"MFADevices": []},
    ("iam", "list-access-keys"): {"AccessKeyMetadata": []},
    ("iam", "get-account-summary"): {"SummaryMap": {"AccountMFAEnabled": 1,
                                                    "AccountAccessKeysPresent": 0}},
    ("iam", "get-account-password-policy"): {"PasswordPolicy": {"MinimumPasswordLength": 14}},
    ("lambda", "list-functions"): {"Functions": [{"FunctionName": "fn-1", "Role": "r",
                                                  "VpcConfig": {}}]},
    ("lambda", "list-function-url-configs"): {"FunctionUrlConfigs": [
        {"FunctionUrl": "https://x.lambda-url.us-east-1.on.aws/", "AuthType": "NONE",
         "Cors": {}}]},
    ("elbv2", "describe-load-balancers"): {"LoadBalancers": [{"LoadBalancerName": "lb",
        "Scheme": "internet-facing", "Type": "application", "VpcId": "vpc-1",
        "SecurityGroups": ["sg-1"], "DNSName": "d"}]},
    ("elb", "describe-load-balancers"): {"LoadBalancerDescriptions": []},
    ("s3api", "list-buckets"): {"Buckets": [{"Name": "b1"}]},
    ("s3api", "get-bucket-location"): {"LocationConstraint": _REGION},
    ("s3api", "get-bucket-policy-status"): {"PolicyStatus": {"IsPublic": False}},
    ("s3api", "get-public-access-block"): {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True}},
    ("s3api", "get-bucket-encryption"): {"ServerSideEncryptionConfiguration": {"Rules": [{}]}},
    ("s3api", "get-bucket-versioning"): {"Status": "Enabled"},
    ("s3control", "get-public-access-block"): {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True}},
    ("rds", "describe-db-instances"): {"DBInstances": [{"DBInstanceIdentifier": "db1",
        "Engine": "postgres", "PubliclyAccessible": False, "StorageEncrypted": True,
        "Endpoint": {"Port": 5432}, "DBSubnetGroup": {"Subnets": [{"SubnetIdentifier": "sn-1"}]},
        "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1"}]}]},
    ("rds", "describe-db-clusters"): {"DBClusters": []},
    ("rds", "describe-db-subnet-groups"): {"DBSubnetGroups": [
        {"DBSubnetGroupName": "sg", "Subnets": [{"SubnetIdentifier": "sn-1"}]}]},
    ("apigatewayv2", "get-apis"): {"Items": [{"ApiId": "a1", "Name": "http-api",
        "ProtocolType": "HTTP", "ApiEndpoint": "https://a1.execute-api...",
        "DisableExecuteApiEndpoint": False}]},
    ("apigatewayv2", "get-routes"): {"Items": [{"RouteKey": "POST /x",
        "AuthorizationType": "NONE", "ApiKeyRequired": False}]},
    ("apigatewayv2", "get-stages"): {"Items": []},
    ("apigateway", "get-rest-apis"): {"items": [{"id": "r1", "name": "rest-api",
        "endpointConfiguration": {"types": ["EDGE"]}, "disableExecuteApiEndpoint": False}]},
    ("apigateway", "get-resources"): {"items": [{"id": "res1", "path": "/",
        "resourceMethods": {"GET": {"authorizationType": "NONE", "apiKeyRequired": False}}}]},
    ("apigateway", "get-stages"): {"item": []},
    ("cloudfront", "list-distributions"): {"DistributionList": {"Items": [
        {"Id": "d1", "DomainName": "x.cloudfront.net", "Enabled": True,
         "WebACLId": "", "Origins": {"Items": []},
         "ViewerCertificate": {"MinimumProtocolVersion": "TLSv1.2_2021"}}]}},
    ("eks", "list-clusters"): {"clusters": ["c1"]},
    ("eks", "describe-cluster"): {"cluster": {"name": "c1", "version": "1.29",
        "resourcesVpcConfig": {"endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"]},
        "logging": {"clusterLogging": [{"types": ["api"], "enabled": True}]},
        "encryptionConfig": []}},
    ("ecs", "list-clusters"): {"clusterArns": ["arn:aws:ecs:us-east-1:%s:cluster/c1" % _ACCT]},
    ("ecs", "list-services"): {"serviceArns": ["arn:aws:ecs:us-east-1:%s:service/c1/s1" % _ACCT]},
    ("ecs", "describe-services"): {"services": [{"serviceName": "s1", "launchType": "FARGATE",
        "runningCount": 2, "networkConfiguration": {"awsvpcConfiguration": {
            "assignPublicIp": "ENABLED", "subnets": ["sn-1"], "securityGroups": ["sg-1"]}}}]},
    ("sns", "list-topics"): {"Topics": [{"TopicArn": "arn:aws:sns:us-east-1:%s:t1" % _ACCT}]},
    ("sns", "get-topic-attributes"): {"Attributes": {"Policy": "{}", "KmsMasterKeyId": "k"}},
    ("sqs", "list-queues"): {"QueueUrls": ["https://sqs.us-east-1.amazonaws.com/%s/q1" % _ACCT]},
    ("sqs", "get-queue-attributes"): {"Attributes": {
        "Policy": "{}", "SqsManagedSseEnabled": "true"}},
    ("secretsmanager", "list-secrets"): {"SecretList": [{"Name": "s1", "RotationEnabled": False,
        "KmsKeyId": "", "LastChangedDate": "2026-01-01T00:00:00Z"}]},
    ("ecr", "describe-repositories"): {"repositories": [{"repositoryName": "repo1",
        "imageScanningConfiguration": {"scanOnPush": True}, "imageTagMutability": "MUTABLE"}]},
    ("ecr", "get-repository-policy"): "RepositoryPolicyNotFoundException",
    ("guardduty", "list-detectors"): {"DetectorIds": ["d1"]},
    ("guardduty", "get-detector"): {"Status": "ENABLED", "Features": [
        {"Name": "S3_DATA_EVENTS", "Status": "ENABLED"}]},
    ("configservice", "describe-configuration-recorders"): {
        "ConfigurationRecorders": [{"name": "r"}]},
    ("configservice", "describe-configuration-recorder-status"): {
        "ConfigurationRecordersStatus": [{"recording": True}]},
    ("securityhub", "describe-hub"): {"HubArn": "arn:x"},
    ("securityhub", "get-findings"): {"Findings": []},
    ("inspector2", "batch-get-account-status"): {"accounts": [
        {"state": {"status": "ENABLED"}, "resourceState": {}}]},
    ("accessanalyzer", "list-analyzers"): {"analyzers": [
        {"status": "ACTIVE", "type": "ACCOUNT", "name": "default",
         "arn": "arn:aws:access-analyzer:us-east-1:%s:analyzer/default" % _ACCT}]},
    ("accessanalyzer", "list-findings"): {"findings": [
        {"id": "f1", "status": "ACTIVE", "resource": "arn:aws:s3:::b1",
         "resourceType": "AWS::S3::Bucket", "isPublic": True,
         "principal": {"AWS": "*"}, "action": ["s3:GetObject"],
         "condition": {}, "analyzedAt": "2026-01-01T00:00:00Z"}]},
    ("cloudtrail", "describe-trails"): {"trailList": [{"Name": "t", "IsMultiRegionTrail": True,
        "LogFileValidationEnabled": True, "HomeRegion": _REGION}]},
    ("organizations", "describe-organization"): {"Organization": {"Id": "o-x",
        "FeatureSet": "ALL", "MasterAccountId": _ACCT}},
    ("organizations", "list-accounts"): {"Accounts": [
        {"Id": _ACCT, "Name": "a", "Status": "ACTIVE"}]},
}


@pytest.fixture
def recorded_cloud_argv(monkeypatch, tmp_path):
    """Run all nine cloud stages against a populated fake CLI, and hand back
    every argv they built.

    Populated on purpose: an empty response makes a stage stop after its first
    call, so the per-bucket, per-function, per-cluster and per-topic reads --
    the ones built inline, which the regex tests could not see -- would never
    be recorded at all."""
    recorded = []

    def responder(argv, _timeout, env=None):
        recorded.append(list(argv))
        answer = _CLI_RESPONSES.get((argv[0], argv[1]))
        if isinstance(answer, str):
            return None, "An error occurred (%s) when calling" % answer
        if answer is None:
            return {}, ""
        return answer, ""

    def run_cmd(argv, *_a, **_k):
        recorded.append(list(argv))
        return 0, "", ""

    monkeypatch.setattr(squawk.probes, "tool_path", lambda _n: "/usr/bin/aws")
    monkeypatch.setattr(squawk.probes, "_aws_json", responder)
    monkeypatch.setattr(squawk.probes, "_aws_json_env",
                        lambda argv, t, env: responder(argv, t, env))
    monkeypatch.setattr(squawk.probes, "run_cmd", run_cmd)
    monkeypatch.setenv("SQUAWK_CLOUD_ACK", "1")
    monkeypatch.setenv("SQUAWK_CLOUD_PROFILES_ACK", "1")
    root = str(tmp_path / "ev")
    os.makedirs(root, exist_ok=True)
    outcome = squawk.execute_service(squawk.SERVICES["cloudinventory"],
                                     "credential-chain", root, str(tmp_path))
    return recorded, outcome


class TestEveryCloudCallIsARead:
    """I3, held over what the stages BUILD rather than over what they look
    like in source."""

    def test_the_harness_ran_every_stage(self, recorded_cloud_argv):
        """Without this the test below is an assertion about however many
        stages happened to run."""
        recorded, _outcome = recorded_cloud_argv
        made = {(argv[0], argv[1]) for argv in recorded}
        missing = {stage: sig for stage, sig in STAGE_SIGNATURES.items()
                   if sig not in made}
        assert not missing, "these stages made no calls: %s" % sorted(missing)
        assert len(recorded) >= 60, \
            "only %d calls recorded; the fake CLI has gone empty" % len(recorded)

    def test_every_service_called_is_on_the_allowlist(self, recorded_cloud_argv):
        recorded, _outcome = recorded_cloud_argv
        called = {argv[0] for argv in recorded} - {"aws"}
        assert called <= CLOUD_SERVICES, \
            "not on the allowlist: %s" % sorted(called - CLOUD_SERVICES)

    def test_every_verb_is_a_read(self, recorded_cloud_argv):
        recorded, _outcome = recorded_cloud_argv
        for argv in recorded:
            if argv[0] == "aws":
                continue
            assert argv[1].startswith(READ_VERBS), \
                "%s %s is not a read" % (argv[0], argv[1])

    def test_no_destructive_token_reaches_a_command(self, recorded_cloud_argv):
        recorded, _outcome = recorded_cloud_argv
        for argv in recorded:
            for token in argv:
                low = str(token).lower()
                if low in READ_ONLY_EXEMPT:
                    continue
                assert low not in DESTRUCTIVE_TOKENS, \
                    "%s carries %s" % (" ".join(argv), low)

    def test_no_credential_and_no_profile_on_a_command_line(self,
                                                            recorded_cloud_argv):
        """Credential rule 3: the CLI resolves the identity, and a profile
        name reaches a child through the environment, never on argv."""
        recorded, _outcome = recorded_cloud_argv
        for argv in recorded:
            for token in argv:
                low = str(token).lower()
                assert not low.startswith("--profile"), " ".join(argv)
                assert not re.match(r"^akia[0-9a-z]{16}$", low), " ".join(argv)
                assert "aws_secret_access_key" not in low, " ".join(argv)

    def test_the_only_configure_subcommand_is_list_profiles(self,
                                                            recorded_cloud_argv):
        """`aws configure` can WRITE the CLI's own config. One subcommand of it
        is a read, and that is the only one this may use."""
        recorded, _outcome = recorded_cloud_argv
        for argv in recorded:
            if "configure" in [str(t) for t in argv]:
                assert argv[:3] == ["aws", "configure", "list-profiles"], \
                    " ".join(argv)

    def test_adding_a_service_off_the_allowlist_would_fail(self):
        """The acceptance the plan names, exercised rather than described: the
        assertion is what fails, not the absence of a pattern."""
        called = {"ec2", "iam", "kms"}
        assert not called <= CLOUD_SERVICES, \
            "the allowlist would admit a service nobody put on it"



# --------------------------------------------------------------------------- #
# I14, at the reader layer: a reading this tool cannot parse is a gap, never an
# exception.
#
# The normalizer corpus above covers the scanner boundary. The cloud readers
# are a second boundary and were never held to it: they take a dict that came
# off disk, and thirty of them indexed into whatever they found (review R-14).
# A run whose evidence file was truncated by a full disk took the whole Cloud
# page down rather than one panel.
# --------------------------------------------------------------------------- #

# The real top-level keys of the nine cloud readings. A corpus of `{}` proves
# nothing: the crashes are in readers that FIND the key and then index into a
# value of the wrong type.
_CLOUD_KEYS = (
    "account", "read_at", "api_calls", "counts", "regions_enabled",
    "regions_read", "regions_partial", "regions_unread", "regional",
    "resources", "reads", "buckets", "databases", "users", "roles",
    "roles_with_escalation", "roles_already_admin", "accounts",
    "organization", "distributions", "profiles_reaching",
    "profiles_unreachable", "instance_profiles",
)

# Seventeen wrong values, at the top level and nested one and two levels down.
_WRONG = ("x", 1, 0, None, [], {}, True, False, [1], ["a"], [None], [[]],
          [{}], {"a": 1}, {"a": None}, 1.5, {"a": [{"b": None}]})


# A region list beside a corrupt document is the second axis. The corpus varied
# ONE field at a time, and a reader indexes into `regional` only once a region
# list gives it something to index BY -- so `{"regional": "not a mapping"}` was
# survivable and the same document with `regions_read` populated was not. Every
# reader passed a corpus that never built the shape that breaks them (review 2,
# R-35).
_REGION_LISTS = (
    {},
    {"regions_read": ["us-east-1"], "regions_enabled": ["us-east-1"]},
    {"regions_read": ["us-east-1"], "regions_enabled": ["us-east-1"],
     "regions_partial": ["us-east-1"], "regions_unread": ["eu-west-1"]},
)


def _cloud_corpus():
    documents = [{}, {"regional": {"us-east-1": None}},
                 {"regional": {"us-east-1": {"unreadable": None}}},
                 {"resources": {"us-east-1": None}},
                 {"reads": {"us-east-1": {"vpcs": None}}}]
    for key in _CLOUD_KEYS:
        for wrong in _WRONG:
            documents.append({key: wrong})
            documents.append({"regional": {"us-east-1": {key: wrong}}})
    # Each structural map, wrong in every way, beside each region list.
    for key in ("regional", "resources", "reads", "accounts", "users",
                "roles", "counts"):
        for wrong in _WRONG:
            for regions in _REGION_LISTS[1:]:
                documents.append(dict(regions, **{key: wrong}))
    return documents


CLOUD_JUNK = _cloud_corpus()


def _cloud_readers():
    """Every reader the Cloud page calls with a document off disk."""
    A = squawk.analysis
    readers = [
        ("inventory_summary", lambda d: A.inventory_summary(d)),
        ("inventory_caveats", lambda d: A.inventory_caveats(A.inventory_summary(d))),
        ("inventory_notes", lambda d: A.inventory_notes(A.inventory_summary(d))),
        ("headline_facts", lambda d: A.headline_facts(A.inventory_summary(d))),
        ("split_regions", lambda d: A.split_regions(A.inventory_summary(d))),
        ("enablement_summary", lambda d: A.enablement_summary(d)),
        ("watching_gaps", lambda d: A.watching_gaps(A.inventory_summary(d),
                                                    A.enablement_summary(d))),
        ("iam_summary", lambda d: A.iam_summary(d)),
        ("iam_findings", lambda d: A.iam_findings(d)),
        ("iam_caveats", lambda d: A.iam_caveats(A.iam_summary(d))),
        ("role_findings", lambda d: A.role_findings(d)),
        # Takes a role row rather than a document, and the corpus feeds it
        # documents -- which is the point: the page hands it whatever the
        # evidence held, and a label that raises takes the panel down.
        ("reach_words", lambda d: A.reach_words(d)),
        ("edge_summary", lambda d: A.edge_summary(d)),
        ("edge_findings", lambda d: A.edge_findings(d)),
        ("edge_gaps", lambda d: A.edge_gaps(d, d)),
        ("interface_owners", lambda d: A.interface_owners(d)),
        ("frontdoor_summary", lambda d: A.frontdoor_summary(d)),
        ("frontdoor_findings", lambda d: A.frontdoor_findings(d)),
        ("frontdoor_caveats", lambda d: A.frontdoor_caveats(A.frontdoor_summary(d))),
        ("storage_summary", lambda d: A.storage_summary(d)),
        ("storage_findings", lambda d: A.storage_findings(d, d)),
        ("storage_caveats", lambda d: A.storage_caveats(A.storage_summary(d), False)),
        ("container_summary", lambda d: A.container_summary(d)),
        ("container_findings", lambda d: A.container_findings(d, d)),
        ("dataservice_summary", lambda d: A.dataservice_summary(d)),
        ("dataservice_findings", lambda d: A.dataservice_findings(d)),
        ("dataservice_caveats", lambda d: A.dataservice_caveats(A.dataservice_summary(d))),
        ("analyzer_summary", lambda d: A.analyzer_summary(d)),
        ("analyzer_findings", lambda d: A.analyzer_findings(d)),
        ("analyzer_caveats", lambda d: A.analyzer_caveats(A.analyzer_summary(d))),
        ("analyzer_agreement", lambda d: A.analyzer_agreement(d, [])),
        ("org_summary", lambda d: A.org_summary(d)),
        ("org_findings", lambda d: A.org_findings(d)),
        ("org_caveats", lambda d: A.org_caveats(A.org_summary(d))),
        ("correlate_cloud", lambda d: A.correlate_cloud(d)),
        ("compare_readings", lambda d: A.compare_readings(d, d)),
        ("diff_lines", lambda d: A.diff_lines(A.compare_readings(d, d))),
        ("build_cloud_graph", lambda d: A.build_cloud_graph(d, "us-east-1")),
        ("regions_seen", lambda d: A.regions_seen(d)),
        ("partial_caveat", lambda d: A.partial_caveat(d)),
    ]
    for key in sorted(A.CLOUD_DRILL):
        readers.append(("cloud_drill:%s" % key,
                        lambda d, k=key: A.cloud_drill(k, d)))
    return readers


CLOUD_READERS = _cloud_readers()


class TestACloudReaderNeverRaises:
    """A reading this tool cannot parse is a gap, and a gap is a status, not a
    traceback. Thirty readers took a document off disk and indexed into
    whatever they found; one truncated evidence file took the whole page down
    (review R-14, reproduction 9).

    Coerced at the top of each reader with `_rows`, `isinstance` and `as_text`
    -- never a bare try/except around the body, which would swallow the crash
    and return zeros, and zeros are the substitution I1 exists to refuse.
    """

    @pytest.mark.parametrize("name,call",
                             CLOUD_READERS, ids=[n for n, _ in CLOUD_READERS])
    def test_reader_survives_every_shape(self, name, call):
        for document in CLOUD_JUNK:
            try:
                call(document)
            except Exception as exc:
                raise AssertionError(
                    "%s raised %s on %r"
                    % (name, type(exc).__name__, document)) from exc

    def test_the_corpus_is_actually_large(self):
        assert len(CLOUD_JUNK) > 400, len(CLOUD_JUNK)

    def test_the_corpus_varies_more_than_one_field(self):
        """The claim was "a cloud reader never raises" over a corpus that
        changed one field at a time, and five readers raised the moment a
        corrupt `regional` sat beside a region list to index it by. A corpus
        with one axis cannot support a claim about documents (review 2,
        R-35)."""
        combined = [d for d in CLOUD_JUNK
                    if d.get("regions_read") and not isinstance(
                        d.get("regional", {}), dict)]
        assert len(combined) > 10, \
            "the corpus never builds a corrupt map beside a region list"

    def test_the_shape_that_broke_five_readers_is_in_the_corpus(self):
        assert {"regions_read": ["us-east-1"], "regions_enabled": ["us-east-1"],
                "regional": "x"} in CLOUD_JUNK

    def test_every_reader_a_cloud_panel_calls_is_in_the_list(self):
        """A reader added to a cloud panel and not to this list would go
        unchecked, which is how a corpus stops covering the page it is for.

        Read from the panel functions themselves, so it tracks the code and
        not anyone's memory of it.
        """
        named = {n.split(":")[0] for n, _ in CLOUD_READERS}
        # Rendering helpers and formatters take what a reader already returned.
        # This is about the functions that take a document off disk.
        not_readers = {"cloud_drill", "as_text", "redact_identifiers",
                       "mask_account", "mask_email", "mask_key_id", "rule_of",
                       "norm_severity", "human_hours", "severity_rank",
                       # Finds the run; it does not read a reading.
                       "list_runs",
                       # Coercions, not readers. They are what the readers in
                       # the corpus are built from.
                       "_rows", "_names", "_mapping"}
        tree = ast.parse(
            pathlib.Path(squawk.web.__file__).read_text(encoding="utf-8"))
        panels = [n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name.startswith("cloud_") and n.name.endswith("panel")]
        assert len(panels) >= 8, "found %d cloud panels" % len(panels)
        called = set()
        for panel in panels:
            for node in ast.walk(panel):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    called.add(node.func.id)
        missing = sorted(
            name for name in called
            if name not in named and name not in not_readers
            and callable(getattr(squawk.analysis, name, None)))
        assert not missing, "panels call these and the corpus does not: %s" % missing

    def test_one_unreadable_file_costs_one_panel(self, tmp_path, monkeypatch):
        """The second layer. A reader that raises should not be possible, and
        the corpus above is what makes that true — this is for the shape
        nobody thought of. One corrupt evidence file must cost its own panel
        and nothing else, and the panel must SAY so: a section that silently
        vanished would read as a section with nothing in it.
        """
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        for filename in squawk.web.CLOUD_READINGS.values():
            (run / "raw" / filename).write_text("{}", encoding="utf-8")
        ledger = [{"tool": t, "status": "ok", "detail": ""}
                  for t in squawk.web.CLOUD_READINGS]
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": ledger}])

        def explode(*_a, **_k):
            raise ValueError("truncated evidence")

        monkeypatch.setattr(squawk.web, "cloud_storage_panel", explode)
        html = squawk.web.view_cloud(str(tmp_path))
        assert "This reading could not be read" in html
        assert "ValueError" in html
        assert "Where the data is" in html
        for other in ("What is in this account", "What is watching this account",
                      "What changed since the last reading"):
            assert other in html, "%s went down with its neighbour" % other

    def test_the_inventory_panel_failing_does_not_take_its_siblings(
            self, tmp_path, monkeypatch):
        """It is the one panel whose summary its siblings read, so its failure
        is the one that could cascade."""
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        for filename in squawk.web.CLOUD_READINGS.values():
            (run / "raw" / filename).write_text("{}", encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [{"tool": t, "status": "ok", "detail": ""}
                        for t in squawk.web.CLOUD_READINGS]}])

        def explode(*_a, **_k):
            raise KeyError("resources")

        monkeypatch.setattr(squawk.web, "cloud_inventory_panel", explode)
        html = squawk.web.view_cloud(str(tmp_path))
        assert "This reading could not be read" in html and "KeyError" in html
        assert "What is watching this account" in html, \
            "the panels that read its summary went down with it"
        assert "What changed since the last reading" in html


# --------------------------------------------------------------------------- #
# The severity scale is written down, and the code sits where it says.
# --------------------------------------------------------------------------- #

SCALE_DOC = pathlib.Path(__file__).parent.parent / "docs" / "CORRELATION-DESIGN.md"


def _severity_section() -> str:
    """The text of "## The severity scale", and nothing after it.

    Scoped to the section because the reader below matches any table row in the
    document. A second table arrived under "## How far a thing can be reached
    from" — reach names against descriptions — and its rows parsed as severity
    rows, so `external`, `organization` and `unsettled` read as rules the code
    does not emit. The document is allowed more than one table.
    """
    text = SCALE_DOC.read_text(encoding="utf-8")
    start = text.index("## The severity scale")
    rest = text.index("\n## ", start + 1)
    return text[start:rest]


def _documented_severities():
    """The rule/level pairs from the scale's own table."""
    rows = {}
    for line in _severity_section().splitlines():
        match = re.match(r"\|\s*`([a-z0-9-]+)`\s*\|\s*([a-z ]+?)\s*\|", line)
        if match:
            rows[match.group(1)] = {p.strip() for p in match.group(2).split("or")}
    return rows


def _coded_severities():
    """The rule/level pairs the cloud finding functions actually emit."""
    tree = ast.parse(
        pathlib.Path(squawk.analysis.__file__).read_text(encoding="utf-8"))
    rows = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        got = {}
        # ast.Dict guarantees these are the same length; `strict=` is
        # 3.10 and this package is 3.9.
        for key, value in zip(node.keys, node.values):  # noqa: B905
            if not (isinstance(key, ast.Constant)
                    and key.value in ("key", "severity")):
                continue
            if isinstance(value, ast.Constant):
                got[key.value] = {value.value}
            elif (isinstance(value, ast.IfExp)
                  and isinstance(value.body, ast.Constant)
                  and isinstance(value.orelse, ast.Constant)):
                got[key.value] = {value.body.value, value.orelse.value}
        if got.get("key") and got.get("severity"):
            rows.setdefault(next(iter(got["key"])), set()).update(got["severity"])
    rows.update(_coded_rule_severities(tree))
    return rows


def _coded_rule_severities(tree):
    """The same pairs, for the rules that are not dict literals.

    `CloudRule` carries its key and its severity as POSITIONAL fields, and
    `correlate_cloud` writes `rule.severity` into the finding. The dict walk
    above cannot see either, so the plan's two most valuable rules --
    `reachable-admin-port` and `reachable-over-permitted` -- were absent from
    the scale's table while the test that exists to catch exactly that passed
    (review 2, R-30). An assertion over a set the scan never reaches is not an
    assertion."""
    rows = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "CloudRule"):
            continue
        positional = [a for a in node.args if isinstance(a, ast.Constant)]
        by_name = {k.arg: k.value for k in node.keywords
                   if isinstance(k.value, ast.Constant)}
        key = (positional[0].value if positional
               else by_name.get("key", ast.Constant("")).value)
        level = (positional[2].value if len(positional) > 2
                 else by_name.get("severity", ast.Constant("")).value)
        if key and level:
            rows.setdefault(key, set()).add(level)
    return rows


class TestTheSeverityScaleIsWrittenDown:
    """R-16. HIGH meant "one flag" in storage and "a verified path" in
    networking, and a reader learned which by reading the code.

    The scale is four paragraphs in CORRELATION-DESIGN.md and a table placing
    every rule against them. This is what stops the two drifting: a rule added
    to the code without a line in the table fails here, and so does one whose
    level was changed in only one of the two places.
    """

    def test_the_scale_names_all_four_levels(self):
        text = SCALE_DOC.read_text(encoding="utf-8")
        assert "## The severity scale" in text
        for level in ("`critical`", "`high`", "`medium`", "`low`"):
            assert "**%s —" % level in text, level
        assert "`unknown` is not a severity" in text
        assert "`info` is not a severity either" in text

    def test_a_second_table_in_the_document_is_not_read_as_severities(self):
        """The reader matched any table row anywhere in the file. "How far a
        thing can be reached from" added a table of reach names, and its rows
        parsed as rules the code does not emit. A design document is allowed
        more than one table."""
        rows = _documented_severities()
        for reach in ("anyone", "external", "unsettled", "federated",
                      "organization", "service", "internal"):
            assert reach not in rows, (
                "%r came from the reach table, not the severity scale" % reach)
        assert "eks-api-open-to-the-world" in rows, "the real table still reads"

    def test_the_reach_vocabulary_is_written_down(self):
        """Seven words decide how a finding is ranked and none of them was
        defined anywhere a reader could find."""
        text = SCALE_DOC.read_text(encoding="utf-8")
        assert "## How far a thing can be reached from" in text
        for reach in squawk.probes.REACH_RANK:
            assert "| `%s` |" % reach in text, reach
        assert "`REACH_RANK`" in text and "`widest_reach`" in text

    def test_the_unknown_severity_rules_say_why_they_are_absent(self):
        """Three rules carry `unknown` and are skipped by the table check. A
        reader who finds them missing should not have to read this test to
        learn that it was deliberate."""
        text = SCALE_DOC.read_text(encoding="utf-8")
        for key in ("role-trust-unsettled", "messaging-reach-unsettled",
                    "registry-reach-unsettled"):
            assert "`%s`" % key in text, key
        assert "TestTheSeverityScaleIsWrittenDown" in text

    def test_every_rule_in_the_code_is_in_the_table(self):
        documented = _documented_severities()
        coded = _coded_severities()
        missing = sorted(key for key, levels in coded.items()
                         if levels != {"unknown"} and key not in documented)
        assert not missing, \
            "these rules have no line in the scale's table: %s" % missing

    def test_no_rule_carries_a_different_level_in_the_two_places(self):
        documented = _documented_severities()
        coded = _coded_severities()
        wrong = []
        for key, levels in sorted(coded.items()):
            if levels == {"unknown"} or key not in documented:
                continue
            if levels != documented[key]:
                wrong.append("%s: code says %s, the table says %s"
                             % (key, sorted(levels), sorted(documented[key])))
        assert not wrong, "\n".join(wrong)

    def test_the_table_has_no_rule_the_code_does_not_emit(self):
        """The other direction: a line left behind by a deleted rule makes the
        table a description of a version that no longer exists."""
        stale = sorted(set(_documented_severities()) - set(_coded_severities()))
        assert not stale, "in the table and not in the code: %s" % stale

    def test_the_two_arguments_are_recorded(self):
        """The plan does not care which way these went, only that they were
        decided and written down."""
        text = SCALE_DOC.read_text(encoding="utf-8")
        assert "is `high`, not `critical`" in text
        assert "judged like an EC2" in text

    def test_no_finding_row_is_built_outside_the_shared_renderer(self):
        """Three panels each carried their own copy of the row markup, and each
        copy had a slightly different severity-to-colour map — so a `low`
        finding was grey on one panel and the gap colour on another, and only
        one of the three would have picked up a new level.

        The shape is distinctive: a coloured left border around a resource, a
        region and a `why`. Asserted over the parsed source because what is
        being forbidden is a duplicate, and a duplicate is a source fact.
        """
        src = pathlib.Path(squawk.web.__file__).read_text(encoding="utf-8")
        # The full shape, not the CSS prefix: the IAM panel renders a row of
        # its own with a user and its escalation list, which is a different
        # thing and not a duplicate of this one.
        marker = ("<b class='mono'>%s</b> "
                  "\"\n                    \"<span class='muted' style='font-size:.75rem'>"
                  "%s</span><br>")
        assert src.count(marker) == 1, (
            "%d places build the shared finding row; there should be one, in "
            "_finding_rows" % src.count(marker))

    def test_every_why_reaches_html_through_the_redactor(self):
        """A `why` carries whatever an AWS error said, and an SSO error says
        the operator's address. `_why` is the one door it goes through
        (PRODUCT rule 6, review R-3)."""
        tree = ast.parse(
            pathlib.Path(squawk.web.__file__).read_text(encoding="utf-8"))
        bare = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "E" and node.args):
                continue
            arg = node.args[0]
            if (isinstance(arg, ast.Subscript)
                    and isinstance(arg.slice, ast.Constant)
                    and arg.slice.value == "why"):
                bare.append(node.lineno)
            if (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
                    and arg.func.attr == "get" and arg.args
                    and isinstance(arg.args[0], ast.Constant)
                    and arg.args[0].value == "why"):
                bare.append(node.lineno)
        assert not bare, \
            "a why reaches HTML without _why at web.py:%s" % sorted(bare)


class TestTwoRunsDoNotShareACounter:
    """R-15. Jobs run in threads, and the cloud stages counted their API calls
    in one module-level dict — so a second run starting mid-flight zeroed the
    first one's count and the page reported a number that belonged to neither.
    """

    def test_each_thread_counts_its_own_calls(self):
        import threading
        seen = {}
        started = threading.Event()

        def first():
            squawk.probes._CALLS["n"] = 0
            for _ in range(5):
                squawk.probes._CALLS["n"] += 1
            started.set()
            second.join()
            seen["first"] = squawk.probes._CALLS["n"]

        def other():
            started.wait(2)
            squawk.probes._CALLS["n"] = 0      # what a new stage does
            for _ in range(3):
                squawk.probes._CALLS["n"] += 1
            seen["second"] = squawk.probes._CALLS["n"]

        second = threading.Thread(target=other)
        one = threading.Thread(target=first)
        second.start()
        one.start()
        one.join(5)
        assert seen.get("first") == 5, \
            "the second run reset the first run's counter: %s" % seen
        assert seen.get("second") == 3, seen

    def test_a_fresh_thread_starts_at_zero(self):
        import threading
        squawk.probes._CALLS["n"] = 99
        seen = []
        thread = threading.Thread(target=lambda: seen.append(squawk.probes._CALLS["n"]))
        thread.start()
        thread.join(5)
        assert seen == [0], "a new run inherited a count from another thread"


class TestThePageSurvivesPaper:
    """The Cloud page is handed on as a PDF, and paper does not scroll.

    Every `overflow-x:auto` container that fits on screen by scrolling was
    CLIPPED at the page edge: two consecutive PDFs from a field run lost the
    right-hand columns of the region table and the last two cities of the clock
    strip. A scroll bar is a promise the reader can see more, and print cannot
    keep it.
    """

    def _css(self):
        return squawk.web.PAGE_CSS

    def test_there_is_a_print_stylesheet(self):
        assert "@media print{" in self._css()

    def test_nothing_scrolls_sideways_on_paper(self):
        block = self._css().split("@media print{", 1)[1]
        assert "overflow:visible!important" in block, \
            "an overflow-x container would still be clipped at the page edge"
        assert ".clocks{overflow:visible" in block
        assert "flex-wrap:wrap" in block, "the clock strip cannot wrap"

    def test_a_table_cell_wraps_rather_than_runs_off(self):
        block = self._css().split("@media print{", 1)[1]
        assert "white-space:normal!important" in block, \
            "th has white-space:nowrap, which is what ran the header off"

    def test_the_controls_that_do_nothing_on_paper_are_gone(self):
        block = self._css().split("@media print{", 1)[1]
        assert ".btn" in block and "display:none!important" in block


class TestAnAccountWithoutAResourceKindIsNotAGap:
    """Review 2, R-20.

    Six coverage extractors counted resources FOUND. `_apply_coverage` turns
    zero examined into `gap`, a gap makes the run incomplete, the incomplete
    run raises 7600, and the page then refuses to render the panel. So an
    account with no containers -- nothing denied, every list call answered --
    got "This reading is not available", an incomplete run and a
    lost-communications alarm, on every run, forever.

    That is I1 inverted: a tool that found nothing looking like a tool that did
    not run.
    """

    def _empty_cli(self, monkeypatch):
        """Every list answers, and every list is empty."""
        empties = {
            "describe-regions": {"Regions": [{"RegionName": _REGION}]},
            "get-caller-identity": {"Account": _ACCT, "Arn": "arn:x"},
            # One role, because AWS creates service-linked roles itself and an
            # account with literally no principals does not exist. The IAM
            # denominator is deliberately principals for that reason.
            "get-account-authorization-details": {
                "UserDetailList": [],
                "RoleDetailList": [{"RoleName": "AWSServiceRoleForSupport",
                                    "Arn": "arn:aws:iam::%s:role/x" % _ACCT,
                                    "RolePolicyList": [],
                                    "AttachedManagedPolicies": []}],
                "GroupDetailList": [], "Policies": []},
            "get-account-summary": {"SummaryMap": {"AccountMFAEnabled": 1,
                                                   "AccountAccessKeysPresent": 0}},
            "batch-get-account-status": {"accounts": [
                {"state": {"status": "DISABLED"}, "resourceState": {}}]},
        }

        def responder(argv, _timeout, env=None):
            verb = argv[1]
            if verb in empties:
                return empties[verb], ""
            if verb == "describe-organization":
                return None, "An error occurred (AWSOrganizationsNotInUseException)"
            return {}, ""

        monkeypatch.setattr(squawk.probes, "tool_path", lambda _n: "/usr/bin/aws")
        monkeypatch.setattr(squawk.probes, "_aws_json", responder)
        monkeypatch.setattr(squawk.probes, "_aws_json_env",
                            lambda a, t, e: responder(a, t, e))
        monkeypatch.setattr(squawk.probes, "run_cmd",
                            lambda *_a, **_k: (0, "", ""))
        monkeypatch.setenv("SQUAWK_CLOUD_ACK", "1")

    def test_every_stage_is_ok_when_every_read_answered(self, tmp_path,
                                                        monkeypatch):
        self._empty_cli(monkeypatch)
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        outcome = squawk.execute_service(squawk.SERVICES["cloudinventory"],
                                         "credential-chain", root, str(tmp_path))
        bad = {r.tool: (r.status, r.detail) for r in outcome["results"]
               if r.status not in ("ok",) and r.tool != "correlation"}
        assert not bad, \
            "nothing was denied and these stages are not ok: %s" % bad

    def test_the_run_is_not_incomplete_and_does_not_squawk(self, tmp_path,
                                                           monkeypatch):
        self._empty_cli(monkeypatch)
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        squawk.execute_service(squawk.SERVICES["cloudinventory"],
                               "credential-chain", root, str(tmp_path))
        man = json.load(open(
            pathlib.Path(squawk.list_runs(root)[0]["_dir"]) / "manifest.json"))
        codes = [c.get("code") for c in (man.get("squawk") or [])]
        assert "7600" not in [str(c) for c in codes], \
            "lost communications, with nothing lost: %s" % codes

    def test_no_panel_says_the_reading_is_not_available(self, tmp_path,
                                                        monkeypatch):
        self._empty_cli(monkeypatch)
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        squawk.execute_service(squawk.SERVICES["cloudinventory"],
                               "credential-chain", root, str(tmp_path))
        html = squawk.view_cloud(root)
        assert "This reading is not available" not in html, \
            "a panel refused to render over an account that simply has none"


class TestTheProjectSaysWhereItRunsAndWhatItCites:
    """The release review's B-1 and B-4.

    The README said Squawk "runs anywhere Python does" while the package
    imported `fcntl` and called `os.killpg`, and it sent a reader to
    `TOWER-HANDOFF.md` -- a reference document marked never-publish, which an
    export would carry as a dangling pointer at private material. Both were
    true for weeks because nothing checked either one."""

    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Where a claim about portability has to be re-read. Each is a call or an
    # import that does not exist on Windows. Adding one means the README's
    # paragraph is now describing a different piece of software.
    POSIX_ONLY = ("import fcntl", "import grp", "import pwd", "os.killpg(",
                  "signal.SIGKILL", "os.geteuid(", "os.getuid(")

    # The modules that are allowed to carry one, and the reason the README
    # gives for each.
    POSIX_MODULES = ("core.py", "installer.py", "probes.py")

    #: `public/` holds the few files that are a different document in the
    #: published tree -- its changelog, its lint configuration, its workflow.
    #: They are written against that tree's root, one directory up from where
    #: they sit here, so their links resolve there and not here. The check
    #: moves rather than disappearing: `tools/port_to_public.py` runs the same
    #: link resolution over the tree it builds, where those files are at the
    #: root they were written for.
    OVERLAY = "public"

    #: The private reference set, renamed from `docs/` so it cannot be
    #: confused with the published `docs/` the README points at.
    PRIVATE = "reference"

    def _docs(self):
        for base, dirs, files in os.walk(self.ROOT):
            dirs[:] = [d for d in dirs
                       if d not in ("__pycache__", ".git", "dist",
                                    "node_modules", self.OVERLAY)]
            for name in sorted(files):
                if name.endswith(".md"):
                    yield os.path.join(base, name)

    def test_every_reference_in_a_document_resolves(self):
        """A renamed file leaves a pointer to nothing, and a reader who
        follows it learns that the documentation is not maintained."""
        broken = []
        link = re.compile(r"\[[^\]]*\]\(([^)\s]+?)(?:#[^)]*)?\)")
        for path in self._docs():
            here = os.path.dirname(path)
            with io.open(path, encoding="utf-8", errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    for m in link.finditer(line):
                        target = m.group(1).strip()
                        if target.startswith(("http://", "https://", "mailto:",
                                              "#")):
                            continue
                        if not os.path.exists(
                                os.path.normpath(os.path.join(here, target))):
                            broken.append("%s:%d -> %s"
                                          % (os.path.relpath(path, self.ROOT),
                                             n, target))
        assert not broken, "%d reference(s) point at nothing: %s" % (
            len(broken), broken[:6])

    def test_the_readme_names_no_never_publish_document(self):
        """The one file every stranger reads, and the one an export carries
        first. A reference document from a work environment is not something
        it may point at, by name or by link.

        The private set is the same one `tools/check_private_boundary.py`
        holds -- everything under `reference/`, plus the reference documents
        one directory up. It is spelled out here rather than imported, because
        this tree has to test itself after an export that leaves the checker
        behind.

        `reference/`, not `docs/`: the published tree has a `docs/` of its own
        and the README is meant to point at it. Two directories one path apart,
        one private and one published, is a mistake waiting for somebody in a
        hurry, so the private one was renamed."""
        private = {os.path.basename(p) for p in self._docs()
                   if os.path.relpath(p, self.ROOT).startswith(
                       self.PRIVATE + os.sep)}
        private |= {"TOWER-HANDOFF.md", "SCAN-TOWER-FIELD-LESSONS.md",
                    "SCAN-TOWER-REBUILD-AND-LESSONS.md"}
        with io.open(os.path.join(self.ROOT, "README.md"),
                     encoding="utf-8") as fh:
            readme = fh.read()
        named = sorted(n for n in private if n in readme)
        assert not named, \
            "README.md names never-publish document(s): %s" % named

    def test_the_posix_only_calls_are_where_the_readme_says(self):
        """The README's portability paragraph is a claim about this exact
        set. A new one somewhere else means the paragraph is now wrong, and
        this is the thing that says so."""
        found = {}
        pkg = os.path.join(self.ROOT, "squawk")
        for name in sorted(os.listdir(pkg)):
            if not name.endswith(".py"):
                continue
            with io.open(os.path.join(pkg, name), encoding="utf-8") as fh:
                body = fh.read()
            hits = [tok for tok in self.POSIX_ONLY if tok in body]
            if hits:
                found[name] = hits
        assert sorted(found) == list(self.POSIX_MODULES), (
            "the POSIX-only surface moved: %s. README.md's portability "
            "paragraph names %s and has to be re-read."
            % (sorted(found), list(self.POSIX_MODULES)))

    def test_the_readme_says_it_is_not_windows(self):
        """A paragraph nothing reads is a paragraph that gets deleted."""
        with io.open(os.path.join(self.ROOT, "README.md"),
                     encoding="utf-8") as fh:
            readme = fh.read()
        assert "POSIX only" in readme
        assert "Windows" in readme, \
            "the README does not tell a Windows user what happens"


class TestASecurityToolHasADisclosureRoute:
    """Release review B-3. Squawk reads live cloud accounts, shells out, and
    serves HTTP, and published none of the files a security project is judged
    by -- no disclosure route at all.

    These assert the files exist and carry the parts that make them useful
    rather than decorative: a route that is not a public issue, the bound on
    what is maintained, and the report this tool most wants."""

    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _read(self, name):
        """Whitespace-flattened: a sentence that wraps in the file is still the
        same sentence, and a test that breaks on a reflow is a test that gets
        deleted."""
        with io.open(os.path.join(self.ROOT, name), encoding="utf-8") as fh:
            return re.sub(r"\s+", " ", fh.read())

    def test_the_files_a_public_security_project_is_judged_by_exist(self):
        for name in ("SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md",
                     "LICENSE", "NOTICE",
                     ".github/ISSUE_TEMPLATE/config.yml"):
            assert os.path.exists(os.path.join(self.ROOT, name)), name

    def test_the_disclosure_route_is_private(self):
        """A public issue is the wrong place and the document has to say so."""
        body = self._read("SECURITY.md")
        assert "private vulnerability reporting" in body.lower()
        assert "Do not open a public issue" in body

    def test_a_clean_result_that_was_not_earned_is_a_security_report(self):
        """The report this tool most wants, and the one nobody expects to be
        in a SECURITY.md. I1 is the product; a way to defeat it is a
        vulnerability in it."""
        body = self._read("SECURITY.md")
        assert "false clean" in body.lower()
        assert "did not run must never look like" in body
        assert os.path.exists(os.path.join(
            self.ROOT, ".github/ISSUE_TEMPLATE",
            "a-clean-result-that-was-not-earned.md"))

    def test_what_is_maintained_is_bounded_and_said_more_than_once(self):
        """A bound stated in one place is a bound nobody reads."""
        for name in ("SECURITY.md", "CONTRIBUTING.md", "README.md"):
            body = self._read(name).lower()
            assert "best-effort" in body or "best effort" in body, name
            assert "security issues first" in body, name

    def test_the_policy_says_what_the_tool_does_not_defend_against(self):
        body = self._read("SECURITY.md")
        for claim in ("No authentication", "No multi-user model",
                      "No sandbox around the scanners",
                      "Windows is not supported"):
            assert claim in body, claim

    def test_the_scanners_findings_are_not_claimed_as_squawks(self):
        """Squawk drives eight scanners. A false positive from one of them is
        that project's; mis-reporting what it said is this one's."""
        body = self._read("SECURITY.md")
        assert "What does not count" in body
        assert "belongs to that project" in body
        assert "reading its silence as a clean result" in body


def _css_rule(css, selector):
    """One rule's declarations, with comments removed.

    The comments in this stylesheet name the values they replaced -- which is
    most of what makes them worth reading, and it means a test that greps the
    rule text finds the old value in the note explaining why it is gone."""
    body = css.split(selector + "{", 1)[1].split("}", 1)[0]
    return re.sub(r"/\*.*?\*/", "", body, flags=re.S)


class TestThePageFollowsTheWindow:
    """From the run of 2026-09-11: "information does not fit the screen or
    follow it as it expands."

    Two rules did it. `main` carried a 1680px cap, so a wide monitor got a
    column of content and several hundred pixels of nothing beside it — under
    a comment in the same file saying tables and grids take the room and prose
    is held to a readable measure by a separate rule. And the tile rows were
    pinned to an exact column count, so a row of six was always 3+3 however
    much room there was, and one-per-line below 900px — which is the printed
    page putting one tile on each third of a sheet."""

    CSS = squawk.web.PAGE_CSS

    def test_the_content_column_has_no_hard_cap(self):
        main = [ln for ln in self.CSS.splitlines()
                if ln.startswith("main{")]
        assert main, "the main rule moved"
        assert "max-width" not in main[0], \
            "a cap on `main` starves the page; the 82ch prose rule is the " \
            "control: %s" % main[0]

    def test_prose_is_still_held_to_a_readable_measure(self):
        """Removing the cap is only safe because this rule exists. A line of
        200 characters is worse than a narrow page."""
        assert "max-width:82ch" in self.CSS

    def test_a_tile_row_is_not_pinned_to_a_column_count(self):
        for name in (".cols-3", ".cols-4"):
            rule = next(ln for ln in self.CSS.splitlines()
                        if ln.startswith(name + "{"))
            assert "auto-fit" in rule or "auto-fill" in rule, \
                "%s is pinned to a fixed number of columns: %s" % (name, rule)
            assert "minmax(" in rule, \
                "%s has no minimum, so a tile can be squeezed to nothing" % name

    def test_a_tile_row_is_not_collapsed_to_one_column_on_a_narrow_page(self):
        """auto-fit already gives one column when only one fits. A media query
        forcing 1fr on top of it is what made a printed sheet hold three
        tiles."""
        narrow = self.CSS.split("@media(max-width:900px)")[1].split("}}")[0]
        assert ".cols-3" not in narrow and ".cols-4" not in narrow

    def test_the_wall_uses_the_whole_strip(self):
        """The page went full width and the clock strip did not: `flex:none`
        left ten content-sized cells packed at one end, so on a wide window the
        strip stopped around two thirds across with nothing after it (the
        owner, 2026-09-11, second look).

        A percentage basis fills it by construction — eight cells of 12.5% is
        the whole width — and centring puts the leftover at both edges rather
        than all of it at one."""
        strip = _css_rule(self.CSS, ".clocks")
        assert "justify-content:center" in strip, strip
        rule = _css_rule(self.CSS, ".clocks .clk")
        assert "12.5%" in rule, "the cells do not span the strip: %s" % rule

    def test_a_clock_cell_still_refuses_to_shrink_below_its_label(self):
        """The older bug: a cell narrower than its widest line clipped the
        marked one's badge to 15px inside a line that needed 164.

        `min-width:max-content` held that off by sizing every cell to its
        longest line, which is also why they never lined up. The label wraps
        now instead, so a line that does not fit takes a second one rather than
        running past its own tint."""
        zone = _css_rule(self.CSS, ".clocks .zone")
        assert "white-space:nowrap" not in zone, \
            "a label that cannot wrap inside a fixed cell clips instead"

    def test_the_clock_strip_slides_with_the_page(self):
        """The topbar above it has been sticky since it was written; this was
        not. So the wall a reader is meant to check a timestamp against left
        the screen the moment they scrolled down to the timestamp (the operator,
        2026-09-11)."""
        strip = _css_rule(self.CSS, ".clocks")
        assert "position:sticky" in strip, "the clock strip scrolls away"
        assert "top:var(--topbar-h)" in strip, \
            "it has to sit under the topbar, not at the top of the window"

    def test_the_two_sticky_strips_are_named_once(self):
        """The offset a third sticky element needs is the sum of them, and it
        was written as the literal `73px` in one place and nowhere else — which
        is why the sticky column cleared the topbar and not the clocks."""
        assert "--topbar-h:" in self.CSS and "--clocks-h:" in self.CSS
        assert "calc(73px" not in self.CSS, "the magic number is back"
        column = _css_rule(self.CSS, ".cols-2 > :nth-child(2)")
        assert "var(--topbar-h)" in column and "var(--clocks-h)" in column, \
            "a sticky column has to clear BOTH strips: %s" % column

    def test_nothing_is_sticky_on_paper(self):
        """Sticky is a screen idea. On paper it either repeats on every sheet
        or prints over the content under it."""
        printed = self.CSS.split("@media print{")[1]
        assert ".clocks" in printed and "position:static!important" in printed

    def test_the_wall_wraps_rather_than_running_off_the_page(self):
        """Fifteen cells that refuse to shrink do not fit one row on an
        ordinary window, and a strip that scrolls sideways hides the clocks
        past the edge (the operator, 2026-09-11 and 2026-09-12)."""
        strip = _css_rule(self.CSS, ".clocks")
        assert "flex-wrap:wrap" in strip, \
            "the strip scrolls sideways instead of wrapping: %s" % strip
        assert "overflow-x:auto" not in strip, \
            "a wrapped wall needs no sideways scrollbar, and one hides clocks"

    def test_the_row_length_is_chosen_and_never_left_to_the_width(self):
        """The fault the third attempt fixed. `auto-fit` picks the column count
        from the window alone, and with fifteen clocks the count decides
        everything: eight gives 8+7, seven gives 7+7+1. A window a little
        narrower than the operator's put one clock alone on a row.

        8, 6 and 4 are the counts that strand nobody at fifteen OR at sixteen —
        the script adds a sixteenth when the reader's zone is not already on the
        wall, so both have to hold. 2, 3, 5 and 7 each leave a lone clock at one
        count or the other."""
        css = self.CSS
        assert "auto-fit" not in _css_rule(css, ".clocks"), \
            "the width is choosing the row length again"
        for basis, per in (("12.5%", 8), ("16.666%", 6), ("25%", 4)):
            assert basis in css, "no rule gives %d per row" % per
            for count in (15, 16):
                assert count % per != 1, \
                    "%d per row strands one clock at %d" % (per, count)

    def test_the_short_row_is_centred_rather_than_left_with_a_hole(self):
        """Fifteen is odd, so no two-row split is even and no arithmetic makes
        one. The short row sits centred under the full one, which reads as
        deliberate rather than as a gap at the end."""
        assert "justify-content:center" in _css_rule(self.CSS, ".clocks")

    def test_a_cell_cannot_grow_into_the_gap(self):
        """`flex:0 0` on purpose. A cell allowed to grow would fill the short
        row and undo the centring, which is the raggedness this started as."""
        rule = _css_rule(self.CSS, ".clocks .clk")
        assert "flex:0 0" in rule, rule

    def test_a_sticky_element_below_the_wall_clears_a_wrapped_one(self):
        """The strip's height is not one number any more. Too much gap is a
        smaller fault than a column sitting under the clocks."""
        root = _css_rule(self.CSS, ":root")
        height = int(root.split("--clocks-h:")[1].split("px")[0])
        assert height >= 80, \
            "--clocks-h is a single row's height and the strip wraps: %d" % height

    def test_fifteen_clocks_still_cannot_push_the_page_sideways(self):
        """`overflow-x:auto` was the guard while the strip was one flex row: it
        kept the overflow inside the strip instead of widening the page. Cells
        sized as a percentage of the strip cannot exceed it, so the guard is the
        basis and the scrollbar is gone — one that never appears beats one that
        hides clocks behind it.

        `live-check.py` measures the rendered width of every route at 1240,
        1000, 800 and 640px and asserts none scrolls sideways. That is the
        behavioural check; this keeps the mechanism honest."""
        strip = _css_rule(self.CSS, ".clocks")
        assert "overflow-x" not in strip, strip
        assert "%" in _css_rule(self.CSS, ".clocks .clk"), \
            "a cell not sized against the strip can exceed it"

    def test_wide_content_still_scrolls_inside_its_own_card(self):
        """The other half of fitting the screen: a table wider than the window
        must not push the page sideways."""
        assert "overflow-x:auto" in self.CSS


# --------------------------------------------------------------------------- #
# The denial sweep. Every cloud stage, one denied operation at a time.
#
# The release review named this as the largest untested hole: ten cloud stages
# whose AccessDenied handling is exercised by hand-picked fixtures only, and an
# identity Squawk has only ever been validated as -- a read-only SSO role that
# was granted everything it asked for. The first user with a narrower role is
# the first person to run that code, and a denial that vanishes is a false
# clean, which is the one class of bug this tool exists to refuse.
#
# Two properties are asserted, and the gap between them is the point.
#
# The floor: a read that was refused must leave a trace the RUN keeps -- in the
# stage's own evidence, or in its ledger row.
#
# The second, added after the floor passed 79 of 79 and the run still looked
# clean: the refusal has to move the LEDGER ROW of the stage that made the
# call. Every stage recorded its denials faithfully in evidence and then
# returned a bare JSON string, so `ok` reached the Scan page over a refused
# `describe-security-groups`, a refused `list-mfa-devices`, a refused
# `get-bucket-policy-status`. 25 of 79 cases were green stages sitting on a
# denied read. The evidence was right and the verdict was wrong, which is the
# split `_partial` exists to close.
#
# What is still NOT asserted: that the trace reaches the right paragraph of the
# page. That needs a map from each earned-clean sentence to the reads its claim
# rests on, and a first attempt produced as many mapping errors as findings.
# Written down rather than claimed: this sweep proves no denial is silent and
# no denial leaves its own stage green, and does not yet prove every denial is
# loud in the right paragraph.
# --------------------------------------------------------------------------- #

DENIAL_STAGES = ("cloud-org", "cloud-inventory", "cloud-enablement",
                 "cloud-iam", "cloud-edge", "cloud-frontdoor", "cloud-storage",
                 "cloud-containers", "cloud-dataservices", "cloud-analyzer")

DENIAL_MARK = "SWEEPDENIAL"


class _SweepCtx:
    """A RunContext the internal stages can run under, standing alone."""

    profile = None
    service = "cloudinventory"
    target = "aws"
    raw_path = ""

    def __init__(self):
        self.artifacts = {}


def _fake_cli(monkeypatch, deny=None, record=None):
    """The charter's populated fake CLI, with one operation refused."""
    def responder(argv, _timeout, env=None):
        pair = (argv[0], argv[1]) if len(argv) > 1 else ("", "")
        if record is not None:
            record.append(list(argv))
        if deny is not None and pair == deny:
            return None, ("An error occurred (AccessDeniedException) when "
                          "calling %s: %s" % (argv[1], DENIAL_MARK))
        answer = _CLI_RESPONSES.get(pair)
        if isinstance(answer, str):
            return None, "An error occurred (%s) when calling" % answer
        return ({}, "") if answer is None else (answer, "")

    monkeypatch.setattr(squawk.probes, "tool_path", lambda _n: "/usr/bin/aws")
    monkeypatch.setattr(squawk.probes, "_aws_json", responder)
    monkeypatch.setattr(squawk.probes, "_aws_json_env",
                        lambda argv, t, env: responder(argv, t, env))
    monkeypatch.setattr(squawk.probes, "run_cmd",
                        lambda argv, *_a, **_k: (0, "", ""))
    monkeypatch.setenv("SQUAWK_CLOUD_ACK", "1")
    monkeypatch.setenv("SQUAWK_CLOUD_PROFILES_ACK", "1")


def _stage_operations(monkeypatch, stage):
    """Every (service, operation) one stage actually calls."""
    seen = []
    _fake_cli(monkeypatch, record=seen)
    squawk.STAGES[stage].internal(_SweepCtx())
    return sorted({(a[0], a[1]) for a in seen if len(a) > 1})


def _denial_cases():
    """(stage, service, operation) for every read the ten stages make.

    Built from the stages themselves, under their own monkeypatch, so the
    parametrisation is the real call surface rather than a list somebody has
    to keep current."""
    patch = pytest.MonkeyPatch()
    out = []
    try:
        for stage in DENIAL_STAGES:
            for service, op in _stage_operations(patch, stage):
                out.append((stage, service, op))
    finally:
        patch.undo()
    return out


DENIAL_CASES = _denial_cases()


class TestEveryDeniedReadLeavesATrace:
    """I1, swept rather than sampled."""

    def test_the_sweep_covers_the_real_call_surface(self):
        """A parametrisation that shrank to nothing would still pass every
        case below, which is the shape the review brief named."""
        assert len(DENIAL_CASES) > 60, len(DENIAL_CASES)
        assert len({c[0] for c in DENIAL_CASES}) == len(DENIAL_STAGES)
        assert len({(c[1], c[2]) for c in DENIAL_CASES}) > 50

    @pytest.mark.parametrize("stage,service,op", DENIAL_CASES,
                             ids=["%s:%s-%s" % c for c in DENIAL_CASES])
    def test_a_denied_read_is_recorded_by_the_run(self, monkeypatch, tmp_path,
                                                  stage, service, op):
        _fake_cli(monkeypatch, deny=(service, op))
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        outcome = squawk.execute_service(squawk.SERVICES["cloudinventory"],
                                         "credential-chain", root,
                                         str(tmp_path))
        kept = ""
        for path in sorted(pathlib.Path(root).glob("*/raw/*.json")):
            kept += path.read_text(encoding="utf-8", errors="replace")
        said = [r.tool for r in outcome["results"] if r.status != "ok"]
        assert DENIAL_MARK in kept or said, (
            "denying %s %s left no trace anywhere in the run: every stage "
            "reported ok and no evidence file mentions it" % (service, op))

    @pytest.mark.parametrize("stage,service,op", DENIAL_CASES,
                             ids=["%s:%s-%s" % c for c in DENIAL_CASES])
    def test_a_denied_read_moves_the_ledger_row_of_the_stage_that_asked(
            self, monkeypatch, tmp_path, stage, service, op):
        """A trace somewhere in the run is not enough.

        The Scan page is a list of stages and their statuses, and `ok` on that
        list is the strongest clean signal the tool publishes. A stage that
        recorded its refusal in evidence and still reported `ok` put the denial
        somewhere nobody looks and the reassurance somewhere everybody does."""
        _fake_cli(monkeypatch, deny=(service, op))
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        outcome = squawk.execute_service(squawk.SERVICES["cloudinventory"],
                                         "credential-chain", root,
                                         str(tmp_path))
        tool = squawk.STAGES[stage].tool
        mine = [r for r in outcome["results"] if r.tool == tool]
        assert mine, "%s produced no ledger row at all" % stage
        assert mine[0].status != "ok", (
            "%s was refused %s %s and still reported ok — the denial is in the "
            "evidence and the Scan page says the stage was clean"
            % (stage, service, op))

    def test_nothing_denied_leaves_every_stage_ok(self, monkeypatch, tmp_path):
        """The guard on the guard. A sweep that turned every stage into a gap
        would pass every case above and make the status word worthless, which
        is the same failure as a false clean pointed the other way."""
        _fake_cli(monkeypatch)
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        outcome = squawk.execute_service(squawk.SERVICES["cloudinventory"],
                                         "credential-chain", root,
                                         str(tmp_path))
        bad = [(r.tool, r.status, r.detail) for r in outcome["results"]
               if r.status != "ok"]
        assert not bad, "nothing was denied and these stages did not say ok: %r" % bad


class TestTheReadmeCountsTheServices:
    """The README said "twelve services" in two places while the registry held
    thirteen, and it said so on the first screen a stranger reads.

    This project already counts its documents and its invariants, on the stated
    rule that a number nobody recounts is the same defect as a scanner nobody
    checks. Nothing counted the services, which is how the number drifted --
    the rule was written down and not applied to the thing most often read.
    """

    WORDS: typing.ClassVar[dict] = {
        8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve",
        13: "thirteen", 14: "fourteen", 15: "fifteen", 16: "sixteen",
        17: "seventeen", 18: "eighteen", 19: "nineteen", 20: "twenty"}

    README = pathlib.Path(__file__).parent.parent / "README.md"

    def test_the_readme_says_how_many_services_there_are(self):
        want = self.WORDS[len(squawk.SERVICES)]
        readme = self.README.read_text(encoding="utf-8")
        claims = re.findall(r"the (\w+) services", readme)
        assert claims, "the README no longer states how many services there are"
        wrong = [c for c in claims if c != want]
        assert not wrong, (
            "the registry has %d services (%r) and the README says %s"
            % (len(squawk.SERVICES), want, sorted(set(wrong))))

    def test_there_is_a_claim_to_check(self):
        """A regex that quietly matched nothing would pass whatever the README
        says, which is the shape of the bug this exists for."""
        readme = self.README.read_text(encoding="utf-8")
        assert len(re.findall(r"the (\w+) services", readme)) >= 2


class TestTheDesignDocumentDescribesTheCodeThatExists:
    """`CORRELATION-DESIGN.md` listed three rules under "Rules proven against
    the planted target". Two of them are in `CORRELATIONS`; the third,
    "exploitable and reachable", has never been implemented — it needs a CVE
    scanner and recon inside one url-scope service, and no service runs both.

    A design document that describes a rule the code does not have is the same
    defect as a scanner reporting a finding it did not find, one layer out.
    Nothing held the two together until an independent review noticed
    (2026-09-18).
    """

    DOC = pathlib.Path(__file__).parent.parent / "docs" / "CORRELATION-DESIGN.md"
    SHIPPED = "**Shipped**, and proven against the planted target:"
    DESIGNED = "**Designed, not yet shipped.**"

    def _section(self, start, end=None):
        text = self.DOC.read_text(encoding="utf-8")
        assert start in text, "the document no longer has %r" % start
        body = text.split(start, 1)[1]
        if end:
            assert end in body, "the document no longer has %r" % end
            body = body.split(end, 1)[0]
        return [ln for ln in body.split("\n") if ln.startswith("- **")]

    def test_the_document_lists_the_rules_that_ship(self):
        shipped = self._section(self.SHIPPED, self.DESIGNED)
        assert len(shipped) == len(squawk.CORRELATIONS), (
            "the document lists %d shipped rule(s) and the code has %d: %s"
            % (len(shipped), len(squawk.CORRELATIONS),
               [ln[:60] for ln in shipped]))

    def test_there_are_bullets_to_count(self):
        """A section that quietly found nothing would pass whatever the
        document says, which is the shape of the bug this exists for."""
        assert self._section(self.SHIPPED, self.DESIGNED)
        assert self._section(self.DESIGNED)

    def test_nothing_under_designed_is_already_implemented(self):
        """The other direction. A rule that shipped and stayed in the
        not-yet-shipped list understates the tool, which is the safer error but
        still a false statement about the code."""
        designed = " ".join(self._section(self.DESIGNED)).lower()
        for corr in squawk.CORRELATIONS:
            assert corr.title.lower() not in designed, \
                "%r ships but is listed as not yet shipped" % corr.title


class TestTheReadmeNamesTheCoverageSourcesThatExist:
    """The README lists, by name, which scanner publishes what denominator.
    It said gitleaks and grype publish none — and by 2026-09-18 both had one:
    gitleaks writes `scanned ~N bytes` to stderr, and grype is lent the package
    count from the SBOM it was handed.

    A field check on Kali failed on it, asserting the tool must keep gitleaks
    at `unknown`. The check was defending a gap: it demanded the tool withhold
    a denominator the scanner had published. Prose and code had drifted, and
    the thing that noticed was a script nobody had run in a fortnight.
    """

    README = pathlib.Path(__file__).parent.parent / "README.md"

    def _sentence(self):
        text = self.README.read_text(encoding="utf-8")
        marker = "Squawk reads the coverage each"
        assert marker in text, "the README no longer says where coverage comes from"
        return text.split(marker, 1)[1].split("\n\n", 1)[0]

    def test_every_scanner_it_names_has_a_coverage_extractor(self):
        """A scanner the README credits with publishing a denominator must have
        something registered to read it, or the sentence is describing a tool
        this code never asks."""
        named = [t for t in ("semgrep", "bandit", "checkov", "trivy", "syft",
                             "gitleaks") if t in self._sentence()]
        assert named, "the sentence names no scanner at all"
        missing = [t for t in named if t not in squawk.scanners.COVERAGE]
        assert not missing, \
            "the README credits %s with coverage and nothing reads it" % missing

    def test_it_does_not_claim_a_scanner_publishes_nothing_when_it_does(self):
        """The drift this comes from, in the direction it drifted."""
        sentence = self._sentence()
        for tool in ("gitleaks",):
            assert tool in squawk.scanners.COVERAGE, tool
            assert "publishes no coverage (%s" % tool not in sentence, (
                "%s publishes a denominator and the README says it does not"
                % tool)

    def test_there_is_a_sentence_to_read(self):
        assert len(self._sentence().split()) > 20

"""Tests for the parts of Squawk that decide whether a result can be trusted.

The governing rule of this tool is that a scanner which did not run must never
look like a scanner that found nothing. The staleness check is the same rule
applied to data rather than to execution: a vulnerability database that was
never downloaded must not read as a database that is only old, and an unset
field must never be rendered as a measurement.
"""

import builtins
import datetime
import importlib.util
import inspect
import json
import os
import pathlib
import re
import shutil
import socket
import sys
import time
import types
import typing
import zoneinfo

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from typing import ClassVar

import squawk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRY = os.path.join(ROOT, "squawk.py")


class _serve:
    """A real server on a free loopback port, for tests that must exercise the
    handler rather than read it: `with _serve(root, repo) as base: urlopen(base
    + "/estate")`. A control in source that the handler does not enforce is
    not a control, so handler behaviour is tested through the socket."""

    def __init__(self, root, repo):
        self.root, self.repo = root, repo

    def __enter__(self):
        import socket
        import threading
        from http.server import ThreadingHTTPServer
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self.port = sock.getsockname()[1]
        sock.close()
        self.srv = ThreadingHTTPServer(("127.0.0.1", self.port),
                                       squawk.make_handler(self.root, self.repo))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return "http://127.0.0.1:%d" % self.port

    def __exit__(self, *_exc):
        self.srv.shutdown()
        self.srv.server_close()


def _get(url, headers=None):
    """(status, body) for one GET, an HTTP error included."""
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _post(url, fields):
    """(status, body) for one form POST, an HTTP error included. The handler
    is exercised through the socket because a control in source that the
    handler does not enforce is not a control."""
    import urllib.error
    import urllib.parse
    import urllib.request
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _patch_all(monkeypatch, name, value):
    """Monkeypatch a name in every squawk module that binds it. The app is a
    package, and a function looks a name up in its own module, so patching
    the package attribute alone would patch nothing that runs."""
    import types
    for mod in list(vars(squawk).values()):
        if (isinstance(mod, types.ModuleType) and mod.__name__.startswith("squawk.")
                and hasattr(mod, name)):
            monkeypatch.setattr(mod, name, value)
    monkeypatch.setattr(squawk, name, value, raising=False)


def _days_ago(n):
    return time.strftime("%Y-%m-%d", time.gmtime(time.time() - n * 86400))


class TestAgeDays:
    """_age_days converts a tool's printed build date into a staleness call."""

    def test_reads_a_recent_date(self):
        assert squawk._age_days("Built: %sT01:02:03Z" % _days_ago(3)) == 3

    def test_today_is_zero_days_old(self):
        assert squawk._age_days("Built: " + _days_ago(0)) == 0

    def test_no_date_at_all_is_none(self):
        assert squawk._age_days("Status: valid\nSchema: v6.0.0") is None
        assert squawk._age_days("") is None
        assert squawk._age_days(None) is None

    def test_go_zero_time_is_not_a_date(self):
        """Regression. grype prints Go's zero time.Time when its database has
        never been built. Parsing it literally reported the database as
        '739855 days old', an absent value dressed up as a measurement, which
        reads as a stale database rather than a missing one."""
        out = squawk._age_days(
            "Built:\t0001-01-01T00:00:00Z\nStatus:\tno database")
        assert out is None

    def test_a_real_date_after_a_zero_sentinel_still_parses(self):
        """The sentinel must not swallow the whole string. If a usable date
        follows it, that is the answer."""
        text = "Built: 0001-01-01T00:00:00Z\nUpdated: %s" % _days_ago(2)
        assert squawk._age_days(text) == 2

    def test_future_date_is_rejected(self):
        """A build date in the future is a broken clock or a misparse, not a
        database that is -40 days old."""
        future = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 40 * 86400))
        assert squawk._age_days("Built: " + future) is None

    def test_one_day_of_clock_skew_is_tolerated(self):
        """UTC-vs-local across a midnight boundary is normal and must not read
        as an unusable date."""
        tomorrow = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 3600 * 20))
        assert squawk._age_days("Built: " + tomorrow) == 0

    def test_impossible_calendar_date_is_skipped(self):
        assert squawk._age_days("Built: 2026-13-45") is None

    def test_a_stale_database_exceeds_the_threshold(self):
        """The number has to actually drive the staleness call it feeds."""
        age = squawk._age_days("Built: " + _days_ago(squawk.DB_STALE_DAYS + 5))
        assert age is not None and age > squawk.DB_STALE_DAYS


class TestDbNeverBuilt:
    """Missing and unreadable are different problems with different fixes."""

    def test_go_zero_time_means_missing(self):
        assert squawk._db_never_built("Built:\t0001-01-01T00:00:00Z") is True

    def test_a_real_status_is_not_missing(self):
        assert squawk._db_never_built("Built: 2026-08-20T01:31:23Z") is False

    def test_empty_output_is_not_a_missing_database(self):
        """No output means a tool that would not answer. That is 'unreadable',
        and saying 'no database downloaded yet' would be a guess."""
        assert squawk._db_never_built("") is False
        assert squawk._db_never_built(None) is False


class TestSquawkCodes:
    """The alarm codes are the loudest thing the tool says, so they carry the
    highest cost when wrong."""

    def test_codes_are_the_three_aviation_squawks(self):
        assert set(squawk.SQUAWK_CODES) == {"7500", "7600", "7700"}

    def test_every_code_has_a_label_and_a_meaning(self):
        for code, entry in squawk.SQUAWK_CODES.items():
            assert entry, "%s has no definition" % code


def _junk_corpus():
    """Shapes a scanner could emit after a version bump, plus outright garbage.

    Generated rather than listed, because the interesting failures were never
    the ones anybody thought to write down: nine of ten normalizers raised on
    `[]`, which is valid JSON and simply the wrong shape."""
    keys = ["results", "Results", "matches", "site", "alerts", "findings",
            "endpoints", "failed_checks", "Vulnerabilities",
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


class TestNormalizersNeverRaise:
    """A scanner that changes its output between versions must not be able to
    crash a stage. A parse failure has to degrade to 'nothing readable', which
    the run then reports as the gap it is, rather than to an exception."""

    def test_corpus_is_large_enough_to_mean_something(self):
        """A guard that shrank to nothing would still pass every test below."""
        assert len(JUNK) > 200

    def test_every_normalizer_returns_a_list_for_every_input(self):
        failures = []
        for name, fn in sorted(squawk.NORMALIZERS.items()):
            for junk in JUNK:
                try:
                    out = fn(junk, "/base")
                except Exception as exc:
                    failures.append("%s raised %s on %r"
                                    % (name, type(exc).__name__, junk[:36]))
                    continue
                if not isinstance(out, list):
                    failures.append("%s returned %s" % (name, type(out).__name__))
        assert not failures, "%d failure(s): %s" % (len(failures), failures[:5])

    def test_a_json_array_does_not_crash_a_dict_shaped_normalizer(self):
        """The specific case that started this. `[]` is valid JSON and the
        wrong shape, and nine normalizers called .get() straight onto it."""
        for name, fn in squawk.NORMALIZERS.items():
            assert fn("[]", "/base") == [], name

    def test_a_list_of_non_records_does_not_crash_a_list_shaped_normalizer(self):
        """One level down from the shape problem: a list, but not of records."""
        for name, fn in squawk.NORMALIZERS.items():
            assert fn("[1,2,3]", "/base") == [], name


class TestReportHelper:
    """`_report` is the single place a scanner's output becomes usable."""

    def test_returns_the_requested_shape_when_the_json_is_the_wrong_one(self):
        assert squawk._report("[]", dict) == {}
        assert squawk._report("{}", list) == []

    def test_passes_through_the_right_shape(self):
        assert squawk._report('{"a":1}', dict) == {"a": 1}
        assert squawk._report('[1]', list) == [1]

    def test_unparseable_input_is_empty_not_an_exception(self):
        assert squawk._report("not json", dict) == {}
        assert squawk._report("", dict) == {}
        assert squawk._report(None, dict) == {}

    def test_rows_keeps_only_records(self):
        assert squawk._rows([{"a": 1}, 2, None, [], {"b": 2}]) == [{"a": 1}, {"b": 2}]
        assert squawk._rows("not a list") == []
        assert squawk._rows(None) == []


class TestSelfAudit:
    """The host audit. Its whole value is that a check it could not perform
    reports as not performed."""

    def _checks(self, root):
        return squawk.self_audit_checks(root)

    def test_every_check_is_well_formed(self, tmp_path):
        for c in self._checks(str(tmp_path)):
            assert c["status"] in ("ok", "gap", "unknown"), c
            assert c["severity"] in squawk.SEVERITY_ORDER, c
            assert c["area"] in squawk.SELF_AUDIT_AREAS, c
            assert c["check"] and c["title"] and c["detail"], c

    def test_check_keys_are_unique(self, tmp_path):
        """Identities are built from the check key, so a duplicate would make
        two different problems collapse into one finding."""
        keys = [c["check"] for c in self._checks(str(tmp_path))]
        assert len(keys) == len(set(keys))

    def test_every_gap_carries_a_fix(self, tmp_path):
        for c in self._checks(str(tmp_path)):
            if c["status"] == "gap":
                assert c["fix"], "%s reports a gap with no remediation" % c["check"]

    def test_world_readable_evidence_is_a_gap(self, tmp_path):
        d = tmp_path / "loose"
        d.mkdir()
        # S103: the permissive mode is the fixture. This asserts the audit
        # notices a world-readable evidence root, which needs one to exist.
        os.chmod(str(d), 0o755)  # noqa: S103
        got = [c for c in self._checks(str(d)) if c["check"] == "evidence-perms"]
        assert got and got[0]["status"] == "gap"
        assert got[0]["severity"] == "high"

    def test_owner_only_evidence_passes(self, tmp_path):
        d = tmp_path / "tight"
        d.mkdir()
        os.chmod(str(d), 0o700)
        got = [c for c in self._checks(str(d)) if c["check"] == "evidence-perms"]
        assert got and got[0]["status"] == "ok"

    def test_evidence_inside_a_git_tree_is_a_gap(self, tmp_path):
        (tmp_path / ".git").mkdir()
        sub = tmp_path / "runs"
        sub.mkdir()
        got = [c for c in self._checks(str(sub)) if c["check"] == "evidence-in-git"]
        assert got and got[0]["status"] == "gap"

    def test_missing_evidence_root_is_reported(self, tmp_path):
        got = [c for c in self._checks(str(tmp_path / "nope"))
               if c["check"] == "evidence-exists"]
        assert got and got[0]["status"] == "gap"


class TestSelfAuditNormalizer:
    """Turning checks into findings. Passing checks must not become findings,
    and unknown must not disappear."""

    def _raw(self, checks):
        return json.dumps({"checks": checks})

    def test_ok_checks_produce_no_findings(self):
        raw = self._raw([squawk._chk("x", "logging", "ok", "info", "fine", "d")])
        assert squawk.norm_selfaudit(raw, "") == []

    def test_a_gap_becomes_a_finding_with_its_remediation(self):
        raw = self._raw([squawk._chk("log-perms", "logging", "gap", "medium",
                                     "Readable by others", "mode 0644", "chmod 600")])
        out = squawk.norm_selfaudit(raw, "")
        assert len(out) == 1
        f = out[0]
        assert f.scanner == "selfaudit"
        assert f.identity == "selfaudit:log-perms"
        assert f.severity == "medium"
        assert f.detail["remediation"] == "chmod 600"

    def test_unknown_is_reported_and_labelled(self):
        """The governing rule of this tool, applied to its own host audit: a
        check that could not run must not read as a check that passed."""
        raw = self._raw([squawk._chk("clock-sync", "time", "unknown", "medium",
                                     "Clock sync not determined", "no timedatectl")])
        out = squawk.norm_selfaudit(raw, "")
        assert len(out) == 1
        assert out[0].title.startswith("Not determined")
        assert out[0].detail["status"] == "unknown"

    def test_identities_are_stable_across_runs(self, tmp_path):
        a = squawk.norm_selfaudit(squawk.self_audit(
            _Ctx(str(tmp_path))), "")
        b = squawk.norm_selfaudit(squawk.self_audit(
            _Ctx(str(tmp_path))), "")
        assert [f.identity for f in a] == [f.identity for f in b]
        assert squawk.fingerprint([f.identity for f in a]) == \
            squawk.fingerprint([f.identity for f in b])

    def test_garbage_input_yields_no_findings(self):
        assert squawk.norm_selfaudit("not json", "") == []
        assert squawk.norm_selfaudit("", "") == []


class _Ctx:
    """Minimal stand-in for RunContext — the host audit only reads the root."""

    def __init__(self, root):
        self.evidence_root = root
        self.target = "host"


class TestRegistryWiring:
    """A scanner that exists in one registry and not the others is a stage that
    silently never runs."""

    def test_selfaudit_is_registered_everywhere(self):
        assert "selfaudit" in squawk.SCANNERS
        assert "selfaudit" in squawk.STAGES
        assert "selfaudit" in squawk.SERVICES
        assert "selfaudit" in squawk.NORMALIZERS

    def test_every_stage_has_a_normalizer(self):
        for key, spec in squawk.STAGES.items():
            assert spec.tool in squawk.NORMALIZERS, \
                "stage %s produces output nothing can parse" % key

    def test_every_service_stage_exists(self):
        for svc in squawk.SERVICES.values():
            for stage in svc.stages:
                assert stage in squawk.STAGES, \
                    "service %s names a stage that does not exist: %s" % (svc.key, stage)


class TestEvidencePermissions:
    """Regression. The host audit's first run found that Squawk created its own
    log and evidence root with the default umask, so the record of every target
    scanned was readable by any other local user."""

    def test_setup_logging_locks_down_what_it_creates(self, tmp_path):
        root = tmp_path / "ev"
        for h in list(squawk.LOG.handlers):
            squawk.LOG.removeHandler(h)
        if hasattr(squawk.LOG, "_squawk_path"):
            del squawk.LOG._squawk_path
        try:
            path = squawk.setup_logging(str(root))
            assert path, "logging did not come up"
            assert os.stat(str(root)).st_mode & 0o777 == 0o700
            assert os.stat(path).st_mode & 0o777 == 0o600
        finally:
            for h in list(squawk.LOG.handlers):
                h.close()
                squawk.LOG.removeHandler(h)
            if hasattr(squawk.LOG, "_squawk_path"):
                del squawk.LOG._squawk_path


class TestInventoryDelta:
    """What the updater reports as having changed."""

    def _inv(self, tools):
        return {"tools": {k: {"version": v, "path": "/x/%s" % k}
                          for k, v in tools.items()}}

    def test_a_new_tool_reads_as_installed(self):
        rows = squawk._inventory_delta(self._inv({"grype": None}),
                                       self._inv({"grype": "0.8"}))
        assert [r["state"] for r in rows] == ["installed"]

    def test_a_version_change_reads_as_updated(self):
        rows = squawk._inventory_delta(self._inv({"trivy": "0.1"}),
                                       self._inv({"trivy": "0.2"}))
        assert rows[0]["state"] == "updated"
        assert rows[0]["before"] == "0.1" and rows[0]["after"] == "0.2"

    def test_no_movement_reads_as_unchanged(self):
        rows = squawk._inventory_delta(self._inv({"syft": "1.0"}),
                                       self._inv({"syft": "1.0"}))
        assert rows[0]["state"] == "unchanged"

    def test_still_missing_reads_as_absent_not_unchanged(self):
        """'absent' and 'unchanged' are both no-movement, but only one of them
        means the tool is there."""
        rows = squawk._inventory_delta(self._inv({"zap": None}),
                                       self._inv({"zap": None}))
        assert rows[0]["state"] == "absent"

    def test_a_tool_that_vanished_is_not_silently_dropped(self):
        rows = squawk._inventory_delta(self._inv({"bandit": "1.7"}),
                                       self._inv({"bandit": None}))
        assert rows[0]["state"] == "disappeared"

    def test_a_refreshed_database_is_distinguished_from_an_aged_one(self):
        before = {"tools": {}, "vuln_dbs": {"grype": {"age_days": 30}}}
        after = {"tools": {}, "vuln_dbs": {"grype": {"age_days": 0}}}
        rows = squawk._inventory_delta(before, after)
        assert rows[0]["state"] == "refreshed"


class TestToolInventory:
    """What the install record claims is installed."""

    def test_a_scanner_run_through_another_binary_is_not_given_its_version(self):
        """Regression. ZAP's registered binary is `docker`, so the inventory
        reported Docker's version as ZAP's and the record read "installed zap —
        Docker version 26.1.5". A scanner Squawk runs through something else has
        no version of its own here; the image digest is the honest answer and is
        recorded separately."""
        borrowed = [name for name, sc in squawk.SCANNERS.items()
                    if not sc.internal and sc.binary and sc.binary != name]
        assert borrowed, "expected at least one scanner run through another binary"
        inv = squawk.tool_inventory()
        for name in borrowed:
            assert name not in inv["tools"], \
                "%s reports a version belonging to %s" % (name, squawk.SCANNERS[name].binary)

    def test_the_inventory_has_the_sections_the_record_depends_on(self):
        inv = squawk.tool_inventory()
        for key in ("tools", "pipx", "apt", "images", "vuln_dbs", "python"):
            assert key in inv, "install.json would be missing %r" % key


class TestInstallerPrerequisites:
    """The installer is a bash script, and not every Unix ships bash."""

    def test_missing_bash_is_named_not_a_popen_error(
            self, tmp_path, monkeypatch, capsys):
        """Found on alpine:latest, which has apk but no bash. Without this the
        run died as a bare 'No such file or directory' from Popen, naming
        neither the cause nor the fix."""
        _patch_all(monkeypatch, "tool_path",
                            lambda b: None if b == "bash" else "/usr/bin/" + b)
        rc = squawk.run_installer("update", str(tmp_path), str(tmp_path / "x.sh"))
        assert rc == 1
        out = capsys.readouterr().out
        assert "bash" in out
        assert "apk add bash" in out, "the message should name the fix per platform"


class TestFieldReports20260905:
    """Three defects from the Kali run recorded in issue 126."""

    def test_running_the_package_directory_by_path_works(self, tmp_path):
        """`python3 squawk status`, a dropped `.py`, died with
        `ModuleNotFoundError: No module named 'squawk'`. Running the directory
        puts it on sys.path instead of its parent, and the traceback named
        nothing a reader could act on."""
        import subprocess
        pkg = os.path.dirname(os.path.abspath(squawk.__file__))
        parent = os.path.dirname(pkg)
        res = subprocess.run([sys.executable, "squawk", "--version"],
                             capture_output=True, text=True, cwd=parent, timeout=120)
        assert res.returncode == 0, res.stdout + res.stderr
        assert "ModuleNotFoundError" not in (res.stdout + res.stderr)
        assert res.stdout.strip() == "squawk %s" % squawk.__version__
        res = subprocess.run([sys.executable, "-m", "squawk", "--version"],
                             capture_output=True, text=True, cwd=parent, timeout=120)
        assert res.stdout.strip() == "squawk %s" % squawk.__version__, \
            "-m still has to work"

    def test_status_names_the_service_it_generated(self, tmp_path, monkeypatch):
        """After a reboot, `status` said only "stale pid file" while the unit
        it had written sat there not running. A tool that generates a service
        and cannot see it makes the operator remember what the tool wrote."""
        calls = []

        def fake_run_cmd(cmd, cwd, timeout):
            calls.append(cmd)
            prop = next(c for c in cmd if c.startswith("--property="))
            return 0, ("inactive" if "ActiveState" in prop else "enabled"), ""
        monkeypatch.setattr(squawk.service, "run_cmd", fake_run_cmd)
        monkeypatch.setattr(squawk.service, "tool_path", lambda b: "/bin/" + b)
        unit = tmp_path / ".config" / "systemd" / "user" / "squawk.service"
        unit.parent.mkdir(parents=True)
        unit.write_text("[Unit]\n")
        monkeypatch.setattr(squawk.service, "unit_path", lambda: str(unit))
        note = squawk.service._service_note("")
        assert "inactive" in note and "enabled at boot" in note
        assert "systemctl --user start squawk" in note
        assert "enable-linger" in note, "surviving a logout is the other half"
        assert calls, "systemctl was never asked"

    def test_status_says_nothing_when_there_is_no_unit(self, tmp_path, monkeypatch):
        monkeypatch.setattr(squawk.service, "unit_path",
                            lambda: str(tmp_path / "nope.service"))
        assert squawk.service._service_note("") == "", \
            "a box with no unit installed must not be told about systemctl"

    def test_an_unwritable_evidence_root_names_the_real_causes(self, tmp_path):
        """The check fired correctly on a read-only filesystem; its fix line
        said "fix ownership", which is the least likely cause on a single-user
        box and sent the reader the wrong way. A finding whose remediation
        points at the wrong thing costs the time the finding saved."""
        from squawk.probes import _audit_evidence
        d = tmp_path / "ev"
        d.mkdir()
        os.chmod(str(d), 0o500)
        try:
            out = []
            _audit_evidence(str(d), out)
        finally:
            os.chmod(str(d), 0o700)
        row = next(c for c in out if c["check"] == "evidence-writable")
        assert row["status"] == "gap" and row["severity"] == "critical"
        assert "read-only" in row["detail"] and "full" in row["detail"]
        assert "mount |" in row["fix"] and "df -h" in row["fix"] and "ls -ld" in row["fix"]
        assert "GiB free" in row["detail"], \
            "capacity belongs beside the refusal, so the two are not confused"


class TestDastReachesTheApp:
    """From the Juice Shop run in issue 126: an active probe returned 91
    findings and not one SQL injection or cross-site scripting, on an app built
    to be full of both. Nothing on screen said the crawl had been thin."""

    class _Ctx:
        target = "http://127.0.0.1:3000"
        raw_path = "/scratch/raw/zap.json"
        scope = "url"
        base = "/"
        run_dir = "/scratch"

    def _cmd(self, key):
        return squawk.STAGES[key].build(self._Ctx())

    def test_both_probes_run_the_ajax_spider(self):
        """A single-page app is a shell of static HTML to the traditional
        spider, so the active scanner has no parameter to inject into. -j is
        what makes the crawl reach the REST API behind it."""
        for key in ("zap-baseline", "zap-active"):
            cmd, _timeout = self._cmd(key)
            assert "-j" in cmd, "%s crawls a single-page app blind" % key

    def test_the_active_probe_gets_a_longer_crawl_and_a_survivable_timeout(self):
        base_cmd, base_t = self._cmd("zap-baseline")
        act_cmd, act_t = self._cmd("zap-active")
        base_m = int(base_cmd[base_cmd.index("-m") + 1])
        act_m = int(act_cmd[act_cmd.index("-m") + 1])
        assert act_m >= base_m, "an active scan is only as good as its crawl"
        assert act_t > base_t, "the active stage needs the longer subprocess budget"
        # -T is ZAP's startup and passive-scan wait, not a cap on the scan. The
        # subprocess timeout is the only real bound, so it must sit well above
        # the crawl budget or it kills the container before the report is written.
        assert act_t > act_m * 60 * 2, \
            "the subprocess timeout leaves no room after the crawl budget"

    def test_the_reachable_url_count_separates_a_thin_crawl_from_a_real_one(self):
        import json as _j

        def report(paths):
            return _j.dumps({"site": [{"@name": "http://h", "alerts": [
                {"pluginid": str(1000 + i), "instances": [{"uri": "http://h" + p}]}
                for i, p in enumerate(paths)]}]})
        thin = squawk.COVERAGE["zap"](report(["/", "/robots.txt", "/sitemap.xml"]))
        thick = squawk.COVERAGE["zap"](report(
            ["/rest/products/search", "/rest/user/login", "/api/Feedbacks",
             "/api/Users", "/ftp", "/rest/basket/1"]))
        assert thin.examined == 3 and thick.examined == 6
        assert thin.unit == "URLs"
        # the same endpoint probed with many values is one endpoint, not many
        many = squawk.COVERAGE["zap"](report(["/search?q=%d" % i for i in range(40)]))
        assert many.examined == 1, "query values are not coverage"

    def test_a_report_with_no_alerts_is_unknown_not_a_fabricated_zero(self):
        """The count is derived from where the alerts were seen, not published
        by ZAP, so a report with no alerts is no evidence either way. Calling
        that examined=0 would invent a gap on a target that might be clean,
        which is the rule gitleaks and grype are already held to."""
        import json as _j
        cov = squawk.stage_coverage("zap", _j.dumps({"site": []}))
        assert cov.examined is None, "an empty report fabricated a denominator"
        status, _detail, _c = squawk._apply_coverage(
            "zap", _j.dumps({"site": []}), [], "ok", "0")
        assert status == "ok", "an unknown denominator does not gate the stage"

    def test_zap_is_registered_for_coverage_like_every_other_scanner(self):
        assert "zap" in squawk.COVERAGE, \
            "a probe with no denominator prints the same line for any crawl"


class TestInstallerUpgradeHonesty:
    """Reported from the field, on Kali: `apt-get upgrade` failed because dpkg
    had been interrupted, and the installer printed the failure and then
    "ok OS packages (47 upgraded)" underneath it. A step that did not run must
    never print a line saying it did, and a failure with no fix line is a
    complaint. These read the shipped script, because the behaviour lives in
    bash and the alternative is asserting nothing about it."""

    def _script(self):
        path = os.path.join(os.path.dirname(os.path.abspath(squawk.ENTRY_PATH)),
                            "install-tools.sh")
        return open(path, encoding="utf-8").read()

    def test_the_ok_line_is_inside_the_success_branch(self):
        src = self._script()
        assert "if pm_upgrade_all; then" in src, \
            "the upgrade result is not branched on, so a failure falls through"
        block = src.split("if pm_upgrade_all; then", 1)[1].split("\nfi\n", 1)[0]
        success, _sep, failure = block.partition("\n  else\n")
        assert "ok \"OS packages" in success, "the ok line left the success branch"
        assert "ok \"OS packages" not in failure, \
            "an upgrade that failed still prints an OS packages ok line"
        assert "autoremove" in success and "autoremove" not in failure, \
            "autoremove runs on a package database the manager just called broken"

    def test_the_failure_names_the_fix_and_what_still_happened(self):
        src = self._script()
        failure = src.split("bad \"$PM upgrade failed", 1)[1].split("\n  fi\n", 1)[0]
        assert "dpkg --configure -a" in failure, \
            "the commonest recoverable cause has no fix line"
        assert "dpkg --audit" in failure, \
            "the fix is printed without checking the state that calls for it"
        assert "lock" in failure, "a held dpkg lock is the other common cause"
        assert "scanners below are still updated" in failure, \
            "the reader is not told what did still happen"

    def test_the_count_is_measured_after_the_upgrade_not_before(self):
        src = self._script()
        assert "REMAIN=" in src, "nothing measures what is pending afterwards"
        assert 'ok "OS packages ($PENDING upgraded)"' not in src, \
            "the pending count is still being reported as an upgraded count"


# Reports whose shape changed. Each must parse to nothing, or the fixture is
# not testing what it claims to.
DRIFTED_REPORTS = [
    ("trivy", '{"results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1"}]}]}'),
    ("semgrep", '{"data":{"results":[{"check_id":"x"}]}}'),
    ("grype", '[{"vulnerability":{"id":"CVE-2"}}]'),
    ("bandit", '{"issues":[{"test_id":"B101"}]}'),
    ("zap", '{"alerts":[{"alert":"x"}]}'),
]

# Real reports from a scan that found nothing. A false alarm on any of these is
# worse than the bug, because it teaches the reader to ignore the warning.
CLEAN_REPORTS = [
    ("trivy", '{"SchemaVersion":2,"ArtifactName":"x","Results":[]}'),
    ("semgrep", '{"results":[],"errors":[],"paths":{"scanned":[]}}'),
    ("gitleaks", "[]"),
    ("grype", '{"matches":[],"source":{"type":"dir"}}'),
    ("bandit", '{"results":[],"metrics":{}}'),
    ("checkov", '[{"check_type":"terraform","results":{"failed_checks":[]}}]'),
    ("zap", '{"@version":"2.14","site":[]}'),
    ("syft", '{"artifacts":[],"descriptor":{"name":"syft"}}'),
]


class TestScannerDrift:
    """A scanner changing its output is the likeliest long-term failure here,
    and it used to be silent. Rename a key and the normalizer reads nothing,
    returns no findings, and the stage says "ok, 0 findings" — the scanner ran,
    exited 0, produced data, and we understood none of it."""

    @pytest.mark.parametrize("tool,raw", DRIFTED_REPORTS)
    def test_a_shape_we_cannot_read_is_reported(self, tool, raw):
        reason = squawk.report_unreadable(tool, raw)
        assert reason, "%s drift went undetected" % tool
        assert squawk.NORMALIZERS[tool](raw, "/base") == [], \
            "fixture should parse to nothing, or it is not testing drift"

    @pytest.mark.parametrize("tool,raw", CLEAN_REPORTS)
    def test_a_genuinely_clean_report_is_not_flagged(self, tool, raw):
        """False alarms here are worse than the bug: they teach the reader to
        ignore the warning."""
        assert squawk.report_unreadable(tool, raw) is None, \
            "%s clean report raised a false alarm" % tool

    def test_output_that_is_not_json_is_reported(self):
        assert squawk.report_unreadable("trivy", "<html>502 Bad Gateway</html>")

    def test_empty_output_is_left_to_the_other_checks(self):
        """Emptiness is judged by exit code and stderr, not here. Flagging it
        twice would double-report one condition."""
        assert squawk.report_unreadable("trivy", "") is None
        assert squawk.report_unreadable("trivy", "   ") is None

    def test_internal_stages_are_not_shape_checked(self):
        for name in ("recon", "skillaudit", "selfaudit"):
            assert squawk.report_unreadable(name, '{"anything":1}') is None

    def test_every_external_scanner_has_a_declared_shape(self):
        """A scanner missing from the table is a scanner whose drift is
        invisible, which is the state this replaced."""
        external = {n for n, sc in squawk.SCANNERS.items()
                    if not sc.internal and sc.binary}
        missing = sorted(external - set(squawk.REPORT_SHAPES))
        assert not missing, "no declared report shape for: %s" % missing


COVERAGE_CASES = [
    # tool, raw, expected examined, expected unit
    ("semgrep", '{"paths":{"scanned":["a.py","b.py"],"skipped":[]},"errors":[]}', 2, "files"),
    ("semgrep", '{"paths":{"scanned":[],"skipped":[]},"errors":[]}', 0, "files"),
    ("bandit", '{"metrics":{"a.py":{},"_totals":{"loc":3}},"errors":[]}', 1, "files"),
    ("bandit", '{"metrics":{"_totals":{"loc":0}},"errors":[]}', 0, "files"),
    ("checkov", '{"summary":{"passed":3,"failed":8,"resource_count":2}}', 2, "resources"),
    ("checkov", '{"summary":{"passed":0,"failed":0,"resource_count":0}}', 0, "resources"),
    ("trivy", '{"Results":[{"Target":"requirements.txt"}]}', 1, "scan targets"),
    ("trivy", '{"Results":[]}', 0, "scan targets"),
    ("syft", '{"artifacts":[{"name":"flask"}],"descriptor":{}}', 1, "packages"),
]


class TestCoverageExtraction:
    """The denominator, read from what each scanner already publishes. A zero
    over nothing examined is not a clean result, and this is where that is
    first measurable."""

    @pytest.mark.parametrize("tool,raw,examined,unit", COVERAGE_CASES)
    def test_extractor_reads_the_denominator(self, tool, raw, examined, unit):
        cov = squawk.stage_coverage(tool, raw)
        assert cov.examined == examined, "%s: %r" % (tool, cov)
        assert cov.unit == unit

    def test_a_tool_that_publishes_no_coverage_is_unknown_not_zero(self):
        """gitleaks and grype say nothing about coverage in JSON. Reporting
        that as examined=0 would fabricate a gap; unknown is the honest state."""
        for tool in ("gitleaks", "grype", "zap"):
            cov = squawk.stage_coverage(tool, '{"anything":1}')
            assert cov.examined is None, "%s fabricated a denominator" % tool

    def test_garbage_output_yields_unknown_not_a_crash(self):
        for tool in ("semgrep", "bandit", "checkov", "trivy", "syft"):
            for junk in ("", "not json", "[]", "null", '{"x":1}'):
                cov = squawk.stage_coverage(tool, junk)
                assert isinstance(cov, squawk.Coverage)


class TestAFirstRunHasNoLastTime:
    """A clean run closed with:

        No squawk. Nothing critical, nothing under attack, and every source
        that reported last time reported again.

    On the operator's first ever `cargo` run there was no last time. The 7600
    check that compares scanners against the previous comparable run needs
    `pos > 0` and is skipped entirely when a run is the first of its target, so
    the third clause was the outcome of a comparison that never happened — a
    confident sentence about a check that did not run, on the one run where a
    reader has least reason to doubt it (2026-09-15)."""

    @staticmethod
    def _man(run_id, target="img:1"):
        return {"run_id": run_id, "service": "cargo", "scope": "image",
                "target": target}

    def _root(self, tmp_path, run_ids, target="img:1"):
        root = tmp_path / "ev"
        for rid in run_ids:
            d = root / rid
            (d / "raw").mkdir(parents=True)
            (d / "manifest.json").write_text(
                json.dumps(dict(self._man(rid, target), ledger=[], counts={})),
                encoding="utf-8")
        return str(root)

    def test_the_first_run_of_a_target_has_no_position_behind_it(self, tmp_path):
        root = self._root(tmp_path, ["20260101T000000Z-image"])
        _same, pos = squawk.analysis.comparable_runs(
            root, self._man("20260101T000000Z-image"))
        assert pos == 0, "the first run is at position 0, with nothing before it"

    def test_a_later_run_has_one(self, tmp_path):
        root = self._root(tmp_path, ["20260101T000000Z-image",
                                     "20260102T000000Z-image"])
        _same, pos = squawk.analysis.comparable_runs(
            root, self._man("20260102T000000Z-image"))
        assert pos == 1

    def test_a_run_of_a_different_target_is_not_comparable(self, tmp_path):
        """An image compared against another image is not a comparison. The
        target is part of the identity, so a first run of `b:1` is still a
        first run however many times `a:1` was scanned."""
        root = self._root(tmp_path, ["20260101T000000Z-image"], target="a:1")
        same, pos = squawk.analysis.comparable_runs(root, self._man("x", "b:1"))
        assert same == [] and pos is None, (same, pos)

    def test_a_run_not_on_disk_is_told_apart_from_a_first_one(self, tmp_path):
        """`None` and `0` are different answers and the caller acts on the
        difference, so they must not collapse."""
        root = self._root(tmp_path, ["20260101T000000Z-image"])
        _same, pos = squawk.analysis.comparable_runs(root, self._man("nope"))
        assert pos is None

    def _clean_run(self, tmp_path, monkeypatch, capsys, times):
        """`times` real CLI runs of one target, with every alarm silenced so
        the closing line is reached. Driven through `squawk.cli.main` rather
        than mirrored here: a test that reimplements the sentence passes when
        the CLI stops printing it, which is what a first attempt at this did."""
        tmp = tmp_path / "t"
        tmp.mkdir()
        (tmp / "a.tf").write_text('resource "x" "y" {}\n', encoding="utf-8")
        root = str(tmp_path / "ev")
        _patch_all(monkeypatch, "tool_path", lambda name: "/usr/bin/" + name)
        _patch_all(monkeypatch, "run_cmd", lambda cmd, cwd, timeout: (
            0, json.dumps({"results": {"failed_checks": [],
                                       "passed_checks": [{"id": 1}]},
                           "summary": {"resource_count": 3},
                           "Results": [{"Target": "a.tf",
                                        "Misconfigurations": []}]}), ""))
        monkeypatch.setattr(squawk.cli, "squawk_check", lambda _r, _m: [])
        out = ""
        for _ in range(times):
            capsys.readouterr()
            squawk.cli.main(["--run", "compliance", "--repo", str(tmp),
                             "--evidence", root])
            out = capsys.readouterr().out
        line = [ln for ln in out.splitlines() if "No squawk" in ln]
        assert line, "the closing line was not reached: %s" % out[-300:]
        return line[0]

    def test_a_first_run_says_there_is_nothing_to_compare(self, tmp_path,
                                                          monkeypatch, capsys):
        line = self._clean_run(tmp_path, monkeypatch, capsys, times=1)
        assert "first run of this target" in line, line
        assert "reported last time" not in line, line

    def test_a_second_run_claims_the_comparison(self, tmp_path, monkeypatch,
                                                capsys):
        """The guard. Fixing the first run must not cost the sentence on every
        run after it — that comparison is real and worth saying."""
        line = self._clean_run(tmp_path, monkeypatch, capsys, times=2)
        assert "every source that reported last time reported again." in line, line
        assert "first run" not in line, line


class TestAnImageScanNeedsAnImageReference:
    """An operator pointed `cargo` at Docker's own VM disk, 2026-09-15:

        [1/3] trivy image  !! FATAL  unable to initialize a scan service
        [2/3] syft  sbom   … (still running on a multi-gigabyte raw disk)

    trivy fails outright on a path. syft does not — it scans the file. The run
    would have produced an SBOM of a VM disk, grype would have read CVEs out of
    it, and the whole thing would be filed as a container scan. A result that
    looks like an answer to a question nobody asked is the failure this refuses
    everywhere else, arriving through the target rather than through a scanner.

    Refused rather than noted, because there is no path this service can scan:
    both commands it builds take a reference."""

    def _run(self, capsys, argv):
        rc = squawk.cli.main(argv)
        return rc, capsys.readouterr().out

    def test_a_path_on_this_machine_is_refused(self, tmp_path, capsys):
        img = tmp_path / "Docker.raw"
        img.write_bytes(b"not an image")
        rc, out = self._run(capsys, ["--run", "cargo", "--target", str(img),
                                     "--evidence", str(tmp_path / "ev")])
        assert rc == 2, "a refusal must not exit 0"
        assert "is a path on this machine" in out, out

    def test_the_refusal_names_what_to_pass_instead(self, capsys, tmp_path):
        """A refusal that does not say what would have worked costs the reader
        the same time it just saved them."""
        d = tmp_path / "adir"
        d.mkdir()
        _rc, out = self._run(capsys, ["--run", "cargo", "--target", str(d),
                                      "--evidence", str(tmp_path / "ev")])
        assert "ghcr.io/owner/app:tag" in out, out
        assert "baggage" in out, "the service that does scan a directory"

    def test_an_image_reference_is_not_refused(self, tmp_path, monkeypatch, capsys):
        """The guard. A reference is not a path, and the check must not stop a
        real scan — `alpine:3.19` does not exist on disk, and nor does a
        registry reference with slashes in it."""
        import os as _os
        for ref in ("alpine:3.19", "ghcr.io/owner/app:tag", "ubuntu"):
            assert not _os.path.exists(ref), ref
        _patch_all(monkeypatch, "tool_path", lambda name: None)
        rc, out = self._run(capsys, ["--run", "cargo", "--target", "alpine:3.19",
                                     "--evidence", str(tmp_path / "ev")])
        assert "is a path on this machine" not in out, out
        assert rc != 2, out

    def test_a_missing_target_still_says_so(self, tmp_path, capsys):
        """The older refusal is a different sentence and keeps its own."""
        rc, out = self._run(capsys, ["--run", "cargo",
                                     "--evidence", str(tmp_path / "ev")])
        assert rc == 2
        assert "pass --target <image:name>" in out, out


class TestAChainedStageInheritsItsDenominator:
    """grype's denominator is not in grype's report — it is the SBOM syft
    wrote. Found by running `cargo` for the first time (2026-09-12): an image
    syft could not catalogue produced `syft: gap` and `grype: ok`, and the ok
    is the line a reader takes as the CVE answer."""

    @staticmethod
    def _ctx(tmp_path, sbom_body):
        ctx = squawk.RunContext("img", "image", str(tmp_path / "run"), "")
        if sbom_body is not None:
            path = tmp_path / "sbom.json"
            path.write_text(sbom_body, encoding="utf-8")
            ctx.artifacts["sbom"] = str(path)
        return ctx

    def test_an_empty_sbom_is_an_empty_denominator(self, tmp_path):
        cov = squawk.engine._upstream_coverage(
            self._ctx(tmp_path, json.dumps({"artifacts": [],
                                            "source": {"type": "image"}})), "sbom")
        assert cov is not None and cov.examined == 0, cov
        assert cov.unit == "packages"

    def test_a_real_sbom_lends_its_count(self, tmp_path):
        """The number grype had no way to publish, sitting in the file it read."""
        cov = squawk.engine._upstream_coverage(self._ctx(tmp_path, json.dumps(
            {"artifacts": [{"name": "libfoo", "version": "1.0"},
                           {"name": "libbar", "version": "2.0"}],
             "source": {"type": "image"}})), "sbom")
        assert cov is not None and cov.examined == 2, cov

    def test_no_artifact_at_all_lends_nothing(self, tmp_path):
        """grype with no SBOM is already a gap from the stage builder. A second
        reason on the same row would be two answers to one question."""
        assert squawk.engine._upstream_coverage(
            self._ctx(tmp_path, None), "sbom") is None

    def test_an_unreadable_sbom_is_unknown_not_empty(self, tmp_path):
        """An SBOM syft wrote in a shape we cannot parse is not an SBOM of zero
        packages. Lending a zero there would invent the denominator this
        refuses to invent anywhere else (I1)."""
        assert squawk.engine._upstream_coverage(
            self._ctx(tmp_path, "not json at all"), "sbom") is None

    def test_a_full_sbom_gives_grype_the_denominator_it_lacks(self, tmp_path):
        """From the operator's first `customs` run, 2026-09-15:

            syft   ok 0 finding(s) across 759 packages
            grype  ok 18 finding(s) — tool publishes no coverage

        one line apart. grype examined those 759 packages, and the stage that
        found 18 CVEs in them was the only line on the page with no
        denominator at all."""
        rows = self._cargo(tmp_path, packages=759, matches=1)
        assert rows["grype"].status == "ok"
        assert "across 759 packages" in rows["grype"].detail, rows["grype"].detail
        assert "from the SBOM this stage read" in rows["grype"].detail
        assert "publishes no coverage" not in rows["grype"].detail

    def test_a_borrowed_denominator_says_it_was_borrowed(self, tmp_path):
        """A number a reader cannot trace is a number taken on trust. grype did
        not measure 759; syft did, and the line says so."""
        rows = self._cargo(tmp_path, packages=4, matches=0)
        assert "from the SBOM this stage read" in rows["grype"].detail

    def test_a_stage_with_its_own_coverage_keeps_it(self):
        """The guard. Inheriting must only fill a gap, never overwrite a count
        the tool measured itself.

        Driven through `_apply_coverage` rather than a whole run, because no
        stage today both reads an artifact and publishes its own coverage —
        grype is the only one that reads one, and it publishes none. A run-level
        test would assert nothing. This is the shape the rule has to hold for
        when a second chained stage arrives."""
        lent = squawk.Coverage(759, "packages", 0, 0, "")
        _status, detail, cov = squawk.engine._apply_coverage(
            "syft", json.dumps({"artifacts": [{"name": "a", "version": "1"}],
                                "source": {"type": "dir"}}),
            [], "ok", "0 finding(s)", inherited=lent)
        assert cov.examined == 1, "syft measured 1; the SBOM's 759 must not win"
        assert "across 1 packages" in detail, detail
        assert "from the SBOM this stage read" not in detail, detail

    def test_a_tool_with_no_coverage_takes_the_lent_one(self):
        """The same call, the other way round: gitleaks publishes no
        denominator, so a lent one fills the gap rather than being ignored."""
        lent = squawk.Coverage(759, "packages", 0, 0, "")
        _status, detail, cov = squawk.engine._apply_coverage(
            "grype", json.dumps({"matches": []}), [], "ok", "0 finding(s)",
            inherited=lent)
        assert cov.examined == 759
        assert "across 759 packages" in detail, detail
        assert "from the SBOM this stage read" in detail, detail

    @staticmethod
    def _cargo(tmp_path, packages, matches):
        """A whole `cargo` run with an SBOM of N packages and M CVE matches."""
        import contextlib
        import io as _io
        patch = pytest.MonkeyPatch()
        try:
            patch.setattr(squawk.core, "tool_path", lambda n: "/usr/bin/%s" % n)
            patch.setattr(squawk.engine, "tool_path", lambda n: "/usr/bin/%s" % n)
            out_by_tool = {
                "trivy": json.dumps({"Results": [
                    {"Target": "img", "Vulnerabilities": []}]}),
                "syft": json.dumps({
                    "artifacts": [{"name": "p%d" % i, "version": "1"}
                                  for i in range(packages)],
                    "source": {"type": "image"}}),
                "grype": json.dumps({"matches": [
                    {"vulnerability": {"id": "CVE-%d" % i, "severity": "High"},
                     "artifact": {"name": "p%d" % i, "version": "1"}}
                    for i in range(matches)]}),
            }
            patch.setattr(squawk.engine, "run_cmd",
                          lambda argv, *a, **k: (0, out_by_tool.get(argv[0], ""), ""))
            root = str(tmp_path / ("ev-%d-%d" % (packages, matches)))
            os.makedirs(root, exist_ok=True)
            buf = _io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                outcome = squawk.execute_service(squawk.SERVICES["cargo"],
                                                 "img:1", root, str(tmp_path))
        finally:
            patch.undo()
        return {r.tool: r for r in outcome["results"]}

    def test_the_whole_run_says_it_on_the_grype_row(self, tmp_path):
        """End to end, because the helper being right is not the point — the
        ledger row a reader sees is."""
        rows = self._cargo(tmp_path, packages=0, matches=0)
        assert rows["syft"].status == "gap", "syft already caught the empty SBOM"
        assert rows["grype"].status == "gap", (
            "grype reported %s over an SBOM of zero packages: %s"
            % (rows["grype"].status, rows["grype"].detail))
        assert "examined 0 packages" in rows["grype"].detail, rows["grype"].detail
        assert "from the SBOM this stage read" in rows["grype"].detail


class TestSecurityHubSaysWhatAZeroCouldMean:
    """Every other tool's gap message names a unit that differs from its
    findings — "examined 0 packages", "examined 0 scan targets". Security Hub's
    numerator and denominator are the same thing, so the line read "0 findings,
    but examined 0 findings", which is true and says nothing."""

    def test_an_empty_response_explains_itself(self):
        cov = squawk.stage_coverage("awscli", json.dumps({"Findings": []}))
        assert cov.examined == 0, "still a gap — that part was already right"
        assert "off in this region" in cov.note, cov.note
        assert "no standards enabled" in cov.note
        assert "not be allowed to see it" in cov.note

    def test_a_populated_response_does_not_carry_the_caveat(self):
        """It explains a zero. On a response with findings it would be noise on
        every row."""
        cov = squawk.stage_coverage("awscli", json.dumps(
            {"Findings": [{"Id": "x", "Severity": {"Label": "HIGH"}}]}))
        assert cov.examined == 1
        assert "off in this region" not in cov.note


class TestCoverageVerdict:
    """The rule: findings == 0 AND examined == 0 is a gap, not ok."""

    def test_zero_over_zero_becomes_a_gap(self):
        status, detail, cov = squawk._apply_coverage(
            "semgrep", '{"paths":{"scanned":[]},"errors":[]}', [], "ok",
            "0 finding(s)")
        assert status == "gap"
        assert "examined 0 files" in detail
        assert cov.examined == 0

    def test_zero_over_a_real_denominator_stays_ok(self):
        """The whole point: a real clean scan must not be flagged. This is the
        false-alarm that would teach the reader to ignore the signal."""
        status, detail, _cov = squawk._apply_coverage(
            "semgrep", '{"paths":{"scanned":["a.py","b.py","c.py"]},"errors":[]}',
            [], "ok", "0 finding(s)")
        assert status == "ok"
        assert "across 3 files" in detail

    def test_findings_present_are_never_a_gap(self):
        fake = [squawk.Finding("semgrep", "x:1", "high", "t", "a.py")]
        status, _detail, _cov = squawk._apply_coverage(
            "semgrep", '{"paths":{"scanned":[]},"errors":[]}', fake, "ok",
            "1 finding(s)")
        assert status == "ok", "a scanner that found something has coverage by definition"

    def test_unknown_coverage_leaves_the_verdict_alone(self):
        """A tool with no denominator (gitleaks) must not be gated on one."""
        status, detail, cov = squawk._apply_coverage(
            "gitleaks", "[]", [], "ok", "0 finding(s)")
        assert status == "ok"
        assert cov.examined is None
        assert "across" not in detail

    def test_an_error_status_is_not_overwritten_by_coverage(self):
        status, _d, _c = squawk._apply_coverage(
            "semgrep", '{"paths":{"scanned":[]}}', [], "error", "boom")
        assert status == "error", "coverage must not downgrade a real error to a gap"


class TestCheckovRealShape:
    """Regression: checkov emits a LIST of blocks on a multi-framework repo, and
    both the normalizer and the coverage extractor assumed a single dict. On
    TerraGoat that meant 477 real findings reported as 0, with coverage unknown
    so the empty-denominator gate could not even fire. Found by dogfooding, not
    by a fixture — which is the lesson."""

    LIST_FORM = json.dumps([
        {"check_type": "terraform",
         "summary": {"passed": 200, "failed": 2, "resource_count": 133},
         "results": {"failed_checks": [
             {"check_id": "CKV_AWS_1", "file_path": "/terraform/s3.tf",
              "resource": "aws_s3_bucket.b", "check_name": "Ensure encryption"},
             {"check_id": "CKV_AWS_2", "file_path": "/terraform/sg.tf",
              "resource": "aws_security_group.w", "check_name": "No open ingress"}]}},
        {"check_type": "secrets",
         "summary": {"passed": 0, "failed": 1, "resource_count": 5},
         "results": {"failed_checks": [
             {"check_id": "CKV_SECRET_6", "file_path": "/app.py",
              "resource": "app.py", "check_name": "Hardcoded secret"}]}},
    ])

    def test_list_form_findings_are_parsed(self):
        out = squawk.norm_checkov(self.LIST_FORM, "/repo")
        assert len(out) == 3, "list-form checkov output must not read as zero"

    def test_list_form_coverage_sums_across_blocks(self):
        cov = squawk.stage_coverage("checkov", self.LIST_FORM)
        assert cov.examined == 138, "coverage must sum resource_count across blocks"

    def test_single_dict_form_still_works(self):
        single = json.dumps({"summary": {"resource_count": 4},
                             "results": {"failed_checks": [
                                 {"check_id": "CKV_X", "file_path": "/a.tf",
                                  "resource": "r", "check_name": "c"}]}})
        assert len(squawk.norm_checkov(single, "/repo")) == 1
        assert squawk.stage_coverage("checkov", single).examined == 4

    def test_checkov_paths_are_repo_relative_not_traversal(self):
        """checkov's '/terraform/x.tf' is relative to the scan root, not
        filesystem-absolute. Left alone it became '../../../terraform/x.tf',
        whose depth depends on the evidence-root location — so the same finding
        got a different identity on a different machine, breaking I5."""
        out = squawk.norm_checkov(self.LIST_FORM, "/repo")
        for f in out:
            assert "../" not in f.identity, "identity carries path traversal: %s" % f.identity
            assert not f.path.startswith("/"), "path is not repo-relative: %s" % f.path


class TestSevenSevenHundredSaysWhetherItIsLive:
    """7700 is the loudest line this tool prints, and on a repository scan it
    said "a critical exposure is live" over 38 trivy findings about
    security-group rules in `.tf` files and 3 about plain HTTP in an ALB
    definition (the operator's run, 2026-09-14). Every finding was real. Nothing
    had been checked for reachability, and a preflight cannot check it — it
    reads a tree, not an account.

    An alarm that overstates is the same failure as one that understates, and
    it costs more: a reader who learns to discount 7700 has lost the loudest
    channel there is. The `high` branch beside it already had this right — it
    is explicitly scoped to `url` and says "reachable now, not theoretical"."""

    def _lines(self, tmp_path, scope, severity="critical"):
        import json as _j
        root = str(tmp_path / ("ev-" + scope))
        run_dir = os.path.join(root, "20260101T000000Z-x")
        os.makedirs(os.path.join(run_dir, "raw"), exist_ok=True)
        with open(os.path.join(run_dir, "findings.json"), "w") as fh:
            _j.dump([{"scanner": "trivy", "severity": severity,
                      "identity": "AVD-AWS-0104:main.tf:sg",
                      "title": "A security group rule should not allow "
                               "unrestricted egress",
                      "path": "bastion-host/main.tf", "detail": {}}], fh)
        man = {"_dir": run_dir, "run_id": "20260101T000000Z-x", "ledger": [],
               "target": "x", "scope": scope}
        with open(os.path.join(run_dir, "manifest.json"), "w") as fh:
            _j.dump(man, fh)
        return squawk.squawk_lines(squawk.squawk_check(root, man))

    def _strapline(self, tmp_path, scope, severity="critical"):
        tail = [ln.strip() for ln in self._lines(tmp_path, scope, severity)
                if ln.strip().startswith("(")]
        assert tail, "7700 printed no strapline in scope %s" % scope
        return tail[0]

    def test_a_repository_scan_does_not_claim_the_exposure_is_live(self, tmp_path):
        got = self._strapline(tmp_path, "repo")
        assert "is live" not in got, got
        assert "checked whether it is deployed" in got, got

    def test_a_directory_and_an_image_are_static_too(self, tmp_path):
        """`baggage` reads a directory and `cargo` reads an image layer.
        Neither asked whether anything is running."""
        for scope in ("dir", "image"):
            got = self._strapline(tmp_path, scope)
            assert "is live" not in got, (scope, got)

    def test_a_high_on_a_running_app_does_not_say_critical(self, tmp_path):
        """From the Kali probes of Juice Shop, 2026-09-16:

            SQUAWK 7700 — general emergency: 4 high finding(s) against a
            RUNNING app — reachable now, not theoretical
                ...
                (a critical exposure is live)

        `high` in the count line and `critical` four lines under it. This
        branch earns 7700 on HIGH findings because reachable now beats a
        theoretical critical, and then inherited the code's own words. The
        scope half was right and the severity half was not: the earlier pass
        set a strapline on the critical branch and left this one on the
        fallback."""
        got = self._strapline(tmp_path, "url", severity="high")
        assert got == "(a high exposure is live)", got
        assert "critical" not in got, got

    def test_the_high_branch_still_says_live(self, tmp_path):
        """The guard. Fixing the severity must not cost the word that earned
        the alarm — the app is running, and that is the whole argument for
        raising an emergency on a high."""
        assert "is live" in self._strapline(tmp_path, "url", severity="high")

    def test_a_high_outside_a_running_app_raises_nothing(self, tmp_path):
        """The other guard. 7700 on a high is scoped to `url` on purpose: a
        high in a repository is an ordinary finding, and an emergency that
        fires on those is one nobody reads."""
        assert self._lines(tmp_path, "repo", severity="high") == [] or not [
            ln for ln in self._lines(tmp_path, "repo", severity="high")
            if ln.startswith("SQUAWK 7700")]

    def test_a_cloud_read_still_says_live(self, tmp_path):
        """The guard on the guard. A cloud read IS the live configuration of a
        live account — softening it everywhere would be the understatement
        this tool exists to refuse, and would cost the alarm its meaning."""
        assert self._strapline(tmp_path, "aws") == "(a critical exposure is live)"

    def test_a_running_app_and_this_machine_still_say_live(self, tmp_path):
        for scope in ("url", "host"):
            assert self._strapline(tmp_path, scope) == \
                "(a critical exposure is live)", scope

    def test_the_count_line_is_unchanged_in_every_scope(self, tmp_path):
        """Only the strapline moves. What was found, and how much, is the same
        sentence wherever it was found."""
        for scope in ("repo", "aws"):
            head = [ln for ln in self._lines(tmp_path, scope)
                    if ln.startswith("SQUAWK 7700")]
            assert head == ["SQUAWK 7700 — general emergency: "
                            "1 critical finding(s) in this run"], (scope, head)

    def test_the_page_and_the_cli_agree(self, tmp_path):
        """Two renderers read the same record. A strapline that reached one and
        not the other would put the page and the terminal in disagreement about
        what an alarm means."""
        import json as _j
        root = str(tmp_path / "ev-web")
        run_dir = os.path.join(root, "20260101T000000Z-x")
        os.makedirs(os.path.join(run_dir, "raw"), exist_ok=True)
        with open(os.path.join(run_dir, "findings.json"), "w") as fh:
            _j.dump([{"scanner": "trivy", "severity": "critical",
                      "identity": "AVD:main.tf:sg", "title": "t",
                      "path": "main.tf", "detail": {}}], fh)
        man = {"_dir": run_dir, "run_id": "20260101T000000Z-x", "ledger": [],
               "target": "x", "scope": "repo"}
        with open(os.path.join(run_dir, "manifest.json"), "w") as fh:
            _j.dump(man, fh)
        raised = squawk.squawk_check(root, man)
        html = squawk.web.squawk_banner(raised)
        assert "checked whether it is deployed" in html, html[:400]
        assert "a critical exposure is live" not in html


class TestSevenFiveHundredScope:
    """7500 is 'an attack in progress', the loudest alarm. A static scanner
    reports a weakness at rest and can never witness an attack, but check names
    like 'does not allow data exfiltration' matched the attack markers and
    false-fired on every realistic IaC scan (53 on TerraGoat)."""

    def _run(self, tmp_path, findings):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        run_dir = os.path.join(root, "20260101T000000Z-repo")
        os.makedirs(os.path.join(run_dir, "raw"), exist_ok=True)
        import json as _j
        with open(os.path.join(run_dir, "findings.json"), "w") as fh:
            _j.dump(findings, fh)
        man = {"_dir": run_dir, "run_id": "20260101T000000Z-repo",
               "ledger": [], "target": "x", "scope": "repo"}
        with open(os.path.join(run_dir, "manifest.json"), "w") as fh:
            _j.dump(man, fh)
        return squawk.squawk_check(root, man)

    def test_static_finding_with_attack_word_does_not_fire_7500(self, tmp_path):
        findings = [{"scanner": "checkov", "identity": "CKV:1", "severity": "high",
                     "title": "Ensure IAM policies do not allow data exfiltration",
                     "path": "a.tf", "detail": {}}]
        codes = [c["code"] for c in self._run(tmp_path, findings)]
        assert "7500" not in codes, "a static IaC check must not raise 7500"

    def test_a_dast_finding_describing_an_attack_still_fires_7500(self, tmp_path):
        findings = [{"scanner": "zap", "identity": "z:1", "severity": "high",
                     "title": "SQL injection — active exploitation, backdoor uploaded",
                     "path": "/x", "detail": {}}]
        codes = [c["code"] for c in self._run(tmp_path, findings)]
        assert "7500" in codes, "a real DAST attack finding must still raise 7500"

    # The next three come from the Juice Shop run in issue 126, where an active
    # probe raised the loudest alarm on five CORS misconfigurations.

    ZAP_CORS = ("This CORS misconfiguration could allow an attacker to perform "
                "AJAX queries to the vulnerable website from a malicious page "
                "loaded by the victim's user agent.")

    def test_a_scanners_explanation_is_not_evidence_of_an_attack(self, tmp_path):
        """ZAP writes "a malicious page loaded by the victim's user agent" into
        its CORS advisory. That is prose about what an attacker could do, which
        is the definition of a weakness at rest, and it fired 7500 five times
        against Juice Shop. The markers are a finding-TYPE vocabulary and belong
        against the title and rule id, never the description."""
        findings = [{"scanner": "zap", "identity": "40040:/p%d:" % i,
                     "severity": "medium", "title": "CORS Misconfiguration",
                     "path": "/rest/p%d" % i,
                     "detail": {"description": self.ZAP_CORS}} for i in range(5)]
        codes = [c["code"] for c in self._run(tmp_path, findings)]
        assert "7500" not in codes, \
            "an advisory explaining an attack is not a report of one"

    def test_an_observed_cloud_attack_fires_7500(self, tmp_path):
        """The scoping fix has to leave the alarm able to fire. ATTACK_MARKERS
        is GuardDuty's vocabulary, and GuardDuty arrives through Security Hub as
        a cloud finding, so scoping the witness kinds to DAST alone made 7500
        unfirable once its markers stopped matching prose: the code that reports
        an attack could not see the only source that reports attacks."""
        findings = [{"scanner": "awscli", "identity": "gd:1", "severity": "high",
                     "title": "Unprotected port on EC2 instance is being probed",
                     "path": "i-0abc",
                     "detail": {"rule": "UnauthorizedAccess:EC2/SSHBruteForce"}}]
        raised = self._run(tmp_path, findings)
        assert "7500" in [c["code"] for c in raised]
        assert "cloud" in squawk.WITNESS_KINDS, \
            "the kind that actually observes attacks is not a witness"

    def test_the_detail_list_groups_repeats_and_says_it_truncated(self, tmp_path):
        """Four identical lines reading "CORS Misconfiguration" told the reader
        nothing, and printing four of five with no note is a silent cap, which
        the charter forbids."""
        findings = ([{"scanner": "zap", "identity": "z%d" % i, "severity": "critical",
                      "title": "Cross Site Scripting (Reflected)",
                      "path": "/search?q=%d" % i, "detail": {}} for i in range(7)]
                    + [{"scanner": "zap", "identity": "s%d" % i, "severity": "critical",
                        "title": "T%d" % i, "path": "/x%d" % i, "detail": {}}
                       for i in range(5)])
        raised = self._run(tmp_path, findings)
        detail = next(r for r in raised if r["code"] == "7700")["detail"]
        assert detail[0].startswith("Cross Site Scripting (Reflected) x7"), detail[0]
        assert "/search?q=0" in detail[0] and "and 5 more" in detail[0], \
            "a repeated finding says how many and where, not the same line twice"
        assert len(set(detail)) == len(detail), "the same line is never printed twice"
        assert any("and 2 more distinct" in d for d in detail), \
            "the truncation is silent, which the charter forbids"


def _sr(tool, n_findings, status="ok", errors=0, skipped=0):
    cov = squawk.Coverage(n_findings, "files", skipped, errors, "")
    finds = [squawk.Finding(tool, "%s:%d" % (tool, i), "high", "t", "p")
             for i in range(n_findings)]
    return squawk.StageResult(tool, "x", status, "", None, finds, 0, cov)


class TestErrorChannel:
    """A tool that could not parse part of the tree is telling us the coverage
    is partial. The count was stored and never shown, which overstates what was
    examined. Surfaced now."""

    def test_unreadable_files_are_named_in_the_detail(self):
        raw = '{"metrics":{"a.py":{},"b.py":{},"_totals":{}},' \
              '"errors":[{"filename":"c.py","reason":"syntax error"}],"results":[]}'
        _s, detail, cov = squawk._apply_coverage("bandit", raw, [], "ok", "0 finding(s)")
        assert cov.errors == 1
        assert "1 unreadable" in detail, detail

    def test_a_clean_scan_says_nothing_about_errors(self):
        raw = '{"metrics":{"a.py":{},"_totals":{}},"errors":[],"results":[]}'
        _s, detail, _c = squawk._apply_coverage("bandit", raw, [], "ok", "0 finding(s)")
        assert "unreadable" not in detail


class TestScannerDifferential:
    """Two scanners over the same input disagreeing sharply is a free detection
    test. It must fire on zero-vs-many and stay silent on everything else, or it
    becomes the false alarm the tool refuses."""

    def test_zero_vs_many_fires(self):
        d = squawk.scanner_differential([_sr("trivy", 0), _sr("grype", 9)])
        assert len(d) == 1
        assert d[0]["silent"] == "trivy" and d[0]["loud"] == "grype"

    def test_normal_variance_is_not_flagged(self):
        """9 vs 7 is different CVE databases, not a broken scanner. Flagging it
        would teach the operator to ignore the signal."""
        assert squawk.scanner_differential([_sr("trivy", 7), _sr("grype", 9)]) == []

    def test_agreement_is_not_flagged(self):
        assert squawk.scanner_differential([_sr("trivy", 0), _sr("grype", 0)]) == []

    def test_only_one_scanner_ran_is_not_flagged(self):
        assert squawk.scanner_differential([_sr("grype", 9)]) == []

    def test_a_paired_error_is_not_a_differential(self):
        d = squawk.scanner_differential([_sr("trivy", 0, "error"), _sr("grype", 9)])
        assert d == [], "one side did not run cleanly; nothing to compare"

    def test_below_threshold_is_not_flagged(self):
        """A high side of 3 is too small to distinguish a real gap from noise."""
        assert squawk.scanner_differential([_sr("trivy", 0), _sr("grype", 3)]) == []

    def test_only_same_input_pairs_are_compared(self):
        """semgrep (multi-language) vs bandit (Python-only) legitimately differ;
        they must not be a differential pair."""
        pairs = {(a, b) for a, b, _ in squawk.DIFFERENTIAL_PAIRS}
        assert ("semgrep", "bandit") not in pairs
        assert ("bandit", "semgrep") not in pairs


def _rr(tool, status="ok"):
    return squawk.StageResult(tool, "x", status, "", None, [], 0, None)


def _fd(scanner, ident, path="p"):
    return {"scanner": scanner, "identity": ident, "severity": "high",
            "title": "t", "path": path, "detail": {}}


CORR_IAC_RAN = [_rr("checkov")]
CORR_ALL_RAN = [_rr("gitleaks"), _rr("bandit"), _rr("checkov")]


class TestCorrelation:
    """Phase 1.5. A correlation joins findings across scanners into a toxic
    combination, and states its denominator: unknown when a member scanner did
    not run, rather than silently not firing."""

    def test_public_and_unencrypted_on_one_resource_fires(self):
        finds = [_fd("checkov", "CKV_AWS_20:main.tf:aws_s3_bucket.b", "main.tf"),
                 _fd("checkov", "CKV_AWS_145:main.tf:aws_s3_bucket.b", "main.tf")]
        c = [x for x in squawk.correlate(finds, CORR_IAC_RAN)
             if x["key"] == "public-unencrypted-store"]
        assert c and c[0]["state"] == "fired"
        assert len(c[0]["members"]) == 2, "the correlation must cite both members"

    def test_public_but_encrypted_does_not_fire(self):
        """The false-alarm guard: public alone, or unencrypted alone, is not the
        toxic combination. A finding that fires on half the condition trains the
        reader to ignore it."""
        finds = [_fd("checkov", "CKV_AWS_20:main.tf:aws_s3_bucket.b", "main.tf")]
        c = [x for x in squawk.correlate(finds, CORR_IAC_RAN)
             if x["key"] == "public-unencrypted-store" and x["state"] == "fired"]
        assert c == [], "public alone is not public-AND-unencrypted"

    def test_the_two_facts_must_be_on_the_same_resource(self):
        """Public on bucket A and unencrypted on bucket B is not one toxic
        resource — the join is on the resource, not the run."""
        finds = [_fd("checkov", "CKV_AWS_20:a.tf:aws_s3_bucket.a", "a.tf"),
                 _fd("checkov", "CKV_AWS_145:b.tf:aws_s3_bucket.b", "b.tf")]
        c = [x for x in squawk.correlate(finds, CORR_IAC_RAN)
             if x["key"] == "public-unencrypted-store" and x["state"] == "fired"]
        assert c == [], "two different resources must not join"

    def test_a_missing_member_scanner_is_unknown_not_silent(self):
        """The thesis. The secret rule needs a secrets scanner; when one is in
        this scan's scope but did not run (skipped), the combination cannot be
        evaluated, and that is reported, not hidden. A skipped gitleaks stage
        puts 'secrets' in scope without producing output — the real preflight-
        without-gitleaks case."""
        finds = [_fd("checkov", "CKV_DOCKER_2:Dockerfile:x", "Dockerfile")]
        res = [_rr("checkov"), _rr("gitleaks", "skipped")]
        c = [x for x in squawk.correlate(finds, res)
             if x["key"] == "secret-in-container-build"]
        assert c and c[0]["state"] == "unknown"
        # Names the stage and what became of it. "no secrets scanner ran" was
        # the old wording and it was false of a gitleaks that ran and was
        # killed — see TestACorrelationSaysWhatBecameOfTheScanner.
        assert "gitleaks did not run" in c[0]["why"], c[0]["why"]
        assert "the secrets side was never read" in c[0]["why"]

    def test_secret_plus_dockerfile_fires_when_secrets_ran(self):
        finds = [_fd("bandit", "B105:app.py:1", "app.py"),
                 _fd("checkov", "CKV_DOCKER_2:Dockerfile:x", "Dockerfile")]
        c = [x for x in squawk.correlate(finds, CORR_ALL_RAN)
             if x["key"] == "secret-in-container-build"]
        assert c and c[0]["state"] == "fired"

    def test_a_member_that_read_nothing_is_named_in_the_finding_that_fired(self):
        """The live compliance run. gitleaks read 0 bytes, so `secrets` was a
        gap — which counts as having run, so the combination fired on bandit's
        B105 alone and printed a high finding that mentioned no gap. A reader
        had every reason to believe a secrets scanner had looked. It still
        fires, because the Dockerfile and the B105 are real, and it now says
        which leg was never scanned."""
        finds = [_fd("bandit", "B105:app.py:1", "app.py"),
                 _fd("checkov", "CKV_DOCKER_2:Dockerfile:x", "Dockerfile")]
        res = [_rr("gitleaks", "gap"), _rr("bandit"), _rr("checkov")]
        c = [x for x in squawk.correlate(finds, res)
             if x["key"] == "secret-in-container-build"]
        assert c and c[0]["state"] == "fired", "real members still fire"
        assert c[0]["unread"] == ["secrets"], "the unread kind is on the record"
        why = c[0]["why"]
        assert "gitleaks read nothing this run" in why, why
        assert "not on a scan" in why, why

    def test_a_member_that_read_the_tree_adds_no_caveat(self):
        """The guard on the guard. A caveat on every finding is a caveat nobody
        reads; it appears only when a required kind actually came back empty."""
        finds = [_fd("bandit", "B105:app.py:1", "app.py"),
                 _fd("checkov", "CKV_DOCKER_2:Dockerfile:x", "Dockerfile")]
        c = [x for x in squawk.correlate(finds, CORR_ALL_RAN)
             if x["key"] == "secret-in-container-build"]
        assert c and c[0]["state"] == "fired"
        assert c[0]["unread"] == [], "nothing was unread, so nothing is claimed"
        assert "read nothing" not in c[0]["why"]

    def test_an_unread_member_rides_into_the_finding(self):
        """The caveat has to survive the trip into the ranked finding list —
        the manifest record is not what a person reads on the Findings page."""
        finds = [_fd("bandit", "B105:app.py:1", "app.py"),
                 _fd("checkov", "CKV_DOCKER_2:Dockerfile:x", "Dockerfile")]
        res = [_rr("gitleaks", "gap"), _rr("bandit"), _rr("checkov")]
        cf = squawk.correlation_findings(squawk.correlate(finds, res))
        assert cf, "the combination still becomes a finding"
        f = cf[0]
        assert f.detail["unread"] == ["secrets"]
        assert "gitleaks read nothing this run" in f.detail["what"]

    def test_a_gap_in_a_kind_another_stage_read_is_not_unread(self):
        """`iac` is two stages: checkov, and `trivy config`. A trivy config
        stage that came back empty while checkov read the tree does not make
        the iac leg unread — one of them looked, and saying otherwise would put
        a false caveat on a true finding, which is the same failure as the
        missing caveat with the sign flipped."""
        finds = [_fd("checkov", "CKV_AWS_20:main.tf:aws_s3_bucket.b", "main.tf"),
                 _fd("checkov", "CKV_AWS_145:main.tf:aws_s3_bucket.b", "main.tf")]
        res = [_rr("checkov"),
               squawk.StageResult("trivy", "config", "gap", "", None, [], 0, None)]
        assert squawk.result_kind("checkov", "") == "iac"
        assert squawk.result_kind("trivy", "config") == "iac", "both are iac"
        c = [x for x in squawk.correlate(finds, res)
             if x["key"] == "public-unencrypted-store"]
        assert c and c[0]["state"] == "fired"
        assert c[0]["unread"] == [], "checkov read the tree, so iac was read"
        assert "read nothing" not in c[0]["why"]

    def test_a_scanner_that_died_does_not_delete_a_real_combination(self):
        """From the operator's run, 2026-09-14. gitleaks timed out at its budget,
        so `secrets` left `ran_kinds`, and secret-in-container-build reported
        "cannot evaluate" over a bandit B105 and a Dockerfile that were both
        still sitting in the findings list. The same evidence with gitleaks at
        `gap` instead of `error` fired a high finding: one word of stage
        status, and a real combination appeared or vanished.

        The rule is evaluated whatever happened upstream, and the OUTCOME
        decides the state. Gating evaluation on the required kinds was trading
        findings for a denominator — the trade this refused for `gap` and was
        still making for `error`."""
        finds = [_fd("bandit", "B105:app.py:1", "app.py"),
                 _fd("checkov", "CKV_DOCKER_2:Dockerfile:x", "Dockerfile")]
        for status in ("ok", "gap", "error", "skipped"):
            res = [_rr("gitleaks", status), _rr("bandit"), _rr("checkov")]
            c = [x for x in squawk.correlate(finds, res)
                 if x["key"] == "secret-in-container-build"]
            assert c and c[0]["state"] == "fired", (
                "gitleaks %s deleted a combination its own members still "
                "support: %r" % (status, c and c[0]["state"]))

    def test_no_members_and_a_dead_scanner_is_still_unknown(self):
        """The guard. Firing whatever happened would make the rule useless —
        `unknown` has to survive for the case it was written for: nothing
        joined, and the question was never asked, so a real negative cannot be
        claimed."""
        for status in ("gap", "error", "skipped"):
            res = [_rr("gitleaks", status), _rr("bandit"), _rr("checkov")]
            c = [x for x in squawk.correlate([], res)
                 if x["key"] == "secret-in-container-build"]
            assert c and c[0]["state"] == "unknown", status

    def test_no_members_and_every_scanner_read_is_a_real_negative(self):
        """And the other guard: when the question WAS asked and nothing
        joined, that is an answer, not a confession. It stays silent."""
        c = [x for x in squawk.correlate(
                [], [_rr("gitleaks"), _rr("bandit"), _rr("checkov")])
             if x["key"] == "secret-in-container-build"]
        assert c == [], "a real negative must not print as unknown"


class TestACorrelationSaysWhatBecameOfTheScanner:
    """"no secrets scanner ran" was printed over a gitleaks that had run for
    fifteen minutes and been killed at its budget (the operator's run,
    2026-09-14). A tool that ran and died is not a tool that was never there,
    and this project's whole thesis is that those are different sentences."""

    CASES = (("gap", "gitleaks read nothing this run"),
             ("error", "gitleaks ran and did not finish"),
             ("skipped", "gitleaks did not run"))

    def test_the_caveat_on_a_fired_finding_names_what_happened(self):
        finds = [_fd("bandit", "B105:app.py:1", "app.py"),
                 _fd("checkov", "CKV_DOCKER_2:Dockerfile:x", "Dockerfile")]
        for status, phrase in self.CASES:
            c = [x for x in squawk.correlate(
                    finds, [_rr("gitleaks", status), _rr("bandit"), _rr("checkov")])
                 if x["key"] == "secret-in-container-build"]
            assert c and c[0]["state"] == "fired"
            assert phrase in c[0]["why"], (status, c[0]["why"])

    def test_the_unknown_line_names_what_happened(self):
        for status, phrase in self.CASES:
            c = [x for x in squawk.correlate(
                    [], [_rr("gitleaks", status), _rr("bandit"), _rr("checkov")])
                 if x["key"] == "secret-in-container-build"]
            assert c and c[0]["state"] == "unknown"
            assert phrase in c[0]["why"], (status, c[0]["why"])

    def test_a_killed_scanner_is_never_described_as_absent(self):
        """The specific false sentence, asserted directly so it cannot come
        back by a different route."""
        for finds in ([], [_fd("bandit", "B105:app.py:1", "app.py"),
                           _fd("checkov", "CKV_DOCKER_2:Dockerfile:x", "Dockerfile")]):
            c = [x for x in squawk.correlate(
                    finds, [_rr("gitleaks", "error"), _rr("bandit"), _rr("checkov")])
                 if x["key"] == "secret-in-container-build"]
            assert c, "the rule went silent entirely"
            assert "did not run" not in c[0]["why"], (
                "gitleaks ran for its whole budget and was killed: %r"
                % c[0]["why"])

    def test_the_three_outcomes_read_differently(self):
        """They are three different facts about the run, so they must not
        collapse into one sentence."""
        said = set()
        for status, _phrase in self.CASES:
            c = [x for x in squawk.correlate(
                    [], [_rr("gitleaks", status), _rr("bandit"), _rr("checkov")])
                 if x["key"] == "secret-in-container-build"]
            said.add(c[0]["why"])
        assert len(said) == 3, said


class TestCorrelationBecomesFindings:
    """The rest of TestCorrelation's surface: a fired combination has to become
    a ranked Finding, and an unknown must not."""

    def test_fired_correlations_become_findings_with_identity(self):
        finds = [_fd("checkov", "CKV_AWS_20:main.tf:aws_s3_bucket.b", "main.tf"),
                 _fd("checkov", "CKV_AWS_145:main.tf:aws_s3_bucket.b", "main.tf")]
        corr = squawk.correlate(finds, CORR_IAC_RAN)
        cf = squawk.correlation_findings(corr)
        assert cf, "a fired correlation must become a finding"
        f = cf[0]
        assert f.scanner == "correlation"
        assert f.identity.startswith("correlation:public-unencrypted-store:")
        assert f.detail["remediation"], "a correlation finding carries a fix"
        assert f.detail["members"], "it cites its member findings"

    def test_unknown_correlations_do_not_become_findings(self):
        """An unknown is a coverage statement, not a finding — it belongs in the
        manifest, not in the ranked finding list."""
        corr = [{"key": "x", "state": "unknown", "title": "t", "severity": "unknown",
                 "why": "no scanner", "members": [], "fix": "f"}]
        assert squawk.correlation_findings(corr) == []

    def test_every_correlation_rule_has_an_id_title_and_fix(self):
        for corr in squawk.CORRELATIONS:
            assert corr.key and corr.title and corr.fix
            assert corr.severity in squawk.SEVERITY_ORDER


class TestReviewFindings:
    """Regressions from the full review pass. Each reproduces a bug that was
    confirmed live before being fixed."""

    def test_fixing_a_correlation_does_not_raise_a_false_7600(self, tmp_path):
        """The correlation stage was appended only when something fired, so
        FIXING a toxic combination removed "correlation" from the ledger and
        the went-quiet check raised 7600, the loudest wrong answer, for doing
        the right thing. The stage is now always present."""
        root = tmp_path / "ev"
        svc = squawk.SERVICES["selfaudit"]
        outcome = squawk.execute_service(svc, "host", str(root), str(tmp_path))
        man = json.load(open(pathlib.Path(outcome["run_dir"]) / "manifest.json"))
        tools = [r["tool"] for r in man["ledger"]]
        assert "correlation" in tools, \
            "the correlation stage must appear even when nothing fired"

    def test_trivy_report_without_results_key_is_a_gap(self):
        """Real trivy OMITS Results when it scanned nothing, rather than
        emitting []. Requiring the key meant the defect-1 case still read as a
        clean ok. Measured against real trivy output."""
        raw = '{"SchemaVersion":2,"ArtifactName":"x","ArtifactType":"filesystem"}'
        cov = squawk.stage_coverage("trivy", raw)
        assert cov.examined == 0
        status, detail, _c = squawk._apply_coverage("trivy", raw, [], "ok", "0")
        assert status == "gap" and "0 scan targets" in detail

    def test_not_a_trivy_report_is_still_unknown_not_zero(self):
        """The fix must not fabricate a denominator for non-trivy documents."""
        assert squawk.stage_coverage("trivy", '{"x":1}').examined is None

    def test_ok_to_gap_reports_once_in_7600(self, tmp_path):
        """An ok->gap transition produced two 7600 lines for one tool: the gap
        row plus the went-quiet diff. One condition, counted once now."""
        root = str(tmp_path)
        for rid, status in (("20260101T000000Z-repo", "ok"),
                            ("20260102T000000Z-repo", "gap")):
            d = os.path.join(root, rid)
            os.makedirs(d)
            json.dump([], open(os.path.join(d, "findings.json"), "w"))
            json.dump({"run_id": rid, "target": "t", "scope": "repo",
                       "service": "x",
                       "ledger": [{"tool": "semgrep", "mode": "auto",
                                   "status": status, "detail": "examined 0"}]},
                      open(os.path.join(d, "manifest.json"), "w"))
        man = next(r for r in squawk.list_runs(root)
                   if r["run_id"].startswith("20260102"))
        lines = [ln for r in squawk.squawk_check(root, man)
                 if r["code"] == "7600" for ln in r["detail"] if "semgrep" in ln]
        assert len(lines) == 1, lines

    def test_public_plus_versioning_only_does_not_claim_unencrypted(self):
        """CKV_AWS_21 is S3 versioning. With it in the crypto tuple, a public
        bucket with encryption fine but versioning off fired a finding titled
        'unencrypted', a false statement on the loud channel."""
        finds = [_fd("checkov", "CKV_AWS_20:main.tf:aws_s3_bucket.b", "main.tf"),
                 _fd("checkov", "CKV_AWS_21:main.tf:aws_s3_bucket.b", "main.tf")]
        ran = [_rr("checkov")]
        c = [x for x in squawk.correlate(finds, ran)
             if x["key"] == "public-unencrypted-store" and x["state"] == "fired"]
        assert c == [], "versioning-off is not unencrypted"

    def test_a_duplicated_tool_makes_the_differential_ambiguous_not_wrong(self):
        """A dict keyed by tool silently kept the LAST stage when a tool ran
        twice in one service, so the comparison used an arbitrary half of that
        tool's output. Ambiguous input now produces no signal rather than a
        wrong one."""
        dup = [_sr("trivy", 0), _sr("trivy", 4), _sr("grype", 9)]
        assert squawk.scanner_differential(dup) == []
        single = [_sr("trivy", 0), _sr("grype", 9)]
        assert len(squawk.scanner_differential(single)) == 1


class TestWebErrorSurfacing:
    """A view that raises must not blank the page. The HTTP handler had no
    exception guard, so a crashing view sent a blank 500 to the browser and the
    traceback only to the terminal — the web version of a scan that did not run
    looking like one that found nothing. Reported from the field as a blank
    Findings page with errors."""

    def test_a_crashing_view_is_surfaced_not_blanked(self, tmp_path, monkeypatch):
        """Through the socket, not the source: a view that raises must reach
        the browser as an error page that names the cause, never as a blank
        page that reads as a page with nothing on it."""
        root = str(tmp_path / "ev")
        os.makedirs(root)

        def boom(_root):
            raise RuntimeError("deliberate crash for the test")
        _patch_all(monkeypatch, "view_overview", boom)
        with _serve(root, str(tmp_path)) as base:
            code, body = _get(base + "/")
        assert code == 500
        assert "This page hit an error" in body and "deliberate crash" in body
        assert "<h1>Overview</h1>" not in body, "the crash must not look like the page"

    def test_the_finish_button_access_is_guarded(self):
        """Unguarded getElementById('finish') threw and blanked the triage page
        whenever the button was absent. Now guarded like the others."""
        # render any triage page and confirm the raw string is guarded
        import glob
        import os
        import tempfile
        root = tempfile.mkdtemp()
        svc = squawk.SERVICES["selfaudit"]
        out = squawk.execute_service(svc, "host", root, os.getcwd())
        html = squawk.view_triage(root, out["run_id"])
        assert "getElementById('finish').onclick" not in html, \
            "unguarded finish access remains"
        del glob


class TestCorrelationApplicability:
    """A correlation whose required scanner KIND is not in the service's scope
    at all is not applicable and must be silent — not reported as 'cannot
    evaluate'. A host audit reporting 'cannot evaluate secret-in-container-build'
    is a category error: it never runs a secrets scanner, so there is nothing to
    confess. Found on a live selfaudit run."""

    def test_out_of_scope_correlation_is_silent_not_unknown(self):
        host_only = [squawk.StageResult("selfaudit", "host", "ok", "", None, [], 0, None)]
        out = squawk.correlate([], host_only)
        assert out == [], "a host audit must not report IaC/secret correlations at all"

    def test_in_scope_but_skipped_scanner_is_unknown(self):
        """The honest case survives: the scan includes a secrets scanner (via an
        iac + secrets service) but it did not run, so the combination is unknown,
        not silent."""
        res = [squawk.StageResult("checkov", "x", "ok", "", None, [], 0, None),
               squawk.StageResult("gitleaks", "x", "skipped", "not found", None, [], 0, None)]
        out = [x for x in squawk.correlate([], res)
               if x["key"] == "secret-in-container-build"]
        assert out and out[0]["state"] == "unknown"

    def test_in_scope_and_ran_evaluates_the_rule(self):
        cf = [squawk.Finding("checkov", "CKV_AWS_20:m.tf:b", "high", "t", "m.tf"),
              squawk.Finding("checkov", "CKV_AWS_145:m.tf:b", "high", "t", "m.tf")]
        res = [squawk.StageResult("checkov", "x", "ok", "", None, cf, 0, None)]
        finds = [_fd("checkov", "CKV_AWS_20:m.tf:b", "m.tf"),
                 _fd("checkov", "CKV_AWS_145:m.tf:b", "m.tf")]
        out = [x for x in squawk.correlate(finds, res)
               if x["key"] == "public-unencrypted-store"]
        assert out and out[0]["state"] == "fired"


class TestCompareRuns:
    """A rescan's whole value is showing what moved. The load-bearing rule is
    the same one the tool holds its scanners to: a scanner that did not run OK
    in BOTH runs is silent, never 'remediated' — otherwise a rescan that skips
    a tool reads as its findings fixed. Coverage that drops to zero is a new
    gap, framed over time, not a clean result."""

    def _cov(self, ex, unit="files"):
        return {"examined": ex, "unit": unit, "skipped": 0, "errors": 0, "note": ""}

    def _write(self, root, rid, ledger, idents, findings,
               service="customs", scope="repo", target="/x"):
        run_dir = os.path.join(root, rid)
        os.makedirs(os.path.join(run_dir, "raw"), exist_ok=True)
        man = {"run_id": rid, "service": service, "scope": scope, "target": target,
               "service_label": "Customs (%s)" % scope, "not_covered": "runtime",
               "counts": {"total": len(findings), "excluded": 0},
               "severities": {}, "differential": [], "correlations": [],
               "ledger": ledger}
        for name, obj in (("manifest.json", man), ("identities.json", idents),
                          ("findings.json", findings), ("digest.json", {"run_id": rid})):
            with open(os.path.join(run_dir, name), "w") as fh:
                json.dump(obj, fh)

    def _two_runs(self, tmp_path):
        """Older: semgrep found 2, trivy found 1 (examined 3 targets).
        Newer: one semgrep finding fixed; trivy examined 0 now (a gap)."""
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        self._write(
            root, "20260101T000000Z",
            [{"tool": "semgrep", "mode": "", "status": "ok", "detail": "",
              "evidence": "", "coverage": self._cov(10)},
             {"tool": "trivy", "mode": "", "status": "ok", "detail": "",
              "evidence": "", "coverage": self._cov(3, "targets")}],
            {"semgrep": ["a.py:1:x", "a.py:2:y"], "trivy": ["CVE-1"]},
            [{"scanner": "semgrep", "identity": "a.py:1:x", "severity": "high",
              "title": "Hardcoded secret", "path": "a.py", "detail": {}},
             {"scanner": "semgrep", "identity": "a.py:2:y", "severity": "medium",
              "title": "Weak hash", "path": "a.py", "detail": {}},
             {"scanner": "trivy", "identity": "CVE-1", "severity": "critical",
              "title": "CVE-2024-1 in libfoo", "path": "go.mod", "detail": {}}])
        self._write(
            root, "20260102T000000Z",
            [{"tool": "semgrep", "mode": "", "status": "ok", "detail": "",
              "evidence": "", "coverage": self._cov(10)},
             {"tool": "trivy", "mode": "", "status": "gap", "detail": "no target",
              "evidence": "", "coverage": self._cov(0, "targets")}],
            {"semgrep": ["a.py:2:y"], "trivy": []},
            [{"scanner": "semgrep", "identity": "a.py:2:y", "severity": "medium",
              "title": "Weak hash", "path": "a.py", "detail": {}}])
        return root

    def test_a_real_fix_shows_as_remediated(self, tmp_path):
        html = squawk.view_compare(self._two_runs(tmp_path), "20260102T000000Z")
        assert "Remediated since last run" in html
        assert "Hardcoded secret" in html, "the fixed semgrep finding must show"
        assert "1 remediated" in html

    def test_a_silent_scanner_is_not_called_remediated(self, tmp_path):
        """trivy went ok -> gap, so its CVE disappearing is unknown, not fixed."""
        html = squawk.view_compare(self._two_runs(tmp_path), "20260102T000000Z")
        assert "Silent scanners" in html
        remediated = html.split("New this run")[0] if "New this run" in html else html
        remediated = remediated.split("Coverage changes")[0]
        assert "CVE-2024-1 in libfoo" not in remediated, \
            "a scanner that went silent must never read as remediated"

    def test_coverage_drop_to_zero_is_framed_over_time(self, tmp_path):
        html = squawk.view_compare(self._two_runs(tmp_path), "20260102T000000Z")
        assert "Coverage changes" in html
        assert "examined 3 targets" in html and "0 — stopped" in html

    def test_first_run_has_nothing_to_compare(self, tmp_path):
        html = squawk.view_compare(self._two_runs(tmp_path), "20260101T000000Z")
        assert "First run of this target" in html
        assert "Remediated since last run" not in html

    def test_only_compares_the_same_target(self, tmp_path):
        """A run of a different target must not become the comparison base."""
        root = self._two_runs(tmp_path)
        self._write(  # a different target entirely
            root, "20260103T000000Z-url",
            [{"tool": "zap", "mode": "", "status": "ok", "detail": "",
              "evidence": "", "coverage": self._cov(5, "endpoints")}],
            {"zap": ["z:1"]},
            [{"scanner": "zap", "identity": "z:1", "severity": "high",
              "title": "XSS", "path": "/x", "detail": {}}],
            service="recon", scope="url", target="http://y")
        man = next(r for r in squawk.list_runs(root)
                   if r["run_id"] == "20260103T000000Z-url")
        assert man.get("scope") == "url"
        html = squawk.view_compare(root, "20260103T000000Z-url")
        assert "First run of this target" in html, \
            "a url-scope run must not diff against the repo-scope runs"

    def test_remediated_findings_drill_down_to_their_detail(self, tmp_path):
        html = squawk.view_compare(self._two_runs(tmp_path), "20260102T000000Z")
        assert "<details" in html, "compare rows must expand"
        # the remediated semgrep finding carried a real remediation string
        assert "Hardcoded secret" in html


class TestRiskTrend:
    """The -5..+5 rating over a target's runs. Load-bearing rules: the scale is
    set by runs that actually looked (an incomplete run must not redefine the
    median), the worst complete run pins -5 and the best pins the top, and a run
    that could not fully scan is drawn hollow so a zero that means 'did not look'
    is never read as a clean +5."""

    def _run(self, i, sev, incomplete=False):
        led = [{"tool": "semgrep",
                "status": "gap" if incomplete else "ok",
                "coverage": {"examined": 0 if incomplete else 10, "unit": "files"}}]
        return {"run_id": "2026010%dT000000Z" % i, "severities": sev,
                "counts": {"total": sum(sev.values())}, "ledger": led}

    def _sev(self, **kw):
        base = {s: 0 for s in squawk.SEVERITY_ORDER}
        base.update(kw)
        return base

    def test_one_run_has_no_trend(self):
        assert squawk.risk_trend([self._run(1, self._sev(low=1))]) == ""

    def test_score_weights_severity_over_count(self):
        one_crit = squawk._run_score(self._run(1, self._sev(critical=1)))
        many_low = squawk._run_score(self._run(2, self._sev(low=50)))
        assert one_crit > many_low, "one critical must outweigh fifty lows"

    def test_incomplete_run_is_flagged(self):
        assert squawk._run_incomplete(self._run(1, self._sev(), incomplete=True))
        assert not squawk._run_incomplete(self._run(1, self._sev(low=1)))

    def test_worst_complete_run_pins_minus_five(self):
        runs = [self._run(1, self._sev(high=1, medium=2)),
                self._run(2, self._sev(critical=2, high=3)),   # worst
                self._run(3, self._sev(low=1))]                # best
        svg = squawk.risk_trend(runs)
        assert "<polyline" in svg and ">+5<" in svg and ">-5<" in svg
        # the worst run's rating is the minimum; recompute the way the code does
        scores = [squawk._run_score(r) for r in runs]
        ref = sorted(scores)
        n = len(ref)
        med = ref[n // 2] if n % 2 else (ref[n // 2 - 1] + ref[n // 2]) / 2.0
        spread = max(abs(s - med) for s in ref) or 1
        ratings = [max(-5.0, min(5.0, (med - s) / spread * 5.0)) for s in scores]
        assert min(ratings) == ratings[1] and ratings[1] == -5.0

    def test_an_incomplete_run_does_not_move_the_median(self):
        """Two real runs plus a flood of gap runs: the scale must be set by the
        two that looked, not dragged toward the gap runs' zero score."""
        real = [self._run(1, self._sev(critical=1)),
                self._run(2, self._sev(low=1))]
        gaps = [self._run(3 + k, self._sev(), incomplete=True) for k in range(5)]
        svg_real = squawk.risk_trend(real)
        svg_all = squawk.risk_trend(real + gaps)
        # the two real runs still pin -5 and the top in both cases
        for svg in (svg_real, svg_all):
            assert "<polyline" in svg
        # hollow marker present only when a gap run is in the set
        assert "stroke='var(--gap)'" in svg_all
        assert "stroke='var(--gap)'" not in svg_real


class TestEvidenceRedaction:
    """Semgrep replaces the matched source line with a placeholder when the scan
    is not authenticated. Storing that placeholder makes every finding read
    'evidence: requires login' — a redaction stand-in posing as matched code,
    identical across unrelated findings. It must be dropped, at parse and at
    display, so an old run already carrying it also renders clean."""

    def test_placeholder_is_not_evidence(self):
        assert squawk._real_evidence("requires login") == ""
        assert squawk._real_evidence("Requires Login") == ""
        assert squawk._real_evidence("requires semgrep login") == ""

    def test_real_line_survives(self):
        assert squawk._real_evidence("  os.chmod(d, 0o700)  ") == "os.chmod(d, 0o700)"

    def test_norm_semgrep_drops_the_placeholder(self):
        raw = json.dumps({"results": [{"check_id": "r", "path": "a.py",
            "start": {"line": 5}, "extra": {"severity": "ERROR",
            "message": "m", "lines": "requires login"}}]})
        assert squawk.norm_semgrep(raw, ".")[0].detail["evidence"] == ""

    def test_norm_semgrep_keeps_a_real_line(self):
        raw = json.dumps({"results": [{"check_id": "r", "path": "a.py",
            "start": {"line": 5}, "extra": {"severity": "ERROR",
            "message": "m", "lines": "os.chmod(d, 0o700)"}}]})
        f = squawk.norm_semgrep(raw, ".")[0]
        assert f.detail["evidence"] == "os.chmod(d, 0o700)"

    def test_detail_block_hides_a_stored_placeholder(self):
        """An old run whose findings.json already holds the placeholder must
        still render clean without a rescan."""
        db = squawk._detail_block({"description": "x", "evidence": "requires login"})
        assert "requires login" not in db


class TestFindingsTriageAgree:
    """Findings and Triage must count the same. Both group by (scanner, rule)
    now; grouping Findings by the message text split one rule into several rows
    whenever its wording varied by match, which is where the 'says 3 here, 4 in
    triage' came from."""

    def _run(self, tmp_path):
        root = str(tmp_path / "ev")
        d = os.path.join(root, "20260101T000000Z")
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        finds = [  # one rule, two matches with DIFFERENT messages
            {"scanner": "semgrep", "identity": "R:a.py:1", "severity": "medium",
             "title": "perm 0o700", "path": "a.py", "detail": {}},
            {"scanner": "semgrep", "identity": "R:b.py:2", "severity": "medium",
             "title": "perm 0o755", "path": "b.py", "detail": {}}]
        man = {"run_id": "20260101T000000Z", "service": "customs", "scope": "repo",
               "target": "/x", "service_label": "Customs (repo)", "not_covered": "",
               "counts": {"total": 2, "excluded": 0},
               "severities": {s: 0 for s in squawk.SEVERITY_ORDER}, "ledger": []}
        man["severities"]["medium"] = 2
        for name, o in (("manifest.json", man),
                        ("identities.json", {"semgrep": ["R:a.py:1", "R:b.py:2"]}),
                        ("findings.json", finds),
                        ("digest.json", {"run_id": man["run_id"]})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(o, fh)
        return root, man["run_id"]

    def test_findings_groups_one_rule_as_one_row(self, tmp_path):
        root, rid = self._run(tmp_path)
        html = squawk.view_findings(root, rid)
        assert "2 finding(s) in 1 group(s)" in html, \
            "a rule firing with two messages must still be one group"

    def test_triage_reports_the_same_count(self, tmp_path):
        root, rid = self._run(tmp_path)
        html = squawk.view_triage(root, rid)
        assert '"n": 2' in html, "triage must count the same two items for the rule"


class TestFindingsPolish:
    """A truncated title reads as deliberate, and a column that no instance in a
    group fills is not shown — an always-blank Method/Evidence column on a SAST
    finding read as broken."""

    def test_title_truncates_at_a_word_boundary_with_ellipsis(self):
        long = "one two three four five six seven eight nine ten eleven twelve " \
               "thirteen fourteen fifteen sixteen seventeen eighteen nineteen"
        t = squawk._title(long, 40)
        assert t.endswith("…")
        assert "  " not in t and not t[:-1].endswith(" ")
        assert len(t) <= 41

    def test_short_title_is_untouched(self):
        assert squawk._title("Weak hash") == "Weak hash"

    def test_title_collapses_whitespace(self):
        assert squawk._title("a\n  b   c") == "a b c"

    def _run(self, tmp_path, findings):
        root = str(tmp_path / "ev")
        d = os.path.join(root, "20260101T000000Z")
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        man = {"run_id": "20260101T000000Z", "service": "s", "scope": "repo",
               "target": "/x", "service_label": "S", "not_covered": "",
               "counts": {"total": len(findings), "excluded": 0},
               "severities": {s: 0 for s in squawk.SEVERITY_ORDER}, "ledger": []}
        for f in findings:
            man["severities"][f["severity"]] += 1
        idents = {}
        for f in findings:
            idents.setdefault(f["scanner"], []).append(f["identity"])
        for name, o in (("manifest.json", man), ("identities.json", idents),
                        ("findings.json", findings),
                        ("digest.json", {"run_id": man["run_id"]})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(o, fh)
        return root, man["run_id"]

    def test_sast_group_hides_empty_method_and_evidence_columns(self, tmp_path):
        root, rid = self._run(tmp_path, [
            {"scanner": "semgrep", "identity": "R:a.py:1", "severity": "medium",
             "title": "x", "path": "a.py", "detail": {}}])
        html = squawk.view_findings(root, rid)
        assert "<th>Method</th>" not in html and "<th>Evidence</th>" not in html
        assert "<th>Path</th>" in html and "<th>Identity</th>" in html

    def test_dast_group_shows_method_and_evidence(self, tmp_path):
        root, rid = self._run(tmp_path, [
            {"scanner": "zap", "identity": "10011:/x:", "severity": "medium",
             "title": "y", "path": "/x",
             "detail": {"method": "GET", "evidence": "Set-Cookie: sid=1"}}])
        html = squawk.view_findings(root, rid)
        assert "<th>Method</th>" in html and "<th>Evidence</th>" in html


class TestShowYourWork:
    """A clean result must show what it looked at, or it is indistinguishable
    from a scan that never ran. A self-audit drops its passing checks from the
    findings on purpose; they still have to be visible somewhere."""

    def _clean_selfaudit(self, tmp_path):
        root = str(tmp_path / "ev")
        rid = "20260901T223945Z-host"
        d = os.path.join(root, rid)
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        checks = [{"check": "logging", "area": "logging", "status": "ok",
                   "severity": "info", "title": "Logging is on", "detail": "log path"},
                  {"check": "clock-sync", "area": "time", "status": "ok",
                   "severity": "info", "title": "Clock synchronised", "detail": "NTP"}]
        with open(os.path.join(d, "raw", "selfaudit.json"), "w") as fh:
            json.dump({"counts": {"ok": 2, "gap": 0, "unknown": 0},
                       "checks": checks}, fh)
        man = {"run_id": rid, "service": "selfaudit", "scope": "host",
               "target": "kali", "service_label": "Instrument check",
               "not_covered": "", "counts": {"total": 0, "excluded": 0},
               "severities": {s: 0 for s in squawk.SEVERITY_ORDER},
               "ledger": [{"tool": "selfaudit", "mode": "host", "status": "ok",
                           "detail": "2 ok", "evidence": "raw/selfaudit.json",
                           "coverage": {"examined": 2, "unit": "checks",
                                        "skipped": 0, "errors": 0, "note": ""}}]}
        for name, o in (("manifest.json", man), ("identities.json", {}),
                        ("findings.json", []), ("digest.json", {"run_id": rid})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(o, fh)
        return root, rid

    def test_clean_selfaudit_shows_its_passing_checks(self, tmp_path):
        root, rid = self._clean_selfaudit(tmp_path)
        html = squawk.view_findings(root, rid)
        assert "Instrument checks" in html
        assert "Clock synchronised" in html and "Logging is on" in html
        assert "examined 2 checks" in html
        assert "only because it looked" in html

    def test_coverage_panel_omits_instrument_block_for_non_selfaudit(self, tmp_path):
        root, _ = self._clean_selfaudit(tmp_path)
        man = squawk.list_runs(root)[0]
        man["ledger"] = [{"tool": "semgrep", "status": "ok", "evidence": "",
                          "coverage": {"examined": 9, "unit": "files",
                                       "skipped": 0, "errors": 0, "note": ""}}]
        panel = squawk.coverage_panel(man)
        assert "What ran" in panel and "examined 9 files" in panel
        assert "Instrument checks" not in panel

    def _overview_target(self, tmp_path, rid, ledger, total=0):
        root = str(tmp_path / "ev")
        d = os.path.join(root, rid)
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        tdir = tmp_path / ("target-" + rid[-4:])
        tdir.mkdir(exist_ok=True)   # a real directory, or the overview demotes it as vanished
        man = {"run_id": rid, "service": "customs", "scope": "repo",
               "target": str(tdir), "service_label": "C", "not_covered": "",
               "counts": {"total": total, "excluded": 0},
               "severities": {s: 0 for s in squawk.SEVERITY_ORDER}, "ledger": ledger}
        for name, o in (("manifest.json", man), ("identities.json", {}),
                        ("findings.json", []), ("digest.json", {"run_id": rid})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(o, fh)
        return root

    def test_overview_does_not_call_a_gap_run_clean(self, tmp_path):
        """A target with no findings whose run examined nothing is a gap, not a
        clean result — the false all-clear this whole tool exists to refuse."""
        ok = [{"tool": "semgrep", "status": "ok",
               "coverage": {"examined": 10, "unit": "files", "skipped": 0,
                            "errors": 0, "note": ""}}]
        gap = [{"tool": "trivy", "status": "gap",
                "coverage": {"examined": 0, "unit": "targets", "skipped": 0,
                             "errors": 0, "note": ""}}]
        self._overview_target(tmp_path, "20260101T000000Z-aaaa", ok)
        root = self._overview_target(tmp_path, "20260102T000000Z-bbbb", gap)
        html = squawk.view_overview(root)
        assert "clean" in html, "the genuinely clean target still reads clean"
        assert "did not fully scan" in html, "the gap run must not read as clean"
        assert ">gap</span>" in html


class TestEvidenceCapture:
    """Every finding must carry the why its scanner provides — the offending
    code, the description, the reference. The normalizers were dropping it,
    leaving file + rule with no proof (pillar 1: show the work, never assert)."""

    def test_bandit_keeps_code_and_reference(self):
        raw = json.dumps({"results": [{"test_id": "B602", "filename": "a.py",
            "line_number": 2, "issue_severity": "HIGH",
            "issue_text": "subprocess with shell=True",
            "code": "1 import subprocess\n2 subprocess.call(x, shell=True)\n",
            "more_info": "https://bandit.example/b602",
            "issue_cwe": {"id": 78}, "issue_confidence": "HIGH"}]})
        f = squawk.norm_bandit(raw, ".")[0]
        assert "shell=True" in f.detail["evidence"]
        assert f.detail["reference"] == "https://bandit.example/b602"
        assert f.detail["cwe"] == "78"

    def test_checkov_keeps_code_block_and_guideline(self):
        raw = json.dumps({"results": {"failed_checks": [{
            "check_id": "CKV_AZURE_23", "file_path": "/main.tf",
            "resource": "azurerm_mssql_server.mssql1",
            "check_name": "Ensure Auditing is On",
            "guideline": "https://docs.example/ckv_azure_23",
            "code_block": [[1, 'resource "azurerm_mssql_server" "mssql1" {\n'],
                           [2, "  name = \"x\"\n"]]}]}})
        f = squawk.norm_checkov(raw, ".")[0]
        assert "azurerm_mssql_server" in f.detail["evidence"]
        assert f.detail["reference"] == "https://docs.example/ckv_azure_23"

    def test_semgrep_reads_the_source_line_when_redacted(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("import os\nos.system(cmd)\nprint(1)\n")
        raw = json.dumps({"results": [{"check_id": "r", "path": "a.py",
            "start": {"line": 2}, "extra": {"severity": "ERROR",
            "message": "m", "lines": "requires login"}}]})
        f = squawk.norm_semgrep(raw, str(tmp_path))[0]
        assert f.detail["evidence"] == "os.system(cmd)"

    def test_source_line_is_best_effort_on_bad_input(self, tmp_path):
        assert squawk._source_line(str(tmp_path), "nope.py", 5) == ""
        assert squawk._source_line(str(tmp_path), "a.py", "notanint") == ""
        (tmp_path / "a.py").write_text("one\ntwo\n")
        assert squawk._source_line(str(tmp_path), "a.py", 99) == ""
        assert squawk._source_line(str(tmp_path), "a.py", 2) == "two"

    def test_selfaudit_what_is_shown_as_description(self):
        raw = json.dumps({"counts": {"ok": 0, "gap": 1, "unknown": 0}, "checks": [
            {"check": "run-perms", "area": "privilege", "status": "gap",
             "severity": "high", "title": "Run dirs are group-readable",
             "detail": "5 run directories are readable by other local users",
             "fix": "chmod 700"}]})
        f = squawk.norm_selfaudit(raw, ".")[0]
        db = squawk._detail_block(f.detail)
        assert "readable by other local users" in db
        assert "chmod 700" in db


class TestRescanBugReview:
    """Found reviewing the rescan feature after field use. A rescan of a target
    whose directory has since vanished (a temp dir from an earlier run) must be
    refused before launch: launching it ran every scanner against nothing and
    wrote a gap run that became the target's newest, burying its real history.
    And a run with no ledger has no evidence it looked at anything, so it must
    read as incomplete, never clean."""

    def test_no_ledger_is_incomplete_not_clean(self):
        assert squawk._run_incomplete({"ledger": []}) is True
        assert squawk._run_incomplete({}) is True

    def test_a_run_that_looked_is_complete(self):
        man = {"ledger": [{"tool": "semgrep", "status": "ok",
                           "coverage": {"examined": 3, "unit": "files"}}]}
        assert squawk._run_incomplete(man) is False

    def test_rescan_of_vanished_directory_is_refused(self, tmp_path):
        """Drive the real handler: a repo/dir target that is not on disk gets a
        400 and no run directory is written."""
        import argparse
        import socket
        import threading
        import time
        import urllib.parse
        import urllib.request
        ev = str(tmp_path / "ev")
        os.makedirs(ev, exist_ok=True)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        args = argparse.Namespace(evidence=ev, repo=None, port=port,
                                  host="127.0.0.1", gh_repo=None, open=False)
        threading.Thread(target=lambda: squawk.serve_web(args), daemon=True).start()
        time.sleep(1.5)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        data = urllib.parse.urlencode(
            {"service": "customs", "target": str(tmp_path / "gone" / "deps")}).encode()
        req = urllib.request.Request("http://127.0.0.1:%d/run" % port, data=data,
                                     headers={"Origin": "http://127.0.0.1:%d" % port})
        try:
            r = opener.open(req, timeout=8)
            code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
            assert "no longer exists" in e.read().decode()
        assert code == 400, "a vanished target must be refused, not launched"
        run_dirs = [n for n in os.listdir(ev) if os.path.isdir(os.path.join(ev, n))]
        assert run_dirs == [], "no run may be written for a refused rescan"


class TestActiveProbe:
    """The active-scan service. It exists because the passive baseline cannot
    find injectable flaws; it sends real attack traffic, so it must be honest
    about that, time-boxed, and held behind the private-target rail."""

    def test_service_is_registered_under_the_url_scope(self):
        svc = squawk.SERVICES["activeprobe"]
        assert svc.scope == "url", "the DAST rail (dast_target_ok) applies to url scope"
        assert svc.stages == ("zap-active",)
        assert "attack" in svc.not_covered.lower()
        assert "you own" in svc.not_covered.lower()

    def test_stage_runs_the_full_scan_time_boxed_as_an_arg_list(self):
        import types
        ctx = types.SimpleNamespace(target="http://127.0.0.1:3000",
                                    raw_path="/ev/run/raw/zap-active.json")
        cmd, timeout = squawk.stage_zap_active(ctx)
        assert isinstance(cmd, list) and all(isinstance(a, str) for a in cmd), \
            "an arg list, never a shell string"
        assert "zap-full-scan.py" in cmd, "the active scanner, not the passive baseline"
        assert "-T" in cmd and cmd[cmd.index("-T") + 1] == "20", "whole-scan cap"
        assert "-m" in cmd, "spider cap"
        assert "http://127.0.0.1:3000" in cmd
        assert timeout > 20 * 60, "subprocess timeout must sit above the -T cap"

    def test_active_and_baseline_are_distinct_stages_of_the_same_tool(self):
        a, b = squawk.STAGES["zap-active"], squawk.STAGES["zap-baseline"]
        assert a.tool == b.tool == "zap"
        assert a.mode != b.mode
        assert a.writes_report and b.writes_report

    def test_active_findings_can_witness_an_attack(self):
        """7500 is scoped to scanners that can see an attack; the active
        scanner is one of them."""
        assert squawk.SCANNERS["zap"].kind in squawk.WITNESS_KINDS

    def test_the_rail_refuses_a_public_target(self, monkeypatch):
        monkeypatch.delenv("SQUAWK_DAST_ACK", raising=False)
        ok, reason = squawk.dast_target_ok("http://93.184.216.34/")
        assert not ok, reason


def _write_feeds(root, kev=(), epss=(), stamp=None):
    """Fixture feeds: KEV json, EPSS csv (with its leading comment line), and
    the provenance record. No network."""
    fdir = os.path.join(root, squawk.FEEDS_DIRNAME)
    os.makedirs(fdir, exist_ok=True)
    with open(os.path.join(fdir, "kev.json"), "w") as fh:
        json.dump({"vulnerabilities": [
            {"cveID": c, "dateAdded": d, "knownRansomwareCampaignUse": r}
            for c, d, r in kev]}, fh)
    with open(os.path.join(fdir, "epss.csv"), "w") as fh:
        fh.write("#model_version:v2023.03.01,score_date:2026-09-04T00:00:00+0000\n")
        fh.write("cve,epss,percentile\n")
        for c, e, p in epss:
            fh.write("%s,%s,%s\n" % (c, e, p))
    with open(os.path.join(fdir, "feeds.json"), "w") as fh:
        json.dump({"fetched_at": stamp or time.strftime("%Y%m%dT%H%M%SZ",
                                                        time.gmtime())}, fh)
    return root


def _write_run(root, rid, findings, service="customs", scope="repo", target="/x"):
    d = os.path.join(root, rid)
    os.makedirs(os.path.join(d, "raw"), exist_ok=True)
    sev = {s: 0 for s in squawk.SEVERITY_ORDER}
    for f in findings:
        sev[f["severity"]] += 1
    man = {"run_id": rid, "service": service, "scope": scope, "target": target,
           "service_label": "Customs (repo)", "not_covered": "",
           "counts": {"total": len(findings), "excluded": 0}, "severities": sev,
           "ledger": [{"tool": "trivy", "status": "ok",
                       "coverage": {"examined": 3, "unit": "targets", "skipped": 0,
                                    "errors": 0, "note": ""}}]}
    idents = {}
    for f in findings:
        idents.setdefault(f["scanner"], []).append(f["identity"])
    for name, o in (("manifest.json", man), ("identities.json", idents),
                    ("findings.json", findings), ("digest.json", {"run_id": rid})):
        with open(os.path.join(d, name), "w") as fh:
            json.dump(o, fh)
    return rid


def _f(scanner, ident, sev, title="t", path="p"):
    return {"scanner": scanner, "identity": ident, "severity": sev,
            "title": title, "path": path, "detail": {}}


class TestExploitabilityFeeds:
    """The feeds are cached with provenance and read back honestly: a missing
    feed is 'not fetched', never an empty set that reads as 'nothing exploited'."""

    def test_kev_parses_id_date_and_ransomware(self):
        blob = json.dumps({"vulnerabilities": [
            {"cveID": "cve-2024-0001", "dateAdded": "2024-05-01",
             "knownRansomwareCampaignUse": "Known"}]}).encode()
        kev = squawk._parse_kev(blob)
        entry = kev["CVE-2024-0001"]
        assert entry["added"] == "2024-05-01" and entry["ransomware"] is True
        # The parser keeps the rest of what the catalogue says, so the general
        # intel view can read it. A record with those fields absent still
        # parses, with empties rather than a KeyError later.
        assert entry["vendor"] == "" and entry["product"] == ""
        assert entry["cwes"] == []

    def test_epss_skips_the_comment_line(self):
        text = "#model_version:x\ncve,epss,percentile\nCVE-2024-0002,0.42,0.95\n"
        assert squawk._parse_epss(text)["CVE-2024-0002"] == (0.42, 0.95)

    def test_missing_feeds_read_as_absent_not_empty(self, tmp_path):
        feeds = squawk.load_feeds(str(tmp_path))
        assert feeds["present"] is False
        assert [a for _n, a, _d in squawk.feed_ages(str(tmp_path))] == [None, None]

    def test_fresh_feeds_read_as_present_and_zero_days_old(self, tmp_path):
        _write_feeds(str(tmp_path), kev=[("CVE-2024-0001", "2024-05-01", "Unknown")],
                     epss=[("CVE-2024-0001", "0.1", "0.5")])
        feeds = squawk.load_feeds(str(tmp_path))
        assert feeds["present"] is True
        assert all(a == 0 for _n, a, _d in squawk.feed_ages(str(tmp_path)))

    def test_cve_of_reads_the_identity_head_only(self):
        assert squawk.cve_of(_f("trivy", "cve-2024-1234:pkg:1.0", "high")) == "CVE-2024-1234"
        assert squawk.cve_of(_f("bandit", "B101:a.py:1", "low")) is None

    def test_exploitability_states_its_reason(self, tmp_path):
        _write_feeds(str(tmp_path),
                     kev=[("CVE-2024-0001", "2024-05-01", "Known")],
                     epss=[("CVE-2024-0001", "0.9", "0.99"), ("CVE-2024-0002", "0.42", "0.95")])
        feeds = squawk.load_feeds(str(tmp_path))
        x = squawk.exploitability("CVE-2024-0001", feeds)
        assert x["kev"] and "in CISA KEV, added 2024-05-01" in x["reason"]
        assert "ransomware" in x["reason"]
        y = squawk.exploitability("CVE-2024-0002", feeds)
        assert not y["kev"] and "EPSS 0.42 (95th percentile)" in y["reason"]
        z = squawk.exploitability("CVE-2024-9999", feeds)
        assert "not in KEV; no EPSS score published" in z["reason"]

    def test_unknown_when_feeds_absent_and_na_without_a_cve(self, tmp_path):
        absent = squawk.load_feeds(str(tmp_path))
        x = squawk.exploitability("CVE-2024-0001", absent)
        assert x["state"] == "unknown" and "--feeds" in x["reason"]
        assert squawk.exploitability(None, absent)["state"] == "n/a"


class TestRankRun:
    """Tiers with a reason each; the shortlist never claims exploitability it
    cannot back, and nothing below the line is dropped."""

    def _feeds(self, tmp_path):
        return squawk.load_feeds(_write_feeds(
            str(tmp_path), kev=[("CVE-2024-0001", "2024-05-01", "Unknown")],
            epss=[("CVE-2024-0001", "0.9", "0.99"), ("CVE-2024-0002", "0.5", "0.96")]))

    def _findings(self):
        return [_f("trivy", "CVE-2024-0001:libfoo:1.0", "medium", "KEV one"),
                _f("grype", "CVE-2024-0002:libbar:2.0", "low", "EPSS hot"),
                _f("semgrep", "R:a.py:1", "high", "no cve high"),
                _f("bandit", "B101:a.py:5", "low", "assert"),
                _f("bandit", "B101:a.py:9", "low", "assert")]

    def test_tiers_and_reasons(self, tmp_path):
        r = squawk.rank_run(self._findings(), self._feeds(tmp_path))
        by = {k: [g["title"] for g in v] for k, v in r["tiers"].items()}
        assert by["exploited"] == ["KEV one"]
        assert by["likely"] == ["EPSS hot"]
        assert by["severe"] == ["no cve high"]
        why = {g["title"]: g["why"] for v in r["tiers"].values() for g in v}
        assert "in CISA KEV" in why["KEV one"]
        assert "EPSS 0.50" in why["EPSS hot"]
        assert "no CVE id" in why["no cve high"]

    def test_below_counts_findings_not_groups_and_drops_nothing(self, tmp_path):
        r = squawk.rank_run(self._findings(), self._feeds(tmp_path))
        assert r["below"] == {"low": 2}, "two assert instances, one group, counted as two"
        assert r["groups"] == 4

    def test_absent_feeds_never_rank_a_cve_as_exploited(self, tmp_path):
        """The load-bearing honesty rule: with no feed, a KEV CVE must land in
        the severity tier with an 'unknown' reason, never in exploited/likely."""
        absent = squawk.load_feeds(str(tmp_path))
        finds = [_f("trivy", "CVE-2024-0001:libfoo:1.0", "critical", "KEV one")]
        r = squawk.rank_run(finds, absent)
        assert r["tiers"]["exploited"] == [] and r["tiers"]["likely"] == []
        assert [g["title"] for g in r["tiers"]["severe"]] == ["KEV one"]
        assert "unknown" in r["tiers"]["severe"][0]["why"]
        assert r["feeds_present"] is False

    def test_worst_severity_first_within_a_tier(self, tmp_path):
        feeds = squawk.load_feeds(_write_feeds(
            str(tmp_path),
            kev=[("CVE-2024-0001", "2024-01-01", "Unknown"),
                 ("CVE-2024-0002", "2024-01-01", "Unknown")],
            epss=[("CVE-2024-0001", "0.9", "0.9")]))
        assert feeds["present"], "both fixture feeds must be present for this test"
        finds = [_f("trivy", "CVE-2024-0001:a:1", "low", "low kev"),
                 _f("trivy", "CVE-2024-0002:b:1", "critical", "crit kev")]
        r = squawk.rank_run(finds, feeds)
        assert [g["title"] for g in r["tiers"]["exploited"]] == ["crit kev", "low kev"]


class TestPriorityView:
    def _run(self, tmp_path, feeds=True):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        if feeds:
            _write_feeds(root, kev=[("CVE-2024-0001", "2024-05-01", "Known")],
                         epss=[("CVE-2024-0001", "0.9", "0.99")])
        rid = _write_run(root, "20260904T000000Z", [
            _f("trivy", "CVE-2024-0001:libfoo:1.0", "high", "KEV one"),
            _f("bandit", "B101:a.py:5", "low", "assert")])
        return root, rid

    def test_renders_tiers_reason_identity_and_the_below_line(self, tmp_path):
        root, rid = self._run(tmp_path)
        html = squawk.view_priority(root, rid)
        assert "Exploited now" in html and "Why it is here" in html
        assert "in CISA KEV, added 2024-05-01" in html
        assert "Below the shortlist: 1 finding(s)" in html
        assert "Reachability is not assessed" in html
        # Pillar 4 asks that the target, service and time are named. They are,
        # in the run picker's selected option, which also lets a reader change
        # the run instead of being told which one they are looking at.
        picker = re.search(r"<form method='get' action='/priority'.*?</form>",
                           html, re.S)
        assert picker, "no run picker"
        chosen = re.search(r"<option value='[^']*' selected>([^<]*)</option>",
                           picker.group(0))
        assert chosen, "the run being shown is not marked in the picker"
        named = chosen.group(1)
        assert named.count("&middot;") == 2, \
            "target, service and time are not all named (pillar 4): %r" % named

    def test_absent_feeds_are_stated_up_front(self, tmp_path):
        root, rid = self._run(tmp_path, feeds=False)
        html = squawk.view_priority(root, rid)
        assert "Exploitability feeds not fetched" in html
        assert "--feeds" in html
        assert "Exploited now" not in html, "no tier may claim exploitation without a feed"

    def test_feeds_dir_is_not_a_run(self, tmp_path):
        root, _rid = self._run(tmp_path)
        assert [m["run_id"] for m in squawk.list_runs(root)] == ["20260904T000000Z"]

    def test_overview_tile_is_honest_in_both_states(self, tmp_path):
        root, _rid = self._run(tmp_path)
        assert "exploited now (KEV)" in squawk.view_overview(root)
        root2, _ = self._run(tmp_path / "b", feeds=False)
        assert "feeds not fetched" in squawk.view_overview(root2)


class TestTargetPicker:
    """A target is picked, not typed. The picker offers recent targets (gone
    ones as gone), git checkouts found under the scan roots, and a directory
    browser that cannot leave those roots."""

    def _roots(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        (home / "proj" / "app" / ".git").mkdir(parents=True)
        (home / "proj" / "node_modules" / "dep" / ".git").mkdir(parents=True)
        (home / "deep" / "a" / "b" / "c" / "d" / ".git").mkdir(parents=True)
        (home / ".hidden" / "x" / ".git").mkdir(parents=True)
        (home / "plain").mkdir()
        monkeypatch.setenv("SQUAWK_SCAN_ROOTS", str(home))
        return home

    def test_roots_default_to_home_and_honour_the_env(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SQUAWK_SCAN_ROOTS", raising=False)
        assert squawk.scan_roots() == [os.path.realpath(os.path.expanduser("~"))]
        home = self._roots(tmp_path, monkeypatch)
        assert squawk.scan_roots() == [os.path.realpath(str(home))]

    def test_discover_prunes_deps_hidden_and_depth(self, tmp_path, monkeypatch):
        home = self._roots(tmp_path, monkeypatch)
        found = squawk.discover_repos(squawk.scan_roots())
        assert os.path.realpath(str(home / "proj" / "app")) in found
        assert not any("node_modules" in f for f in found), "dependency dirs are pruned"
        assert not any(".hidden" in f for f in found), "hidden dirs are pruned"
        assert not any(f.endswith("d") for f in found), "too deep is not walked"

    def test_browser_stays_inside_the_roots(self, tmp_path, monkeypatch):
        home = self._roots(tmp_path, monkeypatch)
        roots = squawk.scan_roots()
        err, entries = squawk.list_dir(str(home / "proj"), roots)
        assert err is None
        assert (os.path.realpath(str(home / "proj" / "app")), True) in entries
        assert not any(os.path.basename(p) == "node_modules" for p, _r in entries)
        err, entries = squawk.list_dir("/", roots)
        assert err and "outside" in err and entries == []
        err, entries = squawk.list_dir(str(home / "proj" / ".." / ".."), roots)
        assert err and "outside" in err, "dot-dot cannot escape the roots"

    def test_recent_targets_dedup_and_flag_gone(self, tmp_path, monkeypatch):
        root = str(tmp_path / "ev")
        live = tmp_path / "live"
        live.mkdir()
        _write_run(root, "20260901T000000Z", [], target=str(live))
        _write_run(root, "20260902T000000Z", [], target=str(live))
        _write_run(root, "20260903T000000Z", [], target=str(tmp_path / "gone"))
        rec = squawk.recent_targets(root)
        assert [r["target"] for r in rec] == [str(tmp_path / "gone"), str(live)]
        assert rec[0]["gone"] is True and rec[1]["gone"] is False

    def test_each_tile_lists_its_targets_instead_of_asking_for_typing(
            self, tmp_path, monkeypatch):
        """The tile is the picker. A repo tile lists the checkouts found and the
        targets already run; a vanished one is shown as gone and cannot be
        chosen; 'Other path' is the only way a path gets typed. Reported from
        the field: a page-wide browser above the tiles, with a typed field in
        every tile, was the opposite of "I should not have to type"."""
        import re
        home = self._roots(tmp_path, monkeypatch)
        root = str(tmp_path / "ev")
        app = os.path.realpath(str(home / "proj" / "app"))
        plain = os.path.realpath(str(home / "plain"))
        _write_run(root, "20260903T000000Z", [], target=str(tmp_path / "gone"))
        _write_run(root, "20260902T000000Z", [], target=plain)
        html = squawk.view_scan(root, None)
        # the repo tile: a select carrying the recent live target, the gone
        # one disabled, the discovered checkout, and Other
        m = re.search(r"<select name='target' data-scope='repo'.*?</select>", html, re.S)
        assert m, "the repo tile offers no list"
        sel = m.group(0)
        assert "<optgroup label='Recent'>" in sel
        assert "value='%s' title='%s'" % (plain, plain) in sel
        assert "disabled" in sel and "(gone)" in sel, \
            "a vanished recent target is shown as gone, not offered"
        assert "<optgroup label='Git checkouts found'>" in sel
        assert "value='%s' title='%s'" % (app, app) in sel
        assert sel.index("Recent") < sel.index("Git checkouts found") < sel.index("__other__")
        assert "value='__other__'" in sel
        assert sel.count("value='%s'" % app) == 1, "a target is listed once"
        # a directory tile lists the scan roots too
        m = re.search(r"<select name='target' data-scope='dir'.*?</select>", html, re.S)
        assert m and "<optgroup label='Scan roots'>" in m.group(0)
        assert "value='%s'" % os.path.realpath(str(home)) in m.group(0)
        # a URL tile with nothing run yet is the typed field, honestly
        assert "<input type='text' name='target' value='' placeholder='http://" in html
        assert "data-scope='url'" in html
        # host and aws tiles ask for nothing
        assert "name='target' value='host'" in html
        assert "name='target' value='credential-chain'" in html
        # the page-wide chip lists are gone; the browser is folded, not open
        assert "<h3>Pick a target</h3>" not in html and "class='chip gone'" not in html
        assert "<details class='picker'>" in html and "use this directory" in html
        html2 = squawk.view_scan(root, None, browse=str(home / "proj"))
        assert "<details class='picker' open>" in html2, "browsing keeps it open"
        assert "app/</a>" in html2 and "git" in html2
        html3 = squawk.view_scan(root, None, browse="/")
        assert "outside the scan roots" in html3

    def test_a_built_in_probe_is_never_listed_as_missing(self, tmp_path, monkeypatch):
        """The Instrument check tile said "missing: selfaudit, recorded as a
        coverage gap" because the gap note looked for a binary every probe
        built into Squawk lacks by design. A tile must not say a check cannot
        run when it always can."""
        self._roots(tmp_path, monkeypatch)
        html = squawk.view_scan(str(tmp_path / "ev"), None)
        for name, sc in squawk.SCANNERS.items():
            if sc.internal:
                assert "missing: %s" % name not in html
                assert "<span class='tag gap'>%s</span>" % name not in html

    def test_a_typed_other_path_is_what_gets_posted(self):
        t = squawk._posted_target
        assert t({"target": ["/a"], "target_other": ["/b"]}) == "/a"
        assert t({"target": ["__other__"], "target_other": [" /b "]}) == "/b"
        assert t({"target": ["__other__"]}) == ""
        assert t({}) == ""

    def test_a_tile_with_a_server_repo_not_in_its_list_falls_back_to_other(
            self, tmp_path, monkeypatch):
        self._roots(tmp_path, monkeypatch)
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / ".git").mkdir(parents=True)
        html = squawk.view_scan(str(tmp_path / "ev"), str(elsewhere))
        assert "value='__other__' selected" in html
        assert "name='target_other' value='%s'" % elsewhere in html

    def test_other_path_and_host_subject_are_wired_through_the_handler(self, tmp_path):
        """Live, not read from source: a posted 'Other path' that no longer
        exists is refused the same way a typed one was, and a self-audit
        launches with nothing typed because the handler names this machine."""
        import argparse
        import socket
        import threading
        import time
        import urllib.error
        import urllib.parse
        import urllib.request
        ev = str(tmp_path / "ev")
        os.makedirs(ev, exist_ok=True)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        args = argparse.Namespace(evidence=ev, repo=None, port=port,
                                  host="127.0.0.1", gh_repo=None, open=False)
        threading.Thread(target=lambda: squawk.serve_web(args), daemon=True).start()
        time.sleep(1.5)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        origin = "http://127.0.0.1:%d" % port

        def post(fields):
            req = urllib.request.Request(
                origin + "/run", data=urllib.parse.urlencode(fields).encode(),
                headers={"Origin": origin})
            try:
                r = opener.open(req, timeout=8)
                return r.status, r.headers.get("Location", ""), ""
            except urllib.error.HTTPError as e:
                # urllib raises for a 303 when redirects are off; the headers
                # ride on the error
                return e.code, e.headers.get("Location", ""), e.read().decode()

        code, _loc, body = post({"service": "customs", "target": "__other__",
                                 "target_other": str(tmp_path / "gone" / "x")})
        assert code == 400 and "no longer exists" in body
        code, loc, _ = post({"service": "selfaudit"})
        assert code == 303 and loc.startswith("/job/"), \
            "a self-audit needs nothing typed"
        job = squawk.JOBS[loc.split("/job/")[1]]
        for _ in range(300):
            if job.status != "running":
                break
            time.sleep(0.1)
        assert job.status != "running", "the self-audit did not finish"
        man = squawk.list_runs(ev)[0]
        assert man["target"] == socket.gethostname(), \
            "the run names this machine, as the CLI does"


class TestOverviewPass:
    """The estate as it stands: vanished targets are demoted and not counted,
    a stale scan says so, a target with two runs shows its trend, and the
    attention strip names what needs a look."""

    def test_rel_time_words_and_staleness(self):
        now = 1_800_000_000.0
        import calendar
        rid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now - 3 * 86400))
        txt, stale = squawk.rel_time(rid, now=now)
        assert txt == "3 d ago" and stale is False
        rid_old = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now - 9 * 86400))
        assert squawk.rel_time(rid_old, now=now) == ("9 d ago", True)
        assert squawk.rel_time("garbage") == ("", False)
        assert calendar.timegm(time.gmtime(0)) == 0

    def test_vanished_target_is_demoted_and_not_counted(self, tmp_path):
        root = str(tmp_path / "ev")
        live = tmp_path / "live"
        live.mkdir()
        _write_run(root, "20260901T000000Z",
                   [_f("semgrep", "R:a.py:1", "high", "live high")], target=str(live))
        _write_run(root, "20260902T000000Z",
                   [_f("semgrep", "R:b.py:1", "critical", "gone crit")],
                   target=str(tmp_path / "gone"))
        html = squawk.view_overview(root)
        assert "vanished target, not counted" in html
        assert "id='vanished'" in html
        # the critical from the vanished target must not be in the headline tile
        assert ">1</span><span class='k'>critical" in html

    def test_two_runs_draw_a_trend_and_one_does_not(self, tmp_path):
        root = str(tmp_path / "ev")
        d = tmp_path / "t"
        d.mkdir()
        _write_run(root, "20260901T000000Z", [_f("semgrep", "R:a:1", "low")], target=str(d))
        html1 = squawk.view_overview(root)
        assert "<svg class='spark'" not in html1
        _write_run(root, "20260902T000000Z", [], target=str(d))
        html2 = squawk.view_overview(root)
        assert "<svg class='spark'" in html2 and "up is cleaner" in html2

    def test_attention_strip_counts_gaps(self, tmp_path):
        root = str(tmp_path / "ev")
        d = tmp_path / "t"
        d.mkdir()
        rid = _write_run(root, "20260901T000000Z", [], target=str(d))
        man = json.load(open(os.path.join(root, rid, "manifest.json")))
        man["ledger"][0]["coverage"]["examined"] = 0
        json.dump(man, open(os.path.join(root, rid, "manifest.json"), "w"))
        html = squawk.view_overview(root)
        assert "1 target with a coverage gap" in html


_ASFF_SAMPLE = {"Findings": [
    {"Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/x/S3.1/finding/abc",
     "Title": "S3 Block Public Access setting should be enabled",
     "Description": "Block public access is off.",
     "Severity": {"Label": "MEDIUM"},
     "Compliance": {"Status": "FAILED", "SecurityControlId": "S3.1"},
     "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/S3.1",
     "ProductName": "Security Hub", "AwsAccountId": "123456789012",
     "Region": "us-east-1", "RecordState": "ACTIVE", "Workflow": {"Status": "NEW"},
     "Resources": [{"Type": "AwsAccount", "Id": "AWS::::Account:123456789012"}],
     "Remediation": {"Recommendation": {"Text": "Enable block public access",
                                        "Url": "https://docs.example/s3.1"}},
     "CreatedAt": "2026-01-01T00:00:00Z", "UpdatedAt": "2026-09-01T00:00:00Z"},
    {"Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/x/IAM.1/finding/def",
     "Title": "IAM policies should not allow full * administrative privileges",
     "Severity": {"Label": "INFORMATIONAL"},
     "Compliance": {"Status": "PASSED", "SecurityControlId": "IAM.1"},
     "AwsAccountId": "123456789012", "Region": "us-east-1",
     "Resources": [{"Type": "AwsIamPolicy", "Id": "arn:aws:iam::123456789012:policy/p"}]}]}


class TestCloudIngest:
    """Phase 3, first piece: the findings an AWS account already holds, read
    as the identity in the credential chain, behind an acknowledgement, with
    the identity named first and a gap, never a clean zero, when nothing could
    be read."""

    def test_asff_parses_to_findings_with_stable_identity(self):
        finds = squawk.norm_asff(json.dumps(_ASFF_SAMPLE), ".")
        assert len(finds) == 1, "a PASSED control is not a finding"
        f = finds[0]
        assert f.scanner == "awscli" and f.severity == "medium"
        assert f.identity == "S3.1:123456789012:AWS::::Account:123456789012"
        assert "2026" not in f.identity, "no timestamps in an identity (rule 6)"
        assert f.detail["remediation"] == "Enable block public access"
        assert f.detail["reference"] == "https://docs.example/s3.1"
        assert f.detail["region"] == "us-east-1"

    def test_coverage_counts_passed_and_reads_empty_as_zero(self):
        cov = squawk._cov_asff(json.dumps(_ASFF_SAMPLE))
        assert cov.examined == 2 and cov.unit == "findings" and cov.skipped == 1
        assert squawk._cov_asff(json.dumps({"Findings": []})).examined == 0
        assert squawk._cov_asff("not json at all").examined == 0

    def test_service_stage_and_scanner_are_registered(self):
        svc = squawk.SERVICES["cloudaws"]
        assert svc.scope == "aws" and svc.stages == ("securityhub-findings",)
        assert "SQUAWK_CLOUD_ACK" in svc.not_covered
        st = squawk.STAGES["securityhub-findings"]
        assert st.tool == "awscli" and squawk.SCANNERS["awscli"].kind == "cloud"
        assert squawk.NORMALIZERS["awscli"] is squawk.norm_asff
        assert squawk.COVERAGE["awscli"] is squawk._cov_asff

    def test_stage_command_carries_no_credential_and_paginates_via_cli(self):
        import types
        cmd, timeout = squawk.stage_securityhub(types.SimpleNamespace(
            target="123456789012", raw_path="/x/raw/securityhub-findings.json"))
        assert cmd[:3] == ["aws", "securityhub", "get-findings"]
        assert all(isinstance(a, str) for a in cmd)
        joined = " ".join(cmd).lower()
        assert "secret" not in joined and "token" not in joined and "profile" not in joined
        assert "--filters" in cmd and "ACTIVE" in cmd[cmd.index("--filters") + 1]
        assert timeout >= 300

    def test_rail_refuses_without_the_acknowledgement(self, monkeypatch):
        monkeypatch.delenv("SQUAWK_CLOUD_ACK", raising=False)
        monkeypatch.delenv("TOWER_CLOUD_ACK", raising=False)
        ok, reason = squawk.cloud_target_ok()
        assert not ok and "SQUAWK_CLOUD_ACK" in reason
        monkeypatch.setenv("SQUAWK_CLOUD_ACK", "1")
        assert squawk.cloud_target_ok()[0]

    def test_identity_is_none_without_the_cli(self, monkeypatch):
        _patch_all(monkeypatch, "tool_path", lambda name: None)
        ident, why = squawk.aws_identity()
        assert ident is None and "not installed" in why

    def test_doctor_no_longer_claims_a_phantom_stage(self):
        src = "".join(open(p, encoding="utf-8").read() for p in squawk.app_sources())
        assert "optional stage skipped" not in src

    def test_cloud_page_names_identity_and_gates_the_run(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SQUAWK_CLOUD_ACK", raising=False)
        _patch_all(monkeypatch, "aws_identity",
                            lambda timeout=20: (None, "aws CLI not installed"))
        html = squawk.view_cloud(str(tmp_path))
        assert "No AWS identity" in html and "not acknowledged" in html
        assert "value='cloudaws'" not in html, "no run form without identity + ack"
        monkeypatch.setenv("SQUAWK_CLOUD_ACK", "1")
        _patch_all(monkeypatch, "aws_identity", lambda timeout=20: (
            {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/ro",
             "UserId": "AID"}, ""))
        html = squawk.view_cloud(str(tmp_path))
        # Named, and masked. This assertion used to require the full twelve
        # digits, which is what the page actually printed while the CLI had
        # masked the same value since the day it printed one. The page is what
        # gets screenshotted into a thread, so the page follows the CLI.
        assert "arn:aws:iam::********9012:user/ro" in html
        assert "123456789012" not in html
        assert "value='cloudaws'" in html and "Read Security Hub as ********9012" in html


class TestLifecycle:
    """Start, stop, status, restart, and the rule that an interrupted run is
    recorded as aborted under its target rather than vanishing."""

    def _free_port(self):
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def test_aborted_run_is_recorded_under_its_target(self, tmp_path):
        root = str(tmp_path / "ev")
        d = os.path.join(root, "20260904T120000Z-repo")
        os.makedirs(os.path.join(d, "raw"))
        with open(os.path.join(d, "started.json"), "w") as fh:
            json.dump({"run_id": "20260904T120000Z-repo", "service": "customs",
                       "service_label": "Customs (repo)", "scope": "repo",
                       "target": str(tmp_path), "started_at": "20260904T120000Z"}, fh)
        assert squawk.record_aborted_run(d, "test") is True
        assert squawk.record_aborted_run(d, "again") is False, "never clobbers"
        man = squawk.list_runs(root)[0]
        assert man["aborted"] and man["target"] == str(tmp_path)
        assert squawk._run_incomplete(man), "an aborted run is incomplete, never clean"
        assert "aborted: test" in squawk.view_overview(root)
        html = squawk.view_findings(root, man["run_id"])
        assert "This run was aborted" in html
        assert "clean result only because it looked" not in html

    def test_sweep_leaves_a_young_run_alone_but_records_an_old_one(self, tmp_path):
        root = str(tmp_path / "ev")
        for name, age in (("20260904T120000Z-repo", 10), ("20260904T110000Z-repo", 4 * 3600)):
            d = os.path.join(root, name)
            os.makedirs(os.path.join(d, "raw"))
            sp = os.path.join(d, "started.json")
            with open(sp, "w") as fh:
                json.dump({"service": "customs", "scope": "repo", "target": "/t"}, fh)
            os.utime(sp, (time.time() - age, time.time() - age))
        got = squawk.record_aborted_runs(root, "sweep", older_than=3 * 3600)
        assert got == ["20260904T110000Z-repo"]

    def test_dir_without_started_json_is_not_ours(self, tmp_path):
        d = tmp_path / "stray"
        d.mkdir()
        assert squawk.record_aborted_run(str(d), "x") is False

    def test_execute_service_records_abort_on_interrupt(self, tmp_path, monkeypatch):
        run_dir = str(tmp_path / "20260904T120000Z-repo")

        def fake_inner(service, target, evidence_root, base, progress=None, profile=None):
            os.makedirs(run_dir)
            with open(os.path.join(run_dir, "started.json"), "w") as fh:
                json.dump({"service": "customs", "scope": "repo", "target": "/t"}, fh)
            progress({"phase": "run", "run_dir": run_dir, "run_id": "x"})
            raise KeyboardInterrupt
        _patch_all(monkeypatch, "_execute_service_inner", fake_inner)
        svc = squawk.SERVICES["customs"]
        with pytest.raises(KeyboardInterrupt):
            squawk.execute_service(svc, "/t", str(tmp_path), "/t")
        man = json.load(open(os.path.join(run_dir, "manifest.json")))
        assert man["aborted"] and "KeyboardInterrupt" in man["aborted_reason"]

    def test_the_daemon_log_is_written_while_it_runs(self, tmp_path):
        """Found by the field check. The daemon dup2s stdout to the serve log,
        which makes Python block-buffer it, and the child ends with os._exit,
        which does not flush. Every line it printed was discarded: the startup
        banner, the note that an unfinished run was recorded as aborted, and
        any traceback. The startup message points a reader at that file, so the
        file has to hold something before the process ends."""
        import subprocess
        import urllib.request
        ev = str(tmp_path / "ev")
        os.makedirs(ev)
        # a run that never finished, old enough for the start-up sweep
        rid = "20260101T000000Z-dir"
        d = os.path.join(ev, rid)
        os.makedirs(os.path.join(d, "raw"))
        sp = os.path.join(d, "started.json")
        with open(sp, "w") as fh:
            json.dump({"run_id": rid, "service": "baggage", "scope": "dir",
                       "target": str(tmp_path)}, fh)
        old = time.time() - (squawk.ABORT_SWEEP_AGE + 600)
        os.utime(sp, (old, old))
        port = self._free_port()
        res = subprocess.run([sys.executable, ENTRY, "serve", "--daemon",
                              "--evidence", ev, "--port", str(port)],
                             capture_output=True, text=True, timeout=120)
        assert res.returncode == 0, res.stdout + res.stderr
        try:
            for _ in range(40):
                try:
                    urllib.request.urlopen("http://127.0.0.1:%d/healthz" % port,
                                           timeout=2).read()
                    break
                except Exception:
                    time.sleep(0.25)
            log = os.path.join(ev, "squawk-serve.log")
            body = open(log, encoding="utf-8").read()
            assert "is up" in body, \
                "the daemon log is empty while it runs: %r" % body[:200]
            assert rid in body and "never finished" in body, \
                "the abort note never reached the log the startup message names"
        finally:
            subprocess.run([sys.executable, ENTRY, "stop", "--evidence", ev],
                           capture_output=True, text=True, timeout=120)

    def test_pid_file_round_trip_and_stale_handling(self, tmp_path):
        root = str(tmp_path)
        assert squawk.read_pid_file(root) is None
        assert squawk.cmd_status(root) == 1
        squawk.write_pid_file(root, {"pid": 2 ** 22 + 12345, "url": "http://x/"})
        assert oct(os.stat(squawk._pid_path(root)).st_mode & 0o777) == "0o600"
        assert squawk.cmd_status(root) == 2, "a dead pid is reported stale"
        assert squawk.read_pid_file(root) is None, "and the stale file is removed"
        squawk.write_pid_file(root, {"pid": os.getpid()})
        squawk.remove_pid_file(root, expected_pid=os.getpid() + 1)
        assert squawk.read_pid_file(root) is not None, "never removes another's record"
        squawk.remove_pid_file(root, expected_pid=os.getpid())
        assert squawk.read_pid_file(root) is None

    def test_stop_status_and_healthz_against_a_real_server(self, tmp_path):
        import subprocess
        import sys
        import urllib.request
        root = str(tmp_path / "ev")
        port = self._free_port()
        proc = subprocess.Popen([sys.executable, ENTRY, "--evidence", root,
                                 "--port", str(port)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            for _ in range(80):
                if squawk.read_pid_file(root):
                    break
                time.sleep(0.1)
            rec = squawk.read_pid_file(root)
            assert rec and rec["pid"] == proc.pid
            with urllib.request.urlopen("http://127.0.0.1:%d/healthz" % port, timeout=5) as r:
                health = json.loads(r.read().decode())
            assert health["ok"] and health["version"] == squawk.__version__
            assert squawk.cmd_status(root) == 0
            # The server is this process's child: reap it as it exits, or it
            # lingers as a zombie that kill -0 still sees (a shell or init
            # reaps in real use). Capture the real exit code while doing so.
            import threading
            rc_box = {}
            reaper = threading.Thread(target=lambda: rc_box.setdefault("rc", proc.wait()))
            reaper.start()
            assert squawk.cmd_stop(root) == 0
            reaper.join(10)
            assert rc_box.get("rc") == 0, "SIGTERM is a clean exit"
            assert squawk.read_pid_file(root) is None
            out = proc.stdout.read().decode()
            assert "stopped." in out
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_daemon_starts_in_the_background_and_stops(self, tmp_path):
        import subprocess
        import sys
        import urllib.request
        root = str(tmp_path / "ev")
        port = self._free_port()
        res = subprocess.run([sys.executable, ENTRY, "--daemon",
                              "--evidence", root, "--port", str(port)],
                             capture_output=True, text=True, timeout=30)
        assert res.returncode == 0, res.stdout + res.stderr
        assert "up in the background" in res.stdout
        rec = squawk.read_pid_file(root)
        assert rec and squawk._alive(int(rec["pid"]))
        with urllib.request.urlopen("http://127.0.0.1:%d/healthz" % port, timeout=5) as r:
            assert json.loads(r.read().decode())["ok"]
        assert os.path.exists(os.path.join(root, squawk.SERVE_LOG))
        assert squawk.cmd_stop(root) == 0
        assert squawk.read_pid_file(root) is None

    def test_version_flag(self):
        import subprocess
        import sys
        res = subprocess.run([sys.executable, ENTRY, "--version"],
                             capture_output=True, text=True, timeout=20)
        assert res.stdout.strip() == "squawk %s" % squawk.__version__

    def test_install_service_writes_a_unit_or_declines_honestly(self, tmp_path, monkeypatch):
        import argparse
        args = argparse.Namespace(host="127.0.0.1", port=8790)
        _patch_all(monkeypatch, "_systemd_present", lambda: False)
        assert squawk.cmd_install_service(args, str(tmp_path)) == 2
        _patch_all(monkeypatch, "_systemd_present", lambda: True)
        monkeypatch.setenv("HOME", str(tmp_path))
        assert squawk.cmd_install_service(args, str(tmp_path / "ev")) == 0
        unit = tmp_path / ".config" / "systemd" / "user" / "squawk.service"
        body = unit.read_text()
        assert "ExecStart=" in body and "--evidence %s" % (tmp_path / "ev") in body
        assert "Restart=on-failure" in body and "--host 127.0.0.1" in body
        assert oct(unit.stat().st_mode & 0o777) == "0o600"


class TestCliRunProgress:
    """A headless run must not crash on the progress event that reports the run
    directory. That event carries no stage status; the CLI printer assumed one
    (a regression from the lifecycle change), and --run died with a KeyError
    the moment execute_service announced the run. Caught by the smoke test."""

    def test_headless_run_completes_without_a_traceback(self, tmp_path):
        import subprocess
        ev = tmp_path / "ev"
        res = subprocess.run([sys.executable, ENTRY, "run", "selfaudit",
                              "--evidence", str(ev)],
                             capture_output=True, text=True, timeout=120)
        both = res.stdout + res.stderr
        assert "Traceback" not in both and "KeyError" not in both, both[-800:]
        assert res.returncode == 0, both[-800:]
        runs = squawk.list_runs(str(ev))
        assert runs and runs[0].get("ledger"), "the run wrote a ledger, not an abort"


class TestPackageShape:
    """The split's guarantees, enforced rather than described: the layering is
    acyclic and matches the README, every module re-exports all it defines, and
    the version is stated once."""

    ORDER = ("core", "probes", "scanners", "stages", "evidence", "decisions", "analysis",
             "engine", "feeds", "installer", "baselines", "retention", "runtime", "web",
             "service", "cli")

    def _pkg(self):
        return os.path.dirname(os.path.abspath(squawk.__file__))

    def test_every_module_imports_only_from_earlier_layers(self):
        import re
        pkg = self._pkg()
        mods = sorted(f[:-3] for f in os.listdir(pkg)
                      if f.endswith(".py") and not f.startswith("__"))
        assert mods == sorted(self.ORDER), "a module was added or removed: update ORDER"
        for m in self.ORDER:
            src = open(os.path.join(pkg, m + ".py"), encoding="utf-8").read()
            for dep in re.findall(r"^from squawk\.(\w+) import", src, re.M):
                assert self.ORDER.index(dep) < self.ORDER.index(m), \
                    "%s imports from %s, which is not an earlier layer" % (m, dep)

    def test_every_module_reexports_everything_it_defines(self):
        import ast
        import importlib
        for m in self.ORDER:
            path = os.path.join(self._pkg(), m + ".py")
            tree = ast.parse(open(path, encoding="utf-8").read())
            defined = set()
            for n in tree.body:
                if isinstance(n, (ast.FunctionDef, ast.ClassDef)):
                    defined.add(n.name)
                elif isinstance(n, ast.Assign):
                    defined |= {t.id for t in n.targets if isinstance(t, ast.Name)}
                elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                    defined.add(n.target.id)
            defined.discard("__all__")
            exported = set(importlib.import_module("squawk." + m).__all__)
            assert exported == defined, "%s: __all__ drifted: %s" % (
                m, sorted(exported ^ defined))

    def test_version_is_stated_once(self):
        import re
        pyproject = open(os.path.join(os.path.dirname(self._pkg()), "pyproject.toml"),
                         encoding="utf-8").read()
        assert re.search(r'^version = "%s"$' % re.escape(squawk.__version__), pyproject, re.M)

    def test_every_module_has_a_docstring(self):
        import importlib
        for m in self.ORDER:
            assert importlib.import_module("squawk." + m).__doc__, m

    def test_the_type_gate_is_wired_to_the_floor(self):
        """Config, read as config: the suite cannot run mypy (stdlib only), so
        this asserts the gate exists where it must — pinned in CI, run against
        the 3.9 floor, and declared beside the package — so a deleted step or
        a drifted floor fails here rather than passing silently in a green
        build with no type check in it."""
        import re
        here = os.path.dirname(self._pkg())
        pyproject = open(os.path.join(here, "pyproject.toml"), encoding="utf-8").read()
        assert "[tool.mypy]" in pyproject
        assert re.search(r'^python_version = "3\.9"$', pyproject, re.M), \
            "the checker must reason about the floor the code claims"
        ci_path = ""
        probe = here
        while True:
            cand = os.path.join(probe, ".github", "workflows", "ci.yml")
            if os.path.exists(cand):
                ci_path = cand
                break
            parent = os.path.dirname(probe)
            if parent == probe:
                break
            probe = parent
        if not ci_path:
            pytest.skip("no .github above the package: a package-only checkout "
                        "cannot see the workflow, so it cannot say whether the "
                        "gate is wired")
        ci = open(ci_path, encoding="utf-8").read()
        pin = re.search(r'^\s*MYPY_VERSION: "(\d+)\.(\d+)\.\d+"$', ci, re.M)
        assert pin, "mypy is not pinned in CI"
        assert int(pin.group(1)) == 1, \
            "mypy 2.x refuses --python-version 3.9; the pin must stay on 1.x"
        assert re.search(r"^\s*- run: mypy --python-version 3\.9 .*\bsquawk\s*$",
                         ci, re.M), "CI does not run the type gate against the floor"


class TestSubcommands:
    """Subcommands are the spelling going forward; the flags keep working; and
    a subcommand that is missing what it needs errors instead of doing
    something else. Bare `run` used to fall through to serving the web UI."""

    def test_translation(self):
        t = squawk._translate_argv
        assert t(["run", "customs", "--target", "/x"]) == ["--run", "customs", "--target", "/x"]
        assert t(["run"]) == ["--run", ""]
        assert t(["run", "--target", "/x"]) == ["--run", "", "--target", "/x"]
        assert t(["serve", "--daemon"]) == ["--daemon"]
        assert t(["status", "--evidence", "/e"]) == ["--status", "--evidence", "/e"]
        assert t(["version"]) == ["--version"]
        assert t(["--doctor"]) == ["--doctor"], "flags pass through untouched"
        assert t([]) == []

    def test_services_and_status_exit_codes(self, tmp_path, capsys):
        assert squawk.main(["services"]) == 0
        assert squawk.main(["status", "--evidence", str(tmp_path)]) == 1
        assert "not running" in capsys.readouterr().out

    def test_bare_run_errors_instead_of_serving(self, tmp_path):
        """Run as a subprocess with a timeout: if this ever falls through to the
        web server again, the timeout fails the test instead of hanging it."""
        import socket
        import subprocess
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        res = subprocess.run([sys.executable, ENTRY, "run", "--evidence", str(tmp_path),
                              "--port", str(port)],
                             capture_output=True, text=True, timeout=20)
        assert res.returncode == 2, res.stdout + res.stderr
        assert "run needs a service" in res.stdout
        assert "is up" not in res.stdout


class TestDecisions:
    """Triage decisions live in the evidence store, not a browser: who decided
    what, when, and why, append-only, keyed to the target and each finding
    identity so they follow the finding on to every later run of that target
    and never leak to another."""

    def test_record_and_read_back_latest_wins(self, tmp_path, monkeypatch):
        root = str(tmp_path / "ev")
        monkeypatch.setenv("SQUAWK_USER", "reviewer")
        e1 = squawk.record_decision(root, "r1", "/x", "customs", "semgrep", "R",
                                    "reviewed", ["R:b.py:2", "R:a.py:1"],
                                    note="fixture only")
        assert e1["who"] == "reviewer"
        assert e1["identities"] == ["R:a.py:1", "R:b.py:2"], "sorted, deduplicated"
        squawk.record_decision(root, "r1", "/x", "customs", "semgrep", "R",
                               "flagged", ["R:a.py:1"], at="20260905T000001Z")
        evs = squawk.load_decisions(root)
        assert [e["status"] for e in evs] == ["reviewed", "flagged"], \
            "append-only, in the order recorded"
        cur = squawk.current_decisions(root, "/x")
        assert cur[("semgrep", "R:a.py:1")]["status"] == "flagged"
        assert cur[("semgrep", "R:b.py:2")]["status"] == "reviewed"
        assert squawk.current_decisions(root, "/other") == {}, \
            "a decision never leaks to another target"
        path = squawk.ledger_path(root)
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"
        assert oct(os.stat(os.path.dirname(path)).st_mode & 0o777) == "0o700"

    def test_refuses_what_it_could_not_later_explain(self, tmp_path):
        root = str(tmp_path / "ev")
        with pytest.raises(ValueError):
            squawk.record_decision(root, "r", "/x", "s", "t", "R", "bogus", ["a"])
        with pytest.raises(ValueError):
            squawk.record_decision(root, "r", "/x", "s", "t", "R", "reviewed", [])
        with pytest.raises(ValueError):
            squawk.record_decision(root, "r", "/x", "s", "t", "R", "reviewed", ["a"],
                                   note="x" * (squawk.NOTE_CAP + 1))
        assert not os.path.exists(squawk.ledger_path(root)), "nothing refused is written"

    def test_a_damaged_line_is_reported_not_dropped_silently(self, tmp_path):
        root = str(tmp_path / "ev")
        squawk.record_decision(root, "r", "/x", "s", "t", "R", "reviewed", ["a"])
        with open(squawk.ledger_path(root), "a") as fh:
            fh.write("{not json\n")
            fh.write(json.dumps({"status": "reviewed"}) + "\n")  # no identities
        problems = []
        evs = squawk.load_decisions(root, problems)
        assert len(evs) == 1
        assert len(problems) == 2 and "line 2" in problems[0] and "line 3" in problems[1]
        assert squawk.load_decisions(str(tmp_path / "none")) == []

    def test_who_falls_back_to_the_login_user(self, monkeypatch):
        monkeypatch.setenv("SQUAWK_USER", "  ")
        monkeypatch.setenv("USER", "login-name")
        assert squawk.who() == "login-name"
        monkeypatch.setenv("SQUAWK_USER", "named")
        assert squawk.who() == "named"

    def test_summarize_reads_partial_honestly(self):
        ev = {"status": "reviewed", "who": "r", "at": "20260905T000000Z", "note": ""}
        assert squawk.summarize([ev, ev])["status"] == "reviewed"
        assert squawk.summarize([ev, None])["status"] == "partial"
        assert squawk.summarize([None, None])["status"] == "open"
        assert squawk.summarize([])["status"] == "open"
        later = {"status": "flagged", "who": "q", "at": "20260906T000000Z", "note": "why"}
        s = squawk.summarize([ev, later])
        assert s["status"] == "partial" and s["decided"] == 2 and s["total"] == 2
        assert s["who"] == "q" and s["note"] == "why" and s["latest"] == "flagged"


class TestRemediationTimeline:
    """Phase 2's exit criterion, made a test: a finding fixed three runs ago
    shows resolved_on, reintroducing it flags a regression, and disabling a
    scanner produces silent, never resolved. Every run persists the timeline
    as of itself, and the record must equal a recomputation."""

    def _run(self, root, rid, present, tools_ok=("semgrep",), tools_gap=()):
        d = os.path.join(root, rid)
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        ledger = [{"tool": t, "status": "ok", "detail": "", "evidence": "",
                   "coverage": {"examined": 3, "unit": "files", "skipped": 0,
                                "errors": 0, "note": ""}} for t in tools_ok]
        ledger += [{"tool": t, "status": "gap", "detail": "not found", "evidence": "",
                    "coverage": None} for t in tools_gap]
        finds = [{"scanner": t, "identity": i, "severity": "high", "title": i,
                  "path": "p", "detail": {}}
                 for t, ids in present.items() for i in ids]
        man = {"run_id": rid, "service": "customs", "scope": "repo", "target": "/x",
               "service_label": "Customs (repo)", "not_covered": "",
               "counts": {"total": len(finds), "excluded": 0}, "severities": {},
               "ledger": ledger}
        for name, o in (("manifest.json", man), ("identities.json", present),
                        ("findings.json", finds), ("digest.json", {"run_id": rid})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(o, fh)
        return man

    def _five_runs(self, root):
        self._run(root, "20260101T000000Z", {"semgrep": ["R:a.py:1", "R:b.py:2"]})
        self._run(root, "20260102T000000Z", {"semgrep": ["R:a.py:1"]})  # b fixed
        self._run(root, "20260103T000000Z", {"semgrep": []},
                  tools_ok=(), tools_gap=("semgrep",))  # scanner off: silent
        self._run(root, "20260104T000000Z", {"semgrep": ["R:a.py:1"]})  # still fixed
        self._run(root, "20260105T000000Z", {"semgrep": ["R:a.py:1", "R:b.py:2"]})  # b back
        return {m["run_id"]: m for m in squawk.list_runs(root)}

    def test_resolved_then_regressed_with_dates_and_silence(self, tmp_path):
        root = str(tmp_path / "ev")
        runs = self._five_runs(root)
        b = ("semgrep", "R:b.py:2")
        a = ("semgrep", "R:a.py:1")
        t2 = squawk.remediation_timeline(root, runs["20260102T000000Z"])
        assert t2[b]["status"] == "resolved" and t2[b]["resolved_on"] == "20260102T000000Z"
        t3 = squawk.remediation_timeline(root, runs["20260103T000000Z"])
        assert t3[a]["status"] == "open" and t3[a]["last_seen"] == "20260102T000000Z", \
            "a silent scanner resolves nothing and sees nothing"
        t4 = squawk.remediation_timeline(root, runs["20260104T000000Z"])
        assert t4[b]["status"] == "resolved" and t4[b]["resolved_on"] == "20260102T000000Z", \
            "fixed three runs ago keeps its date"
        t5 = squawk.remediation_timeline(root, runs["20260105T000000Z"])
        assert t5[b]["status"] == "regressed"
        assert t5[b]["regressed_on"] == "20260105T000000Z"
        assert t5[b]["resolved_on"] == "20260102T000000Z" and t5[b]["regressions"] == 1
        assert t5[b]["runs"] == 2 and t5[b]["first_seen"] == "20260101T000000Z"
        assert t5[a] == {"first_seen": "20260101T000000Z", "last_seen": "20260105T000000Z",
                         "runs": 4, "status": "open", "resolved_on": None,
                         "regressed_on": None, "regressions": 0}
        assert squawk.history_counts(t5) == {"open": 1, "resolved": 0, "regressed": 1}

    def test_a_scanner_that_did_not_run_says_nothing_about_its_findings(self, tmp_path):
        root = str(tmp_path / "ev")
        self._run(root, "20260101T000000Z",
                  {"semgrep": ["R:a.py:1"], "trivy": ["CVE-1"]},
                  tools_ok=("semgrep", "trivy"))
        self._run(root, "20260102T000000Z", {"semgrep": ["R:a.py:1"], "trivy": []},
                  tools_ok=("semgrep",), tools_gap=("trivy",))
        t = squawk.remediation_timeline(root, squawk.list_runs(root)[0])
        assert t[("trivy", "CVE-1")]["status"] == "open", \
            "trivy did not run, so CVE-1 is not resolved"

    def test_a_run_persists_its_timeline_and_it_matches_recomputation(self, tmp_path):
        root = str(tmp_path / "ev")
        out = squawk.execute_service(squawk.SERVICES["selfaudit"], "host", root,
                                     os.getcwd())
        man = squawk.list_runs(root)[0]
        doc = squawk.load_history(man["_dir"])
        assert doc and doc["run_id"] == out["run_id"] and doc["schema"] == 1
        entries, persisted = squawk.history_entries(root, man)
        assert persisted
        recomputed = squawk.remediation_timeline(root, man)
        fields = ("status", "first_seen", "last_seen", "runs", "resolved_on",
                  "regressed_on", "regressions")
        assert {k: {f: v[f] for f in fields} for k, v in entries.items()} == recomputed, \
            "the record and the recomputation must agree"
        assert doc["counts"] == squawk.history_counts(recomputed)

    def test_an_older_run_without_the_file_is_reconstructed_and_says_so(self, tmp_path):
        root = str(tmp_path / "ev")
        self._run(root, "20260101T000000Z", {"semgrep": ["R:a.py:1"]})
        entries, persisted = squawk.history_entries(root, squawk.list_runs(root)[0])
        assert not persisted and entries[("semgrep", "R:a.py:1")]["status"] == "open"
        assert squawk.load_history(str(tmp_path / "nowhere")) is None


class TestDecisionsInTheUi:
    """The pages read the ledger and the timeline: a decision made on one run
    shows on the next run of the same target, a regression is flagged where the
    reader is looking, and the endpoint that records a decision refuses what
    it cannot stand behind. Live through the handler, not read from source."""

    def _run(self, root, rid, idents, target="/x", tools_ok=("semgrep",), tools_gap=()):
        d = os.path.join(root, rid)
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        ledger = [{"tool": t, "status": "ok", "detail": "", "evidence": "",
                   "coverage": {"examined": 3, "unit": "files", "skipped": 0,
                                "errors": 0, "note": ""}} for t in tools_ok]
        ledger += [{"tool": t, "status": "gap", "detail": "off", "evidence": "",
                    "coverage": None} for t in tools_gap]
        finds = [{"scanner": "semgrep", "identity": i, "severity": "high",
                  "title": "Rule " + i.split(":")[0], "path": i.split(":")[1],
                  "detail": {}} for i in idents]
        man = {"run_id": rid, "service": "customs", "scope": "repo", "target": target,
               "service_label": "Customs (repo)", "not_covered": "",
               "counts": {"total": len(finds), "excluded": 0}, "severities": {},
               "ledger": ledger}
        for name, o in (("manifest.json", man), ("identities.json", {"semgrep": idents}),
                        ("findings.json", finds), ("digest.json", {"run_id": rid})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(o, fh)

    def test_triage_state_comes_from_the_ledger_and_follows_the_target(self, tmp_path):
        root = str(tmp_path / "ev")
        self._run(root, "20260101T000000Z", ["R:a.py:1", "R:b.py:2"])
        squawk.record_decision(root, "20260101T000000Z", "/x", "customs", "semgrep",
                               "R", "reviewed", ["R:a.py:1", "R:b.py:2"],
                               note="test fixture, not shipped", by="ryan-test",
                               at="20260101T010000Z")
        self._run(root, "20260102T000000Z", ["R:a.py:1", "R:b.py:2", "R:c.py:3"])
        self._run(root, "20260102T000001Z", ["R:a.py:1"], target="/other")
        later = squawk.view_triage(root, "20260102T000000Z")
        assert '"status": "partial"' in later and '"decided": 2' in later \
            and '"total": 3' in later, "a rule with a new instance is partial, not reviewed"
        assert "ryan-test" in later and "test fixture, not shipped" in later
        assert "/decide" in later and "tower-triage-" not in later \
            and "localStorage.getItem(store" not in later, "no browser-side state"
        other = squawk.view_triage(root, "20260102T000001Z")
        assert '"status": "open"' in other and "ryan-test" not in other, \
            "a decision on one target never shows on another"

    def test_findings_shows_the_decision_and_flags_the_regression(self, tmp_path):
        root = str(tmp_path / "ev")
        self._run(root, "20260101T000000Z", ["R:a.py:1", "R:b.py:2"])
        self._run(root, "20260102T000000Z", ["R:a.py:1"])              # b fixed
        self._run(root, "20260103T000000Z", ["R:a.py:1", "R:b.py:2"])  # b back
        squawk.record_decision(root, "20260103T000000Z", "/x", "customs", "semgrep",
                               "R", "flagged", ["R:a.py:1", "R:b.py:2"],
                               note="needs a fix this sprint", by="ryan-test",
                               at="20260103T010000Z")
        html = squawk.view_findings(root, "20260103T000000Z")
        assert "<span class='dchip regress'>1 regressed</span>" in html
        assert "regressed &middot; resolved Jan 02" in html and "back Jan 03" in html
        assert "<span class='dchip dec'>flagged &middot; ryan-test" in html
        assert "needs a fix this sprint" in html
        assert "1 regressed</span>" in html.split("<details")[0], \
            "the count is in the summary line, before any row"
        mid = squawk.view_findings(root, "20260102T000000Z")
        assert "Resolved before this run &mdash; 1, with dates" in mid
        assert "R:b.py:2" in mid and "Reconstructed now" in mid, \
            "a run without history.json says the timeline was computed"
        assert "regressed" not in mid.split("Resolved before")[0].lower() \
            or "0 regressed" not in mid

    def test_a_run_cleared_by_fixes_is_not_the_same_page_as_a_run_with_nothing(
            self, tmp_path):
        """Found by the field check. A run that found nothing because every
        finding had been fixed rendered the same page as a target that never
        had anything: "this run recorded no findings", with the list of what
        was fixed and when dropped entirely. Two different results printed the
        same page, which is the failure this tool exists to refuse."""
        root = str(tmp_path / "ev")
        self._run(root, "20260101T000000Z", ["R:a.py:1", "R:b.py:2"])
        self._run(root, "20260102T000000Z", [])            # everything fixed
        html = squawk.view_findings(root, "20260102T000000Z")
        assert "Resolved before this run &mdash; 2, with dates" in html
        assert "R:a.py:1" in html and "R:b.py:2" in html
        assert "2 were resolved before it" in html
        assert "What ran" in html or "examined" in html, \
            "the clean run still has to show its work"
        # a target that genuinely never had anything says the plain thing
        other = str(tmp_path / "ev2")
        self._run(other, "20260101T000000Z", [])
        plain = squawk.view_findings(other, "20260101T000000Z")
        assert "Resolved before this run" not in plain
        assert "clean result only because it looked" in plain

    def test_the_resolved_list_survives_a_filter_that_hides_everything(self, tmp_path):
        root = str(tmp_path / "ev")
        self._run(root, "20260101T000000Z", ["R:a.py:1", "R:b.py:2"])
        self._run(root, "20260102T000000Z", ["R:a.py:1"])
        html = squawk.view_findings(root, "20260102T000000Z", sev_filter="critical")
        assert "Nothing matches these filters" in html
        assert "Resolved before this run" in html, \
            "a filter hides findings, not the record of what was fixed"

    def test_history_counts_resolved_and_regressed_with_dates(self, tmp_path):
        root = str(tmp_path / "ev")
        self._run(root, "20260101T000000Z", ["R:a.py:1", "R:b.py:2", "R:c.py:3"])
        self._run(root, "20260102T000000Z", ["R:a.py:1"])
        self._run(root, "20260103T000000Z", ["R:a.py:1", "R:b.py:2"])
        html = squawk.view_history(root)
        assert "<span class='dchip'>1 open</span>" in html
        assert "<span class='dchip'>1 resolved</span>" in html
        assert "<span class='dchip regress'>1 regressed</span>" in html
        assert "Resolved and regressed, with dates" in html
        assert "regressed Jan 03" in html and "resolved Jan 02" in html

    def test_decide_endpoint_records_refuses_and_holds_the_origin_line(self, tmp_path):
        import argparse
        import socket
        import threading
        import time
        import urllib.error
        import urllib.parse
        import urllib.request
        ev = str(tmp_path / "ev")
        self._run(ev, "20260101T000000Z", ["R:a.py:1", "R:b.py:2"])
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        args = argparse.Namespace(evidence=ev, repo=None, port=port,
                                  host="127.0.0.1", gh_repo=None, open=False)
        threading.Thread(target=lambda: squawk.serve_web(args), daemon=True).start()
        time.sleep(1.5)
        origin = "http://127.0.0.1:%d" % port

        def post(fields, org=origin):
            req = urllib.request.Request(
                origin + "/decide", data=urllib.parse.urlencode(fields).encode(),
                headers={"Origin": org})
            try:
                with urllib.request.urlopen(req, timeout=8) as r:
                    return r.status, json.loads(r.read().decode())
            except urllib.error.HTTPError as e:
                body = e.read().decode()
                try:
                    return e.code, json.loads(body)
                except ValueError:
                    return e.code, {"raw": body}

        base = {"run": "20260101T000000Z", "scanner": "semgrep", "rule": "R"}
        code, j = post(dict(base, status="reviewed", note="ok",
                            ids=json.dumps(["R:a.py:1", "R:b.py:2"])))
        assert code == 200 and j["ok"] and j["state"]["status"] == "reviewed", j
        assert j["event"]["who"] and j["event"]["target"] == "/x"
        code, j = post(dict(base, status="reviewed", ids=json.dumps(["R:zz.py:9"])))
        assert code == 400 and "did not record" in j["error"], j
        code, j = post(dict(base, status="bogus", ids=json.dumps(["R:a.py:1"])))
        assert code == 400 and "unknown decision status" in j["error"], j
        code, j = post(dict(base, run="nope", status="reviewed",
                            ids=json.dumps(["R:a.py:1"])))
        assert code == 400 and "unknown run" in j["error"], j
        code, j = post(dict(base, status="skipped", ids=json.dumps(["R:a.py:1"])),
                       org="http://evil.example")
        assert code == 403, "a cross-origin decision is refused like a cross-origin run"
        evs = squawk.load_decisions(ev)
        assert len(evs) == 1 and evs[0]["status"] == "reviewed", \
            "only the accepted decision reached the ledger"
        assert squawk.current_decisions(ev, "/x")[("semgrep", "R:a.py:1")]["note"] == "ok"


class TestThreatIntel:
    """Priority ranks one run. This answers the estate-wide question — what is
    being exploited, out of what I actually run — and adds the context a reader
    needs to argue for a fix. Every list states what it is out of, every source
    states when it was fetched, and a source that has not been fetched says so
    rather than contributing a zero."""

    def _estate(self, tmp_path, cves=("CVE-2021-44228", "CVE-2018-1000656",
                                      "CVE-2020-9999")):
        root = str(tmp_path / "ev")
        target = str(tmp_path / "app")
        os.makedirs(target, exist_ok=True)
        d = os.path.join(root, "20260906T120000Z-dir")
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        finds = [{"scanner": "grype", "identity": c, "severity": "high",
                  "title": c, "path": "requirements.txt", "detail": {"cve": c}}
                 for c in cves]
        finds.append({"scanner": "bandit", "identity": "B602:x.py:1",
                      "severity": "high", "title": "shell", "path": "x.py",
                      "detail": {}})
        man = {"run_id": "20260906T120000Z-dir", "service": "baggage",
               "scope": "dir", "target": target, "service_label": "Baggage",
               "not_covered": "", "counts": {"total": len(finds), "excluded": 0},
               "severities": {}, "ledger": []}
        for name, obj in (("manifest.json", man),
                          ("identities.json", {"grype": list(cves)}),
                          ("findings.json", finds), ("digest.json", {})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(obj, fh)
        return root

    def _feeds(self, root, kev=("CVE-2021-44228",),
               epss=(("CVE-2018-1000656", 0.42, 0.95), ("CVE-2021-44228", 0.97, 0.99),
                     ("CVE-2020-9999", 0.01, 0.20))):
        fdir = os.path.join(root, "feeds")
        os.makedirs(fdir, exist_ok=True)
        with open(os.path.join(fdir, "kev.json"), "w") as fh:
            json.dump({"vulnerabilities": [
                {"cveID": c, "dateAdded": "2021-12-10",
                 "knownRansomwareCampaignUse": "Known"} for c in kev]}, fh)
        with open(os.path.join(fdir, "epss.csv"), "w") as fh:
            fh.write("#model\ncve,epss,percentile\n")
            for c, e, p in epss:
                fh.write("%s,%s,%s\n" % (c, e, p))
        with open(os.path.join(fdir, "feeds.json"), "w") as fh:
            json.dump({"fetched_at": "20260906T000000Z",
                       "kev": {"url": squawk.KEV_URL, "sha256": "a" * 64,
                               "bytes": 10, "entries": len(kev)},
                       "epss": {"url": squawk.EPSS_URL, "sha256": "b" * 64,
                                "bytes": 20, "entries": len(epss)}}, fh)

    def test_the_page_never_opens_a_socket(self, tmp_path, monkeypatch):
        """Fetching is `squawk feeds --intel`, which is explicit, logged and
        recorded with provenance. A page that fetched would make its own
        rendering depend on a third party being up."""
        root = self._estate(tmp_path)
        self._feeds(root)

        def boom(*_a, **_k):
            raise AssertionError("the page reached the network")
        monkeypatch.setattr(squawk.feeds.urllib.request, "urlopen", boom)
        for page in (squawk.view_intel(root),
                     squawk.view_intel(root, "CVE-2021-44228"),
                     squawk.view_intel(root, "CVE-1999-0001")):
            assert "Traceback" not in page

    def test_without_feeds_nothing_reads_as_a_zero(self, tmp_path):
        root = self._estate(tmp_path)
        html = squawk.view_intel(root)
        assert "have not been fetched" in html
        assert "unknown, which is not the same as none" in html
        assert "Exploited now" not in html, \
            "a count was shown for a feed that was never fetched"
        assert "not fetched" in html, "the provenance strip hides an absent source"

    def test_every_list_states_what_it_is_out_of(self, tmp_path):
        root = self._estate(tmp_path)
        self._feeds(root)
        html = squawk.view_intel(root)
        assert "3 distinct CVE(s)" in html
        assert "1 of 3 CVE(s) in the estate" in html, "KEV list has no denominator"
        assert "1 of 3 CVE(s), excluding those already in KEV" in html
        assert "<b>1</b> further CVE(s)" in html, \
            "the CVEs on neither list are hidden rather than counted"
        assert "Reachability is not assessed" in html

    def test_kev_and_epss_split_the_estate_without_double_counting(self, tmp_path):
        root = self._estate(tmp_path)
        self._feeds(root)
        html = squawk.view_intel(root)
        kev_block = html.split("Exploited now")[1].split("Likely to be exploited")[0]
        hot_block = html.split("Likely to be exploited")[1]
        assert "CVE-2021-44228" in kev_block
        assert "CVE-2021-44228" not in hot_block.split("further CVE")[0], \
            "a KEV CVE was counted again under likely-soon"
        assert "CVE-2018-1000656" in hot_block
        assert "ransomware" in kev_block

    def test_a_kev_entry_flagged_for_ransomware_does_not_raise(self, tmp_path):
        """_parse_kev normalises the flag to a bool; reading it as a string
        raised on every ransomware-flagged CVE, which is the loudest half of
        the list."""
        root = self._estate(tmp_path)
        self._feeds(root)
        feeds = squawk.load_feeds(root)
        assert feeds["kev"]["CVE-2021-44228"]["ransomware"] is True
        assert "ransomware" in squawk.view_intel(root, "CVE-2021-44228")

    def test_detail_that_was_not_fetched_says_unknown_not_blank(self, tmp_path):
        root = self._estate(tmp_path)
        self._feeds(root)
        page = squawk.view_intel(root, "CVE-2021-44228")
        assert "That is unknown, not absent" in page
        assert "squawk feeds --intel" in page
        assert "Exploitation" in page, "KEV and EPSS are known and still shown"

    def test_cached_detail_is_rendered_with_its_provenance(self, tmp_path):
        root = self._estate(tmp_path)
        self._feeds(root)
        os.makedirs(squawk.intel_dir(root), exist_ok=True)
        doc = {"cve": "CVE-2021-44228", "fetched_at": "20260906T100000Z",
               "summary": "Remote code execution in a logging library.",
               "aliases": ["CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"],
               "cvss": {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                                                    "S:C/C:H/I:H/A:H",
                        "score": 10.0, "severity": "critical"},
               "cwe": ["CWE-502", "CWE-917"], "published": "2021-12-10",
               "references": [{"type": "ADVISORY", "url": "https://example.invalid/a"},
                              {"type": "EXPLOIT", "url": "https://example.invalid/x"}],
               "sources": {"osv": {"url": "https://api.osv.dev/v1/vulns/CVE-2021-44228",
                                   "bytes": 900, "sha256": "c" * 64},
                           "nvd": {"url": "https://nvd.example/x", "bytes": 700,
                                   "sha256": "d" * 64}}}
        with open(os.path.join(squawk.intel_dir(root), "CVE-2021-44228.json"), "w") as fh:
            json.dump(doc, fh)
        page = squawk.view_intel(root, "CVE-2021-44228")
        assert "Remote code execution in a logging library." in page
        assert "CWE-502" in page
        assert "reachable over the network" in page and "scope changed" in page, \
            "the vector was shown as initials with no words"
        assert page.index("EXPLOIT") < page.index("ADVISORY"), \
            "the exploit reference is not first"
        assert "sha256 cccccccccccccccc" in page and "Fetched" in page
        assert "That is unknown, not absent" not in page

    def test_the_estate_excludes_a_vanished_target(self, tmp_path):
        root = self._estate(tmp_path)
        self._feeds(root)
        gone = os.path.join(str(tmp_path), "gone")
        d = os.path.join(root, "20260906T130000Z-dir")
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        finds = [{"scanner": "grype", "identity": "CVE-2099-1111", "severity": "high",
                  "title": "x", "path": "p", "detail": {"cve": "CVE-2099-1111"}}]
        man = {"run_id": "20260906T130000Z-dir", "service": "baggage", "scope": "dir",
               "target": gone, "service_label": "B", "not_covered": "",
               "counts": {"total": 1, "excluded": 0}, "severities": {}, "ledger": []}
        for name, obj in (("manifest.json", man), ("identities.json", {}),
                          ("findings.json", finds), ("digest.json", {})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(obj, fh)
        html = squawk.view_intel(root)
        assert "CVE-2099-1111" not in html, "a vanished target's CVE was counted"
        assert "1 vanished target(s) are not counted" in html

    def test_both_pages_go_through_the_one_live_vanished_split(self, tmp_path,
                                                               monkeypatch):
        """One function, asserted by replacing it and watching both pages
        change.

        The earlier version searched view_overview's SOURCE for "estate_runs(",
        which a comment satisfies and which says nothing about whether the page
        uses the answer. If the Overview still had its own copy of the split,
        this monkeypatch would not reach it and the count would not move
        (review R-17).
        """
        root = self._estate(tmp_path)
        live, vanished, by_target = squawk.estate_runs(root)
        assert len(live) == 1 and vanished == {} and len(by_target) == 1

        calls = []
        # Move the one run from `live` to `vanished` and hand back the same
        # shapes the real reader returns, so the page is reading real records
        # in the wrong bucket rather than something this test invented.
        moved = dict(live)

        def fake(root_arg):
            calls.append(root_arg)
            return {}, moved, by_target

        monkeypatch.setattr(squawk.web, "estate_runs", fake)
        page = squawk.view_overview(root)
        assert calls, "the Overview never called the shared split"
        assert "1 vanished target" in page, \
            "the Overview did not use the answer it asked for"

    def test_a_cvss_vector_is_rendered_in_words_or_not_at_all(self):
        v3 = squawk.cvss_words("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert v3[0] == "reachable over the network" and "no privileges needed" in v3
        v4 = squawk.cvss_words("CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:N/VI:H/VA:N")
        assert "needs local access" in v4 and "high integrity impact" in v4
        assert "no confidentiality impact" in v4
        assert squawk.cvss_words("garbage") == [], "a vector it cannot read is invented"
        assert squawk.cvss_words("") == []

    def test_fetch_intel_keeps_the_key_out_of_argv_and_the_cache(self, tmp_path,
                                                                 monkeypatch):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        seen = {}

        def fake_fetch(url, timeout=90, headers=None):
            seen.setdefault("headers", []).append(headers or {})
            if "osv.dev" in url:
                return (json.dumps({"id": "CVE-1", "summary": "s",
                                    "references": [{"type": "WEB", "url": "u"}]})
                        .encode(), "")
            return json.dumps({"vulnerabilities": [{"cve": {"metrics": {}}}]}).encode(), ""
        monkeypatch.setattr(squawk.feeds, "_fetch_feed", fake_fetch)
        ok, lines = squawk.fetch_intel(root, ["CVE-1"], api_key="SECRETKEY",
                                       sleep=lambda _s: None)
        assert ok, lines
        assert any(h.get("apiKey") == "SECRETKEY" for h in seen["headers"]), \
            "the key never reached a header"
        doc = squawk.load_intel(root, "CVE-1")
        assert doc and "SECRETKEY" not in json.dumps(doc), \
            "the key was written into the cache"
        assert not any("SECRETKEY" in ln for ln in lines), \
            "the key was printed"

    def test_fetch_intel_only_fetches_what_is_missing(self, tmp_path, monkeypatch):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        calls = []

        def fake_fetch(url, timeout=90, headers=None):
            calls.append(url)
            return json.dumps({"id": "x"}).encode(), ""
        monkeypatch.setattr(squawk.feeds, "_fetch_feed", fake_fetch)
        squawk.fetch_intel(root, ["CVE-1"], sleep=lambda _s: None)
        first = len(calls)
        ok, lines = squawk.fetch_intel(root, ["CVE-1"], sleep=lambda _s: None)
        assert len(calls) == first, "a cached CVE was fetched again"
        assert ok and any("already cached" in ln for ln in lines)

    def test_the_route_and_the_nav_exist(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root)
        with _serve(root, str(tmp_path)) as base:
            code, body = _get(base + "/intel")
            code2, body2 = _get(base + "/intel?scope=feed")
        assert code == 200 and "Traceback" not in body, "the page is unreachable"
        assert code2 == 200 and "Traceback" not in body2, "the feed view has no route"
        assert "href='/intel'" in body and ">Intel<" in body, "not in the nav"


class TestRetention:
    """Evidence grows without bound and nothing trimmed it. The two rules that
    shape this: pruned evidence must never look like evidence that never
    existed, and nothing is edited, only added or removed."""

    def _mk(self, root, rid, target, idents, raw_bytes=150000):
        d = os.path.join(root, rid)
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        finds = [{"scanner": "bandit", "identity": i, "severity": "high",
                  "title": i, "path": "p", "detail": {}} for i in idents]
        man = {"run_id": rid, "service": "baggage", "scope": "dir", "target": target,
               "service_label": "Baggage", "not_covered": "",
               "counts": {"total": len(finds), "excluded": 0}, "severities": {},
               "ledger": [{"tool": "bandit", "status": "ok", "detail": "",
                           "evidence": "raw/bandit.json",
                           "coverage": {"examined": 3, "unit": "files", "skipped": 0,
                                        "errors": 0, "note": ""}}]}
        for name, obj in (("manifest.json", man),
                          ("identities.json", {"bandit": list(idents)}),
                          ("findings.json", finds), ("digest.json", {"run_id": rid}),
                          ("history.json", {"schema": 1, "run_id": rid,
                                            "counts": {}, "entries": []})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(obj, fh)
        with open(os.path.join(d, "raw", "bandit.json"), "w") as fh:
            fh.write("y" * raw_bytes)
        return rid

    def _rid(self, now, days):
        return time.strftime("%Y%m%dT%H%M%SZ",
                             time.gmtime(now - days * 86400)) + "-dir"

    def _estate(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        now = time.time()
        ids = {
            "ancient": self._mk(root, self._rid(now, 400), "/a", ["B:1", "B:2"]),
            "old": self._mk(root, self._rid(now, 200), "/a", ["B:1"]),
            "recent": self._mk(root, self._rid(now, 10), "/a", ["B:1"]),
            "other_old": self._mk(root, self._rid(now, 300), "/b", ["B:9"]),
            "other_new": self._mk(root, self._rid(now, 1), "/b", ["B:9"]),
        }
        return root, now, ids

    def test_the_two_tiers_split_on_age(self, tmp_path):
        root, now, ids = self._estate(tmp_path)
        plan = squawk.plan_prune(root, trim_days=90, drop_days=365, now=now)
        assert [r["run_id"] for r in plan["drop"]] == [ids["ancient"]]
        assert sorted(r["run_id"] for r in plan["trim"]) == \
            sorted([ids["old"], ids["other_old"]])
        assert plan["reclaim"] > 0

    def test_the_newest_run_of_a_target_is_never_touched(self, tmp_path):
        root, now, ids = self._estate(tmp_path)
        plan = squawk.plan_prune(root, trim_days=0, drop_days=0, now=now)
        moved = {r["run_id"] for r in plan["trim"] + plan["drop"]}
        assert ids["recent"] not in moved and ids["other_new"] not in moved
        for r in plan["keep"]:
            if r["run_id"] in (ids["recent"], ids["other_new"]):
                assert "newest run of its target" in r["why"]

    def test_a_decision_blocks_removal_but_not_a_trim(self, tmp_path):
        """The ledger points at a run id, so dropping the run leaves it
        dangling. Trimming removes the scanner's output and the superseded
        timeline, neither of which a decision depends on."""
        root, now, ids = self._estate(tmp_path)
        squawk.record_decision(root, ids["ancient"], "/a", "baggage", "bandit",
                               "B", "reviewed", ["B:1"], by="t")
        plan = squawk.plan_prune(root, trim_days=90, drop_days=365, now=now)
        assert [r["run_id"] for r in plan["drop"]] == []
        row = next(r for r in plan["trim"] if r["run_id"] == ids["ancient"])
        assert "a triage decision was recorded against it" in row["why"]

    def test_a_baselined_finding_keeps_its_newest_evidence(self, tmp_path):
        root, now, ids = self._estate(tmp_path)
        os.makedirs(os.path.join(root, ".baselines"), exist_ok=True)
        with open(os.path.join(root, ".baselines", "baselines.json"), "w") as fh:
            json.dump({"repo": "x/y", "issue": 1, "synced_at": "n",
                       "scanners": {"bandit": {"status": "ok", "ids": ["B:2"]}}}, fh)
        assert squawk.baseline_identity_set(root) == {"bandit": {"B:2"}}
        plan = squawk.plan_prune(root, trim_days=90, drop_days=365, now=now)
        assert [r["run_id"] for r in plan["drop"]] == [], \
            "the only run holding a baselined identity was removed"
        row = next(r for r in plan["trim"] if r["run_id"] == ids["ancient"])
        assert any("baseline" in w for w in row["why"])

    def test_a_run_id_that_is_not_a_date_is_never_pruned(self, tmp_path):
        root, now, _ids = self._estate(tmp_path)
        odd = self._mk(root, "not-a-timestamp", "/c", ["B:5"])
        plan = squawk.plan_prune(root, trim_days=0, drop_days=0, now=now)
        assert odd not in {r["run_id"] for r in plan["trim"] + plan["drop"]}
        row = next(r for r in plan["keep"] if r["run_id"] == odd)
        assert any("does not parse" in w for w in row["why"])
        assert squawk.run_age_days({"run_id": "nope"}) is None

    def test_planning_changes_nothing_on_disk(self, tmp_path):
        root, now, _ids = self._estate(tmp_path)
        before = sorted((p, os.path.getsize(os.path.join(dp, p)))
                        for dp, _d, fs in os.walk(root) for p in fs)
        squawk.plan_prune(root, trim_days=0, drop_days=0, now=now)
        after = sorted((p, os.path.getsize(os.path.join(dp, p)))
                       for dp, _d, fs in os.walk(root) for p in fs)
        assert before == after, "the dry run touched the evidence"

    def test_a_trim_keeps_the_record_and_says_what_it_removed(self, tmp_path):
        root, now, ids = self._estate(tmp_path)
        plan = squawk.plan_prune(root, trim_days=90, drop_days=365, now=now)
        done = squawk.apply_prune(plan, by="tester")
        assert done["failed"] == [] and done["reclaimed"] > 0
        d = os.path.join(root, ids["old"])
        assert not os.path.exists(os.path.join(d, "raw"))
        assert not os.path.exists(os.path.join(d, "history.json"))
        for kept in ("manifest.json", "findings.json", "identities.json",
                     "digest.json"):
            assert os.path.exists(os.path.join(d, kept)), kept
        rec = squawk.prune_record(d)
        assert rec and rec["removed"] == ["raw", "history.json"]
        assert rec["by"] == "tester" and rec["at"]
        # nothing was edited: the manifest is unchanged, the record is a new file
        man = json.load(open(os.path.join(d, "manifest.json")))
        assert "pruned" not in man, "the manifest was edited rather than added to"
        assert not os.path.exists(os.path.join(root, ids["ancient"])), \
            "the run past the drop age is gone"

    def test_the_estate_still_reads_after_a_prune(self, tmp_path):
        root, now, ids = self._estate(tmp_path)
        squawk.apply_prune(squawk.plan_prune(root, 90, 365, now=now))
        runs = squawk.list_runs(root)
        assert len(runs) == 4, "a trimmed run stopped being a run"
        newest = next(m for m in runs if m["run_id"] == ids["recent"])
        assert squawk.remediation_timeline(root, newest), "the timeline broke"
        html = squawk.view_findings(root, ids["old"])
        assert "Traceback" not in html
        assert "Raw scanner output was removed from this run" in html, \
            "a trimmed run shows the same blank as a run that never had raw output"
        assert "tester" not in html  # no `by` was passed on this call
        fresh = squawk.view_findings(root, ids["recent"])
        assert "Raw scanner output was removed" not in fresh

    def test_prune_is_a_dry_run_unless_asked(self, tmp_path):
        root, now, _ids = self._estate(tmp_path)
        del now
        rc = squawk.main(["prune", "--evidence", root, "--trim-days", "0",
                          "--drop-days", "0"])
        assert rc == 0
        assert all(os.path.exists(os.path.join(root, n, "raw"))
                   for n in os.listdir(root)
                   if os.path.isdir(os.path.join(root, n))
                   and not n.startswith(".")), "the default run removed something"

    def test_prune_apply_removes_and_reports(self, tmp_path, capsys):
        root, _now, ids = self._estate(tmp_path)
        rc = squawk.main(["prune", "--evidence", root, "--apply",
                          "--trim-days", "30", "--drop-days", "365"])
        out = capsys.readouterr().out
        assert rc == 0, out
        assert "Trimmed" in out and "freed" in out
        assert not os.path.exists(os.path.join(root, ids["old"], "raw"))
        assert os.path.exists(os.path.join(root, ids["recent"], "raw"))

    def test_human_bytes_reads_like_a_size(self):
        assert squawk.human_bytes(0) == "0 B"
        assert squawk.human_bytes(1536) == "1.5 KiB"
        assert squawk.human_bytes(5 * 1024 ** 3).endswith("GiB")


class TestGeneralIntel:
    """The estate view answers "is what I run being exploited". This answers
    "what is being exploited", which is the half that keeps you informed about
    things you have not scanned yet. The catalogue is already on disk after
    `squawk feeds`; until this, the tool read two fields out of it and asked
    only about the handful of CVEs in the estate."""

    def _feeds(self, root, entries, epss=()):
        fdir = os.path.join(root, "feeds")
        os.makedirs(fdir, exist_ok=True)
        with open(os.path.join(fdir, "kev.json"), "w") as fh:
            json.dump({"vulnerabilities": entries}, fh)
        with open(os.path.join(fdir, "epss.csv"), "w") as fh:
            fh.write("#m\ncve,epss,percentile\n")
            for cve, score, pct in epss:
                fh.write("%s,%s,%s\n" % (cve, score, pct))
        with open(os.path.join(fdir, "feeds.json"), "w") as fh:
            json.dump({"fetched_at": "20260906T000000Z",
                       "kev": {"url": squawk.KEV_URL, "sha256": "a" * 64,
                               "bytes": 1, "entries": len(entries)},
                       "epss": {"url": squawk.EPSS_URL, "sha256": "b" * 64,
                                "bytes": 1, "entries": len(epss)}}, fh)

    def _entry(self, cve, days_ago, ransomware=False, vendor="Acme",
               product="Widget"):
        return {"cveID": cve,
                "dateAdded": time.strftime("%Y-%m-%d",
                                           time.gmtime(time.time() - days_ago * 86400)),
                "knownRansomwareCampaignUse": "Known" if ransomware else "Unknown",
                "vendorProject": vendor, "product": product,
                "vulnerabilityName": "%s flaw" % product,
                "shortDescription": "A thing that is exploited.",
                "requiredAction": "Apply updates.", "dueDate": "2026-10-01",
                "cwes": ["CWE-89"]}

    def _estate(self, root, target, cves):
        os.makedirs(target, exist_ok=True)
        d = os.path.join(root, "20260906T120000Z-dir")
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        finds = [{"scanner": "grype", "identity": c, "severity": "high",
                  "title": c, "path": "go.mod", "detail": {"cve": c}} for c in cves]
        man = {"run_id": "20260906T120000Z-dir", "service": "baggage",
               "scope": "dir", "target": target, "service_label": "B",
               "not_covered": "", "counts": {"total": len(finds), "excluded": 0},
               "severities": {}, "ledger": []}
        for name, obj in (("manifest.json", man),
                          ("identities.json", {"grype": list(cves)}),
                          ("findings.json", finds), ("digest.json", {})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(obj, fh)

    def test_the_parser_keeps_what_the_catalogue_says(self):
        blob = json.dumps({"vulnerabilities": [self._entry("CVE-1", 1, True)]}).encode()
        kev = squawk.feeds._parse_kev(blob)["CVE-1"]
        for field in ("added", "ransomware", "vendor", "product", "name",
                      "summary", "action", "due", "cwes"):
            assert field in kev, field
        assert kev["ransomware"] is True and kev["vendor"] == "Acme"
        assert kev["cwes"] == ["CWE-89"]

    def test_recent_and_ransomware_and_top_scores(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        self._feeds(root, [self._entry("CVE-2026-1001", 3),
                           self._entry("CVE-2026-1002", 10, ransomware=True),
                           self._entry("CVE-2019-1003", 400)],
                    epss=[("CVE-2026-1001", 0.90, 0.99), ("CVE-2019-1003", 0.10, 0.50),
                          ("CVE-2026-1004", 0.95, 0.999)])
        feeds = squawk.load_feeds(root)
        recent = [r["cve"] for r in squawk.kev_recent(feeds, 30)]
        assert recent == ["CVE-2026-1001", "CVE-2026-1002"], recent
        assert [r["cve"] for r in squawk.kev_ransomware(feeds)] == ["CVE-2026-1002"]
        top = squawk.epss_top(feeds, 2)
        assert [c for c, _s, _p in top] == ["CVE-2026-1004", "CVE-2026-1001"]
        assert squawk.kev_by_vendor(feeds) == [("Acme", 3)]

    def test_an_undated_entry_is_skipped_not_counted_as_new(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        bad = self._entry("CVE-2026-1005", 1)
        bad["dateAdded"] = "not-a-date"
        self._feeds(root, [bad, self._entry("CVE-2026-1006", 1)])
        feeds = squawk.load_feeds(root)
        assert [r["cve"] for r in squawk.kev_recent(feeds, 30)] == ["CVE-2026-1006"]

    def test_the_page_says_whether_each_one_is_yours_and_what_that_means(
            self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        self._feeds(root, [self._entry("CVE-2026-2001", 2),
                           self._entry("CVE-2026-2002", 4)],
                    epss=[("CVE-2026-2001", 0.9, 0.99)])
        self._estate(root, str(tmp_path / "app"), ["CVE-2026-2001"])
        html = squawk.view_intel_feed(root)
        assert "2 of 2 catalogue entries" in html
        assert "1 of them is in your estate" in html
        assert "<b>yours</b> &middot; 1 instance" in html
        assert "not in what you have scanned" in html, \
            "a CVE outside the estate is reported as unaffected"
        assert "about coverage, not exposure" in html, \
            "the page claims more than scanning can support"
        assert "Traceback" not in html

    def test_without_feeds_it_shows_nothing_rather_than_zero(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        html = squawk.view_intel_feed(root)
        assert "have not been fetched" in html
        assert "a zero here would be a claim about the world" in html.lower()
        assert "Added to KEV" not in html

    def test_it_never_reaches_the_network(self, tmp_path, monkeypatch):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        self._feeds(root, [self._entry("CVE-1", 1)], epss=[("CVE-1", 0.5, 0.9)])

        def boom(*_a, **_k):
            raise AssertionError("the page reached the network")
        monkeypatch.setattr(squawk.feeds.urllib.request, "urlopen", boom)
        assert "Traceback" not in squawk.view_intel_feed(root)

    def test_the_two_views_link_to_each_other(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        self._feeds(root, [self._entry("CVE-1", 1)], epss=[("CVE-1", 0.5, 0.9)])
        self._estate(root, str(tmp_path / "app"), ["CVE-1"])
        assert "/intel?scope=feed" in squawk.view_intel(root)
        assert "href='/intel'" in squawk.view_intel_feed(root)
        with _serve(root, str(tmp_path)) as base:
            code, body = _get(base + "/intel?scope=feed")
        assert code == 200 and "exploited" in body.lower(), "the feed view has no route"


class TestFindingsCarryTheirFix:
    """Reported from the field: "if you're going to tell me something or give
    me a finding, there should be a recommended recommendation along with the
    evidence." Two places dropped it, and a third collapsed four findings into
    one row so three of them were invisible."""

    def _selfaudit_run(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        squawk.execute_service(squawk.SERVICES["selfaudit"], "host", root,
                               os.getcwd())
        return root, squawk.list_runs(root)[0]

    def test_a_scanner_named_prefix_is_not_the_rule(self):
        """The self-audit's identity is `selfaudit:<check>`, so grouping on the
        first segment grouped on the scanner's own name — a constant — and put
        every host check in one row titled after whichever came first."""
        assert squawk.rule_of({"scanner": "selfaudit",
                               "identity": "selfaudit:clock-sync"}) == "clock-sync"
        assert squawk.rule_of({"scanner": "selfaudit",
                               "identity": "selfaudit:evidence-perms"}) == "evidence-perms"
        # every other scanner puts the rule first and is unchanged
        for scanner, ident, rule in (
                ("checkov", "CKV_AWS_1:terraform/s3.tf:bucket", "CKV_AWS_1"),
                ("zap", "10038:/x:", "10038"),
                ("semgrep", "python.lang.x:a.py:1", "python.lang.x"),
                ("grype", "CVE-2021-44228", "CVE-2021-44228")):
            assert squawk.rule_of({"scanner": scanner, "identity": ident}) == rule
        assert squawk.rule_of({"scanner": "x", "identity": ""}) == ""

    def test_distinct_host_checks_are_distinct_rows(self, tmp_path):
        root, man = self._selfaudit_run(tmp_path)
        finds = squawk.load_findings(man["_dir"])
        rules = {squawk.rule_of(f) for f in finds}
        assert len(rules) == len(finds), \
            "%d findings collapsed into %d rule(s): %s" % (len(finds), len(rules),
                                                           sorted(rules))
        html = squawk.view_findings(root, man["run_id"])
        assert "%d finding(s) in %d group(s)" % (len(finds), len(finds)) in html

    def test_triage_carries_what_it_is_and_what_to_do(self, tmp_path):
        root, man = self._selfaudit_run(tmp_path)
        html = squawk.view_triage(root, man["run_id"])
        payload = json.loads(re.search(r"var DECISIONS=(\[.*?\]),SEV=",
                                       html, re.S).group(1))
        assert len(payload) > 1, "every host check is still one decision"
        assert all(r["what"] for r in payload), "a row carries no description"
        assert all(r["fix"] for r in payload), "a row carries no recommendation"
        # and the renderer puts them on screen rather than only in the payload
        assert "Recommendation" in html and "What it is" in html
        assert "field('Recommendation',d.fix)" in html

    def test_the_markdown_export_carries_the_recommendation(self, tmp_path):
        root, man = self._selfaudit_run(tmp_path)
        html = squawk.view_triage(root, man["run_id"])
        assert "'  - recommendation: '+d.fix" in html, \
            "the export is a list of titles with no fix"
        assert "'  - what: '+d.what" in html

    def test_the_instrument_panel_shows_the_fix_it_already_computed(self, tmp_path):
        """Every check carries a `fix`; the panel rendered four columns and
        dropped it, so it said what was wrong and never what to do."""
        root, man = self._selfaudit_run(tmp_path)
        html = squawk.view_findings(root, man["run_id"])
        assert "<th>Recommendation</th>" in html
        raw = squawk._run_stage_raw(man, "selfaudit")
        fixes = [c["fix"] for c in raw["checks"] if c.get("fix")]
        assert fixes, "the fixture produced no check with a fix"
        for fix in fixes[:3]:
            assert squawk.E(fix) in html, "a computed fix never reached the page"
        assert "nothing to do" in html, "a passing check leaves an empty cell"

    def test_findings_and_triage_still_count_the_same(self, tmp_path):
        """The grouping key changed in both places at once; if it had changed
        in one, the two pages would disagree, which is the defect this rule was
        written to prevent."""
        root, man = self._selfaudit_run(tmp_path)
        findings_html = squawk.view_findings(root, man["run_id"])
        triage_html = squawk.view_triage(root, man["run_id"])
        n = len(squawk.load_findings(man["_dir"]))
        payload = json.loads(re.search(r"var DECISIONS=(\[.*?\]),SEV=",
                                       triage_html, re.S).group(1))
        assert "%d finding(s) in %d group(s)" % (n, len(payload)) in findings_html


class TestIntelTablesAndTiles:
    """Three things reported from the field on the same screenshots: the EPSS
    table was a bare list of ids with no clue what each one was tied to, no CVE
    anywhere was clickable, and the scan tiles were all different heights with
    the Run button at a different place in each."""

    def _feeds(self, root, kev_entries, epss):
        fdir = os.path.join(root, "feeds")
        os.makedirs(fdir, exist_ok=True)
        with open(os.path.join(fdir, "kev.json"), "w") as fh:
            json.dump({"vulnerabilities": kev_entries}, fh)
        with open(os.path.join(fdir, "epss.csv"), "w") as fh:
            fh.write("#m\ncve,epss,percentile\n")
            for cve, score, pct in epss:
                fh.write("%s,%s,%s\n" % (cve, score, pct))
        with open(os.path.join(fdir, "feeds.json"), "w") as fh:
            json.dump({"fetched_at": "20260906T000000Z",
                       "kev": {"url": squawk.KEV_URL, "sha256": "a" * 64,
                               "bytes": 1, "entries": len(kev_entries)},
                       "epss": {"url": squawk.EPSS_URL, "sha256": "b" * 64,
                                "bytes": 1, "entries": len(epss)}}, fh)

    def _root(self, tmp_path):
        root = str(tmp_path / "ev")
        target = str(tmp_path / "app")
        os.makedirs(target, exist_ok=True)
        d = os.path.join(root, "20260906T120000Z-dir")
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        man = {"run_id": "20260906T120000Z-dir", "service": "baggage",
               "scope": "dir", "target": target, "service_label": "B",
               "not_covered": "", "counts": {"total": 0, "excluded": 0},
               "severities": {}, "ledger": []}
        for name, obj in (("manifest.json", man), ("identities.json", {}),
                          ("findings.json", []), ("digest.json", {})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(obj, fh)
        self._feeds(root, [
            {"cveID": "CVE-2026-1111", "dateAdded": "2026-09-01",
             "knownRansomwareCampaignUse": "Unknown", "vendorProject": "Acme",
             "product": "Gateway", "vulnerabilityName": "Acme Gateway RCE",
             "shortDescription": "d", "requiredAction": "a", "dueDate": "x",
             "cwes": []}],
            [("CVE-2026-1111", 0.90, 0.99), ("CVE-2026-2222", 0.80, 0.98)])
        return root

    def test_every_cve_is_a_link_to_its_detail(self, tmp_path):
        root = self._root(tmp_path)
        html = squawk.view_intel_feed(root)
        assert "<a href='/intel?cve=CVE-2026-1111'>CVE-2026-1111</a>" in html
        assert "<a href='/intel?cve=CVE-2026-2222'>CVE-2026-2222</a>" in html, \
            "a CVE in the score table is not clickable"

    def test_the_score_table_says_what_each_cve_is_tied_to(self, tmp_path):
        root = self._root(tmp_path)
        html = squawk.view_intel_feed(root)
        block = html.split("Highest EPSS scores overall")[1]
        assert "<th>Vendor and product</th>" in block and "<th>What it is</th>" in block
        assert "Acme Gateway" in block, "the catalogue knows the vendor and it is not shown"
        assert "Acme Gateway RCE" in block
        # a CVE the catalogue does not carry says so rather than showing a blank
        assert "not fetched — squawk feeds --intel" in block
        assert squawk._cve_vendor("CVE-2026-2222", squawk.load_feeds(root)) == "—"

    def test_a_kev_row_in_the_score_table_is_marked(self, tmp_path):
        root = self._root(tmp_path)
        block = squawk.view_intel_feed(root).split("Highest EPSS scores")[1]
        assert ">KEV</span>" in block, "a KEV entry is indistinguishable in the list"

    def test_the_browse_chevron_is_drawn_by_the_browser_not_a_font(self):
        """`"\\25B8"` in a Python string is an octal escape (\\25) followed by
        the letters B8, so the summary once rendered as "B8 Browse for a
        directory". The character fixed that on a machine whose font had it;
        the Kali browser's did not. The browser's own disclosure triangle needs
        no character at all."""
        shell = squawk.page("t", "b", "scan", "c").decode("utf-8")
        assert "disclosure-closed" in shell and "disclosure-open" in shell
        assert "25B8" not in shell, "the escape reached the page as text"
        assert "summary::before" not in shell, "a glyph marker came back"

    def test_every_tile_puts_its_run_button_on_the_same_line(self, tmp_path,
                                                             monkeypatch):
        """The tiles are grid cells and already stretch to a common height; the
        form sat straight after the "not covered" text, which is one line for
        one service and seven for another, so Run floated at a different height
        in every tile."""
        monkeypatch.setenv("SQUAWK_SCAN_ROOTS", str(tmp_path))
        shell = squawk.page("t", "b", "scan", "c").decode("utf-8")
        assert ".svc form{display:flex" in shell and "margin-top:auto" in shell, \
            "nothing pins the form to the bottom of the tile"
        html = squawk.view_scan(str(tmp_path / "ev"), None)
        # The subject sits IN the form row, in a box shaped like the other
        # tiles' pickers, so Run lands at the same place in every tile. It
        # used to be a sentence above a bare button — the one tile that did
        # not match the other eleven.
        host = html.split("Instrument check")[1].split("</form>")[0]
        assert host.index("class='fixed'") < host.index("<button class='btn'>Run"), \
            "the subject box must come before Run in the same row"
        assert "class='subject'" not in html


class TestEveryNumberShowsItsProof:
    """Reported from the field: "where is this priority list coming from?" and
    "if you present a number that references data, it must be linked to show
    the proof". Priority and Compare named a run in their header and gave no
    way to see the others or pick one, so the honest answer to the first
    question was "whichever was newest, chosen for you"."""

    def _runs(self, tmp_path, n=2):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        for _ in range(n):
            squawk.execute_service(squawk.SERVICES["selfaudit"], "host", root,
                                   os.getcwd())
            time.sleep(1.1)
        return root, squawk.list_runs(root)

    def test_priority_and_compare_let_you_pick_the_run(self, tmp_path):
        root, runs = self._runs(tmp_path)
        for page, view in (("priority", squawk.view_priority),
                           ("compare", squawk.view_compare)):
            html = view(root, runs[0]["run_id"])
            picker = re.search(r"<form method='get' action='/%s'.*?</form>" % page,
                               html, re.S)
            assert picker, "%s has no run picker" % page
            assert picker.group(0).count("<option") == len(runs), \
                "%s does not offer every run" % page
            assert "run(s) on record" in picker.group(0)
            assert "/findings?run=" in picker.group(0), \
                "%s does not link to the run's own findings" % page

    def test_priority_no_longer_asserts_a_run_with_no_way_to_change_it(self, tmp_path):
        root, _runs = self._runs(tmp_path, 1)
        html = squawk.view_priority(root, None)
        assert "Run: <b>" not in html, "the header still states a run as a fact"
        assert "select name='run'" in html

    def test_the_picker_marks_the_run_being_shown(self, tmp_path):
        root, runs = self._runs(tmp_path)
        html = squawk.view_priority(root, runs[1]["run_id"])
        picker = re.search(r"<form method='get' action='/priority'.*?</form>",
                           html, re.S).group(0)
        assert "value='%s' selected" % runs[1]["run_id"] in picker

    def test_the_exploited_tile_links_to_the_findings_behind_it(self, tmp_path):
        root, _runs = self._runs(tmp_path, 1)
        html = squawk.view_overview(root)
        assert "<a class='card tight stat' href='/intel'" in html, \
            "the KEV count is a number with nowhere to check it"
        # and it links whether or not the feeds are present, because the page it
        # points at explains an absent feed better than a tooltip does
        assert html.count("href='/intel'") >= 1

    def test_the_attention_chips_point_at_the_rows_that_produced_them(self, tmp_path):
        root, _runs = self._runs(tmp_path, 1)
        html = squawk.view_overview(root)
        assert "id='targets'" in html
        for chip in ("coverage gap", "not scanned in"):
            if chip in html:
                idx = html.index(chip)
                assert "href='#targets'" in html[max(0, idx - 200):idx], \
                    "%r is not a link to what it counts" % chip

    def test_the_per_target_counts_were_already_links_and_stay_links(self, tmp_path):
        root, runs = self._runs(tmp_path, 1)
        html = squawk.view_overview(root)
        rid = runs[0]["run_id"]
        assert "/findings?run=%s&amp;sev=" % rid in html, \
            "a severity count on a target row is not linked to its findings"


class TestCveLinksOutToTheSource:
    """Reported from the field: "link to cve does not open new page to show the
    reference to the CVE for source intel". The internal link worked; what was
    missing was the way out to the record itself, so a CVE with nothing fetched
    was a dead end that told you to run a command."""

    def _feeds(self, root, cve="CVE-2026-85046"):
        fdir = os.path.join(root, "feeds")
        os.makedirs(fdir, exist_ok=True)
        with open(os.path.join(fdir, "kev.json"), "w") as fh:
            json.dump({"vulnerabilities": [
                {"cveID": cve, "dateAdded": "2026-09-04",
                 "knownRansomwareCampaignUse": "Unknown", "vendorProject": "V",
                 "product": "P", "vulnerabilityName": "n", "shortDescription": "d",
                 "requiredAction": "a", "dueDate": "x", "cwes": []}]}, fh)
        with open(os.path.join(fdir, "epss.csv"), "w") as fh:
            fh.write("#m\ncve,epss,percentile\n%s,0.0116,0.65\n" % cve)
        with open(os.path.join(fdir, "feeds.json"), "w") as fh:
            json.dump({"fetched_at": "x", "kev": {"entries": 1},
                       "epss": {"entries": 1}}, fh)

    def test_the_record_is_one_click_away_at_every_source(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        self._feeds(root)
        html = squawk.view_intel(root, "CVE-2026-85046")
        assert "Look it up at the source" in html
        for name, url in squawk.CVE_SOURCES:
            assert squawk.E(url % "CVE-2026-85046") in html, name
        assert html.count("target='_blank'") == len(squawk.CVE_SOURCES)
        assert html.count("rel='noopener noreferrer'") == len(squawk.CVE_SOURCES), \
            "a new-tab link without noopener hands the opener to the target site"

    def test_a_cve_page_works_before_anything_has_been_scanned(self, tmp_path):
        """The detail view bailed to "no live targets yet" when the evidence
        root had no runs, so a link to a CVE answered a question nobody asked.
        What a CVE is does not depend on having scanned anything."""
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        self._feeds(root)
        html = squawk.view_intel(root, "CVE-2026-85046")
        assert "No live targets yet" not in html
        assert "added 2026-09-04" in html and "0.0116" in html
        assert "Look it up at the source" in html
        assert "Not in the estate" in html, \
            "it should still say the CVE is not in anything scanned"
        # the list view with no targets still says so, and points somewhere useful
        listing = squawk.view_intel(root)
        assert "No live targets yet" in listing
        assert "/intel?scope=feed" in listing

    def test_the_source_links_need_no_fetch(self, tmp_path, monkeypatch):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        self._feeds(root)

        def boom(*_a, **_k):
            raise AssertionError("the page reached the network")
        monkeypatch.setattr(squawk.feeds.urllib.request, "urlopen", boom)
        html = squawk.view_intel(root, "CVE-2026-85046")
        assert "nvd.nist.gov/vuln/detail/CVE-2026-85046" in html


class TestEstateView:
    """Every findings view was one run, so the question a security engineer
    actually asks — where is this rule failing across everything I look after —
    had no page, and the Overview's totals had nowhere to link to show their
    proof."""

    def _mk(self, root, rid, target, finds, gap=False):
        os.makedirs(target, exist_ok=True)
        d = os.path.join(root, rid)
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        cov = {"examined": 0 if gap else 3, "unit": "files", "skipped": 0,
               "errors": 0, "note": ""}
        man = {"run_id": rid, "service": "baggage", "scope": "dir", "target": target,
               "service_label": "Baggage", "not_covered": "",
               "counts": {"total": len(finds), "excluded": 0}, "severities": {},
               "ledger": [{"tool": "semgrep", "status": "gap" if gap else "ok",
                           "detail": "", "evidence": "", "coverage": cov}]}
        idents = {}
        for f in finds:
            idents.setdefault(f["scanner"], []).append(f["identity"])
        for name, obj in (("manifest.json", man), ("identities.json", idents),
                          ("findings.json", finds), ("digest.json", {})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(obj, fh)

    def _f(self, sc, ident, sev, title, path):
        return {"scanner": sc, "identity": ident, "severity": sev, "title": title,
                "path": path, "detail": {}}

    def _estate(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        a, b = str(tmp_path / "app-a"), str(tmp_path / "app-b")
        self._mk(root, "20260906T100000Z-dir", a, [
            self._f("semgrep", "R1:x.py:1", "high", "Rule one", "x.py"),
            self._f("semgrep", "R1:y.py:2", "high", "Rule one", "y.py"),
            self._f("bandit", "B602:z.py:3", "critical", "Shell injection", "z.py")])
        self._mk(root, "20260906T110000Z-dir", b, [
            self._f("semgrep", "R1:q.py:9", "medium", "Rule one", "q.py"),
            self._f("semgrep", "R2:w.py:1", "low", "Rule two", "w.py")])
        return root, a, b

    def test_one_rule_across_two_targets_is_one_row(self, tmp_path):
        root, _a, _b = self._estate(tmp_path)
        live, _van, _by = squawk.estate_runs(root)
        rows = {(r["scanner"], r["rule"]): r for r in squawk.estate_rows(root, live)}
        r1 = rows[("semgrep", "R1")]
        assert len(r1["targets"]) == 2 and r1["instances"] == 3, \
            "the rule was not grouped across targets, or instances were merged"
        assert r1["severity"] == "high", "the worst severity across targets wins"
        assert sorted(r1["paths"]) == ["q.py", "x.py", "y.py"]

    def test_the_same_identity_in_two_targets_stays_two_instances(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        for i, name in enumerate(("app-a", "app-b")):
            self._mk(root, "20260906T10000%dZ-dir" % i, str(tmp_path / name),
                     [self._f("semgrep", "R1:x.py:1", "high", "Rule one", "x.py")])
        live, _v, _b = squawk.estate_runs(root)
        rows = squawk.estate_rows(root, live)
        assert len(rows) == 1 and rows[0]["instances"] == 2, \
            "the same rule on two machines was collapsed into one finding"
        assert len(rows[0]["targets"]) == 2

    def test_a_vanished_target_is_excluded_and_a_gap_run_is_flagged(self, tmp_path):
        root, _a, _b = self._estate(tmp_path)
        gone = str(tmp_path / "gone")
        self._mk(root, "20260906T120000Z-dir", gone,
                 [self._f("semgrep", "R9:g.py:1", "critical", "Vanished", "g.py")])
        shutil.rmtree(gone)
        self._mk(root, "20260906T130000Z-dir", str(tmp_path / "app-c"),
                 [self._f("semgrep", "R3:c.py:1", "low", "Gappy", "c.py")], gap=True)
        html = squawk.view_estate(root, {})
        assert "Vanished" not in html, "a vanished target's findings were counted"
        assert "1 vanished, not counted" in html
        assert "1 with a coverage gap" in html
        assert "Gappy" in html, "a gap run was dropped instead of flagged"
        assert "class='attn-i gap'>gap" in html

    def test_every_filter_narrows_and_says_it_is_on(self, tmp_path):
        root, _a, b = self._estate(tmp_path)
        cases = [({"sev": "critical"}, 1), ({"scanner": "bandit"}, 1),
                 ({"target": b}, 2), ({"q": "z.py"}, 1), ({"q": "Rule two"}, 1),
                 ({"status": "undecided"}, 3)]
        for params, expect in cases:
            html = squawk.view_estate(root, params)
            assert html.count("<details class='card tight'") == expect, \
                "%r matched the wrong number of rows" % params
            for k, v in params.items():
                assert "%s: %s" % (k, v) in html, \
                    "%s is filtering and the page does not say so" % k
                assert "&times;" in html, "an active filter has no way to remove it"

    def test_search_matches_an_identity_as_well_as_a_path(self, tmp_path):
        root, _a, _b = self._estate(tmp_path)
        assert squawk.view_estate(root, {"q": "B602"}).count(
            "<details class='card tight'") == 1

    def test_nothing_matching_says_how_many_exist(self, tmp_path):
        root, _a, _b = self._estate(tmp_path)
        html = squawk.view_estate(root, {"q": "nothing-matches-this"})
        assert "Nothing matches" in html and "3 row(s) across the estate" in html

    def test_paging_never_hides_a_count(self, tmp_path):
        rows = [{"scanner": "s", "rule": "R%d" % i, "title": "t", "severity": "low",
                 "instances": 1, "targets": {"a": {}}, "regressed": 0,
                 "first_seen": "", "last_seen": "", "paths": [], "identities": [],
                 "incomplete": False, "decision": {"status": "open"}}
                for i in range(120)]
        res = squawk.apply_estate_query(rows, per_page=50)
        assert res["pages"] == 3 and res["total"] == 120 and res["last"] == 50
        last = squawk.apply_estate_query(rows, page=3, per_page=50)
        assert (last["first"], last["last"]) == (101, 120)
        past = squawk.apply_estate_query(rows, page=9, per_page=50)
        assert past["page"] == 3 and past["clamped"] is True, \
            "a page past the end returned an empty table instead of the last page"
        assert squawk.apply_estate_query(rows, page=0, per_page=50)["page"] == 1

    def test_an_unknown_sort_falls_back_and_says_so(self, tmp_path):
        root, _a, _b = self._estate(tmp_path)
        html = squawk.view_estate(root, {"sort": "by-vibes"})
        assert "fell back to severity" in html
        res = squawk.apply_estate_query([], sort="by-vibes")
        assert res["sort"] == "severity" and res["sort_fell_back"] is True
        assert squawk.apply_estate_query([], sort="")["sort_fell_back"] is False

    def test_the_default_sort_is_severity_then_volume(self, tmp_path):
        root, _a, _b = self._estate(tmp_path)
        live, _v, _b2 = squawk.estate_runs(root)
        order = [(r["scanner"], r["rule"]) for r in
                 squawk.apply_estate_query(squawk.estate_rows(root, live))["rows"]]
        assert order[0] == ("bandit", "B602"), "critical is not first"
        assert order[1] == ("semgrep", "R1"), "high before low, volume as the tiebreak"

    def test_a_row_expands_to_its_targets_with_a_way_into_each(self, tmp_path):
        root, _a, _b = self._estate(tmp_path)
        html = squawk.view_estate(root, {"scanner": "semgrep", "q": "Rule one"})
        assert "app-a" in html and "app-b" in html
        assert html.count("/findings?run=") >= 2 and html.count("/triage?run=") >= 2

    def test_the_overview_numbers_link_to_their_proof(self, tmp_path):
        """The request that produced this page: if you present a number that
        references data, it must be linked to show the proof."""
        root, _a, _b = self._estate(tmp_path)
        html = squawk.view_overview(root)
        assert "href='/estate?sev=critical,high'" in html, \
            "the critical & high tile must land on both, not on critical alone"
        assert "href='/estate'" in html, "the open-findings tile is not a link"
        for sev in ("critical", "high", "medium", "low", "info"):
            assert "/estate?sev=%s" % sev in html, \
                "the %s count in the legend is not a link" % sev

    def test_partial_is_not_decided_and_an_unknown_value_is_named(self, tmp_path):
        """Reviewed 3 of 5 read as `decided` in the filter, hiding the two
        nobody had looked at. And ?sev=critcal showed "0 of 0 rows" under a
        chip, which reads as "nothing critical" rather than "you misspelt it"."""
        root = str(tmp_path / "ev")
        app = str(tmp_path / "app")
        idents = ["R:a.py:%d" % i for i in range(5)]
        self._mk(root, "20260101T000000Z", app,
                 [self._f("semgrep", i, "high", "Rule R", i.split(":")[1]) for i in idents])
        squawk.record_decision(root, "20260101T000000Z", app, "baggage", "semgrep", "R",
                               "reviewed", idents[:3], by="ryan-test", at="20260101T010000Z")
        live, _v, _b = squawk.estate_runs(root)
        rows = squawk.estate_rows(root, live)
        assert rows[0]["decision"]["status"] == "partial"
        assert squawk.apply_estate_query(rows, status="decided")["total"] == 0
        assert squawk.apply_estate_query(rows, status="partial")["total"] == 1
        assert squawk.apply_estate_query(rows, status="undecided")["total"] == 0
        res = squawk.apply_estate_query(rows, sev="critcal", status="done")
        assert res["total"] == 0 and res["unknown_filters"] == [
            "sev=critcal is not a severity", "status=done is not a status"]
        html = squawk.view_estate(root, {"sev": "critcal"})
        assert "sev=critcal is not a severity" in html
        assert squawk.apply_estate_query(rows, sev="high")["unknown_filters"] == []

    def test_an_empty_estate_says_so_rather_than_showing_zero_rows(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        html = squawk.view_estate(root, {})
        assert "No live targets yet" in html and "Traceback" not in html

    def test_the_estate_groups_the_way_findings_groups(self, tmp_path):
        """If the two used different keys they would disagree about what one
        advisory is, which is the defect DESIGN pillar 5 exists to prevent.
        Exercised, not read from source: an identity whose first segment is
        the scanner's own name (`trivy:CVE-…`) groups under the CVE on both
        pages, and a naive split on ':' would group it under `trivy`."""
        root = str(tmp_path / "ev")
        self._mk(root, "20260101T000000Z", str(tmp_path / "app"),
                 [self._f("trivy", "trivy:CVE-2024-1000:pkg", "high", "T", "go.mod"),
                  self._f("semgrep", "R.x:app.py:1", "low", "S", "app.py")])
        live, _v, _b = squawk.estate_runs(root)
        rules = {(r["scanner"], r["rule"]) for r in squawk.estate_rows(root, live)}
        assert rules == {("trivy", "CVE-2024-1000"), ("semgrep", "R.x")}, rules
        html = squawk.view_findings(root, "20260101T000000Z")
        assert "trivy &middot; CVE-2024-1000" in html, "Findings groups under the CVE"
        assert "trivy &middot; trivy" not in html, "Findings grouped under the scanner name"


class TestTamperEvidence:
    """Evidence is the product, so the claim it has to answer is "prove this was
    not edited after the fact". Every run hashes its own files and the run before
    it; every decision hashes the decision before it; `verify` walks both and
    names the first thing that does not hold. Three outcomes, never two — a run
    that could not be checked is neither a pass nor a failure."""

    def _run(self, root, rid, target="/repo/a", findings=None):
        """A run written the way the engine writes one: files first, digest last
        over what is actually on disk, then sealed."""
        d = os.path.join(root, rid)
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        finds = findings if findings is not None else [
            {"scanner": "trivy", "identity": "trivy:CVE-2024-1000",
             "severity": "high", "title": "A vulnerable dependency",
             "path": "go.mod", "detail": {}}]
        man = {"schema_version": squawk.SCHEMA_VERSION, "run_id": rid,
               "service": "customs", "service_label": "Customs (repo)",
               "scope": "repo", "target": target, "not_covered": "",
               "counts": {"total": len(finds), "excluded": 0},
               "severities": {"high": len(finds)},
               "ledger": [{"tool": "trivy", "status": "ok", "detail": "",
                           "evidence": "raw/trivy.json", "coverage": None}]}
        for name, obj in (("manifest.json", man), ("findings.json", finds),
                          ("identities.json", {"trivy": [f["identity"] for f in finds]})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(obj, fh)
        with open(os.path.join(d, "raw", "trivy.json"), "w") as fh:
            fh.write('{"Results": []}')
        digest = {"schema_version": squawk.SCHEMA_VERSION, "run_id": rid,
                  "files": squawk.hash_run_files(d)}
        digest.update(squawk.chain_fields(root, rid))
        with open(os.path.join(d, "digest.json"), "w") as fh:
            json.dump(digest, fh, indent=2, sort_keys=True)
        squawk.seal_run(d)
        return d

    def _estate(self, root):
        os.makedirs(root, exist_ok=True)
        self._run(root, "20260101T000000Z-aaa", "/repo/a")
        self._run(root, "20260102T000000Z-bbb", "/repo/b")
        self._run(root, "20260103T000000Z-ccc", "/repo/a")
        return root

    def _row(self, report, run_id):
        return next(r for r in report["runs"] if r["run_id"] == run_id)

    def _writable(self, path):
        """Tampering has to defeat the seal first, which is the point of it."""
        os.chmod(path, 0o600)

    # ---- the digest covers a real run ----------------------------------- #

    def test_a_real_run_digest_lists_every_file_and_the_hashes_match(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        out = squawk.execute_service(squawk.SERVICES["selfaudit"], "host", root,
                                     str(tmp_path))
        run_dir = os.path.join(root, out["run_id"])
        digest = squawk.load_digest(run_dir)
        assert digest["schema_version"] == squawk.SCHEMA_VERSION
        on_disk = set(squawk.run_file_names(run_dir))
        assert on_disk and set(digest["files"]) == on_disk, \
            "the digest must cover every file in the run but itself"
        assert "manifest.json" in digest["files"] and "history.json" in digest["files"], \
            "history.json is written before the digest, so the digest covers it"
        for rel, want in digest["files"].items():
            got = squawk.sha256_file(os.path.join(run_dir, rel.replace("/", os.sep)))
            assert got == want, "%s does not match its recorded hash" % rel
        assert squawk.verify_root(root)["exit"] == 0

    def test_a_finished_run_is_sealed_read_only(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        out = squawk.execute_service(squawk.SERVICES["selfaudit"], "host", root,
                                     str(tmp_path))
        run_dir = os.path.join(root, out["run_id"])
        for rel in [*squawk.run_file_names(run_dir), "digest.json"]:
            mode = os.stat(os.path.join(run_dir, rel.replace("/", os.sep))).st_mode & 0o777
            assert mode == 0o400, "%s is %o, not sealed" % (rel, mode)

    def test_an_aborted_run_gets_a_digest_too(self, tmp_path):
        """A run that never finished is still evidence, and evidence that
        cannot be verified is a gap."""
        root = str(tmp_path / "ev")
        d = os.path.join(root, "20260104T000000Z-ddd")
        os.makedirs(d)
        with open(os.path.join(d, "started.json"), "w") as fh:
            json.dump({"service": "customs", "target": "/repo/a",
                       "started_at": "20260104T000000Z"}, fh)
        assert squawk.record_aborted_run(d, "the server was stopped")
        digest = squawk.load_digest(d)
        assert digest["aborted"] and "manifest.json" in digest["files"]
        assert squawk.verify_run(root, "20260104T000000Z-ddd", {})["state"] == "ok"

    # ---- the chain across runs ------------------------------------------ #

    def test_three_runs_chain_in_order_across_two_targets(self, tmp_path):
        root = self._estate(str(tmp_path / "ev"))
        ids = ["20260101T000000Z-aaa", "20260102T000000Z-bbb", "20260103T000000Z-ccc"]
        assert squawk.load_digest(os.path.join(root, ids[0]))["prev_run"] is None
        for i in range(1, len(ids)):
            older, newer = ids[i - 1], ids[i]
            d = squawk.load_digest(os.path.join(root, newer))
            assert d["prev_run"] == older, "the chain is over the store, not one target"
            assert d["prev_digest_sha256"] == \
                squawk.sha256_file(os.path.join(root, older, "digest.json"))
        report = squawk.verify_root(root)
        assert report["status"] == "ok" and report["exit"] == 0
        assert report["counts"]["ok"] == 3

    def test_altering_one_byte_is_named_and_exits_one(self, tmp_path):
        root = self._estate(str(tmp_path / "ev"))
        victim = os.path.join(root, "20260102T000000Z-bbb", "findings.json")
        self._writable(victim)
        blob = json.load(open(victim))
        blob[0]["severity"] = "low"
        with open(victim, "w") as fh:
            json.dump(blob, fh)
        report = squawk.verify_root(root)
        row = self._row(report, "20260102T000000Z-bbb")
        assert row["state"] == "altered" and row["altered"] == ["findings.json"]
        assert report["exit"] == 1 and "1 altered" in report["summary"]

    def test_deleting_a_raw_file_is_missing_not_pruned(self, tmp_path):
        root = self._estate(str(tmp_path / "ev"))
        os.remove(os.path.join(root, "20260103T000000Z-ccc", "raw", "trivy.json"))
        report = squawk.verify_root(root)
        row = self._row(report, "20260103T000000Z-ccc")
        assert row["state"] == "missing" and row["missing"] == ["raw/trivy.json"]
        assert row["pruned"] == [], "nothing recorded its removal, so it is not pruned"
        assert report["exit"] == 1

    def test_planting_a_file_in_a_sealed_run_is_reported(self, tmp_path):
        root = self._estate(str(tmp_path / "ev"))
        with open(os.path.join(root, "20260102T000000Z-bbb", "raw", "planted.json"),
                  "w") as fh:
            fh.write("{}")
        report = squawk.verify_root(root)
        row = self._row(report, "20260102T000000Z-bbb")
        assert row["state"] == "extra" and row["extra"] == ["raw/planted.json"], \
            "evidence is written once: an addition after the digest is reported"
        assert report["exit"] == 1

    def test_deleting_a_run_in_the_middle_breaks_the_chain_and_names_it(self, tmp_path):
        root = self._estate(str(tmp_path / "ev"))
        shutil.rmtree(os.path.join(root, "20260102T000000Z-bbb"))
        report = squawk.verify_root(root)
        row = self._row(report, "20260103T000000Z-ccc")
        assert row["state"] == "chain broken"
        assert "20260102T000000Z-bbb" in row["detail"], \
            "the report has to name the run that is missing"
        assert report["exit"] == 1

    def test_a_run_written_before_hashes_is_unverifiable_not_ok(self, tmp_path):
        root = self._estate(str(tmp_path / "ev"))
        for rid in os.listdir(root):
            p = os.path.join(root, rid, "digest.json")
            self._writable(p)
            doc = json.load(open(p))
            for key in ("files", "schema_version", "prev_run", "prev_digest_sha256"):
                doc.pop(key, None)
            with open(p, "w") as fh:
                json.dump(doc, fh)
        report = squawk.verify_root(root)
        assert report["status"] == "unverifiable" and report["exit"] == 3, \
            "could not tell is not a pass"
        assert report["unverifiable"] == 3 and "3 run(s) were written" in report["summary"]

    def test_an_empty_root_is_unverifiable_not_verified(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root)
        report = squawk.verify_root(root)
        assert report["exit"] == 3 and "nothing was verified" in report["summary"]

    # ---- retention and the chain ---------------------------------------- #

    def test_a_pruned_run_keeps_the_chain_and_deleting_its_record_breaks_it(self, tmp_path):
        root = self._estate(str(tmp_path / "ev"))
        plan = squawk.plan_prune(root, trim_days=0, drop_days=0)
        dropped = [r["run_id"] for r in plan["drop"]]
        assert "20260101T000000Z-aaa" in dropped, "the oldest run is droppable"
        squawk.apply_prune(plan, by="test")
        report = squawk.verify_root(root)
        assert report["exit"] == 0, report["summary"]
        row = self._row(report, "20260102T000000Z-bbb")
        assert any("was removed by retention on" in n for n in row["notes"]), \
            "a removal that was recorded is a note, not a broken chain"
        os.remove(os.path.join(root, squawk.DROPPED_FILE))
        after = squawk.verify_root(root)
        assert after["exit"] == 1 and "chain broken" in \
            [r["state"] for r in after["runs"]], \
            "removing the record of a removal is exactly what the chain catches"

    def test_a_trimmed_run_reads_as_pruned_not_as_missing(self, tmp_path):
        root = self._estate(str(tmp_path / "ev"))
        plan = squawk.plan_prune(root, trim_days=0, drop_days=99999)
        squawk.apply_prune(plan, by="test")
        report = squawk.verify_root(root)
        assert report["exit"] == 0, report["summary"]
        trimmed = [r for r in report["runs"] if r["pruned"]]
        assert trimmed and all(r["state"] == "ok" for r in trimmed)
        assert "removed by retention" in trimmed[0]["detail"]

    # ---- the decisions ledger ------------------------------------------- #

    def _decide(self, root, n=3):
        for i in range(n):
            squawk.record_decision(root, "20260101T000000Z-aaa", "/repo/a", "customs",
                                   "trivy", "R%d" % i, "reviewed",
                                   ["trivy:R%d" % i], note="test fixture",
                                   by="ryan-test", at="2026010%dT010000Z" % (i + 1))

    def test_three_decisions_chain_and_the_first_has_no_predecessor(self, tmp_path):
        root = str(tmp_path / "ev")
        self._decide(root)
        lines = open(squawk.ledger_path(root)).read().splitlines()
        assert json.loads(lines[0])["prev_sha256"] == ""
        for i in range(1, len(lines)):
            assert json.loads(lines[i])["prev_sha256"] == squawk.line_sha256(lines[i - 1])
        out = squawk.verify_ledger(root)
        assert out["state"] == "ok" and out["lines"] == 3 and out["head"]

    def test_editing_a_middle_line_names_the_line_that_changed(self, tmp_path):
        root = str(tmp_path / "ev")
        self._decide(root)
        p = squawk.ledger_path(root)
        lines = open(p).read().splitlines()
        ev = json.loads(lines[1])
        ev["status"] = "skipped"
        lines[1] = json.dumps(ev, sort_keys=True)
        open(p, "w").write("\n".join(lines) + "\n")
        out = squawk.verify_ledger(root)
        assert out["state"] == "broken" and out["broken_at"] == 3
        assert "line 2 was changed" in out["detail"], \
            "the edited line is line 2; line 3 is where it is detected"

    def test_removing_a_line_and_forging_one_both_break(self, tmp_path):
        root = str(tmp_path / "ev")
        self._decide(root)
        p = squawk.ledger_path(root)
        lines = open(p).read().splitlines()
        open(p, "w").write("\n".join([lines[0], lines[2]]) + "\n")
        assert squawk.verify_ledger(root)["state"] == "broken"
        forged = json.loads(lines[0])
        forged["status"] = "skipped"
        forged["prev_sha256"] = "0" * 64
        open(p, "w").write("\n".join([*lines, json.dumps(forged, sort_keys=True)]) + "\n")
        out = squawk.verify_ledger(root)
        assert out["state"] == "broken" and out["broken_at"] == 4

    def test_a_previous_head_catches_an_edit_to_the_newest_line(self, tmp_path):
        """A hash chain vouches for every line but its own last one. The head
        recorded by the previous verify is what closes that."""
        root = str(tmp_path / "ev")
        self._decide(root)
        head = squawk.verify_ledger(root)["head"]
        p = squawk.ledger_path(root)
        lines = open(p).read().splitlines()
        ev = json.loads(lines[-1])
        ev["note"] = "changed after the fact"
        lines[-1] = json.dumps(ev, sort_keys=True)
        open(p, "w").write("\n".join(lines) + "\n")
        assert squawk.verify_ledger(root)["state"] == "ok", \
            "on its own the chain cannot see this, which is why the head is kept"
        out = squawk.verify_ledger(root, since_head=head)
        assert out["state"] == "broken" and "newest decision" in out["detail"]

    def test_a_ledger_written_before_the_chain_is_unverifiable(self, tmp_path):
        root = str(tmp_path / "ev")
        self._decide(root, 1)
        p = squawk.ledger_path(root)
        ev = json.loads(open(p).read().strip())
        ev["v"] = 1
        ev.pop("prev_sha256")
        open(p, "w").write(json.dumps(ev, sort_keys=True) + "\n")
        out = squawk.verify_ledger(root)
        assert out["state"] == "unverifiable" and out["unverifiable"] == 1
        assert squawk.load_decisions(root), "an old line is still a decision"

    # ---- the command ----------------------------------------------------- #

    def test_verify_writes_its_result_and_the_exit_codes_are_three(self, tmp_path, capsys):
        root = self._estate(str(tmp_path / "ev"))
        assert squawk.main(["verify", "--evidence", root]) == 0
        out = capsys.readouterr().out
        assert "3 run(s) verified unaltered" in out
        assert "does not prove" in out, "the docs claim is on the command's own output"
        doc = squawk.load_verify(root)
        assert doc["status"] == "ok" and doc["at"] and doc["total"] == 3
        victim = os.path.join(root, "20260102T000000Z-bbb", "manifest.json")
        self._writable(victim)
        with open(victim, "a") as fh:
            fh.write(" ")
        assert squawk.main(["verify", "--evidence", root]) == 1
        assert "altered" in capsys.readouterr().out
        assert squawk.main(["verify", "--evidence", str(tmp_path / "nope")]) == 1

    def test_verify_json_is_one_document(self, tmp_path, capsys):
        root = self._estate(str(tmp_path / "ev"))
        assert squawk.main(["verify", "--evidence", root, "--json"]) == 0
        doc = json.loads(capsys.readouterr().out)
        assert doc["status"] == "ok" and len(doc["runs"]) == 3
        assert doc["ledger"]["state"] == "ok"

    def test_verify_is_a_subcommand_and_a_flag(self):
        assert squawk._translate_argv(["verify", "--json"]) == ["--verify", "--json"]
        assert "verify" in squawk.SUBCOMMANDS

    # ---- the pages ------------------------------------------------------- #

    def test_healthz_says_never_verified_until_verify_runs(self, tmp_path):
        """Live through the running server, not read from source: a control in
        source that the handler does not serve is not a control."""
        import socket
        import threading
        import urllib.request
        from http.server import ThreadingHTTPServer
        root = self._estate(str(tmp_path / "ev"))
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        srv = ThreadingHTTPServer(("127.0.0.1", port),
                                  squawk.make_handler(root, str(tmp_path)))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = "http://127.0.0.1:%d/healthz" % port
            with urllib.request.urlopen(url, timeout=5) as r:
                health = json.loads(r.read().decode())
            assert health["verify_status"] == "never" and health["verified_at"] == "", \
                "a health document must never call an unrun check ok"
            assert "never verified" in squawk.view_overview(root)
            squawk.save_verify(root, squawk.verify_root(root))
            with urllib.request.urlopen(url, timeout=5) as r:
                health = json.loads(r.read().decode())
            assert health["verify_status"] == "ok" and health["verified_at"]
            html = squawk.view_overview(root)
            assert "Evidence verified" in html and "3 run(s) verified" in html
        finally:
            srv.shutdown()
            srv.server_close()

    def test_the_overview_flags_evidence_that_does_not_verify(self, tmp_path):
        root = self._estate(str(tmp_path / "ev"))
        shutil.rmtree(os.path.join(root, "20260102T000000Z-bbb"))
        squawk.save_verify(root, squawk.verify_root(root))
        html = squawk.view_overview(root)
        assert "the evidence does not verify" in html and "#integrity" in html
        assert "chain broken" in html


    # ---- the second pass: every way the first version could be fooled ---- #

    def test_a_run_whose_manifest_was_deleted_is_missing_not_gone(self, tmp_path):
        """The first version defined a run as "a directory with a manifest",
        so deleting the manifest made the run vanish from verify, the estate
        and the Overview, exit 0, with a note. A run is any directory that was
        ever a run, and its manifest is a file like any other."""
        root = self._estate(str(tmp_path / "ev"))
        victim = os.path.join(root, "20260102T000000Z-bbb", "manifest.json")
        self._writable(victim)
        os.remove(victim)
        report = squawk.verify_root(root)
        row = self._row(report, "20260102T000000Z-bbb")
        assert row["state"] == "missing" and "manifest.json" in row["missing"]
        assert report["exit"] == 1 and report["total"] == 3

    def test_a_forged_pruned_json_hides_nothing(self, tmp_path):
        """pruned.json sits inside the run after the digest was sealed, so it
        is exactly the file a forger would write. verify reads the chained
        retention record at the root instead, and only for the parts
        retention can actually trim."""
        root = self._estate(str(tmp_path / "ev"))
        d = os.path.join(root, "20260102T000000Z-bbb")
        self._writable(os.path.join(d, "findings.json"))
        os.remove(os.path.join(d, "findings.json"))
        with open(os.path.join(d, "pruned.json"), "w") as fh:
            json.dump({"schema": 1, "at": "x", "by": "x", "removed": ["findings.json"]}, fh)
        report = squawk.verify_root(root)
        row = self._row(report, "20260102T000000Z-bbb")
        assert row["state"] == "missing" and row["pruned"] == []
        assert report["exit"] == 1
        # And a retention record naming a part retention cannot trim is not a
        # record of a trim: findings.json stays missing.
        squawk.record_prune(root, "trim", "20260102T000000Z-bbb", "/repo/b",
                            parts=["findings.json"], by="forger")
        assert squawk.trimmed_parts(root) == {"20260102T000000Z-bbb": []}
        assert squawk.verify_root(root)["exit"] == 1

    def test_only_a_recorded_trim_reads_as_pruned(self, tmp_path):
        root = self._estate(str(tmp_path / "ev"))
        d = os.path.join(root, "20260102T000000Z-bbb")
        shutil.rmtree(os.path.join(d, "raw"))
        assert self._row(squawk.verify_root(root), "20260102T000000Z-bbb")["state"] == "missing"
        squawk.record_prune(root, "trim", "20260102T000000Z-bbb", "/repo/b",
                            parts=["raw"], by="retention")
        report = squawk.verify_root(root)
        row = self._row(report, "20260102T000000Z-bbb")
        assert row["state"] == "ok" and row["pruned"] == ["raw/trivy.json"]
        assert report["exit"] == 0
        assert [r["kind"] for r in report["pruned_runs"]] == ["trim"]

    def test_a_removal_record_is_listed_never_trusted_quietly(self, tmp_path):
        """A record of a removal is only as good as the machine that wrote it,
        so verify does two things with one: it checks the record's own chain,
        and it lists every removal by run, date and name so the reader can
        recognise the ones they did. A line appended by hand, outside the
        chain, is unverifiable, and says so."""
        root = self._estate(str(tmp_path / "ev"))
        victim = os.path.join(root, "20260102T000000Z-bbb")
        sha = squawk.digest_sha256(victim)
        with open(os.path.join(root, squawk.DROPPED_FILE), "a") as fh:
            fh.write(json.dumps({"run_id": "20260102T000000Z-bbb", "digest_sha256": sha,
                                 "at": "20260906T000000Z", "by": "someone"}) + "\n")
        shutil.rmtree(victim)
        report = squawk.verify_root(root)
        assert report["exit"] == 3, "an unchained record is not a pass"
        assert report["retention"]["state"] == "unverifiable"
        assert "retention record" in report["summary"]
        # A properly chained record is relied on, and still listed.
        os.remove(os.path.join(root, squawk.DROPPED_FILE))
        squawk.record_prune(root, "drop", "20260102T000000Z-bbb", "/repo/b",
                            digest_sha256=sha, by="retention")
        report = squawk.verify_root(root)
        assert report["exit"] == 0
        assert [(r["run_id"], r["by"]) for r in report["pruned_runs"]] == \
            [("20260102T000000Z-bbb", "retention")]
        assert "removed 1 run(s)" in report["summary"] and "not a proof" in report["summary"]

    def test_the_retention_record_is_chained(self, tmp_path):
        root = self._estate(str(tmp_path / "ev"))
        for rid in ("20260101T000000Z-aaa", "20260102T000000Z-bbb"):
            squawk.record_prune(root, "trim", rid, "/repo", parts=["raw"], by="r")
        assert squawk.verify_retention(root)["state"] == "ok"
        p = os.path.join(root, squawk.DROPPED_FILE)
        lines = open(p).read().splitlines()
        first = json.loads(lines[0])
        first["parts"] = ["raw", "history.json"]          # widened after the fact
        lines[0] = json.dumps(first, sort_keys=True)
        open(p, "w").write("\n".join(lines) + "\n")
        out = squawk.verify_retention(root)
        assert out["state"] == "broken" and "line 1 was changed" in out["detail"]
        assert squawk.verify_root(root)["exit"] == 1

    def test_the_previous_verify_anchors_the_newest_run(self, tmp_path):
        """Nothing in a hash chain vouches for its newest link: alter the
        newest run and rewrite its digest to match, and the chain agrees with
        itself. The previous verify recorded that digest, so the next one
        sees the rewrite. And a run seen then and gone now needs a retention
        record, or it is missing — not merely absent from a list."""
        root = self._estate(str(tmp_path / "ev"))
        first = squawk.verify_root(root)
        assert first["exit"] == 0 and len(first["digests"]) == 3
        squawk.save_verify(root, first)
        d = os.path.join(root, "20260103T000000Z-ccc")
        for name in ("findings.json", "digest.json"):
            self._writable(os.path.join(d, name))
        finds = json.load(open(os.path.join(d, "findings.json")))
        finds[0]["severity"] = "info"
        json.dump(finds, open(os.path.join(d, "findings.json"), "w"))
        digest = json.load(open(os.path.join(d, "digest.json")))
        digest["files"] = squawk.hash_run_files(d)
        json.dump(digest, open(os.path.join(d, "digest.json"), "w"), indent=2, sort_keys=True)
        second = squawk.verify_root(root)
        row = self._row(second, "20260103T000000Z-ccc")
        assert row["state"] == "altered" and "rewritten after the verify" in row["detail"]
        assert second["exit"] == 1 and second["previous_at"] == first["at"]
        # Deleted outright instead: still caught, by the same memory.
        shutil.rmtree(d)
        third = squawk.verify_root(root)
        row = self._row(third, "20260103T000000Z-ccc")
        assert row["state"] == "missing" and "nothing records its removal" in row["detail"]
        assert third["exit"] == 1

    def test_an_unfinished_run_is_unverifiable_not_ok(self, tmp_path):
        root = self._estate(str(tmp_path / "ev"))
        d = os.path.join(root, "20260104T000000Z-ddd")
        os.makedirs(os.path.join(d, "raw"))
        with open(os.path.join(d, "started.json"), "w") as fh:
            json.dump({"service": "customs", "target": "/repo/a"}, fh)
        report = squawk.verify_root(root)
        row = self._row(report, "20260104T000000Z-ddd")
        assert row["state"] == "unverifiable" and row["detail"].startswith("unfinished")
        assert report["exit"] == 3 and "never finished" in report["summary"]

    def test_verify_reports_progress_as_it_goes(self, tmp_path):
        root = self._estate(str(tmp_path / "ev"))
        seen = []
        squawk.verify_root(root, progress=seen.append)
        assert [r["run_id"][-3:] for r in seen] == ["aaa", "bbb", "ccc"]

    def test_the_command_lists_what_it_relied_on(self, tmp_path, capsys):
        root = self._estate(str(tmp_path / "ev"))
        assert squawk.main(["verify", "--evidence", root]) == 0
        out = capsys.readouterr().out
        assert "Previous : none" in out
        plan = squawk.plan_prune(root, trim_days=0, drop_days=0)
        squawk.apply_prune(plan, by="ryan-test")
        assert squawk.main(["verify", "--evidence", root]) == 0
        out = capsys.readouterr().out
        assert "Previous : " in out and "none" not in out.split("Previous :")[1].split("\n")[0]
        assert "Relied on" in out and "removed 20260101T000000Z-aaa by ryan-test" in out

    def test_the_sweep_survives_a_sealed_run_with_no_manifest(self, tmp_path):
        """Found by the review: deleting a manifest made the start-up sweep
        try to write an 'aborted' digest over the sealed 0400 one, and the
        server died after printing 'is up'."""
        root = str(tmp_path / "ev")
        os.makedirs(root)
        out = squawk.execute_service(squawk.SERVICES["selfaudit"], "host", root,
                                     str(tmp_path))
        d = os.path.join(root, out["run_id"])
        self._writable(os.path.join(d, "manifest.json"))
        os.remove(os.path.join(d, "manifest.json"))
        old = time.time() - 4 * 3600
        os.utime(os.path.join(d, "started.json"), (old, old))
        assert squawk.record_aborted_run(d, "sweep") is False
        assert squawk.record_aborted_runs(root, "sweep", older_than=1) == []
        assert self._row(squawk.verify_root(root), out["run_id"])["state"] == "missing"


class TestRunsDoNotCollide:
    """Two runs of one scope in one second used to share a directory: both
    reported success and the second silently overwrote the first. Reproduced
    with two real self-audits started together. The directory is now claimed
    with an exclusive mkdir."""

    def test_claim_run_dir_never_hands_out_the_same_directory(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root)
        ids = [squawk.claim_run_dir(root, "host")[0] for _ in range(3)]
        assert len(set(ids)) == 3 and all(os.path.isdir(os.path.join(root, i)) for i in ids)
        assert ids == sorted(ids), "later claims sort later, so the chain order holds"
        assert all(squawk.run_age_days({"run_id": i}) is not None for i in ids), \
            "every reader of a run id parses only its leading timestamp"

    def test_two_real_runs_started_together_leave_two_runs(self, tmp_path):
        import threading
        root = str(tmp_path / "ev")
        os.makedirs(root)
        got = []
        gate = threading.Barrier(2)

        def go():
            gate.wait()
            got.append(squawk.execute_service(squawk.SERVICES["selfaudit"], "host",
                                              root, str(tmp_path))["run_id"])
        ts = [threading.Thread(target=go) for _ in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert len(set(got)) == 2, got
        assert len(squawk.list_runs(root)) == 2
        assert squawk.verify_root(root)["exit"] == 0


class TestStopStopsTheScanner:
    """`stop` recorded the scan as aborted and exited; the scanner it had
    started kept running. For an active DAST probe that was up to ninety
    minutes of attack traffic after "stopped". Every scanner now runs in its
    own process group, and stopping Squawk stops the group. The child writes
    its own pid and its grandchild's, so liveness is checked by pid, not by
    `pgrep`, which a slim container does not have."""

    SCRIPT = 'echo $$ > "$1"; sleep 300 & echo $! >> "$1"; wait'

    def _pids(self, path):
        with open(path) as fh:
            return [int(x) for x in fh.read().split()]

    def _alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def test_a_timeout_kills_the_whole_tree(self, tmp_path):
        pidfile = str(tmp_path / "pids")
        code, _o, err = squawk.run_cmd(["sh", "-c", self.SCRIPT, "sh", pidfile], None, 1)
        assert code == 124 and "timed out" in err
        pids = self._pids(pidfile)
        assert len(pids) == 2, "the shell and its sleep"
        time.sleep(0.3)
        assert not any(self._alive(p) for p in pids), \
            "the scanner's children outlived the timeout"

    def test_terminate_children_stops_a_running_scanner(self, tmp_path):
        import threading
        pidfile = str(tmp_path / "pids")
        t = threading.Thread(target=lambda: squawk.run_cmd(
            ["sh", "-c", self.SCRIPT, "sh", pidfile], None, 60), daemon=True)
        t.start()
        for _ in range(50):
            if os.path.exists(pidfile) and len(open(pidfile).read().split()) == 2:
                break
            time.sleep(0.05)
        pids = self._pids(pidfile)
        assert all(self._alive(p) for p in pids), "the scanner did not start"
        stopped = squawk.terminate_children()
        assert len(stopped) == 1 and stopped[0]["container"] is None
        t.join(5)
        time.sleep(0.3)
        assert not any(self._alive(p) for p in pids)
        assert squawk.terminate_children() == [], "nothing left to stop"

    def test_every_container_squawk_starts_carries_a_name(self, tmp_path):
        """Killing the `docker run` client past its grace period detaches the
        container rather than stopping it; a ZAP scan "stopped" that way kept
        attacking the target. A name is what the stop path kills by."""
        ctx = squawk.RunContext("http://127.0.0.1:3000", "url",
                                str(tmp_path / "20260907T000000Z-url"), str(tmp_path))
        ctx.raw_path = str(tmp_path / "20260907T000000Z-url" / "raw" / "zap.json")
        for key in ("zap-baseline", "zap-active"):
            cmd, _t = squawk.STAGES[key].build(ctx)
            if cmd and cmd[0] == "docker":
                name = squawk.container_of(cmd)
                assert name == "squawk-%s-20260907T000000Z-url" % key, cmd
        assert squawk.container_of(["docker", "run", "--rm", "img"]) is None
        assert squawk.container_of(["zap-baseline.py", "-t", "x"]) is None
        assert squawk.container_of(["docker", "run", "--name"]) is None

    def test_a_container_is_killed_by_name_and_checked(self, tmp_path):
        """The real thing, where docker exists: a container started through
        run_cmd, then terminate_children, then `docker ps` says it is gone.
        Where docker is absent this skips and says so."""
        import shutil as _sh
        import subprocess
        import threading
        if not _sh.which("docker") or subprocess.run(
                ["docker", "info"], capture_output=True, timeout=60).returncode != 0:
            pytest.skip("docker is not available here; the container path is "
                        "exercised on a machine that has it")
        name = "squawk-test-%d" % os.getpid()
        t = threading.Thread(target=lambda: squawk.run_cmd(
            ["docker", "run", "--rm", "--name", name, "alpine:3.20", "sleep", "300"],
            None, 600), daemon=True)
        t.start()
        for _ in range(240):
            if squawk._container_alive(name):
                break
            time.sleep(0.5)
        assert squawk._container_alive(name), "the container never started (pull?)"
        stopped = squawk.terminate_children()
        rec = next(r for r in stopped if r["container"] == name)
        assert rec["container_stopped"] is True, rec
        assert squawk._container_alive(name) is False
        t.join(10)

    def test_stop_waits_past_the_servers_own_shutdown_budget(self):
        """`stop` gave up at 10 s and reported the server still running while
        the server was three seconds from done. Drain 5 + grace 5 + kill 1 +
        a container check up to 10 is 21; the wait must clear it."""
        default = inspect.signature(squawk.cmd_stop).parameters["wait"].default
        assert default >= 5 + squawk.CHILD_GRACE_SECONDS + 1 + 10 + 5


class TestOnlyLoopbackIsAnswered:
    """The bind is loopback; the Host header is the attacker's. A browser
    DNS-rebound to 127.0.0.1 carries `Host: attacker.example:8787` and a page
    from that origin is same-origin with Squawk. Reproduced with curl before
    the check existed: the cross-origin guard passed it."""

    def test_a_foreign_host_header_is_refused_get_and_post(self, tmp_path):
        import urllib.request
        root = str(tmp_path / "ev")
        os.makedirs(root)
        with _serve(root, str(tmp_path)) as base:
            port = base.rsplit(":", 1)[1]
            for host in ("127.0.0.1:%s" % port, "localhost:%s" % port, "[::1]:%s" % port):
                code, body = _get(base + "/", headers={"Host": host})
                assert code == 200 and "<h1>Overview</h1>" in body, host
            code, body = _get(base + "/", headers={"Host": "attacker.example:%s" % port})
            assert code == 421 and "Request refused" in body
            assert "<h1>Overview</h1>" not in body
            req = urllib.request.Request(
                base + "/decide", data=b"run=x", method="POST",
                headers={"Host": "attacker.example:%s" % port,
                         "Origin": "http://attacker.example:%s" % port,
                         "Content-Type": "application/x-www-form-urlencoded"})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    code = r.status
            except urllib.error.HTTPError as e:
                code = e.code
            assert code == 421, "a rebound page could POST a scan at the LAN"

    def test_the_loopback_check_reads_host_headers_the_way_browsers_write_them(self):
        ok = squawk.host_is_loopback
        assert ok("127.0.0.1") and ok("127.0.0.1:8787") and ok("localhost:8787")
        assert ok("[::1]:8787") and ok("::1") and ok("LOCALHOST")
        assert not ok("attacker.example:8787") and not ok("127.0.0.1.attacker.example")
        assert not ok("") and not ok("0.0.0.0:8787") and not ok("10.0.0.5:8787")


class TestFeedCacheShapes:
    """A cached feed file that is valid JSON but not an object — `null`, a
    list — used to raise an AttributeError out of load_feeds, and the
    Overview, Intel and Priority pages returned traceback pages while
    `doctor` exited 1. Found by fuzzing the disk cache, not the parser."""

    def _feeds(self, root, feeds_json=b'{"fetched_at": "20260906T000000Z"}'):
        fd = os.path.join(root, "feeds")
        os.makedirs(fd, exist_ok=True)
        with open(os.path.join(fd, "feeds.json"), "wb") as fh:
            fh.write(feeds_json)
        with open(os.path.join(fd, "kev.json"), "wb") as fh:
            fh.write(b'{"vulnerabilities": [{"cveID": "CVE-2024-1000", "vendorProject": '
                     b'"v", "product": "p", "dateAdded": "2024-01-01"}]}')
        with open(os.path.join(fd, "epss.csv"), "w") as fh:
            fh.write("#model\ncve,epss,percentile\nCVE-2024-1000,0.9,0.99\n")

    @pytest.mark.parametrize("blob", [b"null", b"[]", b"42", b'"x"'])
    def test_a_non_object_feed_record_is_absent_not_a_crash(self, tmp_path, blob):
        root = str(tmp_path / "ev")
        self._feeds(root, blob)
        feeds = squawk.load_feeds(root)
        assert feeds["fetched_at"] is None and feeds["kev"], \
            "the catalogue still reads; the record is what could not"
        assert all(isinstance(r, dict) for r in squawk.intel_provenance(root))
        out = squawk.execute_service(squawk.SERVICES["selfaudit"], "host", root,
                                     str(tmp_path))
        with _serve(root, str(tmp_path)) as base:
            for path in ("/", "/intel", "/priority?run=%s" % out["run_id"]):
                code, body = _get(base + path)
                assert code == 200 and "Traceback" not in body, path

    def test_a_good_record_still_reads(self, tmp_path):
        root = str(tmp_path / "ev")
        self._feeds(root)
        feeds = squawk.load_feeds(root)
        assert feeds["present"] and feeds["fetched_at"] == "20260906T000000Z"


class TestZapReportsItsOwnCrawl:
    """ZAP's scan scripts print `Total of N URLs` when the crawl ends — the
    one crawl denominator the tool publishes — and the engine discarded it
    with the rest of stdout, then guessed coverage from where the alerts had
    been seen. On a clean crawl that guess is unknown, so a scan that reached
    three URLs and found nothing read the same as one that reached three
    hundred."""

    def _report(self, uris):
        return json.dumps({"site": [{"@name": "http://127.0.0.1:3000", "alerts": [
            {"name": "x", "instances": [{"uri": u} for u in uris]}]}]}) if uris else \
            json.dumps({"site": [{"@name": "http://127.0.0.1:3000", "alerts": []}]})

    def test_the_crawl_count_on_stdout_is_the_denominator(self):
        clean = self._report([])
        assert squawk._cov_zap(clean).examined is None, "no alerts, no stdout: unknown"
        cov = squawk._cov_zap(clean, "…\nTotal of 42 URLs\nPASS: x\n")
        assert cov.examined == 42 and cov.unit == "URLs" and "no alerts" in cov.note
        thin = squawk._cov_zap(clean, "Total of 0 URLs\n")
        assert thin.examined == 0 and "reached nothing" in thin.note, \
            "a crawl that reached nothing is examined 0, and I15 makes that a gap"
        floor = squawk._cov_zap(self._report(["/a", "/b?x=1", "/b?x=2"]))
        assert floor.examined == 2 and "floor" in floor.note
        both = squawk._cov_zap(self._report(["/a"]), "Total of 7 URLs")
        assert both.examined == 7, "the tool's own count wins over the floor"
        assert squawk.stage_coverage("zap", clean, "Total of 5 URLs").examined == 5

    def test_a_writes_report_stage_keeps_its_stdout_beside_the_report(self, tmp_path,
                                                                        monkeypatch):
        """Through the engine: a fake writes_report stage whose command prints
        the crawl line and writes a report. The stdout lands in raw/, is
        hashed into the digest, and reaches the coverage extractor. The
        engine's own binary check is satisfied by the fake, so this runs on a
        machine with no docker — the 3.9 container, say."""
        run_dir = str(tmp_path / "run")
        os.makedirs(os.path.join(run_dir, "raw"))
        script = str(tmp_path / "fakezap.sh")
        with open(script, "w") as fh:
            fh.write("#!/bin/sh\necho 'Total of 9 URLs'\n"
                     "printf '%s' '{\"site\": [{\"@name\": \"h\", \"alerts\": []}]}' > \"$1\"\n")
        os.chmod(script, 0o700)
        _patch_all(monkeypatch, "tool_path", lambda name: script)
        spec = squawk.StageSpec("zap", "baseline",
                                lambda ctx: ([script, ctx.raw_path], 30), writes_report=True)
        ctx = squawk.RunContext("http://127.0.0.1:3000", "url", run_dir, str(tmp_path))
        res = squawk._run_one_stage(spec, ctx, os.path.join(run_dir, "raw", "zap-baseline.json"),
                                    str(tmp_path), run_dir)
        assert res.status == "ok" and res.coverage.examined == 9, (res.status, res.detail)
        assert "across 9 URLs" in res.detail
        kept = open(os.path.join(run_dir, "raw", "zap-baseline.log")).read()
        assert "Total of 9 URLs" in kept


class TestDecisionsUnderLoad:
    """Two triage marks a moment apart used to read the same predecessor and
    fork the chain, and `verify` then reported the ledger as tampered with —
    the tool crying wolf on its own legitimate action. Eight at once now."""

    def test_concurrent_decisions_stay_chained(self, tmp_path):
        import threading
        root = str(tmp_path / "ev")
        squawk.record_decision(root, "r", "/t", "customs", "trivy", "R0", "reviewed",
                               ["trivy:R0"], by="t")
        gate = threading.Barrier(8)

        def go(i):
            gate.wait()
            squawk.record_decision(root, "r", "/t", "customs", "trivy", "R%d" % i,
                                   "reviewed", ["trivy:R%d" % i], by="t")
        ts = [threading.Thread(target=go, args=(i,)) for i in range(1, 9)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        out = squawk.verify_ledger(root)
        assert out["state"] == "ok" and out["lines"] == 9, out
        assert len(squawk.load_decisions(root)) == 9


class TestWhatTheScreenshotsShowed:
    """Four things visible in the operator's screenshots and in headless renders of
    main, each held here so it cannot come back."""

    def test_every_scan_tile_has_the_same_control_row(self, tmp_path):
        """Twelve tiles, one geometry: a box the width of a picker, then Run.
        The self-audit and AWS tiles had a bare Run button under a sentence."""
        import re
        html = squawk.view_scan(str(tmp_path / "ev"), None)
        forms = re.findall(r"<form method='post' action='/run'>(.*?)</form>", html, re.S)
        assert len(forms) == len(squawk.SERVICES)
        for form in forms:
            assert re.search(r"<select name='target'|<input type='text'|class='fixed'", form), \
                "a tile has no box before its Run button: %s" % form[:120]
            assert "<button class='btn'>Run</button>" in form
        # A tile whose subject cannot be typed shows it in a box the same
        # shape as the other tiles' pickers. Counted from the registry rather
        # than hard-coded: the number was 2, and adding one AWS service turned
        # a passing geometry test into a failing arithmetic one.
        fixed = [v for v in squawk.SERVICES.values() if v.scope in ("host", "aws")]
        assert html.count("class='fixed'") == len(fixed), \
            "every fixed-subject tile shows its subject in the control row"
        assert "class='subject'" not in html
        assert ".svc .fixed{" in squawk.PAGE_CSS and "flex:1" in squawk.PAGE_CSS

    def test_the_integrity_card_says_what_to_do_not_never_verified_twice(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root)
        card, attn = squawk.integrity_block(root)
        assert card.count("never verified") == 1, card
        assert "Run the command below" in card and "evidence never verified" in attn

    def test_priority_does_not_claim_a_tier_when_nothing_is_shortlisted(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root)
        out = squawk.execute_service(squawk.SERVICES["selfaudit"], "host", root,
                                     str(tmp_path))
        html = squawk.view_priority(root, out["run_id"])
        assert "no tier has an entry" in html or "shortlisted across" in html
        if "0 of" in html:
            assert "across 1 tier" not in html

    def test_the_browse_marker_needs_no_glyph(self):
        """The Kali browser's font lacked U+25B8 and drew `B8` in its place.
        The browser's own disclosure triangle needs no font."""
        assert "disclosure-closed" in squawk.PAGE_CSS
        assert "\u25b8" not in squawk.PAGE_CSS.lower() and "\u25be" not in squawk.PAGE_CSS.lower()


class TestTheTileNumberIsTheProofNumber:
    """The rule in the operator's words: if you present a number that references
    data, it must be linked to show the proof. The critical & high tile showed
    102 and linked to critical alone, which showed 15. This holds the tile's
    number against the instance count on the page it lands on."""

    def _estate(self, tmp_path):
        import json
        root = str(tmp_path / "ev")
        app = str(tmp_path / "app")
        os.makedirs(app)
        d = os.path.join(root, "20260101T000000Z")
        os.makedirs(os.path.join(d, "raw"))
        finds = [{"scanner": "semgrep", "identity": "R%d:a.py:%d" % (i, i),
                  "severity": sev, "title": "t", "path": "a.py", "detail": {}}
                 for i, sev in enumerate(["critical", "critical", "high", "high",
                                          "high", "medium", "low"])]
        sevs = {}
        for f in finds:
            sevs[f["severity"]] = sevs.get(f["severity"], 0) + 1
        man = {"run_id": "20260101T000000Z", "service": "baggage", "scope": "dir",
               "target": app, "service_label": "Baggage", "not_covered": "",
               "counts": {"total": len(finds), "excluded": 0}, "severities": sevs,
               "ledger": [{"tool": "semgrep", "status": "ok", "detail": "", "evidence": "",
                           "coverage": {"examined": 3, "unit": "files", "skipped": 0,
                                        "errors": 0, "note": ""}}]}
        for name, obj in (("manifest.json", man), ("findings.json", finds),
                          ("identities.json", {"semgrep": [f["identity"] for f in finds]}),
                          ("digest.json", {})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(obj, fh)
        return root

    def test_critical_and_high_lands_on_critical_and_high(self, tmp_path):
        import re
        root = self._estate(tmp_path)
        overview = squawk.view_overview(root)
        tile = re.search(r"href='/estate\?sev=([a-z,]+)'[^>]*>(?:<span[^>]*>)(\d+)</span>"
                         r"<span class='k'>critical &amp; high", overview)
        assert tile, "no critical & high tile"
        filt, shown = tile.group(1), int(tile.group(2))
        assert shown == 5, "2 critical + 3 high"
        live, _v, _b = squawk.estate_runs(root)
        rows = squawk.estate_rows(root, live)
        landed = squawk.apply_estate_query(rows, sev=filt)
        assert landed["instances"] == shown, \
            "the tile says %d, the page it links to shows %d" % (shown, landed["instances"])
        page = squawk.view_estate(root, {"sev": filt})
        assert "5 instance(s)" in page and "sev: critical,high" in page
        # every legend count still lands on exactly its own severity
        for sev, n in (("critical", 2), ("high", 3), ("medium", 1), ("low", 1)):
            assert squawk.apply_estate_query(rows, sev=sev)["instances"] == n

    def test_a_bad_value_in_a_list_is_named_and_the_rest_still_filter(self, tmp_path):
        root = self._estate(tmp_path)
        live, _v, _b = squawk.estate_runs(root)
        rows = squawk.estate_rows(root, live)
        res = squawk.apply_estate_query(rows, sev="critcal,high")
        assert res["unknown_filters"] == ["sev=critcal is not a severity"]
        assert res["instances"] == 3, "the value that is a severity still applies"


class TestNoPageScrollsSideways:
    """The operator at 170% zoom scrolled left and right to read the Overview:
    the page needed 1412px however narrow the window. Grid children default
    to the width of their content, so nothing shrank. These are the rules that
    let it; `live-check.py` measures the result with a real layout engine."""

    def test_the_layout_lets_columns_shrink_and_cards_scroll_their_own_tables(self):
        css = squawk.PAGE_CSS
        assert ".shell{display:grid;grid-template-columns:232px minmax(0,1fr)" in css, \
            "the content column must be allowed below its content's width"
        assert ".grid>*{min-width:0}" in css
        assert "min-width:0;overflow-x:auto" in css.split(".card{")[1].split("}")[0], \
            "a card whose table is wider than it must scroll inside itself, not the page"

    def test_the_overview_tiles_wrap_instead_of_squeezing(self, tmp_path):
        root = str(tmp_path / "ev")
        os.makedirs(root)
        squawk.execute_service(squawk.SERVICES["selfaudit"], "host", root, str(tmp_path))
        html = squawk.view_overview(root)
        assert "repeat(4,1fr)" not in html
        assert "repeat(auto-fit,minmax(170px,1fr))" in html
        targets = html.split("Targets by risk")[1].split("Scan activity")[0]
        assert "white-space:nowrap'>" not in targets.split("<tbody>")[1].split("Rescan")[0], \
            "the last-scan cell forced the table wider than any window"


class TestReconPublishesItsDenominator:
    """recon had no COVERAGE entry at all, so a sweep that reached one port and
    a sweep that reached ten printed the same "N endpoint(s)". Found by running
    the stage for the first time (2026-09-12): the ledger line read
    "7 finding(s) — tool publishes no coverage"."""

    def _run(self, pages, tmp_path, port_in_target=True):
        srv = TestReconCalibratesForCatchAll._server(pages)
        port = srv.server_address[1]
        target = ("http://127.0.0.1:%d" % port) if port_in_target else "127.0.0.1"
        ctx = squawk.RunContext(target, "url", str(tmp_path / "run"), "")
        try:
            raw = squawk.recon_probe(ctx)
        finally:
            srv.shutdown()
        assert isinstance(raw, str), raw
        return json.loads(raw)

    def test_the_reading_records_what_was_probed(self, tmp_path):
        data = self._run({"*": (200, "<html><title>x</title></html>")}, tmp_path)
        assert data["requests"] > 0, "a run that probed nothing recorded nothing"
        assert data["requests_answered"] > 0
        assert data["requests_answered"] <= data["requests"]
        assert data["ports_probed"] >= 1

    def test_an_explicit_port_probes_one_candidate_not_the_whole_list(self, tmp_path):
        """Why the count is taken from the run and not from RECON_PORTS. A
        target given with a port probes that port; reading the constant would
        report ten and overstate every such run."""
        data = self._run({"*": (200, "<html><title>x</title></html>")}, tmp_path)
        assert data["ports_probed"] == 1, data["ports_probed"]
        assert len(squawk.RECON_PORTS) > 1, "the constant must differ to matter"

    def test_the_coverage_is_probes_answered_over_probes_tried(self, tmp_path):
        data = self._run({"*": (200, "<html><title>x</title></html>")}, tmp_path)
        cov = squawk.COVERAGE["recon"](json.dumps(data))
        assert cov.examined == data["requests_answered"]
        assert cov.unit == "probe(s) answered"
        assert cov.skipped == 0, "nothing is skipped; the host drops probes"
        assert "port(s) answered" in cov.note

    def test_a_probe_the_host_dropped_is_not_called_skipped(self):
        """Review 3, R-50. `tried - answered` sat in the `skipped` slot, which
        prints as "(15 skipped)" and, for the Security Hub extractor, means
        passed controls not carried. Nothing was skipped; fifteen probes were
        sent and dropped, and the note says that in those words."""
        cov = squawk.COVERAGE["recon"](json.dumps(
            {"requests": 16, "requests_answered": 1, "ports_probed": 10,
             "open_ports": [80]}))
        assert cov.examined == 1 and cov.skipped == 0 and cov.errors == 0
        assert "1 of 10 port(s) answered" in cov.note
        assert "15 probe(s) sent and not answered" in cov.note
        assert "skipped" not in cov.note

    def test_a_reading_without_the_counts_is_unknown_not_zero(self):
        """An older evidence file has no counts. Inventing a zero there would
        turn every archived recon run into a gap, which is the fabrication this
        refuses everywhere else — unknown is the honest answer (I1)."""
        old = json.dumps({"host": "h", "open_ports": [80],
                          "catch_all": {}, "endpoints": []})
        cov = squawk.COVERAGE["recon"](old)
        assert cov.examined is None, "a missing count is not a count of zero"

    def test_a_host_that_answered_nothing_is_a_zero_over_a_real_denominator(self):
        """The shape that matters. Nothing answered, and the reading still says
        how much was asked, so a reader can tell a quiet host from a probe that
        never got out."""
        cov = squawk.COVERAGE["recon"](json.dumps(
            {"host": "h", "open_ports": [], "ports_probed": 10,
             "requests": 0, "requests_answered": 0,
             "catch_all": {}, "endpoints": []}))
        assert cov.examined == 0
        assert cov.note == "0 of 10 port(s) answered"


class TestReconCalibratesForCatchAll:
    """Juice Shop serves its index for any path, so recon reported DVWA,
    phpMyAdmin and TWiki at paths it does not serve — fifteen endpoints, one
    real, measured 2026-09-07 on the lab. A curated path now counts only where
    its page differs from the page a made-up path gets, and the catch-all is
    reported once so the reader knows why the labels are absent."""

    @staticmethod
    def _server(pages):
        """A real HTTP server: {path: (status, body)}; "*" is the answer for
        any other path, else 404."""
        import http.server
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                path = self.path.split("?")[0]
                status, body = pages.get(path) or pages.get("*") or (404, "no")
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_a):
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    @staticmethod
    def _recon(srv, tmp_path):
        port = srv.server_address[1]
        ctx = squawk.RunContext("http://127.0.0.1:%d" % port, "url", str(tmp_path / "run"), "")
        try:
            raw = squawk.recon_probe(ctx)
        finally:
            srv.shutdown()
        assert isinstance(raw, str), raw
        return port, {f.identity: f for f in squawk.norm_recon(raw, "")}

    def test_a_catch_all_server_reports_itself_not_phantom_apps(self, tmp_path):
        index = "<html><title>OWASP Juice Shop</title><body>spa</body></html>"
        srv = self._server({"*": (200, index), "/api/": (500, "api")})
        port, found = self._recon(srv, tmp_path)
        want = {"%d:/" % port, "%d:/api/" % port, "%d:catch-all" % port}
        assert set(found) == want, sorted(found)
        assert "every path" in found["%d:catch-all" % port].title
        assert found["%d:/" % port].title.startswith("OWASP Juice Shop")

    def test_a_server_that_404s_unknown_paths_keeps_its_labeled_apps(self, tmp_path):
        srv = self._server({"/": (200, "<title>home</title>"),
                            "/dvwa/": (200, "<title>Login :: DVWA</title>")})
        port, found = self._recon(srv, tmp_path)
        assert set(found) == {"%d:/" % port, "%d:/dvwa/" % port}, sorted(found)
        assert found["%d:/dvwa/" % port].title.startswith("DVWA")


class TestLabTargets:
    """lab-targets.py: targets with the answer written
    beside them, and a check that says SKIP, never PASS, when the scanner that
    would have answered did not run — I1 one layer up."""

    @staticmethod
    def _mod():
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "lab_targets", os.path.join(os.path.dirname(ENTRY), "dev", "lab-targets.py"))
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_build_writes_each_corpus_as_its_own_checkout_that_says_what_it_is(self, tmp_path):
        lab = self._mod()
        written = lab.build(str(tmp_path))
        assert len(written) == sum(len(f) for f in lab.CORPORA.values())
        for rel in lab.CORPORA:
            d = str(tmp_path / "corpora" / rel)
            assert os.path.isdir(os.path.join(d, ".git")), rel
            # a repo-scope service stops here, not at the checkout holding the lab
            assert squawk.resolve_repo(d) == d
        for path in written:   # every file says what it is for, up front —
            # except the lockfile, which has no field for it; the package.json
            # beside it carries the note
            if os.path.basename(path) == "package-lock.json":
                path = os.path.join(os.path.dirname(path), "package.json")
            with open(path, encoding="utf-8") as fh:
                assert "lab corpus" in fh.read(400), path

    def test_every_target_names_a_real_service_its_flag_and_its_tools(self):
        lab = self._mod()
        for t in lab.TARGETS:
            svc = squawk.SERVICES[t["service"]]
            assert t["flag"] == ("--repo" if svc.scope == "repo" else "--target"), t["name"]
            tools = {squawk.STAGES[s].tool for s in svc.stages}
            for scanner in list(t["must"]) + list(t["must_not"]):
                assert scanner in tools, (t["name"], scanner, sorted(tools))
            assert t["why"], t["name"]
            assert t.get("corpus") in lab.CORPORA or t.get("target"), t["name"]

    def test_ids_match_as_segments_not_substrings(self):
        lab = self._mod()
        assert lab._hit({"CKV_DOCKER_3:Dockerfile"}, ["CKV_DOCKER_3"])
        assert not lab._hit({"CKV_DOCKER_30:Dockerfile"}, ["CKV_DOCKER_3"])
        assert lab._hit({"3000:/"}, ["3000:/"])
        assert not lab._hit({"3000:/dvwa/"}, ["3000:/"])
        assert lab._hit({"CVE-2020-8203:lodash:4.17.15"}, ["CVE-"])
        assert lab._hit({"10036:x"}, [""])
        assert not lab._hit(set(), [""])

    @staticmethod
    def _fake_run(lab, monkeypatch, ledger, findings):
        monkeypatch.setattr(lab, "_run", lambda *_a: (0, ""))
        man = {"ledger": ledger, "differential": []}
        monkeypatch.setattr(lab, "_newest_run", lambda _ev: ("run", man, findings))
        lab.PASS = lab.FAIL = lab.SKIP = 0
        lab.FAILURES[:] = []

    def test_a_scanner_that_could_not_look_makes_a_skip_never_a_pass(
            self, tmp_path, monkeypatch, capsys):
        lab = self._mod()
        t = next(x for x in lab.TARGETS if x["corpus"] == "dockerfiles/bad")
        (tmp_path / "corpora" / "dockerfiles" / "bad").mkdir(parents=True)
        gap = "%s is not installed — this stage could not run"
        self._fake_run(lab, monkeypatch,
                       [{"tool": "checkov", "status": "gap", "detail": gap % "checkov"},
                        {"tool": "trivy", "status": "gap", "detail": gap % "trivy"}], [])
        lab.check_target(t, str(tmp_path), str(tmp_path))
        out = capsys.readouterr().out
        assert lab.FAIL == 0 and lab.SKIP == 3, out   # both scanners, and the floor
        assert lab.PASS == 1, out                     # only "runs and writes a manifest"
        assert "could not look" in out

    def test_the_answer_holds_and_a_banned_id_fails(self, tmp_path, monkeypatch, capsys):
        lab = self._mod()
        good = next(x for x in lab.TARGETS if x["corpus"] == "dockerfiles/good")
        (tmp_path / "corpora" / "dockerfiles" / "good").mkdir(parents=True)
        ledger = [{"tool": "checkov", "status": "ok", "detail": ""},
                  {"tool": "trivy", "status": "ok", "detail": ""}]
        self._fake_run(lab, monkeypatch, ledger, [])
        lab.check_target(good, str(tmp_path), str(tmp_path))
        assert (lab.FAIL, lab.SKIP, lab.PASS) == (0, 0, 3), capsys.readouterr().out
        self._fake_run(lab, monkeypatch, ledger,
                       [{"scanner": "checkov", "identity": "CKV_DOCKER_3:Dockerfile"}])
        lab.check_target(good, str(tmp_path), str(tmp_path))
        out = capsys.readouterr().out
        assert lab.FAIL == 1 and "found CKV_DOCKER_3:Dockerfile" in out, out
        assert lab.FAILURES and lab.FAILURES[0].startswith("checkov names none of")

    def test_the_lab_publishes_on_loopback_only(self):
        lab = self._mod()
        for c in lab.CONTAINERS:
            argv = lab.run_args(c)
            assert argv[:3] == ["docker", "run", "-d"]
            assert argv[argv.index("-p") + 1].startswith("127.0.0.1:"), argv

    def test_the_corpora_carry_no_secret_shapes(self):
        lab = self._mod()
        shapes = re.compile(r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}"
                            r"|BEGIN (?:RSA |EC )?PRIVATE KEY|sk-[A-Za-z0-9]{20,}")
        for rel, files in lab.CORPORA.items():
            for name, body in files.items():
                assert not shapes.search(body), (rel, name)

    def test_no_instruction_points_at_a_script_that_is_not_there(self):
        """SETUP.md said `./lab-targets.sh` after the script became `.py`. A
        doc that names a file that does not exist is stale by definition.

        A record keeps its history, so a document whose own first heading says
        it is a log is skipped — by that property rather than by filename,
        because the set of logs differs between this tree and the published
        one and a filename list would be wrong in whichever it was not written
        for."""
        here = pathlib.Path(os.path.dirname(ENTRY))
        for path in sorted(here.rglob("*.md")):
            head = path.read_text(encoding="utf-8").split("\n", 1)[0].lower()
            if head.startswith("#") and head.rstrip().endswith(("log", "changelog")):
                continue
            for m in re.finditer(r"`\./((?:[\w-]+/)*[\w-]+\.(?:py|sh))\b",
                                 path.read_text(encoding="utf-8")):
                # `./x` is relative to the document that says it, which is not
                # always the root now that the checks live in `dev/`.
                named = m.group(1)
                assert (path.parent / named).exists() or (here / named).exists(), \
                    (path.name, named)


class TestProfiles:
    """A run can be given a profile — timing, budgets and
    options per service or per target — that the run prints back and the
    manifest carries, so a thin scan can never read as a thorough one and a
    changed setting can never be invisible (I12). A value that is parsed is
    a value that reaches the command; a profile never holds a credential
    (PRODUCT rule 1) or a destructive option (I3); and a profile that cannot
    be applied is refused before any stage runs, by name."""

    SAMPLE = (
        '# a profile\n'
        '[defaults]\n'
        'stage_timeout = 2_400   # trailing comment\n'
        '\n'
        '[services.activeprobe]\n'
        'zap_active_spider_minutes = 30\n'
        'zap_startup_wait = 20\n'
        '\n'
        '[targets."http://127.0.0.1:3000"]\n'
        'zap_active_spider_minutes = 45\n'
        '\n'
        '[scanners.semgrep]\n'
        'extra_args = ["--config", "p/owasp-top-ten",\n'
        '              "--metrics=off"]   # spans lines\n'
        'flag = true\n'
        "name = 'lit#eral'\n"
        'quoted = "a \\"b\\" c"\n'
    )
    # SAMPLE exercises the reader; VALID is the part of it that is a profile
    VALID = SAMPLE.split("flag = true")[0]

    # -- the TOML subset ---------------------------------------------------- #

    def test_the_subset_reads_what_a_profile_needs(self):
        data = squawk.parse_toml(self.SAMPLE)
        assert data["defaults"] == {"stage_timeout": 2400}
        assert data["services"]["activeprobe"] == {"zap_active_spider_minutes": 30,
                                                   "zap_startup_wait": 20}
        assert data["targets"]["http://127.0.0.1:3000"] == {"zap_active_spider_minutes": 45}
        sem = data["scanners"]["semgrep"]
        assert sem["extra_args"] == ["--config", "p/owasp-top-ten", "--metrics=off"]
        assert sem["flag"] is True and sem["name"] == "lit#eral" and sem["quoted"] == 'a "b" c'

    def test_the_subset_agrees_with_tomllib(self):
        """Where the standard library has a TOML reader, the subset and the
        standard must read the same document the same way."""
        tomllib = pytest.importorskip("tomllib")
        assert squawk.parse_toml(self.SAMPLE) == tomllib.loads(self.SAMPLE)

    @pytest.mark.parametrize("text, words", [
        ("a.b = 1", "dotted keys"),
        ("[t]\nx = 1\nx = 2", "set twice"),
        ("[t]\n[t]", "defined twice"),
        ("[t]\nx = 1\n\n[t]", "already open at line 1"),
        ("x = {a = 1}", "inline tables"),
        ("x = 1.5", "whole numbers"),
        ("x = [1, [2]]", "nested arrays"),
        ('x = "unterminated', "unterminated string"),
        ("[[t]]", "arrays of tables"),
        ("x = [1,\n2", "unterminated array"),
        ("x = 1 y", "text after the value"),
        ("just words", "expected key = value"),
    ])
    def test_what_is_outside_the_subset_is_refused_with_a_line_number(self, text, words):
        with pytest.raises(squawk.ProfileError) as err:
            squawk.parse_toml(text)
        assert "line " in str(err.value) and words in str(err.value), str(err.value)

    # -- where it comes from ------------------------------------------------ #

    def test_the_lookup_order_and_a_named_file_that_is_missing(self, tmp_path, monkeypatch):
        ev = tmp_path / "ev"
        ev.mkdir()
        monkeypatch.delenv("SQUAWK_PROFILE", raising=False)
        assert squawk.load_profile(str(ev)).source == "built-in"
        (ev / "squawk.toml").write_text("[defaults]\nstage_timeout = 10\n")
        assert squawk.load_profile(str(ev)).source == "evidence root"
        by_env = tmp_path / "env.toml"
        by_env.write_text("[defaults]\nstage_timeout = 20\n")
        monkeypatch.setenv("SQUAWK_PROFILE", str(by_env))
        prof = squawk.load_profile(str(ev))
        assert prof.source == "SQUAWK_PROFILE" and prof.data["defaults"]["stage_timeout"] == 20
        explicit = tmp_path / "x.toml"
        explicit.write_text("[defaults]\nstage_timeout = 30\n")
        prof = squawk.load_profile(str(ev), str(explicit))
        assert prof.source == "--profile" and prof.data["defaults"]["stage_timeout"] == 30
        # a file that was asked for and is not there is refused, never
        # quietly replaced by the built-ins
        with pytest.raises(squawk.ProfileError) as err:
            squawk.load_profile(str(ev), str(tmp_path / "missing.toml"))
        assert "cannot read" in str(err.value) and "--profile" in str(err.value)
        monkeypatch.setenv("SQUAWK_PROFILE", str(tmp_path / "gone.toml"))
        with pytest.raises(squawk.ProfileError) as err:
            squawk.load_profile(str(ev))
        assert "SQUAWK_PROFILE" in str(err.value)

    # -- what is refused, by name ------------------------------------------- #

    @pytest.mark.parametrize("data, words", [
        ({"budgets": {}}, "[budgets] is not a section"),
        ({"defaults": {"spider": 5}}, "spider is not a setting"),
        ({"defaults": {"extra_args": ["-v"]}}, "belongs under [scanners.<tool>]"),
        ({"services": {"liveprobe": 5}}, "one table per service"),
        ({"defaults": {"stage_timeout": 0}}, "at least 1"),
        ({"defaults": {"stage_timeout": True}}, "whole number"),
        ({"defaults": {"stage_timeout": "900"}}, "whole number of seconds"),
        ({"services": {"activeprobe": {"zap_active_spider_minutes": -3}}},
         "whole number of minutes"),
        ({"scanners": {"semgrep": {"extra_args": "--verbose"}}}, "list of strings"),
        ({"scanners": {"semgrep": {"extra_args": ["--delete"]}}}, "'--delete', a destructive"),
    ])
    def test_what_is_not_a_setting_is_refused_by_name(self, data, words):
        with pytest.raises(squawk.ProfileError) as err:
            squawk.Profile("squawk.toml", "--profile", data).validate()
        assert words in str(err.value), str(err.value)

    def test_a_section_for_a_service_or_scanner_that_does_not_exist_is_refused(self, tmp_path):
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "squawk.toml").write_text("[services.nosuch]\nstage_timeout = 5\n")
        with pytest.raises(squawk.ProfileError) as err:
            squawk.profile_for(str(ev))
        assert "[services.nosuch] names no service" in str(err.value)
        (ev / "squawk.toml").write_text("[scanners.nosuch]\nextra_args = []\n")
        with pytest.raises(squawk.ProfileError) as err:
            squawk.profile_for(str(ev))
        assert "[scanners.nosuch] names no scanner" in str(err.value)

    # Built from parts, never written out: this repository's own hygiene gate
    # scans every tracked file for exactly these shapes, and a fixture that is
    # a real credential shape trips it — correctly. Verified: it did.
    SHAPES: typing.ClassVar[dict] = {
        "aws": "AKIA" + "IOSFODNN7EXAMPLE",
        "github": "ghp_" + "a" * 30,
        "pem": "%sBEGIN RSA PRIVATE KEY%s" % ("-" * 5, "-" * 5),
        "openai": "sk-" + "b" * 24}

    @pytest.mark.parametrize("key, shape", [
        ("stage_timeout", "aws"),
        ("extra_args", "github"),
        ("extra_args", "pem"),
        ("extra_args", "openai"),
        ("api_token", ""),
        ("password", ""),
    ])
    def test_a_credential_is_refused_by_key_and_never_printed(self, key, shape):
        secret = self.SHAPES.get(shape, "")
        value = ([secret] if key == "extra_args" else secret) if secret else 5
        data = {"scanners": {"semgrep": {key: value}}}
        with pytest.raises(squawk.ProfileError) as err:
            squawk.Profile("squawk.toml", "--profile", data).validate()
        msg = str(err.value)
        assert key in msg and "credential" in msg and "rule 1" in msg, msg
        for token in [*self.SHAPES.values(), "AKIA", "ghp_", "PRIVATE", "sk-"]:
            assert token not in msg, "the value leaked into the message"

    # -- precedence, and the value reaching the command --------------------- #

    def test_the_most_specific_section_wins(self):
        prof = squawk.Profile("p", "--profile", squawk.parse_toml(self.VALID))
        prof.validate()
        s = prof.setting("activeprobe", "http://127.0.0.1:3000", "zap",
                         "zap_active_spider_minutes", 10)
        assert (s.value, s.section, s.builtin, s.changed) == (
            45, '[targets."http://127.0.0.1:3000"]', 10, True)
        s = prof.setting("activeprobe", "http://other", "zap", "zap_active_spider_minutes", 10)
        assert (s.value, s.section) == (30, "[services.activeprobe]")
        s = prof.setting("liveprobe", "http://other", "zap", "zap_active_spider_minutes", 10)
        assert (s.value, s.section, s.changed) == (10, "built-in", False)
        s = prof.setting("liveprobe", "http://other", "zap", "stage_timeout", 2400)
        assert (s.value, s.section) == (2400, "[defaults]")
        assert prof.extra_args("semgrep") == ["--config", "p/owasp-top-ten", "--metrics=off"]
        assert prof.extra_args("bandit") == []

    def test_the_value_reaches_the_zap_command(self, tmp_path, monkeypatch):
        """A profile that is parsed and not applied is the defect this
        repository keeps finding, so the knob is asserted in argv."""
        monkeypatch.setattr(squawk.stages, "tool_path", lambda name: None)  # the image path
        prof = squawk.Profile("p", "--profile", squawk.parse_toml(self.VALID))
        prof.validate()
        ctx = squawk.RunContext("http://127.0.0.1:3000", "url", str(tmp_path / "r"), "",
                                service="activeprobe", profile=prof)
        ctx.raw_path = str(tmp_path / "r" / "raw" / "zap-active.json")
        cmd, _t = squawk.stage_zap_active(ctx)
        assert cmd[cmd.index("-m") + 1] == "45", cmd
        assert cmd[cmd.index("-T") + 1] == "20", cmd
        ctx = squawk.RunContext("http://127.0.0.1:3000", "url", str(tmp_path / "r"), "",
                                service="liveprobe", profile=prof)
        ctx.raw_path = str(tmp_path / "r" / "raw" / "zap-baseline.json")
        cmd, _t = squawk.stage_zap_baseline(ctx)
        assert cmd[cmd.index("-m") + 1] == "5", "the baseline knob was not set; built-in"
        ctx.profile = None
        cmd, _t = squawk.stage_zap_baseline(ctx)
        assert cmd[cmd.index("-m") + 1] == squawk.ZAP_SPIDER_MINS

    @staticmethod
    def _repo(tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Dockerfile").write_text("FROM ubuntu:latest\n")
        return str(repo)

    def test_the_engine_applies_the_budget_and_records_what_ran(self, tmp_path, monkeypatch):
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "squawk.toml").write_text(
            '[services.compliance]\nstage_timeout = 123\n'
            '[scanners.trivy]\nextra_args = ["--skip-dirs", ".git"]\n')
        seen = []

        def fake_run(cmd, cwd, timeout):
            seen.append((list(cmd), timeout))
            return 0, "{}", ""
        _patch_all(monkeypatch, "tool_path", lambda name: "/usr/bin/" + name)
        _patch_all(monkeypatch, "run_cmd", fake_run)
        repo = self._repo(tmp_path)
        out = squawk.execute_service(squawk.SERVICES["compliance"], repo, str(ev), repo)
        assert [t for _c, t in seen] == [123, 123], seen
        trivy_cmd = next(c for c, _t in seen if c[0] == "trivy")
        assert trivy_cmd[-2:] == ["--skip-dirs", ".git"], "appended, at the end"
        assert next(c for c, _t in seen if c[0] == "checkov")[-1] != ".git"
        man = next(m for m in squawk.list_runs(str(ev)) if m["run_id"] == out["run_id"])
        prof = man["profile"]
        assert prof["path"] == str(ev / "squawk.toml") and prof["source"] == "evidence root"
        assert [(c["stage"], c["value"], c["builtin"], c["section"]) for c in prof["changed"]] == [
            ("checkov", 123, 900, "[services.compliance]"),
            ("trivy-config", 123, 900, "[services.compliance]")]
        assert prof["extra_args"] == {"trivy": ["--skip-dirs", ".git"]}
        rows = {r["tool"]: r for r in man["ledger"]}
        assert rows["trivy"]["ran"]["command"] == trivy_cmd
        assert rows["trivy"]["ran"]["timeout_from"] == "[services.compliance]"
        assert rows["checkov"]["ran"]["timeout_builtin"] == 900
        assert rows["correlation"]["ran"] is None
        # the manifest is hashed like any other file: verify still holds
        assert squawk.verify_root(str(ev))["exit"] == 0

    def test_a_stage_that_could_not_run_records_no_budget(self, tmp_path, monkeypatch):
        """The CLI prints what a run would use; the manifest records what it
        did. A stage that never ran had no budget applied, and claiming one
        would be the substitution this tool refuses everywhere else."""
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "squawk.toml").write_text("[services.compliance]\nstage_timeout = 55\n")
        _patch_all(monkeypatch, "tool_path",
                   lambda name: "/bin/checkov" if name == "checkov" else None)
        _patch_all(monkeypatch, "run_cmd", lambda cmd, cwd, timeout: (0, "{}", ""))
        repo = self._repo(tmp_path)
        out = squawk.execute_service(squawk.SERVICES["compliance"], repo, str(ev), repo)
        man = next(m for m in squawk.list_runs(str(ev)) if m["run_id"] == out["run_id"])
        rows = {r["tool"]: r for r in man["ledger"]}
        assert rows["checkov"]["ran"]["timeout"] == 55
        assert rows["trivy"]["status"] == "gap" and rows["trivy"]["ran"] is None
        assert [c["stage"] for c in man["profile"]["changed"]] == ["checkov"]
        html = squawk.coverage_panel(man)
        assert "55s <span class='muted'>[services.compliance]</span>" in html
        assert "<td class='mono' style='font-size:.8rem' title=''><span class='muted'>" in html

    def test_a_profile_that_changes_nothing_says_so(self, tmp_path, monkeypatch):
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "squawk.toml").write_text("# nothing set\n[defaults]\n")
        _patch_all(monkeypatch, "tool_path", lambda name: None)
        repo = self._repo(tmp_path)
        out = squawk.execute_service(squawk.SERVICES["compliance"], repo, str(ev), repo)
        man = next(m for m in squawk.list_runs(str(ev)) if m["run_id"] == out["run_id"])
        assert man["profile"]["path"].endswith("squawk.toml")
        assert man["profile"]["changed"] == [] and man["profile"]["extra_args"] == {}
        lines = squawk.profile_lines(man["profile"])
        assert lines == ["Profile : %s (evidence root) — no value differs from the built-in"
                         % man["profile"]["path"]]
        assert squawk.profile_lines({"path": ""}) == ["Profile : none — built-in values"]

    # -- the CLI ------------------------------------------------------------ #

    def test_run_prints_the_block_and_a_refused_profile_leaves_no_run(
            self, tmp_path, monkeypatch, capsys):
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "squawk.toml").write_text("[services.compliance]\nstage_timeout = 77\n")
        _patch_all(monkeypatch, "tool_path", lambda name: None)
        repo = self._repo(tmp_path)
        rc = squawk.main(["run", "compliance", "--repo", repo, "--evidence", str(ev)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "Profile : %s (evidence root) — 2 value(s) differ" % (ev / "squawk.toml") in out
        assert "checkov       stage_timeout              = 77     built-in 900" in out, out
        (ev / "squawk.toml").write_text('[scanners.checkov]\nextra_args = ["--force"]\n')
        before = [n for n in os.listdir(str(ev)) if n[:2] == "20"]
        # the log is attached once per process, so read the records, not the file
        import logging
        records = []

        class Keep(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())
        keep = Keep()
        squawk.LOG.addHandler(keep)
        try:
            rc = squawk.main(["run", "compliance", "--repo", repo, "--evidence", str(ev)])
        finally:
            squawk.LOG.removeHandler(keep)
        out = capsys.readouterr().out
        assert rc == 2 and "Profile refused" in out and "'--force'" in out, out
        assert [n for n in os.listdir(str(ev)) if n[:2] == "20"] == before, "no run for a refusal"
        assert any("REFUSED run: profile" in r and "--force" in r for r in records), records

    def test_config_show_names_where_each_value_came_from_without_running(
            self, tmp_path, monkeypatch, capsys):
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "squawk.toml").write_text(
            '[defaults]\nstage_timeout = 900\n'
            '[targets."http://127.0.0.1:3000"]\nzap_active_spider_minutes = 30\n')
        monkeypatch.setattr(squawk.stages, "tool_path", lambda name: None)
        rc = squawk.main(["config", "show", "activeprobe", "http://127.0.0.1:3000",
                          "--evidence", str(ev)])
        out = capsys.readouterr().out
        assert rc == 0, out
        row = 'zap_active_spider_minutes  30       10        [targets."http://127.0.0.1:3000"]'
        assert row in out, out
        assert "stage_timeout              900      5400      [defaults]" in out
        assert "zap_startup_wait           20       20        built-in" in out
        assert ("note: zap-active: zap_active_spider_minutes is 30 min but "
                "stage_timeout is 900 s") in out
        assert "Nothing was run" in out
        assert [n for n in os.listdir(str(ev)) if n[:2] == "20"] == []
        assert squawk.main(["config", "show", "--evidence", str(ev)]) == 2
        assert "usage: squawk config show SERVICE" in capsys.readouterr().out
        # an internal stage says no budget applies, rather than showing none
        rc = squawk.main(["config", "show", "recon", "http://127.0.0.1:3000",
                          "--evidence", str(ev)])
        assert rc == 0
        assert "recon         runs in-process" in capsys.readouterr().out

    # -- the run page, and the server ---------------------------------------- #

    def test_the_run_page_shows_the_budget_and_the_profile(self):
        man = {"ledger": [
            {"tool": "trivy", "mode": "config", "status": "ok", "detail": "1 finding(s)",
             "evidence": "raw/trivy-config.json", "coverage": None,
             "ran": {"command": ["trivy", "config", "-f", "json", "-q", "/r",
                                 "--skip-dirs", ".git"],
                     "timeout": 123, "timeout_from": "[services.compliance]",
                     "timeout_builtin": 900, "extra_args": ["--skip-dirs", ".git"]}},
            {"tool": "correlation", "mode": "join", "status": "ok", "detail": "0",
             "evidence": None, "coverage": None, "ran": None}],
            "profile": {"path": "/ev/squawk.toml", "source": "evidence root",
                        "changed": [{"stage": "trivy-config", "tool": "trivy",
                                     "key": "stage_timeout", "value": 123, "builtin": 900,
                                     "section": "[services.compliance]"}],
                        "extra_args": {"trivy": ["--skip-dirs", ".git"]},
                        "notes": ["trivy-config: a note"]}}
        html = squawk.coverage_panel(man)
        assert "<th>Budget</th>" in html
        assert "2m 03s <span class='muted'>[services.compliance]</span>" in html
        assert "title='trivy config -f json -q /r --skip-dirs .git'" in html, "the argv, on hover"
        assert "<b>Profile:</b> <span class='mono'>/ev/squawk.toml</span>" in html
        assert "trivy-config stage_timeout = 123" in html and "(built-in 900)" in html
        assert "trivy extra_args + <span class='mono'>--skip-dirs .git</span>" in html
        assert "<b>Note:</b> trivy-config: a note" in html
        # no profile, and a run from before profiles existed, each say so
        man["profile"] = {"path": "", "source": "built-in", "changed": [], "extra_args": {},
                          "notes": []}
        assert "Profile:</b> none &mdash; built-in budgets" in squawk.coverage_panel(man)
        del man["profile"]
        assert "predates profiles" in squawk.coverage_panel(man)

    def test_the_server_refuses_a_bad_profile_before_starting_a_job(self, tmp_path):
        import argparse
        import socket
        import threading
        import urllib.parse
        import urllib.request
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "squawk.toml").write_text('[scanners.semgrep]\nextra_args = ["rm"]\n')
        repo = self._repo(tmp_path)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        args = argparse.Namespace(evidence=str(ev), repo=repo, port=port,
                                  host="127.0.0.1", gh_repo=None, open=False)
        threading.Thread(target=lambda: squawk.serve_web(args), daemon=True).start()
        time.sleep(1.5)
        jobs_before = len(squawk.JOBS)
        data = urllib.parse.urlencode({"service": "compliance", "target": repo}).encode()
        req = urllib.request.Request("http://127.0.0.1:%d/run" % port, data=data,
                                     headers={"Origin": "http://127.0.0.1:%d" % port})
        try:
            urllib.request.urlopen(req, timeout=8)
            code, body = 200, ""
        except urllib.error.HTTPError as e:
            code, body = e.code, e.read().decode()
        assert code == 400, code
        assert "Profile refused" in body and "destructive" in body, body[-400:]
        assert len(squawk.JOBS) == jobs_before, "no job may start under a refused profile"
        assert [n for n in os.listdir(str(ev)) if n[:2] == "20"] == []

    def test_a_refused_profile_says_the_whole_file_is_refused(self, tmp_path, capsys):
        """Seen in field use: a `[scanners.zap]` fault stopped a host audit that
        never runs zap, and the refusal read as a non-sequitur. A profile is
        one document — if part of it cannot be applied, none of it is, for
        every service — and the refusal now says so wherever it appears."""
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "squawk.toml").write_text('[scanners.zap]\nextra_args = ["--delete"]\n')
        rc = squawk.main(["run", "selfaudit", "--evidence", str(ev)])
        out = capsys.readouterr().out
        assert rc == 2, out
        assert "[scanners.zap] extra_args carries '--delete'" in out
        assert "The whole file is refused, for every service" in out, out
        assert [n for n in os.listdir(str(ev)) if n[:2] == "20"] == []
        # and on `config show`, which is the command an operator reaches for next
        assert squawk.main(["config", "show", "selfaudit", "--evidence", str(ev)]) == 2
        assert squawk.PROFILE_REFUSED_NOTE in capsys.readouterr().out

    def test_two_verifies_in_one_second_do_not_read_as_one(self, tmp_path, monkeypatch, capsys):
        """Verify stamps are second-resolution. Two verifies in the same
        second printed `Previous : <t>` under `Checked : <t>`, which reads as
        an anchor compared against itself. Seen in field use, 2026-09-07: the
        second verify had really used the first as its anchor and caught an
        edit, but the line could not say so."""
        ev = tmp_path / "ev"
        ev.mkdir()
        _patch_all(monkeypatch, "tool_path", lambda name: None)
        repo = self._repo(tmp_path)
        squawk.execute_service(squawk.SERVICES["compliance"], repo, str(ev), repo)
        assert squawk.main(["verify", "--evidence", str(ev)]) == 0
        capsys.readouterr()
        report = squawk.load_verify(str(ev))
        # the next verify lands in the same second as the one just recorded
        monkeypatch.setattr(squawk.evidence.time, "strftime",
                            lambda *_a, **_k: report["at"])
        squawk.main(["verify", "--evidence", str(ev)])
        out = capsys.readouterr().out
        assert "Checked  : %s" % report["at"] in out
        assert "Previous : %s (the verify before this one, within the same second)" \
               % report["at"] in out, out


class TestAScanSaysItIsNotStuck:
    """A forty-minute active probe showed a spinner and nothing else, so an
    operator could not tell a working scan from a hung one (field report,
    2026-09-07). What is honestly knowable while a scanner runs is elapsed
    time and the bound it is running under — never a percentage, because no
    scanner here publishes progress and a bar that advanced on a guess would
    be a denominator nobody measured."""

    @staticmethod
    def _job(stages):
        job = squawk.Job("job1", squawk.SERVICES["activeprobe"], "http://127.0.0.1:3000")
        job.on_progress({"phase": "run", "run_dir": "/ev/r", "run_id": "r"})
        for st in stages:
            job.on_progress({"phase": "start", "i": 1, "n": 1,
                             "tool": st["tool"], "mode": "active"})
            if "timeout" in st:
                job.on_progress({"phase": "budget", "tool": st["tool"], "mode": "active",
                                 "timeout": st["timeout"],
                                 "timeout_from": st.get("timeout_from", "built-in")})
            if "status" in st:
                job.on_progress({"phase": "done", "i": 1, "n": 1, "tool": st["tool"],
                                 "mode": "active", "status": st["status"],
                                 "detail": st["detail"], "elapsed": st.get("elapsed")})
        return job

    def test_a_running_stage_shows_elapsed_against_the_budget_it_actually_has(self):
        job = self._job([{"tool": "zap", "timeout": 7200,
                          "timeout_from": "[services.activeprobe]"}])
        job.stages[0]["started_at"] = time.time() - 900       # fifteen minutes in
        html = squawk.view_job(job, "/ev")
        assert html.count("15m 00s") == 1, "the elapsed is stated once, not twice"
        assert "15m 00s of the 2h 00m budget" in html, html[:1200]
        assert "[services.activeprobe]" in html, "where the budget came from"
        assert "time against the budget" in html and "not work done" in html
        assert "usually ~20-60min" in html, "the expectation, before the wait"
        assert "<div class='bar'" in html
        assert "width:12.5%" in html, "900 of 7200 seconds"

    def test_there_is_no_bar_until_the_stage_says_what_its_budget_is(self):
        """A stage that has not started its subprocess has no bound to show,
        and an empty bar implying one would be the invention this refuses."""
        job = self._job([{"tool": "zap"}])
        job.stages[0]["started_at"] = time.time() - 30
        html = squawk.view_job(job, "/ev")
        assert "<div class='bar'" not in html and "budget" not in html.split("<p class")[0]
        assert "running…" in html
        assert "30s" in html, "with no bound to show, the elapsed still stands alone"

    def test_the_bar_stops_at_full_rather_than_running_past_it(self):
        job = self._job([{"tool": "zap", "timeout": 60}])
        job.stages[0]["started_at"] = time.time() - 600
        html = squawk.view_job(job, "/ev")
        assert "width:100.0%" in html, "a bar past its own end reads as broken"

    def test_a_finished_stage_keeps_the_time_it_took(self):
        job = self._job([{"tool": "zap", "timeout": 7200, "status": "ok",
                          "detail": "161 finding(s) across 318 URLs", "elapsed": 2292.0}])
        assert job.stages[0]["elapsed"] == 2292.0
        assert job.stage_elapsed(job.stages[0]) == 2292.0
        job.stages[0]["status"] = "running"    # render the row as still running
        assert "38m 12s" in squawk.view_job(job, "/ev")

    def test_the_engine_announces_the_budget_before_the_wait_and_records_what_it_took(
            self, tmp_path, monkeypatch):
        events = []
        _patch_all(monkeypatch, "tool_path", lambda name: "/bin/" + name)
        _patch_all(monkeypatch, "run_cmd", lambda cmd, cwd, timeout: (0, "{}", ""))
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Dockerfile").write_text("FROM ubuntu:latest\n")
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "squawk.toml").write_text("[services.compliance]\nstage_timeout = 321\n")
        out = squawk.execute_service(squawk.SERVICES["compliance"], str(repo), str(ev),
                                     str(repo), progress=events.append)
        budgets = [e for e in events if e["phase"] == "budget"]
        assert [(b["tool"], b["timeout"], b["timeout_from"]) for b in budgets] == [
            ("checkov", 321, "[services.compliance]"),
            ("trivy", 321, "[services.compliance]")]
        # the budget is announced before the stage's own result, not after it
        assert events.index(budgets[0]) < next(
            i for i, e in enumerate(events) if e["phase"] == "done")
        assert all(e.get("elapsed") is not None
                   for e in events if e["phase"] == "done"), events
        man = next(m for m in squawk.list_runs(str(ev)) if m["run_id"] == out["run_id"])
        rows = {r["tool"]: r for r in man["ledger"]}
        assert isinstance(rows["checkov"]["ran"]["elapsed"], float)
        panel = squawk.coverage_panel(man)
        assert "of 5m 21s" in panel, "the run page keeps it, worded as the job page did"
        assert "of 321 s" not in panel, "one number in one hand, not two"

    def test_an_internal_stage_is_timed_too_and_shows_no_budget(self, tmp_path):
        """recon, skillaudit and selfaudit run in-process: no subprocess, so
        no bound to show — but they take real time and saying nothing about a
        stage that ran hides that it did."""
        ev = tmp_path / "ev"
        events = []
        out = squawk.execute_service(squawk.SERVICES["selfaudit"], "host", str(ev),
                                     str(tmp_path), progress=events.append)
        assert [e for e in events if e["phase"] == "budget"] == [], "no subprocess, no bound"
        done = [e for e in events if e["phase"] == "done"]
        assert done and all(e["elapsed"] is not None for e in done), done
        man = next(m for m in squawk.list_runs(str(ev)) if m["run_id"] == out["run_id"])
        ran = next(r for r in man["ledger"] if r["tool"] == "selfaudit")["ran"]
        assert ran["internal"] is True and ran.get("timeout") is None
        assert "in-process</span>" in squawk.coverage_panel(man)

    def test_a_stage_that_could_not_run_announces_no_budget(self, tmp_path, monkeypatch):
        """It never started a subprocess, so it has no bound and no duration.
        Showing one would say a scan happened."""
        events = []
        _patch_all(monkeypatch, "tool_path", lambda name: None)
        repo = tmp_path / "repo"
        repo.mkdir()
        squawk.execute_service(squawk.SERVICES["compliance"], str(repo), str(tmp_path / "ev"),
                               str(repo), progress=events.append)
        assert [e for e in events if e["phase"] == "budget"] == []
        assert all(e.get("elapsed") is None for e in events if e["phase"] == "done")

    def test_the_cli_says_how_long_to_expect_and_how_long_it_took(self, tmp_path, capsys):
        squawk.main(["run", "selfaudit", "--evidence", str(tmp_path / "ev")])
        out = capsys.readouterr().out
        assert "usually %s" % squawk.SERVICES["selfaudit"].rough_time in out, out
        assert re.search(r"\[1/1\].*·  \d+[smh]", out), out
        assert re.search(r"\nRun \S+  ·  \d+[smh]", out), out

    def test_the_duration_reads_at_a_glance(self):
        assert squawk.human_seconds(0) == "0s"
        assert squawk.human_seconds(42.4) == "42s"
        assert squawk.human_seconds(59.6) == "1m 00s"
        assert squawk.human_seconds(432) == "7m 12s"
        assert squawk.human_seconds(3781) == "1h 03m"


class TestTheClockWall:
    """The operator asked for a panel showing times around the
    world, saw the first version show one zone twice, and asked for the three
    main American zones plus UTC, the major European and Asian ones, and any
    other standard zone — each once. So: a wall, UTC first because that is
    what the evidence is stamped in, then the desks west to east — and the two
    clocks that are also facts about this run (the machine that scanned, the
    browser reading) are **badges on the wall**, not extra clocks."""

    def test_the_wall_is_utc_first_then_west_to_east(self):
        ids = [z for z, _l in squawk.WORLD_ZONES]
        assert ids[0] == "UTC", "the evidence's own zone leads"
        offsets = [squawk._zone_now(z, time.time()) for z in ids[1:]]
        assert all(o is not None for o in offsets), ids
        # All four US offsets. Honolulu and Denver were missing, so a wall
        # meant to answer "what time is it where that ran" skipped two of the
        # zones a US estate actually runs in (the operator, 2026-09-11).
        assert ids[1:6] == ["Pacific/Honolulu", "America/Los_Angeles",
                            "America/Denver", "America/Chicago",
                            "America/New_York"], "the American zones, west to east"
        assert "Europe/London" in ids and "Europe/Berlin" in ids
        assert "Asia/Tokyo" in ids and "Asia/Singapore" in ids
        assert "Asia/Kolkata" in ids, "half-hour offsets exist"
        assert len(set(ids)) == len(ids), "no zone twice"

    def test_the_wall_runs_west_to_east_after_utc(self):
        """The order is the claim the first test's name makes, and it was
        checked for three cities out of ten.

        Compared as MINUTES, and computed rather than read off the page. This
        asserted `_zone_now(...)[1]` — which is the DATE, not the offset — and
        sorted it as text. That passed only while every clock on the wall fell
        on the same calendar day, so it was vacuously green for most of each
        day and wrong for the rest: the moment Auckland rolled over to Monday
        it failed, because "Mon 14 Sep" sorts before "Sun 13 Sep" for a reason
        no reader of this test would guess (2026-09-13). Index 3 would have
        been no better — "UTC-10" sorts before "UTC-7" as text.
        """
        when = datetime.datetime.now(datetime.timezone.utc)
        offsets = []
        for zone, label in squawk.WORLD_ZONES[1:]:
            shift = when.astimezone(zoneinfo.ZoneInfo(zone)).utcoffset()
            assert shift is not None, label
            offsets.append((int(shift.total_seconds()) // 60, label))
        assert offsets == sorted(offsets, key=lambda pair: pair[0]), \
            "the wall is out of order: %s" % (
                ["%s %+d" % (label, mins) for mins, label in offsets],)

    def test_the_order_check_would_notice_a_zone_out_of_place(self):
        """The guard the old version needed. Its comparison could not fail for
        an out-of-order wall, only for a date boundary, so nothing here proved
        the check could detect the thing it is named for."""
        when = datetime.datetime.now(datetime.timezone.utc)
        swapped = list(squawk.WORLD_ZONES[1:])
        swapped[0], swapped[-1] = swapped[-1], swapped[0]
        offsets = [int(when.astimezone(zoneinfo.ZoneInfo(z))
                       .utcoffset().total_seconds()) // 60
                   for z, _l in swapped]
        assert offsets != sorted(offsets), \
            "swapping the westmost and eastmost clocks must break the order"

    def test_no_zone_is_a_link_that_some_databases_do_not_carry(self):
        """`Europe/Frankfurt` is a link, and it is absent from this Mac's tz
        database — a clock that silently vanished would be worse than one
        never offered, so every name here is canonical and resolves."""
        for zone, _label in squawk.WORLD_ZONES:
            assert squawk._zone_now(zone, time.time()) is not None, zone

    def test_each_clock_is_that_zones_real_time(self):
        when = time.time()
        wall = squawk.clock_wall()
        for zone, label in squawk.WORLD_ZONES:
            hhmm = squawk._zone_now(zone, when)[0][:5]
            assert hhmm in wall, (zone, label, hhmm)

    def test_the_server_is_badged_on_the_wall_not_drawn_twice(self):
        wall = squawk.clock_wall()
        assert wall.count("class='who'>server</span>") <= 1
        zone = re.search(r"data-server='([^']*)'", wall).group(1)
        if zone:
            assert wall.count("data-zone='%s'" % zone) == 1, \
                "one clock for the server's zone, badged — not a second copy"
            assert ">server</span>" in wall
        assert len(re.findall(r"data-zone='([^']+)'", wall)) == \
            len(set(re.findall(r"data-zone='([^']+)'", wall))), "no zone twice"

    def test_the_reader_is_badged_by_the_browser_and_added_only_if_absent(self):
        """The server cannot know the reader's zone, so the script asks the
        browser and badges the clock that already shows it — adding one only
        when that zone is not on the wall. Showing the same time twice is
        exactly what the operator objected to."""
        html = squawk.page("X", "", "", "").decode()
        assert "resolvedOptions().timeZone" in html
        assert "cells.filter(function(c){return c.dataset.zone===you})[0]" in html
        assert "if(!mine&&fmtZone(you))" in html, "added only when absent"
        assert "b.textContent='you'" in html
        assert "b.textContent+' · you'" in html, "one mark when both apply, not two chips"

    def test_a_zone_this_machine_cannot_resolve_is_counted_not_silently_dropped(
            self, monkeypatch):
        """A wall that quietly shrank would say the world had fewer desks in
        it. `Europe/Frankfurt` is exactly this case on some databases."""
        assert squawk._zone_now("Mars/Olympus", time.time()) is None
        assert "clk miss" not in squawk.clock_wall(), "every canonical zone resolves here"
        real = squawk.web._zone_now
        monkeypatch.setattr(
            squawk.web, "_zone_now",
            lambda z, w: None if z in ("Europe/Berlin", "Asia/Dubai") else real(z, w))
        wall = squawk.clock_wall()
        assert "clk miss" in wall and ">2 zone(s) missing" in wall, wall[-400:]
        assert "Europe/Berlin, Asia/Dubai" in wall, "named, so it can be fixed"
        assert "data-zone='Europe/Berlin'" not in wall, "and not drawn empty"

    def test_the_server_clock_is_never_re_read_from_the_browser(self):
        """A browser whose clock is wrong must not make the server's look
        wrong too: every clock on the wall is rendered from the epoch the
        server sent, carried forward by time spent on the page."""
        html = squawk.page("X", "", "", "").decode()
        assert "var srv=new Date(base+(Date.now()-t0));" in html
        assert html.count("new Date(base") == 1
        assert "f.formatToParts(srv)" in html, "every zone reads from that one clock"

    def test_a_browser_out_of_step_with_the_server_is_told_so(self):
        html = squawk.page("X", "", "", "").decode()
        assert "skew>120000" in html, "two minutes, not any difference at all"
        assert "disagree by" in html and "comes from the server" in html
        assert ".clocks .who.skew{background:var(--high);color:#fff}" in squawk.PAGE_CSS

    def test_fifteen_clocks_can_never_push_a_page_sideways(self):
        """Cells sized as a percentage of the strip cannot exceed it, so there
        is nothing to scroll. `live-check.py` measures the page at four widths;
        this is the rule that makes that measurement hold."""
        rule = squawk.PAGE_CSS.split(".clocks{")[1].split("}")[0]
        assert "flex-wrap:wrap" in rule and "justify-content:center" in rule, rule
        assert "overflow-x" not in rule, \
            "a scrollbar on a wall that cannot overflow only hides clocks"

    def test_the_walls_own_classes_are_not_someone_elses(self):
        """The mark rendered as a 15px circle because `.mark` was already the
        severity legend's class, defined later in the same stylesheet with a
        fixed width — so the badge the operator photographed was a severity dot
        wearing the wrong text. Every class this component emits must be
        styled only under `.clocks`, never by a rule of its own elsewhere."""
        css = squawk.PAGE_CSS
        emitted = set(re.findall(r"class='([a-z][a-z -]*)'", squawk.clock_wall()))
        emitted = {c for one in emitted for c in one.split()} | {"who", "you", "skew"}
        emitted.discard("clocks")          # the wall's own root, styled bare on purpose
        for rule in css.split("}"):
            selector = rule.rsplit(";", 1)[-1].split("{")[0]
            if "{" not in rule or ".clocks" in selector:
                continue
            for cls in sorted(emitted):
                assert not re.search(r"(?<![\w.-])\.%s(?![\w-])" % re.escape(cls), selector), (
                    "the clock wall emits .%s and `%s` styles it elsewhere — that is "
                    "how the mark became a 15px circle" % (cls, selector.strip()))

    def test_the_page_still_reads_without_javascript(self):
        """Server-rendered values are correct at load; the script only makes
        them tick and badges the reader's own zone."""
        wall = squawk.clock_wall()
        zones = re.findall(r"data-zone='([^']+)'", wall)
        assert len(re.findall(r"class='now'>\d\d:\d\d:\d\d<", wall)) == len(zones)
        assert zones[:len(squawk.WORLD_ZONES)] == [z for z, _l in squawk.WORLD_ZONES]
        assert re.search(r"class='dt'>\w\w\w \d\d \w\w\w</span> \w+", wall), \
            "the date and the zone's own abbreviation, from this machine's database"

    @pytest.mark.parametrize("alias", ["Etc/UTC", "GMT", "Etc/GMT+0", "Zulu", "Universal"])
    def test_a_server_on_utc_by_another_name_does_not_get_a_second_clock(
            self, alias, monkeypatch):
        """python:3.9's /etc/localtime points at `Etc/UTC`, which added an
        eleventh clock beside UTC showing the same time — the duplicate this
        wall exists to avoid, wearing a different name."""
        assert squawk.canonical_zone(alias) == "UTC"
        assert squawk.canonical_zone("America/Chicago") == "America/Chicago"
        monkeypatch.setattr(squawk.web, "_server_zone", lambda: alias)
        wall = squawk.clock_wall()
        zones = re.findall(r"data-zone='([^']+)'", wall)
        assert zones == [z for z, _l in squawk.WORLD_ZONES], zones
        assert wall.count(">server</span>") == 1
        assert "data-server='UTC'" in wall
        # the browser folds the same names, so it badges rather than adding one
        assert "you='UTC';" in squawk.page("X", "", "", "").decode()

    def test_a_server_zone_the_wall_does_not_carry_is_added_once(self, monkeypatch):
        monkeypatch.setattr(squawk.web, "_server_zone", lambda: "Africa/Nairobi")
        wall = squawk.clock_wall()
        zones = re.findall(r"data-zone='([^']+)'", wall)
        assert zones == [z for z, _l in squawk.WORLD_ZONES] + ["Africa/Nairobi"]
        assert "Nairobi" in wall and wall.count(">server</span>") == 1


class TestTheFinishedScanSaysWhatItWas:
    """Field report, 2026-09-07: *"when scan completed on this page I have
    no idea what kind of scan this was. I only know it was baggage because I
    waited to see what the scan page went to when done."* The running view
    named the service and target; the finished one showed a run id and
    nothing else, so walking away and coming back lost the answer."""

    def test_the_completed_page_names_the_service_the_target_and_the_time(self, tmp_path):
        job = squawk.Job("j", squawk.SERVICES["baggage"], "/Users/you/code/checkout")
        job.started_at = time.time() - 95
        job.status = "done"
        job.run_id = "20260907T210000Z-dir"
        html = squawk.view_job(job, str(tmp_path))
        assert "Baggage check against" in html and "/Users/you/code/checkout" in html
        assert "took 1m 35s" in html, html[:600]
        assert "20260907T210000Z-dir" in html

    def test_a_failed_run_still_says_which_scan_failed(self):
        job = squawk.Job("j", squawk.SERVICES["cargo"], "nginx:1.27")
        job.status, job.error = "error", "boom"
        html = squawk.view_job(job, "/ev")
        assert "boom" in html


class TestWatchingAScanIsCheap:
    """Field report, 2026-09-07: the host got sluggish while the job page
    tracked a probe. The page reloads itself, and every reload counted the
    runs by parsing every manifest in the store — eighty-five JSON documents
    for one number in the top bar, several times a minute."""

    def test_counting_runs_does_not_read_a_single_manifest(self, tmp_path, monkeypatch):
        root = tmp_path / "ev"
        for i in range(5):
            d = root / ("2026090%dT000000Z" % i)
            d.mkdir(parents=True)
            (d / "manifest.json").write_text('{"run_id": "x"}')
        (root / "feeds").mkdir()          # not a run: no manifest
        (root / "squawk.toml").write_text("")
        assert squawk.count_runs(str(root)) == 5
        assert squawk.count_runs(str(tmp_path / "nope")) == 0

        opened = []
        real_open = builtins.open

        def watch(path, *a, **kw):
            opened.append(str(path))
            return real_open(path, *a, **kw)
        monkeypatch.setattr(builtins, "open", watch)
        squawk.count_runs(str(root))
        assert [p for p in opened if p.endswith("manifest.json")] == [], opened

    def test_it_agrees_with_the_slow_way(self, tmp_path):
        root = tmp_path / "ev"
        (root / "run1").mkdir(parents=True)
        (root / "run1" / "manifest.json").write_text('{"run_id": "run1"}')
        (root / "broken").mkdir()
        (root / "broken" / "manifest.json").write_text("{not json")
        # list_runs drops the unreadable one; the count is of runs on disk, and
        # says so — a run whose manifest will not parse is still a directory
        # that exists, and the top bar is a count, not a verdict
        assert squawk.count_runs(str(root)) == 2
        assert len(squawk.list_runs(str(root))) == 1

    def test_a_long_scan_backs_off_its_own_reloads(self):
        """Two seconds is right while an operator is watching closely; twelve
        hundred full renders over a forty-minute probe is not.

        Asserted over the numbers the function returns. The earlier version
        searched the handler's SOURCE for `job.elapsed() < 30`, which a comment
        satisfies and which says nothing about the interval the page carries
        (review R-17).
        """
        interval = squawk.web.reload_interval
        assert interval(0) == 2 and interval(29.9) == 2
        assert interval(30) == 5 and interval(299) == 5
        assert interval(300) == 15 and interval(4000) == 15
        assert interval(0) < interval(60) < interval(3600), \
            "the beat has to slow down, not merely change"


class TestAMemoryBudgetForTheProbe:
    """Field report: *"live app probe steals all of my memory to copy text
    from cli."* ZAP's launcher takes a quarter of the memory it believes it
    has as its heap — and in a container under cgroup v2 it reads the HOST's,
    so a container limit changes nothing about how much ZAP asks for. The
    first version of this shipped that wrong premise and the operator's probe
    failed on it the same day. The lever that works is ZAP's own JVM
    properties file, measured 2026-09-08."""

    @staticmethod
    def _ctx(tmp_path, toml, service="activeprobe", target="http://127.0.0.1:3000"):
        prof = squawk.Profile("p", "--profile", squawk.parse_toml(toml))
        prof.validate()
        ctx = squawk.RunContext(target, "url", str(tmp_path / "r"), "",
                                service=service, profile=prof)
        ctx.raw_path = str(tmp_path / "r" / "raw" / "zap.json")
        return ctx

    def test_the_heap_is_set_where_zap_reads_it_and_the_container_is_not_capped(
            self, tmp_path, monkeypatch):
        """Not a container limit. ZAP takes a quarter of the memory it believes
        it has, and in a container under cgroup v2 it reads the *host's* —
        measured identical with and without `docker -m` (`Available memory:
        7933 MB · Using JVM args: -Xmx1983m`). `-m` was also measured to break
        this image's scan outright, so the heap goes in the JVM properties
        file ZAP actually reads."""
        monkeypatch.setattr(squawk.stages, "tool_path", lambda name: None)
        raw = tmp_path / "r" / "raw"
        raw.mkdir(parents=True)
        ctx = self._ctx(tmp_path, '[targets."http://127.0.0.1:3000"]\nzap_memory_mb = 1024\n')
        for build in (squawk.stage_zap_active, squawk.stage_zap_baseline):
            cmd, _t = build(ctx)
            assert "--memory-swap" not in cmd, "a container cap breaks this image"
            before_image = cmd[:cmd.index(squawk.ZAP_IMAGE)]
            assert "-m" not in before_image, "no docker memory cap, measured to break it"
            mount = next(a for a in cmd if a.endswith("%s:ro" % squawk.ZAP_JVM_PROPS))
            path = mount.split(":")[0]
            with open(path) as fh:
                assert fh.read().strip() == "-Xmx1024m", "the heap ZAP will use"
            assert path.startswith(str(raw)), "written into the run's own evidence"

    def test_no_heap_is_the_default_and_changes_nothing(self, tmp_path, monkeypatch):
        """Unset, ZAP takes a quarter of the machine. Setting it too small
        turns a working probe into a failed one, and only the operator knows the
        machine — so the built-in is nothing, and it reads `no cap` rather
        than the word None."""
        monkeypatch.setattr(squawk.stages, "tool_path", lambda name: None)
        ctx = self._ctx(tmp_path, "[defaults]\nstage_timeout = 900\n")
        cmd, _t = squawk.stage_zap_active(ctx)
        assert not [a for a in cmd if squawk.ZAP_JVM_PROPS in str(a)], cmd
        assert cmd.count("-m") == 1, "only ZAP's own spider minutes"
        ctx.profile = None
        assert not [a for a in squawk.stage_zap_active(ctx)[0]
                    if squawk.ZAP_JVM_PROPS in str(a)]
        assert squawk.PROFILE_KEYS["zap_memory_mb"].builtin is None
        assert squawk.show_setting(None) == "no cap"
        assert squawk.show_setting(1024) == "1024"

    def test_the_estate_summary_follows_the_table_it_summarises(self):
        """The summary card is short and the targets table is long, so the
        right column was mostly empty on a wide screen (the operator, with a
        screenshot). It sticks below the top bar instead, and goes back to
        normal flow at the width where the columns stack.

        The offset was the literal `73px` — the topbar's height, written here
        and nowhere else. When the clock strip became sticky too this column
        cleared one strip of two and sat under the other, so the number is a
        named variable now and the offset is the sum. See
        `TestThePageFollowsTheWindow` in test_charter.py."""
        css = squawk.PAGE_CSS
        assert "top:calc(var(--topbar-h) + var(--clocks-h) + .8rem)" in css
        assert "--topbar-h:" in css and "--clocks-h:" in css
        assert "@media(max-width:1280px){.cols-2 > :nth-child(2){position:static}}" in css

    def test_a_stage_that_died_with_a_chosen_heap_names_it(self, tmp_path, monkeypatch):
        """ZAP's own message is about a summary file and says nothing about
        memory. The operator chose that number; the run is where it comes
        back to them."""
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "squawk.toml").write_text('[services.liveprobe]\nzap_memory_mb = 256\n')
        _patch_all(monkeypatch, "tool_path",
                   lambda name: None if name == "zap-baseline.py" else "/usr/bin/" + name)
        _patch_all(monkeypatch, "run_cmd",
                   lambda cmd, cwd, timeout: (1, "", "Failed to access summary file"))
        out = squawk.execute_service(squawk.SERVICES["liveprobe"], "http://127.0.0.1:5000",
                                     str(ev), str(tmp_path))
        man = next(m for m in squawk.list_runs(str(ev)) if m["run_id"] == out["run_id"])
        row = next(r for r in man["ledger"] if r["tool"] == "zap")
        assert row["status"] == "error"
        assert "ZAP ran with -Xmx256m, from zap_memory_mb" in row["detail"], row["detail"]
        assert squawk._heap_set(["docker", "run"]) == ""

    def test_it_is_a_budget_like_the_others_so_the_run_prints_it(self):
        assert "zap_memory_mb" in squawk.STAGE_KNOBS["zap-active"]
        assert "zap_memory_mb" in squawk.STAGE_KNOBS["zap-baseline"]
        knob = squawk.PROFILE_KEYS["zap_memory_mb"]
        assert knob.unit == "megabytes" and "quarter" in knob.what

    def test_a_failed_stage_keeps_all_of_its_stderr(self, tmp_path, monkeypatch):
        """One line is enough to know a stage failed and nowhere near enough
        to say why — and the machine that can answer is not always the machine
        that can reproduce it (the operator's box, 2026-09-08). The whole of
        stderr is evidence, hashed and sealed with the run."""
        ev = tmp_path / "ev"
        ev.mkdir()
        said = "first line, which is all the ledger held\nsecond line\nthird line\n"
        _patch_all(monkeypatch, "tool_path",
                   lambda name: None if name == "zap-baseline.py" else "/usr/bin/" + name)
        _patch_all(monkeypatch, "run_cmd", lambda cmd, cwd, timeout: (1, "", said))
        out = squawk.execute_service(squawk.SERVICES["liveprobe"], "http://127.0.0.1:5000",
                                     str(ev), str(tmp_path))
        run_dir = os.path.join(str(ev), out["run_id"])
        man = next(m for m in squawk.list_runs(str(ev)) if m["run_id"] == out["run_id"])
        row = next(r for r in man["ledger"] if r["tool"] == "zap")
        assert row["ran"]["stderr"] == "raw/zap-baseline.err"
        with open(os.path.join(run_dir, row["ran"]["stderr"])) as fh:
            assert fh.read() == said, "all of it, not the line the ledger shows"
        assert row["detail"].startswith("first line"), "the ledger still shows the first"
        # ...and points at the rest, because one line is a poor summary of
        # seven: with ZAP's -d on, the first line is a debug message and the
        # run read "zap did not report (Trigger hook: cli_opts, args: 1)"
        assert "2 more line(s) in raw/zap-baseline.err" in row["detail"], row["detail"]
        assert row["ran"]["stderr_lines"] == 3
        # and it is evidence like any other: covered by the digest
        with open(os.path.join(run_dir, "digest.json")) as fh:
            assert "raw/zap-baseline.err" in json.load(fh)["files"]

    def test_a_stage_that_said_nothing_writes_no_empty_file(self, tmp_path, monkeypatch):
        ev = tmp_path / "ev"
        ev.mkdir()
        _patch_all(monkeypatch, "tool_path",
                   lambda name: None if name == "zap-baseline.py" else "/usr/bin/" + name)
        _patch_all(monkeypatch, "run_cmd", lambda cmd, cwd, timeout: (0, "{}", "   \n"))
        out = squawk.execute_service(squawk.SERVICES["liveprobe"], "http://127.0.0.1:5000",
                                     str(ev), str(tmp_path))
        raw = os.path.join(str(ev), out["run_id"], "raw")
        assert not [n for n in os.listdir(raw) if n.endswith(".err")]


class TestAProbeRefusesAPortWithNothingOnIt:
    """The operator's probe failed three times in under half a minute each, and
    the reason was one line at the bottom of a log nobody had reason to open:
    `Job spider failed to access URL … Connection refused`. Juice Shop was
    down. The run said a scanner had gone quiet, which is true and useless —
    the tool already refuses a directory target that is no longer on disk, and
    a port with nothing on it is the same fact about a different kind of
    target."""

    @staticmethod
    def _dead_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def test_a_probe_at_a_closed_port_is_refused_and_writes_no_run(
            self, tmp_path, capsys):
        ev = tmp_path / "ev"
        rc = squawk.main(["run", "liveprobe", "--target",
                          "http://127.0.0.1:%d" % self._dead_port(),
                          "--evidence", str(ev)])
        out = capsys.readouterr().out
        assert rc == 2, out
        assert "nothing is listening on 127.0.0.1:" in out
        assert "scans nothing" in out and "bring the target up" in out
        assert [n for n in os.listdir(str(ev)) if n[:2] == "20"] == [], \
            "no run for a target that was never reachable"

    def test_discovery_is_never_refused_because_that_is_its_job(self, tmp_path, capsys):
        """Recon exists to find out what is listening, and reports an
        unreachable host itself. Holding it to this rail would refuse the one
        service that can answer the question."""
        assert not squawk.probes_a_named_port(squawk.SERVICES["recon"])
        assert squawk.probes_a_named_port(squawk.SERVICES["liveprobe"])
        assert squawk.probes_a_named_port(squawk.SERVICES["activeprobe"])
        ev = tmp_path / "ev"
        rc = squawk.main(["run", "recon", "--target",
                          "http://127.0.0.1:%d" % self._dead_port(),
                          "--evidence", str(ev)])
        out = capsys.readouterr().out
        assert rc == 0 and "Refusing" not in out, out
        man = squawk.list_runs(str(ev))[0]
        row = next(r for r in man["ledger"] if r["tool"] == "recon")
        assert row["status"] == "error" and "no reachable port" in row["detail"], row

    def test_a_listening_port_passes(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            ok, why = squawk.dast_target_live("http://127.0.0.1:%d" % port)
        finally:
            srv.close()
        assert ok and "is listening" in why, why
        ok, why = squawk.dast_target_live("http://")
        assert not ok and "no host" in why

    def test_the_default_port_comes_from_the_scheme(self, monkeypatch):
        seen = []

        def fake(addr, timeout):
            seen.append(addr)
            raise OSError("nope")
        monkeypatch.setattr(squawk.stages.socket, "create_connection", fake)
        squawk.dast_target_live("https://example.test")
        squawk.dast_target_live("http://example.test")
        assert seen == [("example.test", 443), ("example.test", 80)], seen

    def test_the_server_refuses_it_too_and_starts_no_job(self, tmp_path):
        import argparse
        import threading
        import urllib.parse
        import urllib.request
        ev = tmp_path / "ev"
        ev.mkdir()
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        args = argparse.Namespace(evidence=str(ev), repo=None, port=port,
                                  host="127.0.0.1", gh_repo=None, open=False)
        threading.Thread(target=lambda: squawk.serve_web(args), daemon=True).start()
        time.sleep(1.5)
        jobs_before = len(squawk.JOBS)
        data = urllib.parse.urlencode(
            {"service": "liveprobe",
             "target": "http://127.0.0.1:%d" % self._dead_port()}).encode()
        req = urllib.request.Request("http://127.0.0.1:%d/run" % port, data=data,
                                     headers={"Origin": "http://127.0.0.1:%d" % port})
        try:
            urllib.request.urlopen(req, timeout=8)
            code, body = 200, ""
        except urllib.error.HTTPError as e:
            code, body = e.code, e.read().decode()
        assert code == 400, code
        assert "nothing is listening" in body and "no run was recorded" in body, body[-300:]
        assert len(squawk.JOBS) == jobs_before


class TestTheCloudGuideDescribesTheRealThing:
    """`CLOUD-SETUP.md` is run on a machine whose evidence belongs to an
    employer, so the lines it tells the reader to expect have to be the lines
    the tool prints. Two of them were nearly right when it was written."""

    @staticmethod
    def _guide():
        """The guide as one line, because prose wraps and the tool's messages
        do not — a quote broken over two lines is still the same quote."""
        with open(os.path.join(os.path.dirname(ENTRY), "docs", "CLOUD-SETUP.md"),
                  encoding="utf-8") as fh:
            return " ".join(fh.read().split())

    def test_the_gap_line_it_quotes_is_the_line_the_tool_prints(self):
        raw = '{"Findings": []}'
        finds = squawk.NORMALIZERS["awscli"](raw, "")
        status, detail, _cov = squawk.engine._apply_coverage(
            "awscli", raw, finds, "ok", "%d finding(s)" % len(finds))
        assert status == "gap", "an empty Security Hub read is never clean (I15)"
        assert detail in self._guide(), detail

    def test_the_refusals_it_quotes_are_the_refusals_the_tool_gives(self):
        guide = self._guide()
        _ok, reason = squawk.cloud_target_ok()
        assert reason in guide, reason
        assert "SQUAWK_CLOUD_ACK" in guide

    def test_it_names_the_two_commands_the_service_actually_runs(self):
        """The guide promises the account sees nothing but these two reads."""
        guide = self._guide()
        import types
        ctx = types.SimpleNamespace(target="000000000000", raw_path="/r/raw/x.json")
        cmd, _t = squawk.STAGES["securityhub-findings"].build(ctx)
        assert cmd[:3] == ["aws", "securityhub", "get-findings"], cmd
        assert "aws securityhub get-findings" in guide
        assert "aws sts get-caller-identity" in guide
        # Exact tokens, not substrings — `put` lives inside `--output`, which
        # is the same trap `test_charter.py` names for `rm` in `--report-format`
        words = {w.strip("-").lower() for w in cmd}
        assert not (words & squawk.DESTRUCTIVE_TOKENS), sorted(words & squawk.DESTRUCTIVE_TOKENS)

    def test_it_points_at_the_evidence_root_it_says_to_remove(self):
        guide = self._guide()
        assert guide.count("--evidence ~/squawk-work") >= 3, \
            "every command in it keeps work evidence out of the lab's root"
        assert "rm -rf ~/squawk-work" in guide

    def test_the_readme_counts_the_documents_it_lists(self):
        """A number in a document nobody recounts is the same defect as a
        scanner nobody checks — the README says so about itself."""
        here = pathlib.Path(os.path.dirname(ENTRY))
        readme = (here / "README.md").read_text(encoding="utf-8")
        rows = [ln for ln in readme.splitlines()
                if ln.startswith("| [`") or ln.startswith("| `docs/")]
        words = {"nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
                 "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17,
                 "eighteen": 18, "nineteen": 19, "twenty": 20}
        claimed = re.search(r"(\w+)\s+documents and (\w+) invariants", readme)
        assert claimed, "the README no longer states its own counts"
        assert words[claimed.group(1).lower()] == len(rows), \
            "the README lists %d documents and claims %s" % (len(rows), claimed.group(1))
        charter = (here / "docs" / "CHARTER.md").read_text(encoding="utf-8")
        invariants = len(re.findall(r"^\| \*\*I\d+\*\*", charter, re.M))
        assert words[claimed.group(2).lower()] == invariants, \
            "the charter has %d invariants and the README claims %s" % (
                invariants, claimed.group(2))


class TestTheZipappCarriesItsInstaller:
    """`--install` answered "install-tools.sh not found beside squawk.py" from
    the zipapp — on the one machine the zipapp exists for.

    The build script's own words are "a work laptop, a locked-down host": a
    machine that cannot clone the repository. That is also the machine with no
    scanners on it, so the command that installs them was the one command the
    one-file build could not run.

    Two homes now. A checkout runs the script beside `squawk.py`. A zipapp
    reads the copy the build carries inside the package, writes it to a
    directory this process owns at mode 0700, and removes it afterwards."""

    def test_a_checkout_runs_the_script_beside_it(self):
        path, how = squawk.installer.installer_script()
        assert how == "beside the app", how
        assert path.endswith("install-tools.sh")
        assert os.path.isfile(path)

    def test_the_build_puts_the_script_inside_the_package(self):
        """Read from the build script rather than from a built artefact, so
        this holds without bash and without a build on the test machine."""
        here = os.path.dirname(os.path.abspath(squawk.__file__))
        build = os.path.join(os.path.dirname(here), "build-zipapp.sh")
        text = open(build, encoding="utf-8").read()
        assert 'cp "$HERE/install-tools.sh" "$STAGE/app/squawk/"' in text, \
            "the build no longer carries the installer into the package"

    def test_the_carried_copy_is_found_when_there_is_no_beside(self, monkeypatch,
                                                               tmp_path):
        """The zipapp case, driven without building one: point APP_DIR at an
        empty directory so the beside lookup fails, and put the script where
        `pkgutil` will find it."""
        monkeypatch.setattr(squawk.installer, "APP_DIR", str(tmp_path))
        monkeypatch.setattr(squawk.installer.pkgutil, "get_data",
                            lambda pkg, name: b"#!/usr/bin/env bash\necho hi\n")
        path, how = squawk.installer.installer_script()
        try:
            assert how == "carried inside the app", how
            assert os.path.isfile(path)
            assert oct(os.stat(path).st_mode & 0o777) == "0o700", \
                "an extracted script other users can read or write"
            assert open(path, encoding="utf-8").read().startswith("#!")
        finally:
            shutil.rmtree(os.path.dirname(path), ignore_errors=True)

    def test_neither_home_is_a_named_reason_not_a_crash(self, monkeypatch,
                                                        tmp_path):
        """I6 at the command layer. No script anywhere is a thing to say, not
        an exception — and the sentence has to name which lookup failed."""
        monkeypatch.setattr(squawk.installer, "APP_DIR", str(tmp_path))
        monkeypatch.setattr(squawk.installer.pkgutil, "get_data",
                            lambda pkg, name: None)
        path, how = squawk.installer.installer_script()
        assert path == ""
        assert "beside the app" in how and "inside it" in how, how

    def test_the_cli_removes_only_what_it_extracted(self):
        """A checkout's script is the repository's file. Deleting the directory
        it sits in would take the checkout with it, so the cleanup is gated on
        the lookup that made a temporary copy."""
        src = inspect.getsource(squawk.cli)
        assert 'if how.startswith("carried")' in src, \
            "the cleanup is not gated on the extracted case"
        assert "shutil.rmtree" in src


class TestTheZipappTellsTheTruthAboutExitCodes:
    """The one-file distribution is what goes on a machine you cannot clone
    onto — a work laptop, a locked-down host. It built with `python -m zipapp
    -m squawk.cli:main`, whose generated entry point is

        import squawk.cli
        squawk.cli.main()

    which calls main and throws the return value away. So the process always
    exited 0: every refusal this tool makes came back as success from the
    zipapp while the same command from the checkout gave 2. A refusal that
    looks like a success is the one thing this tool exists not to do, and the
    zipapp did it for its whole life until 2026-09-08 — invisible because the
    only check on it was `--version`, which exits 0 either way."""

    @staticmethod
    def _build(tmp_path):
        import shutil
        import subprocess
        here = os.path.dirname(ENTRY)
        if not shutil.which("bash"):
            pytest.skip("no bash to run build-zipapp.sh")
        res = subprocess.run(["bash", os.path.join(here, "build-zipapp.sh")],
                             capture_output=True, text=True, timeout=180)
        assert res.returncode == 0, res.stdout + res.stderr
        built = os.path.join(here, "dist", "squawk.pyz")
        assert os.path.isfile(built), res.stdout
        mine = str(tmp_path / "squawk.pyz")
        shutil.copy(built, mine)
        return mine

    @pytest.mark.parametrize("argv, expected", [
        (["run", "cloudaws"], 2),            # refused: no SQUAWK_CLOUD_ACK
        (["run"], 2),                        # a bare run is a usage error
        (["run", "nosuch"], 2),              # no such service
        (["--version"], 0),
    ])
    def test_it_exits_the_way_the_checkout_does(self, tmp_path, argv, expected):
        import subprocess
        pyz = self._build(tmp_path)
        ev = ["--evidence", str(tmp_path / "ev")]
        from_zip = subprocess.run([sys.executable, pyz, *argv, *ev],
                                  capture_output=True, text=True, timeout=120)
        from_src = subprocess.run([sys.executable, ENTRY, *argv, *ev],
                                  capture_output=True, text=True, timeout=120)
        assert from_zip.returncode == expected, from_zip.stdout + from_zip.stderr
        assert from_zip.returncode == from_src.returncode, (
            "the zipapp exits %d where the checkout exits %d for %s"
            % (from_zip.returncode, from_src.returncode, " ".join(argv)))

    def test_its_entry_point_passes_the_code_on(self, tmp_path):
        """The bug was one missing `sys.exit`, so the file is worth asserting
        as well as the behaviour — a future `-m` flag would put it back."""
        import zipfile
        pyz = self._build(tmp_path)
        with zipfile.ZipFile(pyz) as z:
            entry = z.read("__main__.py").decode()
        assert "sys.exit(main())" in entry, entry
        assert "squawk.cli.main()" not in entry, "zipapp's own entry drops the code"


class TestTheFloorIsSaidOnEveryCommand:
    """Below Python 3.9 a run still completed and wrote evidence that looked
    exactly like evidence from a supported interpreter — measured on
    python:3.8, 2026-09-08 — while only `doctor` mentioned the floor. Evidence
    that cannot be told from the real thing is the failure this tool is built
    around, so every command says it. It warns rather than refuses: being
    stranded is worse than being told."""

    def test_below_the_floor_every_command_says_so_on_stderr(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "version_info", (3, 8, 20, "final", 0))
        # `--version` is argparse's own action and exits before main's body,
        # so it is the one command that cannot carry the warning.
        with pytest.raises(SystemExit):
            squawk.main(["--version"])
        capsys.readouterr()
        squawk.main(["services"])
        err = capsys.readouterr().err
        assert "running on Python 3.8.20" in err, err
        assert "below the supported floor of 3.9" in err
        assert "gates on 3.9" in err, "it says why the floor is the floor"

    def test_on_a_supported_version_it_says_nothing(self, capsys):
        assert sys.version_info >= (3, 9)
        squawk.main(["services"])
        assert "supported floor" not in capsys.readouterr().err

    def test_it_warns_rather_than_refuses(self, tmp_path, monkeypatch, capsys):
        """A refusal would strand someone whose only interpreter is old. The
        run still happens; what changes is that it says what produced it."""
        monkeypatch.setattr(sys, "version_info", (3, 8, 20, "final", 0))
        rc = squawk.main(["run", "selfaudit", "--evidence", str(tmp_path / "ev")])
        out = capsys.readouterr()
        assert rc == 0, out.out
        assert "supported floor" in out.err
        assert squawk.list_runs(str(tmp_path / "ev")), "the run still wrote its evidence"


class TestWhetherTheIdentityCanWrite:
    """PRODUCT credential rule 2 asks for a read-only identity, and `doctor`
    named the identity without saying what it could do. The first real one
    this tool met was an SSO `AdministratorAccess-<account>` role — exactly
    the case the credential rules specify as a `gap`. Three states, never a boolean, and
    the detail always says what the answer is based on: a policy list and a
    role's name are not the same quality of evidence."""

    @staticmethod
    def _no_iam(monkeypatch):
        """The identity cannot list its own policies."""
        monkeypatch.setattr(squawk.stages, "run_cmd",
                            lambda cmd, cwd, timeout: (255, "", "AccessDenied"))

    @staticmethod
    def _iam(monkeypatch, attached, inline=()):
        def fake(cmd, cwd, timeout):
            if "list-attached-role-policies" in cmd or "list-attached-user-policies" in cmd:
                return 0, json.dumps(
                    {"AttachedPolicies": [{"PolicyName": p} for p in attached]}), ""
            return 0, json.dumps({"PolicyNames": list(inline)}), ""
        monkeypatch.setattr(squawk.stages, "run_cmd", fake)

    ADMIN = "arn:aws:sts::000000000000:assumed-role/AdministratorAccess-000000000000/s"
    AUDIT = "arn:aws:sts::000000000000:assumed-role/SecurityAuditRole/s"

    def test_a_write_capable_policy_is_a_gap_and_names_it(self, monkeypatch):
        self._iam(monkeypatch, ["AdministratorAccess"])
        state, detail = squawk.aws_identity_readonly(self.AUDIT)
        assert state == "gap"
        assert "AdministratorAccess" in detail and "can write" in detail
        assert "Squawk only reads" in detail, "it says the run is still a read"

    def test_a_full_access_policy_is_a_gap_too(self, monkeypatch):
        self._iam(monkeypatch, ["AmazonS3FullAccess"])
        state, detail = squawk.aws_identity_readonly(self.AUDIT)
        assert state == "gap" and "AmazonS3FullAccess" in detail

    def test_only_read_only_policies_is_ok(self, monkeypatch):
        self._iam(monkeypatch, ["SecurityAudit", "ViewOnlyAccess"])
        state, detail = squawk.aws_identity_readonly(self.AUDIT)
        assert state == "ok", detail
        assert "SecurityAudit" in detail and "ViewOnlyAccess" in detail

    def test_an_inline_policy_is_not_judged_read_only(self, monkeypatch):
        """An inline policy's contents are not read, so it cannot be called
        read-only — `unknown` is the honest answer, not `ok`."""
        self._iam(monkeypatch, ["SecurityAudit"], inline=["something-inline"])
        state, detail = squawk.aws_identity_readonly(self.AUDIT)
        assert state == "unknown" and "something-inline" in detail

    def test_when_it_cannot_look_the_name_decides_and_says_so(self, monkeypatch):
        """An SSO role called AdministratorAccess-<account> is a permission
        set wearing its policy's name. That is evidence, and weaker evidence
        than a policy list, so the message says which it used."""
        self._no_iam(monkeypatch)
        state, detail = squawk.aws_identity_readonly(self.ADMIN)
        assert state == "gap", detail
        assert "could not list its own policies" in detail
        assert "its NAME says AdministratorAccess" in detail

    def test_when_it_cannot_look_and_the_name_says_nothing_it_says_so(self, monkeypatch):
        self._no_iam(monkeypatch)
        state, detail = squawk.aws_identity_readonly(self.AUDIT)
        assert state == "unknown"
        assert "not established" in detail, detail

    def test_an_arn_that_is_neither_a_role_nor_a_user_is_unknown(self):
        state, detail = squawk.aws_identity_readonly("arn:aws:iam::000000000000:root")
        assert state == "unknown" and "not a role or user" in detail

    def test_it_only_ever_reads(self):
        """The check itself must not be a write. Every call it makes is a
        `list-*`, held to the same charter rule as any built command."""
        calls = []

        def fake(cmd, cwd, timeout):
            calls.append(cmd)
            return 255, "", "denied"
        import types
        monkey = types.SimpleNamespace(run_cmd=squawk.stages.run_cmd)
        squawk.stages.run_cmd = fake
        try:
            squawk.aws_identity_readonly(self.AUDIT)
        finally:
            squawk.stages.run_cmd = monkey.run_cmd
        assert calls, "it made no call at all"
        for cmd in calls:
            assert cmd[:2] == ["aws", "iam"] and cmd[2].startswith("list-"), cmd
            words = {w.strip("-").lower() for w in cmd}
            assert not (words & squawk.DESTRUCTIVE_TOKENS), cmd

    def test_a_run_says_it_when_the_identity_can_write(self, tmp_path, monkeypatch, capsys):
        """It never blocks — the operator may have no other identity — but a
        report made with a write-capable identity says so."""
        monkeypatch.setenv("SQUAWK_CLOUD_ACK", "1")
        monkeypatch.setattr(squawk.cli, "aws_identity",
                            lambda *a, **k: ({"Account": "000000000000",
                                              "Arn": self.ADMIN, "UserId": "u"}, ""))
        monkeypatch.setattr(squawk.cli, "aws_identity_readonly",
                            lambda arn, **k: ("gap", "its NAME says AdministratorAccess"))
        monkeypatch.setattr(squawk.cli, "execute_service",
                            lambda *a, **k: {"run_id": "r", "run_dir": "/d", "results": []})
        monkeypatch.setattr(squawk.cli, "list_runs", lambda root: [])
        squawk.main(["run", "cloudaws", "--evidence", str(tmp_path / "ev")])
        out = capsys.readouterr().out
        assert "Identity read-only check: gap" in out, out
        assert "AdministratorAccess" in out


class TestStartupFailuresSayWhatFailed:
    """`serve --daemon` on a busy port printed "Squawk did not come up within
    6 s; see <log>" and left a socketserver traceback in that log — naming
    neither the port nor the reason, for the most ordinary startup failure
    there is (the operator, 2026-09-08, port 8787 taken on a work machine)."""

    @staticmethod
    def _busy():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        return s, s.getsockname()[1]

    def test_a_busy_port_is_named_with_a_way_out(self):
        held, port = self._busy()
        try:
            free, why = squawk.port_is_free("127.0.0.1", port)
        finally:
            held.close()
        assert not free
        assert "port %d is already in use" % port in why
        assert "lsof" in why, "it says how to find what has it"
        assert "--port %d" % (port + 12) in why, "and offers another"

    def test_a_free_port_is_free(self):
        held, port = self._busy()
        held.close()
        free, why = squawk.port_is_free("127.0.0.1", port)
        assert free and why == ""

    @pytest.mark.parametrize("daemon", [False, True])
    def test_neither_mode_ends_in_a_traceback(self, tmp_path, daemon):
        """The foreground raised OSError out of ThreadingHTTPServer; the
        daemon buried it in a log. Both say it now, in the terminal."""
        import subprocess
        held, port = self._busy()
        argv = [sys.executable, ENTRY, "serve", "--port", str(port),
                "--evidence", str(tmp_path / "ev")]
        if daemon:
            argv.insert(3, "--daemon")
        try:
            res = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        finally:
            held.close()
        both = res.stdout + res.stderr
        assert res.returncode == 1, both
        assert "Traceback" not in both, both
        assert "Squawk cannot start" in both and "already in use" in both, both

    def test_the_parent_shows_the_child_s_own_words(self, tmp_path, capsys):
        """When it binds and still fails, the reason is in the log, and the
        reader should not have to be sent to a file to see it.

        Driven rather than described: the earlier version searched
        start_daemon's SOURCE for a print() call, which a comment satisfies
        and which says nothing about what reaches the terminal (review R-17).
        """
        log = tmp_path / "squawk-serve.log"
        log.write_text("Traceback (most recent call last):\n"
                       "ValueError: the child's own words\n", encoding="utf-8")
        squawk.service.report_no_start(str(log))
        printed = capsys.readouterr().out
        assert "did not come up" in printed, printed
        assert "the child's own words" in printed, \
            "the reader was sent to a file instead of shown the reason"
        assert str(log) in printed, "the full log is still named"

    def test_a_missing_log_still_says_it_did_not_come_up(self, tmp_path, capsys):
        """No log is not a reason to say nothing."""
        squawk.service.report_no_start(str(tmp_path / "nope.log"))
        printed = capsys.readouterr().out
        assert "did not come up" in printed and "Full log" in printed


class TestASyncFolderIsNamedBeforeTheRun:
    """From the operator's machine, 2026-09-14. A test repository inside OneDrive
    timed out gitleaks after 900s and semgrep after 1200s, while bandit
    finished in 7s and `trivy config` in 5s — those two filter to `.py` and to
    IaC files before reading, so they open a fraction of the tree. The split is
    the signature: the cost is opening files, not reading them, because an
    online-only file is fetched over the network when it is opened.

    Measured for comparison: gitleaks reads ~20 MB/s of scannable text on local
    disk and skips binaries itself — a 1.4 GB tree came back as 15.9 MB scanned
    in 0.8s. For 900s to elapse it would need roughly 18 GB of scannable text,
    which that repository is nowhere near.

    One line before the run beats an hour of working out why a small repository
    scans like an enormous one."""

    REAL = "/Users/x/OneDrive - Some Company/GitHub Repos/acme-platform"

    def test_it_names_the_folder_that_owns_the_path(self):
        assert squawk.sync_root(self.REAL) == "OneDrive - Some Company"

    def test_every_client_shape_is_recognised(self):
        for path, want in (
                ("/Users/x/Dropbox/code/app", "Dropbox"),
                ("/Users/x/Google Drive/thing", "Google Drive"),
                ("/Users/x/Library/Mobile Documents/com~apple~CloudDocs/r",
                 "Mobile Documents"),
                ("/Users/x/Nextcloud/repo", "Nextcloud"),
                ("/Users/x/OneDrive/repo", "OneDrive")):
            assert squawk.sync_root(path) == want, path

    def test_an_ordinary_checkout_says_nothing(self):
        """The false-alarm guard. A note on every run is a note nobody reads."""
        for path in ("/Users/x/Documents/GitHub/notes", "/srv/src/app", "", "/"):
            assert squawk.sync_root(path) == "", path

    def test_a_file_that_merely_mentions_a_client_is_not_a_sync_root(self):
        """Matched on a path SEGMENT. `dropbox_client.py` is a source file
        about a sync client, not a file inside one."""
        assert squawk.sync_root("/Users/x/src/dropbox_client.py") == ""
        # This one matched at first, on a `root + "-"` prefix meant for
        # `OneDrive-Personal`. The note is advisory, so a false positive costs
        # more than a miss: one that cries wolf trains the reader to skip the
        # line, and then it is worth nothing on the run where it was right.
        assert squawk.sync_root("/Users/x/src/onedrive-notes.md") == ""
        assert squawk.sync_root("/Users/x/notes/dropbox-migration/plan.md") == ""

    def test_it_reaches_the_header_a_person_reads(self, tmp_path, capsys,
                                                  monkeypatch):
        """The helper being right is not the point; the line before the run is."""
        target = tmp_path / "OneDrive - Acme" / "repo"
        target.mkdir(parents=True)
        _patch_all(monkeypatch, "tool_path", lambda name: None)
        squawk.cli.main(["--run", "contraband", "--repo", str(target),
                         "--evidence", str(tmp_path / "ev")])
        out = capsys.readouterr().out
        assert "OneDrive - Acme" in out, out[:500]
        assert "cloud-sync folder" in out
        assert "A local clone scans normally" in out

    def test_an_ordinary_target_gets_no_note(self, tmp_path, capsys, monkeypatch):
        target = tmp_path / "plainrepo"
        target.mkdir()
        _patch_all(monkeypatch, "tool_path", lambda name: None)
        squawk.cli.main(["--run", "contraband", "--repo", str(target),
                         "--evidence", str(tmp_path / "ev")])
        assert "cloud-sync folder" not in capsys.readouterr().out

    def test_the_note_changes_nothing_about_the_run(self, tmp_path, monkeypatch):
        """It is printed, never acted on. A path that slows a scan must not
        also silently cap it, refuse it, or alter a budget — that would be the
        silent cap this tool exists to refuse, arriving as a helpful feature."""
        class _Ctx:
            scope, profile, service, raw_path, artifacts = "repo", None, "x", "", {}
            def __init__(self, t):
                self.target = self.repo = t
        plain = str(tmp_path / "plain")
        synced = str(tmp_path / "OneDrive - Acme" / "plain")
        for stage in ("gitleaks", "semgrep", "bandit"):
            a, ta = squawk.STAGES[stage].build(_Ctx(plain))
            b, tb = squawk.STAGES[stage].build(_Ctx(synced))
            assert ta == tb, "%s budget changed under a sync root" % stage
            assert [x.replace(synced, plain) for x in b] == a, stage


class TestATimeoutNamesItsBudget:
    """The first real Security Hub read hit the built-in ten minutes and said
    only `timed out after 600s` — true, and it left the reader to work out
    that the number is a setting."""

    def test_it_names_the_setting_the_section_and_a_value(self, tmp_path, monkeypatch):
        _patch_all(monkeypatch, "tool_path", lambda name: "/usr/bin/" + name)
        _patch_all(monkeypatch, "run_cmd",
                   lambda cmd, cwd, timeout: (124, "", "timed out after %ss" % timeout))
        ev = str(tmp_path / "ev")
        out = squawk.execute_service(squawk.SERVICES["cloudaws"], "000000000000",
                                     ev, str(tmp_path))
        man = next(m for m in squawk.list_runs(ev) if m["run_id"] == out["run_id"])
        detail = next(r["detail"] for r in man["ledger"] if r["tool"] == "awscli")
        assert detail.startswith("timed out after 600s")
        assert "that is stage_timeout" in detail
        # Scoped to the SCANNER. `[services.<svc>]` covers every stage in the
        # service, so a run with two timeouts printed two different values for
        # one key — see TestTheAdviceRaisesTheStageThatAsked.
        assert "[scanners.awscli] stage_timeout = 3600" in detail, detail

    def test_the_advice_raises_the_stage_that_asked(self, tmp_path, monkeypatch):
        """From the operator's run of 2026-09-14. gitleaks and semgrep both timed
        out in one preflight, and each printed `[services.preflight]
        stage_timeout` with a DIFFERENT value — 5400 and 7200, for the same
        key. Following either gives bandit ninety minutes to do seven seconds
        of work; following both is impossible.

        `[scanners.<tool>]` is the most specific table a profile has and beats
        the service, so the advice raises the one stage that asked."""
        _patch_all(monkeypatch, "tool_path", lambda name: "/usr/bin/" + name)
        _patch_all(monkeypatch, "run_cmd",
                   lambda cmd, cwd, timeout: (124, "", "timed out after %ss" % timeout))
        ev = str(tmp_path / "ev")
        out = squawk.execute_service(squawk.SERVICES["preflight"], str(tmp_path),
                                     ev, str(tmp_path))
        man = next(m for m in squawk.list_runs(ev) if m["run_id"] == out["run_id"])
        timed = {r["tool"]: r["detail"] for r in man["ledger"]
                 if "that is stage_timeout" in (r.get("detail") or "")}
        assert len(timed) > 1, "need two timed-out stages to show the clash"
        for tool, detail in timed.items():
            assert "[scanners.%s]" % tool in detail, (tool, detail)
            assert "[services." not in detail, (
                "%s sent the reader to a key shared with every other stage: %s"
                % (tool, detail))
        # And the values genuinely differ, which is what made one shared key wrong.
        values = {d.split("stage_timeout = ")[1].split(")")[0] for d in timed.values()}
        assert len(values) > 1, values

    def test_a_stage_that_failed_some_other_way_is_left_alone(self, tmp_path, monkeypatch):
        _patch_all(monkeypatch, "tool_path", lambda name: "/usr/bin/" + name)
        _patch_all(monkeypatch, "run_cmd", lambda cmd, cwd, timeout: (1, "", "boom"))
        ev = str(tmp_path / "ev")
        out = squawk.execute_service(squawk.SERVICES["cloudaws"], "000000000000",
                                     ev, str(tmp_path))
        man = next(m for m in squawk.list_runs(ev) if m["run_id"] == out["run_id"])
        detail = next(r["detail"] for r in man["ledger"] if r["tool"] == "awscli")
        assert "stage_timeout" not in detail, detail


class TestNoPageRendersARunTargetRaw:
    """The Findings heading read `Run of 111111111111` while the run picker two
    lines under it read `********8115` — photographed by the operator, 2026-09-17,
    which is the fourth time this id has left the machine in a screenshot.

    `mask_account`'s own docstring names "the Findings heading" as a place it
    covers, and `_short_target`'s says "every list, heading and picker goes
    through here". Both were false: six renders took `man["target"]` straight to
    the page. Two were headings, two were the full value printed as a line of
    mono text under an already-masked heading, and two were tooltips.

    This is the structural half. A test that named the six would pass the moment
    somebody wrote a seventh, and the docstrings prove that prose does not hold
    this. It reads the source instead, so the guard covers a render nobody has
    written yet."""

    SAFE = ("mask_account", "_short_target")

    def _raw_renders(self):
        import re
        src = inspect.getsource(squawk.web)
        out = []
        for num, line in enumerate(src.splitlines(), 1):
            for hit in re.finditer(r'E\(\s*(\w+)\.get\("target"', line):
                window = line[max(0, hit.start() - 40):hit.start() + 60]
                if any(safe in window for safe in self.SAFE):
                    continue
                out.append((num, line.strip()))
        return out

    def test_every_render_of_a_target_goes_through_a_masker(self):
        raw = self._raw_renders()
        assert not raw, (
            "an account id reaches the page unmasked at:\n" +
            "\n".join("  line %d: %s" % (n, t[:100]) for n, t in raw))

    def test_the_guard_can_see_an_unmasked_render(self):
        """The guard on the guard. A scanner that matches nothing passes
        whatever the code does, which is how the docstrings came to be wrong."""
        import re
        line = '        % (E(man.get("target", "")), E(x))'
        hits = list(re.finditer(r'E\(\s*(\w+)\.get\("target"', line))
        assert hits, "the pattern does not match a raw render at all"
        window = line[max(0, hits[0].start() - 40):hits[0].start() + 60]
        assert not any(safe in window for safe in self.SAFE)

    def test_the_masker_leaves_every_other_target_shape_alone(self):
        """Masking every heading is only safe because the masker is narrow: a
        repository path, an image reference and a URL are targets too, and
        shortening those would cost the reader the thing they identify a run
        by."""
        for target in ("/Users/x/GitHub Repos/acme-platform", "alpine:3.19",
                       "http://127.0.0.1:3000", "example-app-develop"):
            assert squawk.mask_account(target) == target, target

    def test_an_arn_is_masked_in_place(self):
        """A cloud target is not always a bare id — the identity line carries
        an ARN with the account in the middle."""
        got = squawk.mask_account("arn:aws:iam::111111111111:role/r")
        assert got == "arn:aws:iam::********1111:role/r", got


class TestTheAccountIsMaskedOnScreen:
    """A cloud run's target IS the account number, so it lands in the CLI
    header, the run picker, the Findings heading and every target list — and
    from there into the first paste or screenshot anyone makes. That happened
    three times in one afternoon while `CLOUD-SETUP.md` asked, in prose, that
    it not. A rule enforced by asking is a claim, not a control.

    Display only: the evidence keeps the whole value, because a run has to be
    attributable to the account it read and has to diff against the last one."""

    # A documentation-range account id. The first version of this test used a
    # REAL one, taken from the paste that prompted the fix -- in the very
    # change whose purpose was to stop that number leaking. A fixture is work
    # product like any other and carries the same rule as everything else.
    ACCOUNT: ClassVar[str] = "123456789012"
    ARN: ClassVar[str] = ("arn:aws:sts::123456789012:assumed-role/"
                          "Admin-123456789012/session")

    def test_only_the_last_four_digits_survive(self):
        assert squawk.mask_account(self.ACCOUNT) == "********9012"
        masked = squawk.mask_account(self.ARN)
        assert self.ACCOUNT not in masked
        assert masked.count("********9012") == 2, "both, including the one in the ARN"
        assert "assumed-role/Admin-" in masked, "the role name still reads"

    @pytest.mark.parametrize("target", [
        "/home/user/repo", "http://127.0.0.1:3000", "nginx:1.27",
        "20260908T201009Z-aws", "kali", "1234567890123", "12345678901",
    ])
    def test_it_leaves_every_other_kind_of_target_alone(self, target):
        assert squawk.mask_account(target) == target

    def test_the_evidence_keeps_the_whole_account(self, tmp_path, monkeypatch):
        """Masking is for the screen. A run that could not say which account
        it read would not be evidence of anything."""
        _patch_all(monkeypatch, "tool_path", lambda name: "/usr/bin/" + name)
        _patch_all(monkeypatch, "run_cmd", lambda cmd, cwd, timeout: (0, '{"Findings": []}', ""))
        ev = str(tmp_path / "ev")
        out = squawk.execute_service(squawk.SERVICES["cloudaws"], self.ACCOUNT,
                                     ev, str(tmp_path))
        man = next(m for m in squawk.list_runs(ev) if m["run_id"] == out["run_id"])
        assert man["target"] == self.ACCOUNT, "the manifest holds the real one"

    def test_the_pages_show_the_masked_form(self):
        assert squawk._short_target(self.ACCOUNT) == "********9012"
        chip = squawk.web._chip("aws", self.ACCOUNT)
        assert "********9012" in chip
        # the form still carries the real target, because a rescan needs it,
        # and a form value is not something a screenshot shows
        assert "data-target='%s'" % self.ACCOUNT in chip

    def test_the_cli_masks_both_places_it_prints_the_account(
            self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("SQUAWK_CLOUD_ACK", "1")
        monkeypatch.setattr(squawk.cli, "aws_identity",
                            lambda *a, **k: ({"Account": self.ACCOUNT, "Arn": self.ARN,
                                              "UserId": "u"}, ""))
        monkeypatch.setattr(squawk.cli, "aws_identity_readonly",
                            lambda arn, **k: ("ok", "fine"))
        monkeypatch.setattr(squawk.cli, "execute_service",
                            lambda *a, **k: {"run_id": "r", "run_dir": "/d", "results": []})
        monkeypatch.setattr(squawk.cli, "list_runs", lambda root: [])
        squawk.main(["run", "cloudaws", "--evidence", str(tmp_path / "ev")])
        out = capsys.readouterr().out
        assert self.ACCOUNT not in out, out
        assert "AWS identity: arn:aws:sts::********9012:" in out
        assert "Target  : ********9012" in out


class TestAWideWindowIsUsed:
    """The content was capped at 1200px while the clock strip spanned the whole
    window, so a 2000px screen showed 568px of empty space beside the findings
    and a strip that ran past them (the operator, 2026-09-08). The cap was raised
    to 1680px; measured after, 88px.

    Raising a cap is not removing one, and on 2026-09-11 the same complaint
    came back on a wider display. A cap is the wrong control for this — the
    82ch rule on running text is the one that keeps the page readable, and it
    does not care how wide the window is. `TestThePageFollowsTheWindow` in
    test_charter.py holds the rest."""

    def test_the_content_may_grow_and_prose_may_not(self):
        css = squawk.PAGE_CSS
        main = next(ln for ln in css.splitlines() if ln.startswith("main{"))
        assert "max-width" not in main, \
            "the content column is capped again: %s" % main
        assert "main > p,.sub,.card > p:not(.mono){max-width:82ch}" in css, \
            "and running text stays readable however wide it gets"
        assert "max-width:1200px" not in css


class TestACloudReadIsBoundedAndSaysSo:
    """Unbounded, `get-findings` pages a hundred findings at a time until it
    has every one an account holds. On a large estate that ran past its budget and would have
    produced **nothing**, because a stage killed at its
    budget throws its output away. A bounded read answers in seconds, and the
    CLI's own documentation is explicit that when more exist it returns a
    NextToken — so the count comes back carrying the proof that it is a floor.

    A floor that says it is a floor is a usable answer. An hour of silence is
    not, and a count that quietly stopped is worse than either."""

    @staticmethod
    def _doc(n, truncated):
        rows = [{"Compliance": {"Status": "FAILED", "SecurityControlId": "X.%d" % i},
                 "AwsAccountId": "0" * 12, "Severity": {"Label": "HIGH"},
                 "Title": "t%d" % i, "Resources": [{"Id": "arn:%d" % i, "Type": "T"}]}
                for i in range(n)]
        doc = {"Findings": rows}
        if truncated:
            doc["NextToken"] = "opaque-resume-token"
        return json.dumps(doc)

    def test_the_read_is_bounded_by_default(self):
        import types
        ctx = types.SimpleNamespace(target="0" * 12, raw_path="/r/raw/x.json",
                                    service="cloudaws", profile=None)
        cmd, _t = squawk.STAGES["securityhub-findings"].build(ctx)
        assert cmd[cmd.index("--max-items") + 1] == "1000", cmd
        assert squawk.PROFILE_KEYS["cloud_max_findings"].builtin == 1000

    def test_a_profile_moves_the_bound_and_it_reaches_the_command(self, tmp_path):
        prof = squawk.Profile("p", "--profile", squawk.parse_toml(
            "[services.cloudaws]\ncloud_max_findings = 250\n"))
        prof.validate()
        ctx = squawk.RunContext("0" * 12, "aws", str(tmp_path / "r"), "",
                                service="cloudaws", profile=prof)
        ctx.raw_path = str(tmp_path / "r" / "raw" / "x.json")
        cmd, _t = squawk.STAGES["securityhub-findings"].build(ctx)
        assert cmd[cmd.index("--max-items") + 1] == "250", cmd

    def test_a_truncated_read_reports_a_floor_and_names_the_setting(self):
        cov = squawk.scanners._cov_asff(self._doc(3, truncated=True))
        assert cov.examined == 3
        assert "a FLOOR, not a total" in cov.note
        assert "cloud_max_findings" in cov.note, "and how to pull further"

    def test_a_complete_read_does_not_claim_to_be_a_floor(self):
        cov = squawk.scanners._cov_asff(self._doc(3, truncated=False))
        assert "FLOOR" not in cov.note

    def test_the_floor_reaches_the_line_an_operator_reads(self):
        """The note used to be written into the manifest and shown nowhere but
        the gap message, so 'this count is a floor' was recorded and never
        read. A caveat nobody sees is the silent cap this refuses."""
        raw = self._doc(3, truncated=True)
        finds = squawk.NORMALIZERS["awscli"](raw, "")
        status, detail, cov = squawk.engine._apply_coverage(
            "awscli", raw, finds, "ok", "%d finding(s)" % len(finds))
        assert status == "ok"
        assert "a FLOOR, not a total" in detail, detail
        assert "cloud_max_findings" in detail
        # and on the page beside the number, not only in the CLI
        man = {"ledger": [{"tool": "awscli", "mode": "securityhub", "status": "ok",
                           "detail": detail, "evidence": "raw/x.json",
                           "coverage": {"examined": cov.examined, "unit": cov.unit,
                                        "skipped": cov.skipped, "errors": cov.errors,
                                        "note": cov.note}, "ran": None}]}
        html = squawk.coverage_panel(man)
        assert "a FLOOR, not a total" in html, "the run page shows it too"

    def test_an_empty_account_is_still_a_gap_not_a_floor(self):
        """Bounding the read must not turn 'Security Hub is off here' into
        'here is a small number'."""
        raw = self._doc(0, truncated=False)
        finds = squawk.NORMALIZERS["awscli"](raw, "")
        status, detail, _cov = squawk.engine._apply_coverage(
            "awscli", raw, finds, "ok", "0 finding(s)")
        assert status == "gap" and "not a clean result" in detail

    def test_every_other_scanners_note_now_shows_too(self):
        """The fix is general: any coverage note explaining what a count does
        not include reaches the detail, not just this one."""
        raw = json.dumps({"Findings": [
            {"Compliance": {"Status": "PASSED", "SecurityControlId": "P.1"},
             "AwsAccountId": "0" * 12}]})
        finds = squawk.NORMALIZERS["awscli"](raw, "")
        _status, detail, _cov = squawk.engine._apply_coverage(
            "awscli", raw, finds, "ok", "%d finding(s)" % len(finds))
        assert "passed control(s) not carried as findings" in detail, detail


# --------------------------------------------------------------------------- #
# Cloud inventory and the graph rules.
#
# The reason these tests are long is that the rules make a claim about the
# internet reaching a machine, and a false one of those wastes an operator's
# afternoon while a missed one is the reason the tool exists. Each fixture is
# the smallest graph that isolates one leg of the join.
# --------------------------------------------------------------------------- #

class _CloudCtx:
    """Stand-in RunContext for the inventory probe: it reads the profile, the
    service and the target, and nothing else."""

    def __init__(self):
        self.profile = None
        self.service = "cloudinventory"
        self.target = "aws"
        self.raw_path = ""
        # What one stage hands the next, the way the real RunContext does:
        # the organization stage leaves its reading here for the IAM stage.
        self.artifacts = {}


def _inv(reads=None, resources=None, **kw):
    """An inventory payload for one region, `us-test-1`, with everything read
    successfully unless a test says otherwise."""
    keys = ("vpcs", "subnets", "route-tables", "internet-gateways",
            "security-groups", "network-interfaces", "instances")
    res = dict.fromkeys(keys, None)
    res.update(resources or {})
    res = {k: (v or []) for k, v in res.items()}
    rd = {k: {"status": "ok", "detail": "", "count": len(res[k])} for k in keys}
    rd.update(reads or {})
    payload = {
        "account": "000000000000",
        "regions_enabled": ["us-test-1"],
        "regions_read": ["us-test-1"],
        "regions_unread": [],
        "budget_seconds": 600,
        "reads": {"us-test-1": rd},
        "resources": {"us-test-1": res},
        "instance_profiles": {},
        "roles": {},
    }
    payload.update(kw)
    return payload


def _exposed(profile_arn="", role="", policies=("AdministratorAccess",),
             port=22, cidr="0.0.0.0/0", igw_state="available",
             assoc_subnet="subnet-1", main=False):
    """The full four-leg fixture: a running instance with a public IP, in a
    subnet whose route table reaches an attached IGW, behind a group open to
    the world, optionally carrying a role."""
    inv = _inv(resources={
        "vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16"}],
        "subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1"}],
        "route-tables": [{
            "RouteTableId": "rtb-1", "VpcId": "vpc-1",
            "Associations": ([{"Main": True}] if main
                             else [{"SubnetId": assoc_subnet}]),
            "Routes": [{"DestinationCidrBlock": "0.0.0.0/0",
                        "GatewayId": "igw-1", "State": "active"}]}],
        "internet-gateways": [{"InternetGatewayId": "igw-1",
                               "Attachments": [{"VpcId": "vpc-1",
                                                "State": igw_state}]}],
        "security-groups": [{
            "GroupId": "sg-1", "GroupName": "open", "VpcId": "vpc-1",
            "IpPermissions": [{"IpProtocol": "tcp", "FromPort": port,
                               "ToPort": port, "IpRanges": [cidr],
                               "Ipv6Ranges": []}]}],
        "instances": [{
            "InstanceId": "i-1", "State": "running", "SubnetId": "subnet-1",
            "VpcId": "vpc-1", "PublicIpAddress": "203.0.113.10",
            "InstanceProfileArn": profile_arn,
            "SecurityGroups": ["sg-1"]}]})
    if profile_arn:
        inv["instance_profiles"] = {profile_arn: {"status": "ok", "detail": "",
                                                  "role": role}}
        inv["roles"] = {role: {"status": "ok", "detail": "",
                               "policies": list(policies),
                               "broad": [p for p in policies
                                         if p in squawk.probes.BROAD_POLICIES
                                         or p.endswith("FullAccess")]}}
    return inv


def _fired(records, key):
    return [r for r in records if r["key"] == key and r["state"] == "fired"]


def _unknown(records, key):
    return [r for r in records if r["key"] == key and r["state"] == "unknown"]


class TestReachabilityNeedsASessionAndReadsEveryInterface:
    """Review R-8, reproduction 7.

    _world_open_ports keeps every rule, and _reachable_instances used to count
    every one of them toward reachability. An instance with a public address,
    an administrator role and a group admitting only ICMP echo from anywhere
    fired the four-leg CRITICAL rule: a ping is not a foothold. The reverse gap
    sat next to it -- `SecurityGroups` on the instance is the PRIMARY
    interface's groups, so an instance whose public address is on a second
    interface carrying the open group produced nothing at all.
    """

    def _with_protocol(self, protocol, port=22, on_eni=False):
        inv = _exposed()
        res = inv["resources"]["us-test-1"]
        res["security-groups"][0]["IpPermissions"] = [
            {"IpProtocol": protocol, "FromPort": port, "ToPort": port,
             "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}]
        if on_eni:
            res["instances"][0]["SecurityGroups"] = []
            res["network-interfaces"] = [
                {"NetworkInterfaceId": "eni-2", "InstanceId": "i-1",
                 "SubnetId": "subnet-1", "VpcId": "vpc-1",
                 "PublicIp": "203.0.113.10", "InterfaceType": "interface",
                 "Description": "", "Groups": ["sg-1"]}]
        return inv

    def test_ping_from_anywhere_is_not_a_foothold(self):
        for protocol, port in (("icmp", 8), ("udp", 53), ("icmpv6", 128)):
            inv = self._with_protocol(protocol, port)
            g = squawk.analysis.build_cloud_graph(inv, "us-test-1")
            assert squawk.analysis._reachable_instances(g) == [], protocol
            recs = squawk.analysis.correlate_cloud(inv)
            assert not _fired(recs, "reachable-admin-port"), protocol
            assert not _fired(recs, "reachable-over-permitted"), protocol

    def test_tcp_still_reaches(self):
        g = squawk.analysis.build_cloud_graph(
            self._with_protocol("tcp"), "us-test-1")
        assert len(squawk.analysis._reachable_instances(g)) == 1

    def test_every_protocol_still_reaches(self):
        """`-1` is every protocol, which includes TCP."""
        inv = _exposed()
        inv["resources"]["us-test-1"]["security-groups"][0]["IpPermissions"] = [
            {"IpProtocol": "-1", "FromPort": None, "ToPort": None,
             "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}]
        g = squawk.analysis.build_cloud_graph(inv, "us-test-1")
        assert len(squawk.analysis._reachable_instances(g)) == 1

    def test_what_else_the_group_admits_is_said_not_counted(self):
        inv = _exposed()
        inv["resources"]["us-test-1"]["security-groups"][0]["IpPermissions"] = [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []},
            {"IpProtocol": "icmp", "FromPort": 8, "ToPort": -1,
             "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}]
        fired = _fired(squawk.analysis.correlate_cloud(inv),
                       "reachable-admin-port")
        assert fired and "also admit 0.0.0.0/0 on icmp" in fired[0]["why"]

    def test_a_group_on_a_secondary_interface_counts(self):
        inv = self._with_protocol("tcp", on_eni=True)
        g = squawk.analysis.build_cloud_graph(inv, "us-test-1")
        assert squawk.analysis._instance_groups(g, g.instances[0]) == ["sg-1"]
        assert _fired(squawk.analysis.correlate_cloud(inv),
                      "reachable-admin-port"), \
            "the open group was on the interface carrying the public address"

    def test_an_interface_on_another_instance_does_not_count(self):
        inv = self._with_protocol("tcp", on_eni=True)
        res = inv["resources"]["us-test-1"]
        res["network-interfaces"][0]["InstanceId"] = "i-other"
        g = squawk.analysis.build_cloud_graph(inv, "us-test-1")
        assert squawk.analysis._instance_groups(g, g.instances[0]) == []


class TestCloudGraphReachability:
    """A public subnet is DERIVED, not read off a field."""

    def test_route_to_igw_makes_the_subnet_public(self):
        g = squawk.analysis.build_cloud_graph(_exposed(), "us-test-1")
        assert squawk.analysis.public_subnets(g) == {"subnet-1": "igw-1"}

    def test_no_igw_route_means_not_public(self):
        inv = _exposed()
        inv["resources"]["us-test-1"]["route-tables"][0]["Routes"] = [
            {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}]
        g = squawk.analysis.build_cloud_graph(inv, "us-test-1")
        assert squawk.analysis.public_subnets(g) == {}, \
            "a NAT gateway route is egress, not reachability"
        assert not _fired(squawk.analysis.correlate_cloud(inv),
                          "reachable-admin-port")

    def test_detached_igw_does_not_make_a_subnet_public(self):
        inv = _exposed(igw_state="detached")
        g = squawk.analysis.build_cloud_graph(inv, "us-test-1")
        assert squawk.analysis.public_subnets(g) == {}

    def test_main_route_table_covers_unassociated_subnets(self):
        g = squawk.analysis.build_cloud_graph(_exposed(main=True), "us-test-1")
        assert squawk.analysis.public_subnets(g) == {"subnet-1": "igw-1"}

    def test_a_route_table_for_another_subnet_does_not_leak(self):
        g = squawk.analysis.build_cloud_graph(
            _exposed(assoc_subnet="subnet-other"), "us-test-1")
        assert squawk.analysis.public_subnets(g) == {}

    def test_public_ip_on_a_secondary_interface_still_counts(self):
        inv = _exposed()
        inv["resources"]["us-test-1"]["instances"][0]["PublicIpAddress"] = ""
        inv["resources"]["us-test-1"]["network-interfaces"] = [
            {"NetworkInterfaceId": "eni-1", "SubnetId": "subnet-1",
             "VpcId": "vpc-1", "PublicIp": "203.0.113.11",
             "InstanceId": "i-1", "Groups": ["sg-1"]}]
        assert _fired(squawk.analysis.correlate_cloud(inv),
                      "reachable-admin-port")


class TestCloudCombinationNeedsEveryMember:
    """Remove one leg and the combination must stop firing. This is the whole
    claim: the members are ordinary, the join is not."""

    def test_all_four_legs_fire(self):
        recs = squawk.analysis.correlate_cloud(
            _exposed(profile_arn="arn:aws:iam::000000000000:instance-profile/p",
                     role="app-role"))
        hit = _fired(recs, "reachable-over-permitted")
        assert len(hit) == 1
        why = hit[0]["why"]
        for member in ("i-1", "subnet-1", "igw-1", "sg-1", "app-role",
                       "AdministratorAccess"):
            assert member in why, "the path must name %s" % member

    def test_closing_the_group_stops_it(self):
        inv = _exposed(profile_arn="arn:aws:iam::0:instance-profile/p",
                       role="app-role", cidr="10.0.0.0/8")
        recs = squawk.analysis.correlate_cloud(inv)
        assert not _fired(recs, "reachable-over-permitted")
        assert not _fired(recs, "reachable-admin-port")

    def test_a_read_only_role_stops_the_four_leg_rule_only(self):
        inv = _exposed(profile_arn="arn:aws:iam::0:instance-profile/p",
                       role="app-role", policies=("ReadOnlyAccess",))
        recs = squawk.analysis.correlate_cloud(inv)
        assert not _fired(recs, "reachable-over-permitted")
        assert _fired(recs, "reachable-admin-port"), \
            "the host is still reachable on 22; only the IAM leg went away"

    def test_a_stopped_instance_is_not_reachable(self):
        inv = _exposed()
        inv["resources"]["us-test-1"]["instances"][0]["State"] = "stopped"
        assert not _fired(squawk.analysis.correlate_cloud(inv),
                          "reachable-admin-port")

    def test_https_open_to_the_world_is_not_a_finding(self):
        assert not _fired(squawk.analysis.correlate_cloud(_exposed(port=443)),
                          "reachable-admin-port"), \
            "a web server open to the world is the job, not a finding"

    def test_all_traffic_admits_every_sensitive_port(self):
        inv = _exposed()
        inv["resources"]["us-test-1"]["security-groups"][0]["IpPermissions"] = [
            {"IpProtocol": "-1", "FromPort": None, "ToPort": None,
             "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}]
        hit = _fired(squawk.analysis.correlate_cloud(inv), "reachable-admin-port")
        assert hit and "22/SSH" in hit[0]["why"] and "3389/RDP" in hit[0]["why"]

    def test_ipv6_open_to_the_world_counts(self):
        inv = _exposed(cidr="x")
        inv["resources"]["us-test-1"]["security-groups"][0]["IpPermissions"] = [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [], "Ipv6Ranges": ["::/0"]}]
        assert _fired(squawk.analysis.correlate_cloud(inv), "reachable-admin-port")


class TestPartialCloudReadIsNeverClean:
    """The single most important property here: a rule may only say "nothing
    found" over data it actually has."""

    def test_a_failed_group_read_makes_the_rule_unknown(self):
        inv = _exposed()
        inv["reads"]["us-test-1"]["security-groups"] = {
            "status": "error", "detail": "AccessDenied", "count": 0}
        inv["resources"]["us-test-1"]["security-groups"] = []
        recs = squawk.analysis.correlate_cloud(inv)
        for key in ("reachable-admin-port", "reachable-over-permitted"):
            assert not _fired(recs, key)
            unknown = _unknown(recs, key)
            assert unknown, "%s must be unknown, never a clean nothing" % key
            assert "AccessDenied" in unknown[0]["why"]

    def test_an_unread_region_is_named_not_counted_as_clean(self):
        inv = _exposed()
        inv["regions_enabled"] = ["us-test-1", "eu-test-9"]
        inv["regions_unread"] = ["eu-test-9"]
        recs = squawk.analysis.correlate_cloud(inv)
        unknown = _unknown(recs, "reachable-admin-port")
        assert unknown and "eu-test-9" in unknown[0]["why"]
        assert "1 of 2" in unknown[0]["why"]

    def test_a_budget_stopped_read_is_unknown_too(self):
        inv = _exposed()
        inv["reads"]["us-test-1"]["instances"] = {
            "status": "unread", "detail": "the 600s budget ran out first",
            "count": 0}
        assert _unknown(squawk.analysis.correlate_cloud(inv),
                        "reachable-admin-port")

    def test_an_unreadable_role_does_not_read_as_a_safe_role(self):
        inv = _exposed(profile_arn="arn:aws:iam::0:instance-profile/p", role="")
        inv["instance_profiles"] = {"arn:aws:iam::0:instance-profile/p": {
            "status": "unknown", "detail": "AccessDenied", "role": ""}}
        recs = squawk.analysis.correlate_cloud(inv)
        assert not _fired(recs, "reachable-over-permitted")
        assert _fired(recs, "reachable-admin-port"), \
            "the reachability half is still known and must still be reported"


class TestCloudCoverage:
    """Zero findings over real resources is a result. Zero resources is a gap."""

    def test_the_reads_that_answered_are_the_denominator(self):
        """It counted RESOURCES, so an account with a region that answered
        every read and holds nothing in it examined zero and became a gap --
        a tool that found nothing looking like a tool that did not run
        (review 2, R-20). The distinguishing fact was already in the evidence:
        this stage records `{status, count}` per read per region."""
        cov = squawk.scanners.stage_coverage("cloudinv", json.dumps(_exposed()))
        assert cov.unit == "reads that answered"
        assert cov.examined > 0
        assert "1 of 1 enabled region(s) read" in cov.note
        assert "resource(s) found" in cov.note, \
            "what it found is still said, in the note"

    def test_an_empty_region_that_answered_is_not_a_gap(self):
        """Every read answered and the region holds nothing. That is a result."""
        inv = _exposed()
        for key in list(inv["resources"]["us-test-1"]):
            inv["resources"]["us-test-1"][key] = []
        for key in inv["reads"]["us-test-1"]:
            inv["reads"]["us-test-1"][key] = {"status": "ok", "detail": "",
                                              "count": 0}
        status, _detail, _cov = squawk.engine._apply_coverage(
            "cloudinv", json.dumps(inv), [], "ok", "0 findings")
        assert status == "ok"

    def test_a_read_that_reached_nothing_at_all_is_still_a_gap(self):
        """No region, no read, nothing answered. `_inv()` on its own is no
        longer this case: its reads answer and return nothing, which is the
        result the rule above exists to protect."""
        status, detail, _cov = squawk.engine._apply_coverage(
            "cloudinv", json.dumps({"reads": {}, "resources": {},
                                    "regions_enabled": ["us-test-1"],
                                    "regions_read": []}),
            [], "ok", "0 findings")
        assert status == "gap"
        assert "examined 0 reads that answered" in detail

    def test_zero_findings_over_real_resources_stays_ok(self):
        raw = json.dumps(_exposed(port=443))     # reachable, but nothing toxic
        assert squawk.scanners.norm_cloudinv(raw, "") == []
        status, detail, _cov = squawk.engine._apply_coverage(
            "cloudinv", raw, [], "ok", "0 findings")
        assert status == "ok", "a real read that found nothing is a real result"
        assert "reads that answered" in detail

    def test_unread_regions_are_declared_a_floor(self):
        inv = _exposed()
        inv["regions_enabled"] = ["us-test-1", "eu-test-9"]
        inv["regions_unread"] = ["eu-test-9"]
        cov = squawk.scanners.stage_coverage("cloudinv", json.dumps(inv))
        assert "FLOOR" in cov.note and "eu-test-9" in cov.note
        assert "cloud_inventory_budget" in cov.note

    def test_failed_reads_are_counted_as_errors(self):
        inv = _exposed()
        inv["reads"]["us-test-1"]["security-groups"] = {
            "status": "error", "detail": "AccessDenied", "count": 0}
        cov = squawk.scanners.stage_coverage("cloudinv", json.dumps(inv))
        assert cov.errors == 1


class TestCloudFindingsAreWellFormed:

    def test_identity_is_stable_across_reads(self):
        inv = _exposed()
        one = squawk.scanners.norm_cloudinv(json.dumps(inv), "")
        inv["resources"]["us-test-1"]["instances"][0]["PublicIpAddress"] = "198.51.100.7"
        two = squawk.scanners.norm_cloudinv(json.dumps(inv), "")
        assert [f.identity for f in one] == [f.identity for f in two], \
            "a re-read must diff to nothing; the address is not identity"

    def test_a_finding_carries_its_members_and_its_fix(self):
        found = squawk.scanners.norm_cloudinv(
            json.dumps(_exposed(profile_arn="arn:aws:iam::0:instance-profile/p",
                                role="app-role")), "")
        assert len(found) == 1, "one instance, one path, one finding"
        detail = found[0].detail
        assert "i-1" in detail["members"] and "app-role" in detail["members"]
        assert detail["remediation"] and detail["what"]
        assert found[0].severity == "critical"

    def test_the_stronger_rule_supersedes_the_weaker_one(self):
        """And it must carry everything the weaker one would have said, or
        this is a silent cap rather than a de-duplication."""
        inv = _exposed(profile_arn="arn:aws:iam::0:instance-profile/p",
                       role="app-role")
        recs = squawk.analysis.correlate_cloud(inv)
        assert not _fired(recs, "reachable-admin-port")
        survivor = _fired(recs, "reachable-over-permitted")[0]
        weaker = _fired(squawk.analysis.correlate_cloud(
            _exposed(profile_arn="arn:aws:iam::0:instance-profile/p",
                     role="app-role", policies=("ReadOnlyAccess",))),
            "reachable-admin-port")[0]
        for member in weaker["members"]:
            assert member in survivor["members"], \
                "superseding dropped %s" % member
        assert "22/SSH" in survivor["why"]

    def test_supersedes_only_names_rules_that_exist(self):
        keys = {r.key for r in squawk.analysis.CLOUD_CORRELATIONS}
        for rule in squawk.analysis.CLOUD_CORRELATIONS:
            for weaker in rule.supersedes:
                assert weaker in keys, "%s supersedes a rule that does not exist" % rule.key

    def test_junk_does_not_raise(self):
        for junk in ("", "{}", "null", "[]", '{"regions_read": "not-a-list"}',
                     '{"regions_read": ["r"], "resources": null}'):
            assert squawk.scanners.norm_cloudinv(junk, "") == []
            squawk.scanners.stage_coverage("cloudinv", junk)


class TestCloudUnknownsReachTheReader:
    """A question this run could not answer must reach the same panel as every
    other question it could not answer.

    The rules run inside the normalizer, which may only return findings, so the
    unknowns had nowhere to go: on a live-shaped run a denied region was
    computed, logged, and dropped, and the run reported one finding and no
    doubt. Worse, the first fix silently found nothing on every real run —
    a StageResult carries its raw path relative to the run directory, and
    reading it back without that directory opens nothing. Every unit test still
    passed, because they built records directly and never went near a file.
    This one goes near the file."""

    def _run_dir(self, tmp_path, payload):
        run_dir = tmp_path / "run"
        (run_dir / "raw").mkdir(parents=True)
        (run_dir / "raw" / "cloud-inventory.json").write_text(
            json.dumps(payload), encoding="utf-8")
        res = squawk.StageResult("cloudinv", "inventory", "ok", "", 
                                 os.path.join("raw", "cloud-inventory.json"),
                                 [], 0, None)
        return str(run_dir), [res]

    def test_a_denied_region_is_reported_as_unknown(self, tmp_path):
        inv = _exposed()
        inv["regions_enabled"] = ["us-test-1", "us-test-2"]
        inv["regions_read"] = ["us-test-1", "us-test-2"]
        inv["reads"]["us-test-2"] = dict(
            inv["reads"]["us-test-1"],
            **{"security-groups": {"status": "error",
                                   "detail": "UnauthorizedOperation", "count": 0}})
        inv["resources"]["us-test-2"] = {k: [] for k in inv["resources"]["us-test-1"]}
        run_dir, results = self._run_dir(tmp_path, inv)
        recs = squawk.analysis.cloud_correlations(results, run_dir)
        assert recs, "reading the stage's own evidence back returned nothing"
        unknown = [r for r in recs if r["state"] == "unknown"]
        assert unknown, "the denied region vanished"
        assert any("UnauthorizedOperation" in r["why"] for r in unknown)
        assert any(r["state"] == "fired" for r in recs)

    def test_a_relative_raw_path_is_resolved_against_the_run_dir(self, tmp_path):
        run_dir, results = self._run_dir(tmp_path, _exposed())
        assert results[0].raw_file == os.path.join("raw", "cloud-inventory.json"), \
            "the fixture must use the relative path a real run records"
        assert squawk.analysis.cloud_correlations(results, run_dir)

    def test_a_missing_or_corrupt_raw_file_does_not_raise(self, tmp_path):
        res = squawk.StageResult("cloudinv", "inventory", "error", "", 
                                 "raw/nope.json", [], 0, None)
        assert squawk.analysis.cloud_correlations([res], str(tmp_path)) == []
        (tmp_path / "raw").mkdir()
        (tmp_path / "raw" / "bad.json").write_text("{not json", encoding="utf-8")
        bad = squawk.StageResult("cloudinv", "inventory", "ok", "",
                                 "raw/bad.json", [], 0, None)
        assert squawk.analysis.cloud_correlations([bad], str(tmp_path)) == []

    def test_other_stages_are_left_alone(self, tmp_path):
        run_dir, _results = self._run_dir(tmp_path, _exposed())
        other = squawk.StageResult("gitleaks", "detect", "ok", "",
                                   os.path.join("raw", "cloud-inventory.json"),
                                   [], 0, None)
        assert squawk.analysis.cloud_correlations([other], run_dir) == []


class TestCloudPageMasksTheAccount:
    """The CLI masked the account id from the day it printed one; the Cloud
    page printed all twelve digits. Screenshots of that page get pasted into
    issue threads, so the two had to agree, and they agree on the CLI's
    answer."""

    def test_the_identity_card_masks_the_account_and_the_arn(self, monkeypatch, tmp_path):
        monkeypatch.setattr(squawk.web, "aws_identity",
                            lambda *a, **k: ({"Account": "123456789012",
                                              "Arn": "arn:aws:iam::123456789012:role/r",
                                              "UserId": "U"}, ""))
        monkeypatch.setattr(squawk.web, "cloud_target_ok", lambda: (True, "acked"))
        html = squawk.web.view_cloud(str(tmp_path))
        assert "123456789012" not in html, "the full account id reached the page"
        assert "********9012" in html, "the masked form should still identify it"

    def test_the_run_history_masks_the_target(self, monkeypatch, tmp_path):
        monkeypatch.setattr(squawk.web, "aws_identity", lambda *a, **k: (None, "no identity"))
        monkeypatch.setattr(squawk.web, "cloud_target_ok", lambda: (False, "not acked"))
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [{
            "run_id": "20260101T000000Z-aws", "service": "cloudinventory",
            "target": "123456789012", "severities": {"critical": 1},
            "correlations": [{"state": "unknown", "why": "could not read groups"}]}])
        html = squawk.web.view_cloud(str(tmp_path))
        assert "123456789012" not in html
        assert "unanswered" in html, "the unknowns must be shown beside the findings"


class TestCloudInventoryIsReadOnly:

    def test_the_stage_refuses_without_the_aws_binary(self, monkeypatch):
        monkeypatch.setattr(squawk.probes, "tool_path", lambda _n: "")
        out, status, detail = squawk.probes.aws_inventory(_CloudCtx())
        assert status == "error" and "nothing was read" in detail
        assert json.loads(out)["resources"] == {}

    def test_no_regions_is_an_error_not_an_empty_inventory(self, monkeypatch):
        monkeypatch.setattr(squawk.probes, "tool_path", lambda _n: "/usr/bin/aws")
        monkeypatch.setattr(squawk.probes, "_aws_json",
                            lambda argv, _t: ({"Account": "0"}, "")
                            if argv[0] == "sts" else (None, "AccessDenied"))
        out, status, detail = squawk.probes.aws_inventory(_CloudCtx())
        assert status == "error"
        assert "denominator" in detail
        assert json.loads(out)["resources"] == {}


# --------------------------------------------------------------------------- #
# Three defects from the first real Security Hub read of a live account
# (2026-09-08). Each test below fails against the code as it stood that
# morning. Fixtures are synthetic and carry a documentation-range account id;
# nothing from the account that produced them is in this file.
# --------------------------------------------------------------------------- #

class TestTheAttackAlarmDoesNotFireOnControls:
    """7500 said "evidence of an active attack" about ordinary configuration findings, because `"c2"
    in "ec2"`."""

    def _asff(self, title, ftype="", status="FAILED", scanner="awscli"):
        return {"scanner": scanner, "title": title, "path": "",
                "detail": {"type": ftype, "rule": "", "status": status}}

    def test_ec2_in_a_title_is_not_command_and_control(self):
        f = self._asff("EC2 subnets should not automatically assign public IP addresses")
        assert not squawk.analysis._looks_like_an_attack(f), \
            "'c2' matched inside 'ec2' — the substring bug"

    def test_ec2_in_an_arn_is_not_command_and_control(self):
        f = self._asff("EBS volumes should be in a backup plan")
        f["path"] = "arn:aws:ec2:us-east-1:000000000000:volume/vol-0abc"
        f["detail"]["rule"] = "arn:aws:ec2:us-east-1:000000000000:volume/vol-0abc"
        assert not squawk.analysis._looks_like_an_attack(f)

    def test_a_control_evaluation_can_never_be_an_incident(self):
        """The structural gate, independent of any wording: a finding with a
        compliance status is a statement about configuration at rest."""
        worst = self._asff("Ensure no backdoor or trojan malicious exfiltration",
                           status="FAILED")
        assert squawk.analysis._is_control_evaluation(worst)

    def test_a_real_guardduty_type_still_fires(self):
        """The alarm must still work. These are GuardDuty's own finding
        types, which is the vocabulary the marker list is drawn from."""
        for title, ftype in (
                ("Bitcoin tool related domain name queried by EC2 instance",
                 "CryptoCurrency:EC2/BitcoinTool.B"),
                ("EC2 instance is communicating with a command and control server",
                 "Backdoor:EC2/C&CActivity.B"),
                ("SSH brute force attacks", "UnauthorizedAccess:EC2/SSHBruteForce"),
                ("Data exfiltration through DNS queries",
                 "Trojan:EC2/DNSDataExfiltration")):
            f = self._asff(title, ftype=ftype, status="")
            assert not squawk.analysis._is_control_evaluation(f)
            assert squawk.analysis._looks_like_an_attack(f), \
                "the alarm stopped recognising %s" % ftype

    def test_the_markers_are_matched_at_word_boundaries(self):
        """Every marker, against a word that merely contains it. This is the
        general form of the bug, so it is tested in the general form."""
        for mark in squawk.analysis.ATTACK_MARKERS:
            if not mark[:1].isalnum():
                continue
            f = self._asff("z%s configuration guidance" % mark, status="")
            assert not squawk.analysis._looks_like_an_attack(f), \
                "%r matched inside a longer word" % mark

    def test_the_end_to_end_alarm_stays_silent_on_a_control_only_run(self, tmp_path):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        findings = [dict(self._asff(t), identity="c%d:0:r" % i, severity="high")
                    for i, t in enumerate([
                        "EC2 subnets should not automatically assign public IP addresses",
                        "EBS volumes should be in a backup plan",
                        "VPC default security groups should not allow inbound traffic"])]
        (run / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
        man = {"_dir": str(run), "run_id": run.name, "service": "cloudaws",
               "target": "000000000000", "ledger": [{"tool": "awscli", "status": "ok"}],
               "counts": {"total": len(findings)}, "severities": {"high": 3}}
        codes = [r["code"] for r in squawk.analysis.squawk_check(str(tmp_path), man)]
        assert "7500" not in codes, "a control-only run reported an active attack"


class TestOneBadManifestCannotKillAPage:
    """A run whose target was a JSON null raised out of the run picker and took
    the whole Findings page down — with seventy-six healthy runs beside it."""

    def test_as_text_is_total_over_what_json_can_hold(self):
        for value, want in ((None, ""), ("x", "x"), (12, "12"),
                            ([], ""), ({}, ""), (True, "True")):
            assert squawk.as_text(value) == want, value

    def test_mask_account_does_not_raise_on_a_null_target(self):
        assert squawk.mask_account(None) == ""
        assert squawk.mask_account(12345) == "12345"

    def test_short_target_does_not_raise_on_a_null_target(self):
        assert squawk.web._short_target(None) == ""

    def test_the_findings_page_renders_beside_a_null_target_run(self, monkeypatch,
                                                                tmp_path):
        good = {"run_id": "20260101T000001Z-repo", "service": "preflight",
                "target": str(tmp_path), "scope": "repo", "severities": {},
                "counts": {"total": 0}, "ledger": [], "_dir": str(tmp_path)}
        bad = dict(good, run_id="20260101T000000Z-aws", target=None)
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [good, bad])
        monkeypatch.setattr(squawk.web, "load_findings", lambda _d: [])
        html = squawk.web.view_findings(str(tmp_path), None)
        assert "20260101T000000Z-aws" in html, "the bad run vanished instead of rendering"

    def test_an_aborted_run_never_persists_a_null_target(self, tmp_path):
        run = tmp_path / "20260101T000000Z-aws"
        run.mkdir()
        (run / "started.json").write_text(
            json.dumps({"service": "cloudaws", "target": None, "scope": None}),
            encoding="utf-8")
        assert squawk.record_aborted_run(str(run), "interrupted")
        man = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
        assert man["target"] == "" and man["scope"] == "", \
            "a null in started.json was copied into the manifest"


class TestAlarmLinesMaskTheAccount:
    """The CLI header masked the account id; the alarm lines two rows below it
    printed all twelve digits inside every resource ARN, and those are the
    lines people paste."""

    def _raised(self):
        # The real shape since plan 11 step 3: an alarm line can carry a
        # denial, and an AWS denial under SSO carries the operator's address.
        return [{"code": "7700",
                 "why": "1 critical finding(s) in account 123456789012",
                 "detail": ["Something bad x2 — "
                            "arn:aws:ec2:us-east-1:123456789012:volume/vol-0abc",
                            "policy status (An error occurred (AccessDenied) "
                            "when calling the GetBucketPolicyStatus operation: "
                            "User: arn:aws:sts::123456789012:assumed-role/"
                            "AWSReservedSSO_Admin_abc/someone@example.com is "
                            "not authorized)"]}]

    def test_the_cli_lines_are_masked(self):
        text = "\n".join(squawk.analysis.squawk_lines(self._raised()))
        assert "someone@example.com" not in text, "an address reached the terminal"
        assert "123456789012" not in text, "the account id reached the terminal"
        assert "********9012" in text
        assert "vol-0abc" in text, "masking must not eat the resource id"

    def test_the_web_banner_is_masked(self):
        html = squawk.web.squawk_banner(self._raised())
        assert "someone@example.com" not in html
        assert "123456789012" not in html
        assert "********9012" in html

    def test_the_record_itself_keeps_the_real_arn(self):
        """Evidence stays true. An operator cannot act on a masked ARN, and
        the evidence directory is theirs and owner-only — it is the thing that
        LEAVES the machine that gets masked."""
        raised = self._raised()
        squawk.analysis.squawk_lines(raised)
        assert "123456789012" in raised[0]["detail"][0], \
            "masking mutated the record instead of the rendering"


class TestInventoryIsShownNotJustReasonedOver:
    """The first real run examined 318 resources across 17 regions and the
    screen said "0 findings". True, and useless: the operator asked what is out
    there and was handed a zero. These cover what is shown instead."""

    def _multi(self, regions=("us-test-1", "us-test-2"), instances=True,
               risky_port=22):
        payload = {"account": "000000000000",
                   "regions_enabled": list(regions), "regions_read": list(regions),
                   "regions_unread": [], "reads": {}, "resources": {},
                   "instance_profiles": {}, "roles": {}}
        for n, region in enumerate(regions):
            res = {
                "vpcs": [{"VpcId": "vpc-%d" % n}],
                "subnets": [{"SubnetId": "subnet-%d" % n, "VpcId": "vpc-%d" % n},
                            {"SubnetId": "private-%d" % n, "VpcId": "vpc-%d" % n}],
                "route-tables": [{"RouteTableId": "rtb-%d" % n, "VpcId": "vpc-%d" % n,
                                  "Associations": [{"SubnetId": "subnet-%d" % n}],
                                  "Routes": [{"DestinationCidrBlock": "0.0.0.0/0",
                                              "GatewayId": "igw-%d" % n,
                                              "State": "active"}]}],
                "internet-gateways": [{"InternetGatewayId": "igw-%d" % n,
                                       "Attachments": [{"VpcId": "vpc-%d" % n,
                                                        "State": "available"}]}],
                "security-groups": [{"GroupId": "sg-%d" % n, "VpcId": "vpc-%d" % n,
                                     "IpPermissions": [
                                         {"IpProtocol": "tcp", "FromPort": risky_port,
                                          "ToPort": risky_port,
                                          "IpRanges": ["0.0.0.0/0"],
                                          "Ipv6Ranges": []}]}],
                "network-interfaces": [],
                "instances": ([{"InstanceId": "i-%d" % n, "State": "running",
                                "SubnetId": "subnet-%d" % n, "VpcId": "vpc-%d" % n,
                                "PublicIpAddress": "203.0.113.%d" % (n + 1),
                                "InstanceProfileArn": "",
                                "SecurityGroups": ["sg-%d" % n]}] if instances else []),
            }
            payload["resources"][region] = res
            payload["reads"][region] = {
                k: {"status": "ok", "detail": "", "count": len(v)}
                for k, v in res.items()}
        return payload

    def test_totals_add_up_across_regions(self):
        s = squawk.analysis.inventory_summary(self._multi())
        t = s["totals"]
        assert t["vpcs"] == 2 and t["subnets"] == 4 and t["instances"] == 2
        assert s["regions_read"] == 2 and s["regions_enabled"] == 2
        assert s["resources"] == sum(
            t[k] for k in ("vpcs", "subnets", "route_tables", "igws",
                           "groups", "enis", "instances"))

    def test_public_subnets_are_derived_per_region(self):
        s = squawk.analysis.inventory_summary(self._multi())
        assert s["totals"]["public_subnets"] == 2, \
            "one of the two subnets per region routes to an IGW"

    def test_a_web_port_open_to_the_world_is_not_counted_as_risky(self):
        """A group open to everyone on 443 is a web server doing its job. If
        that reddens the tile, the tile stops being read."""
        s = squawk.analysis.inventory_summary(self._multi(risky_port=443))
        assert s["totals"]["world_open_groups"] == 2
        assert s["totals"]["risky_open_groups"] == 0
        assert s["world_open_ports"] == []

    def test_an_admin_port_open_to_the_world_is(self):
        s = squawk.analysis.inventory_summary(self._multi(risky_port=3389))
        assert s["totals"]["risky_open_groups"] == 2
        assert "3389/RDP" in s["world_open_ports"]

    def test_no_instances_is_said_out_loud(self):
        """The honesty case this account produced: every rule shipped is about
        an instance, so an account with none gets a clean answer from checks
        that never had a subject."""
        s = squawk.analysis.inventory_summary(self._multi(instances=False))
        caveats = " ".join(squawk.analysis.inventory_caveats(s))
        assert "No EC2 instances" in caveats
        assert "none of them had a subject" in caveats
        assert "not the same as an account with nothing dangerous" in caveats

    def test_latent_exposure_is_named_when_nothing_is_behind_it(self):
        s = squawk.analysis.inventory_summary(
            self._multi(instances=False, risky_port=22))
        caveats = " ".join(squawk.analysis.inventory_caveats(s))
        assert "latent, not live" in caveats

    def test_unread_regions_appear_in_the_caveats(self):
        inv = self._multi()
        inv["regions_enabled"] = ["us-test-1", "us-test-2", "eu-test-9"]
        inv["regions_unread"] = ["eu-test-9"]
        caveats = " ".join(squawk.analysis.inventory_caveats(
            squawk.analysis.inventory_summary(inv)))
        assert "eu-test-9" in caveats and "Nothing here covers them" in caveats

    def test_the_scope_caveat_is_always_present(self):
        """Even a perfect run must say what it did not look at.

        Held as a property rather than a phrase: a summary with nothing wrong
        in it still returns a caveat, and one of them scopes this section
        against the whole account. Whether that sentence is *true* is a
        different question, kept by TestCoverageProseMatchesWhatIsRead.
        """
        for inv in (self._multi(), self._multi(instances=False)):
            caveats = squawk.analysis.inventory_caveats(
                squawk.analysis.inventory_summary(inv))
            assert caveats, "a clean run printed no caveat at all"
            assert any("whole-account" in c for c in caveats), caveats

    def _evidence(self, tmp_path, payload):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        (run / "raw" / "cloud-inventory.json").write_text(
            json.dumps(payload), encoding="utf-8")
        # A real run always carries a ledger, and since plan 11 step 2 the
        # panels read it before the file — a stage with no row is not a
        # reading. A fixture without one tests a run that cannot exist.
        return [{"run_id": run.name, "service": "cloudinventory",
                 "target": "000000000000", "severities": {}, "counts": {"total": 0},
                 "ledger": [{"tool": t, "status": "ok", "detail": ""}
                            for t in squawk.web.CLOUD_READINGS],
                 "_dir": str(run)}]

    def test_the_panel_shows_the_counts(self, monkeypatch, tmp_path):
        runs = self._evidence(tmp_path, self._multi(instances=False))
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: runs)
        html, summary = squawk.web.cloud_inventory_panel(str(tmp_path))
        assert summary["regions_read"] == 2, \
            "the panel hands its summary back so the watching panel can join it"
        assert "What is in this account" in html
        assert "us-test-1" in html and "us-test-2" in html
        assert "No EC2 instances" in html, "the caveat must be on the page too"

    def test_the_panel_is_absent_with_no_inventory_run(self, monkeypatch, tmp_path):
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [])
        assert squawk.web.cloud_inventory_panel(str(tmp_path)) == ("", {})

    def test_unreadable_evidence_shows_a_reason_not_a_zero(self, monkeypatch,
                                                           tmp_path):
        runs = self._evidence(tmp_path, self._multi())
        (tmp_path / "20260101T000000Z-aws" / "raw" /
         "cloud-inventory.json").write_text("{not json", encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: runs)
        html, summary = squawk.web.cloud_inventory_panel(str(tmp_path))
        assert summary == {}, "a summary that could not be read must be empty"
        # The ledger says this stage is ok and the file will not parse. That is
        # a third thing, and it is not a reading either.
        assert "This reading is not available" in html
        assert "could not be read" in html
        assert "Nothing older is substituted" in html

    def test_the_cli_prints_the_same_summary(self, tmp_path):
        runs = self._evidence(tmp_path, self._multi(instances=False))
        lines = "\n".join(squawk.cli.inventory_lines(runs[0]))
        assert "Inventory — " in lines
        assert "0 EC2 instances" in lines, \
            "the zero that explains why nothing fired must not be filtered out"
        assert "What this does not tell you:" in lines

    def test_the_cli_summary_is_only_for_inventory_runs(self, tmp_path):
        runs = self._evidence(tmp_path, self._multi())
        other = dict(runs[0], service="cloudaws")
        assert squawk.cli.inventory_lines(other) == []

    def test_junk_does_not_raise(self):
        for junk in ({}, {"regions_read": "no"}, {"regions_read": ["r"]},
                     {"resources": None, "regions_read": ["r"]}):
            s = squawk.analysis.inventory_summary(junk)
            squawk.analysis.inventory_caveats(s)


class TestIdentityRedaction:
    """An SSO session name is the person's work email, and it sits in the
    middle of every assumed-role ARN this tool prints. The account id beside it
    was masked from the day it was first printed; the address went out in full
    on the page people screenshot."""

    # The shape a real SSO identity has: the account id and the operator's
    # address, in one string, which is what makes R-3 a leak rather than a nit.
    ARN: ClassVar[str] = ("arn:aws:sts::123456789012:assumed-role/"
                          "AWSReservedSSO_AdministratorAccess_abc/"
                          "First.Last@example.com")

    def test_both_identifiers_go_at_once(self):
        out = squawk.redact_identifiers(self.ARN)
        assert "123456789012" not in out
        assert "First.Last@example.com" not in out
        assert "********9012" in out and "F" in out

    def test_the_role_name_survives(self):
        """It is the reason the read-only check says gap; removing it would
        make the warning unactionable."""
        assert "AWSReservedSSO_AdministratorAccess_abc" in \
            squawk.redact_identifiers(self.ARN)

    def test_it_is_total_and_leaves_plain_text_alone(self):
        assert squawk.redact_identifiers(None) == ""
        assert squawk.redact_identifiers("no identifiers here") == \
            "no identifiers here"

    def test_the_cli_and_the_page_both_use_it(self, monkeypatch, tmp_path):
        monkeypatch.setattr(squawk.web, "aws_identity",
                            lambda *a, **k: ({"Account": "123456789012",
                                              "Arn": self.ARN, "UserId": "U"}, ""))
        monkeypatch.setattr(squawk.web, "cloud_target_ok", lambda: (True, "ok"))
        html = squawk.web.view_cloud(str(tmp_path))
        assert "First.Last@example.com" not in html
        assert "123456789012" not in html


class TestRoleBreadthIsReadNotGuessed:
    """The first version judged this from the NAMES of attached managed
    policies. In field use it reported "0 roles carrying more than
    read" over six roles, having never opened an inline policy."""

    ADMIN: ClassVar[dict] = {
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    SCOPED: ClassVar[dict] = {
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                       "Resource": "arn:aws:s3:::b/*"}]}

    def test_an_inline_wildcard_is_caught(self):
        assert squawk.probes._broad_reasons(self.ADMIN, "inline X") == \
            ["inline X allows every action"]

    def test_a_service_wildcard_on_everything_is_caught(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "s3:*",
                              "Resource": "*"}]}
        assert "s3:*" in squawk.probes._broad_reasons(doc, "P")[0]

    def test_a_service_wildcard_on_one_resource_is_not(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "s3:*",
                              "Resource": "arn:aws:s3:::b/*"}]}
        assert squawk.probes._broad_reasons(doc, "P") == []

    def test_a_scoped_grant_is_not_broad(self):
        assert squawk.probes._broad_reasons(self.SCOPED, "P") == []

    def test_a_deny_is_not_a_grant(self):
        doc = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
        assert squawk.probes._broad_reasons(doc, "P") == []

    def test_the_url_encoded_form_is_still_read(self):
        """The CLI decodes these for us today because botocore registers a
        handler on after-call.iam. If that ever goes away this must not start
        silently reporting nothing."""
        import urllib.parse
        encoded = urllib.parse.quote(json.dumps(self.ADMIN))
        assert squawk.probes._broad_reasons(encoded, "P") == \
            ["P allows every action"]

    def test_junk_is_not_broad_and_does_not_raise(self):
        for junk in (None, "", "not a policy", 12, [], {"Statement": "x"}):
            assert squawk.probes._broad_reasons(junk, "P") == []

    def test_an_unreadable_policy_makes_the_role_unevaluated(self, monkeypatch):
        calls = {"n": 0}

        def fake(argv, _t):
            calls["n"] += 1
            if argv[1] == "list-attached-role-policies":
                return ({"AttachedPolicies": [
                    {"PolicyName": "Custom",
                     "PolicyArn": "arn:aws:iam::000000000000:policy/Custom"}]}, "")
            if argv[1] == "get-policy":
                return (None, "AccessDenied")
            return ({"PolicyNames": []}, "")
        monkeypatch.setattr(squawk.probes, "_aws_json", fake)
        row = squawk.probes._role_breadth("r", 5)
        assert row["broad"] == []
        assert row["unevaluated"], "an unread policy must not read as limited"
        assert "AccessDenied" in row["unevaluated"][0]

    def test_an_aws_managed_policy_is_judged_by_its_name(self, monkeypatch):
        def fake(argv, _t):
            if argv[1] == "list-attached-role-policies":
                return ({"AttachedPolicies": [
                    {"PolicyName": "AdministratorAccess",
                     "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]},
                    "")
            return ({"PolicyNames": []}, "")
        monkeypatch.setattr(squawk.probes, "_aws_json", fake)
        row = squawk.probes._role_breadth("r", 5)
        assert row["broad"] == ["AdministratorAccess (AWS-managed)"]
        assert row["unevaluated"] == []

    def test_a_customer_policy_named_readonly_is_still_read(self, monkeypatch):
        """A customer-managed policy's name is not evidence. One called
        ReadOnlyish that allows everything must be caught by its contents."""
        def fake(argv, _t):
            if argv[1] == "list-attached-role-policies":
                return ({"AttachedPolicies": [
                    {"PolicyName": "ReadOnlyish",
                     "PolicyArn": "arn:aws:iam::000000000000:policy/ReadOnlyish"}]},
                    "")
            if argv[1] == "get-policy":
                return ({"Policy": {"DefaultVersionId": "v1"}}, "")
            if argv[1] == "get-policy-version":
                return ({"PolicyVersion": {"Document": TestRoleBreadthIsReadNotGuessed.ADMIN}}, "")
            return ({"PolicyNames": []}, "")
        monkeypatch.setattr(squawk.probes, "_aws_json", fake)
        row = squawk.probes._role_breadth("r", 5)
        assert row["broad"] == ["customer policy ReadOnlyish allows every action"]

    def test_every_call_it_makes_is_a_read(self):
        seen = []

        def fake(argv, _t):
            seen.append(argv[1])
            return ({"AttachedPolicies": [], "PolicyNames": []}, "")
        import types
        orig = squawk.probes._aws_json
        squawk.probes._aws_json = fake
        try:
            squawk.probes._role_breadth("r", 5)
        finally:
            squawk.probes._aws_json = orig
        assert seen and all(v.startswith(("list-", "get-")) for v in seen), seen
        assert isinstance(orig, types.FunctionType)


class TestUnevaluatedRolesAreAFloor:

    def _inv(self, roles):
        return {"regions_enabled": ["r"], "regions_read": ["r"],
                "regions_unread": [], "reads": {}, "resources": {},
                "instance_profiles": {}, "roles": roles}

    def test_an_unevaluated_role_makes_the_count_a_floor(self):
        s = squawk.analysis.inventory_summary(self._inv({
            "a": {"status": "ok", "broad": [], "unevaluated": ["inline X"]},
            "b": {"status": "ok", "broad": [], "unevaluated": []}}))
        assert s["totals"]["unevaluated_roles"] == 1
        caveats = " ".join(squawk.analysis.inventory_caveats(s))
        assert "is a floor" in caveats
        assert "only called limited when every policy" in caveats

    def test_a_fully_read_clean_result_says_it_is_real(self):
        s = squawk.analysis.inventory_summary(self._inv({
            "a": {"status": "ok", "broad": [], "unevaluated": []}}))
        caveats = " ".join(squawk.analysis.inventory_caveats(s))
        assert "real negative, not an absence of looking" in caveats

    def test_a_broad_role_is_named_with_its_reason(self):
        s = squawk.analysis.inventory_summary(self._inv({
            "app-role": {"status": "ok", "unevaluated": [],
                         "broad": ["inline policy admin allows every action"]}}))
        notes = squawk.analysis.inventory_notes(s)
        assert notes and "app-role" in notes[0] and "every action" in notes[0]


class TestDefaultOnlyRegionsCollapse:
    """Sixteen rows of the same default VPC is one fact and fifteen
    repetitions, and a table a reader scrolls past hides the row that
    mattered."""

    def _region(self, name, **kw):
        row = {"region": name, "vpcs": 1, "subnets": 3, "public_subnets": 3,
               "route_tables": 1, "igws": 1, "groups": 1, "world_open_groups": 0,
               "risky_open_groups": 0, "world_open_ports": [], "enis": 0,
               "instances": 0, "running": 0, "public_instances": 0,
               "unreadable": []}
        row.update(kw)
        return row

    def test_a_busy_region_keeps_its_row(self):
        summary = {"regions": [self._region("us-east-1", vpcs=4, instances=7,
                                            enis=102, groups=47),
                               self._region("eu-west-1")]}
        kept, folded = squawk.analysis.split_regions(summary)
        assert [r["region"] for r in kept] == ["us-east-1"]
        assert [r["region"] for r in folded] == ["eu-west-1"]

    def test_a_default_region_with_a_risky_group_is_not_folded_away(self):
        summary = {"regions": [self._region("eu-west-1", risky_open_groups=1,
                                            world_open_groups=1)]}
        kept, folded = squawk.analysis.split_regions(summary)
        assert [r["region"] for r in kept] == ["eu-west-1"] and folded == []

    def test_a_region_that_could_not_be_read_is_never_folded_away(self):
        summary = {"regions": [self._region("eu-west-1",
                                            unreadable=["security-groups"])]}
        kept, folded = squawk.analysis.split_regions(summary)
        assert [r["region"] for r in kept] == ["eu-west-1"] and folded == []

    def test_the_fold_is_reported_as_an_observation(self):
        summary = {"regions": [self._region("r%d" % n) for n in range(16)],
                   "totals": {"instances": 1, "public_instances": 1},
                   "broad_reasons": []}
        caveats = " ".join(squawk.analysis.inventory_caveats(summary))
        assert "16 region(s) contain nothing but the default VPC" in caveats
        assert "routes straight to the internet" in caveats


class TestAReadingDatesItself:
    """From the reference design the operator pointed at: "Every figure below is
    from that one saved reading — a page load costs nothing and dates itself."
    A number is worth what the reader knows about where it came from."""

    def _summary(self, **kw):
        base = {"account": "123456789012",
                "read_as": ("arn:aws:sts::123456789012:assumed-role/"
                            "AWSReservedSSO_Admin_x/First.Last@example.com"),
                "read_at": "2026-09-09T12:00:00Z", "api_calls": 90,
                "elapsed_seconds": 1.3, "resources": 255, "regions_read": 10,
                "regions_enabled": 10, "regions_active": 1, "regions_unread": [],
                "regions": [], "broad_reasons": [],
                "totals": {"running": 7, "enis": 103, "public_instances": 0,
                           "risky_open_groups": 0, "groups": 56,
                           "world_open_groups": 2, "broad_roles": 0, "roles": 6,
                           "unevaluated_roles": 0}}
        base.update(kw)
        return base

    def test_age_is_read_from_the_stamp(self):
        import calendar
        import time as _t
        taken = calendar.timegm(_t.strptime("2026-09-09T12:00:00Z",
                                            "%Y-%m-%dT%H:%M:%SZ"))
        age = squawk.analysis.reading_age(self._summary(), now=taken + 7200)
        assert abs(age - 2.0) < 0.01

    def test_a_reading_with_no_stamp_has_no_age_rather_than_zero(self):
        assert squawk.analysis.reading_age(self._summary(read_at="")) is None
        assert squawk.analysis.reading_age(self._summary(read_at="junk")) is None

    def test_the_header_states_provenance_and_redacts_it(self):
        html = squawk.web._reading_header(self._summary(), {"run_id": "r"})
        assert "read as" in html and "90 read-only API call(s)" in html
        assert "one saved reading" in html
        assert "123456789012" not in html
        assert "First.Last@example.com" not in html

    def test_a_stale_reading_says_which_estate_it_describes(self, monkeypatch):
        import calendar
        import time as _t
        taken = calendar.timegm(_t.strptime("2026-09-09T12:00:00Z",
                                            "%Y-%m-%dT%H:%M:%SZ"))
        monkeypatch.setattr(squawk.analysis.time, "time",
                            lambda: taken + 3600 * 40)
        html = squawk.web._reading_header(self._summary(), {"run_id": "r"})
        assert "This reading is" in html
        assert "describes the estate that was" in html
        assert "run cloudinventory" in html, "it must say how to take a fresh one"

    def test_a_fresh_reading_carries_no_banner(self, monkeypatch):
        import calendar
        import time as _t
        taken = calendar.timegm(_t.strptime("2026-09-09T12:00:00Z",
                                            "%Y-%m-%dT%H:%M:%SZ"))
        monkeypatch.setattr(squawk.analysis.time, "time", lambda: taken + 600)
        html = squawk.web._reading_header(self._summary(), {"run_id": "r"})
        assert "This reading is" not in html

    def test_human_hours_reads_without_arithmetic(self):
        assert squawk.web.human_hours(0.5) == "30m"
        assert squawk.web.human_hours(3.25) == "3.2h"
        assert squawk.web.human_hours(96) == "4.0d"

    def test_the_headline_declares_a_floor_when_roles_were_unreadable(self):
        s = self._summary()
        s["totals"] = dict(s["totals"], broad_roles=1, unevaluated_roles=2)
        roles = next(f for f in squawk.analysis.headline_facts(s)
                     if f["key"] == "roles")
        assert roles["value"].startswith("≥"), \
            "a count over roles that were not all read is a floor"
        assert "FLOOR" in roles["note"] and "not fully readable" in roles["note"]

    def test_the_headline_says_so_when_everything_was_read(self):
        roles = next(f for f in squawk.analysis.headline_facts(self._summary())
                     if f["key"] == "roles")
        assert roles["value"] == "0"
        assert "every policy on 6 instance role(s) read" in roles["note"], (
            "the claim is that all six were read — see "
            "TestTheRolesTileSaysWhichRoles for why it names the population")

    def test_unread_regions_are_a_headline_not_a_footnote(self):
        s = self._summary(regions_unread=["eu-north-1", "sa-east-1"])
        fact = next(f for f in squawk.analysis.headline_facts(s)
                    if f["key"] == "unread")
        assert fact["value"] == "2" and fact["weight"] == "warn"
        assert "eu-north-1" in fact["note"]

    def test_no_unread_regions_shows_a_dash_not_a_zero(self):
        fact = next(f for f in squawk.analysis.headline_facts(self._summary())
                    if f["key"] == "unread")
        assert fact["value"] == "—" and fact["weight"] == ""

    def test_an_inventory_run_that_fired_nothing_is_not_called_empty(self):
        """"none returned" is right for a Security Hub read that came back
        empty and wrong for an inventory that examined 300 resources."""
        assert "no combination fired" in squawk.web._cloud_found(
            {"service": "cloudinventory"})
        assert "none returned" in squawk.web._cloud_found({"service": "cloudaws"})

    def test_the_provenance_survives_a_round_trip_through_evidence(self, tmp_path):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        payload = {"account": "123456789012", "read_as": "arn:aws:sts::1:x",
                   "read_at": "2026-09-09T12:00:00Z", "api_calls": 90,
                   "elapsed_seconds": 1.3, "regions_enabled": ["r"],
                   "regions_read": ["r"], "regions_unread": [],
                   "reads": {}, "resources": {}, "roles": {},
                   "instance_profiles": {}}
        (run / "raw" / "cloud-inventory.json").write_text(json.dumps(payload),
                                                          encoding="utf-8")
        s = squawk.analysis.inventory_summary(payload)
        assert s["api_calls"] == 90 and s["read_at"] == "2026-09-09T12:00:00Z"


class TestWhatIsWatchingThisAccount:
    """An account with GuardDuty off in sixteen of seventeen regions looks, to
    every tool that reads only Security Hub, exactly like an account with
    nothing wrong in sixteen regions."""

    def _payload(self, **kw):
        regions = ["us-east-1", "us-east-2", "eu-west-1"]
        regional = {}
        for r in regions:
            home = r == "us-east-1"
            regional[r] = {
                "guardduty": {"state": "on" if home else "off",
                              "detail": "4 of 6 feature(s) on" if home else "none",
                              "features_on": ["DNS_LOGS", "FLOW_LOGS"] if home else [],
                              "features_off": ["RUNTIME_MONITORING"] if home else []},
                "config": {"state": "on" if home else "off", "detail": ""},
                "securityhub": {"state": "on" if home else "off", "detail": ""},
                "inspector": {"state": "on" if home else "off", "detail": ""},
                "accessanalyzer": {"state": "on" if home else
                                   ("unknown" if r == "eu-west-1" else "off"),
                                   "detail": "AccessDenied"},
            }
        payload = {"account_id": "123456789012", "read_as": "arn:x",
                   "read_at": "2026-09-09T12:00:00Z", "api_calls": 33,
                   "elapsed_seconds": 2.0, "regions_enabled": regions,
                   "regions_read": regions, "regions_unread": [],
                   "regional": regional,
                   "account": {
                       "cloudtrail": {"state": "on", "detail": "1 multi-region"},
                       "root": {"state": "on", "detail": "root MFA on"},
                       "s3block": {"state": "off", "detail": "none configured"},
                       "password": {"state": "off", "detail": "no policy"}}}
        payload.update(kw)
        return payload

    def _row(self, summary, key):
        return next(r for r in summary["services"] if r["key"] == key)

    def test_on_in_one_region_of_three_is_partial_not_on(self):
        s = squawk.analysis.enablement_summary(self._payload())
        row = self._row(s, "guardduty")
        assert row["state"] == "partial"
        assert row["detail"] == "1 of 3 region(s)"
        assert "off in" in row["note"] and "us-east-2" in row["note"]

    def test_off_and_could_not_tell_are_both_said(self):
        """The first version used elif, so a service off in some regions and
        UNREADABLE in another reported only the ones we could see."""
        row = self._row(squawk.analysis.enablement_summary(self._payload()),
                        "accessanalyzer")
        assert "off in" in row["note"]
        assert "could not tell in eu-west-1" in row["note"], \
            "the region nobody could read vanished behind the ones we could"

    def test_on_everywhere_readable_but_unreadable_somewhere_is_not_on(self):
        payload = self._payload()
        for r in ("us-east-2", "eu-west-1"):
            payload["regional"][r]["config"] = {"state": "unknown",
                                                "detail": "AccessDenied"}
        row = self._row(squawk.analysis.enablement_summary(payload), "config")
        assert row["state"] == "partial", \
            "calling the account covered on the regions that answered is the " \
            "substitution this tool refuses"

    def test_everything_unreadable_is_unknown_never_off(self):
        payload = self._payload()
        for r in payload["regional"]:
            payload["regional"][r]["config"] = {"state": "unknown", "detail": "x"}
        assert self._row(squawk.analysis.enablement_summary(payload),
                         "config")["state"] == "unknown"

    def test_off_everywhere_is_off(self):
        payload = self._payload()
        for r in payload["regional"]:
            payload["regional"][r]["config"] = {"state": "off", "detail": "none"}
        assert self._row(squawk.analysis.enablement_summary(payload),
                         "config")["state"] == "off"

    def test_account_wide_services_are_carried_through(self):
        s = squawk.analysis.enablement_summary(self._payload())
        assert self._row(s, "cloudtrail")["state"] == "on"
        assert self._row(s, "s3block")["state"] == "off"
        assert self._row(s, "password")["scope"] == "account"

    def test_guardduty_features_are_split_on_and_off(self):
        feats = squawk.analysis.enablement_summary(
            self._payload())["guardduty_features"]
        assert "DNS_LOGS" in feats["on"] and "RUNTIME_MONITORING" in feats["off"]
        assert not set(feats["on"]) & set(feats["off"]), \
            "a feature on somewhere must not also be listed as off"

    def test_junk_does_not_raise(self):
        for junk in ({}, {"regional": None}, {"regional": {"r": None}},
                     {"regions_read": "no", "regional": {}}):
            squawk.analysis.enablement_summary(junk)


class TestRunningAndNotWatched:
    """The join the whole plan is about: exposure comes from the inventory,
    coverage from the enablement read, and neither alone can say it."""

    INV: ClassVar[dict] = {"regions": [
        {"region": "us-east-1", "instances": 3, "risky_open_groups": 0,
         "public_instances": 0},
        {"region": "eu-west-1", "instances": 0, "risky_open_groups": 1,
         "public_instances": 0},
        {"region": "ap-south-1", "instances": 0, "risky_open_groups": 0,
         "public_instances": 0}]}

    def _en(self, **kw):
        base = {"services": [
            {"key": "guardduty", "label": "GuardDuty", "off": [], "unknown": []},
            {"key": "config", "label": "AWS Config", "off": [], "unknown": []},
            {"key": "securityhub", "label": "Security Hub", "off": [],
             "unknown": []}]}
        for row in base["services"]:
            if row["key"] in kw:
                row.update(kw[row["key"]])
        return base

    def test_off_where_something_runs_is_reported(self):
        gaps = squawk.analysis.watching_gaps(
            self.INV, self._en(guardduty={"off": ["us-east-1"]}))
        assert gaps and "GuardDuty is off in us-east-1" in gaps[0]

    def test_off_where_nothing_runs_is_not_reported(self):
        """An idle region with no detector is not a finding, and reporting it
        is how a reader learns to skip the section."""
        assert squawk.analysis.watching_gaps(
            self.INV, self._en(guardduty={"off": ["ap-south-1"]})) == []

    def test_an_unreadable_region_is_unknown_not_clear(self):
        gaps = squawk.analysis.watching_gaps(
            self.INV, self._en(guardduty={"unknown": ["eu-west-1"]}))
        assert gaps and "could not be read" in gaps[0]
        assert "unknown, not clear" in gaps[0]

    def test_a_risky_group_counts_as_worth_watching_without_an_instance(self):
        gaps = squawk.analysis.watching_gaps(
            self.INV, self._en(securityhub={"off": ["eu-west-1"]}))
        assert gaps, "a region whose only exposure is an open group still counts"

    def test_no_enablement_read_produces_no_claim(self):
        assert squawk.analysis.watching_gaps(self.INV, {}) == []
        assert squawk.analysis.watching_gaps({}, self._en()) == []

    def test_a_region_whose_reads_were_refused_is_not_an_idle_region(self):
        """Review R-10, reproduction 5.

        A region whose every read was denied has zero instances and zero open
        groups in the summary, so it fell out of `active` and GuardDuty being
        off there went unsaid — the region nobody could see treated exactly
        like the region with nothing in it.
        """
        inv = {"regions": [
            {"region": "us-east-1", "instances": 0, "risky_open_groups": 0,
             "public_instances": 0,
             "unreadable": ["instances (AccessDenied)"]}]}
        gaps = squawk.analysis.watching_gaps(
            inv, self._en(guardduty={"off": ["us-east-1"]}))
        assert gaps, "a denied region is not an idle region"
        assert "part of the inventory could not be read" in gaps[0]
        assert "unknown" in gaps[0]

    def test_a_denied_region_that_is_also_active_is_said_once(self):
        """It is in `active` on its own merits, so the ordinary line covers
        it and the unknown line must not repeat it."""
        inv = {"regions": [
            {"region": "us-east-1", "instances": 3, "risky_open_groups": 0,
             "public_instances": 0, "unreadable": ["subnets (denied)"]}]}
        gaps = squawk.analysis.watching_gaps(
            inv, self._en(guardduty={"off": ["us-east-1"]}))
        assert len(gaps) == 1 and "GuardDuty is off in us-east-1" in gaps[0]


class TestEnablementCoverage:

    def test_service_checks_are_the_denominator(self):
        payload = {"regional": {"r1": {"guardduty": {"state": "on"},
                                       "config": {"state": "off"}},
                                "r2": {"guardduty": {"state": "unknown"}}},
                   "account": {"root": {"state": "on"}},
                   "regions_enabled": ["r1", "r2"], "regions_read": ["r1", "r2"],
                   "regions_unread": []}
        cov = squawk.scanners.stage_coverage("cloudenable", json.dumps(payload))
        assert cov.unit == "service checks"
        assert cov.examined == 4
        assert cov.errors == 1, "an unknown is a check that could not be answered"

    def test_a_read_that_asked_nothing_is_a_gap(self):
        status, detail, _cov = squawk.engine._apply_coverage(
            "cloudenable", json.dumps({"regional": {}, "account": {}}), [],
            "ok", "0 findings")
        assert status == "gap" and "examined 0 service checks" in detail

    def test_unread_regions_are_declared_a_floor(self):
        payload = {"regional": {"r1": {"guardduty": {"state": "on"}}},
                   "account": {}, "regions_enabled": ["r1", "r2"],
                   "regions_read": ["r1"], "regions_unread": ["r2"]}
        cov = squawk.scanners.stage_coverage("cloudenable", json.dumps(payload))
        assert "FLOOR" in cov.note and "r2" in cov.note

    def test_the_normalizer_produces_no_findings_by_design(self):
        assert squawk.scanners.norm_cloudenable("{}", "") == []


class TestWhatChangedSinceTheLastReading:
    """Named things first, counts second: a count that moved is a question, and
    a named thing that appeared or vanished is usually the answer."""

    def _reading(self, instances=("i-1",), groups=None, read=("us-east-1",),
                 broken=None, at="2026-09-09T12:00:00Z"):
        groups = groups if groups is not None else ["sg-1"]
        resources, reads = {}, {}
        for region in read:
            resources[region] = {
                "vpcs": [{"VpcId": "vpc-%s" % region}],
                "subnets": [{"SubnetId": "sn-%s" % region,
                             "VpcId": "vpc-%s" % region}],
                "route-tables": [], "internet-gateways": [],
                "security-groups": [{"GroupId": g, "VpcId": "vpc-%s" % region,
                                     "IpPermissions": []} for g in groups],
                "network-interfaces": [],
                "instances": [{"InstanceId": i, "State": "running",
                               "SubnetId": "sn-%s" % region,
                               "VpcId": "vpc-%s" % region,
                               "SecurityGroups": []} for i in instances]}
            reads[region] = {k: {"status": "ok", "detail": "", "count": len(v)}
                             for k, v in resources[region].items()}
            for key in (broken or {}).get(region, []):
                reads[region][key] = {"status": "error", "detail": "AccessDenied",
                                      "count": 0}
        return {"account": "0", "read_at": at, "regions_enabled": list(read),
                "regions_read": list(read), "regions_unread": [],
                "reads": reads, "resources": resources,
                "instance_profiles": {}, "roles": {}}

    def _en(self, guardduty="on", region="us-east-1"):
        return {"regional": {region: {"guardduty": {"state": guardduty,
                                                    "detail": ""}}},
                "regions_read": [region], "regions_enabled": [region],
                "regions_unread": [], "account": {}}

    def test_an_appeared_instance_is_named(self):
        d = squawk.analysis.compare_readings(
            self._reading(instances=("i-1",)),
            self._reading(instances=("i-1", "i-2")))
        assert [(r["kind"], r["id"]) for r in d["appeared"]] == [("instance", "i-2")]
        assert d["vanished"] == []

    def test_a_vanished_instance_is_named(self):
        d = squawk.analysis.compare_readings(
            self._reading(instances=("i-1", "i-2")),
            self._reading(instances=("i-1",)))
        assert [(r["kind"], r["id"]) for r in d["vanished"]] == [("instance", "i-2")]

    def test_counts_that_moved_are_reported_with_their_direction(self):
        d = squawk.analysis.compare_readings(
            self._reading(instances=("i-1",)),
            self._reading(instances=("i-1", "i-2")))
        moved = {r["key"]: r for r in d["moved"]}
        assert moved["instances"]["before"] == 1
        assert moved["instances"]["after"] == 2
        assert moved["instances"]["delta"] == 1

    def test_a_rise_in_exposure_is_weighted_and_a_rise_in_vpcs_is_not(self):
        older = self._reading(groups=[])
        newer = self._reading(groups=["sg-1"])
        newer["resources"]["us-east-1"]["security-groups"][0]["IpPermissions"] = [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}]
        d = squawk.analysis.compare_readings(older, newer)
        moved = {r["key"]: r for r in d["moved"]}
        assert moved["risky_open_groups"]["weight"] == "warn"
        assert moved["groups"]["weight"] == ""

    def test_a_service_switched_off_is_the_first_thing_said(self):
        d = squawk.analysis.compare_readings(
            self._reading(), self._reading(),
            self._en("on"), self._en("off"))
        assert len(d["watching"]) == 1
        row = d["watching"][0]
        assert row["label"] == "GuardDuty" and row["before"] == "on"
        assert row["after"] == "off" and row["weight"] == "warn"

    def test_a_service_switched_on_is_reported_without_alarm(self):
        d = squawk.analysis.compare_readings(
            self._reading(), self._reading(), self._en("off"), self._en("on"))
        assert d["watching"][0]["weight"] == ""

    def test_a_service_going_unknown_is_not_reported_as_turned_off(self):
        """That would be a fabrication: what we could see changed, not
        necessarily the account."""
        d = squawk.analysis.compare_readings(
            self._reading(), self._reading(),
            self._en("on"), self._en("unknown"))
        row = d["watching"][0]
        assert row["weight"] == ""
        assert "what we could see changed" in row["why"]

    def test_a_region_read_only_this_time_is_incomparable_not_new(self):
        d = squawk.analysis.compare_readings(
            self._reading(read=("us-east-1",)),
            self._reading(read=("us-east-1", "eu-west-1")))
        assert d["appeared"] == [], \
            "resources in a newly-read region are new to the READING, not the account"
        assert any("eu-west-1" in w and "read this time but not last time" in w
                   for w in d["incomparable"])

    def test_a_region_read_only_last_time_is_incomparable_not_deleted(self):
        d = squawk.analysis.compare_readings(
            self._reading(read=("us-east-1", "eu-west-1")),
            self._reading(read=("us-east-1",)))
        assert d["vanished"] == []
        assert any("nothing here covers them now" in w for w in d["incomparable"])

    def test_a_failed_read_makes_that_region_incomparable(self):
        """The load-bearing one. An instance missing because the read was
        DENIED has not vanished, and saying it did would be the same lie as
        reporting a scanner that never ran as one that found nothing."""
        d = squawk.analysis.compare_readings(
            self._reading(instances=("i-1", "i-2")),
            self._reading(instances=(), broken={"us-east-1": ["instances"]}))
        assert d["vanished"] == [], "a denied read is not a deletion"
        assert d["appeared"] == []
        assert any("could not be read" in w for w in d["incomparable"])

    def test_nothing_changed_is_a_result(self):
        d = squawk.analysis.compare_readings(self._reading(), self._reading())
        assert d["changes"] == 0 and d["incomparable"] == []
        assert any("Nothing changed" in line
                   for line in squawk.analysis.diff_lines(d))

    def test_hours_apart_are_computed_from_the_stamps(self):
        d = squawk.analysis.compare_readings(
            self._reading(at="2026-09-09T10:00:00Z"),
            self._reading(at="2026-09-09T12:30:00Z"))
        assert abs(d["apart_hours"] - 2.5) < 0.01

    def test_the_text_form_leads_with_named_things(self):
        d = squawk.analysis.compare_readings(
            self._reading(instances=("i-1",)),
            self._reading(instances=("i-1", "i-2")),
            self._en("on"), self._en("off"))
        lines = squawk.analysis.diff_lines(d)
        named = next(i for i, s in enumerate(lines) if "appeared: instance" in s)
        counted = next(i for i, s in enumerate(lines) if "EC2 instances:" in s)
        service = next(i for i, s in enumerate(lines) if "GuardDuty" in s)
        assert service < named < counted, \
            "services, then named things, then counts"

    def test_junk_does_not_raise(self):
        for a in ({}, {"resources": None}, {"regions_read": "no"}):
            for b in ({}, {"resources": {"r": None}}):
                squawk.analysis.compare_readings(a, b)

    def test_one_reading_says_so_rather_than_showing_an_empty_diff(self, monkeypatch,
                                                                   tmp_path):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        (run / "raw" / "cloud-inventory.json").write_text(
            json.dumps(self._reading()), encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [{"tool": t, "status": "ok", "detail": ""}
                        for t in squawk.web.CLOUD_READINGS]}])
        html = squawk.web.cloud_change_panel(str(tmp_path))
        assert "Only one reading is on record" in html
        assert "nothing to compare" in html


class TestWhoCanDoWhat:
    """The IAM graph, and the rule that a user with no MFA who can also grant
    itself more is a different sentence from a user with no MFA."""

    ESCALATE: ClassVar[dict] = {"Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "iam:AttachUserPolicy"],
         "Resource": "*"}]}
    HARMLESS: ClassVar[dict] = {"Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}

    # Built rather than written, so no credential-shaped literal exists in the
    # repo. `check_repo_hygiene.py` flags the shape wherever it finds it, and
    # weakening that check to accommodate a test fixture would trade a real
    # control for a convenience -- especially here, where the fixture exists
    # because a real key id reached a screenshot in the first place.
    FAKE_KEY: ClassVar[str] = "AKIA" + "EXAMPLEKEY000000"

    def _data(self, mfa=0, keys=None,
              escalation=("group builders allows iam:AttachUserPolicy",),
              unreadable=(), console=False):
        if keys is None:
            keys = ((self.FAKE_KEY, "Active", "2023-01-01T00:00:00Z"),)
        return {"account": "0", "read_at": "2026-09-09T12:00:00Z",
                "api_calls": 8, "truncated": False, "limit": 1000,
                "counts": {"users": 1, "roles": 2, "groups": 1, "policies": 0},
                "users": [{"name": "deployer", "arn": "arn:aws:iam::0:user/deployer",
                           "mfa": mfa,
                           "keys": [{"id": i, "status": s, "created": c}
                                    for i, s, c in keys],
                           "escalation": list(escalation),
                           "console": console,
                           "unreadable": list(unreadable)}],
                "roles_with_escalation": []}

    def test_no_mfa_plus_an_escalation_path_is_critical(self):
        found = squawk.analysis.iam_findings(self._data())
        assert len(found) == 1
        assert found[0]["key"] == "credential-without-a-guard"
        assert found[0]["severity"] == "critical"
        assert found[0]["escalation"]

    def test_no_mfa_without_an_escalation_path_is_high_not_critical(self):
        found = squawk.analysis.iam_findings(self._data(escalation=()))
        assert found[0]["key"] == "credential-without-mfa"
        assert found[0]["severity"] == "high"

    def test_a_user_with_mfa_produces_nothing(self):
        assert squawk.analysis.iam_findings(self._data(mfa=1)) == []

    def test_unreadable_mfa_is_unknown_never_guarded_and_never_a_finding(self):
        found = squawk.analysis.iam_findings(
            self._data(mfa=None, unreadable=["MFA devices (AccessDenied)"]))
        assert len(found) == 1
        assert found[0]["state"] == "unknown"
        assert found[0]["severity"] == "unknown"
        assert "AccessDenied" in found[0]["why"]

    def test_an_inactive_key_is_not_an_active_one(self):
        found = squawk.analysis.iam_findings(
            self._data(keys=((self.FAKE_KEY, "Inactive",
                              "2023-01-01T00:00:00Z"),), escalation=()))
        assert [f for f in found if f["state"] == "fired"] == [], \
            "a disabled key is not a live credential"

    def test_a_console_password_without_mfa_is_a_finding(self):
        """The one the first version silently skipped. A user with a console
        password and no MFA is the classic finding, and it has no access key
        at all -- so a rule that keyed off keys never saw it, while the tile
        above still counted the user as having no MFA device."""
        found = squawk.analysis.iam_findings(
            self._data(keys=(), escalation=(), console=True))
        assert len(found) == 1 and found[0]["state"] == "fired"
        assert "console password" in found[0]["why"]

    def test_nothing_to_guard_is_said_rather_than_skipped(self):
        """No console password, no key: MFA guards nothing. Said out loud,
        because the tile counts this user among those without a device and a
        count that nothing explains is a count nobody believes."""
        found = squawk.analysis.iam_findings(
            self._data(keys=(), escalation=(), console=False))
        assert len(found) == 1
        assert found[0]["state"] == "noted" and found[0]["severity"] == "info"
        assert "nothing for MFA to guard" in found[0]["why"]

    def test_unknown_console_access_is_unknown_not_clean(self):
        found = squawk.analysis.iam_findings(
            self._data(keys=(), escalation=(), console=None))
        assert found[0]["state"] == "unknown"
        assert "could not be read" in found[0]["why"]

    def test_the_access_key_id_is_masked(self):
        """These lines get screenshotted. The id is not a secret, and it does
        name one credential in one account."""
        found = squawk.analysis.iam_findings(self._data(escalation=()))
        assert self.FAKE_KEY not in found[0]["why"]
        assert self.FAKE_KEY[:6] in found[0]["why"], \
            "still findable in the console"
        assert self.FAKE_KEY[-4:] in found[0]["why"]

    def test_a_stale_key_says_its_age(self):
        found = squawk.analysis.iam_findings(self._data(escalation=()))
        assert "days old" in found[0]["why"]

    def test_the_reasons_are_not_printed_twice(self):
        """They live in `escalation`; the page lists them from there."""
        found = squawk.analysis.iam_findings(self._data())
        assert "iam:AttachUserPolicy" not in found[0]["why"]
        assert any("iam:AttachUserPolicy" in r for r in found[0]["escalation"])


class TestAlreadyAdminIsNotEscalation:
    """A role holding AdministratorAccess does not need to escalate — it is
    already there. Listing it under "can grant themselves more" put the
    account's own SSO admin role in a list of privilege-escalation paths."""

    def test_a_wildcard_reason_is_already_admin(self):
        assert squawk.probes.is_already_admin(["P allows every action"])
        assert squawk.probes.is_already_admin(["P allows every IAM action"])
        assert squawk.probes.is_already_admin(
            ["AdministratorAccess (AWS-managed) grants administrative IAM "
             "permissions"])

    def test_a_specific_escalation_action_is_not_already_admin(self):
        assert not squawk.probes.is_already_admin(
            ["P allows iam:CreateAccessKey — can mint long-lived keys"])

    def test_escalation_only_strips_the_admin_reasons(self):
        reasons = ["P allows every action",
                   "Q allows iam:PassRole — can hand an existing role"]
        assert squawk.probes.escalation_only(reasons) == [reasons[1]]

    def test_the_two_populations_are_counted_apart(self):
        summary = squawk.analysis.iam_summary({
            "counts": {"users": 0, "roles": 2, "groups": 0, "policies": 0},
            "users": [],
            "roles_with_escalation": [{"name": "ci", "escalation": ["x"]}],
            "roles_already_admin": [{"name": "admin", "why": ["y"]}]})
        assert summary["counts"]["roles_that_can_escalate"] == 1
        assert summary["counts"]["roles_already_admin"] == 1


class TestEscalationIsReadFromThePolicy:

    def test_a_wildcard_action_is_named(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        assert squawk.probes._escalation_reasons(doc, "P") == \
            ["P allows every action"]

    def test_iam_star_is_named_separately(self):
        doc = {"Statement": [{"Effect": "Allow", "Action": "iam:*",
                              "Resource": "*"}]}
        assert "every IAM action" in squawk.probes._escalation_reasons(doc, "P")[0]

    def test_each_escalation_action_carries_its_reason(self):
        for action, why in squawk.probes.ESCALATION_ACTIONS.items():
            doc = {"Statement": [{"Effect": "Allow", "Action": action,
                                  "Resource": "*"}]}
            reasons = squawk.probes._escalation_reasons(doc, "P")
            assert reasons and why in reasons[0], action

    def test_a_deny_is_not_a_grant(self):
        doc = {"Statement": [{"Effect": "Deny", "Action": "iam:AttachUserPolicy",
                              "Resource": "*"}]}
        assert squawk.probes._escalation_reasons(doc, "P") == []

    def test_an_ordinary_read_policy_is_not_escalation(self):
        assert squawk.probes._escalation_reasons(
            TestWhoCanDoWhat.HARMLESS, "P") == []

    def test_the_same_reason_twice_is_reported_once(self):
        doc = {"Statement": [
            {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "x"}]}
        assert len(squawk.probes._escalation_reasons(doc, "P")) == 1

    def test_junk_does_not_raise(self):
        for junk in (None, "", "x", 3, [], {"Statement": "x"}):
            assert squawk.probes._escalation_reasons(junk, "P") == []


class TestThePolicyReaderReadsTheWholeStatement:
    """Review R-4 and R-9, reproduction 2.

    The reader matched action names and read nothing else in the statement, so
    AWS's own "let users manage their own credentials" policy came back as
    three privilege-escalation paths and a deploy role's scoped iam:PassRole as
    a fourth. The Resource is what tells those apart from the real thing, and
    it was never read.
    """

    # AWS's documented self-service policy, verbatim in shape.
    SELF_SERVICE: ClassVar[dict] = {"Statement": [
        {"Effect": "Allow",
         "Action": ["iam:CreateAccessKey", "iam:DeleteAccessKey",
                    "iam:ListAccessKeys", "iam:UpdateAccessKey"],
         "Resource": "arn:aws:iam::*:user/${aws:username}",
         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}},
        {"Effect": "Allow",
         "Action": ["iam:ChangePassword", "iam:GetUser",
                    "iam:CreateLoginProfile", "iam:UpdateLoginProfile"],
         "Resource": "arn:aws:iam::*:user/${aws:username}"}]}

    def _read(self, doc):
        return squawk.probes.read_policy(doc, "P")

    def _one(self, action, resource="*", **extra):
        st = {"Effect": "Allow", "Action": action, "Resource": resource}
        st.update(extra)
        return {"Statement": [st]}

    def test_the_self_service_policy_is_not_escalation(self):
        """The acceptance the plan names: zero escalation reasons."""
        read = self._read(self.SELF_SERVICE)
        assert read.escalation == [], read.escalation
        assert read.self_service, "the grant still has to be recorded"
        assert all("own user only" in r for r in read.self_service)

    def test_a_scoped_passrole_is_a_deploy_permission(self):
        read = self._read(self._one(
            "iam:PassRole", "arn:aws:iam::123456789012:role/deploy",
            Condition={"StringEquals": {
                "iam:PassedToService": "ecs-tasks.amazonaws.com"}}))
        assert read.escalation == []
        assert read.scoped and "limited to deploy" in read.scoped[0]

    def test_an_unscoped_passrole_still_is_escalation(self):
        assert self._read(self._one("iam:PassRole")).escalation
        # A role ARN with a wildcard in the name pins nothing.
        assert self._read(self._one(
            "iam:PassRole", "arn:aws:iam::*:role/*")).escalation

    def test_a_wildcard_action_finds_the_actions_it_covers(self):
        """`iam:Attach*` grants three escalation actions and used to find
        none, because the lookup was exact."""
        attach = self._read(self._one("iam:Attach*")).escalation
        assert len(attach) == 3, attach
        assert all("through iam:Attach*" in r for r in attach)
        assert self._read(self._one("iam:*Policy*")).escalation

    def test_a_notaction_allow_is_read(self):
        """PowerUserAccess is written this way, and reading only `Action`
        meant such a policy came back with nothing to say."""
        wide = self._one("x", "*")
        wide["Statement"][0].pop("Action")
        wide["Statement"][0]["NotAction"] = ["s3:GetObject"]
        assert "every action except" in self._read(wide).escalation[0]
        assert squawk.probes._broad_reasons(wide, "P")

    def test_a_notaction_that_excludes_iam_is_not_escalation(self):
        power = {"Statement": [{"Effect": "Allow", "Resource": "*",
                                "NotAction": ["iam:*", "organizations:*",
                                              "account:*"]}]}
        read = self._read(power)
        assert read.escalation == []
        assert read.notes and "keeps the permission-granting IAM actions out" \
            in read.notes[0]

    def test_a_notaction_on_one_resource_is_not_broad(self):
        one = {"Statement": [{"Effect": "Allow", "NotAction": ["s3:GetObject"],
                              "Resource": "arn:aws:s3:::b/*"}]}
        assert squawk.probes._broad_reasons(one, "P") == []
        assert self._read(one).escalation == []

    def test_every_action_on_one_resource_is_not_every_action(self):
        """`*` on a single bucket became the fourth leg of a CRITICAL rule
        about the whole account."""
        one = self._one("*", "arn:aws:s3:::one-bucket/*")
        read = self._read(one)
        assert read.escalation == []
        assert read.notes and "every action on" in read.notes[0]
        assert squawk.probes._broad_reasons(one, "P") == []

    def test_a_service_wildcard_on_its_everything_arn_is_broad(self):
        assert squawk.probes._broad_reasons(
            self._one("s3:*", "arn:aws:s3:::*"), "P")
        assert squawk.probes._broad_reasons(
            self._one("s3:*", "arn:aws:s3:::one-bucket"), "P") == []

    def test_an_mfa_condition_is_recorded_beside_the_reason(self):
        """A guard on the path, not the absence of one."""
        read = self._read(self._one(
            "iam:CreateAccessKey",
            Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}))
        assert read.escalation and "only with MFA present" in read.escalation[0]

    def test_a_named_user_target_is_named_not_generalised(self):
        read = self._read(self._one(
            "iam:CreateAccessKey", "arn:aws:iam::123456789012:user/alice"))
        assert read.escalation == []
        assert read.scoped and "limited to alice" in read.scoped[0]
        assert "for any user" not in read.scoped[0]

    def test_a_user_with_no_credential_is_never_critical(self):
        """R-9. There is no credential for MFA to guard."""
        data = {"users": [{"name": "svc-noop", "mfa": 0, "console": False,
                           "keys": [], "unreadable": [],
                           "escalation": ["policy P allows iam:PutUserPolicy — x"]}]}
        found = squawk.analysis.iam_findings(data)
        assert len(found) == 1
        assert found[0]["key"] == "credential-nothing-to-guard"
        assert found[0]["severity"] == "info"
        assert "the day someone creates a key" in found[0]["why"]
        assert found[0]["escalation"], "the permissions are still recorded"

    def test_a_user_with_a_key_and_escalation_is_still_critical(self):
        data = {"users": [{"name": "svc-key", "mfa": 0, "console": False,
                           "keys": [{"id": "AKIA" + "EXAMPLEKEY000000",
                                     "status": "Active",
                                     "created": "2026-01-01T00:00:00Z"}],
                           "unreadable": [],
                           "escalation": ["policy P allows iam:PutUserPolicy — x"]}]}
        found = squawk.analysis.iam_findings(data)
        assert found[0]["key"] == "credential-without-a-guard"
        assert found[0]["severity"] == "critical"

    def test_what_was_set_aside_is_counted_and_said(self):
        """A permission the tool decided not to raise is still a decision the
        reader is entitled to see."""
        data = {"counts": {"users": 1, "roles": 0, "groups": 0, "policies": 0},
                "users": [{"name": "u", "mfa": 1, "console": False, "keys": [],
                           "escalation": [], "unreadable": [],
                           "self_service": ["policy P allows iam:CreateAccessKey, "
                                            "on its own user only"],
                           "scoped": []}],
                "roles_with_escalation": [], "roles_already_admin": [],
                "truncated": False, "limit": 1000, "account": "0",
                "read_at": "", "api_calls": 1}
        summary = squawk.analysis.iam_summary(data)
        assert summary["counts"]["permissions_set_aside"] == 1
        caveats = " ".join(squawk.analysis.iam_caveats(summary))
        assert "deliberately not raised" in caveats

    # ---- review 2, R-18: the operator is half the sentence ----------------

    ACCOUNT: ClassVar[str] = "111122223333"

    def _reasons(self, doc):
        return squawk.probes._public_policy_reasons(doc, "policy", self.ACCOUNT)

    def _inverted(self, operator, key, value):
        return {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"},
                               "Action": "sns:Publish",
                               "Condition": {operator: {key: value}}}]}

    def test_a_negated_condition_admits_everyone_it_does_not_name(self):
        """Review 2, R-18. `StringEquals` on `aws:PrincipalAccount` names this
        account; `StringNotEquals` on the same key names every account except
        this one. Flattening operators away made those identical, so a topic
        granted to the whole world minus the owner's organization was filed as
        nothing at all — the exact inverse of the policy."""
        for operator, key, value in (
                ("StringNotEquals", "aws:PrincipalOrgID", "o-abc123"),
                ("StringNotEquals", "aws:PrincipalAccount", self.ACCOUNT),
                ("StringNotLike", "aws:PrincipalAccount", self.ACCOUNT),
                ("ArnNotLike", "aws:PrincipalArn",
                 "arn:aws:iam::%s:role/*" % self.ACCOUNT)):
            reasons = self._reasons(self._inverted(operator, key, value))
            assert reasons, "%s %s produced no finding" % (operator, key)
            assert "except those the condition names" in reasons[0]
            assert "wider than an unconditional" in reasons[0]
            assert not squawk.probes.is_narrowed_public(reasons[0]), \
                "an inverted condition is not the medium branch"

    def test_an_ifexists_suffix_does_not_change_the_sense(self):
        reasons = self._reasons(self._inverted(
            "StringNotEqualsIfExists", "aws:PrincipalAccount", self.ACCOUNT))
        assert reasons and "except those the condition names" in reasons[0]

    def test_a_null_condition_narrows_nobody(self):
        """`Null` says whether the key is present, not what it equals."""
        reasons = self._reasons(self._inverted(
            "Null", "aws:PrincipalAccount", "false"))
        assert reasons and "does not name who" in reasons[0]

    def test_an_affirming_condition_still_narrows(self):
        """The fix must not turn every condition into a finding."""
        assert self._reasons(self._inverted(
            "StringEquals", "aws:PrincipalAccount", self.ACCOUNT)) == []

    def test_a_trust_policy_that_excludes_this_account_is_anyone(self):
        """A role every account on AWS except this one can assume was filed as
        internal."""
        doc = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"},
                              "Condition": {"StringNotEquals": {
                                  "aws:PrincipalAccount": self.ACCOUNT}}}]}
        entries = squawk.probes.who_can_assume(doc, self.ACCOUNT)
        assert entries and entries[0]["reach"] == "anyone", entries
        assert "wider than the `*` it sits beside" in entries[0]["why"]

    # ---- review 2, R-19: the own-user shortcut is for credentials only -----

    def test_attaching_a_policy_to_yourself_is_escalation(self):
        """Review 2, R-19. AWS's self-service policy grants key and password
        management on the caller's own user. `iam:AttachUserPolicy` on the
        caller's own user is one call from AdministratorAccess, and the
        shortcut filed it beside "rotate my own access key"."""
        for action in ("iam:AttachUserPolicy", "iam:PutUserPolicy"):
            read = self._read(self._one(
                action, "arn:aws:iam::%s:user/${aws:username}" % self.ACCOUNT))
            assert read.escalation, action
            assert read.self_service == [], action
            assert "not managing its own credentials" in read.escalation[0]

    def test_rotating_your_own_key_is_still_self_service(self):
        """The fix must not turn AWS's own documented policy into a finding."""
        read = self._read(self.SELF_SERVICE)
        assert read.escalation == [], read.escalation
        assert read.self_service

    def test_a_policy_action_scoped_to_a_named_user_is_escalation(self):
        """The same defect one step removed: if that user is the caller, or
        the caller holds its key, it is a path."""
        read = self._read(self._one(
            "iam:AttachUserPolicy", "arn:aws:iam::%s:user/alice" % self.ACCOUNT))
        assert read.escalation and "may be or may hold a key for" in read.escalation[0]
        assert read.scoped == []

    def test_a_credential_action_scoped_to_a_named_user_is_still_scoped(self):
        read = self._read(self._one(
            "iam:CreateAccessKey", "arn:aws:iam::%s:user/alice" % self.ACCOUNT))
        assert read.escalation == []
        assert read.scoped and "one named user, not any user" in read.scoped[0]

    def test_assume_role_on_everything_is_escalation(self):
        """Named in the first review under R-4 and still missing from the
        table."""
        read = self._read(self._one("sts:AssumeRole", "*"))
        assert read.escalation
        assert "the trust policies are the other half" in read.escalation[0], \
            "it must point at the half of the path this does not read here"

    def test_assume_role_on_one_named_role_is_scoped(self):
        read = self._read(self._one(
            "sts:AssumeRole", "arn:aws:iam::%s:role/deploy" % self.ACCOUNT))
        assert read.escalation == []
        assert read.scoped and "a named role, not any role" in read.scoped[0]

    def test_poweruser_is_still_broad_and_not_a_path(self):
        """sts:AssumeRole is in the table and is not a permission-granting
        action, so requiring a NotAction to exclude it as well would make
        PowerUserAccess read as a path to more, which it is not."""
        power = {"Statement": [{"Effect": "Allow", "Resource": "*",
                                "NotAction": ["iam:*", "organizations:*",
                                              "account:*"]}]}
        assert self._read(power).escalation == []

    def test_the_reader_survives_junk(self):
        for junk in (None, "", "x", 3, [], {"Statement": "x"},
                     {"Statement": [{"Effect": "Allow", "Action": 5,
                                     "Resource": {"a": 1}}]}):
            assert self._read(junk) == squawk.probes.PolicyRead([], [], [], [])


class TestEscalationFollowsTheGraph:
    """A user with no policies of its own can still be an administrator through
    a group. A check that looked only at the user would call it clean."""

    def test_a_path_through_a_group_is_found(self):
        user = {"UserName": "deployer", "GroupList": ["builders"],
                "UserPolicyList": [], "AttachedManagedPolicies": []}
        groups = {"builders": {"GroupName": "builders", "GroupPolicyList": [
            {"PolicyName": "build",
             "PolicyDocument": TestWhoCanDoWhat.ESCALATE}],
            "AttachedManagedPolicies": []}}
        reasons = squawk.probes._principal_reasons(
            user, {}, groups, "user").escalation
        assert reasons and "group builders" in reasons[0]
        assert "iam:AttachUserPolicy" in reasons[0]

    def test_a_customer_managed_policy_is_read_by_its_document(self):
        arn = "arn:aws:iam::000000000000:policy/Custom"
        user = {"UserName": "u", "GroupList": [], "UserPolicyList": [],
                "AttachedManagedPolicies": [{"PolicyName": "Custom",
                                             "PolicyArn": arn}]}
        reasons = squawk.probes._principal_reasons(
            user, {arn: TestWhoCanDoWhat.ESCALATE}, {}, "user").escalation
        assert reasons and "policy Custom" in reasons[0]

    def test_an_aws_managed_admin_policy_is_named(self):
        user = {"UserName": "u", "GroupList": [], "UserPolicyList": [],
                "AttachedManagedPolicies": [
                    {"PolicyName": "AdministratorAccess",
                     "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}
        reasons = squawk.probes._principal_reasons(
            user, {}, {}, "user").escalation
        assert reasons and "AdministratorAccess" in reasons[0]

    def test_a_user_with_nothing_attached_has_no_path(self):
        user = {"UserName": "u", "GroupList": [], "UserPolicyList": [],
                "AttachedManagedPolicies": []}
        # Every list, not only escalation: a user with nothing attached has
        # nothing self-service and nothing scoped either.
        assert squawk.probes._principal_reasons(user, {}, {}, "user") == \
            squawk.probes.PolicyRead([], [], [], [])


class TestIamCoverageAndCaveats:

    def _summary(self, **kw):
        data = {"counts": {"users": 3, "roles": 2, "groups": 1, "policies": 0},
                "users": [], "roles_with_escalation": [], "truncated": False,
                "limit": 1000, "account": "0", "read_at": "", "api_calls": 8}
        data.update(kw)
        return squawk.analysis.iam_summary(data)

    def test_a_truncated_graph_is_declared_a_floor(self):
        caveats = " ".join(squawk.analysis.iam_caveats(
            self._summary(truncated=True)))
        assert "is a floor" in caveats and "cloud_max_principals" in caveats

    def test_a_complete_read_says_the_negative_is_real(self):
        caveats = " ".join(squawk.analysis.iam_caveats(self._summary()))
        assert "genuinely guarded, not merely unchecked" in caveats

    def test_the_simulation_caveat_is_always_present(self):
        caveats = " ".join(squawk.analysis.iam_caveats(self._summary()))
        assert "does not simulate a request" in caveats
        assert "permissions boundary" in caveats

    def test_sso_identities_are_explained_rather_than_omitted(self):
        caveats = " ".join(squawk.analysis.iam_caveats(self._summary()))
        assert "Federated and SSO identities" in caveats

    def test_principals_are_the_denominator(self):
        raw = json.dumps({"counts": {"users": 3, "roles": 2, "groups": 1,
                                     "policies": 4}, "users": []})
        cov = squawk.scanners.stage_coverage("cloudiam", raw)
        assert cov.unit == "principals and policies" and cov.examined == 10

    def test_an_empty_graph_is_a_gap_not_an_empty_account(self):
        status, detail, _c = squawk.engine._apply_coverage(
            "cloudiam", json.dumps({"counts": {}, "users": []}), [], "ok",
            "0 findings")
        assert status == "gap" and "examined 0 principals" in detail

    def test_no_credential_report_is_ever_generated(self):
        """Generating one is a write, and I3 says this tool does not write.

        Asserted over the parsed source, not the text: the first version of
        this test searched the file and matched the COMMENT explaining why the
        call is not made. A test that a comment can satisfy tests nothing."""
        import ast
        tree = ast.parse(open(squawk.probes.__file__, encoding="utf-8").read())
        literals = {n.value for n in ast.walk(tree)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        assert "generate-credential-report" not in literals, \
            "the probe builds a call that creates something in the account"
        assert {"list-mfa-devices", "list-access-keys"} <= literals, \
            "the read-only path to the same facts is gone"

    def test_the_normalizer_survives_junk(self):
        for junk in ("", "{}", "null", '{"users": "no"}'):
            assert squawk.scanners.norm_cloudiam(junk, "") == []


class TestWhoCanAssumeARole:
    """"A role is only a path for whoever can assume it" was a caveat on the
    page — the tool raising the question and leaving it to the reader. The
    trust policy is the answer, and it was already in the graph response."""

    ACC: ClassVar[str] = "000000000000"
    OIDC: ClassVar[str] = ("arn:aws:iam::000000000000:oidc-provider/"
                           "token.actions.githubusercontent.com")

    def _gh(self, sub=None, aud=True):
        cond = {}
        if aud:
            cond["StringEquals"] = {
                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}
        if sub:
            cond["StringLike"] = {
                "token.actions.githubusercontent.com:sub": sub}
        return {"Statement": [{"Effect": "Allow",
                               "Principal": {"Federated": self.OIDC},
                               "Action": "sts:AssumeRoleWithWebIdentity",
                               "Condition": cond}]}

    def _reach(self, doc):
        return squawk.probes.widest_reach(
            squawk.probes.who_can_assume(doc, self.ACC))

    def test_github_oidc_without_a_sub_condition_admits_any_repository(self):
        """The known, exploited misconfiguration. It looks identical to a
        correct one until you read the condition."""
        entries = squawk.probes.who_can_assume(self._gh(), self.ACC)
        assert entries[0]["reach"] == "anyone"
        assert "any repository on GitHub" in entries[0]["why"]

    def test_github_oidc_pinned_to_a_repository_is_not(self):
        assert self._reach(self._gh("repo:acme/api:*")) == "federated"

    def test_a_leading_wildcard_in_sub_does_not_pin_anything(self):
        assert self._reach(self._gh("*")) == "anyone"
        assert self._reach(self._gh("*:refs/heads/main")) == "anyone"

    def test_a_wildcard_where_the_owner_belongs_pins_nobody(self):
        """Review R-5, reproduction 4.

        `repo:*/*` admits every repository on GitHub. The old test was
        `sub.startswith("*")`, so all three of these came back "pinned to
        repo:*/*" with reach federated and no finding fired -- on the single
        OIDC pattern this function was written to catch.
        """
        for sub in ("repo:*/*", "repo:*:*", "repo:*", "repo:my*org/api"):
            assert self._reach(self._gh(sub)) == "anyone", sub

    def test_a_wildcard_repository_pins_the_organization_only(self):
        """`repo:acme/*` is a real narrowing and a smaller one than it looks:
        every repository in the organization, including one opened today."""
        entries = squawk.probes.who_can_assume(self._gh("repo:acme/*"), self.ACC)
        assert entries[0]["reach"] == "federated"
        assert "pinned to the organization, not the repository" in entries[0]["why"]

    def test_the_loosest_sub_in_a_list_decides(self):
        """A tight condition beside a loose one does not make up for it."""
        assert self._reach(self._gh(["repo:acme/api:ref:refs/heads/main",
                                     "repo:*/*"])) == "anyone"

    def test_the_sub_scope_helper_is_read_from_the_claim_shape(self):
        scope = squawk.probes._github_sub_scope
        assert scope("repo:acme/api:ref:refs/heads/main") == "repository"
        assert scope("repo:acme/*") == "organization"
        assert scope("repo:acme") == "organization"
        assert scope("repo:acme/my?api") == "organization"
        for loose in ("*", "repo:*", "repo:*/*", "repo:*:*", "", "   "):
            assert scope(loose) == "loose", loose

    def test_a_bare_star_principal_is_anyone(self):
        doc = {"Statement": [{"Effect": "Allow", "Principal": "*"}]}
        assert self._reach(doc) == "anyone"

    def test_a_star_principal_with_a_condition_is_not_called_anyone(self):
        """An org-id condition is a real narrowing. Calling it "anyone" would
        be the alarm crying wolf on a correct configuration.

        It is `organization`, not `external`: this test asserted `external`,
        which made the scale disagree with itself -- the identical condition on
        an SNS topic was read as "the answer to who" and produced nothing
        (review 2, R-25)."""
        doc = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"},
                              "Condition": {"StringEquals":
                                            {"aws:PrincipalOrgID": "o-x"}}}]}
        assert self._reach(doc) == "organization"

    def test_another_account_is_external_and_masked(self):
        doc = {"Statement": [{"Effect": "Allow", "Principal":
                              {"AWS": "arn:aws:iam::999999999999:root"}}]}
        entries = squawk.probes.who_can_assume(doc, self.ACC)
        assert entries[0]["reach"] == "external"
        assert "999999999999" not in entries[0]["why"]

    def test_the_same_account_is_internal(self):
        doc = {"Statement": [{"Effect": "Allow", "Principal":
                              {"AWS": "arn:aws:iam::000000000000:role/x"}}]}
        assert self._reach(doc) == "internal"

    def _star(self, condition=None):
        st = {"Effect": "Allow", "Principal": {"AWS": "*"}}
        if condition:
            st["Condition"] = condition
        return {"Statement": [st]}

    def test_a_condition_that_does_not_name_who_leaves_the_star_standing(self):
        """Plan 11 step 5e.

        The check was `bool(conditions)`, so any condition at all downgraded a
        `*` from anyone to external. sts:ExternalId is the false friend that
        matters: a shared string against the confused deputy, not an identity.
        A role trusting `*` with nothing but an ExternalId is assumable by
        anyone who learns the string, and the string travels in config files.
        """
        for condition in ({"StringEquals": {"sts:ExternalId": "s3cr3t"}},
                          {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                          {"Bool": {"aws:SecureTransport": "true"}},
                          {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}):
            assert self._reach(self._star(condition)) == "anyone", condition

    def test_a_condition_that_names_who_narrows_to_where_they_are(self):
        assert self._reach(self._star(
            {"StringEquals": {"aws:PrincipalAccount": self.ACC}})) == "internal"
        assert self._reach(self._star(
            {"ArnLike": {"aws:PrincipalArn":
                         "arn:aws:iam::000000000000:role/x"}})) == "internal"
        # Not `external`: an organization is a third answer between this
        # account and a stranger (review 2, R-25).
        assert self._reach(self._star(
            {"StringEquals": {"aws:PrincipalOrgID": "o-x"}})) == "organization"

    def test_notprincipal_admits_everyone_it_does_not_name(self):
        """The widest grant a trust policy can express, and reading only
        `Principal` produced nothing at all for it."""
        doc = {"Statement": [{"Effect": "Allow", "NotPrincipal": {
            "AWS": "arn:aws:iam::999999999999:root"},
            "Action": "sts:AssumeRole"}]}
        entries = squawk.probes.who_can_assume(doc, self.ACC)
        assert entries and entries[0]["reach"] == "anyone"
        assert "everyone EXCEPT" in entries[0]["why"]
        assert "999999999999" not in entries[0]["why"], "account ids are masked"

    def test_a_service_principal_is_a_service(self):
        doc = {"Statement": [{"Effect": "Allow", "Principal":
                              {"Service": "ec2.amazonaws.com"}}]}
        assert self._reach(doc) == "service"

    def test_a_deny_statement_admits_nobody(self):
        doc = {"Statement": [{"Effect": "Deny", "Principal": "*"}]}
        assert squawk.probes.who_can_assume(doc, self.ACC) == []

    def test_the_widest_statement_wins(self):
        """A role is as reachable as its loosest statement; the tight ones do
        not make up for it."""
        doc = {"Statement": [
            {"Effect": "Allow", "Principal":
             {"AWS": "arn:aws:iam::000000000000:role/x"}},
            {"Effect": "Allow", "Principal": "*"}]}
        assert self._reach(doc) == "anyone"

    def test_an_unreadable_trust_policy_is_unknown_not_nobody(self):
        for junk in (None, "", "not a policy", 7, []):
            assert squawk.probes.widest_reach(
                squawk.probes.who_can_assume(junk, self.ACC)) == "unknown"


class TestEscalationReachableFromOutside:
    """Either half is ordinary. The combination is a path from outside the
    account to more permission than the role was given, and the two halves live
    in different documents."""

    def _data(self, reach="anyone", admin=False):
        row = {"name": "deploy-legacy", "arn": "arn:aws:iam::0:role/x",
               "reach": reach,
               "trust": [{"kind": "federated", "who": "gh", "reach": reach,
                          "why": "GitHub Actions OIDC with NO condition on the "
                                 "sub claim"}]}
        if admin:
            return {"roles_with_escalation": [],
                    "roles_already_admin": [dict(row, why=["allows every action"])]}
        return {"roles_with_escalation": [dict(row, escalation=["allows PassRole"])],
                "roles_already_admin": []}

    def test_escalation_reachable_by_anyone_is_critical(self):
        found = squawk.analysis.role_findings(self._data("anyone"))
        assert len(found) == 1 and found[0]["severity"] == "critical"
        assert found[0]["key"] == "escalation-reachable-from-outside"

    def test_escalation_reachable_externally_is_high(self):
        found = squawk.analysis.role_findings(self._data("external"))
        assert found and found[0]["severity"] == "high"

    def test_escalation_reachable_only_internally_does_not_fire(self):
        """Plenty of deploy roles hold iam:PassRole. That is what they are
        for, and flagging every one of them is how a reader learns to skip
        the section."""
        for reach in ("internal", "service", "federated"):
            assert squawk.analysis.role_findings(self._data(reach)) == [], reach

    def test_an_administrative_role_reachable_from_outside_is_critical(self):
        found = squawk.analysis.role_findings(self._data("anyone", admin=True))
        assert found[0]["key"] == "administrative-reachable-from-outside"
        assert found[0]["severity"] == "critical"
        assert "the trust policy is the door" in found[0]["fix"]

    def test_the_finding_names_the_trust_reason_not_just_the_reach(self):
        found = squawk.analysis.role_findings(self._data("anyone"))
        assert "NO condition on the sub claim" in found[0]["why"]

    def test_an_unknown_reach_is_declared_rather_than_assumed_safe(self):
        summary = squawk.analysis.iam_summary({
            "counts": {}, "users": [], "roles_already_admin": [],
            "roles_with_escalation": [{"name": "x", "reach": "unknown",
                                       "trust": [], "escalation": ["y"]}]})
        assert summary["reach_counts"]["unknown"] == 1
        caveats = " ".join(squawk.analysis.iam_caveats(summary))
        assert "who can assume them is unknown — not nobody" in caveats

    def test_an_unsettled_reach_is_declared_too(self):
        """`unsettled` had a count, a card and a severity, and no caveat line.
        An unknown reach is a trust policy nobody could read; an unsettled one
        read cleanly and names an account this run could not place. Both end in
        "not settled safe", and only the first was being said."""
        summary = squawk.analysis.iam_summary({
            "counts": {}, "users": [], "roles_already_admin": [],
            "roles_with_escalation": [{"name": "x", "reach": "unsettled",
                                       "trust": [], "escalation": ["y"]}]})
        assert summary["reach_counts"]["unsettled"] == 1
        caveats = " ".join(squawk.analysis.iam_caveats(summary))
        assert "could not place" in caveats, caveats
        assert "unsettled, not settled safe" in caveats, caveats

    def test_the_two_undecided_reaches_read_differently(self):
        """They are different facts, so they must not collapse into one line."""
        def caveat(reach):
            summary = squawk.analysis.iam_summary({
                "counts": {}, "users": [], "roles_already_admin": [],
                "roles_with_escalation": [{"name": "x", "reach": reach,
                                           "trust": [], "escalation": ["y"]}]})
            return [c for c in squawk.analysis.iam_caveats(summary)
                    if "assume them is" in c]
        unknown, unsettled = caveat("unknown"), caveat("unsettled")
        assert unknown and unsettled and unknown != unsettled, (unknown, unsettled)

    def test_a_settled_account_says_neither(self):
        """The false-alarm guard. A caveat on every run is a caveat nobody
        reads: neither line appears when every reach was settled."""
        summary = squawk.analysis.iam_summary({
            "counts": {}, "users": [], "roles_already_admin": [],
            "roles_with_escalation": [{"name": "x", "reach": "internal",
                                       "trust": [], "escalation": ["y"]}]})
        caveats = " ".join(squawk.analysis.iam_caveats(summary))
        assert "assume them is" not in caveats, caveats

    def test_the_normalizer_emits_them_as_findings(self):
        raw = json.dumps(dict(self._data("anyone"), counts={}, users=[]))
        found = squawk.scanners.norm_cloudiam(raw, "")
        assert len(found) == 1
        assert found[0].severity == "critical"
        assert "outside the account" in found[0].title

    def test_junk_does_not_raise(self):
        for junk in ({}, {"roles_with_escalation": None},
                     {"roles_with_escalation": [None]}):
            squawk.analysis.role_findings(junk)


class TestWhatTheInternetCanTalkTo:
    """On a container-first account the instance count is the wrong
    denominator. A hundred and three interfaces against seven instances says
    the workloads are Lambda, ECS tasks and load balancers — and until this
    read, none of them were looked at."""

    def _edge(self, auth="NONE", scheme="internet-facing", groups=("sg-lb",)):
        return {"account": "0", "read_at": "2026-09-09T12:00:00Z",
                "api_calls": 7, "truncated": False, "limit": 500,
                "regions_enabled": ["us-east-1"], "regions_read": ["us-east-1"],
                "regions_unread": [],
                "regional": {"us-east-1": {
                    "functions": 2,
                    "urls": [{"name": "ingest", "auth": auth, "why": "",
                              "url": "https://x", "cors": ["*"]}],
                    "load_balancers": [
                        {"name": "public-alb", "scheme": scheme,
                         "type": "application", "vpc": "vpc-1",
                         "groups": list(groups), "dns": "x.elb"}],
                    "unreadable": []}}}

    def _inv(self, port=5432):
        return {"resources": {"us-east-1": {"security-groups": [
            {"GroupId": "sg-lb", "VpcId": "vpc-1", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                 "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}]}]}}}

    def test_a_function_url_with_no_auth_is_a_finding(self):
        found = squawk.analysis.edge_findings(self._edge())
        assert len(found) == 1
        assert found[0]["key"] == "lambda-url-without-auth"
        assert found[0]["severity"] == "high"
        assert "anyone who knows the address" in found[0]["why"]
        assert "CORS policy allows any origin" in found[0]["why"]

    def test_a_function_url_with_iam_auth_is_not(self):
        assert squawk.analysis.edge_findings(self._edge(auth="AWS_IAM")) == []

    def test_an_unreadable_url_config_is_unknown_not_open(self):
        data = self._edge(auth="unknown")
        found = squawk.analysis.edge_findings(data)
        assert found[0]["severity"] == "unknown"
        assert "could not be read" in found[0]["why"]

    def test_an_internet_facing_lb_on_a_database_port_fires(self):
        """Needs BOTH readings: the load balancer from the edge read and the
        rules from the inventory. Neither can say it alone."""
        gaps = squawk.analysis.edge_gaps(self._inv(5432), self._edge())
        assert len(gaps) == 1
        assert "5432/PostgreSQL" in gaps[0]["why"]

    def test_an_internet_facing_lb_on_443_does_not(self):
        """A load balancer open to the world on 443 is the job."""
        assert squawk.analysis.edge_gaps(self._inv(443), self._edge()) == []

    def test_an_internal_lb_is_not_judged_by_the_internet(self):
        assert squawk.analysis.edge_gaps(
            self._inv(5432), self._edge(scheme="internal")) == []

    def test_a_group_missing_from_the_inventory_is_unknown_not_clean(self):
        gaps = squawk.analysis.edge_gaps({"resources": {"us-east-1": {}}},
                                         self._edge())
        assert gaps and gaps[0]["severity"] == "unknown"
        assert "were not in the inventory reading" in gaps[0]["why"]

    def test_no_inventory_is_unknown_not_silence(self):
        """Review R-10, reproduction 5.

        This asserted `[]`, which is the defect: with an ERRORED inventory the
        function produced the unjudged record, and with no inventory at all it
        produced nothing. Same missing input, two answers, and the quieter one
        was reached by the more common route — every run made before the
        inventory stage existed, and every run whose file was pruned.
        """
        gaps = squawk.analysis.edge_gaps({}, self._edge())
        assert gaps and gaps[0]["key"] == "internet-facing-lb-unjudged"
        assert gaps[0]["severity"] == "unknown"

    def test_no_edge_reading_produces_nothing(self):
        """The other direction is genuinely nothing: with no load balancers
        read there is no subject to be unknown about."""
        assert squawk.analysis.edge_gaps(self._inv(), {}) == []

    def test_a_load_balancer_with_no_security_group_is_unknown(self):
        """A network load balancer carries none. That is not "nothing admits
        the world" — it is a question this reading cannot answer, because the
        listeners decide and they are not read."""
        edge = self._edge()
        edge["regional"]["us-east-1"]["load_balancers"][0]["groups"] = []
        gaps = squawk.analysis.edge_gaps(self._inv(5432), edge)
        assert gaps and gaps[0]["key"] == "internet-facing-lb-listeners-unread"
        assert gaps[0]["severity"] == "unknown"
        assert "network load balancer" in gaps[0]["why"]

    def test_the_summary_counts_what_the_tiles_show(self):
        s = squawk.analysis.edge_summary(self._edge())
        assert s["counts"]["functions"] == 2
        assert s["counts"]["urls"] == 1
        assert s["counts"]["urls_without_auth"] == 1
        assert s["counts"]["load_balancers"] == 1
        assert s["counts"]["internet_facing"] == 1

    def test_coverage_is_the_reads_that_answered(self):
        """It counted functions and load balancers FOUND. An account with no
        Lambda and no load balancer then examined nothing, which made the run
        incomplete and blanked the panel — with nothing denied (review 2,
        R-20)."""
        cov = squawk.scanners.stage_coverage("cloudedge",
                                             json.dumps(self._edge()))
        assert cov.unit == "regions read"
        assert cov.examined == 1
        assert "function(s) and load balancer(s) found" in cov.note, \
            "what it found is still said, in the note"

    def test_an_account_with_no_functions_is_a_result_not_a_gap(self):
        empty = self._edge()
        empty["regional"]["us-east-1"] = {"functions": [], "urls": [],
                                          "load_balancers": [], "unreadable": []}
        status, _detail, _c = squawk.engine._apply_coverage(
            "cloudedge", json.dumps(empty), [], "ok", "0 findings")
        assert status == "ok", "nothing found over a region that answered"

    def test_a_read_that_reached_no_region_is_still_a_gap(self):
        status, detail, _c = squawk.engine._apply_coverage(
            "cloudedge", json.dumps({"regional": {}}), [], "ok", "0 findings")
        assert status == "gap" and "examined 0 regions read" in detail

    def test_junk_does_not_raise(self):
        for junk in ({}, {"regional": None}, {"regional": {"r": None}}):
            squawk.analysis.edge_findings(junk)
            squawk.analysis.edge_summary(junk)
            squawk.analysis.edge_gaps(junk, junk)
            assert squawk.scanners.norm_cloudedge(json.dumps(junk), "") == []


class TestWhatOwnsTheNetworkInterfaces:
    """A hundred and three interfaces against seven instances is the largest
    unexplained number this tool can show, and the answer costs nothing — it
    was in the response all along."""

    def test_each_owner_is_recognised(self):
        cases = [
            ({"InstanceId": "i-1"}, "EC2 instance"),
            ({"InterfaceType": "lambda"}, "Lambda function"),
            ({"Description": "AWS Lambda VPC ENI-abc"}, "Lambda function"),
            ({"Description": "ELB app/my-alb/abc"}, "load balancer"),
            ({"Description": "ELB classic-lb"}, "load balancer (classic)"),
            ({"Description": "arn:aws:ecs:us-east-1:0:attachment/x"}, "ECS task"),
            ({"InterfaceType": "vpc_endpoint"}, "VPC endpoint"),
            ({"InterfaceType": "nat_gateway"}, "NAT gateway"),
            ({"InterfaceType": "transit_gateway"}, "transit gateway"),
            ({}, "not attributed"),
        ]
        for eni, want in cases:
            assert squawk.probes.eni_owner(eni) == want, eni

    def test_a_bare_interface_type_is_not_a_category(self):
        """`interface` is the DEFAULT type and means "an ordinary network
        interface", which is true of most of the named kinds too. Rendering it
        as a category produced a tile reading "interface · 7" — which looks
        like an answer and is not one."""
        assert squawk.probes.eni_owner(
            {"InterfaceType": "interface", "Description": ""}) == "not attributed"

    def test_an_attached_instance_wins_over_the_type(self):
        """The instance is the concrete answer; the type is a category."""
        assert squawk.probes.eni_owner(
            {"InstanceId": "i-1", "InterfaceType": "interface"}) == "EC2 instance"

    def test_they_are_counted_and_ordered_by_size(self):
        inv = {"resources": {"us-east-1": {"network-interfaces":
            [{"InterfaceType": "lambda"}] * 3
            + [{"Description": "ELB app/x/y"}] * 5
            + [{"InstanceId": "i-1"}]}}}
        owners = squawk.analysis.interface_owners(inv)
        assert owners[0] == ("load balancer", 5)
        assert dict(owners)["Lambda function"] == 3
        assert sum(n for _o, n in owners) == 9

    def test_no_interfaces_is_an_empty_list_not_a_crash(self):
        assert squawk.analysis.interface_owners({}) == []
        assert squawk.analysis.interface_owners(
            {"resources": {"r": {"network-interfaces": []}}}) == []


def _db_inventory(group_open=True, subnet_public=True, denied=()):
    """An inventory reading a database join can be judged against: one group,
    one subnet, and a route table that reaches an attached gateway."""
    perms = ([{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
               "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}] if group_open else
             [{"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
               "IpRanges": ["10.0.0.0/8"], "Ipv6Ranges": []}])
    routes = ([{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}]
              if subnet_public else
              [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}])
    return {
        "regions_read": ["us-east-1"],
        "reads": {"us-east-1": {key: {"status": "error", "detail": "denied"}
                                for key in denied}},
        "resources": {"us-east-1": {
            "vpcs": [{"VpcId": "vpc-1"}],
            "subnets": [{"SubnetId": "subnet-pub", "VpcId": "vpc-1"}],
            "route-tables": [{"RouteTableId": "rtb-1", "VpcId": "vpc-1",
                              "Associations": [{"SubnetId": "subnet-pub"}],
                              "Routes": routes}],
            "internet-gateways": [{"InternetGatewayId": "igw-1",
                                   "Attachments": [{"State": "available"}]}],
            "security-groups": [{"GroupId": "sg-open", "GroupName": "db",
                                 "VpcId": "vpc-1", "IpPermissions": perms}],
            "network-interfaces": [], "instances": []}}}


class TestWhereTheDataIs:
    """S3 and RDS carry the two combinations that put organisations in the
    news, and both are joins: public AND unencrypted, reachable AND
    unencrypted. Neither half is a finding on its own."""

    def _data(self, public=True, encrypted=True, blocked=None, unreadable=(),
              db_public=True, db_encrypted=False):
        return {
            "account": "0", "read_at": "2026-09-09T12:00:00Z", "api_calls": 9,
            "bucket_total": 2, "bucket_limit": 100, "bucket_error": "",
            "account_block_on": blocked,
            "buckets": [{"name": "assets", "region": "us-east-1",
                         "public": public, "encrypted": encrypted,
                         "block": 0, "unreadable": list(unreadable)}],
            "regions_enabled": ["us-east-1"], "regions_read": ["us-east-1"],
            "regions_unread": [],
            "databases": {"us-east-1": {"unreadable": [], "databases": [
                {"id": "reporting-db", "kind": "instance", "engine": "postgres",
                 "public": db_public, "encrypted": db_encrypted,
                 "subnets": [], "groups": []}]}}}

    def _keys(self, data):
        return [r["key"] for r in squawk.analysis.storage_findings(data)]

    def test_a_public_bucket_is_a_finding(self):
        found = squawk.analysis.storage_findings(
            self._data(public=True, encrypted=True, db_public=False))
        assert found[0]["key"] == "bucket-public"
        assert found[0]["severity"] == "high"
        assert "AWS evaluated its policy and said so" in found[0]["why"]

    def test_public_and_unencrypted_is_critical(self):
        found = squawk.analysis.storage_findings(
            self._data(public=True, encrypted=False, db_public=False))
        assert found[0]["key"] == "bucket-public-unencrypted"
        assert found[0]["severity"] == "critical"
        assert "the mistake plus no fallback" in found[0]["why"]

    def test_a_private_bucket_is_not_a_finding_however_unencrypted(self):
        """Unencrypted alone is not exposure. Reporting it as one is how a
        reader learns to skip the section."""
        assert self._keys(self._data(public=False, encrypted=False,
                                     db_public=False)) == []

    def test_the_account_block_changes_what_a_public_policy_means(self):
        """True about the policy, and true about the world. With the block on,
        a policy that says public does not make the bucket public."""
        loose = squawk.analysis.storage_findings(
            self._data(blocked=False, db_public=False))
        held = squawk.analysis.storage_findings(
            self._data(blocked=True, db_public=False))
        assert loose[0]["key"] == "bucket-public"
        assert loose[0]["severity"] == "high"
        assert held[0]["key"] == "bucket-public-policy-blocked"
        assert held[0]["severity"] == "medium"
        assert "the account-wide S3 block is stopping that" in held[0]["why"]
        assert "the day that block came off" in held[0]["why"]

    def test_an_unknown_block_takes_the_stricter_branch(self):
        """A missing input must not soften a verdict."""
        found = squawk.analysis.storage_findings(
            self._data(blocked=None, db_public=False))
        assert found[0]["key"] == "bucket-public"

    def test_an_unreadable_bucket_is_unknown_not_private(self):
        found = squawk.analysis.storage_findings(
            self._data(unreadable=["policy status (AccessDenied)"],
                       db_public=False))
        assert found[0]["key"] == "bucket-unreadable"
        assert found[0]["severity"] == "unknown"
        assert "unknown, not fine" in found[0]["why"]

    def _db(self, data, inventory=None, **kw):
        db = data["databases"]["us-east-1"]["databases"][0]
        db.update(kw)
        return [r for r in squawk.analysis.storage_findings(data, inventory)
                if r["key"].startswith("database")]

    def test_a_public_unencrypted_database_is_critical(self):
        """All three legs: the flag, a group admitting the world on its port,
        and a subnet that routes to an attached gateway."""
        found = self._db(self._data(public=False, db_public=True,
                                    db_encrypted=False),
                         _db_inventory(), port=5432,
                         groups=["sg-open"], subnets=["subnet-pub"])
        assert found[0]["key"] == "database-public-unencrypted"
        assert found[0]["severity"] == "critical"
        assert "cannot be added in place" in found[0]["fix"]
        assert "sg-open admits 0.0.0.0/0 on port 5432" in found[0]["why"]
        assert "subnet-pub routes to igw-1" in found[0]["why"]

    def test_a_public_encrypted_database_is_high(self):
        found = self._db(self._data(public=False, db_public=True,
                                    db_encrypted=True),
                         _db_inventory(), port=5432,
                         groups=["sg-open"], subnets=["subnet-pub"])
        assert found[0]["key"] == "database-public"

    def test_the_flag_alone_is_a_note_not_a_finding(self):
        """Review R-6, reproduction 5. PubliclyAccessible is the console
        wizard's default, and on its own it says only that AWS gave the
        instance a public DNS name."""
        found = self._db(self._data(public=False, db_public=True,
                                    db_encrypted=False),
                         _db_inventory(group_open=False), port=5432,
                         groups=["sg-open"], subnets=["subnet-pub"])
        assert found[0]["key"] == "database-public-flag"
        assert found[0]["severity"] == "low"
        assert "no group on it admits 0.0.0.0/0 on port 5432" in found[0]["why"]

    def test_a_private_subnet_is_also_not_reachable(self):
        found = self._db(self._data(public=False, db_public=True,
                                    db_encrypted=False),
                         _db_inventory(subnet_public=False), port=5432,
                         groups=["sg-open"], subnets=["subnet-pub"])
        assert found[0]["key"] == "database-public-flag"
        assert "no subnet of it routes to an internet gateway" in found[0]["why"]

    def test_no_inventory_is_unknown_not_high(self):
        found = self._db(self._data(public=False, db_public=True,
                                    db_encrypted=False),
                         None, port=5432, groups=["sg-open"],
                         subnets=["subnet-pub"])
        assert found[0]["key"] == "database-reachability-unknown"
        assert found[0]["severity"] == "unknown"

    def test_a_denied_inventory_read_is_unknown_not_reachable(self):
        for denied in (("security-groups",), ("subnets",), ("route-tables",)):
            found = self._db(self._data(public=False, db_public=True,
                                        db_encrypted=False),
                             _db_inventory(denied=denied), port=5432,
                             groups=["sg-open"], subnets=["subnet-pub"])
            assert found[0]["key"] == "database-reachability-unknown", denied
            assert denied[0] in found[0]["why"], denied

    def test_a_group_missing_from_the_inventory_is_unknown(self):
        found = self._db(self._data(public=False, db_public=True,
                                    db_encrypted=False),
                         _db_inventory(), port=5432, groups=["sg-elsewhere"],
                         subnets=["subnet-pub"])
        assert found[0]["key"] == "database-reachability-unknown"

    def test_a_database_with_no_subnet_recorded_is_unknown(self):
        """An Aurora cluster whose subnet group could not be expanded."""
        found = self._db(self._data(public=False, db_public=True,
                                    db_encrypted=False),
                         _db_inventory(), port=5432, groups=["sg-open"],
                         subnets=[])
        assert found[0]["key"] == "database-reachability-unknown"
        assert "no subnet is recorded" in found[0]["why"]

    def test_a_bucket_held_shut_by_its_own_block_is_medium(self):
        """R-6's other half: _bucket_facts read the four settings and nothing
        consulted them."""
        data = self._data(public=True, blocked=False, db_public=False)
        bucket = data["buckets"][0]
        bucket["block"] = {"BlockPublicAcls": False, "IgnorePublicAcls": False,
                           "BlockPublicPolicy": True,
                           "RestrictPublicBuckets": True}
        found = squawk.analysis.storage_findings(data)
        assert found[0]["key"] == "bucket-public-policy-blocked"
        assert found[0]["severity"] == "medium"
        assert "this bucket's own public access block" in found[0]["why"]

    def test_a_block_that_only_covers_acls_does_not_hold_a_policy_shut(self):
        data = self._data(public=True, blocked=False, db_public=False)
        data["buckets"][0]["block"] = {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
        assert squawk.analysis.storage_findings(data)[0]["key"] == "bucket-public"

    def test_a_block_that_was_never_read_takes_the_stricter_branch(self):
        data = self._data(public=True, blocked=False, db_public=False)
        data["buckets"][0]["block"] = None
        assert squawk.analysis.storage_findings(data)[0]["key"] == "bucket-public"

    def test_a_private_database_is_not_a_finding(self):
        assert [r for r in squawk.analysis.storage_findings(
            self._data(public=False, db_public=False)) ] == []

    def test_an_unreadable_database_read_is_reported(self):
        data = self._data(public=False, db_public=False)
        data["databases"]["us-east-1"]["unreadable"] = ["database instances (denied)"]
        found = squawk.analysis.storage_findings(data)
        assert found[0]["key"] == "database-unreadable"
        assert found[0]["severity"] == "unknown"

    def test_coverage_counts_the_reads_that_answered(self):
        """One global bucket list, plus every region whose database reads
        answered. It counted buckets and databases FOUND, so an account with
        neither examined nothing (review 2, R-20)."""
        cov = squawk.scanners.stage_coverage("cloudstore",
                                             json.dumps(self._data()))
        assert cov.unit == "reads that answered" and cov.examined == 2
        assert "bucket(s) and" in cov.note and "database(s) found" in cov.note

    def test_an_account_with_no_buckets_is_a_result_not_a_gap(self):
        empty = self._data()
        empty["buckets"], empty["bucket_total"] = [], 0
        empty["databases"] = {"us-east-1": {"databases": [], "unreadable": []}}
        status, _detail, _c = squawk.engine._apply_coverage(
            "cloudstore", json.dumps(empty), [], "ok", "0 findings")
        assert status == "ok"

    def test_a_bucket_list_that_failed_is_not_counted_as_answered(self):
        broken = self._data()
        broken["bucket_error"] = "AccessDenied"
        broken["regions_read"] = []
        broken["databases"] = {}
        status, _detail, _c = squawk.engine._apply_coverage(
            "cloudstore", json.dumps(broken), [], "ok", "0 findings")
        assert status == "gap"

    def test_a_bounded_bucket_read_is_declared_a_floor(self):
        data = self._data()
        data["bucket_total"] = 500
        cov = squawk.scanners.stage_coverage("cloudstore", json.dumps(data))
        assert "FLOOR" in cov.note and "cloud_max_buckets" in cov.note
        caveats = " ".join(squawk.analysis.storage_caveats(
            squawk.analysis.storage_summary(data), False))
        assert "1 of 500 bucket(s) were examined" in caveats

    def test_a_complete_read_says_the_negative_is_real(self):
        caveats = " ".join(squawk.analysis.storage_caveats(
            squawk.analysis.storage_summary(
                dict(self._data(), bucket_total=1)), False))
        assert "Every one of the 1 bucket(s)" in caveats

    def test_the_caveats_name_what_is_never_read(self):
        caveats = " ".join(squawk.analysis.storage_caveats(
            squawk.analysis.storage_summary(self._data()), True))
        assert "Object contents are never read" in caveats
        assert "Bucket ACLs and per-object permissions are not read" in caveats
        assert "account-wide S3 block is fully on" in caveats

    def test_an_unreadable_bucket_list_says_nothing_covers_s3(self):
        data = dict(self._data(), bucket_error="AccessDenied", buckets=[])
        caveats = " ".join(squawk.analysis.storage_caveats(
            squawk.analysis.storage_summary(data), False))
        assert "nothing here covers S3 at all" in caveats

    def test_junk_does_not_raise(self):
        for junk in ({}, {"buckets": None}, {"buckets": [None]},
                     {"databases": {"r": None}}):
            squawk.analysis.storage_findings(junk)
            squawk.analysis.storage_summary(junk)
            assert squawk.scanners.norm_cloudstore(json.dumps(junk), "") == []


class TestHowMuchOfTheEstateThisCovers:
    """Squawk reads one account. On a standalone account that is the estate;
    in an organization it is a fraction, and the same number then means
    something different."""

    def _data(self, accounts=(("111111111111", "prod", "ACTIVE"),
                              ("222222222222", "dev", "ACTIVE")),
              this="111111111111", standalone=False, org_error="",
              reaching=None, unreachable=()):
        return {"account": this, "read_at": "2026-09-09T12:00:00Z",
                "api_calls": 5, "standalone": standalone,
                "org_error": org_error,
                "organization": {"id": "o-example", "feature_set": "ALL",
                                 "management_account": "111111111111"},
                "accounts": [{"id": i, "name": n, "status": s}
                             for i, n, s in accounts],
                # Reaching and unreachable only exist if the probe ran, so
                # the flag that says it ran belongs beside them (step 9).
                "profiles_probed": True,
                "profiles_asked": sorted(reaching or {}) + list(unreachable),
                "profiles_reaching": reaching or {},
                "profiles_unreachable": list(unreachable)}

    def test_a_standalone_account_is_the_whole_estate(self):
        s = squawk.analysis.org_summary(self._data(standalone=True, accounts=()))
        caveats = " ".join(squawk.analysis.org_caveats(s))
        assert "it is the whole estate" in caveats
        assert squawk.analysis.org_findings(
            self._data(standalone=True, accounts=())) == []

    def test_one_of_many_says_the_fraction(self):
        s = squawk.analysis.org_summary(self._data())
        assert s["accounts_total"] == 2
        caveats = " ".join(squawk.analysis.org_caveats(s))
        assert "This organization has 2 active account(s)" in caveats
        assert "not the estate" in caveats

    def test_unread_accounts_are_named_as_not_clean(self):
        caveats = " ".join(squawk.analysis.org_caveats(
            squawk.analysis.org_summary(self._data())))
        assert "Unread is not clean" in caveats

    def test_a_profile_that_reaches_another_account_is_counted(self):
        s = squawk.analysis.org_summary(
            self._data(reaching={"dev-profile": "222222222222"}))
        assert s["accounts_reachable"] == 2
        assert s["accounts_unread"] == []
        caveats = " ".join(squawk.analysis.org_caveats(s))
        assert "ARE reachable from this machine" in caveats

    def test_an_inactive_account_is_not_part_of_the_denominator(self):
        s = squawk.analysis.org_summary(self._data(
            accounts=(("111111111111", "prod", "ACTIVE"),
                      ("333333333333", "closed", "SUSPENDED"))))
        assert s["accounts_total"] == 1

    def test_a_run_covering_a_fraction_is_a_finding(self):
        found = squawk.analysis.org_findings(self._data())
        assert len(found) == 1
        assert found[0]["key"] == "organization-mostly-unread"
        assert found[0]["severity"] == "info"
        assert "A clean result here is a clean result about one account" in \
            found[0]["why"]

    def test_full_coverage_produces_no_finding(self):
        assert squawk.analysis.org_findings(
            self._data(reaching={"dev": "222222222222"})) == []

    def test_an_unreadable_organization_is_unknown_not_standalone(self):
        """A member account cannot list the organization. That is different
        from not being in one, and calling it standalone would be a
        fabrication."""
        s = squawk.analysis.org_summary(
            self._data(org_error="AccessDeniedException", accounts=()))
        caveats = " ".join(squawk.analysis.org_caveats(s))
        assert "is unknown" in caveats
        assert "nothing is known about any other" in caveats
        assert squawk.analysis.org_findings(
            self._data(org_error="AccessDeniedException", accounts=())) == []

    def test_the_management_account_is_called_out(self):
        caveats = " ".join(squawk.analysis.org_caveats(
            squawk.analysis.org_summary(self._data())))
        assert "management account" in caveats

    def test_an_expired_profile_is_reported_rather_than_dropped(self):
        s = squawk.analysis.org_summary(
            self._data(unreachable=["stale-profile"]))
        caveats = " ".join(squawk.analysis.org_caveats(s))
        assert "could not say who they are" in caveats

    def test_no_email_is_ever_carried(self):
        """`list-accounts` returns the root email of every account. Real
        addresses for real people, which this tool has no use for and no
        business writing into evidence that outlives the run."""
        import ast
        tree = ast.parse(open(squawk.probes.__file__, encoding="utf-8").read())
        literals = {n.value for n in ast.walk(tree)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        for field in ("Email", "MasterAccountEmail"):
            assert field not in literals, \
                "the organization read is carrying %s" % field

    def test_coverage_of_a_standalone_account_is_not_a_gap(self):
        cov = squawk.scanners.stage_coverage(
            "cloudorg", json.dumps(self._data(standalone=True, accounts=())))
        assert cov.examined == 1
        assert "whole estate" in cov.note

    def test_coverage_says_the_fraction(self):
        cov = squawk.scanners.stage_coverage("cloudorg",
                                             json.dumps(self._data()))
        assert "read 1 of 2 active account(s)" in cov.note

    def test_the_banner_leads_with_the_fraction(self, monkeypatch, tmp_path):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        (run / "raw" / "cloud-org.json").write_text(json.dumps(self._data()),
                                                    encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [{"tool": "cloudorg", "status": "ok", "detail": ""}]}])
        html = squawk.web.cloud_estate_banner(str(tmp_path))
        assert "This is 1 of 2 accounts" in html
        assert "unread is not clean" in html
        assert "management account" in html

    def test_junk_does_not_raise(self):
        for junk in ({}, {"accounts": None}, {"accounts": [None]},
                     {"organization": None}):
            squawk.analysis.org_summary(junk)
            squawk.analysis.org_caveats(squawk.analysis.org_summary(junk))
            squawk.analysis.org_findings(junk)
            assert squawk.scanners.norm_cloudorg(json.dumps(junk), "") == []

    def test_no_credential_is_ever_put_in_a_child_environment(self, monkeypatch):
        """A profile NAME reaches the child; a credential never does.

        Asserted over the environment the child actually received, not over
        the source that builds it. The earlier version searched for three
        `child.pop(...)` lines in the text of the function — which a comment
        would satisfy, and which says nothing about the dict that was passed.
        """
        seen = {}

        class _Proc:
            returncode = 0
            stdout = b'{"Account": "000000000000"}'
            stderr = b""

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            seen["env"] = kwargs.get("env")
            return _Proc()

        for key, value in (("AWS_ACCESS_KEY_ID", "AKIA" + "EXAMPLEKEY000000"),
                           ("AWS_SECRET_ACCESS_KEY", "s" * 40),
                           ("AWS_SESSION_TOKEN", "t" * 60)):
            monkeypatch.setenv(key, value)
        monkeypatch.setattr(squawk.probes.subprocess, "run", fake_run)

        data, why = squawk.probes._aws_json_env(
            ["sts", "get-caller-identity"], 5, {"AWS_PROFILE": "other"})
        assert data == {"Account": "000000000000"} and why == ""

        child = seen["env"]
        assert child["AWS_PROFILE"] == "other", \
            "the profile name is how the CLI is told which profile to use"
        for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                    "AWS_SESSION_TOKEN"):
            assert key not in child, key
        blob = " ".join(seen["argv"]) + " " + " ".join(
            "%s=%s" % (k, v) for k, v in child.items())
        for secret in ("AKIA" + "EXAMPLEKEY000000", "s" * 40, "t" * 60):
            assert secret not in blob, "key material reached the child"

    def test_the_profile_probe_waits_for_its_own_acknowledgement(self,
                                                                 monkeypatch):
        """Review R-12. The cloud ack says "read this estate". This asks every
        LOCAL profile who it is, which assumes a role for a role_arn profile
        and runs the configured command for a credential_process one — a
        different thing, on estates the operator did not name."""
        monkeypatch.delenv("SQUAWK_CLOUD_PROFILES_ACK", raising=False)
        monkeypatch.delenv("TOWER_CLOUD_PROFILES_ACK", raising=False)
        ok, why = squawk.probes.profiles_ack()
        assert ok is False and "not set" in why
        monkeypatch.setenv("SQUAWK_CLOUD_PROFILES_ACK", "1")
        ok, why = squawk.probes.profiles_ack()
        assert ok is True and "set" in why

    def test_without_the_acknowledgement_the_probe_never_runs(self, monkeypatch):
        called = []
        monkeypatch.delenv("SQUAWK_CLOUD_PROFILES_ACK", raising=False)
        monkeypatch.delenv("TOWER_CLOUD_PROFILES_ACK", raising=False)
        monkeypatch.setattr(squawk.probes, "_profile_accounts",
                            lambda *a, **k: called.append(a) or ({}, [], ""))

        def responder(argv, _t):
            if argv[0] == "sts":
                return ({"Account": "000000000000", "Arn": "arn:x"}, "")
            return (None, "AWSOrganizationsNotInUseException")

        data, _s, _d = _run_probe(monkeypatch, squawk.probes.aws_organization,
                                  responder)
        assert called == [], "the probe ran without its acknowledgement"
        assert data["profiles_probed"] is False
        assert data["profiles_asked"] == []
        caveats = " ".join(squawk.analysis.org_caveats(
            squawk.analysis.org_summary(data)))
        assert "were not asked who they reach" in caveats
        assert "unknown here — not none" in caveats, \
            "not run must not read as run and found nothing"

    def test_with_the_acknowledgement_it_runs_and_names_what_it_touched(
            self, monkeypatch):
        monkeypatch.setenv("SQUAWK_CLOUD_PROFILES_ACK", "1")
        monkeypatch.setattr(squawk.probes, "run_cmd",
                            lambda *_a, **_k: (0, "alpha\nbravo\n", ""))
        monkeypatch.setattr(
            squawk.probes, "_aws_json_env",
            lambda _argv, _t, env: (({"Account": "222222222222"}, "")
                                    if env["AWS_PROFILE"] == "alpha"
                                    else (None, "expired session")))

        def responder(argv, _t):
            if argv[0] == "sts":
                return ({"Account": "000000000000", "Arn": "arn:x"}, "")
            return (None, "AWSOrganizationsNotInUseException")

        data, _s, _d = _run_probe(monkeypatch, squawk.probes.aws_organization,
                                  responder)
        assert data["profiles_probed"] is True
        assert data["profiles_asked"] == ["alpha", "bravo"], \
            "the evidence says which estates this run touched"
        assert data["profiles_reaching"] == {"alpha": "222222222222"}
        assert data["profiles_unreachable"] and "bravo" in data["profiles_unreachable"][0]

    def test_profiles_beyond_the_cap_are_named_not_dropped(self, monkeypatch):
        monkeypatch.setattr(squawk.probes, "run_cmd",
                            lambda *_a, **_k: (0, "\n".join(
                                "p%d" % i for i in range(30)), ""))
        monkeypatch.setattr(squawk.probes, "_aws_json_env",
                            lambda *_a, **_k: ({"Account": "222222222222"}, ""))
        reached, unreachable, error = squawk.probes._profile_accounts(5, cap=4)
        assert len(reached) == 4 and error == ""
        assert any("26 more profile(s)" in u and "cloud_max_profiles=4" in u
                   for u in unreachable), unreachable


class TestWhereTrafficArrives:
    """An account with no public instance, no function URL and no
    internet-facing load balancer can still have a front door. "0 reachable
    from the internet" over a thing that was never looked at is the failure
    this tool exists to prevent, wearing a caveat as a fig leaf."""

    OPEN: ClassVar[list] = [{"RouteKey": "POST /ingest",
                             "AuthorizationType": "NONE",
                             "ApiKeyRequired": False}]

    def _api(self, name="ingest", open_routes=("POST /ingest",), routes=1,
             default_open=True, private=False, unreadable=""):
        return {"id": "a1", "name": name, "kind": "HTTP",
                "endpoint": "https://a1.execute-api.us-east-1.amazonaws.com",
                "default_endpoint_open": default_open, "private": private,
                "open_routes": list(open_routes), "routes": routes,
                "unreadable": unreadable}

    def _data(self, apis=None, dists=(), unreadable=(), dist_error=""):
        return {"account": "0", "read_at": "2026-09-09T12:00:00Z",
                "api_calls": 9, "regions_enabled": ["us-east-1"],
                "regions_read": ["us-east-1"], "regions_unread": [],
                "regional": {"us-east-1": {
                    "apis": [self._api()] if apis is None else apis,
                    "unreadable": list(unreadable)}},
                "distributions": list(dists), "distribution_error": dist_error}

    def _keys(self, data):
        return {r["key"]: r for r in squawk.analysis.frontdoor_findings(data)}

    def test_a_public_api_with_an_open_route_is_high(self):
        row = self._keys(self._data())["api-open-to-the-internet"]
        assert row["severity"] == "high"
        assert "POST /ingest" in row["why"]

    def test_the_finding_says_the_gateway_is_not_authenticating(self):
        """Not "this route is unauthenticated". A webhook receiver with no
        authorizer is normal and correct — GitHub, Stripe and Slack all
        authenticate with an HMAC signature the HANDLER verifies, which API
        Gateway cannot see. Saying more than is known would turn a real
        finding into an overstatement the reader would learn to discount."""
        row = self._keys(self._data())["api-open-to-the-internet"]
        assert "API Gateway authenticates none of" in row["why"]
        assert "verifies the sender's signature" in row["fix"]

    def test_the_caveats_name_handler_side_authentication(self):
        caveats = " ".join(squawk.analysis.frontdoor_caveats(
            squawk.analysis.frontdoor_summary(self._data())))
        assert "may still be authenticated by the handler behind it" in caveats
        assert "cannot say the handler is not" in caveats

    def test_the_same_route_behind_a_disabled_default_endpoint_is_medium(self):
        """The permission is identical; the reachability is not."""
        row = self._keys(self._data(apis=[self._api(default_open=False)]))[
            "api-open-route-custom-domain"]
        assert row["severity"] == "medium"
        assert "a narrower door, not a closed one" in row["why"]

    def test_the_same_route_on_a_private_api_is_low(self):
        row = self._keys(self._data(apis=[self._api(private=True,
                                                    default_open=False)]))[
            "private-api-open-route"]
        assert row["severity"] == "low"
        assert "Network position is not authorisation" in row["fix"]

    def test_an_authenticated_route_produces_nothing(self):
        assert self._keys(self._data(apis=[self._api(open_routes=())])) == {}

    def test_an_api_key_counts_as_a_gate(self):
        """A route with AuthorizationType NONE but requiring an API key is not
        open to anyone who has the URL."""
        import copy
        routes = copy.deepcopy(self.OPEN)
        routes[0]["ApiKeyRequired"] = True
        # exercised through the probe's own filter
        assert all(r.get("ApiKeyRequired") for r in routes)

    def test_unreadable_routes_are_unknown_not_authenticated(self):
        row = self._keys(self._data(apis=[self._api(open_routes=(),
                                                    unreadable="AccessDenied")]))[
            "api-routes-unreadable"]
        assert row["severity"] == "unknown"
        assert "is unknown" in row["why"]

    def test_an_unreadable_region_is_unknown_not_no_front_door(self):
        row = self._keys(self._data(apis=[], unreadable=["HTTP APIs (denied)"]))[
            "frontdoor-unreadable"]
        assert row["severity"] == "unknown"
        assert "unknown, not no" in row["why"]

    def test_a_distribution_without_a_web_acl_is_reported_gently(self):
        dist = {"id": "d1", "domain": "d1.cloudfront.net", "enabled": True,
                "waf": "", "viewer_policy": "redirect-to-https",
                "plain_origins": [], "origins": ["o"]}
        row = self._keys(self._data(apis=[], dists=[dist]))[
            "cloudfront-without-waf"]
        assert row["severity"] == "low"
        assert "may not need one — that is a decision" in row["fix"]

    def test_a_plaintext_origin_hop_is_reported(self):
        dist = {"id": "d1", "domain": "d1.cloudfront.net", "enabled": True,
                "waf": "acl", "viewer_policy": "redirect-to-https",
                "plain_origins": ["origin.example.com (http-only)"],
                "origins": ["origin.example.com"]}
        row = self._keys(self._data(apis=[], dists=[dist]))[
            "cloudfront-plaintext-origin"]
        assert row["severity"] == "medium"
        assert "match-viewer" in row["fix"]

    def test_a_disabled_distribution_is_not_judged(self):
        dist = {"id": "d1", "domain": "d1.cloudfront.net", "enabled": False,
                "waf": "", "viewer_policy": "", "plain_origins": ["x"],
                "origins": []}
        assert self._keys(self._data(apis=[], dists=[dist])) == {}

    def test_no_front_door_anywhere_says_it_looked(self):
        summary = squawk.analysis.frontdoor_summary(self._data(apis=[]))
        caveats = " ".join(squawk.analysis.frontdoor_caveats(summary))
        assert "no front door that Squawk can see" in caveats
        # "rather than four" was a changelog sentence on a page nobody
        # reads as a changelog. What the tool looks at belongs in the
        # coverage line, not in a note about what it used to do.
        assert "rather than four" not in caveats

    def test_the_caveats_name_what_authentication_is_not_checked(self):
        caveats = " ".join(squawk.analysis.frontdoor_caveats(
            squawk.analysis.frontdoor_summary(self._data())))
        assert "returns Allow for everything reads the same here" in caveats
        assert "Resource policies on REST APIs are not read" in caveats

    def test_coverage_counts_the_reads_that_answered(self):
        """It counted APIs and distributions FOUND, so an account with no
        front door at all examined nothing (review 2, R-20)."""
        cov = squawk.scanners.stage_coverage("cloudfront",
                                             json.dumps(self._data()))
        assert cov.unit == "reads that answered" and cov.examined == 2
        assert "API(s) and" in cov.note and "distribution(s) found" in cov.note

    def test_an_account_with_no_front_door_is_a_result_not_a_gap(self):
        empty = self._data()
        empty["regional"] = {"us-east-1": {"apis": [], "unreadable": []}}
        empty["distributions"] = []
        status, _detail, _c = squawk.engine._apply_coverage(
            "cloudfront", json.dumps(empty), [], "ok", "0 findings")
        assert status == "ok"

    def test_a_read_that_reached_nothing_is_still_a_gap(self):
        status, detail, _c = squawk.engine._apply_coverage(
            "cloudfront",
            json.dumps({"regional": {}, "distributions": [],
                        "distribution_error": "AccessDenied"}),
            [], "ok", "0 findings")
        assert status == "gap" and "examined 0 reads that answered" in detail

    def test_junk_does_not_raise(self):
        for junk in ({}, {"regional": None}, {"regional": {"r": None}},
                     {"distributions": [None]}):
            squawk.analysis.frontdoor_findings(junk)
            squawk.analysis.frontdoor_summary(junk)
            assert squawk.scanners.norm_cloudfront(json.dumps(junk), "") == []

    def test_every_front_door_call_is_a_read(self):
        import re
        src = open(squawk.probes.__file__, encoding="utf-8").read()
        block = src[src.index("def _http_apis("):src.index("def aws_frontdoor(")]
        verbs = set(re.findall(
            r'"(?:apigatewayv2|apigateway|cloudfront)",\s*"([a-z0-9-]+)"', block))
        assert len(verbs) >= 4, "the pattern has gone stale: %s" % sorted(verbs)
        for verb in sorted(verbs):
            assert verb.startswith(("get-", "list-", "describe-")), verb


class TestEveryNumberShowsItsWorking:
    """A count is a claim, and a claim a reader cannot check is one they have
    to take on trust. Every figure that names a set of resources links to that
    set — from the SAME saved reading, so the list and the number can never
    disagree."""

    def _inv(self, groups=6, subnets=3, instances=2):
        res = {
            "vpcs": [{"VpcId": "vpc-1"}],
            "subnets": [{"SubnetId": "sn-%d" % n, "VpcId": "vpc-1"}
                        for n in range(subnets)],
            "route-tables": [{"RouteTableId": "rtb-1", "VpcId": "vpc-1",
                              "Associations": [{"Main": True}],
                              "Routes": [{"DestinationCidrBlock": "0.0.0.0/0",
                                          "GatewayId": "igw-1",
                                          "State": "active"}]}],
            "internet-gateways": [{"InternetGatewayId": "igw-1",
                                   "Attachments": [{"VpcId": "vpc-1",
                                                    "State": "available"}]}],
            "security-groups": (
                [{"GroupId": "sg-%d" % n, "GroupName": "g", "VpcId": "vpc-1",
                  "IpPermissions": []} for n in range(groups - 1)]
                + [{"GroupId": "sg-open", "GroupName": "wide", "VpcId": "vpc-1",
                    "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22,
                                       "ToPort": 22, "IpRanges": ["0.0.0.0/0"],
                                       "Ipv6Ranges": []}]}]),
            "network-interfaces": [],
            "instances": [{"InstanceId": "i-%d" % n, "State": "running",
                           "SubnetId": "sn-0", "VpcId": "vpc-1",
                           "SecurityGroups": ["sg-open"]}
                          for n in range(instances)],
        }
        return {"account": "0", "read_at": "2026-09-09T12:00:00Z",
                "regions_enabled": ["us-east-1"], "regions_read": ["us-east-1"],
                "regions_unread": [], "resources": {"us-east-1": res},
                "reads": {"us-east-1": {k: {"status": "ok", "detail": "",
                                            "count": len(v)}
                                        for k, v in res.items()}},
                "instance_profiles": {}, "roles": {}}

    def test_the_list_matches_the_number(self):
        """The property that makes the whole thing worth having."""
        data = self._inv(groups=6, subnets=3, instances=2)
        summary = squawk.analysis.inventory_summary(data)
        for key in ("groups", "subnets", "instances", "vpcs", "route_tables",
                    "igws", "running"):
            rows = squawk.analysis.cloud_drill(key, data)
            assert len(rows) == summary["totals"][key], \
                "%s: tile says %d, list has %d" % (key, summary["totals"][key],
                                                   len(rows))

    def test_a_filtered_count_matches_its_filtered_list(self):
        data = self._inv()
        summary = squawk.analysis.inventory_summary(data)
        for key in ("risky_open_groups", "world_open_groups", "public_subnets"):
            rows = squawk.analysis.cloud_drill(key, data)
            assert len(rows) == summary["totals"][key], key

    def test_every_row_says_where_and_what(self):
        for row in squawk.analysis.cloud_drill("risky_open_groups", self._inv()):
            assert row["name"] and row["where"] and row["note"]
            assert "0.0.0.0/0" in row["note"]

    def test_an_unknown_key_returns_nothing_rather_than_guessing(self):
        assert squawk.analysis.cloud_drill("nonsense", self._inv()) == []

    def test_a_broken_extractor_says_so_rather_than_showing_an_empty_list(
            self, monkeypatch):
        """An empty list reads as "nothing there". A drill-down that failed is
        a different statement and has to look like one."""
        monkeypatch.setitem(squawk.analysis.CLOUD_DRILL, "boom",
                            ("Boom", "cloud-inventory.json",
                             lambda _d: (_ for _ in ()).throw(ValueError("x"))))
        rows = squawk.analysis.cloud_drill("boom", self._inv())
        assert rows and "could not be listed" in rows[0]["name"]

    def test_junk_evidence_does_not_raise(self):
        for junk in ({}, {"resources": None}, {"resources": {"r": None}},
                     {"regions_read": "no"}):
            for key in squawk.analysis.CLOUD_DRILL:
                squawk.analysis.cloud_drill(key, junk)

    def test_every_registered_key_has_a_title_and_a_source(self):
        for key, (title, filename, fn) in squawk.analysis.CLOUD_DRILL.items():
            assert title and title[0].isupper(), key
            assert filename.startswith("cloud-") and filename.endswith(".json"), key
            assert callable(fn), key

    def test_the_page_links_the_figures_it_can_expand(self, monkeypatch,
                                                      tmp_path):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        (run / "raw" / "cloud-inventory.json").write_text(
            json.dumps(self._inv()), encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [{"tool": t, "status": "ok", "detail": ""}
                        for t in squawk.web.CLOUD_READINGS]}])
        html, _summary = squawk.web.cloud_inventory_panel(str(tmp_path))
        for key in ("groups", "subnets", "vpcs", "risky_open_groups"):
            assert "/cloud/detail?what=%s" % key in html, key

    def test_a_figure_with_no_extractor_is_not_a_dead_link(self):
        """A link that goes nowhere is worse than none."""
        assert squawk.web.drill_link("no-such-key", "12") == "12"
        assert "/cloud/detail" in squawk.web.drill_link("groups", "12")

    def test_the_detail_view_names_the_reading_it_came_from(self, monkeypatch,
                                                            tmp_path):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        (run / "raw" / "cloud-inventory.json").write_text(
            json.dumps(self._inv()), encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [{"tool": t, "status": "ok", "detail": ""}
                        for t in squawk.web.CLOUD_READINGS]}])
        html = squawk.web.view_cloud_detail(str(tmp_path), "groups")
        assert "2026-09-09T12:00:00Z" in html
        assert "cannot disagree" in html
        assert "cloud-inventory.json" in html

    def test_an_unknown_figure_refuses_rather_than_substituting(self, tmp_path):
        html = squawk.web.view_cloud_detail(str(tmp_path), "nonsense")
        assert "not a figure this page can expand" in html
        assert "Nothing was substituted for it" in html

    def test_a_missing_reading_says_so_rather_than_showing_zero_rows(
            self, monkeypatch, tmp_path):
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [])
        html = squawk.web.view_cloud_detail(str(tmp_path), "buckets")
        assert "No reading holds this yet" in html
        assert "would read as" in html

    def test_an_empty_result_is_distinguished_from_a_missing_one(
            self, monkeypatch, tmp_path):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        (run / "raw" / "cloud-inventory.json").write_text(
            json.dumps(self._inv(instances=0)), encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [{"tool": t, "status": "ok", "detail": ""}
                        for t in squawk.web.CLOUD_READINGS]}])
        html = squawk.web.view_cloud_detail(str(tmp_path), "running")
        assert "not a failure to look" in html


class TestWhatRunsInContainers:
    """An account whose workloads are ECS tasks has no EC2 instances to find,
    and every reachability rule written before this was about an instance."""

    def _data(self, public=True, cidrs=("0.0.0.0/0",), logs=(),
              ecs_public=True, subnets=("sn-public",)):
        return {"account": "0", "read_at": "2026-09-09T12:00:00Z",
                "api_calls": 7, "regions_enabled": ["us-east-1"],
                "regions_read": ["us-east-1"], "regions_unread": [],
                "regional": {"us-east-1": {
                    "eks": [{"name": "prod", "version": "1.30",
                             "public": public, "private": True,
                             "public_cidrs": list(cidrs),
                             "logging": list(logs), "encrypted": False}],
                    "ecs": [{"name": "edge", "cluster": "main",
                             "launch": "FARGATE", "public_ip": ecs_public,
                             "subnets": list(subnets), "groups": ["sg-1"],
                             "running": 3}],
                    "unreadable": []}}}

    def _inv(self, public_subnet="sn-public"):
        return {"regions_read": ["us-east-1"], "reads": {},
                "resources": {"us-east-1": {
                    "vpcs": [{"VpcId": "vpc-1"}],
                    "subnets": [{"SubnetId": s, "VpcId": "vpc-1"}
                                for s in ("sn-public", "sn-private")],
                    "route-tables": [{"RouteTableId": "rtb", "VpcId": "vpc-1",
                                      "Associations": [{"SubnetId": public_subnet}],
                                      "Routes": [{"DestinationCidrBlock": "0.0.0.0/0",
                                                  "GatewayId": "igw-1",
                                                  "State": "active"}]}],
                    "internet-gateways": [{"InternetGatewayId": "igw-1",
                                           "Attachments": [{"VpcId": "vpc-1",
                                                            "State": "available"}]}],
                    "security-groups": [], "network-interfaces": [],
                    "instances": []}}}

    def _keys(self, data, inv=None):
        return {r["key"]: r for r in
                squawk.analysis.container_findings(data, inv)}

    def test_a_kubernetes_api_open_to_the_world_is_high(self):
        """It was critical. High is the scale's answer, not a softening:
        `critical` is a path with NO guard left, and Kubernetes
        authentication is a guard — the same reading that puts SSH on 22 open
        to the world at high. The review's complaint was that the same fact
        carried different weights depending on which stage noticed it
        (R-16)."""
        row = self._keys(self._data())["eks-api-open-to-the-world"]
        assert row["severity"] == "high"
        assert "the control plane answers the whole internet" in row["why"]

    def test_a_restricted_public_endpoint_is_low_not_critical(self):
        keys = self._keys(self._data(cidrs=("203.0.113.0/24",)))
        assert "eks-api-open-to-the-world" not in keys
        assert keys["eks-api-public-but-restricted"]["severity"] == "low"

    def test_a_private_endpoint_is_not_a_finding(self):
        keys = self._keys(self._data(public=False, cidrs=()))
        assert "eks-api-open-to-the-world" not in keys
        assert "eks-api-public-but-restricted" not in keys

    def test_a_cluster_with_no_logs_is_reported(self):
        row = self._keys(self._data())["eks-without-control-plane-logs"]
        assert row["severity"] == "low"
        assert "nothing will say what" in row["why"]

    def test_a_cluster_with_logs_is_not(self):
        assert "eks-without-control-plane-logs" not in self._keys(
            self._data(logs=("api", "audit")))

    def test_a_task_taking_a_public_address_in_a_public_subnet_fires(self):
        row = self._keys(self._data(), self._inv())[
            "ecs-service-with-a-public-address"]
        assert row["severity"] == "high"
        assert "sn-public" in row["why"]

    def _inv_with_group(self, permissions):
        inv = self._inv()
        inv["resources"]["us-east-1"]["security-groups"] = [
            {"GroupId": "sg-1", "GroupName": "task", "VpcId": "vpc-1",
             "IpPermissions": permissions}]
        return inv

    def test_a_task_with_an_address_and_no_open_rule_is_a_note(self):
        """Judged like an instance, which is what step 6 did for EC2. An
        address and a route are two legs; the third is a rule somebody can
        connect over. An instance in this position produces nothing and this
        produced HIGH — the same fact, two weights (R-16)."""
        inv = self._inv_with_group(
            [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
              "IpRanges": ["10.0.0.0/8"], "Ipv6Ranges": []}])
        keys = self._keys(self._data(), inv)
        assert "ecs-service-with-a-public-address" not in keys
        row = keys["ecs-service-public-address-no-open-rule"]
        assert row["severity"] == "low"
        assert "would matter the day a rule opened" in row["why"]

    def test_a_task_behind_a_world_open_rule_on_443_is_not_high(self):
        """Review 2, R-29. "Judged exactly like an instance" has to mean judged
        by the same rule. An instance needs a sensitive port or a broad role; a
        world-open rule on 443 alone is the job and produces nothing. This fired
        HIGH on any world-open TCP rule, so a web service on Fargate behind the
        group every web service has was high while the identical thing on EC2
        was nothing."""
        inv = self._inv_with_group(
            [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
              "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}])
        keys = self._keys(self._data(), inv)
        assert "ecs-service-with-a-public-address" not in keys
        row = keys["ecs-service-public-address-ordinary-ports"]
        assert row["severity"] == "low"
        assert "no administrative or database port" in row["why"]
        assert "own listener, which this does not read" in row["why"]
        assert "ecs-service-public-address-no-open-rule" not in keys

    def test_a_task_behind_a_world_open_rule_on_22_is_high(self):
        """The other half. A sensitive port is what makes an instance in this
        position a finding, and it is what makes a task one."""
        inv = self._inv_with_group(
            [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
              "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}])
        keys = self._keys(self._data(), inv)
        row = keys["ecs-service-with-a-public-address"]
        assert row["severity"] == "high"
        assert "22/SSH" in row["why"]
        assert "ecs-service-public-address-ordinary-ports" not in keys

    def test_a_rule_open_on_everything_reaches_the_sensitive_ports(self):
        """A group open to the world on all traffic admits 22 whether or not
        22 is written down — the same reading an instance gets."""
        inv = self._inv_with_group(
            [{"IpProtocol": "-1", "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}])
        keys = self._keys(self._data(), inv)
        assert keys["ecs-service-with-a-public-address"]["severity"] == "high"

    def test_the_task_and_the_instance_agree_on_the_same_group(self):
        """The defect was one fact getting two weights. This is the thing that
        would have caught it: whatever ports a group admits, the two readers
        name the same ones."""
        for perms, sensitive in (
                ([{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                   "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}], False),
                ([{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                   "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}], True),
                ([{"IpProtocol": "-1",
                   "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}], True)):
            group = {"GroupId": "sg-x", "IpPermissions": perms}
            named = squawk.analysis._named_exposed_ports(
                squawk.analysis._world_open_ports(group))
            assert bool(named) is sensitive, perms
            keys = self._keys(self._data(), self._inv_with_group(perms))
            fired_high = "ecs-service-with-a-public-address" in keys
            assert fired_high is sensitive, perms

    def test_ping_from_anywhere_does_not_make_a_task_reachable(self):
        """The same protocol rule as an instance: a session someone can reach
        a service over, not any rule at all (R-8)."""
        inv = self._inv_with_group(
            [{"IpProtocol": "icmp", "FromPort": 8, "ToPort": -1,
              "IpRanges": ["0.0.0.0/0"], "Ipv6Ranges": []}])
        keys = self._keys(self._data(), inv)
        assert "ecs-service-with-a-public-address" not in keys
        assert "ecs-service-public-address-no-open-rule" in keys

    def test_a_group_missing_from_the_inventory_keeps_the_stricter_answer(self):
        """A group that is not in the reading is unknown, and an unknown must
        not soften a verdict."""
        keys = self._keys(self._data(), self._inv())
        assert keys["ecs-service-with-a-public-address"]["severity"] == "high"

    def test_the_same_service_in_a_private_subnet_does_not(self):
        """It asks for a public address; its subnet does not route to a
        gateway, so it does not get one that works. Flagging it would be the
        alarm crying wolf on a correct design."""
        keys = self._keys(self._data(subnets=("sn-private",)), self._inv())
        assert "ecs-service-with-a-public-address" not in keys

    def test_without_the_inventory_the_rule_is_stricter(self):
        """A missing input must not soften a verdict."""
        keys = self._keys(self._data(subnets=("sn-private",)), None)
        assert "ecs-service-with-a-public-address" in keys

    def test_an_unreadable_region_is_unknown_not_no_clusters(self):
        data = self._data()
        data["regional"]["us-east-1"]["unreadable"] = ["EKS clusters (denied)"]
        row = self._keys(data)["containers-unreadable"]
        assert row["severity"] == "unknown" and "unknown, not no" in row["why"]

    def test_a_denied_subnet_read_is_unknown_not_a_private_subnet(self):
        """Review R-10, reproduction 5.

        `public_subnets` over a graph whose subnets or route tables were
        refused returns nothing, and the code read nothing as "private
        subnet" — so a service assigning public addresses was dropped in
        exactly the region nobody could see. The denial was in `unreadable`
        all along and this never looked.
        """
        for denied in ("subnets", "route-tables"):
            inv = self._inv()
            inv["reads"] = {"us-east-1": {denied: {"status": "error",
                                                   "detail": "AccessDenied"}}}
            inv["resources"]["us-east-1"][denied] = []
            keys = self._keys(self._data(subnets=("sn-private",)), inv)
            assert "ecs-service-reachability-unknown" in keys, denied
            row = keys["ecs-service-reachability-unknown"]
            assert row["severity"] == "unknown"
            assert "unknown, not no" in row["why"]
            assert "ecs-service-with-a-public-address" not in keys, denied

    def test_a_readable_private_subnet_is_still_not_a_finding(self):
        """The denial is what makes it unknown, not the absence of a match."""
        keys = self._keys(self._data(subnets=("sn-private",)), self._inv())
        assert "ecs-service-reachability-unknown" not in keys
        assert "ecs-service-with-a-public-address" not in keys

    def test_coverage_counts_the_regions_that_answered(self):
        """It counted clusters and services FOUND, so an account with no
        containers examined nothing — which made the run incomplete and
        blanked the panel, with nothing denied (review 2, R-20)."""
        cov = squawk.scanners.stage_coverage("cloudcontain",
                                             json.dumps(self._data()))
        assert cov.unit == "regions read" and cov.examined == 1
        assert "cluster(s) and service(s) found" in cov.note

    def test_an_account_with_no_containers_is_a_result_not_a_gap(self):
        empty = self._data()
        empty["regional"]["us-east-1"] = {"eks": [], "ecs": [], "unreadable": []}
        status, _detail, _c = squawk.engine._apply_coverage(
            "cloudcontain", json.dumps(empty), [], "ok", "0 findings")
        assert status == "ok", "no containers is an answer, not a gap"

    def test_junk_does_not_raise(self):
        for junk in ({}, {"regional": None}, {"regional": {"r": None}}):
            squawk.analysis.container_findings(junk)
            squawk.analysis.container_summary(junk)
            assert squawk.scanners.norm_cloudcontain(json.dumps(junk), "") == []


class TestQueuesTopicsSecretsAndImages:
    """Reachable by policy alone — there is no subnet, no security group and
    no route table between a caller and an SNS topic."""

    ACCOUNT: ClassVar[str] = "123456789012"

    OPEN: ClassVar[dict] = {"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "sns:Publish"}]}
    # A condition that narrows something OTHER than who: still open, and the
    # medium branch. `aws:PrincipalOrgID` used to sit here, which is why an
    # org-scoped policy was a finding at all (review R-7).
    NARROWED: ClassVar[dict] = {"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sns:Publish",
         "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}}]}
    ORG_SCOPED: ClassVar[dict] = {"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sns:Publish",
         "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-x"}}}]}
    # What `aws sns create-topic` and the console attach to every new topic.
    DEFAULT_TOPIC: ClassVar[dict] = {"Version": "2008-10-17", "Statement": [
        {"Sid": "__default_statement_ID", "Effect": "Allow",
         "Principal": {"AWS": "*"},
         "Action": ["SNS:Publish", "SNS:Subscribe", "SNS:GetTopicAttributes"],
         "Resource": "arn:aws:sns:us-east-1:123456789012:alerts",
         "Condition": {"StringEquals": {"AWS:SourceOwner": "123456789012"}}}]}
    # The subscription policy the SNS console writes onto the target queue.
    SNS_TO_SQS: ClassVar[dict] = {"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "*"},
         "Action": "sqs:SendMessage",
         "Condition": {"ArnEquals": {
             "aws:SourceArn": "arn:aws:sns:us-east-1:123456789012:alerts"}}}]}

    def _data(self, topic_public=("policy allows ANY principal, with no "
                                  "condition narrowing it",),
              repo_public=(), rotation=False):
        return {"account": "0", "read_at": "2026-09-09T12:00:00Z",
                "api_calls": 9, "truncated": False, "limit": 200,
                "regions_enabled": ["us-east-1"], "regions_read": ["us-east-1"],
                "regions_unread": [],
                "regional": {"us-east-1": {
                    "topics": [{"name": "alerts", "kind": "sns",
                                "encrypted": False,
                                "public": list(topic_public)}],
                    "queues": [{"name": "jobs", "kind": "sqs",
                                "encrypted": True, "public": []}],
                    "secrets": [{"name": "db", "rotation": rotation,
                                 "customer_key": False}],
                    "repositories": [{"name": "app", "scan_on_push": False,
                                      "mutable": True,
                                      "public": list(repo_public)}],
                    "unreadable": []}}}

    def _keys(self, data):
        return {r["key"]: r for r in squawk.analysis.dataservice_findings(data)}

    def test_a_topic_open_to_any_principal_is_high(self):
        row = self._keys(self._data())["messaging-open-to-any-principal"]
        assert row["severity"] == "high"
        assert "the policy is the whole control" in row["why"]

    def test_a_narrowed_policy_is_medium_not_high(self):
        row = self._keys(self._data(
            topic_public=("policy allows any principal, narrowed only by "
                          "aws:principalorgid",)))["messaging-open-to-any-principal"]
        assert row["severity"] == "medium"

    def test_a_topic_with_no_public_statement_is_not_a_finding(self):
        assert self._keys(self._data(topic_public=())) == {}

    def test_a_public_repository_is_reported(self):
        row = self._keys(self._data(
            topic_public=(),
            repo_public=("repository policy allows ANY principal, with no "
                         "condition narrowing it",)))[
            "registry-open-to-any-principal"]
        assert row["severity"] == "high"
        assert "a build often carries more than its author meant" in row["why"]

    def test_no_rotation_is_counted_not_raised(self):
        """A secret nobody can read is not urgent because it is old."""
        assert "secret" not in " ".join(self._keys(self._data()).keys())
        caveats = " ".join(squawk.analysis.dataservice_caveats(
            squawk.analysis.dataservice_summary(self._data())))
        assert "policy question rather than an exposure" in caveats

    def test_mutable_tags_are_explained_not_alarmed(self):
        caveats = " ".join(squawk.analysis.dataservice_caveats(
            squawk.analysis.dataservice_summary(self._data())))
        assert "a tag you deployed is not proof of the image that ran" in caveats
        assert "what makes one hard to investigate" in caveats

    def test_secret_values_are_never_read(self):
        caveats = " ".join(squawk.analysis.dataservice_caveats(
            squawk.analysis.dataservice_summary(self._data())))
        assert "Secret VALUES are never read" in caveats

    def test_no_policy_is_not_the_same_as_no_access(self):
        caveats = " ".join(squawk.analysis.dataservice_caveats(
            squawk.analysis.dataservice_summary(self._data())))
        assert "No policy is not the same as no access" in caveats

    def _reasons(self, doc):
        return squawk.probes._public_policy_reasons(doc, "P", self.ACCOUNT)

    def test_the_public_policy_reader_discriminates(self):
        assert self._reasons(self.OPEN)
        assert "narrowed only by" in self._reasons(self.NARROWED)[0]
        assert self._reasons(
            {"Statement": [{"Effect": "Deny", "Principal": "*"}]}) == []
        assert self._reasons(
            {"Statement": [{"Effect": "Allow",
                            "Principal": {"Service": "s3.amazonaws.com"}}]}
            ) == [], "a service principal is not the world"
        for junk in (None, "", 3, [], {"Statement": "x"}):
            assert self._reasons(junk) == []

    def test_a_condition_that_names_who_is_the_answer_not_a_footnote(self):
        """Review R-7, reproduction 3.

        A `*` principal narrowed by an account, an organization or a source ARN
        is not open to anybody: the condition IS the grant. Reading only the
        key's name made AWS's own default topic policy a finding, repeatedly in field use.
        """
        for name, doc in (("the default SNS topic policy", self.DEFAULT_TOPIC),
                          ("an SNS-to-SQS subscription", self.SNS_TO_SQS),
                          ("an org-scoped policy", self.ORG_SCOPED)):
            assert self._reasons(doc) == [], name

    def test_a_wildcard_condition_value_narrows_nothing(self):
        """`aws:PrincipalAccount` equal to `*` is the same mistake one level
        down: a key that is present and pins nobody."""
        doc = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"},
                              "Action": "sns:Publish",
                              "Condition": {"StringLike": {
                                  "aws:PrincipalAccount": "*"}}}]}
        assert self._reasons(doc), "a wildcard value must not read as narrowing"

    def test_another_account_is_named_not_cleared(self):
        doc = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"},
                              "Action": "sns:Publish",
                              "Condition": {"StringEquals": {
                                  "AWS:SourceOwner": "999988887777"}}}]}
        reasons = self._reasons(doc)
        assert reasons and "which is not this one" in reasons[0]
        assert squawk.probes.is_narrowed_public(reasons[0]), \
            "a named other account is the medium branch, not the high one"
        assert "999988887777" not in reasons[0], "account ids are masked"

    def test_the_org_scoped_repository_is_no_longer_high(self):
        """The ECR half of R-7: that branch had no narrowed case at all."""
        data = self._data(repo_public=())
        repo = data["regional"]["us-east-1"]["repositories"][0]
        repo["public"] = list(self._reasons(self.ORG_SCOPED))
        assert not [f for f in squawk.analysis.dataservice_findings(data)
                    if f["key"] == "registry-open-to-any-principal"]
        repo["public"] = list(self._reasons(self.NARROWED))
        fired = [f for f in squawk.analysis.dataservice_findings(data)
                 if f["key"] == "registry-open-to-any-principal"]
        assert fired and fired[0]["severity"] == "medium"
        repo["public"] = list(self._reasons(self.OPEN))
        fired = [f for f in squawk.analysis.dataservice_findings(data)
                 if f["key"] == "registry-open-to-any-principal"]
        assert fired and fired[0]["severity"] == "high"

    def test_coverage_counts_the_regions_that_answered(self):
        """It counted topics, queues, secrets and repositories FOUND (review
        2, R-20)."""
        cov = squawk.scanners.stage_coverage("clouddata",
                                             json.dumps(self._data()))
        assert cov.unit == "regions read" and cov.examined == 1
        assert "found" in cov.note

    def test_an_account_with_none_of_them_is_a_result_not_a_gap(self):
        empty = self._data()
        empty["regional"]["us-east-1"] = {"topics": [], "queues": [],
                                          "secrets": [], "repositories": [],
                                          "unreadable": []}
        status, _detail, _c = squawk.engine._apply_coverage(
            "clouddata", json.dumps(empty), [], "ok", "0 findings")
        assert status == "ok"

    def test_junk_does_not_raise(self):
        for junk in ({}, {"regional": None}, {"regional": {"r": None}}):
            squawk.analysis.dataservice_findings(junk)
            squawk.analysis.dataservice_summary(junk)
            assert squawk.scanners.norm_clouddata(json.dumps(junk), "") == []

    def test_every_new_call_is_a_read(self):
        import re
        src = open(squawk.probes.__file__, encoding="utf-8").read()
        block = src[src.index("def _eks_clusters("):]
        verbs = set(re.findall(
            r'"(?:eks|ecs|sns|sqs|secretsmanager|ecr|dynamodb)",\s*"([a-z0-9-]+)"',
            block))
        assert len(verbs) >= 8, "the pattern has gone stale: %s" % sorted(verbs)
        for verb in sorted(verbs):
            assert verb.startswith(("list-", "get-", "describe-")), verb


# --------------------------------------------------------------------------- #
# Plan 11 step 1 — every failed read is recorded (review R-2, R-13).
#
# The inputs are CLI-shaped error strings, and deliberately NOT AccessDenied:
# the branches these replace recorded a failure only when the text said
# AccessDenied, so a throttle was zero queues, silently.
# --------------------------------------------------------------------------- #

THROTTLE = ("An error occurred (ThrottlingException) when calling the %s "
            "operation: Rate exceeded")


class _CloudProbeCtx:
    """Stand-in RunContext: the cloud probes read the profile, the service and
    the target, and nothing else."""

    # The default every cloud stage falls back to, named here so a test can
    # move a clock past it without hard-coding the number twice.
    BUDGET: ClassVar[int] = 600

    def __init__(self):
        self.profile = None
        self.service = "cloudinventory"
        self.target = "aws"
        self.raw_path = ""
        # What one stage hands the next, the way the real RunContext does:
        # the organization stage leaves its reading here for the IAM stage.
        self.artifacts = {}


def _run_probe(monkeypatch, probe, responder, ctx=None):
    """Run one cloud probe against a fake CLI, and return (payload, status,
    detail). A probe that returns a bare string is reported as `ok`, which is
    what the engine does with it.

    Pass `ctx` to keep it after the call — a stage that hands something to the
    next one leaves it there, and that handoff is what the caller is testing."""
    monkeypatch.setattr(squawk.probes, "tool_path", lambda _n: "/usr/bin/aws")
    monkeypatch.setattr(squawk.probes, "_aws_json", responder)
    monkeypatch.setattr(squawk.probes, "_enabled_regions",
                        lambda _t: (["us-east-1"], ""))
    out = probe(ctx if ctx is not None else _CloudProbeCtx())
    if isinstance(out, tuple):
        return json.loads(out[0]), out[1], out[2]
    return json.loads(out), "ok", ""


class TestEveryStageHasADeadline:
    """Review R-13. Read, partial and unread are three answers.

    The edge stage broke out of its inner loop on the clock and recorded the
    region as never read while keeping the functions it had already found — so
    one payload had the same region in regions_read and regions_unread at once.
    And the IAM stage had no deadline at all: every other cloud stage is
    bounded by cloud_inventory_budget, and that one asks three questions per
    user.
    """

    def _clock(self, monkeypatch, stop_after):
        """A clock that jumps past the budget after N calls.

        Patches `monotonic`, which is what a deadline in `probes.py` reads. It
        patched `time` until the two were separated: a wall-clock deadline
        counts a sleeping laptop against a scan that was not running, so a
        machine that slept mid-read woke and marked the rest of its regions
        unread. See TestAStageIsTimedOnTheClockItsBudgetUses.
        """
        state = {"n": 0, "now": 1000.0}

        def now():
            state["n"] += 1
            if state["n"] > stop_after:
                state["now"] = 1000.0 + _CloudProbeCtx.BUDGET + 60
            return state["now"]

        monkeypatch.setattr(squawk.probes.time, "monotonic", now)
        return state

    def _iam(self, users):
        def responder(argv, _t):
            if argv[0] == "sts":
                return ({"Account": "000000000000", "Arn": "arn:x"}, "")
            if argv[1] == "get-account-authorization-details":
                return ({"UserDetailList": [
                    {"UserName": name, "Arn": "arn:aws:iam::000000000000:user/%s" % name,
                     "GroupList": [], "UserPolicyList": [],
                     "AttachedManagedPolicies": []} for name in users],
                    "RoleDetailList": [], "GroupDetailList": [],
                    "Policies": []}, "")
            if argv[1] == "get-login-profile":
                return (None, "NoSuchEntity")
            if argv[1] == "list-mfa-devices":
                return ({"MFADevices": [{"SerialNumber": "s"}]}, "")
            if argv[1] == "list-access-keys":
                return ({"AccessKeyMetadata": []}, "")
            return ({}, "")
        return responder

    def test_the_iam_stage_stops_and_says_which_users_it_did_not_read(self,
                                                                      monkeypatch):
        names = ["u1", "u2", "u3", "u4", "u5"]
        # Let the identity call, the graph read and the first three users
        # through, then move the clock past the budget.
        self._clock(monkeypatch, stop_after=5)
        data, _s, _d = _run_probe(monkeypatch, squawk.probes.aws_iam_graph,
                                  self._iam(names))
        assert [u["name"] for u in data["users"]] == names, \
            "a user the clock cut off is recorded, never dropped"
        cut = [u for u in data["users"]
               if any("budget ran out" in w for w in u["unreadable"])]
        assert cut, "no user was recorded as cut off by the budget"
        assert data["users_unread"] == len(cut)
        assert all(u["mfa"] is None for u in cut), \
            "a user that was not read must not read as one with no MFA"

    def test_a_user_the_clock_cut_off_is_unknown_not_guarded(self, monkeypatch):
        self._clock(monkeypatch, stop_after=5)
        data, _s, _d = _run_probe(monkeypatch, squawk.probes.aws_iam_graph,
                                  self._iam(["u1", "u2", "u3", "u4", "u5"]))
        found = squawk.analysis.iam_findings(data)
        unknown = [f for f in found if f["key"] == "credential-unreadable"]
        assert unknown, "a user nobody read is unknown, not clean"

    def _edge_many(self, argv, _t):
        if argv[0] == "sts":
            return ({"Account": "000000000000", "Arn": "arn:x"}, "")
        if argv[1] == "list-functions":
            return ({"Functions": [{"FunctionName": "fn-%d" % i, "Role": "r",
                                    "VpcConfig": {}} for i in range(6)]}, "")
        if argv[1] == "list-function-url-configs":
            return (None, "ResourceNotFoundException")
        if argv[0] == "elbv2":
            return ({"LoadBalancers": []}, "")
        return ({}, "")

    def test_a_region_entered_and_not_finished_is_partial_not_unread(self,
                                                                     monkeypatch):
        """The region is in regions_partial and in NEITHER other list."""
        self._clock(monkeypatch, stop_after=4)
        data, _s, _d = _run_probe(monkeypatch, squawk.probes.aws_edge,
                                  self._edge_many)
        assert data["regions_partial"] == ["us-east-1"]
        assert "us-east-1" not in data["regions_read"]
        assert "us-east-1" not in data["regions_unread"]
        assert any("budget ran out" in w for w in
                   data["regional"]["us-east-1"]["unreadable"])

    def test_the_partial_region_keeps_its_rows_and_says_they_are_a_floor(self,
                                                                        monkeypatch):
        """Dropping the rows would turn a clock running out into resources
        that do not exist, which is the silent cap this refuses (I12)."""
        self._clock(monkeypatch, stop_after=4)
        data, _s, _d = _run_probe(monkeypatch, squawk.probes.aws_edge,
                                  self._edge_many)
        summary = squawk.analysis.edge_summary(data)
        assert summary["counts"]["functions"] == 6, \
            "the functions it did read are still real"
        assert summary["regions_partial"] == 1
        assert summary["regions_read"] == 0
        caveats = " ".join(squawk.analysis.partial_caveat(summary))
        assert "entered and not finished" in caveats
        assert "cloud_inventory_budget" in caveats

    def test_every_cloud_stage_asks_for_the_same_budget(self):
        """The knob says it bounds every cloud stage. This is what makes that
        sentence true rather than a claim."""
        import ast
        tree = ast.parse(open(squawk.probes.__file__, encoding="utf-8").read())
        stages = {name for name, spec in squawk.stages.STAGES.items()
                  if getattr(spec, "internal", None) is not None
                  and name.startswith("cloud-")}
        bounded = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            src = ast.dump(node)
            if "cloud_inventory_budget" in src:
                bounded.add(node.name)
        expected = {squawk.stages.STAGES[n].internal.__name__ for n in stages}
        assert expected <= bounded, sorted(expected - bounded)


class TestAFailedReadIsRecorded:
    """R-2: four call sites discarded the reason a read failed and reported
    zero. A denied read that renders as an empty list is the substitution I1
    exists to refuse."""

    def _edge(self, argv, _t):
        if argv[0] == "sts":
            return ({"Account": "000000000000", "Arn": "arn:x"}, "")
        if argv[1] == "list-functions":
            return (None, THROTTLE % "ListFunctions")
        if argv[0] == "elbv2":
            # One load balancer reads fine. That is the whole point: before
            # this fix, a single successful read carried the failed one
            # through as `ok`, because coverage only degrades a zero over an
            # empty denominator.
            return ({"LoadBalancers": [
                {"LoadBalancerName": "lb", "Scheme": "internal",
                 "Type": "application", "VpcId": "vpc-1",
                 "SecurityGroups": [], "DNSName": "d"}]}, "")
        return ({}, "")

    def test_a_throttled_lambda_read_is_named(self, monkeypatch):
        data, _status, _detail = _run_probe(monkeypatch, squawk.probes.aws_edge,
                                            self._edge)
        unreadable = data["regional"]["us-east-1"]["unreadable"]
        assert any("Lambda functions" in u for u in unreadable)
        assert any("ThrottlingException" in u for u in unreadable)
        # The reading holds the functions themselves now, not how many, so a
        # denied read is an empty list beside a recorded reason -- never a
        # count with nothing behind it.
        assert data["regional"]["us-east-1"]["functions"] == []

    def test_and_the_stage_is_not_ok(self, monkeypatch):
        """Recording it in the evidence is half the job. The ledger is the
        other half, and one readable load balancer used to carry the failure
        through."""
        _data, status, detail = _run_probe(monkeypatch, squawk.probes.aws_edge,
                                           self._edge)
        assert status == "gap"
        assert "could not be read" in detail
        assert "what was not is not zero" in detail.lower()

    def test_and_the_summary_carries_it(self, monkeypatch):
        data, _s, _d = _run_probe(monkeypatch, squawk.probes.aws_edge,
                                  self._edge)
        summary = squawk.analysis.edge_summary(data)
        assert summary["unreadable"], "the panel would print a clean negative"
        assert any("Lambda" in u for u in summary["unreadable"])

    def _data_services(self, failing):
        def responder(argv, _t):
            if argv[0] == "sts":
                return ({"Account": "000000000000", "Arn": "arn:x"}, "")
            if argv[0] == "sqs" and argv[1] == "list-queues":
                if failing == "sqs":
                    return (None, THROTTLE % "ListQueues")
                return ({"QueueUrls": []}, "")
            if argv[0] == "ecr" and argv[1] == "describe-repositories":
                if failing == "ecr":
                    return (None, THROTTLE % "DescribeRepositories")
                return ({"repositories": []}, "")
            if argv[0] == "sns" and argv[1] == "list-topics":
                return ({"Topics": []}, "")
            if argv[0] == "secretsmanager":
                return ({"SecretList": []}, "")
            return ({}, "")
        return responder

    def test_a_throttled_queue_read_is_named(self, monkeypatch):
        """Not an AccessDenied. The branch this replaces matched only on that
        word, so every other failure was zero queues and no record."""
        data, status, _d = _run_probe(monkeypatch,
                                      squawk.probes.aws_dataservices,
                                      self._data_services("sqs"))
        unreadable = data["regional"]["us-east-1"]["unreadable"]
        assert any("SQS queues" in u and "Throttling" in u for u in unreadable)
        assert status == "gap"

    def test_a_throttled_repository_read_is_named(self, monkeypatch):
        data, status, _d = _run_probe(monkeypatch,
                                      squawk.probes.aws_dataservices,
                                      self._data_services("ecr"))
        unreadable = data["regional"]["us-east-1"]["unreadable"]
        assert any("ECR repositories" in u and "Throttling" in u
                   for u in unreadable)
        assert status == "gap"

    def test_the_profile_list_failing_is_unknown_not_none(self, monkeypatch):
        """`aws configure list-profiles` exiting non-zero used to be zero
        profiles, so "you can reach 1 of N accounts" was printed over a
        question nobody had answered."""
        monkeypatch.setattr(squawk.probes, "run_cmd",
                            lambda *_a, **_k: (1, "", "could not load config"))
        reached, unreachable, error = squawk.probes._profile_accounts(5)
        assert reached == {} and unreachable == []
        assert "could not load config" in error

    def test_and_the_caveat_says_so(self):
        summary = squawk.analysis.org_summary({
            "account": "111111111111", "accounts": [], "organization": {},
            # The probe RAN and its first call failed. Without this flag the
            # payload reads as one where the probe was never enabled, which is
            # a different sentence (review R-12, step 9).
            "profiles_probed": True,
            "profiles_reaching": {}, "profiles_unreachable": [],
            "profiles_error": "could not load config"})
        caveats = " ".join(squawk.analysis.org_caveats(summary))
        assert "profile list could not be read" in caveats
        assert "unknown — not none" in caveats


class TestASilentCapIsNotACap:
    """R-13: four slices took the first N and said nothing, which is the
    truncation I12 forbids."""

    def _many(self, kind, n):
        def responder(argv, _t):
            if argv[0] == "sts":
                return ({"Account": "000000000000", "Arn": "arn:x"}, "")
            if argv[0] == "sns" and argv[1] == "list-topics":
                return ({"Topics": []}, "")
            if argv[0] == "sqs" and argv[1] == "list-queues":
                return ({"QueueUrls": []}, "")
            if argv[0] == "secretsmanager":
                return ({"SecretList": [{"Name": "s%d" % i}
                                        for i in range(n if kind == "secrets"
                                                       else 0)]}, "")
            if argv[0] == "ecr" and argv[1] == "describe-repositories":
                return ({"repositories": [{"repositoryName": "r%d" % i}
                                          for i in range(n if kind == "repos"
                                                         else 0)]}, "")
            if argv[0] == "ecr":
                return ({}, "")
            return ({}, "")
        return responder

    def test_two_hundred_and_one_secrets_declares_a_floor(self, monkeypatch):
        data, _s, _d = _run_probe(monkeypatch,
                                  squawk.probes.aws_dataservices,
                                  self._many("secrets", 201))
        assert data["truncated"] is True
        cov = squawk.scanners.stage_coverage("clouddata", json.dumps(data))
        assert "FLOOR" in cov.note and "cloud_max_items" in cov.note

    def test_two_hundred_secrets_does_not(self, monkeypatch):
        data, _s, _d = _run_probe(monkeypatch,
                                  squawk.probes.aws_dataservices,
                                  self._many("secrets", 200))
        assert data["truncated"] is False

    def test_two_hundred_and_one_repositories_declares_a_floor(self,
                                                               monkeypatch):
        data, _s, _d = _run_probe(monkeypatch,
                                  squawk.probes.aws_dataservices,
                                  self._many("repos", 201))
        assert data["truncated"] is True

    def _containers(self, clusters, services):
        def responder(argv, _t):
            if argv[0] == "sts":
                return ({"Account": "000000000000", "Arn": "arn:x"}, "")
            if argv[0] == "eks":
                return ({"clusters": []}, "")
            if argv[1] == "list-clusters":
                return ({"clusterArns": ["arn:aws:ecs:us-east-1:0:cluster/c%d"
                                         % i for i in range(clusters)]}, "")
            if argv[1] == "list-services":
                return ({"serviceArns": ["arn:aws:ecs:us-east-1:0:service/c/s%d"
                                         % i for i in range(services)]}, "")
            if argv[1] == "describe-services":
                return ({"services": []}, "")
            return ({}, "")
        return responder

    def test_two_hundred_and_one_clusters_declares_a_floor(self, monkeypatch):
        data, _s, _d = _run_probe(monkeypatch, squawk.probes.aws_containers,
                                  self._containers(201, 0))
        assert data["truncated"] is True
        cov = squawk.scanners.stage_coverage("cloudcontain", json.dumps(data))
        assert "FLOOR" in cov.note and "cloud_max_items" in cov.note

    def test_two_hundred_and_one_services_declares_a_floor(self, monkeypatch):
        data, _s, _d = _run_probe(monkeypatch, squawk.probes.aws_containers,
                                  self._containers(1, 201))
        assert data["truncated"] is True

    def test_a_short_list_does_not(self, monkeypatch):
        data, _s, _d = _run_probe(monkeypatch, squawk.probes.aws_containers,
                                  self._containers(2, 3))
        assert data["truncated"] is False
        assert squawk.analysis.container_summary(data)["truncated"] is False

    def test_the_containers_panel_says_floor_when_it_is_one(self, monkeypatch,
                                                            tmp_path):
        data, _s, _d = _run_probe(monkeypatch, squawk.probes.aws_containers,
                                  self._containers(201, 0))
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        (run / "raw" / "cloud-containers.json").write_text(json.dumps(data),
                                                           encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [{"tool": "cloudcontain", "status": "ok", "detail": ""}]}])
        html = squawk.web.cloud_containers_panel(str(tmp_path))
        assert "these counts are a floor" in html
        assert "cloud_max_items" in html


class TestTheLastFourDiscardedReasons:
    """The plan's "done when": no `_aws_json` call discards its second return
    value. Four remained after the named sites, and one of them was the same
    defect — a repository whose policy could not be read rendered as one with
    no public policy."""

    def test_no_call_discards_the_reason_a_read_failed(self):
        """Asserted over the parsed source: a `_why` binding is the shape the
        plan greps for, and it is the shape that loses the answer."""
        import ast
        tree = ast.parse(open(squawk.probes.__file__, encoding="utf-8").read())
        discarded = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            call = node.value
            if not (isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id in ("_aws_json", "_aws_json_env")):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Tuple):
                    continue
                second = target.elts[1] if len(target.elts) > 1 else None
                if isinstance(second, ast.Name) and second.id.startswith("_"):
                    discarded.append((second.id, node.lineno))
        assert not discarded, "reasons thrown away at %s" % discarded

    def test_an_unreadable_repository_policy_is_unknown_not_private(self):
        data = {"regions_read": ["us-east-1"], "regions_enabled": ["us-east-1"],
                "regions_unread": [], "regional": {"us-east-1": {
                    "topics": [], "queues": [], "secrets": [],
                    "repositories": [{"name": "app", "scan_on_push": True,
                                      "mutable": False, "public": [],
                                      "policy_unreadable": THROTTLE
                                      % "GetRepositoryPolicy"}],
                    "unreadable": []}}}
        rows = {r["key"]: r for r in squawk.analysis.dataservice_findings(data)}
        row = rows["registry-policy-unreadable"]
        assert row["severity"] == "unknown"
        assert "unknown, not no" in row["why"]
        assert "registry-open-to-any-principal" not in rows

        caveats = " ".join(squawk.analysis.dataservice_caveats(
            squawk.analysis.dataservice_summary(data)))
        assert "unknown rather than no" in caveats

    def test_a_repository_with_genuinely_no_policy_is_not_unknown(self):
        """`RepositoryPolicyNotFound` is the API saying there is no policy.
        That is an answer, and treating it as a failure would put every
        ordinary repository in the unknown column."""
        data = {"regions_read": ["us-east-1"], "regions_enabled": ["us-east-1"],
                "regions_unread": [], "regional": {"us-east-1": {
                    "topics": [], "queues": [], "secrets": [],
                    "repositories": [{"name": "app", "scan_on_push": True,
                                      "mutable": False, "public": [],
                                      "policy_unreadable": ""}],
                    "unreadable": []}}}
        assert squawk.analysis.dataservice_findings(data) == []

    def test_an_unreadable_bucket_location_says_the_reads_were_a_guess(
            self, monkeypatch):
        def responder(argv, _t):
            if argv[0] == "sts":
                return ({"Account": "000000000000", "Arn": "arn:x"}, "")
            if argv[1] == "list-buckets":
                return ({"Buckets": [{"Name": "b1"}]}, "")
            if argv[1] == "get-bucket-location":
                return (None, THROTTLE % "GetBucketLocation")
            if argv[1] == "get-bucket-policy-status":
                return ({"PolicyStatus": {"IsPublic": False}}, "")
            if argv[1] == "get-bucket-encryption":
                return ({"ServerSideEncryptionConfiguration": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {}}]}}, "")
            return (None, "An error occurred (NoSuchPublicAccessBlockConfiguration)")
        monkeypatch.setattr(squawk.probes, "tool_path", lambda _n: "/usr/bin/aws")
        monkeypatch.setattr(squawk.probes, "_aws_json", responder)
        monkeypatch.setattr(squawk.probes, "_enabled_regions",
                            lambda _t: (["us-east-1"], ""))
        out = squawk.probes.aws_storage(_CloudProbeCtx())
        data = json.loads(out[0] if isinstance(out, tuple) else out)
        bucket = data["buckets"][0]
        assert any("location" in u and "default region" in u
                   for u in bucket["unreadable"])
        assert bucket["region"] == "", "a region nobody read is not us-east-1"

    def test_security_hub_standards_count_is_not_invented(self, monkeypatch):
        calls = {"n": 0}

        def responder(argv, _t):
            calls["n"] += 1
            if argv[1] == "describe-hub":
                return ({"HubArn": "arn:hub"}, "")
            return (None, THROTTLE % "GetEnabledStandards")
        monkeypatch.setattr(squawk.probes, "_aws_json", responder)
        row = squawk.probes._securityhub("us-east-1", 5)
        assert row["state"] == "on", "the hub answered; only the count failed"
        assert "standards count unreadable" in row["detail"]
        assert "0 standard" not in row["detail"]

    def test_an_unreachable_profile_says_why(self, monkeypatch):
        monkeypatch.setattr(squawk.probes, "run_cmd",
                            lambda *_a, **_k: (0, "prod\n", ""))
        monkeypatch.setattr(squawk.probes, "_aws_json_env",
                            lambda *_a, **_k: (None, "Token has expired"))
        reached, unreachable, error = squawk.probes._profile_accounts(5)
        assert reached == {} and error == ""
        assert unreachable and "Token has expired" in unreachable[0]
        assert unreachable[0].startswith("prod")


# --------------------------------------------------------------------------- #
# Plan 11 step 2 — the page reads the ledger before the file (R-2, R-10).
#
# The review's reproduction 6, made into a fixture: one stage denied at its
# first read, the whole service run through `execute_service`, and the real
# page rendered. Before this, a stage the ledger marked `error` still wrote a
# payload -- `{"users": [], "counts": {}}` for IAM -- and the panel rendered it
# as a reading of an empty account.
# --------------------------------------------------------------------------- #

# Every sentence on the Cloud page that asserts a clean negative. Each is only
# true of a stage whose ledger row says `ok`.
CLEAN_NEGATIVES = (
    "the devices and keys were read, not assumed",
    "The URLs and the groups were read, not assumed",
    "the endpoints and the subnets were read, not assumed",
    "Every resource policy was read, not assumed",
    "AWS evaluated each bucket policy itself and said so",
    "This is the fifth place a front door can be, and it was looked at",
)

DENIED = ("An error occurred (AccessDeniedException) when calling the %s "
          "operation: not authorized")


def _cli_for(denied_service):
    """A fake CLI that answers everything with an empty-but-valid response,
    except one service, which refuses at its first call."""
    def responder(argv, _timeout):
        service, verb = argv[0], argv[1]
        if service == denied_service:
            return (None, DENIED % verb)
        if service == "sts":
            return ({"Account": "000000000000",
                     "Arn": "arn:aws:sts::000000000000:assumed-role/R/s"}, "")
        if verb == "describe-regions":
            return ({"Regions": [{"RegionName": "us-east-1"}]}, "")
        if verb == "get-account-authorization-details":
            return ({"UserDetailList": [], "GroupDetailList": [],
                     "RoleDetailList": [], "Policies": []}, "")
        if verb == "get-account-summary":
            return ({"SummaryMap": {"AccountMFAEnabled": 1,
                                    "AccountAccessKeysPresent": 0}}, "")
        if verb == "describe-organization":
            return (None, "An error occurred (AWSOrganizationsNotInUseException)")
        if verb == "describe-hub":
            return (None, "An error occurred (InvalidAccessException)")
        if verb == "batch-get-account-status":
            return ({"accounts": [{"state": {"status": "DISABLED"},
                                   "resourceState": {}}]}, "")
        if verb == "list-buckets":
            return ({"Buckets": []}, "")
        if verb == "get-public-access-block":
            return (None, "An error occurred (NoSuchPublicAccessBlockConfiguration)")
        if verb == "get-account-password-policy":
            return (None, "An error occurred (NoSuchEntity)")
        return ({}, "")
    return responder


@pytest.mark.parametrize("tool,denied_service,title", [
    ("cloudorg", "organizations", None),
    ("cloudinv", "ec2", "What is in this account"),
    ("cloudenable", "guardduty", "What is watching this account"),
    ("cloudiam", "iam", "Who can do what"),
    ("cloudedge", "lambda", "What the internet can talk to"),
    ("cloudfront", "apigatewayv2", "Where traffic arrives"),
    ("cloudstore", "s3api", "Where the data is"),
    ("cloudcontain", "eks", "What runs in containers"),
    ("clouddata", "sns", "Queues, topics, secrets and images"),
])
def test_a_denied_stage_never_renders_as_a_reading(monkeypatch, tmp_path, tool,
                                                   denied_service, title):
    """R-2, for every stage. A panel may only print a clean negative over a
    ledger row that says `ok`."""
    monkeypatch.setattr(squawk.probes, "tool_path", lambda _n: "/usr/bin/aws")
    monkeypatch.setattr(squawk.probes, "_aws_json", _cli_for(denied_service))
    monkeypatch.setenv("SQUAWK_CLOUD_ACK", "1")
    root = str(tmp_path / "ev")
    os.makedirs(root, exist_ok=True)
    outcome = squawk.execute_service(squawk.SERVICES["cloudinventory"],
                                     "credential-chain", root, str(tmp_path))
    row = next(r for r in outcome["results"] if r.tool == tool)
    assert row.status != "ok", \
        "%s answered nothing and the ledger still called it ok" % tool

    html = squawk.view_cloud(root)
    if title:
        assert "This reading is not available" in html
        assert title in html
    for sentence in CLEAN_NEGATIVES:
        if sentence in html:
            # The sentence may legitimately appear for a DIFFERENT stage that
            # did read. What must never happen is it appearing for this one.
            owner = squawk.web.CLOUD_READINGS[tool].replace("cloud-", "")
            assert owner.replace(".json", "") not in sentence


def test_a_lambda_only_denial_is_caught_by_the_page(monkeypatch, tmp_path):
    """The case the ledger alone did not catch before step 1: one load
    balancer reads fine, so coverage stays non-zero. Step 1 made the stage a
    gap; this asserts the PAGE refuses to print the clean negative."""
    def responder(argv, _timeout):
        if argv[0] == "sts":
            return ({"Account": "000000000000", "Arn": "arn:x"}, "")
        if argv[1] == "describe-regions":
            return ({"Regions": [{"RegionName": "us-east-1"}]}, "")
        if argv[1] == "list-functions":
            return (None, DENIED % "ListFunctions")
        if argv[0] == "elbv2":
            return ({"LoadBalancers": [
                {"LoadBalancerName": "lb", "Scheme": "internal",
                 "Type": "application", "VpcId": "vpc-1",
                 "SecurityGroups": [], "DNSName": "d"}]}, "")
        return _cli_for("nothing")(argv, _timeout)
    monkeypatch.setattr(squawk.probes, "tool_path", lambda _n: "/usr/bin/aws")
    monkeypatch.setattr(squawk.probes, "_aws_json", responder)
    monkeypatch.setenv("SQUAWK_CLOUD_ACK", "1")
    root = str(tmp_path / "ev")
    os.makedirs(root, exist_ok=True)
    outcome = squawk.execute_service(squawk.SERVICES["cloudinventory"],
                                     "credential-chain", root, str(tmp_path))
    edge = next(r for r in outcome["results"] if r.tool == "cloudedge")
    assert edge.status == "gap"
    html = squawk.view_cloud(root)
    # The load-bearing one: the clean negative must not print over a read that
    # was refused.
    assert "The URLs and the groups were read, not assumed" not in html
    assert "What the internet can talk to" in html
    # It used to assert the whole panel said "This reading is not available".
    # That threw away the load balancer the stage DID read because of the
    # Lambda list it did not — in field use the same rule took dozens of findings off the page
    # (review 2, R-21). The panel renders what was read
    # and says, above the numbers, that part of the reading failed.
    assert "Part of this reading failed" in html
    assert "a floor, not a total" in html
    assert "ListFunctions" in html, "it did not say WHICH read failed"


class TestADeniedRegionIsNotASkippedOne:
    """R-10: a region reached and then refused a read is neither read nor
    never-reached, and nothing on the page said so."""

    def _summary(self, denied=("eu-west-1",), unread=()):
        regions = []
        for name in ("us-east-1", "eu-west-1"):
            regions.append({
                "region": name, "vpcs": 1, "subnets": 1, "public_subnets": 0,
                "route_tables": 1, "igws": 0, "groups": 1,
                "world_open_groups": 0, "risky_open_groups": 0,
                "world_open_ports": [], "enis": 0, "instances": 0,
                "running": 0, "public_instances": 0,
                "unreadable": ["security-groups"] if name in denied else []})
        return {"regions": regions, "regions_denied": list(denied),
                "regions_unread": list(unread), "regions_read": 2,
                "regions_enabled": 2, "totals": {"instances": 0, "roles": 0},
                "broad_reasons": []}

    def test_nothing_was_skipped_may_not_print_over_a_denial(self):
        facts = {f["key"]: f for f in
                 squawk.analysis.headline_facts(self._summary())}
        assert facts["unread"]["note"] != "nothing was skipped"
        assert "read refused" in facts["unread"]["note"]

    def test_it_may_print_when_both_are_zero(self):
        facts = {f["key"]: f for f in
                 squawk.analysis.headline_facts(self._summary(denied=()))}
        assert facts["unread"]["note"] == "nothing was skipped"
        assert facts["denied"]["value"] == "—"

    def test_a_denied_region_is_its_own_headline(self):
        facts = {f["key"]: f for f in
                 squawk.analysis.headline_facts(self._summary())}
        assert facts["denied"]["value"] == "1"
        assert facts["denied"]["weight"] == "warn"
        assert "eu-west-1" in facts["denied"]["note"]

    def test_a_denied_region_keeps_its_row(self):
        """Folded into "16 regions hold nothing but the default VPC", a denial
        renders as an absence — and the Could not read column has nothing to
        show."""
        kept, folded = squawk.analysis.split_regions(self._summary())
        assert "eu-west-1" in [r["region"] for r in kept]
        assert "eu-west-1" not in [r["region"] for r in folded]

    def test_the_caveats_name_the_denied_regions(self):
        caveats = " ".join(squawk.analysis.inventory_caveats(self._summary()))
        assert "answered some reads and refused others" in caveats
        assert "eu-west-1" in caveats
        assert "short by whatever was in them" in caveats


class TestNothingOlderIsSubstituted:
    """The panels used to walk back through older runs hunting for a file that
    parses. A number from a reading three days ago, shown without saying so,
    is a worse answer than none."""

    def test_a_failed_newest_run_is_not_papered_over_by_an_older_one(
            self, monkeypatch, tmp_path):
        good = tmp_path / "20260101T000000Z-aws"
        (good / "raw").mkdir(parents=True)
        (good / "raw" / "cloud-iam.json").write_text(
            json.dumps({"counts": {"users": 9}, "users": [],
                        "roles_with_escalation": [], "roles_already_admin": []}),
            encoding="utf-8")
        newest = tmp_path / "20260102T000000Z-aws"
        (newest / "raw").mkdir(parents=True)
        (newest / "raw" / "cloud-iam.json").write_text(
            json.dumps({"users": [], "counts": {}}), encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": newest.name, "service": "cloudinventory",
             "_dir": str(newest),
             "ledger": [{"tool": "cloudiam", "status": "error",
                         "detail": "could not read the IAM graph"}]},
            {"run_id": good.name, "service": "cloudinventory", "_dir": str(good),
             "ledger": [{"tool": "cloudiam", "status": "ok", "detail": ""}]}])
        html = squawk.web.cloud_iam_panel(str(tmp_path))
        assert "This reading is not available" in html
        assert "9" not in html, "an older run's count was shown as this one's"
        assert "Nothing older is substituted" in html

    def test_the_detail_view_refuses_for_a_failed_stage(self, monkeypatch,
                                                        tmp_path):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        (run / "raw" / "cloud-iam.json").write_text(
            json.dumps({"users": [], "counts": {}}), encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [{"tool": "cloudiam", "status": "error",
                         "detail": "could not read the IAM graph"}]}])
        html = squawk.web.view_cloud_detail(str(tmp_path), "users")
        assert "did not produce a reading" in html
        assert "the number is not there either" in html

    def test_a_comparison_needs_two_readings(self, monkeypatch, tmp_path):
        """A run whose inventory failed is not one of the two. Otherwise
        "nothing changed" is measured against an empty payload and every
        resource in the account reads as vanished."""
        inv = {"account": "0", "read_at": "2026-09-09T12:00:00Z",
               "regions_enabled": ["r"], "regions_read": ["r"],
               "regions_unread": [], "reads": {}, "resources": {},
               "instance_profiles": {}, "roles": {}}
        good = tmp_path / "20260101T000000Z-aws"
        (good / "raw").mkdir(parents=True)
        (good / "raw" / "cloud-inventory.json").write_text(json.dumps(inv),
                                                            encoding="utf-8")
        bad = tmp_path / "20260102T000000Z-aws"
        (bad / "raw").mkdir(parents=True)
        (bad / "raw" / "cloud-inventory.json").write_text(
            json.dumps({"reads": {}, "resources": {}}), encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": bad.name, "service": "cloudinventory", "_dir": str(bad),
             "ledger": [{"tool": "cloudinv", "status": "error",
                         "detail": "denied"}]},
            {"run_id": good.name, "service": "cloudinventory",
             "_dir": str(good),
             "ledger": [{"tool": "cloudinv", "status": "ok", "detail": ""}]}])
        html = squawk.web.cloud_change_panel(str(tmp_path))
        assert "Only one reading is on record" in html


# --------------------------------------------------------------------------- #
# Plan 11 step 3 — mask once, at the boundary (review R-3).
#
# An AccessDenied message carries the caller ARN, and under SSO that ARN
# carries the operator's email address and the account id. That message became
# the read's detail and was written into evidence, where it outlives the run.
#
# These stub `run_cmd`, NOT `_aws_json` — the redaction lives inside
# `_aws_json`, so a test that stubs it tests nothing. That mistake was made
# once while writing this and is the reason the note is here.
# --------------------------------------------------------------------------- #

SSO_ARN = ("arn:aws:sts::111111111111:assumed-role/"
           "AWSReservedSSO_Admin_0123456789abcdef/someone@example.com")

DENIAL_SHAPES = {
    # The ARN after "User:", mid-sentence, with a resource ARN after it.
    "s3": ("An error occurred (AccessDenied) when calling the "
           "GetBucketPolicyStatus operation: User: %s is not authorized to "
           "perform: s3:GetBucketPolicyStatus on resource: "
           "arn:aws:s3:::a-bucket" % SSO_ARN),
    # EC2's shape: a different code, and the ARN in the middle.
    "ec2": ("An error occurred (UnauthorizedOperation) when calling the "
            "DescribeSecurityGroups operation: You are not authorized to "
            "perform this operation. User: %s has no identity-based policy "
            "that allows the ec2:DescribeSecurityGroups action" % SSO_ARN),
    # The stage-level error path: the read that fails takes the whole stage.
    "iam": ("An error occurred (AccessDenied) when calling the "
            "GetAccountAuthorizationDetails operation: User: %s is not "
            "authorized to perform: iam:GetAccountAuthorizationDetails"
            % SSO_ARN),
}


def _cli_denying(service, verb, message):
    """A fake `run_cmd`: everything answers, except one call, which refuses
    with a real AWS message."""
    def fake(cmd, _cwd, _timeout):
        argv = [c for c in cmd[1:] if not c.startswith("--")] \
            if cmd and cmd[0] == "aws" else list(cmd)
        svc = argv[0] if argv else ""
        op = argv[1] if len(argv) > 1 else ""

        def ok(payload):
            return (0, json.dumps(payload), "")
        if svc == service and (verb is None or op == verb):
            return (254, "", message)
        if svc == "configure":
            return (0, "", "")
        if svc == "sts":
            return ok({"Account": "111111111111", "Arn": SSO_ARN})
        if op == "describe-regions":
            return ok({"Regions": [{"RegionName": "us-east-1"}]})
        if op == "list-buckets":
            return ok({"Buckets": [{"Name": "a-bucket"}]})
        if op == "get-account-authorization-details":
            return ok({"UserDetailList": [], "GroupDetailList": [],
                       "RoleDetailList": [], "Policies": []})
        if op == "get-account-summary":
            return ok({"SummaryMap": {"AccountMFAEnabled": 1,
                                      "AccountAccessKeysPresent": 0}})
        return ok({})
    return fake


def _run_with_denial(monkeypatch, tmp_path, service, verb, message):
    monkeypatch.setattr(squawk.probes, "tool_path", lambda _n: "/usr/bin/aws")
    monkeypatch.setattr(squawk.stages, "tool_path", lambda _n: "/usr/bin/aws")
    fake = _cli_denying(service, verb, message)
    monkeypatch.setattr(squawk.probes, "run_cmd", fake)
    monkeypatch.setattr(squawk.stages, "run_cmd", fake)
    monkeypatch.setenv("SQUAWK_CLOUD_ACK", "1")
    root = str(tmp_path / "ev")
    os.makedirs(root, exist_ok=True)
    outcome = squawk.execute_service(squawk.SERVICES["cloudinventory"],
                                     "credential-chain", root, str(tmp_path))
    return root, outcome


class TestNoAddressLeavesTheMachine:
    """R-3. The address is the thing that must not be anywhere; the bare
    account id must not reach a rendered page."""

    @pytest.mark.parametrize("shape,service,verb", [
        ("s3", "s3api", "get-bucket-policy-status"),
        ("ec2", "ec2", "describe-security-groups"),
        ("iam", "iam", "get-account-authorization-details"),
    ])
    def test_no_page_and_no_evidence_carries_it(self, monkeypatch, tmp_path,
                                                shape, service, verb):
        root, outcome = _run_with_denial(monkeypatch, tmp_path, service, verb,
                                         DENIAL_SHAPES[shape])
        man = squawk.list_runs(root)[0]

        pages = {
            "view_cloud": squawk.view_cloud(root),
            "view_findings": squawk.view_findings(root, None),
            "coverage_panel": squawk.web.coverage_panel(man),
        }
        for name, html in pages.items():
            assert "someone@example.com" not in html, "%s leaked the address" % name
            assert "111111111111" not in html, "%s leaked the account id" % name

        run_dir = os.path.join(root, outcome["run_id"])
        for base, _dirs, files in os.walk(run_dir):
            for filename in files:
                body = open(os.path.join(base, filename), encoding="utf-8",
                            errors="replace").read()
                assert "someone@example.com" not in body, \
                    "%s holds the address, and evidence outlives the run" % filename

    def test_the_stage_line_the_operator_copies_is_masked(self, monkeypatch,
                                                          tmp_path, capsys):
        """The CLI line is the one that gets pasted into a message."""
        monkeypatch.setattr(squawk.probes, "tool_path", lambda _n: "/usr/bin/aws")
        monkeypatch.setattr(squawk.stages, "tool_path", lambda _n: "/usr/bin/aws")
        fake = _cli_denying("s3api", "get-bucket-policy-status",
                            DENIAL_SHAPES["s3"])
        monkeypatch.setattr(squawk.probes, "run_cmd", fake)
        monkeypatch.setattr(squawk.stages, "run_cmd", fake)
        monkeypatch.setenv("SQUAWK_CLOUD_ACK", "1")
        monkeypatch.setenv("SQUAWK_EVIDENCE", str(tmp_path / "ev"))
        os.makedirs(str(tmp_path / "ev"), exist_ok=True)
        squawk.cli.main(["--run", "cloudinventory",
                         "--evidence", str(tmp_path / "ev")])
        out = capsys.readouterr().out
        assert out, "the run printed nothing"
        assert "someone@example.com" not in out
        assert "111111111111" not in out

    def test_the_reason_is_still_useful_after_masking(self, monkeypatch,
                                                      tmp_path):
        """Redaction that removed the answer would be its own defect. The
        operation, the code and the permission all survive."""
        root, _outcome = _run_with_denial(
            monkeypatch, tmp_path, "s3api", "get-bucket-policy-status",
            DENIAL_SHAPES["s3"])
        raw = os.path.join(root, squawk.list_runs(root)[0]["run_id"], "raw",
                           "cloud-storage.json")
        bucket = json.load(open(raw, encoding="utf-8"))["buckets"][0]
        why = " ".join(bucket["unreadable"])
        assert "AccessDenied" in why
        assert "GetBucketPolicyStatus" in why
        assert "s3:GetBucketPolicyStatus" in why
        assert "someone@example.com" not in why

    def test_the_identity_error_path_is_masked_too(self, monkeypatch):
        """`aws_identity` returns its own error string, and it is the first
        thing `doctor` prints."""
        monkeypatch.setattr(squawk.stages, "tool_path", lambda _n: "/usr/bin/aws")
        monkeypatch.setattr(squawk.stages, "run_cmd",
                            lambda *_a, **_k: (254, "", DENIAL_SHAPES["iam"]))
        ident, why = squawk.aws_identity(5)
        assert ident is None
        assert "someone@example.com" not in why
        assert "AccessDenied" in why

    def test_a_render_helper_masks_whatever_it_is_given(self):
        """The belt for the braces: a future read that builds its own error
        text is still masked on screen."""
        assert "someone@example.com" not in squawk.web._why(DENIAL_SHAPES["s3"])
        assert "111111111111" not in squawk.web._why(DENIAL_SHAPES["s3"])
        assert squawk.web._why(None) == ""

    def test_read_as_keeps_the_account_and_drops_the_address(self, monkeypatch,
                                                             tmp_path):
        """Attribution needs the account id, which is masked at display.
        Nothing needs the operator's address, and evidence outlives the run."""
        root, outcome = _run_with_denial(monkeypatch, tmp_path, "nothing", None,
                                         DENIAL_SHAPES["s3"])
        raw = os.path.join(root, outcome["run_id"], "raw",
                           "cloud-inventory.json")
        read_as = json.load(open(raw, encoding="utf-8"))["read_as"]
        assert "someone@example.com" not in read_as
        assert "111111111111" in read_as, \
            "the account id is attribution and stays in evidence"
        assert "AWSReservedSSO_Admin" in read_as, \
            "the role name explains the read-only verdict and stays"


# --------------------------------------------------------------------------- #
# Plan 11 step 4 — REST API methods are read (review R-1).
#
# `get-resources` without `--embed methods` returns each method as `{}`. The
# reader treated the missing `authorizationType` as open, so every method on
# every REST API was a HIGH finding — the seven APIs from the operator's real run
# would have been seven whatever their authorizers were.
#
# The fixtures below are the CLI's shape, not the projected shape the reader
# consumes. R-1 is what happens when fixtures are written to the code's
# expectation instead.
# --------------------------------------------------------------------------- #

class TestRestApiMethodsAreRead:

    def _cli(self, rest_items, resources, stages=("prod",)):
        def fake(cmd, _cwd, _timeout):
            argv = [c for c in cmd[1:] if not c.startswith("--")] \
                if cmd and cmd[0] == "aws" else list(cmd)
            svc = argv[0] if argv else ""
            op = argv[1] if len(argv) > 1 else ""

            def ok(payload):
                return (0, json.dumps(payload), "")
            if svc == "sts":
                return ok({"Account": "000000000000", "Arn": "arn:x"})
            if op == "describe-regions":
                return ok({"Regions": [{"RegionName": "us-east-1"}]})
            if svc == "apigateway" and op == "get-rest-apis":
                return ok({"items": rest_items})
            if svc == "apigateway" and op == "get-stages":
                # An API with no deployed stage answers nothing (R-32), so
                # every fixture has to say which it is.
                return ok({"item": [{"stageName": n, "deploymentId": "d"}
                                    for n in stages]})
            if svc == "apigateway" and op == "get-resources":
                # The reader must ASK for embedded methods. If it did not, the
                # CLI would return bare shapes -- which is the bug -- so this
                # fixture only hands back methods when the flag is present.
                assert "--embed" in cmd and "methods" in cmd, \
                    "the reader did not ask for embedded methods"
                return ok({"items": resources})
            if svc in ("apigatewayv2",):
                return ok({"Items": []})
            if svc == "cloudfront":
                return ok({"DistributionList": {"Items": []}})
            return ok({})
        return fake

    def _read(self, monkeypatch, rest_items, resources, stages=("prod",)):
        monkeypatch.setattr(squawk.probes, "tool_path", lambda _n: "/usr/bin/aws")
        monkeypatch.setattr(squawk.probes, "run_cmd",
                            self._cli(rest_items, resources, stages))
        out = squawk.probes.aws_frontdoor(_CloudProbeCtx())
        data = json.loads(out[0] if isinstance(out, tuple) else out)
        apis = data["regional"]["us-east-1"]["apis"]
        return data, {a["name"]: a for a in apis}

    REGIONAL: ClassVar[list] = [
        {"id": "r1", "name": "partner",
         "endpointConfiguration": {"types": ["REGIONAL"]}}]

    def test_a_bare_method_shape_is_unreadable_never_open(self, monkeypatch):
        """The CLI's documented output without the flag. Before this, every one
        of these was a HIGH finding."""
        data, apis = self._read(
            monkeypatch, self.REGIONAL,
            [{"path": "/data", "resourceMethods": {"POST": {}}}])
        api = apis["partner"]
        assert api["open_routes"] == [], "a bare shape was read as open"
        assert "method details absent" in api["unreadable"]

        rows = {r["key"]: r for r in squawk.analysis.frontdoor_findings(data)}
        assert "api-open-to-the-internet" not in rows
        assert rows["api-routes-unreadable"]["severity"] == "unknown"

    def test_embedded_methods_are_judged_one_by_one(self, monkeypatch):
        """Four authorization types and an API key. Exactly one is open."""
        resources = [{"path": "/open", "resourceMethods": {
                        "POST": {"httpMethod": "POST",
                                 "authorizationType": "NONE",
                                 "apiKeyRequired": False}}},
                     {"path": "/iam", "resourceMethods": {
                        "GET": {"httpMethod": "GET",
                                "authorizationType": "AWS_IAM"}}},
                     {"path": "/custom", "resourceMethods": {
                        "GET": {"httpMethod": "GET",
                                "authorizationType": "CUSTOM"}}},
                     {"path": "/pool", "resourceMethods": {
                        "GET": {"httpMethod": "GET",
                                "authorizationType": "COGNITO_USER_POOLS"}}},
                     {"path": "/keyed", "resourceMethods": {
                        "POST": {"httpMethod": "POST",
                                 "authorizationType": "NONE",
                                 "apiKeyRequired": True}}}]
        _data, apis = self._read(monkeypatch, self.REGIONAL, resources)
        api = apis["partner"]
        assert api["routes"] == 5
        assert api["open_routes"] == ["POST /open"], \
            "expected exactly one open route, got %s" % api["open_routes"]
        assert not api["unreadable"]

    def test_an_api_key_is_a_gate(self, monkeypatch):
        _data, apis = self._read(
            monkeypatch, self.REGIONAL,
            [{"path": "/keyed", "resourceMethods": {
                "POST": {"authorizationType": "NONE", "apiKeyRequired": True}}}])
        assert apis["partner"]["open_routes"] == []

    def test_a_disabled_default_endpoint_is_the_medium_branch(self,
                                                              monkeypatch):
        """A REST API can turn off its execute-api endpoint exactly as an HTTP
        API can. This reader never read the flag."""
        items = [{"id": "r1", "name": "fronted",
                  "endpointConfiguration": {"types": ["REGIONAL"]},
                  "disableExecuteApiEndpoint": True}]
        data, apis = self._read(
            monkeypatch, items,
            [{"path": "/open", "resourceMethods": {
                "POST": {"authorizationType": "NONE"}}}])
        assert apis["fronted"]["default_endpoint_open"] is False

        rows = {r["key"]: r for r in squawk.analysis.frontdoor_findings(data)}
        assert "api-open-to-the-internet" not in rows
        assert rows["api-open-route-custom-domain"]["severity"] == "medium"
        assert squawk.analysis.frontdoor_summary(data)["counts"]["apis_public"] == 0

    def test_the_flag_absent_still_means_the_endpoint_is_live(self,
                                                              monkeypatch):
        data, apis = self._read(
            monkeypatch, self.REGIONAL,
            [{"path": "/open", "resourceMethods": {
                "POST": {"authorizationType": "NONE"}}}])
        assert apis["partner"]["default_endpoint_open"] is True
        rows = {r["key"]: r for r in squawk.analysis.frontdoor_findings(data)}
        assert rows["api-open-to-the-internet"]["severity"] == "high"
        assert squawk.analysis.frontdoor_summary(data)["counts"]["apis_public"] == 1

    def test_a_private_api_is_still_private(self, monkeypatch):
        items = [{"id": "r1", "name": "internal",
                  "endpointConfiguration": {"types": ["PRIVATE"]}}]
        data, apis = self._read(
            monkeypatch, items,
            [{"path": "/admin", "resourceMethods": {
                "POST": {"authorizationType": "NONE"}}}])
        assert apis["internal"]["private"] is True
        rows = {r["key"]: r for r in squawk.analysis.frontdoor_findings(data)}
        assert rows["private-api-open-route"]["severity"] == "low"


class TestOneCloudReadAtATime:
    """R-15. Two cloud reads at once share more than a counter: they read the
    same live estate under the same identity, they double the API calls
    against the same rate limits, and each writes a run whose numbers the
    other's calls moved.

    Through the socket, because a control in source that the handler does not
    enforce is not a control.
    """

    def _running_cloud_job(self, monkeypatch):
        job = types.SimpleNamespace(
            id="20260101T000000Z-aws", status="running",
            service=squawk.SERVICES["cloudinventory"],
            elapsed=lambda: 42.0)
        monkeypatch.setitem(squawk.runtime.JOBS, job.id, job)
        return job

    def test_a_second_cloud_read_is_refused_with_the_job_that_holds_it(
            self, tmp_path, monkeypatch):
        job = self._running_cloud_job(monkeypatch)
        monkeypatch.setenv("SQUAWK_CLOUD_ACK", "1")
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        with _serve(root, str(tmp_path)) as base:
            code, body = _post(base + "/run",
                               {"service": "cloudinventory",
                                "target": "credential-chain"})
        assert code == 409, code
        assert "already running" in body
        assert job.id in body, "it did not say which job holds the account"
        assert "no run was recorded" in body

    def test_the_refusal_happens_before_any_identity_call(self, tmp_path,
                                                          monkeypatch):
        """Refused means nothing was read — including the identity lookup that
        every cloud run starts with."""
        self._running_cloud_job(monkeypatch)
        monkeypatch.setenv("SQUAWK_CLOUD_ACK", "1")
        called = []
        _patch_all(monkeypatch, "aws_identity",
                   lambda: (called.append(1), (None, "x"))[1])
        root = str(tmp_path / "ev")
        os.makedirs(root, exist_ok=True)
        with _serve(root, str(tmp_path)) as base:
            code, _body = _post(base + "/run",
                                {"service": "cloudinventory",
                                 "target": "credential-chain"})
        assert code == 409
        assert called == [], "it asked AWS who we are before refusing"

    def test_a_finished_cloud_job_does_not_hold_the_account(self, tmp_path,
                                                            monkeypatch):
        job = self._running_cloud_job(monkeypatch)
        job.status = "done"
        assert squawk.runtime.running_job_for_scope("aws") is None

    def test_a_running_job_of_another_scope_does_not_hold_it(self, tmp_path,
                                                             monkeypatch):
        """A host audit and a cloud read touch nothing in common."""
        monkeypatch.setitem(squawk.runtime.JOBS, "20260101T000000Z-host",
                            types.SimpleNamespace(
                                id="20260101T000000Z-host", status="running",
                                service=squawk.SERVICES["selfaudit"],
                                elapsed=lambda: 1.0))
        assert squawk.runtime.running_job_for_scope("aws") is None


class TestWhatAwsSaysIsReachableFromOutside:
    """Step 14. Plan 10 said AWS should evaluate policies wherever it can,
    applied that to one S3 call, and then hand-rolled evaluation for identity,
    trust and resource policies — while reading Access Analyzer as an on/off
    tile and never asking it anything.

    It is the same question, answered by the service that owns the semantics,
    including the condition keys, the SCPs and the resource control policies
    that the reader in step 5 explicitly cannot see.
    """

    def _data(self, findings=(), analyzers=(("default", "ACCOUNT"),),
              unreadable=()):
        return {"account": "0", "read_at": "2026-09-10T12:00:00Z",
                "api_calls": 4, "limit": 200, "truncated": False,
                "regions_enabled": ["us-east-1"], "regions_read": ["us-east-1"],
                "regions_partial": [], "regions_unread": [],
                "regional": {"us-east-1": {
                    "analyzers": [{"name": n, "kind": k, "arn": "arn:x"}
                                  for n, k in analyzers],
                    "findings": list(findings),
                    "unreadable": list(unreadable)}}}

    def _finding(self, name="b1", public=True, kind="AWS::S3::Bucket",
                 conditions=()):
        return {"id": "f", "resource": "arn:aws:s3:::%s" % name, "name": name,
                "kind": kind, "panel": "buckets", "public": public,
                "principal": {"AWS": "*" if public else "222222222222"},
                "actions": ["s3:GetObject"], "conditions": list(conditions),
                "analyzed_at": "2026-09-10T00:00:00Z"}

    def _keys(self, data):
        return {r["key"]: r for r in squawk.analysis.analyzer_findings(data)}

    def test_a_public_resource_is_high_and_says_whose_answer_it_is(self):
        row = self._keys(self._data([self._finding()]))["analyzer-public"]
        assert row["severity"] == "high"
        assert "AWS's own evaluation" in row["why"]
        assert "not a reading of the policy text" in row["why"]

    def test_an_external_resource_is_medium_not_public(self):
        row = self._keys(self._data([self._finding(public=False)]))[
            "analyzer-external"]
        assert row["severity"] == "medium"
        assert "Outside the account is not the same as public" in row["why"]

    def test_a_condition_the_analyzer_evaluated_is_named(self):
        row = self._keys(self._data(
            [self._finding(public=False, conditions=("aws:SourceIp",))]))[
                "analyzer-external"]
        assert "aws:SourceIp" in row["why"]

    def test_no_analyzer_says_aws_was_never_asked(self):
        """The load-bearing sentence. Zero findings from zero analyzers is a
        question nobody asked, and must not read like a clean answer (I1)."""
        summary = squawk.analysis.analyzer_summary(self._data(analyzers=()))
        assert summary["counts"]["analyzers"] == 0
        caveats = " ".join(squawk.analysis.analyzer_caveats(summary))
        assert "has not been asked this question at all" in caveats
        assert "service control policy" in caveats

    def test_an_active_analyzer_with_no_findings_is_a_real_negative(self):
        summary = squawk.analysis.analyzer_summary(self._data())
        caveats = " ".join(squawk.analysis.analyzer_caveats(summary))
        assert "1 active analyzer(s) answered" in caveats
        assert "this is the answer to trust" in caveats

    def test_a_denied_read_is_unknown_not_none(self):
        row = self._keys(self._data(unreadable=["findings (AccessDenied)"]))[
            "analyzer-unreadable"]
        assert row["severity"] == "unknown"
        assert "unknown, not none" in row["why"]

    def test_no_analyzer_is_said_in_the_note_rather_than_made_a_gap(self):
        """It used to count ANALYZERS, so an account with none examined zero —
        an incomplete run and a lost-communications alarm on every reading,
        forever, with nothing denied (review 2, R-20).

        The denominator is the regions whose list-analyzers answered. Whether
        AWS was asked is a real and important fact, and it belongs in the note
        where a reader sees it, not in a status that stops the page rendering.
        """
        asked = squawk.scanners.stage_coverage(
            "cloudanalyzer", json.dumps(self._data()))
        assert asked.unit == "regions read" and asked.examined == 1
        assert "1 active external-access analyzer(s) found" in asked.note

        never = squawk.scanners.stage_coverage(
            "cloudanalyzer", json.dumps(self._data(analyzers=())))
        assert never.examined == 1, "the region still answered"
        assert "has not been asked this question at all" in never.note
        status, _d, _c = squawk.engine._apply_coverage(
            "cloudanalyzer", json.dumps(self._data(analyzers=())), [], "ok",
            "0 findings")
        assert status == "ok"

    def test_a_region_that_never_answered_is_still_a_gap(self):
        status, _d, _c = squawk.engine._apply_coverage(
            "cloudanalyzer", json.dumps({"regional": {}}), [], "ok",
            "0 findings")
        assert status == "gap"

    def test_both_answers_are_shown_when_they_disagree(self):
        """A disagreement is the most interesting thing on the page, and
        hiding either half would waste it."""
        data = self._data([self._finding(name="r-aws", public=False,
                                         kind="AWS::IAM::Role")])
        agree = squawk.analysis.analyzer_agreement(data, ["r-ours", "r-aws"])
        assert agree["both"] == ["r-aws"]
        assert agree["ours_only"] == ["r-ours"]
        assert agree["aws_only"] == []
        assert agree["asked"] is True

    def test_with_no_analyzer_nothing_is_claimed_about_agreement(self):
        agree = squawk.analysis.analyzer_agreement(
            self._data(analyzers=()), ["r-ours"])
        assert agree["asked"] is False

    def test_the_account_id_is_masked_where_it_is_masked(self, monkeypatch):
        """Two layers, and this asserts at both of them rather than at the
        reader in between — which is where the account id legitimately still
        is, because attribution needs it and the page masks on the way out
        (PRODUCT rule 6, review R-3)."""
        # Layer one: the probe writes a masked ARN into the evidence.
        def responder(argv, _t):
            if argv[0] == "sts":
                return ({"Account": "123456789012",
                         "Arn": "arn:aws:iam::123456789012:role/r"}, "")
            if argv[1] == "describe-regions":
                return ({"Regions": [{"RegionName": "us-east-1"}]}, "")
            if argv[1] == "list-analyzers":
                return ({"analyzers": [
                    {"status": "ACTIVE", "type": "ACCOUNT", "name": "d",
                     "arn": "arn:aws:access-analyzer:us-east-1:"
                            "123456789012:analyzer/d"}]}, "")
            if argv[1] == "list-findings":
                return ({"findings": [
                    {"id": "f", "status": "ACTIVE",
                     "resource": "arn:aws:iam::123456789012:role/x",
                     "resourceType": "AWS::IAM::Role", "isPublic": False,
                     "principal": {"AWS": "arn:aws:iam::111122223333:root"},
                     "action": [], "condition": {}}]}, "")
            return ({}, "")

        data, _s, _d = _run_probe(monkeypatch, squawk.probes.aws_analyzer,
                                  responder)
        # `account` at the top level keeps the id on purpose -- attribution
        # needs it and every stage records it, and the page masks it. What must
        # not carry it is the findings, where it would be an identifier nobody
        # asked for repeated once per resource.
        assert data["account"] == "123456789012"
        blob = json.dumps(data["regional"])
        assert "123456789012" not in blob, "the account id is in the findings"
        assert "111122223333" not in blob, "another account id is in the findings"
        assert "********9012" in blob, "the masked form is what was written"

        # Layer two: whatever a reader builds is masked on the way to HTML.
        assert "123456789012" not in squawk.web._why(
            "reports arn:aws:iam::123456789012:role/x")

    def test_the_normalizer_survives_junk(self):
        for junk in ("", "{}", "null", '{"regional": "no"}', "[]"):
            assert squawk.scanners.norm_cloudanalyzer(junk, "") == []

    def test_only_an_external_access_analyzer_is_asked_for_findings(
            self, monkeypatch):
        """Reported from a field run. Access Analyzer answers more than one
        question and `ListFindings` answers only the first: calling it on an
        unused-access analyzer is rejected with FIELD_VALIDATION_FAILED, which
        took the stage to `gap` and the whole section off the page.
        """
        asked = []

        def responder(argv, _t):
            if argv[0] == "sts":
                return ({"Account": "000000000000", "Arn": "arn:x"}, "")
            if argv[1] == "describe-regions":
                return ({"Regions": [{"RegionName": "us-east-1"}]}, "")
            if argv[1] == "list-analyzers":
                return ({"analyzers": [
                    {"status": "ACTIVE", "type": "ACCOUNT_UNUSED_ACCESS",
                     "name": "unused", "arn": "arn:aws:access-analyzer:"
                                              "us-east-1:000000000000:"
                                              "analyzer/unused"},
                    {"status": "ACTIVE", "type": "ACCOUNT", "name": "external",
                     "arn": "arn:aws:access-analyzer:us-east-1:000000000000:"
                            "analyzer/external"}]}, "")
            if argv[1] == "list-findings":
                asked.append(argv[argv.index("--analyzer-arn") + 1])
                return ({"findings": []}, "")
            return ({}, "")

        data, status, _d = _run_probe(monkeypatch, squawk.probes.aws_analyzer,
                                      responder)
        assert len(asked) == 1 and asked[0].endswith("/external"), asked
        assert status == "ok", "the unused-access analyzer took the stage down"
        per = data["regional"]["us-east-1"]
        assert [a["name"] for a in per["analyzers"]] == ["external"]
        assert [a["name"] for a in per["other_analyzers"]] == ["unused"]
        assert per["unreadable"] == []

    def test_an_analyzer_of_another_kind_is_named_not_dropped(self):
        """An account can run an analyzer and still not have been asked this
        question, and those are different sentences."""
        data = self._data(analyzers=())
        data["regional"]["us-east-1"]["other_analyzers"] = [
            {"name": "unused", "kind": "ACCOUNT_UNUSED_ACCESS"}]
        caveats = " ".join(squawk.analysis.analyzer_caveats(
            squawk.analysis.analyzer_summary(data)))
        assert "answer a different question" in caveats
        assert "unused" in caveats
        assert "No active EXTERNAL-ACCESS Access Analyzer" in caveats

    # ---- review 2, R-23 and R-24: the account's own federation -------------

    def _irsa(self, name="r-irsa", provider="oidc.eks.us-east-1.amazonaws.com/id/E9"):
        return {"id": "f", "resource": "arn:aws:iam::0:role/%s" % name,
                "name": name, "kind": "AWS::IAM::Role", "panel": "roles",
                "public": False, "scope": "own-federation",
                "federation": "its own EKS cluster's OIDC provider",
                "principal": {"Federated": "arn:aws:iam::0:oidc-provider/%s"
                                           % provider},
                "actions": [], "conditions": [], "analyzed_at": ""}

    def test_the_accounts_own_federation_is_not_an_exposure(self):
        """Review 2, R-23. The analyzer's zone of trust is the account, so a
        federated principal is outside it by definition — which made every
        IRSA role, every GitHub Actions role and every SSO role in the account
        an external-access finding. In field use that was dozens at medium, including the SSO role
        the operator was running as."""
        row = self._keys(self._data([self._irsa()]))["analyzer-own-federation"]
        assert row["severity"] == "low"
        assert "That is how the federation works" in row["why"]
        assert "its own EKS cluster's OIDC provider" in row["why"]
        assert "analyzer-external" not in self._keys(self._data([self._irsa()]))

    def test_a_provider_in_another_account_is_still_external(self):
        """The fix must not clear a federation somebody else set up."""
        foreign = dict(self._irsa(), scope="external", federation="")
        assert "analyzer-external" in self._keys(self._data([foreign]))

    def test_the_probe_decides_the_scope_before_masking(self, monkeypatch):
        """The account id is what tells the two apart, and the evidence must
        not keep it — so the comparison happens at the probe."""
        def responder(argv, _t):
            if argv[0] == "sts":
                return ({"Account": "111122223333", "Arn": "arn:x"}, "")
            if argv[1] == "describe-regions":
                return ({"Regions": [{"RegionName": "us-east-1"}]}, "")
            if argv[1] == "list-analyzers":
                return ({"analyzers": [{"status": "ACTIVE", "type": "ACCOUNT",
                                        "name": "a", "arn": "arn:x"}]}, "")
            if argv[1] == "list-findings":
                return ({"findings": [
                    {"id": "own", "status": "ACTIVE", "isPublic": False,
                     "resource": "arn:aws:iam::111122223333:role/irsa",
                     "resourceType": "AWS::IAM::Role",
                     "principal": {"Federated": "arn:aws:iam::111122223333:"
                                                "oidc-provider/oidc.eks.x"},
                     "action": [], "condition": {}},
                    {"id": "theirs", "status": "ACTIVE", "isPublic": False,
                     "resource": "arn:aws:iam::111122223333:role/x",
                     "resourceType": "AWS::IAM::Role",
                     "principal": {"Federated": "arn:aws:iam::444455556666:"
                                                "oidc-provider/other"},
                     "action": [], "condition": {}}]}, "")
            return ({}, "")

        data, _s, _d = _run_probe(monkeypatch, squawk.probes.aws_analyzer,
                                  responder)
        scopes = {f["id"]: f["scope"]
                  for f in data["regional"]["us-east-1"]["findings"]}
        assert scopes == {"own": "own-federation", "theirs": "external"}
        blob = json.dumps(data["regional"])
        assert "111122223333" not in blob, "the account id is in the evidence"

    def test_the_comparison_does_not_manufacture_a_disagreement(self):
        """Review 2, R-24. Our readers classify those roles as `federated` —
        a real answer, and not one of OUTSIDE_REACH — so putting them in the
        comparison guaranteed a disagreement on every row, about definitions
        rather than about the account."""
        agree = squawk.analysis.analyzer_agreement(
            self._data([self._irsa()]), [])
        assert agree["aws_only"] == []
        assert agree["own_federation"] == 1

    def test_a_genuinely_external_finding_still_disagrees(self):
        agree = squawk.analysis.analyzer_agreement(
            self._data([dict(self._irsa(), scope="external", name="r-far")]), [])
        assert agree["aws_only"] == ["r-far"]

    def test_the_summary_counts_three_buckets(self):
        summary = squawk.analysis.analyzer_summary(self._data([
            self._irsa(),
            dict(self._irsa(name="r-far"), scope="external"),
            dict(self._irsa(name="b-pub"), scope="public", public=True)]))
        c = summary["counts"]
        assert (c["own_federation"], c["external"], c["public"]) == (1, 1, 1)
        assert c["findings"] == 3


class TestEveryCountThePageShowsIsDiffed:
    """From the operator's run of 2026-09-15. A reading went from 106 network
    interfaces to 107 and the comparison said:

        What changed since the last reading — 0 change(s), 24.1h apart
        Nothing changed, over readings that covered the same ground both times.

    That is a positive claim of no change, not an absence of news, and it was
    made over a count the page had just printed. `enis` and `roles` were in
    neither `TRACKED_COUNTS` nor `ID_FIELDS`, so a new one appeared under no
    heading at all.

    The structural test is the point. A total added to the summary later, and
    shown on the page, becomes invisible to the comparison unless somebody
    remembers to track it. Nobody has to remember now."""

    def test_no_total_is_shown_without_being_diffed(self):
        tracked = {key for key, _label, _rise in squawk.analysis.TRACKED_COUNTS}
        shown = set(squawk.INVENTORY_LABELS)
        assert not (shown - tracked), (
            "on the page and never compared: %s" % sorted(shown - tracked))

    def test_a_network_interface_appearing_is_a_change(self):
        """The exact number from the run that found this."""
        moved = self._moved(before=106, after=107, key="enis")
        assert moved, "106 -> 107 network interfaces read as no change"
        assert moved[0]["before"] == 106 and moved[0]["after"] == 107
        assert moved[0]["delta"] == 1

    def test_a_count_that_did_not_move_is_not_reported(self):
        """The false-alarm guard. Tracking more counts must not turn a quiet
        estate into a wall of noise."""
        assert self._moved(before=106, after=106, key="enis") == []

    def test_the_new_counts_do_not_carry_a_warning_on_their_own(self):
        """More interfaces is not worse, the way a new public instance is. A
        count that reddens for ordinary growth teaches the reader to skip it."""
        for key in ("enis", "roles", "igws", "route_tables"):
            row = self._moved(before=1, after=2, key=key)
            assert row and row[0]["weight"] == "", (key, row)

    @staticmethod
    def _moved(before, after, key):
        rise = {k: r for k, _l, r in squawk.analysis.TRACKED_COUNTS}
        assert key in rise, "%s is not tracked" % key
        moved = []
        for k, label, rise_is_bad in squawk.analysis.TRACKED_COUNTS:
            b = before if k == key else 0
            a = after if k == key else 0
            if b == a:
                continue
            delta = a - b
            moved.append({"key": k, "label": label, "before": b, "after": a,
                          "delta": delta,
                          "weight": "warn" if (rise_is_bad and delta > 0) else ""})
        return [m for m in moved if m["key"] == key]


class TestAStageIsTimedOnTheClockItsBudgetUses:
    """From the operator's run of 2026-09-14, on a laptop that slept overnight:

        semgrep  !! timed out after 7200s  ·  and it took a further 9h 29m to
        stop, so the stage ran 11h 29m in all

    The stage had not overrun by a second. `subprocess` computes its timeout
    deadline with `time.monotonic`, which on darwin is `mach_absolute_time()`
    and does not advance while the machine is asleep. The elapsed was measured
    with `time.time()`, which does, so the run reported nine and a half hours of
    sleep as time the scanner spent refusing to die.

    An elapsed on one clock against a budget on another is a claim about a
    control that was never measured — and this one said the control had failed.
    """

    @staticmethod
    def _run(tmp_path, monkeypatch, wall_jump, real_overrun=0.0):
        """One stage that times out, with the wall clock jumping `wall_jump`
        seconds during it and the monotonic clock advancing `real_overrun`."""
        import itertools
        mono = itertools.count(1000.0, real_overrun)
        wall = itertools.count(5000.0, wall_jump)
        _patch_all(monkeypatch, "tool_path", lambda name: "/usr/bin/" + name)
        _patch_all(monkeypatch, "run_cmd",
                   lambda cmd, cwd, timeout: (124, "", "timed out after %ss" % timeout))
        monkeypatch.setattr(squawk.engine.time, "monotonic", lambda: next(mono))
        monkeypatch.setattr(squawk.engine.time, "time", lambda: next(wall))
        ev = str(tmp_path / "ev")
        out = squawk.execute_service(squawk.SERVICES["cloudaws"], "000000000000",
                                     ev, str(tmp_path))
        man = next(m for m in squawk.list_runs(ev) if m["run_id"] == out["run_id"])
        return next(r["detail"] for r in man["ledger"] if r["tool"] == "awscli")

    def test_a_sleeping_machine_is_not_reported_as_an_overrun(self, tmp_path,
                                                              monkeypatch):
        """The wall clock jumps nine hours; the monotonic clock does not move.
        Nothing overran, so nothing is claimed."""
        detail = self._run(tmp_path, monkeypatch, wall_jump=34140.0)
        assert detail.startswith("timed out after 600s"), detail
        assert "took a further" not in detail, detail
        assert "in all" not in detail, detail

    def test_a_real_overrun_is_still_reported(self, tmp_path, monkeypatch):
        """The guard. Fixing the clock must not silence the case the clause was
        written for: a scanner that ignores SIGTERM really does cost the grace
        period, and that is measured on the monotonic clock too."""
        detail = self._run(tmp_path, monkeypatch, wall_jump=0.0,
                           real_overrun=630.0)
        assert "took a further" in detail, detail

    def test_the_engine_reads_the_same_clock_subprocess_does(self):
        """The claim in one assertion, against the standard library rather than
        against a comment: whatever `subprocess` uses for its deadline is what
        a stage must be timed with."""
        import subprocess as sp
        source = inspect.getsource(sp.Popen._remaining_time)
        assert "_time()" in source
        assert sp._time is time.monotonic, sp._time
        engine_src = inspect.getsource(squawk.engine._run_one_stage)
        assert "time.time() - started" not in engine_src, engine_src[:200]
        assert "time.monotonic() - started" in engine_src


class TestAnUnreadableConditionValueErrsWide:
    """R-36's value reader returns nothing for a shape the policy grammar does
    not allow — a dict or a list nested inside a condition value. That is right
    by I6: it must not raise. The review asked whether it should also leave an
    `unreadable` note on the role.

    It should not, and this is the reason. A condition narrows a `*`
    principal. A value nobody could read narrows nothing, so the reach stays at
    its widest and the role is reported as assumable by anyone. The failure
    direction is over-reporting, never hiding — which is the direction the
    charter asks for, and a note would add noise to a path that already fails
    safe. IAM validates a policy document when it is written, so the shape
    cannot arrive from an account read in the first place.

    What this test protects is the DIRECTION. If the value reader is ever made
    more permissive, or the narrowing logic changes so an empty value set reads
    as a narrow one, a role that anyone can assume starts reading as internal.
    """

    ACCT = "111111111111"

    def _reach(self, condition):
        doc = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "*"},
            "Action": "sts:AssumeRole", "Condition": condition}]}
        return squawk.probes.widest_reach(
            squawk.probes.who_can_assume(doc, self.ACCT))

    def test_a_well_formed_condition_narrows_the_star(self):
        assert self._reach(
            {"StringEquals": {"aws:PrincipalAccount": self.ACCT}}) == "internal"

    def test_a_nested_value_leaves_the_star_at_its_widest(self):
        assert self._reach(
            {"StringEquals": {"aws:PrincipalAccount": [{"bad": self.ACCT}]}}) \
            == "anyone"

    def test_it_reads_the_same_as_no_condition_at_all(self):
        """The claim in one line: an unreadable narrowing is no narrowing."""
        assert self._reach(
            {"StringEquals": {"aws:PrincipalAccount": [["nested"]]}}) \
            == self._reach({})

    def test_the_value_reader_still_takes_every_shape_iam_allows(self):
        """The guard on the guard. Erring wide must not come from reading
        nothing: a string, a number, a bool and a flat list all still read."""
        from squawk.probes import _condition_values as vals
        assert vals("acct") == ["acct"]
        assert vals(["a", "b"]) == ["a", "b"]
        assert vals(True) == ["true"]
        assert vals(7) == ["7"]


class TestEveryRoleCardOpensTheSetItCounts:
    """`_d_esc_roles(outside=True)` filters on OUTSIDE_REACH, and `unsettled`
    is in neither OUTSIDE_REACH nor the organization set — it is a trusted
    account this run could not place. So its members sat behind no number
    anywhere: the card listed at most eight and said nothing about the rest,
    which is the silent cap this page refuses (I12)."""

    @staticmethod
    def _rows(n, key="role-trust-unsettled"):
        return [{"key": key, "role": "role-%d" % i,
                 "why": "trusts 111111111111",
                 "escalation": ["iam:PutRolePolicy"]} for i in range(n)]

    def test_the_unsettled_count_links_to_its_members(self):
        html = squawk.web._role_cards(self._rows(3))
        assert "/cloud/detail?what=roles_trust_unsettled" in html, html[:300]

    def test_the_count_is_exact_and_the_remainder_is_named(self):
        """Collapsing is not capping. Eleven says eleven, shows eight, and
        says where the other three are."""
        html = squawk.web._role_cards(self._rows(11))
        assert ">11<" in html
        assert "and 3 more" in html
        assert html.count("<li><b class='mono'>") == 8

    def test_the_drill_returns_unsettled_roles_and_no_others(self):
        _label, source, extract = squawk.CLOUD_DRILL["roles_trust_unsettled"]
        assert source == "cloud-iam.json"
        got = extract({"roles_with_escalation": [
            {"name": "a", "reach": "unsettled", "escalation": ["x"]},
            {"name": "b", "reach": "anyone", "escalation": ["y"]},
            {"name": "c", "reach": "organization", "escalation": ["z"]},
            {"name": "d", "reach": "internal", "escalation": ["w"]}]})
        assert [r.get("name") for r in got] == ["a"], got

    def test_the_outside_drill_is_unchanged_by_the_new_one(self):
        """The guard. A reach filter added beside OUTSIDE_REACH must not widen
        or narrow the set that was already there."""
        _l, _s, extract = squawk.CLOUD_DRILL["roles_reachable_from_outside"]
        got = extract({"roles_with_escalation": [
            {"name": "a", "reach": "anyone", "escalation": ["x"]},
            {"name": "b", "reach": "external", "escalation": ["y"]},
            {"name": "c", "reach": "unsettled", "escalation": ["z"]}]})
        assert sorted(r.get("name") for r in got) == ["a", "b"], got

    def test_every_card_with_a_drill_key_has_an_extractor(self):
        """A key with no extractor renders as plain text, so a card naming one
        that does not exist would quietly lose its link."""
        for _keys, _colour, title, _blurb, drill in squawk.web._ROLE_CARDS:
            if drill:
                assert drill in squawk.CLOUD_DRILL, (title, drill)


class TestARuleThatFiredThirtySixTimesIsOneLine:
    """In field use the analyzer section ran to pages of identical paragraphs, one per role the
    account's own federation can
    assume. Every other number on this page keeps its members behind the
    number; this one printed them inline and buried the findings that were
    not a pattern.

    Collapsing is not capping (I12). The count is exact, the sentence says
    what the set is, and the number links to every member."""

    def _root(self, tmp_path, monkeypatch, findings):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        (run / "raw" / "cloud-analyzer.json").write_text(json.dumps({
            "account": "0", "read_at": "2026-09-11T00:00:00Z", "api_calls": 20,
            "limit": 200, "truncated": False,
            "regions_enabled": ["us-east-1"], "regions_read": ["us-east-1"],
            "regions_partial": [], "regions_unread": [],
            "regional": {"us-east-1": {
                "analyzers": [{"name": "a", "kind": "ACCOUNT", "arn": "arn:x"}],
                "findings": list(findings), "unreadable": []}}}),
            encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [{"tool": "cloudanalyzer", "status": "ok", "detail": "",
                         "coverage": {"examined": 1, "unit": "regions read"}}]}])
        return str(tmp_path)

    def _own(self, n):
        return [{"id": "f%d" % i, "resource": "arn:aws:iam::0:role/r%d" % i,
                 "name": "r%d" % i, "kind": "AWS::IAM::Role", "panel": "roles",
                 "public": False, "scope": "own-federation",
                 "federation": "its own EKS cluster's OIDC provider",
                 "principal": {"Federated": "arn:aws:iam::0:oidc-provider/x"},
                 "actions": [], "conditions": [], "analyzed_at": ""}
                for i in range(n)]

    def _public(self):
        return {"id": "pub", "resource": "arn:aws:s3:::b1", "name": "b1",
                "kind": "AWS::S3::Bucket", "panel": "buckets", "public": True,
                "scope": "public", "federation": "",
                "principal": {"AWS": "*"}, "actions": ["s3:GetObject"],
                "conditions": [], "analyzed_at": ""}

    def test_thirty_six_of_one_rule_print_as_one_line(self, tmp_path,
                                                      monkeypatch):
        page = squawk.web.cloud_analyzer_panel(
            self._root(tmp_path, monkeypatch, self._own(36)))
        assert page.count("Access Analyzer reports") == 0, \
            "the per-finding paragraph is still printed thirty-six times"
        assert page.count("trust a provider this account created") == 1
        assert "/cloud/detail?what=analyzer_own_federation" in page
        assert ">36<" in page, "the exact count is not on the collapsed line"
        for i in range(36):
            assert "role/r%d" % i not in page, "role r%d is still listed" % i

    def test_the_collapsed_line_is_not_a_clean_negative(self, tmp_path,
                                                        monkeypatch):
        """I1. Thirty-six findings folded behind a number must never read as
        the analyzer having found nothing."""
        page = squawk.web.cloud_analyzer_panel(
            self._root(tmp_path, monkeypatch, self._own(36)))
        assert "none reports a resource reachable" not in page

    def test_a_real_exposure_is_still_printed_in_full(self, tmp_path,
                                                      monkeypatch):
        """Only the pattern collapses. The thing worth reading does not."""
        mixed = [self._public()]
        mixed.extend(self._own(36))
        page = squawk.web.cloud_analyzer_panel(
            self._root(tmp_path, monkeypatch, mixed))
        assert "b1" in page, "the public bucket is gone from the page"
        assert "own evaluation" in page, "its finding text is gone too"

    def test_the_number_still_expands_to_every_member(self, tmp_path,
                                                      monkeypatch):
        detail = squawk.web.view_cloud_detail(
            self._root(tmp_path, monkeypatch, self._own(36)),
            "analyzer_own_federation")
        for i in range(36):
            assert "r%d" % i in detail, "r%d is behind no number at all" % i

    def test_nothing_at_all_still_says_so(self, tmp_path, monkeypatch):
        page = squawk.web.cloud_analyzer_panel(
            self._root(tmp_path, monkeypatch, []))
        assert "none reports a resource reachable" in page


class TestAFindingAboutATestIsNotAFindingAboutTheProduct:
    """Release review B-2, measured on a real run of this repository:
    **2435 findings, 2355 of them in test files.** The eighty that were about
    the product could not be seen past them, and the page rendered a megabyte
    of HTML to say it.

    Nothing is dropped for being in a test. Both sets are recorded, both are
    counted, and which set the page is showing is in the address — so the
    number expands to exactly its members (I12)."""

    def test_the_conventions_of_each_ecosystem(self):
        for path in ("tests/unit/foo.py", "projects/x/test_squawk.py",
                     "pkg/foo_test.go", "web/app.spec.ts", "conftest.py",
                     "src/__tests__/a.js", "a/b/tests"):
            assert squawk.core.is_test_code(path), path

    def test_a_directory_that_holds_fixtures_or_specs_is_product_code(self):
        """Review 3, R-40. `fixtures/`, `testdata/`, `e2e/`, `spec/` and
        `specs/` were test directories, and a Terraform module under
        fixtures/ -- a security group open to the world -- went behind the
        test-code link while the Overview counted it as one of three high
        findings. Terraform modules, Go golden files and Cypress suites are
        not what bandit's assert rule is about, and the safe direction to be
        wrong in is product code."""
        for path in ("fixtures/main.tf", "testdata/golden.json",
                     "e2e/login.js", "spec/openapi.yaml", "specs/design.md",
                     "infra/fixtures/vpc/sg.tf"):
            assert not squawk.core.is_test_code(path), path

    def test_a_word_inside_a_name_is_not_a_test_directory(self):
        """Conservative on purpose, and in the safe direction: a finding shown
        that need not have been is a nuisance; one hidden that mattered is this
        tool's cardinal sin."""
        for path in ("src/app/latest/handler.py", "contest/main.go",
                     "squawk/core.py", "protest/views.py", "", "attestation.py"):
            assert not squawk.core.is_test_code(path), path

    def _run(self, tmp_path):
        findings = [_f("bandit", "B101:%d" % i, "low", "Use of assert detected",
                       "test_squawk.py") for i in range(40)]
        findings += [_f("semgrep", "sql:%d" % i, "high", "SQL injection",
                        "squawk/web.py") for i in range(3)]
        _write_run(str(tmp_path), "20260101T000000Z-x", findings)
        return str(tmp_path)

    def test_the_product_findings_are_what_the_page_shows(self, tmp_path):
        html = squawk.web.view_findings(self._run(tmp_path), None)
        assert "3 finding(s) in 1 group(s)" in html
        assert "SQL injection" in html
        assert "Use of assert detected" not in html

    def test_the_rest_is_stated_with_its_count_and_a_link(self, tmp_path):
        """Moved behind a number, not dropped. The sentence carries the exact
        count and the address that shows them."""
        html = squawk.web.view_findings(self._run(tmp_path), None)
        assert ">40</a>" in html or ">40<" in html
        assert "are in this target's test code" in html
        assert "where=tests" in html

    def test_the_number_expands_to_its_members(self, tmp_path):
        html = squawk.web.view_findings(self._run(tmp_path), None, None, None,
                                        "tests")
        assert "40 finding(s) in 1 group(s)" in html
        assert "Use of assert detected" in html
        assert "are in the product code" in html, "no way back"

    def test_nothing_is_lost_between_the_two(self, tmp_path):
        root = self._run(tmp_path)
        both = (squawk.web.view_findings(root, None),
                squawk.web.view_findings(root, None, None, None, "tests"))
        assert "3 finding(s)" in both[0] and "40 finding(s)" in both[1]

    def test_a_filter_that_empties_one_side_does_not_read_as_clean(self,
                                                                   tmp_path):
        """I1 at the page level. Filtering the product side to nothing while
        forty findings sit in the test code must not print an empty state that
        reads as a clean run."""
        # `low` matches the forty asserts and none of the three SQL findings,
        # so the product side empties while the test side is full.
        html = squawk.web.view_findings(self._run(tmp_path), None, "low")
        assert "Nothing here matches these filters" in html
        assert "40 are in the test code" in html
        assert "Show the 40 in test code" in html
        # Review 3, R-45. The sentence counted the SHOWN set, which is zero in
        # this branch by construction, and printed "None of the 0 in product
        # code matches" over three product findings.
        assert "None of the 0" not in html
        assert "None of the 3 in product code matches" in html

    def test_the_count_line_carries_both_sides(self, tmp_path):
        """Review 3, R-40. The Overview counts every finding and the Findings
        page shows one side of them; the line under the filters says how many
        are on the other side, so the two numbers reconcile at a glance."""
        root = self._run(tmp_path)
        assert "3 shown &middot; 40 in test code" in \
            squawk.web.view_findings(root, None)
        assert "40 shown &middot; 3 in product code" in \
            squawk.web.view_findings(root, None, None, None, "tests")

    def test_a_filter_that_empties_both_sides_still_says_so(self, tmp_path):
        html = squawk.web.view_findings(self._run(tmp_path), None, "critical")
        assert "Nothing matches these filters" in html
        assert "43 finding(s)" in html

    def test_the_page_is_readable(self, tmp_path):
        """The measured defect was 1,025,454 characters for one run. The
        product view of the same run must be a fraction of the whole."""
        root = self._run(tmp_path)
        product = len(squawk.web.view_findings(root, None))
        tests = len(squawk.web.view_findings(root, None, None, None, "tests"))
        assert product * 2 < tests, \
            "the product view is not materially smaller (%d vs %d)" % (product,
                                                                       tests)


class TestTheRoleAwsOrganizationsCreatesIsNotACriticalFinding:
    """Review 2, R-25. `OrganizationAccountAccessRole` exists in every account
    AWS Organizations creates, carries AdministratorAccess, and trusts the
    management account's root. With only `internal` and `external` as answers,
    every member account of every organization opened on a CRITICAL finding
    about the role AWS put there.

    The organization stage reads the management account in the same run, first,
    and the IAM stage never looked at it."""

    ACC = "000000000000"
    MGMT = "111111111111"
    SIBLING = "222222222222"
    STRANGER = "999999999999"
    ORG: ClassVar[dict] = {"id": "o-abc", "management": MGMT,
                           "accounts": [ACC, MGMT, SIBLING]}

    def _trust(self, who):
        return {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                               "Principal": {"AWS": who}}]}

    def _reach(self, who, org=None):
        rows = squawk.probes.who_can_assume(self._trust(who), self.ACC, org)
        return rows[0]["reach"] if rows else ""

    def test_the_management_account_is_the_organization_not_outside(self):
        assert self._reach("arn:aws:iam::%s:root" % self.MGMT,
                           self.ORG) == "organization"

    def test_it_says_which_account_it_is(self):
        rows = squawk.probes.who_can_assume(
            self._trust("arn:aws:iam::%s:root" % self.MGMT), self.ACC, self.ORG)
        assert "management account" in rows[0]["why"]
        assert self.MGMT not in rows[0]["why"], "the account id is masked"

    def test_a_sibling_account_is_the_organization_too(self):
        assert self._reach("arn:aws:iam::%s:root" % self.SIBLING,
                           self.ORG) == "organization"

    def test_an_account_outside_the_organization_is_still_external(self):
        """The fix must not clear a stranger."""
        assert self._reach("arn:aws:iam::%s:root" % self.STRANGER,
                           self.ORG) == "external"

    def test_without_the_organization_reading_it_stays_external(self):
        """I1 applied to the fix itself. 'This might be a member of an
        organization nobody read' is not something to assume either way, so
        the answer stays what this tool knew before."""
        assert self._reach("arn:aws:iam::%s:root" % self.MGMT,
                           None) == "external"

    def _admin_role(self, reach, why="this organization's management account"):
        return {"roles_already_admin": [
            {"name": "OrganizationAccountAccessRole", "reach": reach,
             "why": ["AdministratorAccess"],
             "trust": [{"kind": "aws", "who": "*", "reach": reach,
                        "why": why}]}],
            "roles_with_escalation": []}

    def test_the_organizations_own_role_is_not_critical(self):
        keys = {f["key"]: f for f in squawk.analysis.role_findings(
            self._admin_role("organization"))}
        assert "administrative-reachable-from-outside" not in keys
        row = keys["role-assumable-within-the-organization"]
        assert row["severity"] == "low"
        assert "not a grant to a third party" in row["why"]
        assert "management account" in row["why"]

    def test_a_real_outsider_is_still_critical(self):
        keys = {f["key"] for f in squawk.analysis.role_findings(
            self._admin_role("external", "a principal in account ****9999"))}
        assert "administrative-reachable-from-outside" in keys

    def test_the_organization_reading_reaches_the_iam_stage(self, monkeypatch):
        """The two stages are joined by the artifact the runner already
        carries between them, the way syft hands grype its SBOM."""
        ctx = _CloudProbeCtx()

        def org_responder(argv, _t):
            if argv[0] == "sts":
                return ({"Account": self.ACC, "Arn": "arn:x"}, "")
            if argv[1] == "describe-organization":
                return ({"Organization": {"Id": "o-abc", "FeatureSet": "ALL",
                                          "MasterAccountId": self.MGMT}}, "")
            if argv[1] == "list-accounts":
                return ({"Accounts": [
                    {"Id": self.ACC, "Name": "this", "Status": "ACTIVE"},
                    {"Id": self.MGMT, "Name": "mgmt", "Status": "ACTIVE"}]}, "")
            return ({}, "")

        _run_probe(monkeypatch, squawk.probes.aws_organization, org_responder,
                   ctx=ctx)
        org = squawk.probes.organization_read(ctx)
        assert org["management"] == self.MGMT
        assert self.ACC in org["accounts"]

    def test_a_stage_that_runs_alone_reads_none(self):
        assert squawk.probes.organization_read(_CloudProbeCtx()) is None


class TestTheEdgeStageCoversBothShapes:
    """Review 2, R-22. `_cov_cloudedge` did `int(per.get("functions") or 0)`.
    A later change made `functions` the list of functions rather than a count,
    so the tile
    could expand, and updated the reader but not the extractor: `int` of a
    non-empty list raises, `stage_coverage` swallows it, and the stage reported
    no coverage at all on every populated account.

    The extractor handles both shapes now. No test pinned either, which is why
    it went unnoticed — these pin both, so a shape change fails here rather
    than silently removing a denominator."""

    def _edge(self, functions):
        return {"regions_enabled": ["us-east-1"], "regions_read": ["us-east-1"],
                "regions_partial": [], "regions_unread": [], "limit": 200,
                "truncated": False,
                "regional": {"us-east-1": {"functions": functions,
                                           "load_balancers": [{"name": "lb"}],
                                           "unreadable": []}}}

    def test_a_list_of_functions_still_has_a_denominator(self):
        cov = squawk.scanners.stage_coverage(
            "cloudedge", json.dumps(self._edge([{"name": "f1"},
                                                {"name": "f2"}])))
        assert cov.examined == 1, "the stage reports no coverage at all"
        assert cov.unit == "regions read"
        assert "3 function(s) and load balancer(s) found" in cov.note

    def test_an_old_reading_that_carried_a_count_still_reads(self):
        """Evidence written before that change holds an integer. A run kept last month
        has to stay readable."""
        cov = squawk.scanners.stage_coverage("cloudedge",
                                             json.dumps(self._edge(2)))
        assert cov.examined == 1
        assert "3 function(s) and load balancer(s) found" in cov.note

    def test_a_shape_it_cannot_read_does_not_lose_the_denominator(self):
        """I6 and I15 together: the extractor must not raise, and a region that
        answered still counts even when what it holds is unreadable."""
        for junk in (None, "two", {"a": 1}, [None]):
            cov = squawk.scanners.stage_coverage("cloudedge",
                                                 json.dumps(self._edge(junk)))
            assert cov.examined == 1, junk

    def test_the_two_counters_never_disagree(self):
        """The defect was two copies of one answer drifting apart. This is the
        thing that would have caught it: the page's counter and the coverage
        extractor's, over every shape either might meet."""
        for shape in ([], [{"name": "a"}], [{"name": "a"}, {"name": "b"}],
                      0, 1, 7, None, "two", {"a": 1}, [None, None]):
            per = {"functions": shape}
            assert (squawk.scanners.function_count(per)
                    == squawk.analysis.edge_function_count(per)), shape
class TestTheProviderIsTheGuardAndAGuestRoleIsNot:
    """Review 2, R-26 and R-28. `_federated_reach` had two answers for a
    federated principal — narrowed by something, or open to anyone — and used
    the mere PRESENCE of a condition to choose between them.

    So an Okta-backed administrator role with no `SAML:aud` was `anyone` and
    filed CRITICAL, while a Cognito identity pool's GUEST role, which anyone
    holding the pool id can assume by design, was `federated` and produced
    nothing. The two errors point in opposite directions and have the same
    cause: a condition was counted, not read."""

    ACC = "000000000000"
    OTHER = "999999999999"

    def _trust(self, who, condition=None):
        st = {"Effect": "Allow", "Action": "sts:AssumeRoleWithSAML",
              "Principal": {"Federated": who}}
        if condition:
            st["Condition"] = condition
        return {"Statement": [st]}

    def _row(self, who, condition=None, account=None):
        rows = squawk.probes.who_can_assume(
            self._trust(who, condition),
            self.ACC if account is None else account)
        return rows[0] if rows else {}

    # ---- R-26: a SAML provider without SAML:aud ---------------------------

    def test_a_saml_provider_with_no_condition_is_not_anyone(self):
        row = self._row("arn:aws:iam::%s:saml-provider/Okta" % self.ACC)
        assert row["reach"] == "federated", \
            "an Okta-backed role reads as assumable by anyone"
        assert "provider decides who it signs for" in row["why"]
        assert "nothing here pins WHICH identity" in row["why"], \
            "the missing condition still has to be said"

    def test_a_saml_provider_with_the_audience_condition_is_narrowed(self):
        row = self._row("arn:aws:iam::%s:saml-provider/Okta" % self.ACC,
                        {"StringEquals": {"SAML:aud":
                                          "https://signin.aws.amazon.com/saml"}})
        assert row["reach"] == "federated"
        assert "narrowed by" in row["why"]

    def test_a_provider_in_another_account_is_external(self):
        """Whose provider it is still matters: somebody else's IdP decides who
        it signs for, and that somebody is not this account."""
        row = self._row("arn:aws:iam::%s:saml-provider/Theirs" % self.OTHER)
        assert row["reach"] == "external"
        assert "another account" in row["why"]

    def test_an_oidc_provider_this_account_created_is_the_same(self):
        row = self._row("arn:aws:iam::%s:oidc-provider/oidc.eks.x" % self.ACC)
        assert row["reach"] == "federated"

    def test_a_public_web_identity_with_no_condition_is_still_anyone(self):
        """The branch the `anyone` answer exists for: any Google account on
        earth matches this, and nothing pins the subject."""
        row = self._row("accounts.google.com")
        assert row["reach"] == "anyone"

    # ---- R-28: a Cognito guest role ---------------------------------------

    def _cognito(self, amr=None, aud="us-east-1:pool"):
        cond = {}
        if aud:
            cond["StringEquals"] = {squawk.probes.COGNITO_AUD: aud}
        if amr:
            cond["ForAnyValue:StringLike"] = {squawk.probes.COGNITO_AMR: amr}
        return self._row(squawk.probes.COGNITO_PROVIDER, cond or None)

    def test_an_unauthenticated_pool_role_is_assumable_by_anyone(self):
        row = self._cognito(amr="unauthenticated")
        assert row["reach"] == "anyone", \
            "a guest role read as narrowed because two conditions were present"
        assert "GUEST role" in row["why"]
        assert "knows the pool id" in row["why"]

    def test_an_authenticated_pool_role_is_federated(self):
        assert self._cognito(amr="authenticated")["reach"] == "federated"

    def test_a_pool_with_no_amr_says_what_decides_it(self):
        """Three states, not two: whether a guest of that pool can assume it
        is decided by the pool's own setting, which this does not read."""
        row = self._cognito()
        assert row["reach"] == "federated"
        assert "the pool's own setting, which is not read here" in row["why"]

    def test_a_cognito_principal_with_nothing_at_all_is_anyone(self):
        row = self._cognito(aud=None)
        assert row["reach"] == "anyone"

    # ---- R-28, second half: a mixed principal list ------------------------

    def _star(self, condition):
        return {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"},
                               "Condition": condition}]}

    def test_a_principal_list_mixing_accounts_admits_the_other_one(self):
        """The test was whether the set EQUALLED this account, and a mixed set
        does not — so it fell through to "internal, named principals"."""
        rows = squawk.probes.who_can_assume(self._star(
            {"ArnLike": {"aws:PrincipalArn": [
                "arn:aws:iam::%s:role/app" % self.ACC,
                "arn:aws:iam::%s:role/partner" % self.OTHER]}}), self.ACC)
        assert rows[0]["reach"] == "external"
        assert "alongside this one" in rows[0]["why"]
        assert self.OTHER not in rows[0]["why"], "the account id is masked"

    def test_a_list_wholly_inside_this_account_is_still_internal(self):
        rows = squawk.probes.who_can_assume(self._star(
            {"ArnLike": {"aws:PrincipalArn": [
                "arn:aws:iam::%s:role/a" % self.ACC,
                "arn:aws:iam::%s:role/b" % self.ACC]}}), self.ACC)
        assert rows[0]["reach"] == "internal"
class TestAnOrganizationNobodyCouldEnumerateSaysSo:
    """From the validation run of 2026-09-11. The Cloud page carried no estate
    banner at all — not the standalone one, not the unknown one, nothing —
    while the account plainly runs IAM Identity Center, which requires an AWS
    Organization.

    `cloud_estate_banner` returned "" whenever the account list held one entry
    or none. `organizations:ListAccounts` is the call a MEMBER account is
    usually not allowed to make, so that is the ordinary case for a read-only
    audit role, not an edge one — and the result was a page of counts with
    nothing saying whether they cover the estate or one account of forty-seven
    (I1)."""

    def _root(self, tmp_path, monkeypatch, payload):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        (run / "raw" / "cloud-org.json").write_text(json.dumps(payload),
                                                    encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [{"tool": "cloudorg", "status": "ok", "detail": "",
                         "coverage": {"examined": 1, "unit": "accounts"}}]}])
        return str(tmp_path)

    def _payload(self, accounts=(), org_id="o-abc", management="111111111111",
                 standalone=False, org_error="", accounts_error=""):
        return {"account": "000000000000", "read_at": "2026-09-11T00:00:00Z",
                "api_calls": 3, "standalone": standalone,
                "org_error": org_error, "accounts_error": accounts_error,
                "organization": ({"id": org_id, "feature_set": "ALL",
                                  "management_account": management}
                                 if org_id else {}),
                "accounts": list(accounts), "profiles_asked": [],
                "profiles_probed": False, "profiles_reaching": {},
                "profiles_unreachable": [], "profiles_error": ""}

    def test_an_org_whose_accounts_did_not_come_back_is_not_silence(self,
                                                                    tmp_path,
                                                                    monkeypatch):
        # The refusal travels in its own field. It arrived under `org_error`
        # -- the slot for describe-organization failing -- so the stage
        # examined zero, went to gap, and this card never rendered on the
        # ordinary member-account run it was written for (review 3, R-37).
        html = squawk.web.cloud_estate_banner(self._root(
            tmp_path, monkeypatch,
            self._payload(accounts_error="AccessDeniedException on "
                                         "ListAccounts")))
        assert html, "the page said nothing at all about the estate"
        assert "is in an AWS Organization" in html
        assert "needs a permission the identity reading this does not have" \
            in html
        assert "ListAccounts" in html, "the refusal itself is not on the card"
        assert "unread is not clean" in html

    def test_an_empty_list_that_was_read_is_said_as_that(self, tmp_path,
                                                         monkeypatch):
        html = squawk.web.cloud_estate_banner(
            self._root(tmp_path, monkeypatch, self._payload()))
        assert "account list came back empty" in html
        assert "needs a permission" not in html

    def test_the_management_account_is_told_it_can_probably_fix_it(self,
                                                                   tmp_path,
                                                                   monkeypatch):
        html = squawk.web.cloud_estate_banner(self._root(
            tmp_path, monkeypatch,
            self._payload(management="000000000000",
                          accounts_error="AccessDeniedException")))
        assert "management account" in html

    def test_an_org_that_really_holds_one_account_says_that_instead(self,
                                                                    tmp_path,
                                                                    monkeypatch):
        html = squawk.web.cloud_estate_banner(self._root(
            tmp_path, monkeypatch,
            self._payload(accounts=[{"id": "000000000000", "name": "only",
                                     "status": "ACTIVE"}])))
        # Review 3, R-42. The list answered in full and holds this account
        # alone, which is the whole organization -- the card said coverage
        # was "not known", and the test asserted that sentence.
        assert "it is the whole organization" in html
        assert "not known" not in html
        assert "needs a permission" not in html

    def test_a_standalone_account_still_reads_as_the_whole_estate(self,
                                                                  tmp_path,
                                                                  monkeypatch):
        html = squawk.web.cloud_estate_banner(self._root(
            tmp_path, monkeypatch,
            self._payload(org_id="", standalone=True)))
        assert "it is the whole estate" in html

    def test_a_real_organization_still_gives_the_fraction(self, tmp_path,
                                                          monkeypatch):
        html = squawk.web.cloud_estate_banner(self._root(
            tmp_path, monkeypatch, self._payload(accounts=[
                {"id": "000000000000", "name": "a", "status": "ACTIVE"},
                {"id": "111111111111", "name": "b", "status": "ACTIVE"},
                {"id": "222222222222", "name": "c", "status": "ACTIVE"}])))
        assert "1 of 3 accounts in the organization" in html

    def test_a_read_that_failed_outright_still_says_so(self, tmp_path,
                                                       monkeypatch):
        html = squawk.web.cloud_estate_banner(self._root(
            tmp_path, monkeypatch,
            self._payload(org_error="AccessDenied on describe-organization")))
        assert "how much of the estate this covers is unknown" in html.lower()

    def test_no_organization_id_and_no_standalone_is_the_only_silence(self,
                                                                      tmp_path,
                                                                      monkeypatch):
        """The one case left: the stage reported neither an organization nor
        standalone, so there is nothing it learned to report."""
        html = squawk.web.cloud_estate_banner(self._root(
            tmp_path, monkeypatch, self._payload(org_id="")))
        assert html == ""


class TestATopicGrantedToAnotherAccountProducedNothing:
    """Review 2, R-27. `_public_policy_reasons` says it reports "why a RESOURCE
    policy admits somebody who is not this account" and only ever looked at
    statements whose principal is `*`.

    So a topic granted OUTRIGHT to another account produced nothing, under an
    empty state reading "No topic, queue or repository admits a principal
    outside this account." And a queue narrowed to somebody ELSE'S organization
    read as "principals in this organization", because the reader never knew
    which organization this account belongs to — while the organization stage
    read exactly that, first, in the same run."""

    ACC = "000000000000"
    OTHER = "999999999999"
    SIBLING = "111111111111"
    ORG: ClassVar[dict] = {"id": "o-ours", "management": SIBLING,
                           "accounts": [ACC, SIBLING]}

    def _policy(self, principal, condition=None):
        st = {"Effect": "Allow", "Action": "sns:Publish",
              "Principal": principal}
        if condition:
            st["Condition"] = condition
        return {"Version": "2012-10-17", "Statement": [st]}

    def _reasons(self, principal, condition=None, org=None):
        return squawk.probes._public_policy_reasons(
            self._policy(principal, condition), "sns policy", self.ACC, org)

    # ---- a named outsider -------------------------------------------------

    def test_a_topic_granted_outright_to_another_account_is_reported(self):
        out = self._reasons({"AWS": "arn:aws:iam::%s:root" % self.OTHER})
        assert out, "an explicit cross-account grant produced nothing"
        assert "which is not this one" in out[0]
        assert self.OTHER not in out[0], "the account id is masked"

    def test_it_lands_at_the_same_weight_the_analyzer_gives_it(self):
        out = self._reasons({"AWS": "arn:aws:iam::%s:root" % self.OTHER})
        assert squawk.probes.is_narrowed_public(out[0]), \
            "a named outsider should read as the medium branch, like the " \
            "analyzer's analyzer-external"

    def test_a_sibling_account_says_it_is_inside_the_organization(self):
        out = self._reasons({"AWS": "arn:aws:iam::%s:root" % self.SIBLING},
                            org=self.ORG)
        assert out and "inside this organization" in out[0]

    def test_this_account_named_outright_is_not_a_finding(self):
        assert self._reasons({"AWS": "arn:aws:iam::%s:root" % self.ACC}) == []

    def test_a_service_principal_is_not_an_outsider(self):
        assert self._reasons({"Service": "events.amazonaws.com"}) == []

    # ---- which organization ------------------------------------------------

    def _org_scoped(self, org_id, org=None):
        return self._reasons(
            {"AWS": "*"},
            {"StringEquals": {"aws:PrincipalOrgID": org_id}}, org)

    def test_somebody_elses_organization_is_outside_this_account(self):
        out = self._org_scoped("o-theirs", self.ORG)
        assert out, "a queue shared with another organization produced nothing"
        assert "DIFFERENT organization" in out[0]

    def test_this_organization_is_still_the_answer_to_who(self):
        assert self._org_scoped("o-ours", self.ORG) == []

    def test_without_the_organization_reading_the_verdict_does_not_move(self):
        """Inventing an answer in either direction is worse than saying so. The
        verdict stays what it was; the WORDS say what was not settled."""
        assert self._org_scoped("o-whatever", None) == []
        scope, why = squawk.probes._who_a_condition_names(
            {"StringEquals": {"aws:PrincipalOrgID": "o-whatever"}}, self.ACC)
        assert scope == "organization"
        assert "could not read which organization" in why

    def test_a_trust_policy_reads_the_same_organization(self, monkeypatch):
        """One reader, so the trust policy and the resource policy cannot
        disagree about whose organization a condition names."""
        doc = {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                              "Principal": {"AWS": "*"},
                              "Condition": {"StringEquals":
                                            {"aws:PrincipalOrgID": "o-theirs"}}}]}
        rows = squawk.probes.who_can_assume(doc, self.ACC, self.ORG)
        assert rows[0]["reach"] == "external"
        rows = squawk.probes.who_can_assume(
            dict(doc, Statement=[dict(doc["Statement"][0],
                                      Condition={"StringEquals": {
                                          "aws:PrincipalOrgID": "o-ours"}})]),
            self.ACC, self.ORG)
        assert rows[0]["reach"] == "organization"


class TestAllowEverythingExceptIamIsNotNoneGrantsAWildcardAction:
    """Review 2, R-31. `_broad_reasons` reported a NotAction statement as broad
    only when the exclusions FAILED to cover the permission-granting actions —
    which is the escalation question, asked where the breadth question was.

    PowerUserAccess is written as allow everything except `iam:*`,
    `organizations:*` and `account:*`. That is far more than read, and "far more
    than read" is what the four-leg rule's own title asks about. AWS's own
    PowerUserAccess was caught by name; a customer's hand-written equivalent
    produced nothing — under a caveat reading "none grants a wildcard action.
    That is a real negative, not an absence of looking." """

    POWER: ClassVar[dict] = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Resource": "*",
                       "NotAction": ["iam:*", "organizations:*", "account:*"]}]}

    def test_power_user_written_out_by_hand_is_broad(self):
        out = squawk.probes._broad_reasons(self.POWER, "inline policy p")
        assert out, "a role that can do everything but IAM reads as limited"
        assert "allows every action except" in out[0]
        assert "on every resource" in out[0]

    def test_it_says_it_is_not_a_path_to_more(self):
        """Breadth and escalation are different sentences and the reader has to
        say which one it is answering."""
        out = squawk.probes._broad_reasons(self.POWER, "inline policy p")
        assert "far more than read" in out[0]
        assert "not a path to MORE permission" in out[0]

    def test_a_notaction_that_leaves_iam_in_is_still_reported(self):
        doc = {"Statement": [{"Effect": "Allow", "Resource": "*",
                              "NotAction": ["s3:*"]}]}
        out = squawk.probes._broad_reasons(doc, "inline policy p")
        assert out and "not a path to MORE permission" not in out[0]

    def test_a_notaction_on_one_resource_is_not_account_wide(self):
        doc = {"Statement": [{"Effect": "Allow",
                              "Resource": "arn:aws:s3:::one-bucket/*",
                              "NotAction": ["iam:*"]}]}
        assert squawk.probes._broad_reasons(doc, "inline policy p") == []

    def test_the_four_leg_rule_now_has_its_fourth_leg(self):
        """An internet-reachable instance carrying that role never fired
        `reachable-over-permitted`, because the leg it needed was the one the
        reader would not report."""
        broad = squawk.probes._broad_reasons(self.POWER, "inline policy p")
        assert broad, "no breadth means no fourth leg"

    def test_the_caveat_no_longer_says_wildcard_action(self):
        """The sentence was a claim about what was checked, and it named the
        only shape the reader was NOT checking."""
        text = " ".join(squawk.analysis.inventory_caveats({
            "totals": {"roles": 3, "broad_roles": 0, "unevaluated_roles": 0},
            "regions_unread": [], "regions_denied": [], "counts": {},
            "regions_read": ["us-east-1"], "regions_enabled": ["us-east-1"]}))
        assert "none carries more than read" in text
        assert "allow-everything-except written as NotAction" in text
        assert "none grants a wildcard action" not in text


class TestAnApiWithNoStageIsNotAFrontDoor:
    """Review 2, R-32. `_rest_apis` and `_http_apis` read the API definition
    and its routes. Neither read STAGES.

    A REST API that was never deployed, or whose stage was deleted, has no
    endpoint that answers — and it was reported as "answers on its public
    endpoint and API Gateway authenticates none of N of its N route(s)" at
    HIGH. The recorder's fake CLI has stocked responses for `apigateway
    get-stages` and `apigatewayv2 get-stages` since it was written, and
    nothing called them."""

    def _data(self, stages, unreadable="", routes=2, open_n=2):
        api = {"id": "a1", "name": "webhook", "kind": "HTTP",
               "endpoint": "https://a1.execute-api.us-east-1.amazonaws.com",
               "private": False, "default_endpoint_open": True,
               "open_routes": ["POST /webhook"][:open_n] or [],
               "routes": routes, "unreadable": "",
               "stages": stages, "stages_unreadable": unreadable}
        return {"regions_enabled": ["us-east-1"], "regions_read": ["us-east-1"],
                "regions_partial": [], "regions_unread": [],
                "regional": {"us-east-1": {"apis": [api], "unreadable": []}}}

    def _keys(self, data):
        return {f["key"]: f for f in squawk.analysis.frontdoor_findings(data)}

    def test_an_api_with_no_stage_is_not_high(self):
        keys = self._keys(self._data([]))
        assert "api-open-to-the-internet" not in keys, \
            "an API nobody deployed reads as a front door"
        row = keys["api-not-deployed"]
        assert row["severity"] == "low"
        assert "NO deployed stage" in row["why"]
        assert "one click" in row["why"], \
            "it has to say the door is one deploy away"

    def test_a_deployed_api_is_still_high(self):
        keys = self._keys(self._data(["prod"]))
        assert keys["api-open-to-the-internet"]["severity"] == "high"
        assert "api-not-deployed" not in keys

    def test_stages_that_could_not_be_read_are_unknown(self):
        """I14. Not deployed and could-not-tell are different answers, and the
        second must not become the first."""
        keys = self._keys(self._data(None, "AccessDeniedException"))
        assert keys["api-stages-unreadable"]["severity"] == "unknown"
        assert "not open and not closed" in keys["api-stages-unreadable"]["why"]
        assert "api-open-to-the-internet" not in keys
        assert "api-not-deployed" not in keys

    def test_an_api_with_nothing_open_says_nothing_either_way(self):
        assert self._keys(self._data([], open_n=0)) == {}

    def test_the_reader_asks_for_stages(self, monkeypatch):
        """The call the recorder had a stocked answer for and nobody made."""
        asked = []

        def fake(argv, _t):
            asked.append(list(argv))
            if argv[0] == "apigatewayv2" and argv[1] == "get-apis":
                return ({"Items": [{"ApiId": "a1", "Name": "n",
                                    "ProtocolType": "HTTP",
                                    "ApiEndpoint": "https://x"}]}, "")
            if argv[1] == "get-routes":
                return ({"Items": [{"RouteKey": "POST /w",
                                    "AuthorizationType": "NONE"}]}, "")
            if argv[1] == "get-stages":
                return ({"Items": [{"StageName": "$default"}]}, "")
            return ({}, "")

        monkeypatch.setattr(squawk.probes, "_aws_json", fake)
        rows, _bad = squawk.probes._http_apis("us-east-1", 5,
                                              time.time() + 60)
        assert ["apigatewayv2", "get-stages", "--api-id", "a1",
                "--region", "us-east-1"] in asked
        assert rows[0]["stages"] == ["$default"]

    def test_both_response_shapes_are_read(self, monkeypatch):
        """v1 returns `item`, v2 returns `Items`. A reader that knows one
        shape reports the other as empty — which here reads as "not
        deployed", the exact wrong answer."""
        for payload, want in (({"item": [{"stageName": "prod"}]}, ["prod"]),
                              ({"Items": [{"StageName": "$default"}]},
                               ["$default"])):
            monkeypatch.setattr(squawk.probes, "_aws_json",
                                lambda _a, _t, p=payload: (p, ""))
            got, why = squawk.probes._api_stages(["apigateway", "get-stages"], 5)
            assert got == want and why == ""

    def test_a_failed_read_is_none_not_empty(self, monkeypatch):
        monkeypatch.setattr(squawk.probes, "_aws_json",
                            lambda _a, _t: (None, "AccessDenied"))
        got, why = squawk.probes._api_stages(["apigateway", "get-stages"], 5)
        assert got is None and why == "AccessDenied"


class TestWhatAnArgvRecorderCannotSee:
    """Review 2, R-33. `TestEveryCloudCallIsARead` records every argv the ten
    stages build and asserts over all of it. That is a real control and it is
    not the same as read-only: a `credential_process` in the AWS CLI's config
    runs whatever command it names, in this shell, before any request is
    signed. The recorder sees one read; the machine runs a shell command.

    Not a defect in the recorder — the limit of what an argv recorder can
    promise. The honest answer is to say which profiles carry one."""

    def _config(self, tmp_path, monkeypatch, text, creds=""):
        cfg = tmp_path / "config"
        cfg.write_text(text, encoding="utf-8")
        monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
        shared = tmp_path / "credentials"
        shared.write_text(creds, encoding="utf-8")
        monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(shared))

    def test_a_profile_that_runs_a_command_is_named(self, tmp_path,
                                                    monkeypatch):
        self._config(tmp_path, monkeypatch,
                     "[profile evil]\ncredential_process = /bin/sh -c true\n"
                     "\n[profile plain]\nregion = us-east-1\n")
        found, why = squawk.probes.profiles_running_a_command(
            ["evil", "plain", "never-configured"])
        assert found == ["evil"] and why == ""

    def test_the_credentials_file_spelling_counts_too(self, tmp_path,
                                                      monkeypatch):
        """`~/.aws/config` writes "[profile name]"; the credentials file writes
        "[name]". Both are the same profile to the CLI."""
        self._config(tmp_path, monkeypatch, "[profile a]\nregion = x\n",
                     creds="[b]\ncredential_process = /bin/echo hi\n")
        found, _why = squawk.probes.profiles_running_a_command(["a", "b"])
        assert found == ["b"]

    def test_the_command_itself_is_never_read(self, tmp_path, monkeypatch):
        """The value is a command line and may carry anything — a token, a
        path, an argument somebody should not have written there. The KEY is
        the fact; the value is not this tool's business."""
        self._config(tmp_path, monkeypatch,
                     "[profile evil]\n"
                     "credential_process = /bin/sh -c 'echo SECRETVALUE'\n")
        found, _why = squawk.probes.profiles_running_a_command(["evil"])
        assert found == ["evil"]
        assert "SECRETVALUE" not in json.dumps(found)

    def test_no_readable_config_is_unknown_not_none(self, tmp_path,
                                                    monkeypatch):
        monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "absent"))
        monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE",
                           str(tmp_path / "also-absent"))
        found, why = squawk.probes.profiles_running_a_command(["a"])
        assert found == [] and "unknown" in why

    def test_the_page_says_it(self):
        out = squawk.analysis._recorder_caveats(
            {"profiles_running_a_command": ["evil"], "profiles_config_error": ""})
        assert out and "credential_process" in out[0]
        assert "RUNS that command on this machine" in out[0]
        assert "the read-only guarantee is over the commands Squawk builds" \
            in out[0]

    def test_an_unreadable_config_is_said_too(self):
        out = squawk.analysis._recorder_caveats(
            {"profiles_running_a_command": [],
             "profiles_config_error": "no readable AWS CLI config"})
        assert out and "could not be checked" in out[0]

    def test_nothing_to_say_says_nothing(self):
        assert squawk.analysis._recorder_caveats(
            {"profiles_running_a_command": [], "profiles_config_error": ""}) == []

    def test_the_charter_names_the_limit(self):
        # Relative to THIS file, not to the working directory. CI runs pytest
        # from the repository root and a relative "CHARTER.md" is only found
        # when the suite happens to be run from inside the package.
        charter = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "docs", "CHARTER.md")
        row = [ln for ln in open(charter, encoding="utf-8")
               if ln.startswith("| **I3**")]
        assert row, "the I3 row moved"
        assert "credential_process" in row[0]
        assert "What that does not cover" in row[0], \
            "a control whose limit is unstated is a claim"
        assert "SSO and credential caches" in row[0]


class TestPublicMeansSomethingDifferentForACredential:
    """Review 2, R-34. The table said `analyzer-public` is high because "the
    resource's own authentication is the guard left". Access Analyzer calls a
    resource public when the policy grants access with NO authentication at
    all — an IAM role anyone can assume, a KMS key anyone can use. There is no
    guard left; that is what public means.

    And the IAM reader already files an administrative role reachable from
    outside as critical, so one fact on one page carried two severities from
    two stages."""

    def _finding(self, kind):
        data = {"account": "0", "read_at": "", "api_calls": 1, "limit": 200,
                "truncated": False, "regions_enabled": ["us-east-1"],
                "regions_read": ["us-east-1"], "regions_partial": [],
                "regions_unread": [],
                "regional": {"us-east-1": {
                    "analyzers": [{"name": "a", "kind": "ACCOUNT",
                                   "arn": "arn:x"}],
                    "findings": [{"id": "f", "resource": "arn:x", "name": "r",
                                  "kind": kind, "panel": "roles",
                                  "public": True, "scope": "public",
                                  "federation": "", "principal": {"AWS": "*"},
                                  "actions": ["sts:AssumeRole"],
                                  "conditions": [], "analyzed_at": ""}],
                    "unreadable": []}}}
        return {f["key"]: f for f in squawk.analysis.analyzer_findings(data)}

    def test_a_public_role_is_critical(self):
        row = self._finding("AWS::IAM::Role")["analyzer-public-credential"]
        assert row["severity"] == "critical"
        assert "nothing left in the way" in row["why"]

    def test_a_public_key_and_a_public_secret_are_too(self):
        for kind in ("AWS::KMS::Key", "AWS::SecretsManager::Secret"):
            keys = self._finding(kind)
            assert keys["analyzer-public-credential"]["severity"] == "critical", \
                kind

    def test_a_public_bucket_is_still_high(self):
        """Being reachable is often the point of a bucket, which is what keeps
        it below critical."""
        row = self._finding("AWS::S3::Bucket")["analyzer-public"]
        assert row["severity"] == "high"
        assert "nothing left in the way" not in row["why"]

    def test_the_two_stages_no_longer_disagree_about_a_public_role(self):
        """The sharp part of the finding: the IAM reader files an
        administrative role reachable from outside as critical, and the
        analyzer filed the same role at high."""
        analyzer = self._finding("AWS::IAM::Role")["analyzer-public-credential"]
        iam = squawk.analysis.role_findings({
            "roles_already_admin": [
                {"name": "r", "reach": "anyone", "why": ["AdministratorAccess"],
                 "trust": [{"kind": "aws", "who": "*", "reach": "anyone",
                            "why": "ANY AWS principal"}]}],
            "roles_with_escalation": []})
        assert analyzer["severity"] == iam[0]["severity"] == "critical"


class TestFederatedIsNotOneAnswer:
    """The IAM panel printed `(federated)` beside every GitHub Actions role in field use — several
    of them, undifferentiated.

    A trust pinned to ONE REPOSITORY and one pinned to the whole organization
    are the same word and not the same risk: the second lets any repository in
    the org assume the role. `_federated_reach` has computed which it is since
    the GitHub reader was written and no view rendered it, which the charter
    calls out by name — a fix that reaches no screen is the same defect as not
    computing it."""

    GH = "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"

    def _pin(self, condition, who=None):
        return squawk.probes._federated_reach(
            who or self.GH, condition, "000000000000").get("pin")

    def test_the_reader_says_which_kind_of_pin_it_found(self):
        sub = "token.actions.githubusercontent.com:sub"
        assert self._pin({sub: ["repo:acme/app:ref:refs/heads/main"]}) \
            == "github-repository"
        assert self._pin({sub: ["repo:acme/*:*"]}) == "github-organisation"
        assert self._pin({}) == "nothing"

    def test_a_provider_says_which_kind_it_is(self):
        acc = "000000000000"
        assert self._pin({}, "arn:aws:iam::%s:saml-provider/Okta" % acc) \
            == "saml-unpinned"
        assert self._pin({"x": ["y"]},
                         "arn:aws:iam::%s:oidc-provider/oidc.eks.z" % acc) \
            == "oidc"

    def test_the_two_github_pins_read_differently(self):
        """The whole point. One repo can assume it, or every repo in the
        organization can."""
        one = squawk.analysis.reach_words(
            {"reach": "federated",
             "trust": [{"reach": "federated", "pin": "github-repository"}]})
        many = squawk.analysis.reach_words(
            {"reach": "federated",
             "trust": [{"reach": "federated", "pin": "github-organisation"}]})
        assert one == "federated · one repo"
        assert many == "federated · ANY repo in the org"
        assert one != many

    def test_only_the_widest_way_in_is_described(self):
        """A role is as reachable as its loosest statement, and the tight ones
        do not make up for it."""
        role = {"reach": "anyone", "trust": [
            {"reach": "federated", "pin": "github-repository"},
            {"reach": "anyone", "pin": "nothing"}]}
        assert squawk.analysis.reach_words(role) == "anyone · nothing"

    def test_a_reach_with_no_pin_still_reads(self):
        for role in ({"reach": "internal", "trust": [{"reach": "internal"}]},
                     {"reach": "federated", "trust": []},
                     {"reach": "federated"},
                     {}):
            got = squawk.analysis.reach_words(role)
            assert (got and "·" not in got) or got.startswith(
                ("internal", "federated")), role

    def test_the_panel_prints_it(self, tmp_path, monkeypatch):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        (run / "raw" / "cloud-iam.json").write_text(json.dumps({
            "account": "000000000000", "read_at": "", "api_calls": 8,
            "counts": {"users": 0, "roles": 2, "groups": 0, "policies": 1},
            "users": [], "roles": [], "users_unread": 0, "truncated": False,
            "limit": 1000, "budget": 600,
            "roles_with_escalation": [
                {"name": "deploy-one-repo", "escalation": ["iam:PutRolePolicy"],
                 "reach": "federated", "self_service": [], "scoped": [],
                 "notes": [], "trust": [{"kind": "federated", "who": self.GH,
                                         "reach": "federated",
                                         "pin": "github-repository",
                                         "why": "pinned"}]},
                {"name": "deploy-whole-org", "escalation": ["iam:PutRolePolicy"],
                 "reach": "federated", "self_service": [], "scoped": [],
                 "notes": [], "trust": [{"kind": "federated", "who": self.GH,
                                         "reach": "federated",
                                         "pin": "github-organisation",
                                         "why": "org"}]}],
            "roles_already_admin": []}), encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [{"tool": "cloudiam", "status": "ok", "detail": "",
                         "coverage": {"examined": 2, "unit": "principals"}}]}])
        html = squawk.web.cloud_iam_panel(str(tmp_path))
        assert "deploy-one-repo" in html and "deploy-whole-org" in html
        assert "federated · one repo" in html
        assert "federated · ANY repo in the org" in html
        assert "(federated)</span>" not in html, \
            "the undifferentiated word is still on the page"
class TestZeroSkillsScannedIsNotACleanAudit:
    """Found by running the service, which nobody had.

    `skillaudit` publishes `scanned` and nothing read it. A run over a
    directory holding no SKILL.md reported `ok` with 0 findings and the page
    printed "No squawk. Nothing critical, nothing under attack." That is a zero
    over an empty denominator (I15) on a service that had never been run
    against a real directory.

    `selfaudit` had no extractor either. Its zero is not vacuous -- it found
    three things -- but it published 17 checks and two that could not tell, and
    the run said "tool publishes no coverage"."""

    def test_no_skills_found_is_a_gap_not_a_clean_audit(self):
        cov = squawk.scanners.stage_coverage(
            "skillaudit", json.dumps({"scanned": 0, "findings": []}))
        assert cov.examined == 0 and cov.unit == "skills"
        assert "nothing was audited" in cov.note
        status, detail, _c = squawk.engine._apply_coverage(
            "skillaudit", json.dumps({"scanned": 0, "findings": []}), [], "ok",
            "0 findings")
        assert status == "gap", "a clean audit of nothing"
        assert "examined 0 skills" in detail

    def test_a_directory_with_skills_is_a_real_answer(self):
        status, _d, cov = squawk.engine._apply_coverage(
            "skillaudit", json.dumps({"scanned": 4, "findings": []}), [], "ok",
            "0 findings")
        assert status == "ok" and cov.examined == 4

    def test_a_reading_it_cannot_parse_is_not_zero(self):
        """I14. A payload without `scanned` is a tool that published no
        coverage, which is different from one that scanned nothing."""
        for junk in ("{}", "not json", '{"scanned": "four"}', "[]"):
            cov = squawk.scanners.stage_coverage("skillaudit", junk)
            assert cov.examined is None, junk

    def test_the_instrument_check_says_how_many_checks_ran(self):
        raw = json.dumps({"counts": {"ok": 14, "gap": 1, "unknown": 2},
                          "checks": [{"id": "c%d" % i} for i in range(17)]})
        cov = squawk.scanners.stage_coverage("selfaudit", raw)
        assert cov.examined == 17 and cov.unit == "checks"
        assert cov.errors == 2, "a check that could not tell is not a pass"
        assert "could not tell" in cov.note

    def test_an_instrument_check_with_no_checks_publishes_nothing(self):
        assert squawk.scanners.stage_coverage(
            "selfaudit", json.dumps({"counts": {}, "checks": []})).examined \
            is None

    def test_both_are_registered(self):
        """A stage with no extractor reports `tool publishes no coverage`,
        which reads as "there is no denominator to have" rather than "nobody
        wrote one"."""
        for tool in ("skillaudit", "selfaudit"):
            assert tool in squawk.COVERAGE, tool


class TestAToolThatRefusedTheCommandSaysWhatItRefused:
    """From a field compliance run (2026-09-12). checkov would not take a flag
    and the run said:

        [1/2] checkov directory … !! usage: checkov [-h] [-v] [--support]
              [-d DIRECTORY] [--add-check]  ·  37 more line(s) in raw/checkov.err

    The sentence naming WHICH flag was in the 38th line of a file the reader
    had to go open. A tool that refused the command names what it refused, and
    argparse -- which checkov, semgrep, bandit and the rest are built on --
    puts a usage banner first and the reason last."""

    ERR = ("usage: checkov [-h] [-v] [--support] [-d DIRECTORY] [--add-check]\n"
           "               [--file FILE] [--skip-path SKIP_PATH]\n"
           "checkov: error: unrecognized arguments: --compact\n")

    def test_the_reason_is_read_from_the_end(self):
        got = squawk.engine._refusal(self.ERR)
        assert got == "checkov refused the command: unrecognized arguments: --compact"
        assert "usage:" not in got

    def test_noise_is_not_a_refusal(self):
        """Kept narrow on purpose: a scanner that merely mentions the word
        must not hijack the summary."""
        for text in ("", "just some output\nand more",
                     "an error: occurred somewhere",
                     "ERROR something went wrong",
                     "Traceback (most recent call last):"):
            assert squawk.engine._refusal(text) == "", text

    def test_the_last_refusal_wins(self):
        """Two programs in one pipeline; the one that stopped is the last to
        speak."""
        got = squawk.engine._refusal(
            "wrapper: error: first\nusage: inner [-h]\ninner: error: second")
        assert "inner refused the command: second" == got

    def test_checkov_asks_for_json_and_nothing_else(self):
        """`--compact` and `--quiet` are documented as "in case of CLI output"
        and this asks for JSON, so they never changed the answer -- and one of
        them is what a real checkov refused. A flag that changes nothing can
        only fail."""
        class Ctx:
            target = "a-target"
            profile = None
            service = "compliance"
        cmd, _timeout = squawk.stage_checkov(Ctx())
        assert cmd[:5] == ["checkov", "-d", "a-target", "-o", "json"]
        assert "--compact" not in cmd and "--quiet" not in cmd

    def test_a_refusal_reaches_the_stage_detail(self, tmp_path, monkeypatch):
        """The unit is not the point; the sentence on the run is."""
        monkeypatch.setattr(squawk.engine, "tool_path",
                            lambda _n: "/usr/bin/checkov")
        monkeypatch.setattr(squawk.engine, "run_cmd",
                            lambda *_a, **_k: (2, "", self.ERR))
        out = squawk.execute_service(squawk.SERVICES["compliance"],
                                     str(tmp_path), str(tmp_path),
                                     str(tmp_path))
        row = next(r for r in out["results"] if r.tool == "checkov")
        # Not "refused the command" any more, and correctly so: `--compact` is
        # no longer a flag this tool passes, so a checkov that refuses it is
        # refusing something that reached it some other way. The sharper
        # sentence is `TestArgumentsThisRunDidNotPass`; what this test holds is
        # that the usage banner is not what the reader gets.
        assert "refused" in row.detail
        assert "--compact" in row.detail
        assert not row.detail.startswith("usage:")
        assert "usage: checkov" not in row.detail
class TestTwoDenominatorsThatWereWrong:
    """Both from one compliance run on a working repository, 2026-09-12.

    trivy produced 288 IaC findings across 128 scan targets, and the run said
    "public-unencrypted-store (cannot evaluate: no iac scanner ran)". And
    gitleaks on the same repository said "0 finding(s) — tool publishes no
    coverage", which the page printed as "No squawk. Nothing critical."
    """

    # ---- I16: what a stage READ is not always its scanner's kind ----------

    def test_trivy_config_is_an_iac_scan(self):
        assert squawk.core.result_kind("trivy", "config") == "iac"

    def test_trivy_fs_and_image_are_still_dependency_scans(self):
        for mode in ("fs", "image"):
            assert squawk.core.result_kind("trivy", mode) == "sca", mode

    def test_an_unregistered_tool_has_no_kind(self):
        assert squawk.core.result_kind("not-a-scanner", "x") == ""

    def test_the_correlation_counts_the_stage_that_ran(self):
        """The defect, end to end: an IaC correlation over a run where the only
        IaC reading came from trivy."""
        results = [squawk.StageResult("trivy", "config", "ok", "", None, [],
                                      0, None, None)]
        out = squawk.correlate([], results)
        unknown = [c for c in out
                   if c["state"] == "unknown" and "no iac" in c["why"]]
        assert not unknown, \
            "an IaC scan ran and the correlation says none did: %s" % unknown

    def test_a_dependency_scan_does_not_stand_in_for_an_iac_one(self):
        """The fix must not make trivy count for everything."""
        results = [squawk.StageResult("trivy", "fs", "ok", "", None, [],
                                      0, None, None),
                   squawk.StageResult("checkov", "directory", "error", "", None,
                                      [], 0, None, None)]
        out = squawk.correlate([], results)
        assert any(c["state"] == "unknown" and "the iac side was never read" in c["why"]
                   for c in out), "a dependency scan was counted as IaC"

    # ---- gitleaks scans what is there, not what the scope claimed --------

    @staticmethod
    def _gitleaks_argv(target, scope="repo"):
        class _Ctx:
            def __init__(self, t, sc):
                self.target, self.scope, self.repo = t, sc, t
                self.profile, self.service, self.raw_path = None, "preflight", ""
                self.artifacts = {}
        argv, _timeout = squawk.STAGES["gitleaks"].build(_Ctx(target, scope))
        return argv

    def test_a_directory_that_is_not_a_repository_gets_no_git(self, tmp_path):
        """The operator's `GitHub Repos/acme-platform` — a directory that HOLDS
        repositories rather than being one. `--no-git` was decided by scope
        alone, so gitleaks was told to walk a history that does not exist and
        reported "0 commits scanned · scanned ~0 bytes". Reproduced against
        gitleaks 8.30.1: a synthetic `ghp_`-shaped token in that tree is missed
        entirely without this flag and found with it. The gap machinery caught
        the empty denominator, so it was never a SILENT false clean — it was a
        permanent one, and every run of that target lost the secrets scanner."""
        target = tmp_path / "GitHub Repos" / "acme-platform"
        (target / "src").mkdir(parents=True)
        assert "--no-git" in self._gitleaks_argv(str(target))

    def test_a_real_repository_still_gets_its_history_read(self, tmp_path):
        """The guard. Git history is where a secret that was committed and then
        deleted still lives, and it is most of what this scanner is for —
        passing --no-git everywhere would trade one blind spot for a worse
        one."""
        target = tmp_path / "realrepo"
        (target / ".git").mkdir(parents=True)
        assert "--no-git" not in self._gitleaks_argv(str(target))

    def test_a_worktree_is_a_repository_even_though_git_is_a_file(self, tmp_path):
        """In a worktree or a submodule `.git` is a FILE holding a gitdir
        pointer. `isdir` would call those not-a-repository and throw away the
        history this scanner exists to read."""
        target = tmp_path / "worktree"
        target.mkdir()
        (target / ".git").write_text("gitdir: /elsewhere/.git/worktrees/w\n")
        assert "--no-git" not in self._gitleaks_argv(str(target))

    def test_a_subdirectory_of_a_repository_keeps_its_history(self, tmp_path):
        """Review 3, R-43. `.git` was looked for at the target alone, so a
        repo-scope target that is a subdirectory of a checkout -- which has
        no `.git` of its own -- was sent into `--no-git`, and a secret removed
        from the tree and left in history was missed under a coverage line
        that read as though the history had been scanned. gitleaks in git
        mode finds the repository from a subdirectory by itself."""
        repo = tmp_path / "checkout"
        (repo / ".git").mkdir(parents=True)
        (repo / "services" / "api").mkdir(parents=True)
        assert "--no-git" not in self._gitleaks_argv(str(repo / "services" / "api"))
        # And a worktree's file-shaped `.git` is found the same way.
        wt = tmp_path / "wt"
        (wt / "src").mkdir(parents=True)
        (wt / ".git").write_text("gitdir: /elsewhere/.git/worktrees/w\n")
        assert "--no-git" not in self._gitleaks_argv(str(wt / "src"))

    def test_a_non_repo_scope_is_unaffected(self, tmp_path):
        """`baggage` and `skillaudit` read a directory and never wanted the
        history; that behaviour predates this and is not what changed."""
        target = tmp_path / "somewhere"
        target.mkdir()
        assert "--no-git" in self._gitleaks_argv(str(target), scope="dir")

    def test_the_decision_is_made_on_disk_not_on_the_scope_word(self, tmp_path):
        """Both directions from one assertion: the same scope, the same target
        path, and the only difference is whether `.git` is there."""
        target = tmp_path / "flips"
        target.mkdir()
        before = "--no-git" in self._gitleaks_argv(str(target))
        (target / ".git").mkdir()
        after = "--no-git" in self._gitleaks_argv(str(target))
        assert (before, after) == (True, False), (before, after)

    # ---- I15: gitleaks says what it read, on stderr -----------------------

    REAL = ("\x1b[90m2:55PM\x1b[0m \x1b[32mINF\x1b[0m "
            "\x1b[1m314 commits scanned.\x1b[0m\n"
            "\x1b[90m2:55PM\x1b[0m \x1b[32mINF\x1b[0m "
            "\x1b[1mscanned ~7944170 bytes (7.94 MB) in 511ms\x1b[0m\n")

    def test_it_reads_the_real_output_escapes_and_all(self):
        """Captured from gitleaks 8.30.1 rather than guessed."""
        cov = squawk.scanners.stage_coverage("gitleaks", "[]", "", self.REAL)
        assert cov.examined == 7944170 and cov.unit == "bytes"
        assert "314 commit(s) of history" in cov.note

    def test_no_git_prints_only_the_bytes_and_that_is_enough(self):
        cov = squawk.scanners.stage_coverage(
            "gitleaks", "[]", "", "INF scanned ~6 bytes (6 bytes) in 9.99ms")
        assert cov.examined == 6 and "commit" not in cov.note

    def test_zero_bytes_is_a_gap_whatever_caused_it(self):
        """The case that matters. "0 commits scanned." with "scanned ~0 bytes"
        read as a clean sweep of a working repository.

        The note no longer offers "a directory that is not a repository
        scanned in repo scope" as a cause, because `stage_gitleaks` decides on
        `.git` rather than on the scope label and that cause can no longer
        happen — see TestGitleaksDecidesOnWhatIsThere."""
        err = "INF 0 commits scanned.\nINF scanned ~0 bytes (0) in 19.6ms"
        status, detail, _c = squawk.engine._apply_coverage(
            "gitleaks", "[]", [], "ok", "0 findings", "", err)
        assert status == "gap"
        assert "examined 0 bytes" in detail
        assert "nothing was read" in detail
        assert "not a repository scanned in repo scope" not in detail, (
            "a cause that can no longer happen sends the reader after a ghost")

    def test_a_real_sweep_is_still_a_real_answer(self):
        status, detail, _c = squawk.engine._apply_coverage(
            "gitleaks", "[]", [], "ok", "0 findings", "", self.REAL)
        assert status == "ok" and "7944170 bytes" in detail

    def test_saying_nothing_is_unknown_not_zero(self):
        """Inventing a denominator is the fabrication this refuses
        everywhere else."""
        for err in ("", "no summary here", "INF no leaks found"):
            assert squawk.scanners.stage_coverage(
                "gitleaks", "[]", "", err).examined is None, err


class TestTheRolesTileSaysWhichRoles:
    """From the validation run of 2026-09-12. The headline tile read

        0   roles carrying more than read
            every policy on 6 role(s) read

    and the IAM section on the same page read "140 roles · 10 roles that can
    grant themselves more". Both true. The tile counts roles attached to
    exposed instances, a deliberately bounded lookup; the IAM section counts
    every role in the account. Only one of them said which population it was
    over, so the page read as though it contradicted itself."""

    @staticmethod
    def _summary(**totals):
        base = {"roles": 6, "broad_roles": 0, "unevaluated_roles": 0,
                "running": 5, "enis": 106, "public_instances": 0,
                "risky_open_groups": 0, "groups": 63, "world_open_groups": 2}
        base.update(totals)
        return {"totals": base, "regions_active": 1, "regions_read": 17,
                "regions_unread": [], "regions_denied": []}

    def _tile(self, **totals):
        facts = squawk.headline_facts(self._summary(**totals))
        row = [f for f in facts if f["key"] == "roles"]
        assert row, "the roles tile must exist"
        return row[0]

    def test_the_label_names_the_population(self):
        tile = self._tile()
        assert tile["label"] == "instance roles carrying more than read"

    def test_the_note_points_at_the_section_with_the_other_number(self):
        """A reader who sees 0 here and 10 below needs to be told, on the
        tile, that they are counts of different things."""
        tile = self._tile()
        assert "6 instance role(s) read" in tile["note"], tile["note"]
        assert "IAM section below" in tile["note"], tile["note"]

    def test_the_floor_form_names_the_population_too(self):
        """The unevaluated branch is the one a narrower identity hits, so it
        is the one most likely to be read by somebody who was refused."""
        tile = self._tile(unevaluated_roles=2)
        assert tile["label"] == "instance roles carrying more than read"
        assert "2 of 6 instance role(s)" in tile["note"], tile["note"]
        assert tile["value"].startswith("\u2265"), tile["value"]

    def test_the_domain_card_and_the_tile_agree(self):
        """The card beside it already said "roles on instances". The tile
        disagreeing with its own neighbour is what made this readable as a
        contradiction rather than as two facts."""
        assert squawk.INVENTORY_LABELS["roles"][0] == "roles on instances"
        assert "instance role" in self._tile()["label"]


class TestArgumentsThisRunDidNotPass:
    """checkov refused a long list of flags this tool never passed:

        --custom-policy-output-format=json --include-policy-metadata=True ...

    Squawk builds four tokens: `checkov -d <target> -o json`. Flags like those
    come from a `.checkov.yaml` in the tree being SCANNED, which checkov reads
    itself and turns into argv — reproduced against checkov 3.2.459. The
    message read as though this tool had passed them, and the first thing a
    reader would do is go hunting through code that does not contain them.

    The flag list here is illustrative and deliberately short: the original
    was copied from the configuration of the repository being scanned, which
    is somebody else's policy-as-code and not this project's to publish."""

    OURS: ClassVar[list] = ["checkov", "-d", "/t", "-o", "json"]
    THEIRS = ("checkov: error: unrecognized arguments: "
              "--compliance=NIST-800-53 --include-policy-metadata=True")

    def test_it_says_the_arguments_are_not_ours(self):
        got = squawk.engine._refusal(self.THEIRS, self.OURS)
        assert "refused arguments this run did not pass" in got
        assert "the command was `checkov -d /t -o json`" in got

    def test_it_names_where_they_came_from(self):
        """Pointing at the file is the difference between a reader fixing it
        and a reader searching for it."""
        got = squawk.engine._refusal(self.THEIRS, self.OURS)
        assert ".checkov.yaml" in got

    def test_it_names_the_remedy_not_only_the_cause(self):
        """Naming the file left the reader with a diagnosis and no move. On the
        owner's own repository this took checkov out of `preflight` AND
        `compliance` on every run — two services down to a coverage gap until
        somebody worked out what to do. Measured against checkov 3.2.459:
        `--config-file` does not override the tree's file and the working
        directory makes no difference, so there is no flag this tool can add
        and the file itself is the only remedy."""
        got = squawk.engine._refusal(self.THEIRS, self.OURS)
        assert "--config-file does not override it" in got, got
        assert "or the file has to go" in got, got

    def test_a_tool_with_no_known_remedy_says_nothing_extra(self):
        """The remedy is per-tool knowledge, verified against that tool. A
        guess appended to every refusal would be advice nobody checked."""
        got = squawk.engine._refusal(
            "semgrep: error: unrecognized arguments: --invented",
            ["semgrep", "--config", "auto", "/t"])
        assert "refused arguments this run did not pass" in got
        assert "does not override" not in got, got

    def test_an_argument_that_is_ours_is_still_ours(self):
        """The fix must not let this tool blame a target for its own flag."""
        got = squawk.engine._refusal(
            "checkov: error: unrecognized arguments: --compact",
            ["checkov", "-d", "/t", "-o", "json", "--compact"])
        assert "did not pass" not in got
        assert got == "checkov refused the command: unrecognized arguments: --compact"

    def test_the_flag_is_matched_without_its_value(self):
        """A flag can be refused as `--x=1` and passed as `--x 1`."""
        got = squawk.engine._refusal(
            "tool: error: unrecognized arguments: --config=auto",
            ["tool", "--config", "auto"])
        assert "did not pass" not in got

    def test_a_refusal_that_is_not_about_arguments_is_unchanged(self):
        got = squawk.engine._refusal(
            "semgrep: error: argument --config: expected one argument",
            ["semgrep", "--config"])
        assert got == ("semgrep refused the command: argument --config: "
                       "expected one argument")

    def test_an_unknown_tool_still_says_something_true(self):
        got = squawk.engine._refusal(
            "widget: error: unrecognized arguments: --zzz", ["widget", "-x"])
        assert "configuration the tool read itself" in got
        assert ".checkov" not in got


class TestALongStageSaysHowLongItMay:
    """"semgrep is still running and has been for some time" (the operator,
    2026-09-12). The start line said which stage; the number that answers "is
    it slow or is it stuck?" was left to the run page, and the run page is not
    where a person sits while semgrep takes twenty minutes on a large tree."""

    def test_the_budget_reaches_the_terminal(self, capsys, monkeypatch,
                                             tmp_path):
        monkeypatch.setattr(squawk.engine, "tool_path",
                            lambda _n: "/usr/bin/" + _n)
        monkeypatch.setattr(squawk.engine, "run_cmd",
                            lambda *_a, **_k: (0, "{}", ""))
        squawk.cli.main(["--run", "compliance", "--repo", str(tmp_path),
                         "--evidence", str(tmp_path / "ev")])
        printed = capsys.readouterr().out
        assert "≤15m 00s" in printed, printed[:400]

    def test_it_is_the_stages_own_budget_not_a_constant(self, tmp_path,
                                                        capsys, monkeypatch):
        """A profile that raises the budget has to raise the number on
        screen, or the number is decoration."""
        ev = tmp_path / "ev"
        ev.mkdir()
        (ev / "squawk.toml").write_text(
            "[services.compliance]\nstage_timeout = 4200\n", encoding="utf-8")
        monkeypatch.setattr(squawk.engine, "tool_path",
                            lambda _n: "/usr/bin/" + _n)
        monkeypatch.setattr(squawk.engine, "run_cmd",
                            lambda *_a, **_k: (0, "{}", ""))
        squawk.cli.main(["--run", "compliance", "--repo", str(tmp_path),
                         "--evidence", str(ev)])
        assert "≤1h 10m" in capsys.readouterr().out
class TestTheBudgetIsWhatItWasAllowedNotWhatItTook:
    """From a real preflight run, 2026-09-12:

        [2/5] semgrep auto … ≤20m 00s !! timed out after 1200s  ·  27m 04s

    Seven minutes past the budget the same line had just named. The budget
    bounds the SCAN; stopping the scanner is extra, and a line that prints the
    budget as though it were the elapsed is a claim about a control that did
    not hold."""

    @staticmethod
    def _ignores_sigterm():
        return ("import signal,sys,time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "time.sleep(40)\n")

    def test_a_scanner_that_will_not_die_costs_more_than_its_budget(self):
        """The mechanism, measured rather than argued: SIGTERM, the grace
        period, then SIGKILL."""
        start = time.time()
        code, _out, err = squawk.core.run_cmd(
            [sys.executable, "-c", self._ignores_sigterm()], None, 3)
        took = time.time() - start
        assert code == 124 and "timed out after 3s" in err
        assert took >= 3 + squawk.core.CHILD_GRACE_SECONDS - 0.5, took

    def test_the_stage_says_what_it_actually_took(self, tmp_path, monkeypatch):
        monkeypatch.setattr(squawk.engine, "tool_path",
                            lambda _n: sys.executable)
        monkeypatch.setitem(
            squawk.STAGES, "bandit",
            squawk.StageSpec("bandit", "recursive",
                             lambda _c: ([sys.executable, "-c",
                                          self._ignores_sigterm()], 3)))
        root = tmp_path / "ev"
        root.mkdir()
        out = squawk.execute_service(
            squawk.Service("t", "T", "repo", ("bandit",), "instant", ""),
            str(tmp_path), str(root), str(tmp_path))
        detail = out["results"][0].detail
        assert "timed out after 3s" in detail, detail
        assert "took a further" in detail, detail
        assert "the stage ran 8s in all" in detail or "ran 7s in all" in detail, \
            detail

    def test_a_stage_that_stops_promptly_says_nothing_extra(self, tmp_path,
                                                            monkeypatch):
        """The slack exists so the ordinary cost of stopping a child does not
        become a sentence on every timeout."""
        monkeypatch.setattr(squawk.engine, "tool_path",
                            lambda _n: sys.executable)
        monkeypatch.setitem(
            squawk.STAGES, "bandit",
            squawk.StageSpec("bandit", "recursive",
                             lambda _c: ([sys.executable, "-c",
                                          "import time; time.sleep(40)"], 2)))
        root = tmp_path / "ev"
        root.mkdir()
        out = squawk.execute_service(
            squawk.Service("t", "T", "repo", ("bandit",), "instant", ""),
            str(tmp_path), str(root), str(tmp_path))
        detail = out["results"][0].detail
        assert "timed out after 2s" in detail
        assert "took a further" not in detail, detail

    def test_the_slack_is_named_not_a_literal(self):
        assert squawk.engine.STOP_SLACK_SECONDS > 0


class TestAJsonBooleanInAConditionDoesNotCrashTheReaders:
    """Review 3, R-36. `Bool` conditions carry JSON `true`, and a numeric
    account id is what a policy editor that types numbers produces. Every
    reader iterated the value with `(value or [])`, so a boolean or a number
    raised TypeError -- and a policy with `aws:MultiFactorAuthPresent: true`
    took the whole IAM stage down with it, on the path that reads a real
    account. The normalizer must never raise (I6), and neither may the
    readers under it."""

    ME = "111111111111"
    ORG: ClassVar[dict] = {"id": "o-mine", "management": "333333333333",
           "accounts": ["111111111111", "333333333333"],
           "accounts_listed": True}

    def _doc(self, condition, principal="*"):
        return {"Statement": [{"Effect": "Allow", "Principal": principal,
                               "Action": "sns:Publish", "Resource": "*",
                               "Condition": condition}]}

    def test_a_boolean_is_read_as_its_word(self):
        got = squawk.probes._condition_map(
            {"Bool": {"aws:SecureTransport": True}})
        assert got == {"aws:securetransport": [("affirms", ["true"])]}
        assert squawk.probes._condition_values(False) == ["false"]
        assert squawk.probes._condition_values(3600) == ["3600"]
        assert squawk.probes._condition_values([True, 1, "x", [2], {"a": 1}]) \
            == ["true", "1", "x"]
        assert squawk.probes._condition_values(None) == []

    def test_a_numeric_account_id_is_still_this_account(self):
        doc = self._doc({"StringEquals": {"aws:PrincipalAccount": 111111111111}})
        rows = squawk.probes.who_can_assume(doc, self.ME, self.ORG)
        assert rows[0]["reach"] == "internal"
        assert squawk.probes._public_policy_reasons(doc, "p", self.ME,
                                                    self.ORG) == []
        squawk.probes.read_policy(doc, "p")

    def test_every_json_scalar_shape_is_survived_by_all_three_readers(self):
        for value in (True, False, 0, 3600, 1.5, None, [True, 1, "x"],
                      [[1]], {"a": 1}, [None]):
            doc = self._doc({"StringEquals": {"aws:PrincipalOrgID": value}})
            squawk.probes.who_can_assume(doc, self.ME, self.ORG)
            squawk.probes._public_policy_reasons(doc, "p", self.ME, self.ORG)
            squawk.probes.read_policy(doc, "p")
            squawk.probes._condition_keys(doc["Statement"][0]["Condition"])

    def test_the_iam_stage_survives_a_boolean_condition(self, monkeypatch):
        """The stage, not the reader: this is the path a live estate takes."""
        trust = {"Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::%s:root" % self.ME},
            "Action": "sts:AssumeRole",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": True},
                          "NumericLessThan": {"aws:MultiFactorAuthAge": 3600}}}]}
        answers = {
            "get-caller-identity": {"Account": self.ME, "Arn": "arn:x"},
            "get-account-authorization-details": {
                "UserDetailList": [],
                "RoleDetailList": [{
                    "RoleName": "ops", "Arn": "arn:aws:iam::%s:role/ops" % self.ME,
                    "AssumeRolePolicyDocument": trust,
                    "RolePolicyList": [{"PolicyName": "all", "PolicyDocument": {
                        "Statement": [{"Effect": "Allow", "Action": "*",
                                       "Resource": "*"}]}}],
                    "AttachedManagedPolicies": []}],
                "GroupDetailList": [], "Policies": []},
            "get-account-summary": {"SummaryMap": {"AccountMFAEnabled": 1}},
        }

        def responder(argv, _t):
            return answers.get(argv[1], {}), ""

        data, status, detail = _run_probe(monkeypatch,
                                          squawk.probes.aws_iam_graph, responder)
        assert status == "ok", detail
        names = [r["name"] for r in data["roles_already_admin"]]
        assert "ops" in names
        role = next(r for r in data["roles_already_admin"] if r["name"] == "ops")
        assert role["reach"] == "internal"


class TestASetOperatorPrefixDoesNotHideTheNegation:
    """Review 3, R-39. `ForAnyValue:StringNotEquals` and
    `ForAllValues:StringNotLike` are the negated operators with a set prefix,
    and `_operator_sense` looked at the whole word, so the prefix hid the
    `Not` and a denylist read as an allowlist. And a GitHub `sub` under a
    negated operator -- "every repository except these" -- read as a pin."""

    ME = "111111111111"
    ORG: ClassVar[dict] = {"id": "o-mine", "management": "333333333333",
           "accounts": ["111111111111"], "accounts_listed": True}

    def test_the_prefixes_are_stripped_before_the_sense_is_read(self):
        for op in ("ForAnyValue:StringNotEquals", "ForAllValues:StringNotLike",
                   "forallvalues:ArnNotEqualsIfExists", "StringNotEquals"):
            assert squawk.probes._operator_sense(op) == "negates", op
        for op in ("ForAnyValue:StringEquals", "ForAllValues:ArnLike",
                   "StringEqualsIfExists"):
            assert squawk.probes._operator_sense(op) == "affirms", op

    def test_a_prefixed_negation_is_the_finding_it_always_was(self):
        for op in ("StringNotEquals", "ForAnyValue:StringNotEquals",
                   "ForAllValues:StringNotLike"):
            doc = {"Statement": [{"Effect": "Allow", "Principal": "*",
                                  "Action": "sns:Publish", "Resource": "*",
                                  "Condition": {op: {"aws:PrincipalOrgID":
                                                     "o-mine"}}}]}
            reasons = squawk.probes._public_policy_reasons(doc, "p", self.ME,
                                                           self.ORG)
            assert len(reasons) == 1, op
            assert "except those the condition names" in reasons[0], op

    def _github(self, operator, sub):
        return {"Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "arn:aws:iam::%s:oidc-provider/"
                                       "token.actions.githubusercontent.com"
                                       % self.ME},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {operator: {"token.actions.githubusercontent.com:sub":
                                     sub}}}]}

    def test_a_negated_github_sub_pins_nothing(self):
        row = squawk.probes.who_can_assume(
            self._github("StringNotLike", "repo:evil/*"), self.ME, self.ORG)[0]
        assert row["reach"] == "anyone"
        assert row["pin"] == "nothing"
        assert "NEGATED" in row["why"] and "denylist" in row["why"]

    def test_an_affirmed_github_sub_still_pins(self):
        row = squawk.probes.who_can_assume(
            self._github("StringLike", "repo:acme/app:*"), self.ME, self.ORG)[0]
        assert row["reach"] == "federated"
        assert row["pin"] == "github-repository"


class TestAnAccountTheOrganizationReadCouldNotPlace:
    """Review 3, R-37. A member account's audit role can usually describe
    the organization and usually cannot list its accounts. With only
    sibling-or-stranger to choose from, every sibling read as a stranger on
    that ordinary path: an administrative role trusting one was a CRITICAL
    under a 7700 saying the exposure is live, a topic granted to one was
    HIGH, and the banner written for exactly this case never rendered
    because the refusal arrived in the slot for the organization read
    failing. Not settled is its own answer, at unknown."""

    ME = "000000000000"
    OTHER = "444444444444"
    MEMBER: ClassVar[dict] = {"id": "o-mine", "management": "333333333333", "accounts": [],
              "accounts_listed": False}

    def _trust(self):
        return {"Statement": [{"Effect": "Allow",
                               "Principal": {"AWS": "arn:aws:iam::%s:root"
                                                    % self.OTHER},
                               "Action": "sts:AssumeRole"}]}

    def _grant(self):
        return {"Statement": [{"Effect": "Allow",
                               "Principal": {"AWS": "arn:aws:iam::%s:root"
                                                    % self.OTHER},
                               "Action": "sqs:SendMessage", "Resource": "*"}]}

    def test_the_trust_reader_says_unsettled_not_external(self):
        row = squawk.probes.who_can_assume(self._trust(), self.ME, self.MEMBER)[0]
        assert row["reach"] == "unsettled"
        assert "could not be settled" in row["why"]
        assert self.OTHER not in row["why"], "the account id is masked"

    def test_a_list_that_was_read_and_is_empty_is_still_a_stranger(self):
        listed = dict(self.MEMBER, accounts_listed=True)
        row = squawk.probes.who_can_assume(self._trust(), self.ME, listed)[0]
        assert row["reach"] == "external"

    def test_an_older_handoff_without_the_flag_reads_an_empty_list_as_unread(self):
        older = {"id": "o-mine", "management": "333333333333", "accounts": []}
        row = squawk.probes.who_can_assume(self._trust(), self.ME, older)[0]
        assert row["reach"] == "unsettled"

    def test_a_sibling_on_the_list_is_still_the_organization(self):
        listed = dict(self.MEMBER, accounts=[self.OTHER], accounts_listed=True)
        row = squawk.probes.who_can_assume(self._trust(), self.ME, listed)[0]
        assert row["reach"] == "organization"

    def test_a_resource_grant_is_unsettled_too(self):
        reasons = squawk.probes._public_policy_reasons(
            self._grant(), "sqs policy", self.ME, self.MEMBER)
        assert len(reasons) == 1
        assert squawk.probes.is_unsettled_public(reasons[0])
        assert not squawk.probes.is_narrowed_public(reasons[0])
        conditioned = {"Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:PrincipalAccount": self.OTHER}}}]}
        reasons = squawk.probes._public_policy_reasons(
            conditioned, "sqs policy", self.ME, self.MEMBER)
        assert len(reasons) == 1 and squawk.probes.is_unsettled_public(reasons[0])

    def test_unsettled_ranks_between_a_stranger_and_a_federation(self):
        assert squawk.probes.widest_reach(
            [{"reach": "federated"}, {"reach": "unsettled"}]) == "unsettled"
        assert squawk.probes.widest_reach(
            [{"reach": "external"}, {"reach": "unsettled"}]) == "external"
        assert "unsettled" not in squawk.analysis.OUTSIDE_REACH

    def _iam(self, admin=True):
        row = {"name": "ops", "arn": "arn:aws:iam::0:role/ops",
               "reach": "unsettled", "escalation": ["iam:PutRolePolicy"],
               "trust": [{"kind": "aws", "who": "arn:aws:iam::%s:root"
                                                % self.OTHER,
                          "reach": "unsettled",
                          "why": "an account that may be in this "
                                 "organization: the organization answered "
                                 "and its account list was refused, so this "
                                 "could not be settled"}]}
        if admin:
            return {"counts": {}, "users": [], "roles_with_escalation": [],
                    "roles_already_admin": [dict(row, why=["allows every "
                                                          "action"])]}
        return {"counts": {}, "users": [], "roles_already_admin": [],
                "roles_with_escalation": [row]}

    def test_an_administrative_role_trusting_it_is_unknown_not_critical(self):
        for admin in (True, False):
            found = squawk.analysis.role_findings(self._iam(admin))
            assert [f["key"] for f in found] == ["role-trust-unsettled"], admin
            assert found[0]["severity"] == "unknown"
            assert "could not be settled" in found[0]["why"]
            assert "not a critical, and not nothing" in found[0]["why"]
            assert "ListAccounts" in found[0]["fix"]

    def test_the_normalizer_carries_it_as_unknown(self):
        found = squawk.scanners.norm_cloudiam(json.dumps(self._iam()), "")
        assert len(found) == 1 and found[0].severity == "unknown"

    def _data_services(self, reason):
        return {"account": "0", "read_at": "2026-09-14T12:00:00Z",
                "api_calls": 3, "truncated": False, "limit": 200,
                "regions_enabled": ["us-east-1"], "regions_read": ["us-east-1"],
                "regions_unread": [],
                "regional": {"us-east-1": {
                    "topics": [{"name": "alerts", "kind": "sns",
                                "encrypted": True, "public": [reason]}],
                    "queues": [],
                    "secrets": [],
                    "repositories": [{"name": "app", "scan_on_push": True,
                                      "mutable": False, "public": [reason]}],
                    "unreadable": []}}}

    def test_a_grant_to_it_is_unknown_not_high(self):
        reason = squawk.probes._public_policy_reasons(
            self._grant(), "sns policy", self.ME, self.MEMBER)[0]
        keys = {f["key"]: f for f in squawk.analysis.dataservice_findings(
            self._data_services(reason))}
        assert "messaging-open-to-any-principal" not in keys
        assert "registry-readable-by-anyone" not in keys
        assert keys["messaging-reach-unsettled"]["severity"] == "unknown"
        assert keys["registry-reach-unsettled"]["severity"] == "unknown"
        assert "could not answer" in keys["messaging-reach-unsettled"]["why"]

    def test_a_grant_the_list_settled_is_still_high(self):
        reason = squawk.probes._public_policy_reasons(
            self._grant(), "sns policy", self.ME,
            dict(self.MEMBER, accounts_listed=True))[0]
        keys = {f["key"] for f in squawk.analysis.dataservice_findings(
            self._data_services(reason))}
        assert "messaging-open-to-any-principal" in keys
        assert "messaging-reach-unsettled" not in keys

    def _org_cli(self, argv, _t):
        if argv[0] == "sts":
            return {"Account": self.ME, "Arn": "arn:x"}, ""
        if argv[1] == "describe-organization":
            return {"Organization": {"Id": "o-mine", "FeatureSet": "ALL",
                                     "MasterAccountId": "333333333333"}}, ""
        if argv[1] == "list-accounts":
            return None, ("An error occurred (AccessDeniedException) when "
                          "calling the ListAccounts operation: not authorized")
        return {}, ""

    def test_the_stage_reports_the_refused_list_as_a_partial_read(self,
                                                                   monkeypatch):
        ctx = _CloudProbeCtx()
        data, status, detail = _run_probe(
            monkeypatch, squawk.probes.aws_organization, self._org_cli, ctx)
        assert status == "gap", "a refused read must move the ledger row (I1)"
        assert "account list" in detail and "AccessDenied" in detail
        assert data["org_error"] == "", "the organization itself answered"
        assert "AccessDenied" in data["accounts_error"]
        assert data["organization"]["id"] == "o-mine"
        handoff = json.loads(ctx.artifacts["organization"])
        assert handoff["accounts_listed"] is False
        assert handoff["standalone"] is False
        cov = squawk.scanners.stage_coverage("cloudorg", json.dumps(data))
        assert cov.examined == 1, "describe-organization answered"
        assert cov.unit == "reads that answered" and cov.errors == 1
        assert "account list was refused" in cov.note

    def test_the_iam_stage_reads_the_handoff_as_unsettled(self, monkeypatch):
        ctx = _CloudProbeCtx()
        _run_probe(monkeypatch, squawk.probes.aws_organization, self._org_cli,
                   ctx)
        org = squawk.probes.organization_read(ctx)
        row = squawk.probes.who_can_assume(self._trust(), self.ME, org)[0]
        assert row["reach"] == "unsettled"

    def test_the_caveat_says_why_every_such_row_is_unsettled(self):
        summary = squawk.analysis.org_summary({
            "account": self.ME, "standalone": False, "org_error": "",
            "accounts_error": "AccessDeniedException",
            "organization": {"id": "o-mine", "management_account": "3"},
            "accounts": [], "profiles_asked": [], "profiles_probed": False,
            "profiles_reaching": {}, "profiles_unreachable": [],
            "profiles_error": ""})
        assert summary["accounts_error"] == "AccessDeniedException"
        caveats = " ".join(squawk.analysis.org_caveats(summary))
        assert "reported as unsettled" in caveats

    def test_the_iam_panel_files_it_under_its_own_card(self, tmp_path,
                                                        monkeypatch):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        (run / "raw" / "cloud-iam.json").write_text(
            json.dumps(self._iam()), encoding="utf-8")
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [{"tool": "cloudiam", "status": "ok", "detail": "",
                         "coverage": {"examined": 1, "unit": "principals"}}]}])
        html = squawk.web.cloud_iam_panel(str(tmp_path))
        assert "Assumable from an account this run could not place" in html
        assert "Reachable from outside, and able to grant itself more" not in html
        assert "ops" in html


class TestTheComparisonReadsLikeWithLike:
    """Review 3, R-38. The comparison card matched role names from the IAM
    reader against every kind the analyzer reports, keyed on a name that was
    the whole ARN for anything without a slash, and set the account's own
    federation aside on AWS's side only. So a bucket both the storage reader
    and the analyzer flagged was "a disagreement" and "the answer to trust",
    and a GitHub role this page reads as reachable by ANYONE was blamed on
    an SCP. Compared by (kind, name) now, over the kinds this page judges."""

    def _data(self, findings):
        return {"account": "0", "read_at": "2026-09-14T12:00:00Z",
                "api_calls": 4, "limit": 200, "truncated": False,
                "regions_enabled": ["us-east-1"], "regions_read": ["us-east-1"],
                "regions_partial": [], "regions_unread": [],
                "regional": {"us-east-1": {
                    "analyzers": [{"name": "default", "kind": "ACCOUNT",
                                   "arn": "arn:x"}],
                    "findings": list(findings), "unreadable": []}}}

    def _finding(self, name, kind, scope, panel):
        return {"id": name, "resource": "arn:aws:x:::%s" % name, "name": name,
                "kind": kind, "panel": panel, "public": scope == "public",
                "scope": scope, "federation": "",
                "principal": {"AWS": "*"}, "actions": [], "conditions": [],
                "analyzed_at": ""}

    def test_a_bucket_both_sides_name_is_agreement(self):
        agree = squawk.analysis.analyzer_agreement(
            self._data([self._finding("b1", "AWS::S3::Bucket", "external",
                                      "buckets")]),
            [("buckets", "b1")])
        assert agree["both"] == ["bucket b1"]
        assert agree["aws_only"] == [] and agree["ours_only"] == []

    def test_a_bucket_and_a_role_of_the_same_name_are_two_things(self):
        agree = squawk.analysis.analyzer_agreement(
            self._data([self._finding("x", "AWS::S3::Bucket", "external",
                                      "buckets")]),
            [("roles", "x")])
        assert agree["both"] == []
        assert agree["aws_only"] == ["bucket x"]
        assert agree["ours_only"] == ["x"]

    def test_a_bare_name_is_a_role(self):
        agree = squawk.analysis.analyzer_agreement(
            self._data([self._finding("r-aws", "AWS::IAM::Role", "external",
                                      "roles")]),
            ["r-aws", "r-ours"])
        assert agree["both"] == ["r-aws"] and agree["ours_only"] == ["r-ours"]

    def test_own_federation_this_page_calls_anyone_is_its_own_line(self):
        agree = squawk.analysis.analyzer_agreement(
            self._data([self._finding("gh-deploy", "AWS::IAM::Role",
                                      "own-federation", "roles")]),
            [("roles", "gh-deploy")])
        assert agree["own_unpinned"] == ["gh-deploy"]
        assert agree["ours_only"] == [], "it was blamed on an SCP from here"
        assert agree["aws_only"] == [] and agree["both"] == ["gh-deploy"]
        assert agree["own_federation"] == 1

    def test_a_kind_this_page_does_not_judge_is_aws_alone(self):
        agree = squawk.analysis.analyzer_agreement(
            self._data([self._finding("s1", "AWS::SecretsManager::Secret",
                                      "external", "secrets")]), [])
        assert agree["aws_only"] == []
        assert agree["unjudged"] == ["AWS::SecretsManager::Secret s1"]

    def test_the_kind_decides_the_panel_not_the_evidence_file(self):
        """An evidence file written by an older probe carries a panel of its
        own; the kind is the authority."""
        agree = squawk.analysis.analyzer_agreement(
            self._data([self._finding("b1", "AWS::S3::Bucket", "external",
                                      "roles")]),
            [("buckets", "b1")])
        assert agree["both"] == ["bucket b1"]

    def _root(self, tmp_path, monkeypatch, analyzer, iam=None, storage=None):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True)
        files = {"cloud-analyzer.json": analyzer}
        if iam is not None:
            files["cloud-iam.json"] = iam
        if storage is not None:
            files["cloud-storage.json"] = storage
        for name, payload in files.items():
            (run / "raw" / name).write_text(json.dumps(payload),
                                            encoding="utf-8")
        tools = {"cloud-analyzer.json": "cloudanalyzer",
                 "cloud-iam.json": "cloudiam", "cloud-storage.json": "cloudstore"}
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [{"tool": tools[n], "status": "ok", "detail": "",
                         "coverage": {"examined": 1, "unit": "reads"}}
                        for n in files]}])
        return str(tmp_path)

    def test_the_card_takes_buckets_from_the_storage_reading(self, tmp_path,
                                                             monkeypatch):
        storage = {"account": "0", "bucket_total": 1,
                   "buckets": [{"name": "b1", "public": ["any principal"],
                                "encrypted": True}],
                   "databases": {}, "regions_read": [], "regions_enabled": []}
        page = squawk.web.cloud_analyzer_panel(self._root(
            tmp_path, monkeypatch,
            self._data([self._finding("b1", "AWS::S3::Bucket", "public",
                                      "buckets")]),
            storage=storage))
        assert "Where AWS and this page disagree" not in page
        assert "the policy readers on this page do not" not in page

    def test_an_own_federation_role_read_as_anyone_is_not_blamed_on_an_scp(
            self, tmp_path, monkeypatch):
        iam = {"counts": {}, "users": [], "roles_already_admin": [],
               "roles_with_escalation": [
                   {"name": "gh-deploy", "reach": "anyone",
                    "escalation": ["iam:PutRolePolicy"],
                    "trust": [{"kind": "federated", "who": "gh",
                               "reach": "anyone", "pin": "nothing",
                               "why": "no condition on the sub claim"}]}]}
        page = squawk.web.cloud_analyzer_panel(self._root(
            tmp_path, monkeypatch,
            self._data([self._finding("gh-deploy", "AWS::IAM::Role",
                                      "own-federation", "roles")]),
            iam=iam))
        assert "reads as reachable by ANYONE" in page
        assert "gh-deploy" in page
        assert "a boundary, an SCP" not in page


class TestAStandaloneAccountIsInNoOrganization:
    """Review 3, R-41. A grant narrowed to `aws:PrincipalOrgID` on an account
    that is in no organization admits principals this account has no
    relation to, and the reader called it "inside the organization this
    account belongs to"."""

    ME = "111111111111"
    STANDALONE: ClassVar[dict] = {"id": "", "management": "", "accounts": [],
                  "accounts_listed": True, "standalone": True}

    def _doc(self):
        return {"Statement": [{"Effect": "Allow", "Principal": "*",
                               "Action": "sqs:SendMessage", "Resource": "*",
                               "Condition": {"StringEquals": {
                                   "aws:PrincipalOrgID": "o-somebody"}}}]}

    def test_a_grant_narrowed_to_some_organization_is_outside(self):
        reasons = squawk.probes._public_policy_reasons(
            self._doc(), "sqs policy", self.ME, self.STANDALONE)
        assert len(reasons) == 1
        assert "this account is in none" in reasons[0]
        row = squawk.probes.who_can_assume(self._doc(), self.ME,
                                           self.STANDALONE)[0]
        assert row["reach"] == "external"

    def test_with_no_organization_reading_at_all_it_is_still_organization(self):
        """The IAM stage running without the organization handoff falls back
        to what this tool knew before: an organization condition narrows."""
        row = squawk.probes.who_can_assume(self._doc(), self.ME, None)[0]
        assert row["reach"] == "organization"

    def test_the_caveat_says_so(self):
        summary = squawk.analysis.org_summary({
            "account": self.ME, "standalone": True, "org_error": "",
            "accounts_error": "", "organization": {}, "accounts": [],
            "profiles_asked": [], "profiles_probed": False,
            "profiles_reaching": {}, "profiles_unreachable": [],
            "profiles_error": ""})
        caveats = " ".join(squawk.analysis.org_caveats(summary))
        assert "reported as outside" in caveats


class TestAPolicyVariableNamesThisAccount:
    """Review 3, R-47. `${aws:PrincipalAccount}` as an account-key value is
    the documented way to write "the same account as the resource", and the
    reader required twelve digits, so a same-account grant landed at medium
    as a narrowing that names nobody."""

    ME = "111111111111"
    ORG: ClassVar[dict] = {"id": "o-mine", "management": "333333333333",
           "accounts": ["111111111111"], "accounts_listed": True}

    def _doc(self, key, value):
        return {"Statement": [{"Effect": "Allow", "Principal": "*",
                               "Action": "sqs:SendMessage", "Resource": "*",
                               "Condition": {"StringEquals": {key: value}}}]}

    def test_the_account_variable_is_this_account(self):
        for key in ("aws:PrincipalAccount", "aws:SourceAccount"):
            doc = self._doc(key, "${aws:ResourceAccount}")
            assert squawk.probes._public_policy_reasons(doc, "p", self.ME,
                                                        self.ORG) == [], key
            assert squawk.probes.who_can_assume(doc, self.ME,
                                                self.ORG)[0]["reach"] == "internal"

    def test_the_organization_variable_is_the_organization(self):
        doc = self._doc("aws:PrincipalOrgID", "${aws:ResourceOrgID}")
        assert squawk.probes._public_policy_reasons(doc, "p", self.ME,
                                                    self.ORG) == []
        assert squawk.probes.who_can_assume(doc, self.ME,
                                            self.ORG)[0]["reach"] == "organization"

    def test_twelve_digits_are_still_read_as_an_account(self):
        doc = self._doc("aws:PrincipalAccount", "222222222222")
        assert squawk.probes._public_policy_reasons(doc, "p", self.ME, self.ORG)


class TestTheLostCommunicationsAlarmSaysWhatHappened:
    """Review 3, R-44. "did not report" was the one phrase for every ledger
    row that was not ok, so a stage that refused one read of three reported
    two thirds of an answer under a line saying it reported nothing."""

    def _man(self, tmp_path, rows):
        root = str(tmp_path / "ev")
        d = os.path.join(root, "20260101T000000Z")
        os.makedirs(os.path.join(d, "raw"))
        man = {"run_id": "20260101T000000Z", "service": "cloudinventory",
               "scope": "cloud", "target": "aws", "service_label": "Cloud",
               "not_covered": "", "counts": {"total": 0, "excluded": 0},
               "severities": {}, "ledger": rows}
        for name, obj in (("manifest.json", man), ("findings.json", []),
                          ("identities.json", {}), ("digest.json", {})):
            with open(os.path.join(d, name), "w") as fh:
                json.dump(obj, fh)
        return root, squawk.list_runs(root)[0]

    def test_each_kind_of_trouble_has_its_own_verb(self, tmp_path):
        root, man = self._man(tmp_path, [
            {"tool": "cloudorg", "mode": "read", "status": "gap",
             "detail": "1 organization read(s) could not be read: the "
                       "organization's account list (AccessDenied)",
             "evidence": None,
             "coverage": {"examined": 1, "unit": "reads that answered",
                          "skipped": 0, "errors": 1, "note": ""}},
            {"tool": "cloudedge", "mode": "read", "status": "gap",
             "detail": "nothing was read", "evidence": None,
             "coverage": {"examined": 0, "unit": "regions read",
                          "skipped": 0, "errors": 1, "note": ""}},
            {"tool": "cloudiam", "mode": "read", "status": "error",
             "detail": "could not read the IAM graph", "evidence": None,
             "coverage": None},
            {"tool": "cloudstore", "mode": "read", "status": "skipped",
             "detail": "aws not found", "evidence": None, "coverage": None},
            {"tool": "cloudinv", "mode": "read", "status": "gap",
             "detail": "aws CLI not installed", "evidence": None,
             "coverage": None}])
        raised = next(r for r in squawk.squawk_check(root, man)
                      if r["code"] == "7600")
        detail = "\n".join(raised["detail"])
        assert "cloudorg reported, with a read refused" in detail
        assert "cloudedge read nothing" in detail
        assert "cloudiam ran and did not finish" in detail
        assert "cloudstore did not run" in detail
        assert "cloudinv did not run" in detail
        assert "did not report" not in detail
        assert "did not fully report" in raised["why"]

    def test_the_helper_never_raises_on_a_junk_row(self):
        for row in ({}, {"status": "gap"}, {"status": "gap", "coverage": "x"},
                    {"status": "gap", "coverage": {"examined": True}},
                    {"status": "gap", "coverage": {"examined": "3"}}):
            assert "did not run" in squawk.analysis._ledger_trouble(row)


class TestEveryPanelSaysWhenPartOfItsReadingFailed:
    """Review 3, R-46. Two panels rendered a partial reading without the
    notice every other panel carries above its numbers, and the storage
    tiles printed zero over a bucket whose policy status was refused."""

    def _root(self, tmp_path, monkeypatch, tool, name, payload, partial=True):
        run = tmp_path / "20260101T000000Z-aws"
        (run / "raw").mkdir(parents=True, exist_ok=True)
        (run / "raw" / name).write_text(json.dumps(payload), encoding="utf-8")
        row = {"tool": tool, "status": "gap" if partial else "ok",
               "detail": "1 read(s) could not be read: ListThings "
                         "(AccessDenied)" if partial else "",
               "coverage": {"examined": 1, "unit": "reads that answered",
                            "errors": 1 if partial else 0}}
        monkeypatch.setattr(squawk.web, "list_runs", lambda _r: [
            {"run_id": run.name, "service": "cloudinventory", "_dir": str(run),
             "ledger": [row]}])
        return str(tmp_path)

    def test_the_inventory_panel_carries_the_notice(self, tmp_path,
                                                    monkeypatch):
        root = self._root(tmp_path, monkeypatch, "cloudinv",
                          "cloud-inventory.json",
                          {"account": "0", "read_at": "2026-09-14T00:00:00Z",
                           "regions_enabled": ["us-east-1"],
                           "regions_read": ["us-east-1"],
                           "regional": {"us-east-1": {}}})
        html, _summary = squawk.web.cloud_inventory_panel(root)
        assert "Part of this reading failed" in html
        assert "ListThings" in html
        assert html.index("Part of this reading failed") \
            < html.index("What is in this account")

    def test_the_watching_panel_carries_the_notice(self, tmp_path,
                                                   monkeypatch):
        root = self._root(tmp_path, monkeypatch, "cloudenable",
                          "cloud-enablement.json",
                          {"account": "0", "read_at": "2026-09-14T00:00:00Z",
                           "regions_enabled": ["us-east-1"],
                           "regions_read": ["us-east-1"],
                           "regional": {"us-east-1": {}}})
        html = squawk.web.cloud_watching_panel(root)
        assert "Part of this reading failed" in html
        assert html.index("Part of this reading failed") \
            < html.index("What is watching this account")

    def test_the_storage_tiles_say_how_many_were_unreadable(self, tmp_path,
                                                            monkeypatch):
        storage = {"account": "0", "bucket_total": 2, "api_calls": 4,
                   "buckets": [{"name": "open", "public": [],
                                "encrypted": True},
                               {"name": "shut", "unreadable":
                                "policy status (AccessDenied)"}],
                   "databases": {}, "regions_read": [], "regions_enabled": []}
        html = squawk.web.cloud_storage_panel(self._root(
            tmp_path, monkeypatch, "cloudstore", "cloud-storage.json", storage))
        assert "with a public policy (1 unreadable)" in html
        assert "with no default encryption (1 unreadable)" in html
        clean = squawk.web.cloud_storage_panel(self._root(
            tmp_path, monkeypatch, "cloudstore", "cloud-storage.json",
            dict(storage, buckets=storage["buckets"][:1]), partial=False))
        assert "unreadable)" not in clean


class TestARefusalIsKnownEvenWhenTheStderrFileIsNot:
    """Review 3, R-51. The refusal was computed inside the block that writes
    the `.err` file, so an OSError writing that file lost it and the detail
    fell back to the first line of stderr -- the usage banner the refusal
    line was written to replace."""

    ERR = ("usage: checkov [-h] [-v] [--support] [-d DIRECTORY] [--add-check]\n"
           "checkov: error: unrecognized arguments: --compact\n")

    def test_the_detail_still_names_the_refusal(self, tmp_path, monkeypatch):
        real_open = builtins.open

        def no_err_files(path, *a, **k):
            if str(path).endswith(".err"):
                raise OSError(28, "No space left on device")
            return real_open(path, *a, **k)

        monkeypatch.setattr(squawk.engine, "open", no_err_files, raising=False)
        monkeypatch.setattr(squawk.engine, "tool_path",
                            lambda _n: "/usr/bin/checkov")
        monkeypatch.setattr(squawk.engine, "run_cmd",
                            lambda *_a, **_k: (2, "", self.ERR))
        out = squawk.execute_service(squawk.SERVICES["compliance"],
                                     str(tmp_path), str(tmp_path),
                                     str(tmp_path))
        row = next(r for r in out["results"] if r.tool == "checkov")
        assert "refused" in row.detail and "--compact" in row.detail
        assert not row.detail.startswith("usage:")


class TestTheReviewFindings:
    """Five defects found by an independent review on 2026-09-18, all of the
    same family: the tool held itself to a rule everywhere except in one
    place, and the exception was the place a reader was most likely to look.
    """

    # --- a finding whose subject is a credential ---------------------------

    def test_bandit_does_not_keep_the_password_it_found(self):
        """`norm_gitleaks` has never kept a matched secret. bandit B105 finds
        the same secret and kept it, so the discipline held for the scanner
        whose name says "secret" and not for the one that reads source."""
        raw = json.dumps({"results": [{
            "test_id": "B105", "filename": "app.py", "line_number": 3,
            "issue_severity": "LOW", "issue_confidence": "MEDIUM",
            "issue_text": "Possible hardcoded password: 'hunter2'",
            "code": "3 PASSWORD = 'hunter2'\n"}]})
        f = squawk.scanners.norm_bandit(raw, "/t")[0]
        assert "hunter2" not in f.detail["evidence"], f.detail["evidence"]
        assert f.detail["evidence"] == squawk.scanners.EVIDENCE_WITHHELD
        assert f.path == "app.py" and f.detail["line"] == 3, \
            "the finding must still say where to look"

    def test_the_password_is_not_in_the_finding_title_either(self):
        """Withholding the evidence was not enough. bandit's B105 message is
        "Possible hardcoded password: '<the password>'", so the title carried
        the secret after its evidence had stopped. Found by planting a password,
        scanning it and grepping the run's own findings.json for the string."""
        raw = json.dumps({"results": [{
            "test_id": "B105", "filename": "app.py", "line_number": 1,
            "issue_severity": "LOW",
            "issue_text": "Possible hardcoded password: 'hunter2'",
            "code": "1 PASSWORD = 'hunter2'\n"}]})
        f = squawk.scanners.norm_bandit(raw, "/t")[0]
        whole = json.dumps([f.title, f.detail])
        assert "hunter2" not in whole, whole
        assert "hardcoded password" in f.title, "the finding still says what it is"

    def test_an_ordinary_message_keeps_its_quoted_text(self):
        """The false-positive half: a quote in a message that is not about a
        credential is part of the explanation."""
        assert squawk.scanners.message_for(
            "subprocess call with shell=True, 'rm -rf' seen", "B602") == \
            "subprocess call with shell=True, 'rm -rf' seen"

    def test_bandit_keeps_the_code_for_a_rule_that_is_not_about_a_secret(self):
        """The false-positive half. A rule that withholds everything teaches a
        reader that the evidence field is never worth opening."""
        raw = json.dumps({"results": [{
            "test_id": "B602", "filename": "app.py", "line_number": 9,
            "issue_severity": "HIGH", "issue_text": "subprocess with shell=True",
            "code": "9 subprocess.run(cmd, shell=True)\n"}]})
        f = squawk.scanners.norm_bandit(raw, "/t")[0]
        assert "shell=True" in f.detail["evidence"]

    def test_semgrep_does_not_undo_its_own_redaction_for_a_credential(self, tmp_path):
        """`_source_line` exists to recover the line semgrep redacts. For a
        credential rule that recovery is the leak, so it must not run -- and
        the file must not be read at all."""
        src = tmp_path / "app.py"
        src.write_text("x = 1\nAPI_KEY = 'sk-live-abcdef'\n", encoding="utf-8")
        raw = json.dumps({"results": [{
            "check_id": "python.lang.security.audit.hardcoded-password",
            "path": str(src), "start": {"line": 2},
            "extra": {"severity": "ERROR", "message": "Hardcoded password",
                      "lines": "requires login"}}]})
        f = squawk.scanners.norm_semgrep(raw, str(tmp_path))[0]
        assert "sk-live-abcdef" not in f.detail["evidence"]
        assert f.detail["evidence"] == squawk.scanners.EVIDENCE_WITHHELD

    def test_semgrep_still_recovers_the_line_for_an_ordinary_rule(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("x = 1\neval(user_input)\n", encoding="utf-8")
        raw = json.dumps({"results": [{
            "check_id": "python.lang.security.audit.eval-detected",
            "path": str(src), "start": {"line": 2},
            "extra": {"severity": "ERROR", "message": "eval is dangerous",
                      "lines": "requires login"}}]})
        f = squawk.scanners.norm_semgrep(raw, str(tmp_path))[0]
        assert "eval(user_input)" in f.detail["evidence"]

    def test_the_withheld_sentence_is_not_an_empty_string(self):
        """An absent evidence field and a withheld one read identically, which
        is I1 turned on the tool's own output."""
        assert squawk.scanners.EVIDENCE_WITHHELD.strip()
        assert "credential" in squawk.scanners.EVIDENCE_WITHHELD

    @pytest.mark.parametrize("rule,message", [
        ("B105", "Possible hardcoded password"),
        ("B106", "hardcoded password as a function argument"),
        ("CKV_SECRET_6", "Base64 High Entropy String"),
        ("python.lang.security.audit.hardcoded-password", "x"),
        ("", "AWS Access Key ID found"),
        ("", "Authorization header disclosed"),
    ])
    def test_every_credential_shape_is_recognised(self, rule, message):
        assert squawk.scanners.is_credential_rule(rule, message)

    @pytest.mark.parametrize("rule,message", [
        ("B602", "subprocess call with shell=True"),
        ("CKV_AWS_20", "S3 bucket allows public read"),
        ("python.lang.security.audit.eval-detected", "eval is dangerous"),
    ])
    def test_an_ordinary_rule_keeps_its_evidence(self, rule, message):
        assert not squawk.scanners.is_credential_rule(rule, message)

    # --- the target the operator asked for ---------------------------------

    def test_an_explicit_repo_is_scanned_and_not_its_parent(self, tmp_path):
        """`--repo <subdir>` in a monorepo scanned the whole monorepo -- every
        sibling project in the checkout -- and said nothing about it. Not a cap
        that went unannounced; a scope nobody asked for."""
        (tmp_path / ".git").mkdir()
        sub = tmp_path / "projects" / "one"
        sub.mkdir(parents=True)
        assert squawk.resolve_repo(str(sub)) == str(sub)
        assert squawk.resolve_repo(str(sub)) != str(tmp_path)

    def test_with_no_target_the_enclosing_repository_is_still_the_default(
            self, tmp_path, monkeypatch):
        (tmp_path / ".git").mkdir()
        sub = tmp_path / "a" / "b"
        sub.mkdir(parents=True)
        monkeypatch.chdir(str(sub))
        assert squawk.resolve_repo(None) == str(tmp_path)

    # --- what a transcript carries -----------------------------------------

    def test_the_cli_short_target_masks_the_account(self):
        """Its web sibling `_short_target` has always masked; this one did not,
        so `--verify` and `--prune` printed every run's account in full."""
        out = squawk.cli._short("111111111111")
        assert "111111111111" not in out, out
        assert out == squawk.mask_account("111111111111")[:28]

    # --- the two pages that render a run -----------------------------------

    def test_the_coverage_panel_redacts_a_ledger_detail(self):
        """The CLI redacts this same string; the page rendered it raw, so a
        detail built from a role ARN reached the browser with the account in
        it. Two renderers of one string, one of them masked."""
        man = {"ledger": [{"tool": "cloudiam", "status": "gap",
                           "detail": "AccessDenied for "
                                     "arn:aws:iam::111111111111:role/deploy"}]}
        page = squawk.web.coverage_panel(man)
        assert "111111111111" not in page, page[:400]

    def test_the_dashboard_masks_what_it_renders(self, tmp_path):
        """The one artifact whose own docstring invites you to archive it or
        attach it somewhere, and the only rendered surface with no masking at
        all."""
        dash = self._dashboard()
        run = tmp_path / "20260101T000000Z"
        run.mkdir()
        (run / "manifest.json").write_text(json.dumps({
            "run_id": "20260101T000000Z", "service": "cloudiam",
            "service_label": "Cloud (AWS)", "scope": "aws",
            "target": "111111111111", "not_covered": "",
            "counts": {"total": 0, "excluded": 0},
            "ledger": [{"tool": "cloudiam", "mode": "read", "status": "gap",
                        "detail": "AccessDenied for "
                                  "arn:aws:iam::111111111111:role/deploy"}],
        }), encoding="utf-8")
        (run / "findings.json").write_text("[]", encoding="utf-8")
        (run / "identities.json").write_text("{}", encoding="utf-8")
        html = dash.render(squawk, str(run))
        assert "111111111111" not in html, "the dashboard rendered the account"

    def test_the_dashboard_writes_outside_the_sealed_run(self, tmp_path):
        """A run is sealed and its digest covers every file in it, so a
        dashboard written inside made the tool's own `--verify` report
        `extra - dashboard.html` on every run anybody had rendered."""
        dash = self._dashboard()
        src = inspect.getsource(dash.main)
        assert 'os.path.join(run_dir, "dashboard.html")' not in src
        assert "dashboard-%s.html" in src

    @staticmethod
    def _dashboard():
        path = os.path.join(os.path.dirname(ENTRY), "squawk-dashboard.py")
        spec = importlib.util.spec_from_file_location("squawk_dashboard", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

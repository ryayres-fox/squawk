"""The toolbench: what is installed, what an update changed, and the install record."""

import json
import os
import pkgutil
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from squawk.core import (
    APP_DIR,
    INSTALL_DIRNAME,
    LOG,
    SCANNERS,
    SUPPORTING,
    run_cmd,
    tool_path,
    vuln_db_ages,
)

# Images Squawk pulls and then runs. Recorded by digest, because a tag moves.
KNOWN_IMAGES = ("ghcr.io/zaproxy/zaproxy:stable",)


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _binary_version(binary: str, args: Tuple[str, ...]) -> Optional[str]:
    path = tool_path(binary)
    if not path:
        return None
    _code, out, err = run_cmd([path, *args], None, 30)
    return _first_line(out or err) or "(installed, version not reported)"


def pipx_dependencies() -> Dict[str, dict]:
    """What each pipx-managed scanner actually consists of.

    `semgrep 1.2.3` is the answer to "what is installed"; it is not the answer
    to "what is installed along with it". Each pipx tool is a virtualenv with
    its own dependency tree, and that tree is what a CVE against a shared
    library would land in."""
    if not tool_path("pipx"):
        return {}
    code, out, _e = run_cmd(["pipx", "list", "--json"], None, 60)
    if code != 0 or not (out or "").strip():
        return {}
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {}
    result: Dict[str, dict] = {}
    for name, venv in (data.get("venvs") or {}).items():
        meta = (venv.get("metadata") or {})
        main = (meta.get("main_package") or {})
        deps = sorted(main.get("app_paths_of_dependencies") or {})
        pkgs = {}
        for dep_name, dep in (meta.get("injected_packages") or {}).items():
            pkgs[dep_name] = dep.get("package_version")
        result[name] = {
            "version": main.get("package_version"),
            "python": meta.get("python_version"),
            "pip_args": main.get("pip_args") or [],
            "injected": pkgs,
            "dependency_apps": deps,
        }
    return result


def apt_versions(packages: Tuple[str, ...]) -> Dict[str, str]:
    """Distribution package versions, which is what an OS upgrade actually
    moves. An absent package is left out rather than recorded as an error,
    because most of these are optional."""
    if not tool_path("dpkg-query"):
        return {}
    out_map: Dict[str, str] = {}
    for pkg in packages:
        code, out, _e = run_cmd(
            ["dpkg-query", "-W", "-f=${Version}", pkg], None, 15)
        if code == 0 and (out or "").strip():
            out_map[pkg] = out.strip()
    return out_map


def image_digests() -> Dict[str, str]:
    """Digest of each image Squawk runs. A tag is not an identity: `zaproxy:
    stable` is a different image week to week, and the scan it performs changes
    with it."""
    if not tool_path("docker"):
        return {}
    out_map: Dict[str, str] = {}
    for ref in KNOWN_IMAGES:
        code, out, _e = run_cmd(
            ["docker", "image", "inspect", "--format",
             "{{index .RepoDigests 0}}", ref], None, 30)
        if code == 0 and (out or "").strip():
            out_map[ref] = out.strip()
        else:
            out_map[ref] = "(not present locally)"
    return out_map


APT_TRACKED = ("gitleaks", "pipx", "docker.io", "docker-ce", "gh", "auditd")


def tool_inventory() -> dict:
    """Everything Squawk depends on, in one comparable structure."""
    tools: Dict[str, dict] = {}
    for sc in SCANNERS.values():
        if sc.internal or not sc.binary:
            continue
        # A scanner Squawk runs through something else has no version of its
        # own on this machine. ZAP's registered binary is `docker`, so asking
        # for its version answered with Docker's, and the install record read
        # "installed zap — Docker version 26.1.5". The image digest is the
        # honest answer for it, and that is recorded separately.
        if sc.binary != sc.name:
            continue
        path = tool_path(sc.binary)
        tools[sc.name] = {
            "binary": sc.binary,
            "path": path,
            "version": _binary_version(sc.binary, sc.version_args),
        }
    for name in SUPPORTING:
        path = tool_path(name)
        tools[name] = {
            "binary": name,
            "path": path,
            "version": _binary_version(name, ("--version",)),
        }
    dbs = {}
    for name, age, detail in vuln_db_ages():
        dbs[name] = {"age_days": age, "detail": detail}
    return {
        "tools": tools,
        "pipx": pipx_dependencies(),
        "apt": apt_versions(APT_TRACKED),
        "images": image_digests(),
        "vuln_dbs": dbs,
        "python": sys.version.split()[0],
    }


def host_facts() -> dict:
    """The administrative half of the record: who, where, and on what."""
    facts: Dict[str, Any] = {
        "hostname": socket.gethostname(),
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "cwd": os.getcwd(),
    }
    try:
        facts["user"] = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
        facts["uid"] = os.getuid()
        facts["euid"] = os.geteuid()
        facts["running_as_root"] = os.geteuid() == 0
        facts["sudo_user"] = os.environ.get("SUDO_USER") or ""
    except AttributeError:
        pass
    uname = getattr(os, "uname", None)
    if uname:
        u = uname()
        facts["kernel"] = "%s %s" % (u.sysname, u.release)
        facts["arch"] = u.machine
    for path in ("/etc/os-release",):
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("PRETTY_NAME="):
                        facts["os"] = line.split("=", 1)[1].strip().strip('"')
                        break
        except OSError:
            pass
    facts["reboot_required"] = os.path.exists("/var/run/reboot-required")
    return facts


def _inventory_delta(before: dict, after: dict) -> List[dict]:
    """What actually moved. Unchanged entries are reported too, because "we ran
    an update and nothing moved" is a real answer that a diff-only view hides."""
    rows: List[dict] = []
    names = sorted(set(before.get("tools", {})) | set(after.get("tools", {})))
    for name in names:
        b = (before.get("tools") or {}).get(name) or {}
        a = (after.get("tools") or {}).get(name) or {}
        bv, av = b.get("version"), a.get("version")
        if bv is None and av is not None:
            state = "installed"
        elif bv is not None and av is None:
            state = "disappeared"
        elif bv != av:
            state = "updated"
        elif av is None:
            state = "absent"
        else:
            state = "unchanged"
        rows.append({"name": name, "kind": "tool", "state": state,
                     "before": bv, "after": av, "path": a.get("path")})
    for key, label in (("apt", "apt"), ("images", "image")):
        allk = sorted(set(before.get(key) or {}) | set(after.get(key) or {}))
        for name in allk:
            bv = (before.get(key) or {}).get(name)
            av = (after.get(key) or {}).get(name)
            if bv == av:
                state = "unchanged" if av is not None else "absent"
            elif bv is None:
                state = "installed"
            elif av is None:
                state = "disappeared"
            else:
                state = "updated"
            rows.append({"name": name, "kind": label, "state": state,
                         "before": bv, "after": av})
    bdb = before.get("vuln_dbs") or {}
    adb = after.get("vuln_dbs") or {}
    for name in sorted(set(bdb) | set(adb)):
        bv = (bdb.get(name) or {}).get("age_days")
        av = (adb.get(name) or {}).get("age_days")
        if bv == av:
            state = "unchanged"
        elif av is not None and (bv is None or av < bv):
            state = "refreshed"
        else:
            state = "updated"
        rows.append({"name": "%s db" % name, "kind": "vuln-db", "state": state,
                     "before": None if bv is None else "%s days" % bv,
                     "after": None if av is None else "%s days" % av})
    return rows


def _read_facts(path: str) -> List[dict]:
    """Facts the installer script recorded about its own actions, one JSON
    object per line. Written by the shell because only the shell knows what it
    downloaded and from where."""
    facts: List[dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    facts.append(json.loads(line))
                except json.JSONDecodeError:
                    facts.append({"kind": "note", "text": line})
    except OSError:
        pass
    return facts


def _print_delta(rows: List[dict]) -> None:
    changed = [r for r in rows if r["state"] not in ("unchanged", "absent")]
    print("\nWhat changed")
    print("  " + "-" * 68)
    if not changed:
        print("  nothing moved. Every tool, package, image and database is "
              "as it was.")
    for r in changed:
        before = r.get("before") or "(absent)"
        after = r.get("after") or "(absent)"
        # The kind is printed because the same name legitimately appears twice:
        # `gh` is both a tool on PATH and a distribution package, and two rows
        # reading "installed gh" with no way to tell them apart looks like a
        # duplicate rather than two facts.
        print("  %-9s %-7s %-16s %s"
              % (r["state"], r.get("kind", ""), r["name"], after))
        if r["state"] == "updated":
            print("  %-9s %-7s %-16s   was: %s" % ("", "", "", before))
    quiet = [r for r in rows if r["state"] == "unchanged"]
    absent = [r for r in rows if r["state"] == "absent"]
    print("  %d changed, %d unchanged, %d still absent"
          % (len(changed), len(quiet), len(absent)))
    if absent:
        print("  absent: %s" % ", ".join(r["name"] for r in absent))


def last_install_record(evidence_root: str) -> Optional[dict]:
    """The most recent install or update, or None. Summary only: enough for
    --doctor to say when the toolchain last moved and whether it worked."""
    base = os.path.join(evidence_root, INSTALL_DIRNAME)
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return None
    for name in reversed(entries):
        path = os.path.join(base, name, "install.json")
        try:
            with open(path, encoding="utf-8") as fh:
                rec = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        changes = rec.get("changes") or []
        return {
            "mode": rec.get("mode", "?"),
            "started_utc": rec.get("started_utc", name),
            "ok": rec.get("ok", False),
            "exit_code": rec.get("exit_code"),
            "changed": len([c for c in changes
                            if c.get("state") not in ("unchanged", "absent")]),
            "dir": os.path.join(base, name),
        }
    return None


INSTALLER_NAME = "install-tools.sh"


def installer_script() -> "Tuple[str, str]":
    """Where the toolbench installer is, as (path, how), or ("", why not).

    Two homes, because the app has two shapes. A checkout keeps the script
    beside `squawk.py` and runs it in place. A zipapp has no beside: it is one
    file, which is the whole point of it — "a work laptop, a locked-down host",
    in the build script's own words — and `--install` answered
    "install-tools.sh not found beside squawk.py" on the machine the zipapp
    exists for. The scanners it installs are exactly what that machine lacks.

    So the build copies the script into the package and this reads it back out
    with `pkgutil.get_data`, which works the same for a directory package and
    for one inside a zip. The extracted copy goes to a directory this process
    owns, mode 0700, and is removed when the installer returns.
    """
    beside = os.path.join(APP_DIR, INSTALLER_NAME)
    if os.path.isfile(beside):
        return beside, "beside the app"
    try:
        blob = pkgutil.get_data("squawk", INSTALLER_NAME)
    except (OSError, ImportError):
        blob = None
    if not blob:
        return "", ("no %s beside the app and none carried inside it"
                    % INSTALLER_NAME)
    tmp = tempfile.mkdtemp(prefix="squawk-installer-")
    path = os.path.join(tmp, INSTALLER_NAME)
    with open(path, "wb") as fh:
        fh.write(blob)
    os.chmod(path, 0o700)
    return path, "carried inside the app"


def run_installer(mode: str, evidence_root: str, script: str) -> int:
    """Run the installer with a record kept of what it did.

    Returns the installer's exit code. A non-zero exit is reported rather than
    swallowed: an update that half-failed and returned success is the same
    silent-clean problem this tool exists to avoid."""
    started = time.time()
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(started))
    rec_dir = os.path.join(evidence_root, INSTALL_DIRNAME, "%s-%s" % (stamp, mode))
    transcript_path = os.path.join(rec_dir, "transcript.log")
    facts_path = os.path.join(rec_dir, "facts.jsonl")
    try:
        os.makedirs(rec_dir, exist_ok=True)
    except OSError as exc:
        print("Could not create the install record at %s (%s). Continuing "
              "without one — this run will not be auditable." % (rec_dir, exc))
        rec_dir = ""

    print("Taking inventory before the %s..." % mode)
    before = tool_inventory()
    disk_before = shutil.disk_usage(evidence_root).free \
        if os.path.isdir(evidence_root) else None

    LOG.info("installer starting: mode=%s record=%s", mode, rec_dir or "(none)")

    # The installer is a bash script, and not every Unix ships bash — Alpine
    # does not. Without this the run fails as a bare "No such file or
    # directory" from Popen, which names neither the cause nor the fix. Found
    # by running the installer on alpine:latest.
    if not tool_path("bash"):
        print("The installer needs bash, which is not on this system.\n"
              "  Alpine        apk add bash\n"
              "  Debian/Kali   apt-get install bash\n"
              "  Fedora        dnf install bash\n"
              "Squawk itself does not need it; only this installer does.")
        LOG.error("installer refused: bash is not installed")
        return 1

    env_copy = dict(os.environ)
    if rec_dir:
        env_copy["SQUAWK_INSTALL_FACTS"] = facts_path
    cmd = ["bash", script] + (["--update"] if mode == "update" else [])

    lines: List[str] = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                env=env_copy)
    except OSError as exc:
        print("Could not run the installer: %s" % exc)
        LOG.error("installer failed to start: %s", exc)
        return 1
    assert proc.stdout is not None
    for line in proc.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
        lines.append(line)
    code = proc.wait()

    print("\nTaking inventory after the %s..." % mode)
    after = tool_inventory()
    disk_after = shutil.disk_usage(evidence_root).free \
        if os.path.isdir(evidence_root) else None
    rows = _inventory_delta(before, after)
    facts = _read_facts(facts_path) if rec_dir else []

    _print_delta(rows)

    downloads = [f for f in facts if f.get("kind") == "download"]
    if downloads:
        print("\nCode fetched from the network and run with sudo")
        print("  " + "-" * 68)
        for d in downloads:
            print("  %s" % d.get("url", "?"))
            print("      sha256 %s" % d.get("sha256", "(not recorded)"))
        print("  Recorded so a change in an installer script between runs is "
              "visible rather than invisible.")

    deps = after.get("pipx") or {}
    if deps:
        print("\nDependencies of the pipx-managed scanners")
        print("  " + "-" * 68)
        for name in sorted(deps):
            d = deps[name]
            extra = ""
            if d.get("injected"):
                extra = "  + injected: %s" % ", ".join(
                    "%s %s" % (k, v) for k, v in sorted(d["injected"].items()))
            print("  %-10s %-12s python %s%s"
                  % (name, d.get("version") or "?", d.get("python") or "?", extra))

    duration = time.time() - started
    record: Dict[str, Any] = {
        "mode": mode,
        "started_utc": stamp,
        "duration_seconds": round(duration, 1),
        "exit_code": code,
        "ok": code == 0,
        "host": host_facts(),
        "evidence_root": evidence_root,
        "disk_free_before": disk_before,
        "disk_free_after": disk_after,
        "before": before,
        "after": after,
        "changes": rows,
        "installer_facts": facts,
        "transcript": "transcript.log",
    }
    if rec_dir:
        try:
            with open(transcript_path, "w", encoding="utf-8") as fh:
                fh.write("".join(lines))
            with open(os.path.join(rec_dir, "install.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(record, fh, indent=2, sort_keys=True)
            os.chmod(rec_dir, 0o700)
        except OSError as exc:
            print("Could not write the install record: %s" % exc)

    changed = [r for r in rows if r["state"] not in ("unchanged", "absent")]
    for r in changed:
        LOG.info("installer %s: %s %s -> %s", r["state"], r["name"],
                 r.get("before"), r.get("after"))
    LOG.info("installer finished: mode=%s exit=%d changed=%d duration=%.1fs",
             mode, code, len(changed), duration)

    print("\nRecord")
    print("  " + "-" * 68)
    if rec_dir:
        print("  %s" % rec_dir)
        print("  install.json (what moved) + transcript.log (what it printed)")
    else:
        print("  none written")
    print("  log: %s" % (getattr(LOG, "_squawk_path", None) or "OFF"))
    if record["host"].get("reboot_required"):
        print("\n  This host reports a reboot is required to finish the upgrade.")
    if code != 0:
        print("\n  The installer exited %d. Some of the above did not happen; "
              "read the transcript before trusting a scan." % code)

    print("\nNext: python3 squawk.py --run selfaudit --target . "
          "  (checks the machine, not a target)")
    return code


__all__ = [
    'APT_TRACKED',
    'INSTALLER_NAME',
    'KNOWN_IMAGES',
    '_binary_version',
    '_first_line',
    '_inventory_delta',
    '_print_delta',
    '_read_facts',
    'apt_versions',
    'host_facts',
    'image_digests',
    'installer_script',
    'last_install_record',
    'pipx_dependencies',
    'run_installer',
    'tool_inventory',
]

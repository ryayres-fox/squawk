#!/usr/bin/env python3
"""Squawk — the lab: targets with known answers.

A scanner with no target it is known to find something in is a scanner nobody
can say ran right. This brings up the container targets, writes the file
corpora, and holds every service to the answer written beside its target —
as a shape (which rule ids appear, which must not), never an exact count that
the next scanner release would move.

    ./lab-targets.py up       start the container targets, creating them if absent
    ./lab-targets.py fresh    destroy and recreate them  <- before measuring anything
    ./lab-targets.py down     stop and remove them
    ./lab-targets.py status   what exists, and whether it answers
    ./lab-targets.py build    write the file corpora under ~/squawk-lab
    ./lab-targets.py check    run each service against its target; PASS, FAIL or SKIP
    ./lab-targets.py list     the targets and what each is expected to produce

`fresh` is the one to reach for before measuring. Juice Shop records solved
challenges, so a target you have been poking at is not the target you scanned
last week — the container equivalent of reverting a VM snapshot between runs.
Containers survive a reboot in Exited state and keep their names; `up` starts
them again, `fresh` replaces them.

`check` prints one line per assertion with the value it saw. A scanner that is
not installed makes its stage a gap, and every assertion that needed it is a
SKIP that names it — a skip is not a pass. Exit 0 only when nothing failed.

By default everything is loopback: the targets publish on 127.0.0.1 and the
checks look there. When the targets live on another machine — a separate
target machine — the two ends are told apart:

    ./lab-targets.py up --bind 0.0.0.0          on the target machine
    ./lab-targets.py check --host 10.56.0.18    on the machine running Squawk

`--bind` is where the containers publish; `--host` is where the checks look.

The cloud lab is the same idea against AWS: `dev/cloud-lab` plants a small,
deliberately weak estate in a dedicated test account, and

    ./lab-targets.py check --only cloud --aws-profile P --aws-account N --aws-lab L

holds each cloud stage to it. The account is checked before anything runs,
and a profile that resolves anywhere else stops the check. A stage the account
could not exercise is a SKIP that names why, which is how a release knows what
it may claim was validated.
They are separate flags because they run on separate machines, and each refuses
the verbs the other belongs to rather than being quietly ignored. Publishing
beyond loopback puts deliberately vulnerable applications on a network, so it
is never the default and it says so when it happens.

The corpora are written outside the repository (SQUAWK_LAB, default
~/squawk-lab), each as its own git checkout, so a scan of Squawk's tree does
not find the fixtures and a repo-scope service resolves to the corpus rather
than to the checkout that holds the lab.
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

# The checks live in `dev/`; the app is one directory up, at the root of
# the checkout.
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRY = os.path.join(HERE, "squawk.py")
LAB = os.path.expanduser(os.environ.get("SQUAWK_LAB", "~/squawk-lab"))

# --------------------------------------------------------------------------- #
# the container targets — published on 127.0.0.1 unless told otherwise, so by
# default each is reachable by Squawk on this box and by nothing else
# --------------------------------------------------------------------------- #

LOOPBACK = "127.0.0.1"
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                       r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def parse_bind(value: str) -> str:
    """An IPv4 address for `docker run -p` to publish on, and nothing else.

    It lands inside an argv element, so a value carrying a port, a path or a
    second flag is refused here rather than handed to docker to interpret.
    IPv4 only: it is what `-p` takes without brackets, and all a lab needs.
    """
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        raise argparse.ArgumentTypeError(
            "--bind takes an IPv4 address such as 0.0.0.0 or 10.56.0.18, not %r"
            % value) from None


def parse_host(value: str) -> str:
    """An address or hostname the checks connect to. It is put into a URL, so
    anything that is not one — a scheme, a path, a port, a space — is refused
    before it can become part of one."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if _HOSTNAME.match(value):
        return value
    raise argparse.ArgumentTypeError(
        "--host takes an address or a hostname such as 10.56.0.18, not %r" % value)


def netloc(host: str, port: int) -> str:
    """host:port for a URL or a log line; an IPv6 literal needs its brackets."""
    return ("[%s]:%d" if ":" in host else "%s:%d") % (host, port)


def target_url(t: dict, host: str) -> str:
    """The target a check hands to Squawk, pointed at `host`.

    Only the URL targets move. An image reference or a corpus path is not a
    place on the network, and rewriting one would be a silent change of what
    was scanned.
    """
    target = t.get("target") or ""
    if not t.get("needs_port") or not target.startswith(("http://", "https://")):
        return target
    parts = urllib.parse.urlsplit(target)
    return urllib.parse.urlunsplit(
        (parts.scheme, netloc(host, parts.port or t["needs_port"]),
         parts.path, parts.query, parts.fragment))

# name, host port, container port, image, environment
CONTAINERS: Tuple[Tuple[str, int, int, str, Dict[str, str]], ...] = (
    ("juice", 3000, 3000, "bkimminich/juice-shop", {}),
    ("dvwa", 8080, 80, "ghcr.io/digininja/dvwa:latest", {}),
    ("vampi", 5000, 5000, "erev0s/vampi", {"vulnerable": "1"}),
)


def run_args(c: Tuple[str, int, int, str, Dict[str, str]],
             bind: str = LOOPBACK) -> List[str]:
    """The `docker run` for one target. Loopback unless `bind` says otherwise."""
    name, host_port, container_port, image, environ = c
    argv = ["docker", "run", "-d", "--name", name,
            "-p", "%s:%d:%d" % (bind, host_port, container_port)]
    for key, value in sorted(environ.items()):
        argv += ["-e", "%s=%s" % (key, value)]
    return [*argv, image]


def _docker(*args: str) -> Tuple[int, str]:
    res = subprocess.run(["docker", *args], capture_output=True, text=True)
    return res.returncode, (res.stdout + res.stderr).strip()


def docker_problem() -> Optional[str]:
    """None when docker is usable; otherwise what to do about it."""
    try:
        code, out = _docker("info")
    except FileNotFoundError:
        return "docker not found"
    if code != 0:
        return ("the docker daemon is not responding — start it first:\n"
                "       sudo systemctl start docker\n       %s" % out.splitlines()[-1:])
    return None


def container_names(everything: bool = False) -> set:
    code, out = _docker("ps", *(["-a"] if everything else []), "--format", "{{.Names}}")
    return set(out.split()) if code == 0 else set()


def _port_open(port: int, host: str = LOOPBACK) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=1.5)
    except OSError:
        return False
    s.close()
    return True


def answers(port: int, host: str = LOOPBACK, timeout: float = 4.0) -> bool:
    """True when something HTTP is listening — any status counts, a redirect
    or a 404 is still a server."""
    try:
        urllib.request.urlopen("http://%s/" % netloc(host, port), timeout=timeout)
        return True
    except urllib.error.HTTPError:
        return True
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _say(mark: str, color: str, msg: str) -> None:
    print("  \033[%sm%s\033[0m   %s" % (color, mark, msg))


def wait_http(name: str, port: int, host: str = LOOPBACK, tries: int = 30) -> bool:
    where = netloc(host, port)
    for _ in range(tries):
        if answers(port, host):
            _say("ok", "32", "%s answering on %s" % (name, where))
            return True
        time.sleep(2)
    _say("!!", "31", "%s did not answer on %s within %ds — check: docker logs --tail 20 %s"
         % (name, where, tries * 2, name))
    return False


def reachable_from_here(bind: str) -> str:
    """Where `up` on this machine can see what it just published. 0.0.0.0 is every
    interface, which includes loopback; any other address is only itself."""
    return LOOPBACK if ipaddress.IPv4Address(bind).is_unspecified else bind


def cmd_up(fresh: bool = False, bind: str = LOOPBACK) -> int:
    problem = docker_problem()
    if problem:
        print(problem)
        return 2
    if bind != LOOPBACK:
        print("Publishing on %s, not loopback. These are deliberately vulnerable "
              "applications:\nanything that can reach %s can reach them. Do this on an "
              "isolated target machine,\nnot on a workstation. Containers created earlier keep "
              "the address they were\ncreated with — use `fresh` to republish them.\n"
              % (bind, bind))
    have, up = container_names(True), container_names()
    for c in CONTAINERS:
        name = c[0]
        if fresh:
            if name in have:
                _say("..", "36", "removing old %s" % name)
                _docker("rm", "-f", name)
            _say("..", "36", "creating %s" % name)
            code, out = _docker(*run_args(c, bind)[1:])
        elif name in up:
            _say("ok", "32", "%s already running" % name)
            continue
        elif name in have:
            _say("..", "36", "%s exists but is stopped — starting" % name)
            code, out = _docker("start", name)
        else:
            _say("..", "36", "%s absent — creating" % name)
            code, out = _docker(*run_args(c, bind)[1:])
        if code != 0:
            _say("!!", "31", "%s: %s" % (name, out.splitlines()[-1] if out else "docker failed"))
    here = reachable_from_here(bind)
    ready = all(wait_http(c[0], c[1], here) for c in CONTAINERS)
    if fresh and ready:
        print("\nTargets are at a known state. A scan from here is comparable with the last one.")
    return 0 if ready else 1


def cmd_down() -> int:
    problem = docker_problem()
    if problem:
        print(problem)
        return 2
    have = container_names(True)
    for c in CONTAINERS:
        if c[0] in have:
            _docker("rm", "-f", c[0])
            _say("ok", "32", "removed %s" % c[0])
        else:
            _say("ok", "32", "%s absent" % c[0])
    return 0


def cmd_status(host: str = LOOPBACK) -> int:
    problem = docker_problem()
    if problem:
        print(problem)
        return 2
    have = container_names(True)
    worst = 0
    for name, port, _cp, _img, _env in CONTAINERS:
        if name not in have:
            _say("!!", "31", "%-6s absent" % name)
            worst = 1
            continue
        _code, state = _docker("ps", "-a", "--filter", "name=^%s$" % name,
                               "--format", "{{.Status}}")
        if answers(port, host):
            _say("ok", "32", "%-6s %-24s answering on %s" % (name, state, netloc(host, port)))
        else:
            _say("!!", "31", "%-6s %-24s NOT answering on %s"
                 % (name, state, netloc(host, port)))
            worst = 1
    return worst


# --------------------------------------------------------------------------- #
# the file corpora — each file says up front what it is for
# --------------------------------------------------------------------------- #

DOCKERFILE_BAD = """\
# lab corpus: a Dockerfile built badly on purpose — root, :latest, curl | sh,
# ADD, port 22, no HEALTHCHECK. Squawk's compliance service must name these.
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
RUN curl -sSL https://example.invalid/install.sh | sh
ADD . /app
WORKDIR /app
EXPOSE 22
CMD ["python3", "app.py"]
"""

DOCKERFILE_GOOD = """\
# lab corpus: a Dockerfile built carefully — pinned base, non-root user, COPY of
# named files, HEALTHCHECK. None of the ids the bad one trips may appear here.
FROM python:3.12.6-slim
RUN groupadd -r app && useradd -r -g app app
WORKDIR /app
COPY app.py /app/app.py
USER app
HEALTHCHECK --interval=30s --timeout=3s CMD ["python3", "-c", "print('ok')"]
CMD ["python3", "app.py"]
"""

APP_PY = ("# lab corpus: one Python file with nothing wrong in it, so bandit and semgrep\n"
          "# have a file to examine and the run is complete rather than a gap\n"
          "print('hello from the lab corpus')\n")

K8S_BAD = """\
# lab corpus: a pod built badly on purpose — privileged, root, host network,
# a hostPath mount, no limits, :latest. Squawk's compliance service must name these.
apiVersion: v1
kind: Pod
metadata:
  name: lab-bad
spec:
  hostNetwork: true
  containers:
    - name: web
      image: nginx:latest
      securityContext:
        privileged: true
        runAsUser: 0
      volumeMounts:
        - name: host
          mountPath: /host
  volumes:
    - name: host
      hostPath:
        path: /
"""

K8S_GOOD = """\
# lab corpus: a pod built carefully — non-root, no privilege escalation, every
# capability dropped, read-only root, limits set, seccomp on, a pinned tag, its
# own namespace. None of the ids the bad one trips may appear here.
apiVersion: v1
kind: Pod
metadata:
  name: lab-good
  namespace: lab
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    runAsGroup: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: web
      image: nginx:1.27.1
      imagePullPolicy: Always
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 10001
        capabilities:
          drop: ["ALL"]
      resources:
        limits: {cpu: "250m", memory: "128Mi"}
        requests: {cpu: "100m", memory: "64Mi"}
      livenessProbe:
        httpGet: {path: /, port: 8080}
      readinessProbe:
        httpGet: {path: /, port: 8080}
"""

REQUIREMENTS = "# lab corpus: a dependency with published CVEs, pinned on purpose\nflask==0.12.2\n"

PACKAGE_JSON = json.dumps({
    "name": "lab-lockfile-corpus", "version": "1.0.0", "private": True,
    "description": "lab corpus: lodash 4.17.15 has published CVEs, pinned on purpose",
    "dependencies": {"lodash": "4.17.15"}}, indent=2) + "\n"

PACKAGE_LOCK = json.dumps({
    "name": "lab-lockfile-corpus", "version": "1.0.0", "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {"name": "lab-lockfile-corpus", "version": "1.0.0",
             "dependencies": {"lodash": "4.17.15"}},
        "node_modules/lodash": {
            "version": "4.17.15",
            "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"}}},
    indent=2) + "\n"

CORPORA: Dict[str, Dict[str, str]] = {
    "dockerfiles/bad": {"Dockerfile": DOCKERFILE_BAD, "app.py": APP_PY},
    "dockerfiles/good": {"Dockerfile": DOCKERFILE_GOOD, "app.py": APP_PY},
    "k8s/bad": {"pod.yaml": K8S_BAD},
    "k8s/good": {"pod.yaml": K8S_GOOD},
    "lockfiles": {"python/requirements.txt": REQUIREMENTS,
                  "python/app.py": APP_PY,
                  "node/package.json": PACKAGE_JSON,
                  "node/package-lock.json": PACKAGE_LOCK},
}


def build(lab: str = LAB) -> List[str]:
    """Write every corpus, each as a git checkout of its own. Returns the paths."""
    written = []
    for rel, files in CORPORA.items():
        d = os.path.join(lab, "corpora", rel)
        os.makedirs(d, exist_ok=True)
        for name, body in files.items():
            path = os.path.join(d, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
            written.append(path)
        if not os.path.isdir(os.path.join(d, ".git")):
            subprocess.run(["git", "init", "-q", d], check=False, capture_output=True)
    return written


# --------------------------------------------------------------------------- #
# the expected answers — shapes, by rule id, measured before they were written
# --------------------------------------------------------------------------- #

# Each row: the service, how to point it, and what its findings must and must
# not contain. A `must` list is satisfied by ANY of its ids (scanner releases
# rename rules — trivy's DS002 is DS-0002 now); a `must_not` list fails on any.
# An id matches a finding whose identity starts with it as a segment; an id
# ending in "-" or ":" is a prefix; "" is any finding at all.
TARGETS: List[dict] = [
    {"name": "Dockerfile, built badly", "corpus": "dockerfiles/bad",
     "service": "compliance", "flag": "--repo",
     "must": {"checkov": ["CKV_DOCKER_3", "CKV_DOCKER_2", "CKV_DOCKER_7"],
              "trivy": ["DS-0002", "DS-0001", "DS-0026", "DS002", "DS001", "DS026"]},
     "must_not": {}, "min_findings": 3,
     "why": "root, :latest, curl | sh, ADD, port 22, no HEALTHCHECK — both IaC scanners "
            "name them"},
    {"name": "Dockerfile, built carefully", "corpus": "dockerfiles/good",
     "service": "compliance", "flag": "--repo",
     "must": {},
     "must_not": {"checkov": ["CKV_DOCKER_3", "CKV_DOCKER_2", "CKV_DOCKER_7"],
                  "trivy": ["DS-0002", "DS-0001", "DS-0026", "DS002", "DS001", "DS026"]},
     "min_findings": 0,
     "why": "pinned base, USER, COPY, HEALTHCHECK — none of the bad one's ids appear"},
    {"name": "k8s pod, built badly", "corpus": "k8s/bad",
     "service": "compliance", "flag": "--repo",
     "must": {"checkov": ["CKV_K8S_16", "CKV_K8S_23", "CKV_K8S_19"],
              "trivy": ["KSV-0017", "KSV-0012", "KSV-0009", "KSV017", "KSV012", "KSV009"]},
     "must_not": {}, "min_findings": 5,
     "why": "privileged, root, hostNetwork, hostPath, no limits — both IaC scanners name them"},
    {"name": "k8s pod, built carefully", "corpus": "k8s/good",
     "service": "compliance", "flag": "--repo",
     "must": {},
     "must_not": {"checkov": ["CKV_K8S_16", "CKV_K8S_23", "CKV_K8S_19", "CKV_K8S_17"],
                  "trivy": ["KSV-0017", "KSV-0012", "KSV-0009", "KSV017", "KSV012", "KSV009"]},
     "min_findings": 0,
     "why": "non-root, no escalation, capabilities dropped, limits — none of the bad one's ids "
            "appear"},
    {"name": "lockfiles with published CVEs", "corpus": "lockfiles",
     "service": "baggage", "flag": "--target",
     "must": {"trivy": ["CVE-2018-1000656", "CVE-2019-1010083", "CVE-2020-8203",
                        "CVE-2021-23337", "CVE-2019-10744"],
              # grype names these by GHSA id (measured on Kali, 2026-09-07):
              # 562c = CVE-2018-1000656, 5wv5 = CVE-2019-1010083 (flask);
              # 35jh = CVE-2021-23337, 29mw = CVE-2020-28500 (lodash)
              "grype": ["CVE-2018-1000656", "CVE-2019-1010083", "CVE-2020-8203",
                        "CVE-2021-23337", "GHSA-562c-5r94-xh97", "GHSA-5wv5-4vpf-pj6m",
                        "GHSA-35jh-r3h4-6jhm", "GHSA-29mw-wpgm-hmr9"]},
     "must_not": {}, "min_findings": 2,
     "why": "flask 0.12.2 and lodash 4.17.15 — both CVE scanners find them; the differential "
            "stays silent"},
    {"name": "a vulnerable image", "corpus": None, "target": "bkimminich/juice-shop:latest",
     "service": "cargo", "flag": "--target",
     "must": {"trivy": ["CVE-"], "grype": ["CVE-", "GHSA-"]},
     "must_not": {}, "min_findings": 5,
     "why": "the Juice Shop image carries known npm CVEs; both CVE scanners find them; the "
            "differential stays silent"},
    {"name": "Juice Shop, discovered", "corpus": None, "target": "http://127.0.0.1:3000",
     "service": "recon", "flag": "--target", "needs_port": 3000,
     "must": {"recon": ["3000:/", "3000:catch-all"]},
     "must_not": {"recon": ["3000:/dvwa/", "3000:/phpMyAdmin/", "3000:/mutillidae/",
                            "3000:/twiki/", "3000:/webdav/"]},
     "min_findings": 1,
     "why": "recon finds the app on :3000 and, because it answers every path with the same page, "
            "reports the catch-all rather than DVWA, phpMyAdmin and TWiki at paths it does not "
            "serve"},
    {"name": "DVWA, discovered", "corpus": None, "target": "http://127.0.0.1:8080",
     "service": "recon", "flag": "--target", "needs_port": 8080,
     "must": {"recon": ["8080:/"]}, "must_not": {}, "min_findings": 1,
     "why": "recon finds DVWA on :8080 through its login redirect; no expected probe answer "
            "until a profile can log it in"},
    {"name": "VAmPI, discovered", "corpus": None, "target": "http://127.0.0.1:5000",
     "service": "recon", "flag": "--target", "needs_port": 5000,
     "must": {"recon": ["5000:/"]}, "must_not": {"recon": ["5000:catch-all"]},
     "min_findings": 1,
     "why": "recon finds the API on :5000; it answers unknown paths with 404, so no catch-all"},
    {"name": "VAmPI, probed", "corpus": None, "target": "http://127.0.0.1:5000",
     "service": "liveprobe", "flag": "--target", "needs_port": 5000,
     "must": {"zap": ["10036", "10021", "10049", "90004"]}, "must_not": {},
     "min_findings": 1, "urls_at_least": 2,
     "why": "the baseline probe reaches the API, names its header findings and reports the URL "
            "count"},
    # ---- the cloud lab ------------------------------------------------------
    # dev/cloud-lab plants these. Run only with --aws-profile, --aws-account and
    # --aws-lab; without them this is a SKIP that says so. `stages` maps each
    # cloud stage to the lab names its evidence must contain -- proof the probe
    # read what was planted, not merely that it ran. A stage whose ledger row
    # is not `ok` is a SKIP naming why: that is the list a release holds back.
    {"name": "The cloud lab, inventoried", "corpus": None, "target": None,
     "service": "cloudinventory", "flag": None, "cloud": True,
     "stages": {"cloudinv": ["-ssh-world"], "cloudenable": [],
                "cloudiam": ["-nomfa", "-escalates", "-auditor"],
                "cloudedge": ["-fn"], "cloudstore": ["-open", "-held"],
                "cloudcontain": ["-cluster"],
                "clouddata": ["-topic", "-queue", "-registry", "-placeholder"],
                "cloudorg": [], "cloudfront": ["-api", "-open"],
                "cloudanalyzer": ["-analyzer"]},
     # Every one of these must appear, not one of them: the lab planted each.
     # The trailing colon makes each a prefix of `domain:rule:resource`, and
     # keeps `bucket-public:` from matching `bucket-public-policy-blocked:`.
     "must_each": {"cloudstore": ["storage:bucket-public:",
                                  "storage:bucket-public-policy-blocked:"],
                   "cloudiam": ["iam:credential-without-mfa:"],
                   "cloudedge": ["edge:lambda-url-without-auth:"],
                   "cloudfront": ["frontdoor:api-open-to-the-internet:",
                                  "frontdoor:cloudfront-without-waf:",
                                  "frontdoor:cloudfront-plaintext-origin:"],
                   "clouddata": ["data:messaging-open-to-any-principal:",
                                 "data:registry-open-to-any-principal:"],
                   "cloudanalyzer": ["analyzer:analyzer-public:"]},
     # The escalation role is trusted by the account alone, so nothing may call
     # it reachable from outside. Silence here is part of the answer.
     "must": {}, "must_not": {"cloudiam": ["iam:escalation-reachable-from-outside:",
                                           "iam:administrative-reachable-from-outside:"]},
     "min_findings": 1,
     "why": "every planted weakness is named by the stage that reads it, and nothing the lab "
            "kept inside the account is called reachable from outside"},
    {"name": "The cloud lab, Security Hub", "corpus": None, "target": None,
     "service": "cloudaws", "flag": None, "cloud": True,
     "stages": {"awscli": []}, "must_each": {}, "must": {}, "must_not": {},
     "min_findings": 0,
     "why": "Security Hub is read when the lab turned it on (enable_securityhub); off, the "
            "stage is a gap and this is a SKIP, never a clean read"},
]

PASS = FAIL = SKIP = 0
FAILURES: List[str] = []


def ok(msg: str, detail: str = "") -> None:
    global PASS
    PASS += 1
    print("  \033[32mPASS\033[0m %s%s" % (msg, ("  ·  " + detail) if detail else ""))


def bad(msg: str, detail: str = "") -> None:
    global FAIL
    FAIL += 1
    FAILURES.append("%s%s" % (msg, ("  ·  " + detail) if detail else ""))
    print("  \033[31mFAIL\033[0m %s%s" % (msg, ("  ·  " + detail) if detail else ""))


def skip(msg: str, why: str) -> None:
    global SKIP
    SKIP += 1
    print("  \033[33mSKIP\033[0m %s  ·  %s" % (msg, why))


def check(msg: str, condition: bool, detail: str = "") -> bool:
    (ok if condition else bad)(msg, detail)
    return bool(condition)


def section(title: str) -> None:
    print("\n\033[1m%s\033[0m" % title)


def _match(ident: str, want: str) -> bool:
    if want == "":
        return True
    if want[-1] in ":-":
        return ident.startswith(want)
    return ident == want or ident.split(":", 1)[0] == want


def _hit(ids: set, wanted: List[str]) -> bool:
    return any(_match(i, w) for w in wanted for i in ids)


def _run(service: str, flag: Optional[str], target: Optional[str], ev: str,
         env: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
    argv = [sys.executable, ENTRY, "run", service]
    if flag:
        argv += [flag, str(target)]
    res = subprocess.run([*argv, "--evidence", ev], capture_output=True, text=True,
                         timeout=7200, env=env)
    time.sleep(1.1)   # run ids are second-resolution
    return res.returncode, res.stdout + res.stderr


def _newest_run(ev: str) -> Tuple[Optional[str], Optional[dict], Optional[list]]:
    runs = sorted(n for n in os.listdir(ev)
                  if os.path.isdir(os.path.join(ev, n)) and n[:2].isdigit())
    if not runs:
        return None, None, None
    d = os.path.join(ev, runs[-1])
    try:
        with open(os.path.join(d, "manifest.json"), encoding="utf-8") as fh:
            man = json.load(fh)
        with open(os.path.join(d, "findings.json"), encoding="utf-8") as fh:
            finds = json.load(fh)
    except (OSError, ValueError):
        return d, None, None
    return d, man, finds


def _ids(finds: list, scanner: str) -> set:
    return {str(f.get("identity", "")) for f in finds if f.get("scanner") == scanner}


def check_target(t: dict, lab: str, ev: str, host: str = LOOPBACK) -> None:
    section("%s — %s" % (t["name"], t["why"]))
    if t.get("needs_port") and not _port_open(t["needs_port"], host):
        skip("the target answers on %s" % netloc(host, t["needs_port"]),
             "nothing is listening — run `./lab-targets.py up` first"
             + ("" if host == LOOPBACK else
                ", with --bind, on the machine at %s" % host))
        return
    target = target_url(t, host) or os.path.join(lab, "corpora", t["corpus"])
    if t.get("corpus") and not os.path.isdir(target):
        skip("the corpus exists", "%s is missing — run `./lab-targets.py build`" % target)
        return
    rc, _out = _run(t["service"], t["flag"], target, ev)
    d, man, finds = _newest_run(ev)
    if not check("%s runs and writes a manifest" % t["service"],
                 rc == 0 and man is not None and finds is not None,
                 "rc=%d %s" % (rc, d or "no run")):
        return
    assert man is not None and finds is not None
    ledger = {r["tool"]: r for r in man.get("ledger", [])}
    gaps = {tool: r.get("detail", "") for tool, r in ledger.items()
            if r.get("status") in ("gap", "error", "skipped")}
    for scanner, wanted in t["must"].items():
        label = "%s names one of %s" % (scanner, ", ".join(w or "anything" for w in wanted))
        ids = _ids(finds, scanner)
        if scanner in gaps and not ids:
            skip(label, "%s could not look: %s" % (scanner, gaps[scanner]))
            continue
        check(label, _hit(ids, wanted),
              "%d finding(s): %s" % (len(ids), ", ".join(sorted(ids)[:4]) or "none"))
    for scanner, banned in t["must_not"].items():
        label = "%s names none of %s" % (scanner, ", ".join(banned))
        ids = _ids(finds, scanner)
        if scanner in gaps:
            skip(label, "%s could not look: %s" % (scanner, gaps[scanner]))
            continue
        hits = sorted(i for i in ids if _hit({i}, banned))
        check(label, not hits,
              "found %s" % ", ".join(hits) if hits else "%d other finding(s)" % len(ids))
    if t["min_findings"]:
        total = len(finds)
        if total < t["min_findings"] and gaps:
            skip("at least %d finding(s)" % t["min_findings"],
                 "%d, and a stage could not look: %s"
                 % (total, "; ".join("%s (%s)" % kv for kv in gaps.items())))
        else:
            check("at least %d finding(s)" % t["min_findings"],
                  total >= t["min_findings"], "%d" % total)
    if "trivy" in ledger and "grype" in ledger:
        diff = man.get("differential") or []
        if "trivy" in gaps or "grype" in gaps:
            skip("the trivy/grype differential stays silent",
                 "one side could not look: %s"
                 % ", ".join(s for s in ("trivy", "grype") if s in gaps))
        else:
            check("the trivy/grype differential stays silent", not diff,
                  "; ".join(str(x.get("note", "")) for x in diff) if diff else "silent")
    if t.get("urls_at_least"):
        row = ledger.get("zap", {})
        cov = row.get("coverage") or {}
        n = cov.get("examined")
        if row.get("status") in ("gap", "error", "skipped"):
            skip("the probe reports a URL count", "zap could not look: %s" % row.get("detail"))
        else:
            check("the probe reports a URL count of at least %d" % t["urls_at_least"],
                  isinstance(n, int) and n >= t["urls_at_least"],
                  "%s %s" % (n, cov.get("unit", "")))


# --------------------------------------------------------------------------- #
# the cloud lab
# --------------------------------------------------------------------------- #

# What each cloud stage did on the account, for the validation report: a
# release may claim only the stages that are `validated` here.
CLOUD_RESULTS: List[Tuple[str, str, str]] = []

_PROFILE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
_LAB = re.compile(r"^[a-z0-9][a-z0-9-]{2,40}$")


def parse_account(value: str) -> str:
    """Twelve digits. It is compared, never interpolated, but a value that is
    not an account id is a typo the check should name rather than run with."""
    if not re.fullmatch(r"[0-9]{12}", value or ""):
        raise argparse.ArgumentTypeError("--aws-account is a twelve-digit account id")
    return value


def parse_profile(value: str) -> str:
    if not _PROFILE.match(value or ""):
        raise argparse.ArgumentTypeError("--aws-profile is a profile name from ~/.aws/config")
    return value


def parse_lab(value: str) -> str:
    """The lab's name prefix, as Terraform printed it (`lab_name`)."""
    if not _LAB.match(value or ""):
        raise argparse.ArgumentTypeError("--aws-lab is the lab_name output, e.g. squawk-lab-1a2b3c")
    return value


def masked(account: str) -> str:
    return "********" + account[-4:] if len(account) == 12 else "(unknown)"


def aws_account_of(profile: str) -> Tuple[Optional[str], str]:
    """The account a profile resolves to, asked of AWS itself. Credentials
    stay with the CLI: nothing here reads, holds or passes one."""
    try:
        res = subprocess.run(["aws", "sts", "get-caller-identity", "--profile", profile,
                              "--output", "json"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)[:200]
    if res.returncode != 0:
        lines = res.stderr.strip().splitlines()
        return None, (lines[-1] if lines else "the call failed")[:200]
    try:
        return str(json.loads(res.stdout)["Account"]), ""
    except (ValueError, KeyError, TypeError):
        return None, "an answer with no account in it"


def cloud_env(profile: str) -> Dict[str, str]:
    """The run's environment: this profile and nothing that could override it.
    Keys in the environment outrank a profile in the CLI's chain, so a
    leftover AWS_ACCESS_KEY_ID would quietly read some other account."""
    env = dict(os.environ)
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
              "AWS_DEFAULT_PROFILE", "AWS_PROFILE"):
        env.pop(k, None)
    env["AWS_PROFILE"] = profile
    env["SQUAWK_CLOUD_ACK"] = "1"
    return env


def _raw_text(run_dir: str, row: dict) -> str:
    path = row.get("evidence") or ""
    if not path:
        return ""
    try:
        with open(os.path.join(run_dir, path), encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def check_cloud_target(t: dict, ev: str, aws: Optional[Dict[str, str]]) -> None:
    section("%s — %s" % (t["name"], t["why"]))
    if not aws:
        skip("the cloud lab was read",
             "no test account named — pass --aws-profile, --aws-account and --aws-lab "
             "(dev/cloud-lab/README.md)")
        for tool in t["stages"]:
            CLOUD_RESULTS.append((tool, "not run", "no test account named"))
        return
    rc, _out = _run(t["service"], None, None, ev, env=cloud_env(aws["profile"]))
    d, man, finds = _newest_run(ev)
    if not check("%s runs and writes a manifest" % t["service"],
                 rc == 0 and d is not None and man is not None and finds is not None,
                 "rc=%d %s" % (rc, d or "no run")):
        for tool in t["stages"]:
            CLOUD_RESULTS.append((tool, "failed", "the run did not complete (rc=%d)" % rc))
        return
    assert d is not None and man is not None and finds is not None
    ledger = {r.get("tool"): r for r in man.get("ledger", [])}
    usable = set()
    for tool, names in t["stages"].items():
        row = ledger.get(tool)
        if row is None:
            bad("%s is in the run" % tool, "the ledger has no row for it")
            CLOUD_RESULTS.append((tool, "failed", "no ledger row"))
            continue
        if row.get("status") != "ok":
            why = "%s: %s" % (row.get("status"), row.get("detail") or "no detail")
            skip("%s was exercised on this account" % tool,
                 "%s — not validated here, so a release holds it back" % why)
            CLOUD_RESULTS.append((tool, "not exercised", why))
            continue
        raw = _raw_text(d, row)
        missing = [aws["lab"] + n for n in names if aws["lab"] + n not in raw]
        if check("%s read what the lab planted" % tool, not missing,
                 "missing from its evidence: %s" % ", ".join(missing) if missing
                 else ", ".join(aws["lab"] + n for n in names) or "nothing to plant"):
            usable.add(tool)
        else:
            CLOUD_RESULTS.append((tool, "failed", "evidence does not name %s" % ", ".join(missing)))
    for tool, wanted in t.get("must_each", {}).items():
        if tool not in usable:
            continue                          # already a SKIP or a FAIL above
        ids = _ids(finds, tool)
        for w in wanted:
            if not check("%s names %s" % (tool, w), _hit(ids, [w]),
                         "%d finding(s): %s" % (len(ids), ", ".join(sorted(ids)[:4]) or "none")):
                usable.discard(tool)
                CLOUD_RESULTS.append((tool, "failed", "did not name %s" % w))
    for tool, banned in t.get("must_not", {}).items():
        if tool not in usable:
            continue
        hits = sorted(i for i in _ids(finds, tool) if _hit({i}, banned))
        if not check("%s names none of %s" % (tool, ", ".join(banned)), not hits,
                     "found %s" % ", ".join(hits) if hits else "none"):
            usable.discard(tool)
            CLOUD_RESULTS.append((tool, "failed", "named %s" % ", ".join(hits)))
    for tool in t["stages"]:
        if tool in usable:
            CLOUD_RESULTS.append((tool, "validated", "read the lab and named what it planted"))


def write_cloud_report(path: str, account: str) -> None:
    """The record a release reads to decide what it may ship."""
    lines = ["# Cloud validation", "",
             "Run %s against test account %s." % (time.strftime("%Y-%m-%d %H:%M"),
                                                  masked(account)),
             "A stage ships only if it is `validated` here.", "",
             "| stage | result | detail |", "|---|---|---|"]
    for tool, result, detail in CLOUD_RESULTS:
        lines.append("| %s | %s | %s |" % (tool, result, detail.replace("|", "/")))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def cmd_check(args: argparse.Namespace) -> int:
    print("Squawk lab check · %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    print("corpora: %s" % os.path.join(args.lab, "corpora"))
    print("targets: %s" % args.host)
    aws = None
    if args.aws_profile:
        # Before anything runs, and for the whole check: the profile must
        # resolve to the account that was named. The lab is weak on purpose,
        # and the validator reads as whoever the profile is -- so the one
        # thing it must never do is read somewhere it was not pointed.
        got, why = aws_account_of(args.aws_profile)
        if got is None:
            print("Refusing the cloud check: profile %s did not resolve — %s"
                  % (args.aws_profile, why))
            return 2
        if got != args.aws_account:
            print("Refusing the cloud check: profile %s resolves to %s, not the test "
                  "account %s. Nothing was run." % (args.aws_profile, masked(got),
                                                     masked(args.aws_account)))
            return 2
        aws = {"profile": args.aws_profile, "account": args.aws_account, "lab": args.aws_lab}
        print("cloud: profile %s · account %s · lab %s"
              % (args.aws_profile, masked(args.aws_account), args.aws_lab))
    ev = args.evidence or tempfile.mkdtemp(prefix="squawk-lab-ev-")
    print("evidence: %s — kept; every line below is a real run" % ev)
    for t in TARGETS:
        if args.only and args.only not in t["name"] and args.only != t["service"]:
            continue
        if t.get("cloud"):
            check_cloud_target(t, ev, aws)
        else:
            check_target(t, args.lab, ev, args.host)
    if args.report:
        write_cloud_report(args.report, args.aws_account or "")
        print("cloud validation written to %s" % args.report)
    section("Result")
    print("  %d passed, %d failed, %d skipped" % (PASS, FAIL, SKIP))
    if FAILURES:
        print("\n  Paste these back:")
        for f in FAILURES:
            print("   - %s" % f)
    if SKIP:
        print("\n  A skip is a scanner that could not look or a target that was not up. "
              "It is not a pass.")
    return 1 if FAIL else 0


def cmd_build(args: argparse.Namespace) -> int:
    for p in build(args.lab):
        print("  wrote %s" % p)
    print("\n%d corpora under %s, each its own git checkout."
          % (len(CORPORA), os.path.join(args.lab, "corpora")))
    return 0


def cmd_list(_args: argparse.Namespace) -> int:
    print("%-8s %-6s %s" % ("target", "port", "image"))
    for name, port, _cp, image, _env in CONTAINERS:
        print("%-8s %-6d %s" % (name, port, image))
    print()
    print("%-30s %-11s %s" % ("check", "service", "expected"))
    for t in TARGETS:
        print("%-30s %-11s %s" % (t["name"], t["service"], t["why"]))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("verb", choices=["up", "fresh", "down", "status", "build", "check", "list"])
    ap.add_argument("--lab", default=LAB, help="where the corpora live (default %s)" % LAB)
    ap.add_argument("--evidence", help="evidence root for the check runs (default: a temp dir)")
    ap.add_argument("--only", help="check only the target whose name or service contains this")
    ap.add_argument("--bind", type=parse_bind,
                    help="up/fresh: publish the targets on this IPv4 address instead of "
                         "%s (0.0.0.0 for every interface)" % LOOPBACK)
    ap.add_argument("--host", type=parse_host,
                    help="status/check: look for the targets here instead of %s" % LOOPBACK)
    ap.add_argument("--aws-profile", type=parse_profile,
                    help="check: the read-only profile for the cloud lab's test account")
    ap.add_argument("--aws-account", type=parse_account,
                    help="check: the test account; the profile must resolve to it")
    ap.add_argument("--aws-lab", type=parse_lab,
                    help="check: the lab's name prefix (Terraform's lab_name output)")
    ap.add_argument("--report", help="check: write the cloud validation table here")
    args = ap.parse_args(argv)
    cloud = [args.aws_profile, args.aws_account, args.aws_lab]
    if any(cloud) and args.verb != "check":
        ap.error("--aws-profile, --aws-account and --aws-lab belong to `check`")
    if any(cloud) and not all(cloud):
        # Two of three would run against a profile with no account to hold it
        # to, or name an account and read as whoever the default chain is.
        ap.error("the cloud check needs all three: --aws-profile, --aws-account, --aws-lab")
    # Each flag belongs to one side. Accepting it on the other side and doing
    # nothing with it would let `check --bind 10.56.0.18` look at loopback and
    # report on whatever happens to be there.
    if args.bind is not None and args.verb not in ("up", "fresh"):
        ap.error("--bind is where `up` and `fresh` publish; for %s use --host" % args.verb)
    if args.host is not None and args.verb not in ("status", "check"):
        ap.error("--host is where `status` and `check` look; for %s use --bind" % args.verb)
    args.bind = args.bind or LOOPBACK
    args.host = args.host or LOOPBACK
    if args.verb == "up":
        return cmd_up(bind=args.bind)
    if args.verb == "fresh":
        return cmd_up(fresh=True, bind=args.bind)
    if args.verb == "down":
        return cmd_down()
    if args.verb == "status":
        return cmd_status(args.host)
    if args.verb == "build":
        return cmd_build(args)
    if args.verb == "list":
        return cmd_list(args)
    return cmd_check(args)


if __name__ == "__main__":
    sys.exit(main())

# Squawk

A local, single-user orchestrator for open-source security scanners. Point it at
a git repo, a directory, or a container image; it runs a chosen set of scanners,
normalizes their findings into one model with a stable per-finding identity, and
keeps every run as immutable evidence on disk so later runs can diff against it.

A small package beside one entry point, standard library only, no database,
no server to run, loopback-only.

**What this is for:** the instrument a security engineer carries into a new org —
code, running app, and cloud in one ranked, read-only assessment they can rerun to
prove things are getting fixed. See [`PRODUCT.md`](docs/PRODUCT.md) for the product
definition and the hard boundaries.

## Quick start

```bash
python3 squawk.py --install               # provision the scanner toolbench (Unix)
python3 squawk.py --update                 # OS, scanners, vuln DBs, ZAP image, and record what moved
python3 squawk.py --doctor                 # what's installed, what's missing, and the instrument check
python3 squawk.py --run selfaudit          # audit this machine, not a target
python3 squawk.py --list-services          # the thirteen services
python3 squawk.py --run compliance --repo /path/to/checkout
python3 squawk.py sarif > squawk.sarif        # the last run, as SARIF 2.1.0
```

`--doctor` exits non-zero on exactly two conditions: no scanner at all, or an
unwritable evidence root. Every other absence prints as a gap with a reason and
still exits 0, because it narrows what you can run rather than stopping you.

To stand it up on Kali against a containerized target end to end, meaning Docker,
the target, recon, DAST and the full scanner set, follow [`SETUP.md`](docs/SETUP.md).

### The instrument check

Findings are only worth what the machine producing them is worth. A finding
written to a world-readable directory has leaked. A timestamp from an
unsynchronised clock cannot order two runs. A scanner resolved through a
world-writable `PATH` entry is whatever the last writer wanted it to be. None of
that appears in a scan of the target, because none of it is wrong with the
target.

`--run selfaudit` checks the analysis host itself: logging on and rotating,
permissions on both the evidence root and the run directories inside it, free
space, whether the evidence root sits inside a git working tree, clock
synchronisation, the host's own audit trail, whether Squawk is running as root or
in the docker group, `PATH` and code integrity, and database freshness.
`--doctor` prints the summary and records it.

The number of checks is not fixed and the documentation does not claim one: some
depend on what is installed, since each vulnerability database present is its own
check, and the logging checks only exist once logging is up.

The denominator is published next to every count. A scanner reports what it
found; almost none reports what it *looked at*, and a zero over nothing examined
prints the same as a zero over a real tree. Squawk reads the coverage each
scanner already emits: semgrep's `paths.scanned`, bandit's per-file `metrics`,
checkov's `resource_count`, trivy's `Results` targets, syft's `artifacts`. It
shows the number inline. `0 findings across 214 files` is a clean scan; `0
findings, but examined 0 files` is a **gap**, not a pass, and it raises squawk
code 7600. A tool that publishes no coverage (gitleaks, grype) is reported
`unknown`, never a fabricated zero.

Correlation joins findings across scanners into toxic combinations: a public
bucket that is also unencrypted, or a secret in a tree that builds a container
image. The join is what a platform sells; the honest part, which no platform
shows, is that a combination a member scanner could not evaluate reports
`unknown` rather than silently not firing, so a toxic combination is never missed
because half of it was never looked for.

Scanner drift is checked the same way. A scanner changing its output is more
likely than a scanner breaking, and it used to be silent: rename a field, the
normalizer reads nothing, and the stage reports `0 findings` from a scan that ran
fine and produced data nobody could read. A report that does not look like a
report from that tool is now an error naming what it expected and what it saw.

Every check reports one of three states, and the third is the point. **`ok`** is
a verified pass, **`gap`** is a verified problem with a fix line, and **`not
determined`** is an admission: the honest answer where the probe does not exist,
which is never folded into a pass.

The first real run found a defect in Squawk itself: it was creating its own log
and evidence root with the default umask, leaving the record of every target
scanned readable by any other local user. Both are owner-only now.


### What an update records

`--update` takes an inventory before and after and writes it to
`~/scan-evidence/installs/<stamp>-update/`, alongside the installer's full
transcript. It reports what moved, what did not, and what is still absent; the
dependency tree behind each pipx-managed scanner, because `semgrep 1.2.3` does
not tell you what came with it; the digest of each container image, because a
tag is not an identity; and the sha256 of every vendor installer fetched over
the network before it runs as root.

That last one is not a safety guarantee. Hashing a script you are about to run
as root does not make it safe. It makes the thing that ran identifiable
afterwards, so a change between two runs is visible rather than invisible.

A failed step now exits non-zero. A half-finished update that reports success is
the same silent-clean problem the rest of the tool exists to avoid.

`--doctor` exits non-zero on exactly two conditions — no scanner at all, or an
unwritable evidence root. Every other absence prints as a gap with a reason and
still exits 0, because it narrows what you can run rather than stopping you.

To stand it up on Kali against a containerized target end to end — Docker, the
target, recon, DAST, and the full scanner set — follow [`SETUP.md`](docs/SETUP.md).

## Why "Squawk"

Aircraft squawk a transponder code when something is wrong, and the three
emergency codes map onto this tool almost exactly:

| Code | Aviation | Here |
|---|---|---|
| **7700** | general emergency | a critical exposure is live |
| **7600** | lost communications | a scanner or target went silent |
| **7500** | unlawful interference | evidence of an active attack |

**7600 is the one this tool is built around.** "Radio failure" is precisely the
governing rule: *a scanner that did not run must never look like a scanner that
found nothing.* A quiet run is not a clean run, and the alarm says so — a
scanner that reported last time and not this time raises 7600 rather than
letting the smaller number read as progress.

The rest of the vocabulary is the same airport. **Scan** is where a run starts,
and the thirteen services are **pre-flight check**, **customs manifest**,
**baggage check**, **contraband sweep**, **cargo scan**, **recon**, **live
probe**, **active probe**, **compliance**, **cloud (AWS)**, **self-audit** and
**skill audit**. Every one of them declares what it does *not* cover before you
read its result. (The Scan page was called the Kiosk until each service tile
became its own target picker; `squawk services` lists them.)


## Status

Rebuilt in iterations from a private handoff document, each verified before the next. The design record that came out of it is
[`DESIGN.md`](docs/DESIGN.md) and [`CHARTER.md`](docs/CHARTER.md); nothing here depends on the source material.

- **Iteration 1 — the engine (done).** `--doctor` preflight, the scanner registry
  and normalizers, the run pipeline, the evidence model (`manifest.json`,
  `.ledger.tsv`, `raw/` — a scanner's own report and, where it prints its
  coverage only to stdout, that too — `identities.json`, `digest.json` — which
  is written last and hashes all the rest, plus the run before it), stable identity keys,
  the contamination filter, and a headless `--run <service>`.
- **Iteration 2 — the loopback web UI (done).** Kiosk (pick a service + target,
  runs execute in a background thread and stream to a self-refreshing status
  page), Findings (the evidence table with the identity key on every row),
  History (per-scanner identity diff against the previous comparable run, where
  a scanner absent from either run reads *silent*, never *resolved*), and Posture
  (newest run per target, a 12-week strip where a week with no scan is a gap).
- **Iteration 3 — baselines, triage, and `squawk-dashboard.py` (done).**
  - *GitHub-issue baselines*: `--sync-baselines` (or the Baselines page) pulls
    issues titled "Local scan report" read-only via `gh`, parses the
    `## Diff baseline` table + `<details>` identity blocks, and caches under
    `<evidence>/.baselines/`. The **truncation guard** recomputes
    `sha256(sorted ids)[:16]` from what was actually parsed and only uses
    scanners whose hash reconciles — a deleted slice of a 4,000-identity set is
    rejected, never read as 1,150 fixes (tested). Counts-only issues are
    unusable, with the reason shown. The generator splits sets across comments
    (and within a scanner, labeled `part N of M`) to stay under GitHub's 65,536
    cap — and Squawk generates but **never posts**.
  - *Triage*: one row per **decision** (an advisory affecting four packages is
    one decision showing 4 items), `j/k/x/a/r/f/s/o/n` keyboard flow, every
    mark recorded in an append-only ledger in the evidence store (who, when,
    why, which identities) and shown on every later run of the target,
    baseline-matched findings hidden as already filed (with a show-anyway
    toggle), and Finish produces paste-ready markdown of that record.
  - *`squawk-dashboard.py`*: a static single-page render of one run. It imports
    its counting logic **from** `squawk.py` (same directory, refuses to run
    without it) so the identity keys, the contamination filter, and the
    fingerprint are defined once — its per-scanner fingerprint is byte-identical
    to the baseline table's, so you can eyeball one against the other.

- **Iteration 4 — the estate, and evidence you can prove (done).** Ten pages
  now, not four: **Overview** (newest run per target, every number a link),
  **Scan** (each service tile is its own picker), **Findings**, **Estate** (one
  row per `(scanner, rule)` across every live target, filtered, searched and
  paged, with every count stating what it is out of), **Priority** (ranked by
  exploitability, not severity), **Intel** (CISA KEV and EPSS with provenance,
  per-CVE detail from OSV and NVD, and general intel that does not depend on
  having scanned anything), **Triage**, **History**, **Cloud** (AWS Security Hub
  ingest, read-only), **Baselines**. Underneath: a real lifecycle (`status`,
  `stop`, `restart`, `--daemon`, `/healthz`, a generated systemd unit, aborted
  runs recorded), evidence retention with a dry run and a record of what went,
  and — as of plan 02 — a digest chain across runs, a hash chain in the
  decisions ledger and `squawk verify` to walk both. A run can be given a
  **profile** (`squawk.toml`): timing, budgets and scanner options per
  service, per target or per scanner, printed before the run, carried in the
  manifest, shown on the run page, and refused by name when a value is unsafe
  or unknown. The type checker is a gate: `mypy` 1.20.2 against the 3.9
  floor, zero errors, on every push.

Start the UI with no flag (or `--open` to launch a browser):

```bash
python3 squawk.py --repo /path/to/checkout        # serves http://127.0.0.1:8787/
```

## What makes it worth building next to DefectDojo

The category is not empty. [DefectDojo](https://www.defectdojo.org/) is the
open-source aggregator of record — 200+ scanner formats, dedupe, compliance
mapping — but it is a server plus a database, built for teams. **Hokage** and AWS
**ASH** orchestrate a similar scanner set. Squawk is deliberately a different
shape, and borrows the good ideas from all three:

| The platforms | Squawk |
|---|---|
| Server + database | Two stdlib files, no install |
| Team-scale | Single user, loopback-only, personal |
| Aggregate & dedupe | Aggregate **plus** correctness guarantees |
| CI / org pipeline | The tool you run on your own laptop, on your own checkout |

The correctness guarantees are the reason it exists:

- **Absence is a gap, not a pass.** A missing scanner is recorded with a reason;
  it never reads as a clean zero.
- **A lived-in tree is noisy.** The contamination filter drops `.terraform`,
  `.terraform.nosync`, `.venv*` and `.local-scans` from every count and shows the
  excluded total separately (the difference between a grype count of 12 and 1,270).
- **Stable identity.** A finding's identity carries no timestamp or absolute path,
  so two identical runs diff to nothing and a real change stands out.
- **Silent is not resolved** (from iteration 2): a scanner that did not run in
  both runs is reported silent, not fixed.

## The charter

The guarantees are the product; the scanners are commodity. So the rules are
written down as things a test can check rather than intentions to agree with:
[`CHARTER.md`](docs/CHARTER.md) holds seventeen invariants, and `test_charter.py`
fails when one is broken.

They are enforced across the registry rather than per feature, so a scanner
added later is checked automatically. A sample of what that catches: a scanner
registered without a normalizer, a stage no service offers, a service with no
coverage statement, a normalizer that raises on an unexpected report shape, a
finding identity carrying a timestamp or hostname, a built command containing a
destructive token, and a host check that reports a boolean where three states
are required.

Verified by breaking them on purpose: four deliberate violations produced five
test failures. A conformance suite that cannot fail is decoration.

## The direction

Squawk is built to grow into the widest local insight one machine can give —
beyond source and dependencies into **containers, builds, running apps, and
infrastructure**. The engine is registry-driven on purpose: a new scanner is an
entry in `SCANNERS` plus a normalizer, and a new service is an entry in
`SERVICES`. That is the seam every future capability plugs into.

Next up is **runtime testing**: DAST (OWASP ZAP) against an app running in a
VirtualBox VM, and standing containerized apps up under Docker locally to probe
them live. The full plan — scopes, safety rails, and setup notes — is in
[`ROADMAP.md`](docs/ROADMAP.md).

## Requirements and portability

Python 3.9+ (and 3.9-safe, no `X | Y` annotations). Scanners are optional and
discovered at runtime: `gitleaks`, `semgrep`, `bandit`, `checkov`, `trivy`,
`syft`, `grype`. Supporting: `git`, `docker`, `gh`. [`SETUP.md`](docs/SETUP.md) is
the install and first run, [`CLOUD-SETUP.md`](docs/CLOUD-SETUP.md) the AWS side, and
[`DESIGN.md`](docs/DESIGN.md) the reasoning behind each design choice.

**POSIX only.** Squawk is stdlib Python, but it is not portable to Windows and
is not tested there: it locks with `fcntl`, ends a runaway scanner by process
group with `os.killpg` and `SIGKILL`, and reads uid, gid and group membership
through `os` and `grp`. On Windows, use WSL2 — which is a Linux, and untested
here rather than known good. macOS, Kali, Debian, Ubuntu, Fedora, Alpine and
openSUSE are the ground it is built and run on: the six Linuxes are the
container matrix `test-matrix.sh` runs. Arch is in that matrix on request, and
only on amd64.

Two parts touch the operating system more than that: the installer and the host
self-audit.

The installer works out the package manager and how to escalate, so the same
script serves **apt** (Debian, Kali, Ubuntu), **dnf** and **yum** (Fedora, RHEL,
Rocky, Alma), **apk** (Alpine), **pacman** (Arch), **zypper** (openSUSE) and
**brew** (macOS). Distribution knowledge is confined to one table and one
dispatch; everything after it is shared. The heavy tools need no package manager
at all — syft, grype and trivy come from vendor installers, and semgrep, bandit
and checkov from pipx — so most of the toolbench lands even on a system it does
not recognise.

`./install-tools.sh --detect` reports what it would do on the current machine
and changes nothing. The answer to "what will this do to my system" should not
require running it on your system.

It needs `bash`, which Alpine does not ship. That is named with the per-platform
fix rather than failing as an unexplained `No such file or directory`.

### Verifying that claim

`./dev/test-matrix.sh` runs the detection and the host self-audit across container
images and reports a table. Portability asserted is not portability tested.

Currently passing 18 of 18 checks on `debian:stable-slim`, `ubuntu:24.04`,
`fedora:latest`, `alpine:latest`, `opensuse/tumbleweed` and
`kalilinux/kali-rolling`, plus `brew` detection on macOS. Arch is published for
amd64 only, so it is out of the default set on an arm64 host.

Containers are not virtual machines. They run as root, usually have no sudo and
have no systemd, which makes them a hostile environment for an installer — three
conditions that each broke the original script. What they cannot test is the
systemd side: `clock-sync` and `journal-persistent` answer *not determined*
there, and only a real VM makes them answer properly.

## Reporting something, and what is maintained

[`SECURITY.md`](SECURITY.md) is how to report a vulnerability — through GitHub's
private reporting, never a public issue. It also says what counts as one here,
including the case people do not expect: **a clean result Squawk did not earn.**
If you can make this tool print an empty finding list, a green stage or a zero
over something it did not read, that is a security report and it is the one most
wanted.

[`CONTRIBUTING.md`](CONTRIBUTING.md) is the gate a change passes and the six
questions a new capability answers. [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
is one paragraph.

**Maintenance is one person, best-effort**: security issues first, bugs triaged
as time allows, no commitment on feature requests. Pre-1.0, the newest release
is the only supported one and there are no backports. Written down so nobody has
to guess it.

## Development standard

Branches, code and PRs here are written to pass a peer-review standard,
summarised for a contributor in [`CONTRIBUTING.md`](CONTRIBUTING.md):
default-block posture, evidence for every claim, real tests, no secrets or wildcards, arg-list
subprocess calls, explicit error handling, and live-vs-source verification. See
[`PRODUCT.md`](docs/PRODUCT.md) for the credential-handling rules that gate every
future cloud and authenticated capability.

Live-vs-source verification has a script. `./dev/live-check.py` reads the route
table out of the handler, serves a daemon on a free port against a throwaway
evidence root, fetches every route it found, and fails on a non-200, a
traceback in a body or in the server log, or a server still listening after
stop. A route added to the handler is a route it fetches, so a page cannot be
added and never seen fail.

`./dev/kali-check.py` is the field check: 84 assertions over the lifecycle, the
subcommands, an aborted run, the decisions ledger, resolved and regressed
dates, a scanner going silent, the refusals and the empty-feed states, the
evidence chain and every way of editing it, `stop` killing a live ZAP
container, and a profile printed, applied and refused, each printing the
value it saw. It found two defects the first time it ran, which is
the argument for it. `./dev/smoke-test.sh` and `./dev/phase1-check.sh` are the other
half: the whole app against real code, because a fixture is the author's idea
of the format.

`./dev/lab-targets.py` is the lab: the container targets on loopback, the file corpora with a known answer each, and `check`, which holds every service to the answer written beside its target in [`TARGETS.md`](dev/TARGETS.md) — `PASS`, `FAIL` or `SKIP` per line with the value it saw, and a skip is never a pass.

## The documents, and which one answers what

Ten, which is enough to need an order. They answer different questions, and
where two of them disagree the one higher in this list wins.

| Read this | To answer |
|---|---|
| [`CHARTER.md`](docs/CHARTER.md) | What must stay true no matter what gets built. Seventeen invariants, each naming the test that fails when it is broken, and the six questions every new capability answers in its own commit. **Start here.** |
| [`PRODUCT.md`](docs/PRODUCT.md) | What this is, what it will never be, and the eight credential rules |
| [`DESIGN.md`](docs/DESIGN.md) | The seven experience pillars and the user journey: what must stay consistent on screen, with a checklist to hold each page against |
| [`ROADMAP.md`](docs/ROADMAP.md) | What gets built next, in what order, and how you know a phase is finished |
| [`CHANGELOG.md`](CHANGELOG.md) | What shipped, newest first |
| [`SETUP.md`](docs/SETUP.md) | Standing it up on Kali, with verify lines |
| [`TARGETS.md`](dev/TARGETS.md) | Sample targets with known properties, and how to verify a scan's output is what it should be |
| [`LAB-SETUP.md`](dev/LAB-SETUP.md) | The container lab on the Kali box, and the VM topology it replaced |
| [`CLOUD-SETUP.md`](docs/CLOUD-SETUP.md) | Reading AWS Security Hub for the first time, written for a machine you do not own — including what is safe to send back |
| [`CORRELATION-DESIGN.md`](docs/CORRELATION-DESIGN.md) | Phase 1.5 design: joining findings across layers, verified against real scanner output |

Both counts in this section were wrong here for weeks — it said nine documents
and thirteen invariants while listing eleven and enforcing sixteen. A number in
a document nobody recounts is the same defect as a scanner nobody checks, so if
you add a document or an invariant, fix the count in the same commit. Ten
documents and seventeen invariants as of 2026-09-18.

## Layout

The code is a package, `squawk/`, beside a thin entry point, `squawk.py`, so
`python3 squawk.py ...` works exactly as before. The modules are layered so that
each imports only from the ones above it:

| Module | What it holds |
|---|---|
| `core` | constants, logging, the finding model, the small helpers everything uses |
| `probes` | Squawk's own in-process probes: target recon, the skill audit, the host self-audit |
| `scanners` | reading each scanner's output: report shapes, coverage extractors, normalizers |
| `stages` | how each scanner is invoked; the stage and service registries; the safety rails |
| `evidence` | reading runs back from the evidence root; the remediation timeline (open, resolved, regressed); the per-run digest chain and what verifies it |
| `decisions` | triage decisions: an append-only ledger of who decided what, when and why, each line hashing the one before it |
| `analysis` | the differential, correlation, the squawk codes, the run score, the estate row model, the verify verdict |
| `engine` | running a service and writing its evidence |
| `feeds` | CISA KEV and EPSS, cached with provenance; per-CVE detail from OSV and NVD; the priority ranking |
| `installer` | the toolbench: what is installed, what an update changed |
| `baselines` | GitHub-issue baselines |
| `retention` | what evidence is kept, what is let go, and what is said about it |
| `runtime` | jobs in flight; the server's pid file |
| `sarif` | one run as SARIF 2.1.0: a stage that read nothing is an unsuccessful invocation carrying its denominator, and a correlation that could not be evaluated is a `notApplicable` result |
| `web` | every page, and the request handler |
| `service` | serve, daemonize, status, stop, the systemd unit |
| `cli` | the parser, the subcommands, `--doctor`, `--run`, `main()` |

Subcommands are the spelling going forward and the flags still work:
`python3 squawk.py run customs --target /path`, `doctor`, `serve --daemon`,
`status`, `stop`, `restart`, `feeds`, `update`, `install`, `services`,
`install-service`, `prune`, `verify`, `version`. `python3 -m squawk` works too, and
`./build-zipapp.sh` builds a one-file `dist/squawk.pyz` of the app.

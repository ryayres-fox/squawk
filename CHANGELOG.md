# Changelog

Dates are when the change merged to `main`.

This repository starts at its first public release. Squawk was developed in a
private repository before this one existed, and that history is not carried
over: the published record begins with this tree.

Everything here is tested against synthetic fixtures and against deliberately
vulnerable public targets — OWASP Juice Shop, DVWA and VAmPI.

**The cloud services are published ahead of their validation.** Their
validation against a dedicated test AWS account is in progress, using the lab
in [`dev/cloud-lab`](dev/cloud-lab/README.md), which plants a known weakness
for every cloud stage and checks that the stage names it. Until that report is
in, treat the two `aws` services as unvalidated; a stage that fails validation
is removed in a follow-up release rather than left in.

Where a decision looks arbitrary, one of four documents says why:
[`CHARTER.md`](docs/CHARTER.md) for the invariants,
[`PRODUCT.md`](docs/PRODUCT.md) for the boundaries and the credential rules,
[`DESIGN.md`](docs/DESIGN.md) for what must stay true on screen, and
[`CORRELATION-DESIGN.md`](docs/CORRELATION-DESIGN.md) for how findings are
joined across layers.

## Unreleased

## 0.12.0 — 2026-11-20

The first public release since 0.10.0; it includes everything below.

### nuclei, a known-vulnerability probe

- **`cveprobe` runs ProjectDiscovery's nuclei** against a running web app,
  behind the same private-target rail as the other DAST services. Only the
  `cve`, `misconfig` and `exposure` template tags, never `dos`, `fuzz` or
  `intrusive`; medium severity and up; no code, headless or fuzzing templates
  (switched off explicitly on the command line), nothing sent to an
  interaction server, no cloud upload. A nuclei configuration that turns any
  of those on is refused, with the key named.
- **The run states what it sent**: templates loaded, requests, errors and
  matches, from nuclei's own final stats line. What nuclei's own configuration
  and its `.nuclei-ignore` leave out is printed on the stage line and listed
  by `doctor`.
- **A finding says where, how serious and how to reproduce it**: the full URL,
  the template's CWE and CVSS score, the exact request nuclei sent, and the
  template's public page. A CVE template's finding is read as its CVE, so KEV,
  EPSS and the watchlist apply. Anything a template extracted (exposure
  templates can extract secrets) is withheld from the evidence; only a count
  is kept.
- **`install-tools.sh` installs nuclei** from its release zip, checked against
  the release's checksums, and fetches its templates.

### Reports and exports

- **The engineer report** lists each finding once with how often it was seen,
  and carries CWE, CVSS, references and a reproduction step for every scanner
  that supplies them.
- **SARIF** gives a web finding its full URL rather than a path a
  code-scanning tool would read as a repository file.

### Threat intel: a watchlist, the estate by weakness, and ATT&CK techniques

- **A CVE watchlist.** `squawk watch add CVE --reason TEXT`, `squawk watch
  remove CVE` and `squawk watch` keep a list of CVEs to flag whenever they
  appear. Each change is an append-only, chained line in the evidence root;
  `verify` checks the chain, and an edited line makes the verdict `failed`. The
  Intel page shows each watched CVE and the targets it is present in, or "not
  in what you have scanned" ("in this scope" under a filter). A bad id exits 2
  and writes nothing; a damaged line is reported wherever the list is read.
- **The estate by weakness.** The Intel page counts every CWE the live
  findings name, with MITRE's name and abstraction level for each, out of
  every finding, so a scanner that names none shows as a gap. A CWE comes from
  the finding itself (ZAP, Bandit, Semgrep) or, for a CVE, from its cached NVD
  record. `squawk feeds` now fetches MITRE's CWE catalogue with its URL, size
  and sha256.
- **ATT&CK techniques, derived and labelled.** `squawk feeds --attack`
  (opt-in, about 55 MB) fetches MITRE's CAPEC catalogue and Enterprise ATT&CK.
  Techniques are derived CWE to CAPEC to ATT&CK from MITRE's own links and the
  page says so: a row is MITRE's statement that the weakness is used in that
  technique, not an observed attack. Only Base and Variant CWEs are followed,
  because a Pillar such as CWE-693 maps to everything. Every finding is
  accounted for (derived, no CWE, only broad CWEs, no route in MITRE's data,
  or a CWE the catalogue does not list), and a technique ATT&CK has revoked or
  deprecated is named, never counted.
- **The conformance test for chained files** now finds every function that
  writes one and fails on any that `verify` does not walk.

### The clock wall is five clocks, one row

- **UTC, Los Angeles, Chicago, New York and London**, down from fifteen, plus
  the server's zone and the reader's when either is not one of them. Each clock
  has its own width, so a wide screen keeps them together, and the sticky
  offset below the strip follows its drawn height when it wraps.

## 0.10.0 — 2026-10-27

### Engagements, a pre-handover checklist, and reports you can hand over

- **Engagements.** The web UI groups the estate by engagement and scopes each
  page to one; an `engagements.json` maps targets to an engagement by glob
  without re-scanning. Remove an engagement (the runs stay, read as
  `Unassigned`) and hide a report (the runs stay) from the UI.
- **A pre-handover checklist.** A per-engagement manual-review signoff (OWASP
  WSTG / ASVS by default, overridable with `checklist.md`). Each tick is a
  sealed, chained ledger line that `verify` now checks, and "ready to hand over"
  turns green only when every item is `pass` or `N/A`.
- **Handover reports.** `report --share` writes an executive and an engineer
  report (Markdown, HTML, PDF), redacted at render time, the reviewer's findings
  and attacker abilities first, each image summarised by what it exposes. Every
  report carries remediation deadlines, and a sealed decision can close a finding.
- **A grep backup** for the checklist: a manual-review sweep grouped by the
  checklist's coverage areas, cross-language, high recall — a corroboration of
  the scanners and a lead where they are blind.

### Authenticated DAST, and more scanners

- **`authdast`** logs in to a running web app and tests the authenticated
  surface — including a login behind a per-request CSRF token (DVWA's
  `user_token`, Rails' `authenticity_token`, a Flask-WTF `csrf_token`).
  Credentials come from the environment, never argv, and the session is never
  written to disk.
- **An object-authorization (BOLA) probe**, **schemathesis** against a running
  API's OpenAPI schema, and **zizmor** for GitHub Actions workflows.
- **hadolint, trufflehog, dockle and osv-scanner** added through the registry,
  each with its own coverage denominator (or a stated reason it has none).
- **Headless count lines name the test share** — `N finding(s) (X in tests, Y in
  product)` — so a flood of a test idiom never buries the product findings.

### `verify` covers the checklist ledger

- `squawk verify` now walks the pre-handover checklist's signoff chain as well
  as the runs and the decisions ledger, so a tampered or back-dated signoff is
  reported, not passed silently.

### `stop` stops the server in the evidence root again, whatever port it is on

`stop --evidence X` was refused for any server not on port 8787. The port
check — a typed `--port` must match the server about to be stopped, so a stop
aimed at one server cannot land on another — received the built-in default as
though it had been typed, because the parser supplied one. The parser no
longer does: the port is filled in after parsing for the commands that serve,
and `stop` checks a port only when one was typed. Found by the field check,
which starts its servers on free ports and could not stop any of them; the
unit tests for the check called the function directly and never met the
parser, and the one with no port used 8787. They go through the command line
now, on a port that is not the default.

## 0.9.1 — 2026-10-08

### First release of this repository

Services across six scopes, from one entry point, standard library only, on
Python 3.9 and up:

| Scope | Services |
|---|---|
| repo | pre-flight check, contraband sweep, customs manifest, compliance audit |
| dir | baggage check, skill audit |
| image | cargo scan |
| url | recon, live probe, active probe |
| host | self-audit |
| aws | cloud inventory, cloud (AWS) |

Each one declares what it does **not** cover before you read its result, and
each run is kept on disk as immutable evidence so a later run can diff against
it rather than against memory.

The governing rule, and the reason for the name: **a scanner that did not run
must never look like a scanner that found nothing.** A quiet run is not a clean
run. Seventeen invariants in `CHARTER.md` hold that line, each naming the test
that fails when it is broken, and the suite that runs on every push is the
argument that they hold.

Correlation joins findings across layers and states its denominator when it
does — a correlation that could not be evaluated says so and says which input
was missing, rather than reporting nothing found.

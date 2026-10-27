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

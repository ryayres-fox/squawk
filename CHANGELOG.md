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

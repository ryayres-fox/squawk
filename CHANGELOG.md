# Changelog

Dates are when the change merged to `main`. This repository's record starts
here, deliberately.

Squawk was built in a private repository, against a real estate, and almost
every entry in that changelog is anchored to a measurement taken there: a
masked account id, a masked access key, a masked address, a run against
infrastructure that is not mine to publish. The value of those entries *is*
that provenance, and the provenance is the part that cannot travel. Rewriting
them against synthetic targets is an exercise in which one missed identifier
undoes the whole thing, so they stay where they were written.

What crossed instead is the reasoning that can be stated from public standards
and checked against this tree: [`CHARTER.md`](CHARTER.md) for the invariants,
[`PRODUCT.md`](PRODUCT.md) for the boundaries and the credential rules,
[`DESIGN.md`](DESIGN.md) for what must stay true on screen, and
[`CORRELATION-DESIGN.md`](CORRELATION-DESIGN.md) for how findings are joined
across layers. Where a decision looks arbitrary, one of those four says why.

## Unreleased

### First public release — 0.9.0

Thirteen services across five scopes, from one entry point, standard library
only, on Python 3.9 and up:

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

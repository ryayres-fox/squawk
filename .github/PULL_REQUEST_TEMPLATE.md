<!--
Read CONTRIBUTING.md first. This template is the short form of it.

The bar here is unusual and deliberate: this is a tool whose whole argument is
that a result you cannot check is not a result. The same applies to a change.
-->

## What this changes, and why

<!-- The defect or the capability, in a few sentences. If it is a defect: what
     was wrong, how it was found, and what a reader saw that was not true. -->

## What proves it

<!-- Commands and their output. Not "tests pass" — the command and the count.

| # | Command | Result |
|---|---|---|
| 1 | `ruff check .` | rc=0 |
| 2 | `mypy --python-version 3.9 --ignore-missing-imports squawk` | rc=0 |
| 3 | `pytest -q` | rc=0, `N passed` |
-->

## The test that fails without the fix

<!-- Name it, and say what happens when the fix is reverted and it is run.
     A test that passes with the behaviour removed is not a test of it. -->

## Checklist

- [ ] `pytest -q` passes with no `-k`, `--ignore`, `--deselect` or `--skip`, and the collected count did not drop
- [ ] `ruff check .` clean
- [ ] `mypy --python-version 3.9 --ignore-missing-imports squawk` clean
- [ ] Runs on Python 3.9 — no PEP 604 `X | Y` in an annotation, no walrus in a 3.9-invalid place
- [ ] Standard library only (I13): no new third-party import
- [ ] New behaviour has a test that fails when the behaviour is removed
- [ ] A scanner that did not run still cannot look like one that found nothing (I1)
- [ ] No secret, credential, account ID, ARN, internal hostname or real domain in the diff, fixtures included
- [ ] Docs changed alongside the code, in the same commit

## Anything you could not check

<!-- Say so. A change that claims to have been fully verified, on a project
     about coverage denominators, is the defect performed on itself. -->

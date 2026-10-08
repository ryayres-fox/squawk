# Contributing

Squawk is a small tool with a strong opinion, and the opinion is the part worth
protecting. Read [`CHARTER.md`](docs/CHARTER.md) first — seventeen rules, each naming
the test that fails when it is broken. A change that breaks one of them is not
rejected for style; it is a different tool.

## What is wanted

- **Bug reports with a reproduction.** Best of all: a case where Squawk printed
  a clean result over something it did not read. See
  [`SECURITY.md`](SECURITY.md) — that is a security report, not a bug.
- **A scanner integration**, if the scanner is free, is better than anything
  that could be written here, and answers the six questions below.
- **Portability fixes.** It is built on macOS and Kali and runs on the other
  POSIX platforms by argument rather than by measurement.
- **Documentation that is wrong.** A claim the code contradicts is a defect on
  the same footing as a crash. The README claimed to run on Windows for weeks.

## What is not

[`CHARTER.md`](docs/CHARTER.md) has a section called *What Squawk will never be*.
It is not a list of priorities to revisit. In short: not a remediator, not
multi-user, not a SIEM, not an agent, not CI, and not a scanner — where a good
free tool exists, Squawk drives it rather than competing with it.

Adding a dependency is also out. Standard library only (I13), so it stands up on
a bare machine's system Python with no install step.

## The six questions

Before a scanner, stage, service or check is added, it answers all six. A "no"
is not a blocker — it is a thing that must be written down in the same commit.

1. **What does it claim?** State it as a sentence someone could disagree with.
2. **How would a reader check it?** If the answer is "trust the output", stop.
3. **What does it look like when the underlying tool is broken?** If that looks
   the same as a clean result, it violates I1 and cannot ship.
4. **What does it not cover?** Goes in `not_covered`, in the words a user would
   use, not a disclaimer.
5. **What is its identity, and is it portable?** No timestamps, paths or hosts.
6. **What evidence does it leave?** If a run of it leaves nothing on disk, it
   did not happen.

## The gate

Everything below passes before a change is proposed. It is the same set CI runs.

```bash
python3 -m ruff check .
python3 -m pytest -q
python3 -m mypy --python-version 3.9 squawk/
./smoke-test.sh
python3 live-check.py
```

- **`ruff`** and **`mypy`** at the 3.9 floor, both with zero errors. The floor is
  a claim the code makes; CI pins the newest mypy that still accepts it.
- **`pytest`** green. New behaviour arrives with a test that **fails against the
  old code** — say so in the pull request, with the failure pasted. A test that
  passes before and after has not established anything.
- **`smoke-test.sh`** and **`live-check.py`** exercise the real CLI and every
  HTTP route. A view that raises is a failure, because a page that failed must
  never look like a page with nothing on it.

## Habits the code keeps

These are conventions, not style preferences. Each exists because its absence
caused a specific defect.

- **Three states, never two.** `ok`, `gap`, `unknown`. Never a boolean, because
  a boolean has nowhere to put "the probe does not exist here".
- **No silent caps (I12).** Any truncation, top-N, sampling or retry limit is
  printed. A number folded behind a link is fine — a number quietly capped is
  not. The difference is whether it expands to its members.
- **A zero needs a denominator (I15).** Findings are a numerator. A scan that
  found nothing and examined nothing prints the same zero as a scan of a real
  tree.
- **Remediation travels with the finding.** A finding with no fix line is a
  complaint. It also has to reach the screen — the fix was computed for every
  self-audit check and rendered by no view for weeks, which is the same defect
  as not computing it.
- **An identity is never changed to fix a display.** Identities are the stable
  key every diff, baseline, decision and timeline hangs off. Change the view.
- **Add to the registry, not beside it.** `SCANNERS`, `STAGES`, `SERVICES`,
  `NORMALIZERS`. Anything reaching findings by another route skips identity,
  evidence, history and baselines.
- **Docs change in the commit that changes the behaviour.** Not the next one.

## Commits and pull requests

- One idea per branch. Branch names read `feature/…`, `fix/…`, `docs/…` and say
  what the change does, not which file it touches.
- **The commit message is the argument.** What was wrong, what a reader saw,
  why this is the fix, and what it deliberately does not do. Not a summary of
  the diff — the diff is already there.
- The pull request carries the evidence: the failing output before, the passing
  output after, and the gate.
- No generated co-author trailers.

## Reporting a security issue

Not here. [`SECURITY.md`](SECURITY.md).

## Maintenance

**One person, best-effort.** Security issues first, bugs triaged as time allows,
and no commitment on feature requests. Pre-1.0: the newest release is the only
supported one and there are no backports. That is the honest bound, and it is
written down so nobody has to guess it.

> **Absorbed into `ROADMAP.md` (2026-08-30).** This document is kept for its
> reasoning and its lineage from the reference tool. The ordered plan lives in
> the roadmap now, and the rules it has to satisfy live in `CHARTER.md`. Where
> this and the roadmap disagree, the roadmap is current.

# Porting from the mature tool — what Squawk takes, and in what order

`docs/` holds the reference documents for a mature scanner built in a work
environment (its own handoff, scanner plan, rebuild lessons, reconcile plan, UX
conventions, and a bug and security review). They are **private and never
published**; what follows is what Squawk takes from them.

**The rule for porting:** keep the shapes, the mechanisms and the named failure
modes. Drop every proper noun, internal number and issue citation. A rule is
worth taking because of the failure that produced it, not because of where it
happened.

---

## Already done, because reading them found live problems

- **Cross-origin POSTs are refused.** `/run` spawns scanners — with a url-scope
  service, live DAST traffic at a target — and had no Origin check. A page open
  in the same browser could have made Squawk attack something. Fixed; a
  no-Origin request still passes so CLI callers keep working.
- **An unknown `?run=` no longer substitutes a different run.** It rendered
  `runs[0]` under a header asserting the id you asked for.

Both were the same shape as findings in the reference security review, and both
were *incidental safety made intentional* — the class worth looking for.

## Phase 1 — make a number mean something (do first)

Nothing below this line is worth building until these hold, because every count
Squawk reports is currently unverified.

- [ ] **Canaries, as two distinct checks.** `rules-<tool>`: did the target's own
      config actually load. `canary-<tool>`: does the tool, as configured,
      produce a finding at all — run against a fixture engineered to yield
      exactly one hit. A tool can pass the first and fail the second.
      - A failed canary pulls the run's **`trustworthy`** flag down and the
        message says a clean result from that tool is meaningless.
      - Build the fixture in a temp directory **outside** the scanned tree, so no
        in-repo allowlist can silence it.
      - **Do not build a secrets canary on a vendor's published documentation
        key** — scanners allowlist those deliberately. Use a synthetic,
        correctly-shaped one.
      - Canary results are recorded as **assurance**, never as scanner runs;
        emitting them as runs reads as "N tools found nothing".
- [ ] **Coverage chains to inputs, not findings.** Zero findings is legitimately
      clean, so it cannot be the coverage signal. Count what each stage was
      **handed**; no inputs is `skipped`, never `ran`. Without this, an exclusion
      that accidentally excludes everything reads as a clean run.
- [ ] **`ran` asserted from a positive signal** in the tool's own output — a
      scanned-path count, an artifact count, the presence of a results key —
      never from exit code 0.
- [ ] **The `orphans` check.** Any file in `raw/` that no reader ever parses.
      Collect the expected names **from the loader function**, not a hand-kept
      list, and declare deliberate non-findings artifacts with a reason. This is
      the check that catches the bug you cannot see: elsewhere a stage found 83
      misconfigurations and reported zero everywhere while its ledger row said
      `ran`, because the writer and the reader disagreed about a filename.
- [ ] **Manifest honesty fields**: `trustworthy` (false if any stage or canary
      failed), `reproducible` **with named reasons**, and `rulesets` per tool —
      because two runs whose rulesets differ are not comparable however similar
      the counts look.

## Phase 2 — a test suite that can actually fail

Squawk has none. Write these four rules first, in this order:

- [ ] **Records ≡ identities.** The parsed finding set and the identity set must
      be byte-identical per tool. Squawk has both a findings table and
      identity-key baselines; if they diverge, the UI and the posted baselines
      describe different sets with nothing saying so.
- [ ] **The page parses.** Squawk builds HTML in Python, so Python's own syntax
      check validates the wrapper and says nothing about any inline script. Feed
      the whole script to a parser; a fragment reports the error in the wrong
      place.
- [ ] **A failed load is bounded and is said.** Elsewhere a rejected fetch left a
      null cached value, the error handler re-rendered, the view re-fetched —
      501 iterations, triggered by being offline, with nothing on screen saying
      so. Assert both halves.
- [ ] **Two identical runs diff to nothing.** Five minutes, and it validates the
      entire identity-key contract. A non-empty diff means a key is picking up
      something unstable and every diff after it is noise.

**Four properties the gate itself must have**, each of which was wrong once in
the reference build:

1. **A skip is not a pass.** A sentinel compared against itself let a suite print
   "76 of 76 rules hold" on a machine where three never executed. Count and name
   skips separately; still exit zero.
2. **A check inside a loop can run zero times** — carry a positive control that
   asserts it had something to compare.
3. **A moving check count is a signal**, so assert the total.
4. **A positive control can match itself** — assemble sentinels at runtime, never
   as literals in the file being scanned.

And ship each rule with a **negative control**: break it deliberately and watch
it go red. Checking for the symptoms you thought of is not the same as checking
for the defect you found.

## Phase 3 — decisions and baselines that survive

- [ ] **Decisions move server-side.** Squawk's triage state is in browser
      localStorage today: *a dismissal masquerading as a record — per-browser,
      per-machine, unreviewable*. Append-only `decisions.jsonl` in the evidence
      root, keyed by identity, written via POST. localStorage becomes a cache.
- [ ] **Validation fails closed, and a rejected decision is not a decision** —
      the finding stays in the queue and the refusal states its reason.
- [ ] **A group decision carries a `covers` list** — one advisory across N files
      is one human decision that matches no single identity.
- [ ] **`resolved-candidate`, never `resolved`.** Absence is not resolution. A
      finding graduates only when the tool actually ran, its coverage is at least
      the baseline's for that tool, the ruleset fingerprint matches, and a human
      said so. (Elsewhere a narrower auto-selected ruleset read 68 findings as
      remediated.)
- [ ] **A diff names its baseline.** A pinned baseline pointer with a recorded
      reason; every digest records what it diffed against. *A diff that does not
      name its baseline is a number with no denominator.*
- [ ] **Re-hash issue-carried identity sets on pull.** Squawk pulls sets from
      issue bodies and is exposed to the same comment-length truncation that
      turns a truncated set into a false "resolved". The guard exists on read;
      the generator needs the matching within-scanner part splitting.

## Phase 4 — cloud, built with its rails from the first probe

Not after. The allowlist pattern is ~30 lines and is what makes "read-only" a
property rather than a promise.

- [ ] **Read-only enforced before a client is constructed**, refusing with the
      offending call named. Any call that creates something is listed separately
      with the reason it is safe and gated behind its own flag.
- [ ] **Three-state failure classification: `off` / `denied` / `error`.** A
      permissions failure rendered as "not enabled" is the same clean-looking
      answer about coverage, and it is wrong.
- [ ] **Scope travels with every enablement claim.** "Enabled" is not a fact;
      "enabled in 1 of 17 regions" is.
- [ ] **Paid calls declared, off by default, stating the cost.**
- [ ] **A saved snapshot recording every call made and every call refused**, so a
      panel can show its own provenance. The page renders the snapshot, never a
      live call.
- [ ] **A field audit**: every collected field the page never reads, with an
      allowlist carrying a reason. *A field gathered and never rendered is worse
      than one never gathered — the collector looks thorough and the page looks
      complete.*
- [ ] **Declare the unbuilt provider with its probe list**, so it renders as a
      gap rather than as nothing.

## Phase 5 — evidence operations

- [ ] Ledger as a cross-run journal; **coverage written first**, because coverage
      is what makes a falling finding count interpretable.
- [ ] A dated digest — what was known on a date, what is silent rather than
      fixed, what carries a decision. Make target paths repo-relative **before**
      hashing or the digest is machine-specific.
- [ ] Prune with **dry-run as the default verb**, windows per *(target, service)*
      not per target, refusals printed with reasons, and any derived answer
      materialised before the delete and **labelled as materialised**.
- [ ] Collapse counts by canonical id, and resolve aliases before any catalog
      join — a join on the wrong id space returns zero by construction and keeps
      returning zero after a real hit appears.

## Adopt as practice, not code

- **The assumption audit.** Before building a reconciler, write down every fact
  the design assumes and verify each against running code. Three of four busted
  in a document written by someone who knew the system.
- **A verified-in-code inventory before planning** — what already exists, with
  anchors, so the work is chaining rather than rebuilding.
- **Record the controls that held** as named findings, not silence.
- **Live-smoke every subcommand's success *and* failure path.** A syntax check
  proves nothing; the reference bug review found a crash on a documented command
  that compiled fine.
- **Extracted, not invented** — write Squawk's UX conventions by reading its own
  shipped CSS, with a divergences table carrying a verdict, before adding
  another page.
- **Every row carries its reason**; untrust is a banner above the fold, not a
  footnote; emphasis is spent only at the top or the page is uniformly loud.

## Deliberately not taking

- Anything keyed to an internal store, portal, issue tracker or approver file.
- The estate figures. Where a measurement makes a point, it is restated as
  "measured on one estate".
- The reference tool's naming and vocabulary. Squawk has its own airport
  vocabulary and its own alarm codes.

# Squawk — the charter

What this tool is for, written as rules that can be checked rather than
sentiments that can be agreed with. Every rule below has an enforcement column
naming the thing that fails when the rule is broken.

[`PRODUCT.md`](PRODUCT.md) says what Squawk is. [`ROADMAP.md`](ROADMAP.md) says
what gets built next. This says what must stay true while that happens, and it
outranks both. When a
feature and a rule here disagree, the rule wins or the rule changes on purpose,
in a commit that says so.

## The one idea

**A security tool's output is a claim about the world, and a claim nobody can
check is worth nothing.** Everything else follows. The scanners are not the
product; the guarantees around them are. Any competent developer can shell out
to gitleaks. The work is making the result mean something a week later, on a
different machine, to someone who was not there.

## The rules

| # | Rule | Why | Enforced by |
|---|---|---|---|
| **I1** | A tool that did not run must never look like a tool that found nothing | The failure mode that makes every other guarantee worthless. A silent scanner and a clean scanner produce the same empty list. A read that was REFUSED is the same failure one call in: it must leave a trace the run keeps, and it must move the ledger row of the stage that asked — a denial recorded in evidence under a green stage puts the refusal where nobody looks and the reassurance where everybody does | `test_charter.py::TestSilenceIsNotClean`, `TestEveryDeniedReadLeavesATrace` (79 reads, refused one at a time, on both axes), `_partial`, squawk code 7600 |
| **I2** | Absence is recorded with a reason | "We did not check for secrets" and "there are no secrets" are different sentences | Every scanner carries `contributes`, every service carries `not_covered` |
| **I3** | Read-only, always | Squawk assesses. It never remediates, writes to an account, or changes a resource. Auto-actuation is a different risk class | `TestReadOnly` scans every built command for destructive tokens, and `TestEveryCloudCallIsARead` runs every cloud stage against a populated fake CLI and asserts over every argv they actually built — an allowlisted service, a read verb, no destructive token, no credential and no `--profile` on a command line. **What that does not cover**, named because a control whose limit is unstated is a claim: an argv recorder sees the command Squawk builds and not what the AWS CLI does with it. A `credential_process` in the CLI config runs whatever command it names before a request is signed, so a recorded read is a shell command on this machine — the run reads the config and names every profile it asked that carries one. And the CLI writes its own SSO and credential caches under the home directory during an ordinary run. Neither is Squawk writing to the account, and neither is nothing |
| **I4** | Loopback only, private targets only | No auth exists, so exposure is the whole risk. DAST against something you do not own is someone else's incident | `TestLoopbackOnly`, `guard_host`, `dast_target_ok` |
| **I5** | Identity is stable and portable | No timestamps, no absolute paths, no hostnames. Two identical runs must diff to nothing, and the same finding on another machine must match | `TestIdentityIsPortable` |
| **I6** | A normalizer never raises | Scanners change output between versions. A parse failure must degrade to "nothing readable", never to a crashed stage | `TestNormalizersNeverRaise`, 3,000+ generated inputs |
| **I7** | Every finding is well-formed | A finding with an unknown severity or an empty identity cannot be sorted, diffed or baselined | `TestFindingsAreWellFormed` |
| **I8** | Three states, never two | `ok`, `gap`, and `unknown`. "I could not tell" is not a pass, and folding it into one is how a machine with no clock sync reads as a machine with a good one | `TestThreeStates` |
| **I9** | Nothing is done without evidence | Logging on by default, evidence written per run, owner-only. If it has no log, it is not done | `TestEvidenceIsWritten`, `TestEvidencePermissions` |
| **I10** | The registry stays closed | Every scanner reaches a stage, every stage a normalizer, every service real stages. A half-registered scanner is a stage that silently never runs | `TestRegistryIsClosed` |
| **I11** | The instrument is audited too | A finding written to a world-readable directory has leaked. A timestamp from an unsynchronised clock cannot order two runs | `selfaudit` service, summary in `--doctor` |
| **I12** | No silent caps | Any truncation, top-N, sampling or retry limit is printed. Silent truncation reads as "we covered everything" | Review practice, the baseline truncation guard, and `TestProfiles`: every budget a run runs under is printed before it runs, written into the manifest and shown on the run page |
| **I13** | Python 3.9, stdlib only | It has to stand up on a bare machine's system Python, with no install step | CI compiles under 3.9 and asserts the interpreter |
| **I14** | A report we cannot read is not a clean result | The likeliest long-term failure is a scanner changing its output, not breaking. Rename a field and the normalizer reads nothing, and "0 findings" is the answer. The scanner ran and produced data; we understood none of it | `report_unreadable`, `TestScannerDrift`, stage status becomes `error` |
| **I15** | A zero over an empty denominator is not a clean result | Findings are a numerator. A scan that found nothing and examined nothing prints the same zero as a scan of a real tree; the denominator, read from what the scanner already reports, tells them apart | `stage_coverage`, `_apply_coverage`, `TestCoverageVerdict`, stage status becomes `gap` |
| **I16** | A correlation states its denominator | Joining findings across scanners is what a platform sells, but the honest part is that a combination a member scanner could not evaluate reports `unknown`, never silently absent — a toxic combination is never missed because half of it was not looked for. The same rule applies to one that **does** fire: a required scanner that ran and read nothing is named in the finding, so a real combination is never reported as if every leg of it had been scanned | `correlate`, `_unread_caveat`, `TestCorrelation`, `TestCorrelationStatesItsDenominator`, the manifest carries fired/unknown states and the unread kinds |
| **I17** | Evidence proves it was not edited | Evidence is the product, and "written once" was prose until a command could check it. Every run hashes its own files and the run before it; every decision and every retention act hashes the one before it; a recorded verify covers the newest of each from then on. A run the check cannot read exits 3, never 0. The first version was fooled four ways with exit 0; each is now a test | `squawk verify`, `TestTamperEvidence` (the second pass included), `verify_root` / `verify_ledger` / `verify_retention` |

## What Squawk will never be

Written down so scope creep has to argue with something. These are not
priorities to revisit; they are the shape of the thing.

- **Not a remediator.** Read-only is I3 and it is not negotiable.
- **Not multi-user.** No auth, no tenancy, no shared server. Two people means
  two copies. Team aggregation is DefectDojo's job.
- **Not a SIEM.** No log ingestion, no alert pipeline, no detection runtime.
- **Not an agent.** Nothing is deployed into the estate being assessed.
- **Not CI.** CI scans a clean checkout on a clean runner. Squawk scans a
  lived-in tree, which is why the contamination filter exists at all.
- **Not a scanner.** It orchestrates scanners that already exist and are better
  than anything worth writing here. Where a good free tool exists, Squawk drives
  it rather than competing with it.

## The test every new capability has to pass

Before a scanner, stage, service or check is added, it answers all six. A "no"
is not a blocker, it is a thing that must be written down in the same commit.

1. **What does it claim?** State it as a sentence someone could disagree with.
2. **How would a reader check it?** If the answer is "trust the output", stop.
3. **What does it look like when the underlying tool is broken?** If that looks
   the same as a clean result, it violates I1 and cannot ship.
4. **What does it not cover?** Goes in `not_covered`, in the words a user would
   use, not a disclaimer.
5. **What is its identity, and is it portable?** No timestamps, paths or hosts.
6. **What evidence does it leave?** If a run of it leaves nothing on disk, it
   did not happen.

## Consistency rules for whoever builds this

Including me, across sessions, which is the case these exist for.

- **Add to the registry, not beside it.** New capability means an entry in
  `SCANNERS`, `STAGES`, `SERVICES` and `NORMALIZERS`. Anything that reaches
  findings by another route skips identity, evidence, history and baselines.
- **The three-state habit.** Anything that reports a condition reports `ok`,
  `gap` or `unknown`. Never a boolean, because a boolean has nowhere to put
  "the probe does not exist here".
- **Remediation travels with the finding.** A finding with no fix line is a
  complaint. It also has to reach the screen: the fix was computed for every
  self-audit check and rendered by no view for weeks, which is the same defect
  as not computing it.
- **An identity is never changed to fix a display.** Identities are the stable
  key (I5) and every diff, baseline, decision and timeline hangs off them.
  Rewriting one so a page groups better makes every existing finding look new
  and silently rewrites the history. Change the view, or the function the view
  groups by, and leave the key alone.
- **Nothing writes into a finished run without saying so, and the record
  lives outside the run.** A run directory is sealed and hashed the moment it
  finishes (I17). Anything that legitimately removes a file afterwards has to
  record it in the chained retention file at the root *before* doing it, the
  way retention does. A record inside the run — `pruned.json` — is for the
  pages; `verify` never trusts it, because a file written after the seal is
  exactly what a forger would write. And only the parts retention can trim
  count: a record is an allowlist, so its vocabulary is closed.
- **A check answers "what can you not see?" before it ships.** The review of
  I17 found four ways `verify` exited 0 on destroyed evidence, and every one
  was a thing the check defined out of existence: a run was "a directory with
  a manifest", a prune was "whatever `pruned.json` says". Write the population
  and the allowances down, then try to fall outside them.
- **Failures exit non-zero.** Anything that shells out returns a real code.
- **Docs change in the commit that changes the behaviour.** Not the next one.
- **Verify on the thing, not the idea of the thing.** Claims about Linux get
  checked on Linux; `test-matrix.sh` exists because portability asserted is not
  portability tested.
- **Write after each edit, never batch-assert at the end.** A script that
  applies six edits and asserts at the end throws away five when the sixth
  anchor misses.
- **A failed step must stop the script.** The same mistake in shell: a `git
  checkout` that aborts on a dirty file, or a `worktree add` that fails, and the
  next twenty lines run anyway against whatever state is actually there. Both
  have happened here. Use `set -e`, or check the exit code, and never read `$?`
  through a pipe — it reports the last command in the pipeline, not the one you
  care about. That error turned "the installer exits non-zero" into a claim that
  was wrong for a whole review cycle.

# Squawk — roadmap

The single ordered plan. [`CHARTER.md`](CHARTER.md) says what must stay true;
this says what gets built and in what order; [`POSITIONING.md`](POSITIONING.md) says who it
is for and what releasing it would cost. When any of them disagree, the charter
wins.

Ordering principle, taken from the charter's one idea: **a claim nobody can
check is worth nothing.** So the work goes trust the instrument, then trust the
answer, then trust it over time, then widen what it reads, then let it talk to
other tools. Widening the sources before the answer can be trusted just produces
more unverifiable claims.

### Why Phase 1 comes before everything, including 1.5

Phase 1.5 (correlation) is the more compelling feature and Phase 1 (the
denominator) is the one to build first. Those are different questions, and
accuracy is the second one.

Every phase after Phase 1 inherits Phase 1's guarantee or its absence. Correlate
before you know the denominator and a toxic-combination rule reasons over
findings that might be lies. Rank before you know it and you sort garbage
confidently. The failure is concrete, not theoretical. Trivy pointed at a
directory it cannot resolve returns a valid report with zero blocks and exits ok,
and Squawk records that today as `status=ok, 0 finding(s)`, indistinguishable
from a real clean scan. A correlation rule built on that reads "trivy-config ran,
found nothing" and reports *no toxic combination here*, when the truth is *not
checked*. That turns a coverage gap into a false all-clear at the layer that is
supposed to be the most trustworthy, because a correlation amplifies its members.

So the denominator is not one feature among several. It is the property the
others borrow their credibility from, and 1.5's own honesty, its `unknown` when
a member scanner was silent, is the denominator concept restated. Build it first
and 1.5 inherits a true "did it look"; build 1.5 first and it inherits a guess.

For long-term success the same order holds for a different reason. Phase 1 is the
part that cannot rot, because it is derived from each run rather than from an
artifact anyone maintains. Founding the tool's accuracy on the one thing that
does not decay is what makes the claim survive being handed to someone else. The
parts that could rot, external feeds and correlation rules, sit on top of a
base that does not.

Each phase has an exit criterion. A phase is not finished because the code
merged; it is finished when the criterion is demonstrable.

---

## Merged

On `main`, and exercised. Everything here has either a merged pull request or a
run that produced evidence.

| | |
|---|---|
| Engine: registry, immutable evidence, stable identity, contamination filter | it 1 |
| Loopback web UI, live per-stage progress | it 2 |
| Baselines from GitHub issues with the truncation guard, triage, dashboard | it 3 |
| DAST via the ZAP image, private-target rail, host-free identities | it 4 |
| Target recon feeding the kiosk | it 4 |
| AST10 skill audit | it 4 |
| Findings grouped by advisory with drill-down and per-instance history | #61 |
| Alarm codes 7500 / 7600 / 7700 | #62 |
| Logging on by default, every refusal recorded | #68 |
| The squawk verdict rendered on the web *Scan complete* page | #72 |
| A never-built vulnerability database no longer reads as 739855 days old | #73 |
| Normalizers survive a report shape they did not expect | #75 |
| Host self-audit across seven areas, three states | #76 |
| Install and update evidence: inventory, transcript, sha256, dependencies | #77 |
| Portable installer, and 18/18 across six distributions | #78 |
| Charter, and conformance tests that fail when it is broken | #79 |
| Positioning, novelty assessment, licence and release gates | #80 |
| Phase 1 finished: error channels carried, cross-scanner differential | #90 |
| Correlation across scanners, stating the denominator | #91 |
| Phase 1 field-check script for the full-toolbench paths | #94 |

## In review, not merged

Nothing currently in review. The last open stack (#75–#80) merged, and the
Phase 1 / 1.5 work (#90, #91) with it. When a pull request is open with green
checks but not yet accepted it belongs here, so the distinction — *tests passed*
is not *done* — survives someone skimming.

## Shipped outside the phase plan

Merged 2026-08-30 → 09-01, and not part of any numbered phase. Three came from
dogfooding Squawk on its own source and on a live target; one was an interface
overhaul; two were features the operator asked for after using it. Recorded here
so the plan is not the only place work is written down, and so nothing above
implies the phases are the whole story.

| | |
|---|---|
| A crashing web view showed a blank page; now surfaces the traceback | #96 |
| An out-of-scope correlation reads "not applicable", not "cannot evaluate" | #97 |
| The field check's differential test was vacuous — it never staged agreement | #95 |
| **UI overhaul**: teal instrument panel, light and dark, colour-impaired-safe, one design system shared by the app and the exported report | #98 |
| Overview tiles no longer stretch empty; the tagline says what the tool is for | #99 |
| **Rescan** a prior target without retyping it | #100 |
| **Compare** a rescan to the previous run — the *what changed* view | #101 |
| Drill-down on compared findings; a findings-rating trend (−5 to +5, median at 0) | #103 |
| Real evidence, targets named on every run, drillable triage, overview drill-down | #104 |
| Findings and Triage count the same (both group by rule) | #105 |
| Title and column polish; a clean result shows its work; a gap run is never drawn clean | #106, #107, #108 |
| Topbar fixed; the design charter, `DESIGN.md` | #109, #110 |
| Every scanner's evidence captured (code, description, reference); the passive-DAST claim made honest | #111, #112 |
| A rescan of a vanished directory is refused; no ledger is not clean | #113 |
| **Active app probe**: active DAST (zap-full-scan) behind the private-target rail | #114 |
| **Cloud inventory**: ten API-driven AWS stages — org, inventory, enablement, IAM, edge, front door, storage, containers, data services, Access Analyzer — with toxic combinations joined across them | #197 and before |
| **The cloud review, closed out**: seventeen findings from the 2026-09-10 review; every number on the page opens the set it counts, a reading that cannot be parsed is a gap rather than an exception, one severity scale with the code held to it, and AWS's own analyzer read where the account runs one | #199-#209 |

The compare view (#101) is the first working piece of Phase 2's remediation
tracking; see that phase for what it does and does not yet do.

---

## Phase 1 — publish the denominator ✅ done

Every scanner reports what it found. Almost none reports what it *looked at*, and
no aggregator publishes it. **Findings are a numerator, and the lie lives in the
missing denominator.** A zero over nothing examined is not a clean result, it is
no result, and today those two produce the same string.

This replaces an earlier plan built around canaries. That plan was wrong, and the
reason is worth keeping: a canary needs a fixture per tool, maintained forever,
and one that stops firing because the scanner changed its rules looks exactly
like a scanner that broke. That is this tool's own failure one level up, it is a
treadmill, and it is the most likely explanation for why nobody has shipped this.

Coverage has none of those properties. It is already in the output, there is
nothing to keep in sync, and it cannot go stale because it is derived from the
run rather than from an artifact. Measured, not assumed:

| Scanner | What it already publishes |
|---|---|
| semgrep | `paths.scanned`, `paths.skipped`, `skipped_rules`, `errors` |
| bandit | `metrics` per file, `_totals.loc`, `errors` |
| trivy | `Results` blocks and the `Target` each covers |
| checkov | `summary.passed` / `failed` / `resource_count` |

Two runs that prove the point. Semgrep with an empty ruleset: **0 findings, 0
files scanned.** Semgrep with real rules on the same tree: **0 findings, 6 files
scanned.** Identical finding counts, and the denominator separates them
completely. Trivy on a directory it could not resolve returned a valid,
clean-looking report with **zero `Results` blocks** — defect 1 and defect 4 in
issue #58, both visible for free.

- [x] **Extract coverage per stage** into the run evidence: units examined, units
      skipped, and what the unit means for that tool, because files, resources
      and packages are not comparable and pretending otherwise invents a number. **Done** — `stage_coverage`, `Coverage` in the ledger.
- [x] **A zero over an empty denominator is never `ok`.** It reports as a gap
      with the denominator quoted. This is I1 with something behind it at last. **Done** — `_apply_coverage`, charter I15, and it raises 7600.
- [x] **Carry the tools' own error channels.** `errors`, `skipped_rules` and
      `parsing_errors` are discarded today. A scanner that says it could not
      parse half the tree is telling us the coverage is a lie, and we throw the
      message away. **Done** — surfaced in the detail line as `(N unreadable, N skipped)` and logged `COVERAGE`.
- [x] **Show coverage next to every count.** "0 findings across 214 files" and
      "0 findings across 3 files" are different claims and currently read the
      same. **Done** — shown inline in the CLI and the ledger.
- [x] **Cross-scanner differential where domains overlap.** trivy and grype both
      read the same SBOM. Sustained disagreement is a health signal that costs
      nothing to collect and needs no fixture. **Done** — `scanner_differential`, zero-vs-many only, in the manifest and CLI summary.

**Exit criterion:** point a scanner at a directory it cannot resolve, or load it
with an empty ruleset, and the run reports a gap naming the empty denominator
rather than a clean zero. Neither case involves a fixture.

### The residual, and why it is small now

Coverage answers *did it look*. It does not answer *can it still see* — a scanner
with rules loaded, files scanned and a broken detector looks healthy. That is the
only place a real detection test is still needed, and scoping it this narrowly is
what makes it survivable:

- [ ] **Detection tests against a corpus somebody else maintains** — OWASP
      Benchmark, Juice Shop, or the vulnerable fixtures the scanners ship with.
      Not hand-written fixtures that rot in this repository.
- [ ] **Run them on install and update, not on every scan.** The question is
      whether this toolchain can see, which changes when the toolchain changes,
      not when the target does.
- [ ] **A stale or unrunnable detection test reports `unknown`.** Never a pass,
      and never a build failure. Break someone's pipeline with a rotting fixture
      and they delete the fixture within a week, and then the tool trusts zeros
      while claiming it does not.

## Phase 1.5 — correlate, and let the scanners check each other ✅ core done

The three deliverables below are merged (#91) and the exit criterion was
demonstrated both ways. Open follow-ons, scoped in the PR rather than implied:
the exploitable-and-reachable rule (needs recon and a CVE scanner in one
url-scope service), Dockerfile COPY-target confirmation for the secret rule, and
the review-gap items in the section below.

Designed in [`CORRELATION-DESIGN.md`](CORRELATION-DESIGN.md), against the identity
formats the normalizers actually emit, verified by running the scanners on a
planted target rather than by imagining their output.

This is the answer to "what does Wiz sell that the scanners underneath do not".
Not detection — correlation across layers. A secret, a public bucket and a
reachable service are three findings a scanner reports and a platform joins into
one path. Squawk already writes every input to disk with stable identities; the
join is a local operation nobody performs on open-source output.

- [x] **Toxic combinations, registry-driven.** A correlation is a finding whose
      evidence is other findings. **Done** — `CORRELATIONS` registry; public+unencrypted and secret+build rules, each citing members. Proven live.
- [x] **Correlations state their denominator.** If a member scanner did not run,
      the combination reports `unknown`, never silent. **Done** — charter I16, verified live: secret+build went `unknown` when gitleaks was absent.
- [x] **Disagreement as a free detection test.** Two scanners over the same input
      disagreeing sharply is a health signal that needs no fixture and cannot go
      stale. **Done** — shipped in Phase 1 as `scanner_differential` (#90),
      zero-vs-many only. Measured: bandit found a hardcoded password gitleaks
      missed.

**Exit criterion:** a target with a secret in a copied file reports one HIGH
correlation citing both members; skip `trivy-config` and the same combination
reports `unknown` rather than nothing. The second behaviour is the one nobody
else does.

### Review 2026-08-30 — gaps found, and where each stands

An adversarial pass over everything to date found six defects (all fixed in #91,
each with a regression test that failed on the pre-fix code) and four gaps that
are documented here rather than fixed, with the reason.

- **Web: not-evaluable correlations and a coverage strip.** Fired correlations
  already render on the Findings page (verified by rendering it: group, rule
  title, cited members all present), and per-stage coverage rides in each ledger
  detail line. What the web does not show is the `unknown` correlation states
  and a per-stage coverage summary on the run page. Small UI item; CLI and
  manifest carry both today.
- **checkov's `parsing_errors` are not carried.** The error-channel work reads
  bandit's and semgrep's error arrays; checkov reports its own unparseable files
  in `summary.parsing_errors` and that number is still dropped. Same pattern as
  the shipped extractors; belongs with the next coverage touch.
- **The differential has one pair.** trivy/grype is the only same-input pair the
  toolbench currently offers, by design rather than omission, since semgrep/bandit
  legitimately differ. The next genuine same-input pair (a second SBOM reader, a
  second IaC scanner over the same framework) joins the table when it exists.
- **trivy gaps on no-lockfile trees, by design.** After the review fix, a trivy
  report with no `Results` key gates as "examined 0 scan targets". On a tree
  with no dependency manifests that is the honest I15 answer, and it will show
  as a gap row on mixed targets. Expected, not a bug; `TARGETS.md` says so.

## Phase 2 — make it true over time ◑ started

A single run is a photograph. The value is in the sequence, and the sequence is
where the honest mistakes live: a scanner that stops running looks like a
problem that got fixed.

- ◑ **Remediation tracking.** `first_seen`, `last_seen`, `status`,
      `resolved_on`, reconstructed from immutable run history rather than a
      separate mutable ledger. Open becomes resolved with a date; a resolved
      finding that returns is flagged as a regression; **a scanner that was
      silent never reads as a fix** (charter I1 across time).
      *Started in #101:* the *what changed* view diffs a run against the prior
      run of the same target and already enforces the load-bearing rule — a
      scanner that did not run OK in both runs is silent, never remediated, with
      five regression tests. `finding_history` reconstructs `first`/`last`/`runs`
      from the immutable evidence. *Done next:* `remediation_timeline`
      walks every comparable run and gives each finding open / resolved (dated
      to the first run it was missing from) / regressed (dated, counted), with
      a scanner that did not run OK changing nothing; every run persists it as
      `history.json` (the timeline as of that run, so the report on that date
      is itself evidence), and a page recomputes it and must agree (tested).
      Findings flags a regression on its row and lists what was resolved
      before the run, with dates; History shows open / resolved / regressed
      per target with the dated list. The exit criterion below is a test.
- [ ] **Suppressions that expire, written as VEX.** Every real tool needs
      exceptions, and exceptions are where tools go to die quietly. Each carries
      a reason, a person and an expiry; an expired one returns the finding; a
      suppressed finding stays visible as suppressed rather than disappearing.
      **Emit them as VEX** (OpenVEX or CycloneDX) rather than inventing a format.
      "This CVE does not affect us, and here is why" is a solved problem with a
      standard, other tools already read it, and the EU CRA is about to make it
      the expected way to say it. An invented format would be work spent
      producing something nobody else can consume.
- [x] **Retention and pruning.** *Done:* `squawk prune`, a dry run unless
      `--apply`. Two tiers, because the parts of a run are not equally
      valuable. *Trim* drops `raw/` and the superseded `history.json` from runs
      past `--trim-days`, keeping the manifest, findings, identities and
      digest, so every page still renders and the timeline still resolves.
      *Remove* deletes a run past `--drop-days` entirely, which shortens that
      target's history and is never the default. The newest run of a target is
      never touched; a run a decision names, or the last run holding a
      baselined identity, can be trimmed but never removed; a run id that does
      not parse as a date is never pruned. A trimmed run keeps a `pruned.json`
      and its pages say the raw output was removed, so it never reads as a run
      that had none. Nothing is edited: the record is a new file, not a field
      added to the manifest.

**Exit criterion:** a finding fixed three runs ago shows `resolved_on`, and
reintroducing it flags a regression. Disabling a scanner produces "silent", not
"resolved". *Met, as `TestRemediationTimeline` in the suite.*

---

## Phase 2b — make the list survivable ◑ core shipped

The plan up to here is entirely about **false negatives**: not missing things.
That is the right obsession and it is only half the problem. Tools do not get
abandoned because they missed something. They get abandoned because they
produced four hundred findings nobody had time to read, and for one person with
no team that is the same as producing nothing.

- [x] **Exploitability, not just severity.** Rank with **CISA KEV** (what is
      being exploited now) and **EPSS** (what is likely to be, within 30 days)
      alongside CVSS. Both feeds are free and public. Published figures put the
      reduction in urgent work at up to **95%**, because only a small fraction of
      CVEs are ever exploited while most carry a High or Critical score. For the
      reader this is written for, that is the difference between a list they act
      on and a list they close.
- [x] **Say why something is ranked where it is.** A score with no reasoning is
      another number to take on trust, which is the thing this tool exists to
      refuse. "In KEV, added 2026-06-04" is a reason; "8.8" is not.
- [x] **Reachability where a tool can tell us.** A vulnerable dependency nobody
      calls is a different claim from one on a live path. Where a scanner reports
      it, carry it; where none does, say so rather than implying it was checked.
- [x] **Count the noise honestly.** If the contamination filter or a severity
      floor is hiding findings, the number hidden is printed. No silent caps
      (I12).

*Core shipped:* CISA KEV and FIRST EPSS are cached under `feeds/` with
provenance (when, from where, sha256, entry count) and refreshed by `--feeds`
or `--update`; their age is reported like a vulnerability database's. A
**Priority** page ranks a run into three tiers, each item stating why it is
there (`in CISA KEV, added 2024-05-01`, `EPSS 0.42 (95th percentile)`), with
everything below the shortlist counted by severity, never hidden. With no
feed fetched, every CVE reads *exploitability unknown* and the page says so:
no silent fall-back to severity dressed as likelihood. Reachability is stated
as not assessed, because no scanner here reports it. Left for later: CVSS
alongside the feeds, and a scanner that can report reachability.

**Exit criterion:** a run with 400 findings produces a shortlist somebody with an
hour can work through, and every item on it can say why it is there.

---

## Phase 2c — it has to run without being remembered 🔜

The audience is one person with no time. A tool you must remember to run is a
tool that does not run, and one that squawks into a terminal nobody is watching
has not told anybody anything.

- [ ] **Scheduled runs**, by cron or a systemd timer, generated rather than
      described in a document.
- [ ] **Tell somebody when it squawks.** A local notification, a file a shell
      profile can read, or an exit code something else can watch. Not email, not
      a service, nothing that needs an account.
- [ ] **Unattended runs are still evidence.** Same run directory, same logging,
      and a scheduled run that failed to start is itself a gap the next
      interactive run reports. A cron job that silently stopped is I1 wearing a
      different hat.

**Exit criterion:** the tool runs for a fortnight untouched, and the operator
learns about the one thing that changed without having gone looking.

---

## Phase 3 — widen what it reads ◑ started

Only after a number can be trusted. Ordered by value per unit of work on the
first day at a new organisation.

- [x] **Cloud native findings ingest: AWS.** Security Hub (ASFF) is read as the
      read-only identity in the credential chain, behind SQUAWK_CLOUD_ACK, with
      the identity named first and an empty read counted as a gap (#116).
      Defender for Cloud is still to do.
- [ ] **Cloud native findings ingest, Azure.** Security Hub (ASFF) and
      Defender for Cloud assessments into normalizers; account and
      subscription-scoped identities so cloud findings diff across rescans the
      way code findings do. This answers "what does this estate already know
      about itself", and pulls in GuardDuty, Inspector, Config and whatever
      third-party integrations are already paid for.
- [ ] **Prowler as the fallback posture stage.** Orchestrated, never
      reimplemented, for estates where native security is off.
- [ ] **Container and build analysis.** hadolint for Dockerfiles;
      image-to-image SBOM and CVE drift, so "what did this build add" is
      answerable the way History answers "what did this commit add".
- [x] **Multi-target inventory.** *Done:* `/estate` (Tier 2 below) answers this
      for findings — several targets as one estate, one row per rule across all
      of them. What is still one-checkout-at-a-time is *running* a scan: there
      is no "scan these six" action, and that is the part left.

**Exit criterion:** a read-only cloud identity produces a ranked, deduplicated
list that diffs across two runs, with the same identity guarantees as a code
finding.

---

## Phase 4 — let it talk to other things 🔜

- [ ] **SARIF export.** The one format everything reads.
- [ ] **CSV export** for the spreadsheet that ends up in front of a manager.
- [ ] **A configuration file.** Everything is environment variables today, which
      is fine for one machine and poor for a reproducible setup. *Now shipped
      as scan profiles:* per-service and per-target timing,
      budgets and options, printed on the run and carried in the manifest,
      with the read-only and no-secret rails applied to the file.

**Exit criterion:** a run's findings open in another tool with severity, path
and identity intact.

---

## Professional grade: the gap list (2026-09-04)

Asked directly: what is still missing for this to read as professional-grade
rather than a young tool. Honest answer, tiered by what the rest depends on.
Each item names where it lands.

**Tier 1, foundations the rest borrows credibility from**

- [x] **A lifecycle.** A pid file; `--status`, `--stop`, `--restart`, `--daemon`;
      `/healthz`; `--version`; a generated systemd user unit; and an interrupted
      run written up as aborted under its target instead of vanishing. Shipped
      in the lifecycle change.
- [x] **A package, not a 6,000-line file.** *Done:* fourteen layered modules
      (sixteen now — `decisions` and `retention` came later),
      an entry point that keeps every command working, subcommands with the
      flags as aliases, `pyproject.toml`, `python3 -m squawk`, a zipapp build,
      a CHANGELOG. *And, 2026-09-06:* `mypy` is gated in CI at 1.20.2 against
      the 3.9 floor with zero errors — the thirty advisory ones typed away
      (plan 03), none a behaviour change, one a real contract (`StageSpec.
      internal` returns a triple as well as a string).
      Original scope: split into `squawk/` (engine,
      scanners one module each, web views, feeds, evidence, cli) with
      `squawk.py` kept as the entry point so nothing you type changes; CLI
      subcommands (`squawk run|doctor|serve|stop|status|feeds|update`) with the
      current flags kept as aliases; `pyproject.toml`, a CHANGELOG, `mypy` in
      CI; a zipapp build so one-file distribution survives the split. This is
      the structural fix for "written like a high schooler": it changes how the
      code is organised, reviewed and shipped, not what it does. Big, staged,
      and should come before more features pile onto the monolith.
- [x] **Durable decisions.** *Done:* every triage mark is a line in an
      append-only ledger in the evidence store (who, when, which run, target,
      scanner, rule, status, note, the identities covered); the current state
      is the last line covering a finding; it shows on every later run of that
      target in Triage and Findings, and never on another target. A rule that
      gained instances since it was reviewed reads *reviewed 3/5*, not
      reviewed. `resolved_on` and the regression flag are persisted per run
      (below). Was: triage state in the browser's localStorage (defect 5).
- [x] **Tamper-evident evidence.** *Done:* `schema_version` on the manifest,
      digest and history document; `digest.json` written last over the sha256 of
      every other file in the run, plus the previous run's id and digest hash;
      the decisions ledger chained line to line; `squawk verify` walking both
      and naming the first thing that does not hold, exit 0/1/**3** so a run it
      could not check never reads as a pass. A finished run is sealed 0400 as a
      tripwire. Retention leaves a tombstone carrying a removed run's digest
      hash, so pruning does not break the chain and deleting the record of a
      prune does. No signatures: it proves the evidence was not edited, not who
      wrote it, and the command says so on its own output. *Second pass, same
      day:* an adversarial review fooled the first version four ways with exit
      0 (a deleted manifest, a forged `pruned.json`, a hand-written tombstone,
      the newest run rewritten). Closed: a run is any directory that was ever
      a run; the retention record at the root is chained and is the only
      authority on what was pruned, its vocabulary limited to what retention
      can trim; a recorded verify anchors the newest run and the newest ledger
      line and remembers every run it saw; removals are listed, not trusted.

**Tier 2, what practitioners expect to find**

- [x] **A threat intel page.** *Done:* `/intel` answers the estate-wide
      question Priority could only answer per run — what is being exploited,
      out of what you actually run. KEV for exploited now, EPSS for likely
      soon, both stating their denominator; the CVEs on neither list counted
      rather than hidden; a vanished target's CVEs excluded and said to be.
      `squawk feeds --intel` caches OSV and NVD detail per CVE with URL, size
      and sha256, and the detail page renders the CVSS vector in words, the
      weakness ids and the references with exploit-typed ones first. A page
      never fetches; detail that has not been fetched reads *unknown, not
      absent*. A second view, `?scope=feed`, answers the general question —
      what is being exploited, whether or not you run it — out of the same
      cached catalogue: new KEV entries, the ransomware-flagged subset, the
      highest EPSS scores, and vendor concentration, each row saying whether
      it is in what you have scanned and a banner saying that is coverage, not
      exposure. *Left:* ATT&CK technique mapping, which needs a 30 MB feed and
      a mapping most scanners do not publish, and a watchlist.
- [x] **An estate-wide findings view.** *Done:* `/estate`, one row per
      `(scanner, rule)` across the newest run of every live target, grouped by
      the same key one run's Findings page uses. Filters for severity, scanner,
      target and status, a search over title, rule, identity and path, a sort
      control, and fifty rows a page with every count stating what it is out
      of. A vanished target is excluded and counted; a run with a coverage gap
      is included and flagged. The Overview's critical tile, open-findings tile
      and all five legend counts link into it filtered, which is what made
      "every number links to its proof" answerable.
- [ ] **Exports: SARIF, CSV, JSON.** Phase 4, unchanged.
- [ ] **Suppressions as VEX, with expiry.** Phase 2, unchanged.
- [ ] **Scheduled runs and a notification** (a timer unit, generated; a local
      notification or exit code). Phase 2c. The service unit shipped here is
      the first half of "generated rather than described".
- [ ] **An Instrument page in the web UI**: what `--doctor` prints (scanners,
      database and feed ages, identity, service status, log tail), so the
      tool's own health is not CLI-only. *Part of it landed with plan 02:* the
      Overview closes with an **Evidence integrity** card and `/healthz` carries
      `verify_status` and `verified_at`. The rest is still CLI-only.
- [x] **A config file** (`squawk.toml`) with environment overrides and
      `squawk config show`. *Shipped 2026-09-07:* a
      profile per service, target or scanner for timing, budgets and
      `extra_args`, found by `--profile`, `SQUAWK_PROFILE` or the evidence
      root; every changed value printed before the run, carried in the
      manifest and shown on the run page; unsafe or unknown values refused
      by name before any stage runs.

**Tier 3, finish**

- [ ] A template layer for HTML instead of string concatenation; error cards
      with a correlation id instead of a raw traceback; an optional structured
      (JSON) log; pinned scanner versions in the installer, and the AWS CLI
      shipped by it.

Deliberately not on the list: multi-user, auth, a shared server, an agent, a
CI product. See *Deliberately not doing*.

## Long term, and what shapes the plan

Not work to schedule. Direction of travel, recorded so the near-term choices are
made with it in view rather than against it.

**SBOMs stop being an intermediate artifact.** Today syft's output exists so
grype can read it, and it is deleted with the run. The EU Cyber Resilience Act
makes a machine-readable SBOM a product obligation from **11 December 2027**,
with vulnerability reporting obligations starting **11 September 2026**. The
reader this is written for may well be the person at a small company who
discovers that lands on them. That does not mean building a compliance tool, and
this will not become one. It means an SBOM should be an **output you can keep and
hand over**, not a temporary file, and that costs almost nothing to do now and a
rewrite to retrofit.

**VEX becomes the expected way to say "not affected".** Which is why the
suppression work in Phase 2 emits it rather than inventing a format. A standard
that regulators, scanners and other tools already read beats a bespoke one that
only this tool understands, and the decision costs nothing today.

**Exploitability data is the leverage, and it is free.** KEV and EPSS are public
feeds. Anything that gets a solo operator from four hundred findings to the ten
that matter is worth more than any additional scanner, and adding a scanner is
the tempting move because it feels like progress.

**The instinct to resist.** Every item in Phase 3 widens what is read, and
widening produces more findings, and more findings without better ranking makes
the tool worse for the person it is for. Phase 2b exists to be done *before*
Phase 3, and if only one of the two ever happens it should be 2b.

---

## Gated on credential handling

Not scheduled, because the gate is the eight rules in `PRODUCT.md` rather than
effort. The load-bearing ones: provider credential chain only and never argv,
which is visible in the process table; read-only identities only; `--doctor`
names the identity before anything queries with it; evidence is never committed.

Authenticated DAST, private registry images, and anything that reads a cloud
account wait behind that.

---

## Deliberately not doing

Recorded so the question is answered once. See the charter for the reasoning.

- Remediation or write access of any kind
- Multi-user, auth, a shared server
- Log ingestion, alerting, detection runtime
- An agent deployed into the assessed estate
- Becoming a CI tool
- Writing scanners that already exist and are better

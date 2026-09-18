# Squawk — what it claims, who it is for, and what happens if it goes public

Not a business plan. There is nothing to sell and no intention to sell it. This
is the document that stops the project drifting into "a thing I built" and keeps
it as "a thing that makes a specific argument", because the argument is the part
worth being known for.

Written 2026-08-30. Revisit before any public release.

**Status: personal tool, developed in the private repository.** It stays there
until there is a version solid enough to stand on its own, which the release
gates at the end of this document define. Public release would be as a give-back
in the security repository rather than as a product, and it is a possibility
rather than a plan.

## The honest position on novelty

**The category is crowded. The stance is not.**

What is thoroughly built already, by people with more resources:

- Running many scanners and normalizing their output. DefectDojo parses more than
  500 tools, deduplicates, tracks remediation and maps to compliance frameworks.
  It is the reference implementation for this and has been for years.
- Aggregation, ranking, SLA tracking, ticketing. That is the whole ASPM product
  category, commercial and well funded.
- The scanners themselves. Semgrep, Trivy, Grype, Syft, gitleaks, checkov, ZAP.
  Nothing here competes with those and nothing should.

Wiring scanners together is a weekend for a competent engineer. **No part of the
orchestration is new, and claiming otherwise would be the first thing a reviewer
disproved.**

What appears genuinely under-occupied:

- **The problem is documented; the answer is not built into a general tool.**
  "When clean scans lie" is a known failure. There is academic work on it, and
  SVS-TEST exists as a research harness for detecting silent failure in
  SBOM-based vulnerability scanners. So this project did not discover the
  problem, and saying it did would be false.
- What I could not find is a general-purpose tool **organized around** it. The
  usual shape is: aggregate findings, then trust them. The unusual shape is:
  treat every zero as unproven until something demonstrates the scanner could
  still have found a thing.

The five mechanisms that make that concrete, as a combination:

1. **Canaries per scanner**, splitting two questions that get conflated: did the
   rules load, and can it still find something known to be findable.
2. **Three-state reporting**, where "unknown" is first class and never collapses
   into "pass".
3. **Auditing the instrument** — the machine doing the analysis is checked, not
   assumed, because a finding written to a world-readable directory has leaked
   and a timestamp from an unsynchronised clock cannot order two runs.
4. **Provenance on the toolchain** — what installed, from where, at what hash.
5. **Invariants enforced by a conformance suite** rather than asserted in prose.

**The claim to make, and it is defensible:** not "nobody has built a scanner
orchestrator", which is plainly false, but "the ones that exist ask what was
found, and this one also asks whether the finding process could be trusted."

**The claim not to make:** that this is better than DefectDojo. Different scope,
different user, different scale. Saying otherwise invites a comparison it loses.

## Why the gap exists, if the ideas are ordinary

They are ordinary. Anyone who has been lied to by a scanner thinks of canaries
within a week. The interesting question is not why nobody thought of it, but why
nothing ships it, and the answer is six structural reasons rather than one clever
insight nobody had.

**1. It has been built, privately, many times.** Every mature security team
eventually writes a canary after a scanner silently stops finding things. It
stays internal because it is glue wired to that team's stack, because releasing
plumbing earns nobody a promotion, and because by the time it works the incident
is over and everyone has moved on. Absence from GitHub is not absence from
practice.

**2. Verification falls in the gap between two layers.** DefectDojo *receives*
reports. It cannot check that a scanner ran correctly because it never ran it; it
sees an uploaded file and has to trust it. The layer that *could* verify is the
one that executes, and that layer is usually CI, whose job is a fast pass or
fail. So the capability sits in a seam, and both sides can reasonably call it the
other's problem. A local orchestrator that runs the scanners itself is one of the
few places the check is even possible.

**3. Vendor incentives point the other way.** "0 findings" is a clean bill of
health a customer can put in a report. "0 findings, unverified" is a support
ticket and a worse-looking product. No commercial scanner ships doubt about its
own output, and no aggregator wants to be the one telling you the tools you
bought might be lying.

**4. The maintenance is genuinely hard, and this is the honest answer to "is it
too hard".** The tool is not hard to maintain. The canaries are. Each is per-tool
and drifts with every scanner release, and a canary that stops firing because the
scanner changed its rules looks exactly like a scanner that broke. That is the
same failure one level up, and it is where projects that attempt this die.

The design has to assume canaries rot. A stale or unrunnable canary must report
**unknown**, never pass and never fail the build, which is the three-state rule
already in the charter doing the work it was written for. If a canary going stale
breaks someone's pipeline, they will delete the canary, and then the tool is back
to trusting zeros while claiming it does not.

**5. The value is invisible.** Nobody can demo a bug they did not miss. There is
no screenshot of a zero you can trust. Attention, funding and stars follow
visible output, and this produces confidence, which photographs badly.

**6. The people who feel it most can afford it least.** At one machine and one
person, verifying everything is cheap. At five hundred repositories and fifty
scanners, verification cost multiplies until it is the largest line item. So the
organisations with the worst version of this problem are the least able to adopt
this particular answer, and the ones who can adopt it have a milder problem.

### What that means for the claim

The claim is not invention. It is **discipline**: knowing what a trustworthy
negative costs and paying it, in public, consistently enough that it is enforced
rather than intended.

That is the weaker-sounding claim and the stronger one to make. Invention claims
are checkable and usually fail. A discipline claim is demonstrated by the
artifact itself — the charter, the conformance suite, the times a check caught
its own author — and cannot really be argued with, because it is right there in
the commit history.

## Who it is actually for

The security professional working without an enterprise security stack.

`PRODUCT.md` had this right from the start: an architect, engineer or analyst
assessing an estate with a laptop, read-only credentials if they are lucky, and
no Wiz, no Tenable, no Snyk — because procurement has not happened, or never
will. The first security hire at a two-hundred-person company. The consultant on
day one of an assessment. The engineer at a school district, a nonprofit, a city
government, where the tooling budget is zero and stays zero. The one-man shop is
in this audience; it does not define it.

An earlier version of this section said "the person doing security alone", which
shrank a professional audience into a personal one. The unifying trait is not
loneliness. It is the **absence of the platform** — and everything a platform
quietly provides: something correlating findings across layers, something adding
exploitability context, something noticing when a scan went wrong. Without it,
open-source scanners are the toolbench, and the practitioner is the only thing
standing between a wrong answer and a decision made on it.

That is what the guarantees here replace. The denominator, the three states, the
fix line on every gap, the refusal to let silence look like success — none of it
is scepticism for its own sake. It is the checking layer the platform would have
been.

It follows that the tool has to say what is wrong **unprompted and in plain
words**, because the reader may be answering to management this week and may not
know that a clean trivy scan can be a broken trivy scan. Anything that requires
already knowing the failure mode is written for the wrong person.

It is not for teams running a shared platform, not a CI gate, and not for anyone
who wants a dashboard. Two people means two copies.

## Can this be handed over, or is it only good for its author?

Checked rather than assumed. There is nothing personal in the code: no hardcoded
paths, no usernames, no host assumptions. `resolve_repo` walks up from wherever
it is run, the evidence root defaults under the running user's home, and the
installer works out its own package manager across seven of them. Single-user is
a deliberate boundary rather than a limitation — two people means two copies, and
that is written in the charter.

So the software hands over. The question worth asking is different: **would a
second person be able to keep it honest?**

### What rots, and who notices

| What decays | How fast | Who notices today |
|---|---|---|
| Vulnerability databases | Daily | The tool. Age is checked, staleness is a gap, and a database that was never built says so |
| Scanner output formats | Every few releases | **The tool, as of this change.** A report it cannot read is an error with a reason, not `0 findings` |
| Scanner CLI flags | Occasionally | The tool. The stage fails loudly and the run says which |
| Vendor install scripts | Whenever the vendor edits them | The tool. The sha256 of each is recorded, so a change between runs is visible |
| The host itself | Constantly | The tool. Clock, permissions, disk, PATH, code integrity |
| **Canaries** | Every scanner release | **Nobody yet.** They are not built. This is the honest hole |

The pattern is deliberate. Anything that decays should be something the tool
reports, not something the operator has to remember. A maintenance model that
depends on vigilance fails the first week the operator is busy, and the failure
is silent, which is the failure this whole project exists to refuse.

### The one that looked genuinely hard, until it did not

The first plan here was canaries, and canaries rot faster than anything else,
because each is tied to one scanner's rules. When a scanner changes what it
detects the canary stops firing, and **that looks identical to a scanner that
broke**. It is this tool's own problem one level up, it is a treadmill, and it is
probably why nobody has shipped this: you start with canaries, meet the
maintenance, and stop.

The way out is to stop asking the expensive question. A canary asks *can you
still find something I planted*, which needs a fixture per tool forever. Coverage
asks *what did you look at*, which is already in the output, has nothing to keep
in sync, and cannot go stale because it is derived from the run rather than from
an artifact.

**Findings are a numerator. Almost nothing publishes the denominator, and that is
where the lie lives.** A zero over nothing examined is not a clean result, it is
no result, and today both print the same string.

Measured rather than argued: semgrep with an empty ruleset reports 0 findings
over **0 files scanned**; with real rules on the same tree, 0 findings over **6
files scanned**. Same finding count, and the denominator tells them apart. Trivy
pointed at a directory it could not resolve returned a valid, clean-looking
report with zero `Results` blocks.

That demotes canaries from the strategy to the last tenth of it: a detection test
against a corpus somebody else maintains, run when the toolchain changes rather
than when the target does. And the rule that keeps even that survivable is the
one already in the charter — a test that cannot run reports **unknown**, never a
pass and never a build failure, because a rotting fixture that breaks a pipeline
gets deleted within a week.

### What a second person would still need from the author

Honestly, not much of the code, and most of the reasoning:

- **Why a zero is suspicious.** Without that, every guarantee here reads as
  ceremony and gets stripped out the first time it is inconvenient. That is what
  `CHARTER.md` is for, and why it names an enforcing test for each rule rather
  than asking to be believed.
- **What the alarm codes mean.** Documented, and the codes are aviation rather
  than invented, so the metaphor carries itself.
- **Which trade-offs were deliberate.** Read-only, loopback-only, single-user and
  no CI are decisions with reasons, not gaps waiting to be filled. Written down
  so that scope creep has to argue with something.

Two kinds of reader take this on without argument. People who have run an
infrastructure vulnerability programme already know a clean scan can mean a
broken scan; validating the scan before trusting the findings is established
practice there, and they need no convincing at all. And people working alone,
who feel the absence of a second reviewer whether or not they can name it.

The reader it does not survive is the one who believes a clean scan is a clean
scan and has never been shown otherwise. That reader strips all of this out as
overhead the first time it is inconvenient. Which is the argument for the tool
explaining itself as it goes rather than assuming the premise, since the person
who most needs it is often the one who has not met the failure yet.

## What success looks like, given nothing is being sold

Ranked. The first is the only one that matters.

1. **The argument travels.** Somebody who has never run the tool changes how they
   read a zero. A write-up that gets quoted does this better than a repository
   that gets starred.
2. **It is credible under inspection.** Someone senior reads the charter and the
   tests and concludes the author knows what they are doing. This is the career
   asset, and it is already mostly built.
3. **A handful of real users.** Ten people who run it monthly is a success. Not
   a thousand who star it and never clone it.
4. **Contributions.** Genuinely optional. Most projects at this size get none,
   and planning for them is planning for a thing that will not happen.

What is explicitly not success: stars, adoption metrics, any revenue, or being
called innovative by anyone who has not read it.

## What is likely to happen on release

Stated plainly, because the realistic case is not the hoped-for case.

**The most likely outcome is quiet.** The median security tool released on GitHub
gets a few dozen stars, a handful of clones, no issues and no contributors. Being
correct is not distribution. If it is released and nothing else is done, that is
the outcome to expect.

**What actually moves it** is the writing, not the code. A post that names the
failure with real examples, shows the evidence, and links the tool will do more
than the repository will. The tool is proof the author is not theorising.

**The risks, and what each costs:**

| Risk | Likelihood | What it costs | What reduces it |
|---|---|---|---|
| Nobody notices | High | Time spent, no reputational loss | Lead with the argument, not the code |
| Name collision buries it | **Certain as things stand** | Discoverability, permanently | Rename before release |
| Released then abandoned | Medium | Real reputational damage, worse than never releasing | A bounded, written maintenance promise |
| Someone builds it better | Medium | The idea spreads, credit does not | Publish first, date it, be the clearest explanation |
| Issue and support load | Low at this size | Time, obligation | Issues off or a stated response window |
| A vulnerability found in it | Low, but it is a security tool | Credibility, if handled badly | SECURITY.md and a real disclosure path before release |
| Employer material leaks | Low, and already guarded | Serious, and not recoverable | The private-boundary gate; `docs/` never ships |

The abandonment risk is the one worth taking seriously. An unmaintained security
tool with a confident README reads worse than no tool at all, because it invites
someone to rely on it.

## What can and cannot be protected

**Cannot:** the idea. Canaries on scanners, three-state reporting and auditing
the instrument are concepts, and concepts are free to reimplement. If a vendor
reads this and ships it next quarter, that is legal and there is no defence.

**Can:**

- **The expression.** Copyright is automatic on the code and the writing from the
  moment it is written. It does not need registration to exist.
- **The name**, if a usable one is chosen. Rights come from use, not filing.
- **The attribution**, through the licence.
- **The record of having said it first.** Publishing is a defensive publication:
  it becomes prior art, which makes it harder for anyone to patent the mechanism
  later. Dated commits and a dated write-up are the evidence.

**Licence: Apache-2.0. Decided 2026-08-30, and in the tree.** It requires
attribution, includes an explicit patent grant that MIT lacks, and is permissive
enough that people will actually use it. Since the goal is credit and reach
rather than revenue, permissive is the right trade. AGPL was considered and
rejected: it would prevent a vendor absorbing the work without giving back, at
the cost of most of the adoption, and would be protecting revenue that does not
exist.

The `LICENSE` file is the canonical text fetched from apache.org rather than
retyped, verified at 11,358 bytes and sha256 `cfc7749b96f63bd31c3c42b5c471bf75`
`6814053e847c10f3eb003417bc523d30`. A truncated licence has happened here before,
on another repository, where GitHub then reported the project as NOASSERTION.
`NOTICE` carries the copyright line and states that the orchestrated scanners are
obtained from their own publishers under their own licences and are not vendored.

**For citability**, a Zenodo DOI on a tagged release makes the work referenceable
in a way a repository URL is not.

## The name

**"Squawk" is unusable.** It is taken several times over in the same audience: a
PostgreSQL migration linter that developers already know, a Sun Microsystems Java
virtual machine, a SQL query tool, a generative-AI package, and a Claude Code
monitoring tool. That is permanent discoverability loss, not a stylistic worry.

**Direction chosen: keep aviation. Candidate: `skinpaint`.**

In radar, a *skin paint* is detecting an aircraft from its own physical radar
return rather than from the reply its transponder chooses to send. It is what you
do when you cannot trust, or do not have, the target's self-report. That is this
tool's argument in two words, and it means the alarm codes stay coherent rather
than becoming decoration: the transponder reply is the self-report, and the skin
paint is the independent check.

Availability checked rather than assumed, on 2026-08-30:

| Candidate | GitHub name matches | PyPI |
|---|---|---|
| **skinpaint** | **8**, all zero-star Minecraft skin mods, none in security | **free** |
| primaryradar | 1 | free |
| nordo | 139 | free |
| modec | 379 | free |
| transponder | 266 | taken |
| airworthy | 7 | taken |
| crosscheck | 369 | taken |
| squelch | 139 | taken |

**The rename is deliberately not done yet.** Five pull requests are open for
review and a rename would conflict with every one of them. It happens once the
stack lands, in a single commit, and it touches the module, the services, the
environment prefix, the log name and the docs. The `SQUAWK_` environment prefix
already honours the older `TOWER_` prefix, so that pattern is established and the
next rename should extend it rather than break existing shells.

## Release gates

Nothing goes public until all of these are true. Each is checkable.

- [ ] **Phase 1 of the roadmap is done.** Canaries and provenance are the
      headline claim. Releasing before they exist means the README describes a
      tool that does not yet do the thing it is named for.
- [ ] **The name is resolved** and clear on GitHub and PyPI. Direction and
      candidate chosen; the rename itself is gated on the review stack landing.
- [x] **Licence file and NOTICE** in place, author named. Apache-2.0, canonical
      text verified by hash.
- [ ] **SECURITY.md** with a real disclosure route, since this is a security tool
      that reads source and runs scanners.
- [ ] **A maintenance statement**, bounded and honest: what will be fixed, what
      will not, and how quickly. "Best effort, security issues first, no feature
      requests" is a fine answer and better than silence.
- [ ] **The private boundary holds.** `docs/` and every reference document stay
      out. The existing gate enforces this; it gets re-run against the public
      tree specifically.
- [ ] **A README that leads with the argument.** Someone should understand why it
      exists before they learn what it installs.
- [ ] **One post written**, explaining the failure with real examples. The code
      supports the post rather than the other way round.

## The thing to be known for

Not the tool. The sentence.

**A security tool that did not run must never look like one that found nothing.**

Everything here is an implementation of that. If the tool is forgotten and the
sentence spreads, that is a better outcome than the reverse, and it should be
written and argued as if that were the plan.

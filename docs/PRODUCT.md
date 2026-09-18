# Squawk — what it is, and what it will never be

> The rules that must stay true while this is built live in
> [`CHARTER.md`](CHARTER.md), where each one names the test that fails when it
> is broken. The ordered plan lives in [`ROADMAP.md`](ROADMAP.md). This document
> is the definition the other two serve.

The product definition. `ROADMAP.md` says what gets built next; this says who it
is for and where the edges are, so scope stays deliberate.

## The user, and the moment

A security engineer who has just joined a team, or is assessing an estate they
did not build. Day one they have a laptop, read-only credentials if they are
lucky, no budget approved, no platform access, and three questions they are
expected to answer quickly:

1. **What do we have, and how bad is it?**
2. **What gets fixed first?**
3. **Is any of it actually getting fixed?**

Squawk is the instrument that person carries. Not a platform the org buys and
onboards — a tool the practitioner runs on their own machine, on day one, before
any procurement conversation has started.

## The four sources it reads

One normalized finding model, one identity scheme, four places findings come
from:

| Source | Covers | Status |
|---|---|---|
| **Code & repo** | SAST, secrets, dependencies/SBOM, IaC policy | built |
| **Running app** | recon (what's reachable) → DAST | built |
| **Cloud — native findings** | what the account already knows: Security Hub / Defender for Cloud, and everything feeding them | AWS built, Azure planned |
| **Cloud — direct queries** | the account's own resources, read through the API, and the combinations they add up to — the answer when native security is off | AWS networking + compute built; storage, IAM graph and serverless next |

The third and fourth rows are the point of this document. Most tooling assumes
Security Hub or Defender for Cloud is already enabled and that you have access to
it. On day one at a new org, often neither is true.

## Prior art, and what Squawk does not rebuild

The lesson from the first round: check what exists, then take a real niche.

- **[Prowler](https://prowler.com/)** — ~600 AWS checks across 84 services, 44
  compliance frameworks, multi-cloud, free, read-only, local CLI, JSON output.
  Cloud posture checking is a solved problem. **Squawk orchestrates Prowler; it
  does not reimplement cloud checks.** That is the same relationship Squawk has
  with semgrep, gitleaks, trivy and ZAP — a `SCANNERS` entry plus a normalizer.
- **ScoutSuite** — the other well-known auditor; not updated since May 2024.
- **DefectDojo** — the aggregator of record, but a server plus a database built
  for teams. Squawk is the single-user, zero-dependency shape.

**What no free tool does, and Squawk will:**

1. **One prioritized list across code, running app, and cloud.** Prowler is
   cloud-only; semgrep is code-only. Nothing correlates a hardcoded credential in
   the repo, an exposed endpoint from DAST, and a public storage bucket into a
   single ranked list with one identity scheme.
2. **Reading the findings the account already has.** Prowler *writes* to Security
   Hub; it does not read it. Ingesting existing Security Hub / Defender findings
   pulls in GuardDuty, Inspector, Config and any third-party integrations the org
   already paid for — the fastest possible answer to "what does this estate
   already know about itself."
3. **Remediation tracking over time, locally.** Prowler's CLI is point-in-time;
   trending lives in its paid cloud product. Squawk's stable identity keys plus
   immutable run evidence make open → resolved → regressed reconstructable on
   your own disk, for free.

## The hard boundaries — what Squawk will never be

Written down so scope creep has to argue with something.

- **Read-only. Always.** Squawk never writes to a cloud account, never remediates,
  never changes a resource. Auto-actuation is a different risk class entirely
  (see §2.12 of the peer-review standard) and Squawk does not enter it.
- **Single-user, loopback-only.** No auth, no multi-tenancy, no shared server.
  Two people means two copies. Team-scale aggregation is DefectDojo's job.
- **Not a SIEM.** No log ingestion, no alerting pipeline, no detection runtime.
- **Not an agent.** Nothing is deployed into the estate being assessed.
- **Not CI.** CI scans a fresh checkout on a clean runner; Squawk scans a lived-in
  tree and a live estate, which is why the contamination filter exists at all. It
  can export findings toward CI-adjacent tools; it does not become one.
- **Not a notary.** The evidence store is tamper-*evident*, not signed. See
  below.

## What the evidence chain proves, and what it does not

Every run writes `digest.json` last, holding the sha256 of every other file in
the run and the id and digest hash of the run before it anywhere in the store.
Every decision in the ledger carries the hash of the decision before it.
`squawk verify` walks both and names the first thing that does not hold.

**It proves:** no file in a verified run changed since the run wrote it; each
run proves the run before it existed at the moment it was written; a decision
edited, removed or forged into the sequence is detected and the changed line is
named. And once a verify has been recorded, it remembers: the newest run's
digest and the newest ledger line are covered from then on, and a run that was
there at the last verify and is gone now is `missing` unless retention recorded
removing it.

**What retention changes.** Retention may remove a run or trim its raw output.
Each act is recorded, before it happens, in a chained file at the root
(`pruned-runs.jsonl`), and `verify` reads that record — never the `pruned.json`
inside the run, which sits after the seal and is exactly what a forger would
write. A run removed with a record is **listed, by name, date and who**, every
time verify runs; a run removed without one breaks the chain. Only the parts
retention can trim (`raw/`, `history.json`) ever read as pruned; a record
claiming `findings.json` was trimmed is not a record of a trim.

**It does not prove:** who wrote it. There are no signatures, no keys and no
external timestamping. Anyone who can write the whole evidence root can rebuild
a consistent chain — and, more cheaply, can append a well-formed retention
record for a run they then delete. That is why the record is *listed* rather
than trusted: the reader recognises the prunes they did. This is tamper
evidence for the person holding the files, not proof of authorship to a third
party. Do not present a verified evidence root as attestable to someone who
does not trust the machine it sits on. The `verify` command prints this every
time it runs, rather than leaving it in a document nobody opens.

**The first version of `verify` was fooled four ways**, each reproduced with
exit 0 on 2026-09-06 by an adversarial review: delete a run's manifest and the
run vanished from every list; forge a `pruned.json` and a deleted file read as
pruned; hand-write a tombstone and a deleted run read as retention; alter the
newest run and rewrite its digest and nothing disagreed. All four are closed
and each is a test. The lesson is the charter's own: a check that reports
success must be asked what it cannot see.

A finished run is sealed read-only (0400). That is a tripwire — it makes an
accidental overwrite impossible and a deliberate edit a two-step act — not
evidence in itself; the digest is what detects a change.

## What runs now, and what waits on credentials

Capabilities split cleanly by whether they need a secret. Everything that reads a
local artifact works today. Everything that reaches a live estate or an
authenticated surface waits until credentials can be supplied safely — that is a
prerequisite, not a delay.

| Capability | Credential needed | Status |
|---|---|---|
| SAST, secrets, IaC policy, SBOM + CVE | none | available |
| Skill audit (AST10) | none | available |
| Container image scan | none for a locally built or public image | available |
| Recon + unauthenticated DAST against a local target | none | available |
| Cloud native findings ingest: AWS Security Hub | read-only cloud identity + `SQUAWK_CLOUD_ACK=1` | available, **not yet exercised against a real account**; [`CLOUD-SETUP.md`](CLOUD-SETUP.md) is the guide for doing so on a machine you do not own |
| Cloud inventory + toxic combinations: AWS networking, compute, attached roles | read-only cloud identity + `SQUAWK_CLOUD_ACK=1` | available, **not yet exercised against a real account**; works whether or not Security Hub is on |
| Cloud native findings ingest: Defender for Cloud | read-only cloud identity | waits |
| Prowler fallback posture | read-only cloud identity | waits |
| Authenticated DAST | app credential / session | waits |
| Private registry images | registry credential | waits |

The practical consequence: **if a build can be produced locally, Squawk can assess
it locally today.** Check out the repo and scan the tree; build the image and
scan the image; run the app in a container and probe it. None of that path needs
a secret, which is why it is the part that is finished first.

## Credential handling rules

Design constraints, not preferences. They apply to every credentialed capability
added from here on.

1. **Squawk never stores a credential.** It reads the provider's own chain —
   `AWS_PROFILE` / `~/.aws`, the `az login` token cache, `gh auth`. No Squawk
   config file holds a secret, there is no Squawk keystore, and no credential is
   ever passed as a command-line argument (argv is visible in the process table).
   A profile (`squawk.toml`) is held to this at load time: a value shaped like
   a credential, or a key named like one, is refused before any stage runs,
   and the value is never printed.
2. **Read-only identities only.** AWS `SecurityAudit` / `ViewOnlyAccess`; Azure
   `Reader` / `Security Reader`. Squawk's read-only promise is worth nothing if the
   identity it runs as can write.
3. **`--doctor` names the identity before you use it** — which cloud contexts are
   reachable, and as whom. You should know what you are about to query.
4. **Short-lived credentials preferred.** SSO / `az login` over long-lived keys. A
   long-lived key, where unavoidable, stays in the provider's credential file at
   `0600` — not inline in the environment, never in a repository.
5. **Evidence is sensitive and is never committed.** Run evidence carries account
   ids, resource names and finding detail. The evidence root stays outside the
   repository (default `~/scan-evidence`) and is git-ignored; secrets a scanner
   finds are stored redacted wherever the scanner supports it.
6. **No credential reaches a log, a report, or an identity key.** Identity keys
   are built from resource and check ids — never from a token or session value.
7. **Authenticated DAST config is generated per run and removed after.** The ZAP
   context holding a session exists for the run, not on disk afterwards.
8. **An explicit acknowledgement before any live estate is queried**, the same
   rail as the DAST private-target check. `SQUAWK_CLOUD_ACK=1` covers the
   estate the credential chain resolves to. Reading the machine's *other* AWS
   CLI profiles — which for a `role_arn` profile is an AssumeRole into an
   account you did not target, and for a `credential_process` profile runs the
   command it configures — is a second thing and takes a second
   acknowledgement, `SQUAWK_CLOUD_PROFILES_ACK=1`. Without it the run says the
   profiles were not asked, which is a different answer from none reaching
   anything. `cloud_max_profiles` bounds how many are asked, and the evidence
   records their names, so a run says which estates it touched.

## Built to the review standard

Squawk is developed against a peer-review standard, summarised for a
contributor in [`CONTRIBUTING.md`](../CONTRIBUTING.md). Branches, code and PRs are
written to pass it: default-block posture, evidence
for every claim, real tests rather than stubs, no secrets or wildcards, arg-list
subprocess calls, explicit error handling, docstrings, and live-vs-source
verification.

That last one is the standard's sharpest rule and it is also Squawk's thesis: **a
control that exists in source but is not enforced on the running system is not a
control.** The known open gap against §4 is that Squawk still has no committed
test suite — closing it is the next standards task, not an optional nicety.

## How cloud fits the existing seam

No engine rewrite — the same registry pattern as everything else.

- **New scopes** `aws` and `azure`, alongside `repo` / `dir` / `image` / `url`.
- **Native-findings stages** — `securityhub-findings` (ASFF) and
  `defender-assessments` (the `securityresources` assessment/subassessment pair),
  each with a normalizer mapping into `Finding`. The Security repo's
  findings-normalizer already parses ASFF and is reference for the mapping.
- **Fallback stage** — `prowler` (and later targeted direct queries: Resource
  Graph KQL, AWS `describe-*`) for when native security is off.
- **Identity keys** — account/subscription-scoped resource id plus check id, no
  timestamps, no session data. Cloud findings then diff across rescans and feed
  remediation tracking exactly like code findings.
- **Credentials** — read from the environment (`AWS_PROFILE`, `az login`), never
  stored by Squawk. `--doctor` reports which cloud contexts are reachable and as
  which identity, so you know what you are about to query before you query it.
- **A rail** — running against a cloud account requires an explicit
  acknowledgement, the same shape as the DAST private-target rail. Querying
  someone's production estate should be a deliberate act.

## Prioritization — the ranked list

A severity dump is not a priority list. The rank is:

**severity × exposure × exploitability × blast radius**

- *exposure* — is it internet-reachable? (recon and cloud both answer this)
- *exploitability* — KEV / EPSS where a CVE is involved, not CVSS alone
- *blast radius* — production? shared? a data store? an identity boundary?

Same logic as `severity × frequency` in the detection work: you triage the
product, not the label.

## The first 90 days — the narrative it serves

- **Week 1** — `--doctor`, point at the repos and the cloud contexts, run the
  assessment. Output: what exists and what is exposed.
- **Weeks 2–4** — the prioritized list. Output: the "what we fix first"
  conversation, with evidence per finding.
- **Months 2–3** — rescan. Output: open → resolved with dates, regressions
  flagged. The "are we actually improving" report, backed by run history rather
  than assertion.

## Build order

1. **Native findings ingest, both clouds** — Security Hub (ASFF) and Defender
   assessments. Highest value per unit of work, reuses the normalizer pattern,
   and answers "what does this estate already know" on day one.
2. **Prowler as the fallback stage** — orchestrated, not rebuilt, for estates
   with native security off.
3. **Remediation tracking** — the long-term half, now spanning cloud too.
   *Shipped for code and app targets:* `resolved_on` and the regression flag are
   persisted per run, decisions live in an append-only chained ledger, and
   `/estate` carries first-seen and last-seen per rule across every target.
4. Targeted direct queries (ARG KQL / `describe-*`) where Prowler's answer is not
   the shape needed.

*The through-line: Squawk is the practitioner's instrument for assessing an estate
they inherited — code, app, and cloud in one ranked list, read-only, on their own
machine, with the history to prove whether it is getting better.*

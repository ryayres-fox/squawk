# Design — correlation and disagreement (Phase 1.5)

Status: design, not built. Written against the identity formats the normalizers
actually produce, verified by running the scanners against a planted target on
2026-08-30, not against how they are imagined to work.

This is the answer to a specific question: what does a security platform sell
that the scanners underneath do not? Wiz and Tenable do not out-detect
open-source scanners on the individual finding. What they sell is what happens *between*
the scanners: correlation across layers, exploitability context, and noticing
when a scan went wrong. Squawk already writes every input needed for the first
of those to disk, with stable identities, in one place. Nobody joins them.

## Why this is possible here and not in an aggregator

An aggregator receives one report at a time and deduplicates within a layer. It
never holds the whole estate's evidence at once with identities it can join
across layers. Squawk does, because a run writes every stage's findings to a
single directory keyed by stable identities. The join is a local operation over
data already on disk.

## The join keys are already there

Measured from the normalizers, not assumed:

| Scanner | Identity | Join dimension it carries |
|---|---|---|
| bandit | `test:file:line` | **file** |
| gitleaks | `rule:file:line` | **file** |
| checkov | `check:file:resource` | **file**, **resource** |
| trivy-config | `check:file:resource` | **file**, **resource** |
| grype | `vid:pkg:ver` | **package** |
| trivy (vuln) | `vid:pkg` | **package** |
| recon | `port:path` | **exposure** |
| zap | `plugin:path` | **exposure** (path/port) |

Three join axes fall out: **file**, **package**, **exposure**. Every correlation
rule below is a join on one of them.

## Part 1 — toxic combinations

A correlation is a finding whose evidence is other findings. It is registry
driven, exactly like `SCANNERS`, so a new rule is an entry and not a code change.

    class Correlation(NamedTuple):
        key: str
        title: str
        joins_on: str          # "file" | "package" | "exposure"
        requires: Tuple[str, ...]   # scanner kinds that must have RUN
        rule: Callable[[Dict[str, List[Finding]]], List[CorrFinding]]
        lift: str              # resulting severity, and why

Rules proven against the planted target:

- **Secret baked into every image.** A secret-class finding in file X (`bandit`
  B105 or `gitleaks`) + a Dockerfile that `COPY . .` (`trivy-config`
  `CKV_DOCKER`). Join on **file** being inside the build context. Fired on the
  target: `bandit B105:app.py:3` + Dockerfile `COPY . .`. Lift: two LOWs to HIGH,
  because a credential in source is bad, a credential in every published image
  is worse, and the reason is the join itself.
- **Exploitable and reachable.** A CVE in package P (`grype`) + the app that
  ships P is listening (`recon`). Join on **package** appearing in a reachable
  service. Lift depends on the CVE, but reachability is the multiplier no single
  scanner applies.
- **Exposed misconfiguration.** A public-ingress rule (`checkov` `CKV_AWS_24`,
  open SSH to `0.0.0.0/0`) + a public bucket in the same estate (`CKV_AWS_20`).
  Join on **resource** proximity. Neither is news alone; together they describe a
  reachable path.

Every correlation **cites its members**. The output is not a new opaque
"critical"; it is "critical *because* these three findings, and here they are." The
evidence chain the rest of the tool guards is preserved through the join.

## The charter makes this honest, and this is the novel part

A correlation joins findings from several scanners. If one of those scanners did
not run, the naive implementation silently does not fire, and a toxic combination
goes unreported because half of it was never looked for. That is I1 again, at
the correlation layer.

So a rule reports three states, like everything else:

- all member scanners ran, join present  ->  **finding**
- all ran, no join                         ->  **nothing** (a real negative)
- a member scanner did not run             ->  **`unknown`**: "cannot evaluate
  'exploitable and reachable' — recon did not run"

**No platform shows you this.** A graph tool renders the correlations it found
and stays silent about the ones it could not evaluate. Correlation *with a stated
denominator*, "these 4 toxic combinations, and 2 more I could not check because
recon was skipped", is the Phase 1 denominator argument one layer up, and the
part that would be genuinely new.

### The fourth state: it fired, and one leg was never scanned

Three states turned out not to be enough, and a live `compliance` run showed why.
A stage that runs and reads nothing is a **gap**, and a gap counts as having run.
That is deliberate — if an empty scanner pushed every combination needing it to
`unknown`, one bad path would erase real findings to protect a denominator.

But `gap` counting as "ran" means a combination can fire with one of its required
legs unscanned. It did: gitleaks read **0 bytes** of the target, and
`secret-in-container-build` fired anyway on bandit's `B105` plus a Dockerfile —
a high finding that named no gap. Every word of it was true, and a reader had
every reason to conclude a secrets scanner had looked at that tree. It had not.

So the rule keeps firing and carries what it could not check:

> a secret (app.py) sits in a tree that builds a container image; if the
> Dockerfile copies it, it ships in every image — **gitleaks read nothing this
> run, so the secrets leg of this rests on the members cited, not on a scan**

A kind counts as unread only when **every** stage reporting it came back empty.
`iac` is checkov *and* `trivy config`; if checkov read the tree, the iac leg was
read, and claiming otherwise would put a false caveat on a true finding — the
same failure with the sign flipped. `TestCorrelationStatesItsDenominator` drives
both directions off the scanner registry, so a rule written later inherits the
guarantee instead of having to remember it.

## Part 2 — disagreement as the detection test

This retires the last of the canary idea. The toolbench has built-in redundancy:

| Overlap | Same input |
|---|---|
| trivy (vuln) vs grype | the SBOM / dependency set |
| semgrep vs bandit | Python source |
| checkov vs trivy-config | Terraform |
| gitleaks vs bandit B105 | hardcoded secrets |

Two scanners looking at the same input and disagreeing sharply is a detection
test that needs no fixture and cannot go stale, because the scanners maintain
themselves. Measured on the target: **bandit found the hardcoded password
(B105:app.py:3); gitleaks found nothing on the same file.** That disagreement is
a true signal, since a weak-entropy literal slips gitleaks' rules, and it
surfaces a coverage gap no planted canary was needed to reveal.

The rule: where two scanners cover the same input, a large asymmetry (one finds
many, the other zero) is reported as a **health finding** against the silent one,
not as a vulnerability. "grype: 9 CVEs from this SBOM; trivy: 0 from the same
tree, so one of these is degraded." It reports `unknown` when only one of the pair
ran, because there is nothing to compare against.

This lets the Phase 1 residual, "a detection test against an external corpus",
shrink or disappear. Disagreement is a continuous detection test that comes free
with running the scanners you already run.

## What this is not

- Not a graph database. Joins are over one run's findings in memory. Estate-scale
  graphs are a platform's job, at a platform's cost.
- Not machine learning. The rules are stated and auditable, because a correlation
  you cannot explain is a number to take on trust, which is what this refuses.
- Not exhaustive. It fires the rules written. A rule not written is a gap, and
  the honest move is to say which combinations are checked, the way services
  already declare `not_covered`.

## Build order

1. Load a run's findings grouped by scanner (exists — `load_findings`).
2. Index by join dimension: file, package, exposure.
3. The `Correlation` registry + the three-state evaluator.
4. Two or three proven rules above; each cites members; each carries a fix line.
5. Disagreement pass over the redundant pairs.
6. Correlations are findings, so they inherit identity, evidence, history and
   ranking for free. A regressed toxic combination is a regression like any other.

## Exit criterion

On a target with a secret in a file the Dockerfile copies, the run reports one
HIGH correlation citing both member findings, and if `trivy-config` was not run
it reports that combination as `unknown` rather than staying silent. Both
behaviours are the point; the second is the one nobody else does.

## The severity scale

Written down because it was not. The same fact carried a different weight
depending on which stage noticed it: a public address behind an open group was
nothing on an EC2 instance and HIGH on an ECS task; an endpoint open to the
world behind Kubernetes authentication was CRITICAL while port 22 open to the
world behind SSH authentication was HIGH. HIGH meant "one flag" in storage and
"a verified path" in networking, and a reader learned which by reading the code
(review R-16).

Four levels, and two words that are not levels.

**`critical` — a verified path, with nothing left in the way.** A route from the
internet, or from outside the account, to data or to more permission, where
every leg was read and no guard remains that this tool can see. It is reserved
for combinations. No single setting earns it, because a single setting is
almost never the whole story, and a scale whose top level fires on one flag has
no top level.

**`high` — a verified exposure with one guard left.** The path is real and
something still stands in it: an authenticated door (SSH, Kubernetes, a
database engine, the handler behind an API route), or a fallback that would
limit the damage. Also a single credential missing its second factor. This is
where most true findings live, and it is the level that says "look at this
today" rather than "stop what you are doing".

**`medium` — it would expose the day a guard someone controls is removed.** A
public bucket policy held shut by a public access block. A `*` principal
narrowed by something weaker than an identity. The exposure is not live; the
configuration that produces it is, and the thing holding it back is a setting
somebody can change in one click.

**`low` — a hygiene fact worth a line and no urgency.** A flag with nothing
behind it. A missing web ACL. A cluster that is not logging. These are worth
knowing and are not worth an evening.

**`unknown` is not a severity.** It is what this tool says when a reading could
not answer the question, and it exists so that a refused read never renders as
a clean one (I1, I14). **`info` is not a severity either.** It is a fact that
was recorded because a count on the page would otherwise be unexplained.

Two placements are deliberate and were argued about:

- **An EKS endpoint open to `0.0.0.0/0` is `high`, not `critical`.** Its blast
  radius is larger than one host's — compromise reaches every workload in the
  cluster — and blast radius is not an input to this scale, because Squawk does
  not read what runs in the cluster and would be guessing. What it reads is
  that a door is on the internet and that Kubernetes authenticates it. That is
  the same shape as SSH on port 22, and it gets the same weight.
- **An ECS service that assigns public addresses is judged like an EC2
  instance.** An address and a route are two legs; the third is a rule someone
  can connect over. Without that rule it is `low`, which is what an instance in
  the same position gets — nothing at `high`, and a note.

### Where every cloud rule sits

Rules whose severity is `unknown` are omitted: they are questions, not
findings, and every stage has one. `TestTheSeverityScaleIsWrittenDown` fails if
a rule in the code is missing from this table or carries a different level.

| rule | level | why it sits there |
|---|---|---|
| `administrative-reachable-from-outside` | critical | every leg read: a role holding a wildcard action, assumable from outside the account. Nothing else has to be true |
| `role-assumable-within-the-organization` | low | The role can be assumed from another account in the same AWS organization — most often `OrganizationAccountAccessRole`, which Organizations creates in every member account with AdministratorAccess and a trust on the management account. An organization is a trust boundary somebody chose, so this is stated rather than raised; what would make it a finding is the organization's own accounts being less tightly held than this one |
| `analyzer-own-federation` | low | AWS reports it as outside the zone of trust because the principal is federated, and the provider is one this account created — its own EKS cluster, its own GitHub Actions OIDC, its own SAML. That is how the federation works; what decides whether it is safe is the condition on the claim, read in the identity section |
| `analyzer-external` | medium | AWS says a named account or organization outside the zone of trust can reach it — narrowed, and not to us. The same weight the hand-rolled reader gives a `*` narrowed by an account key |
| `analyzer-public` | high | AWS's own evaluation says anyone can reach it, conditions included. For a bucket or a repository this is its contents, reachable — bad, and often the point of the resource, which is what keeps it below critical |
| `analyzer-public-credential` | critical | the same evaluation, on a kind where being public means a CREDENTIAL or a KEY anyone can use: a role anyone can assume, a KMS key anyone can use, a secret anyone can read. There is no guard left — that is what AWS means by public here — so it meets the critical paragraph as written. The old row said high because "the resource's own authentication is the guard left", which is not true of these kinds, and the IAM reader already files an administrative role reachable from outside as critical: one fact on one page carried two severities from two stages |
| `api-not-deployed` | low | the routes authenticate nothing and the API has NO deployed stage, so no endpoint answers for them today. Real, and not a door until somebody deploys it — which is one click, which is why it is stated rather than dropped |
| `api-stages-unreadable` | unknown | the routes authenticate nothing and whether any is deployed could not be read. Not open and not closed |
| `api-open-route-custom-domain` | medium | the default endpoint is off, so it is reachable only through a domain this does not read |
| `api-open-to-the-internet` | high | an unauthenticated door whose handler is unknown — API Gateway is not authenticating; the handler behind it may be |
| `reachable-admin-port` | high | the three legs a reader can check themselves: a running instance answers on a public address, its subnet routes to an attached internet gateway, and a group on it admits 0.0.0.0/0 on a port that administers or stores something. Every leg was read; what is left in the way is the service's own authentication |
| `reachable-over-permitted` | critical | the same three legs AND a role on the instance that can do far more than read. A foothold with credentials already attached, with nothing left in the way. Supersedes `reachable-admin-port` on the same instance, which is why that one is named in its `supersedes` rather than dropped |
| `bucket-public` | high | AWS evaluated the policy and said public. Being reachable is often the point of a bucket, so it is not critical on its own |
| `bucket-public-policy-blocked` | medium | it would expose the day the block someone controls came off |
| `bucket-public-unencrypted` | critical | public, and no fallback if the policy was a mistake. The second fact is what makes it a path |
| `cloudfront-plaintext-origin` | medium | the hop behind the edge is in the clear; the edge itself is not open |
| `cloudfront-without-waf` | low | hygiene. A distribution without a web ACL is ordinary |
| `credential-nothing-to-guard` | info | a recorded fact, not a severity: there is no credential for MFA to guard |
| `credential-without-a-guard` | critical | a credential that exists, no second factor, and a permission that grants more. Every leg read |
| `credential-without-mfa` | high | a credential that exists with one guard missing |
| `database-public` | high | three legs read: the flag, a group admitting the world on its port, a subnet that routes. The engine's own authentication is the guard left |
| `database-public-flag` | low | the flag with nothing behind it. It is what would let it become reachable |
| `database-public-unencrypted` | critical | reachable, and no fallback |
| `ecs-service-public-address-no-open-rule` | low | an address and a route, and no rule anyone can connect over. The same answer an instance in this position gets |
| `ecs-service-public-address-ordinary-ports` | low | address, route and a world-open rule, but on no administrative or database port. An instance in the same position produces nothing; what is left is the task's own listener, which is not read. Stated because the address is what would matter the day a rule opened |
| `ecs-service-with-a-public-address` | high | address, route and a world-open rule ON A SENSITIVE PORT — judged by the same rule as an instance, which is what "judged exactly like an instance" has to mean. A group whose contents were not read keeps this weight, because a missing input must not soften a verdict. The task's own listener is the guard left |
| `eks-api-open-to-the-world` | high | the control plane on the public internet, with Kubernetes authentication as the guard left. Deliberately the same weight as SSH on 22 open to the world |
| `eks-api-public-but-restricted` | low | public and narrowed to named addresses. Worth a line |
| `eks-without-control-plane-logs` | low | hygiene, and what makes an incident hard to investigate rather than more likely |
| `escalation-reachable-from-outside` | high or critical | critical when the role is already administrative, high when it can become so — the difference between a path and a shorter path |
| `internet-facing-lb-on-a-risky-port` | high | internet-facing and its group admits the world on an administrative or database port. The service behind it is the guard left |
| `lambda-url-without-auth` | high | an unauthenticated door whose handler is unknown, exactly as an API Gateway route is |
| `messaging-open-to-any-principal` | high or medium | high for a bare `*`; medium when narrowed by something weaker than an identity |
| `organization-mostly-unread` | info | a recorded fact about coverage, not about configuration |
| `private-api-open-route` | low | the API is private, so the open route is reachable only from inside |
| `registry-open-to-any-principal` | high or medium | the same split as messaging, and the same reason |

## How far a thing can be reached from

The scale above weighs what a finding means. This weighs who can get to it, and
the two are separate: a role anyone may assume and a role only this account may
assume can carry the same permission and are not the same finding.

One word per answer, ordered widest first. `REACH_RANK` in `squawk/probes.py`
holds the order, and `widest_reach` takes the minimum over a trust policy's
statements, because a role is as reachable as its loosest statement and the
tight ones do not make up for it.

| reach | who that is | why it sits here |
|---|---|---|
| `anyone` | a bare `*` principal with no condition that names a caller | the widest answer there is. Nothing has to be true for a stranger to try it |
| `external` | a named account or principal outside this account and outside the organization | somebody chose this, and the chosen party is not part of the estate |
| `unsettled` | a named account the run could not place | the organization answered and its account list was refused, so whether the account is a sibling or a stranger was never established. Wider than `federated` because the ceiling is `external` |
| `federated` | an identity provider this account created: OIDC, SAML, a Cognito pool, an EKS cluster | the door is real and the condition on the claim decides who fits through it, which is why `_federated_reach` reports the pin as well as the kind |
| `organization` | an account this run placed inside the same organization | a trust boundary somebody chose, and the run has the account list to prove the placement |
| `service` | an AWS service principal | the caller is the platform, acting on this account's own resources |
| `internal` | this account, and nothing else | the narrowest answer, and the only one that closes the question |

A trust policy that could not be read at all is `unknown`, which is not on this
scale: it is the absence of an answer rather than a wide one. `iam_caveats`
declares `unknown` and `unsettled` in separate sentences for that reason.

**The three unsettled rules carry `unknown` as their severity**, and that is
why they are absent from the table in *The severity scale* above:
`role-trust-unsettled`, `messaging-reach-unsettled` and
`registry-reach-unsettled`. `TestTheSeverityScaleIsWrittenDown` skips any rule
whose only level is `unknown`, so a rule that says "this was never established"
is not asked to name a weight it does not have. A rule that later gains a real
level has to join the table, and that test is what notices.

## Where this scale is still arguing with itself

Written down rather than left for the next reader to rediscover (review 2,
R-34).

**Blast radius is counted in some rows and excluded in others, and this
document does not defend the difference.** `bucket-public-unencrypted` is
critical because there is no fallback if the policy was a mistake;
`credential-without-a-guard` is critical because the permission grants more.
Both are impact counted as a leg. `eks-api-public` is high, and the argument
for keeping it there — that Kubernetes authentication is a guard and blast
radius is not an input — excludes the same reasoning those two rows rely on.

The honest position is that the four paragraphs describe how much was READ and
how little is left in the way, and impact keeps arriving as a tiebreak without
being named as one. PRODUCT's second question is "what gets fixed first", which
a scale with no impact input cannot answer and a scale with an unstated one
answers inconsistently.

This is the operator's call and it is not made here. What this file will not do is
settle it silently in one row at a time.

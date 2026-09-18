# Squawk — reading AWS Security Hub, on a machine you do not own

This is the guide for pointing Squawk at a real AWS account for the first
time, written for someone who has not used it before. It is deliberately
cautious, because the machine most people have an account on is a work
machine, and the evidence a cloud run writes is about an employer's estate.

**Read the last section before the first one.** *What is safe to send back*
matters more than any of the steps.

## What this does, and what it does not

Squawk's cloud service (`cloudaws`) **reads the findings Security Hub already
holds**, as whoever your AWS credential chain resolves to. That is the whole
of it.

It does **not**:

- scan any resource, reach any instance, or send a packet to anything in the
  account beyond the Security Hub API;
- enable Security Hub, Config, GuardDuty or anything else — if Security Hub is
  off in your profile's region, the run reads as a **gap**, never a clean zero;
- store a credential, write one to disk, or pass one on a command line. It
  runs `aws sts get-caller-identity` and `aws securityhub get-findings`, and
  the AWS CLI reads `AWS_PROFILE` / `~/.aws` itself (PRODUCT credential rules
  1 and 3);
- change anything. `get-findings` is a read. There is no write path in this
  service, and `TestReadOnly` in `test_charter.py` fails the build if a
  destructive token appears in any built command.

Two rails stand in front of it: the run is refused unless you set
`SQUAWK_CLOUD_ACK=1`, and it is refused again if the credential chain resolves
to nobody.

## Before you start

**Use a read-only identity.** AWS `SecurityAudit` or `ViewOnlyAccess` is the
right shape; `securityhub:GetFindings` is the permission actually used.
Squawk's read-only promise is worth nothing if the identity it runs as can
write (PRODUCT credential rule 2). Prefer a short-lived credential — SSO, or
`aws sso login` — over a long-lived key (rule 4). Step 1 tells you which you
have; it does not take your word for it.

**With SSO, export the profile.** `aws sso login --profile NAME` authenticates
that *named* profile. Squawk asks the CLI without naming one, so the CLI falls
back to the default profile — which usually has nothing, and `doctor` then says
`NoCredentials` even though you just logged in successfully:

```sh
aws sso login --profile NAME
export AWS_PROFILE=NAME          # ← the step that is easy to miss
python3 squawk.py doctor --evidence ~/squawk-work
```

Squawk takes no profile flag on purpose: a credential never travels on a
command line (rule 1), and the CLI reads `AWS_PROFILE` itself. Confirm the
CLI agrees before involving Squawk at all:

```sh
aws sts get-caller-identity          # names your identity, or says why not
```

**Keep work evidence in its own place.** Pass `--evidence ~/squawk-work` to
every command below. Work findings then never mix with lab runs, the digest
chain for each stays its own, and removing all of it afterwards is one
`rm -rf ~/squawk-work`.

**You need:** the AWS CLI on `PATH`, a profile that resolves, and Security Hub
enabled in that profile's region. Squawk itself needs nothing installed — the
cloud service uses no scanner, so a `doctor` full of missing-scanner gaps does
not affect it.

### Getting it onto the machine

Either shape works, and every command in this guide is the same in both.

**One file.** `./build-zipapp.sh` produces `dist/squawk.pyz`, about 600 KB.
Copy that across and run it directly — no clone, nothing installed, and it
writes only inside the evidence root you give it:

```sh
python3 squawk.pyz doctor --evidence ~/squawk-work
```

Read this guide from the repository, though: the documents do not travel
inside the zipapp.

**Or the checkout**, if you can clone the repository there. Then the guides sit
beside the code and `python3 squawk.py …` replaces `python3 squawk.pyz …`.

**Either way it needs Python 3.9 or newer**, and nothing else. Check first:

```sh
python3 --version
```

macOS ships 3.9.6 with the Command Line Tools, which clears the floor. If it
is older, every command will say so on stderr — it warns rather than refuses,
but a run below the floor is not covered by the test suite and should not be
treated as evidence of anything.

## 1 · Ask who you are, before using it

```sh
python3 squawk.py doctor --evidence ~/squawk-work
```

Look at the **AWS** block. With no credentials resolved it reads:

```
AWS (Security Hub ingest, read-only):
  gap  identity  none in the credential chain: aws: [ERROR]: An error occurred (NoCredentials): Unable to locate credentials.
  gap  ack       SQUAWK_CLOUD_ACK not set; a cloud run is refused until it is
```

With a profile resolved it names the identity, and then says what that
identity can do:

```
  ok   identity  arn:aws:iam::000000000000:role/ExampleReadOnly (account 000000000000)
  ok   read-only role ExampleReadOnly carries only SecurityAudit
```

That pair is the point of the step: **you see whose credentials you are about
to use, and what they can do, before you use them.** Nothing has been read
from the account beyond `sts get-caller-identity` and two `iam list-*` calls
about your own identity.

The second line has three states and never a plain yes or no:

| | |
|---|---|
| `ok   read-only` | every policy on the identity is one of the read-only managed ones, and there are no inline policies. |
| `gap  read-only` | something write-capable is attached — `AdministratorAccess`, `PowerUserAccess`, any `*FullAccess` — **or** the identity could not list its own policies and its own name says so, which is what an SSO role called `AdministratorAccess-<account>` is. The message says which of the two it used, because a policy list and a role's name are not the same quality of evidence. |
| `?    read-only` | it could not be established. Said as "could not tell", not guessed either way. |

**On how long it takes.** The service tile says `~1-3min`, which was a guess
made before it had ever met a live estate. The first one it did meet took
longer than ten minutes and was still going, so treat that estimate as
unmeasured and give a large estate `stage_timeout = 3600` from the start.

**A `gap` does not stop the run.** You may have no other identity, and the
run is still only a read. But it is printed on the run and it is the reason
to ask for a `SecurityAudit` role before doing this regularly.

If it names an identity you did not expect — the wrong account, or write
access you did not intend to be using — stop here and fix the profile. That is
what this step is for.

## 2 · The acknowledgement

A cloud run is refused until you say, in the command, that you know it queries
a live estate:

```sh
python3 squawk.py run cloudaws --evidence ~/squawk-work
```

```
Refusing cloud query: set SQUAWK_CLOUD_ACK=1 to acknowledge that this reads a
live AWS account, as the identity in your credential chain
```

`rc=2`, and **no run directory is written**. The same shape as the DAST
private-target rail: the tool will not query someone's estate because a
command was half-typed.

## 3 · The run

```sh
SQUAWK_CLOUD_ACK=1 python3 squawk.py run cloudaws --evidence ~/squawk-work
```

Expect, in order: the identity line, the target (which is the **account
number** — see the last section), the stage, and the coverage.

```
AWS identity: arn:aws:iam::000000000000:role/ExampleReadOnly (account 000000000000)
Service : AWS Security Hub (aws) · usually ~1-3min
Target  : 000000000000
  [1/1] awscli    securityhub … ok N finding(s) across M findings (P skipped)  ·  12s
```

`M` is every finding the account returned, **passed controls included** — the
denominator. `N` is the ones that are not passing, and `P` is the passed
controls, which are counted rather than reported. A low `N` against a high `M`
is a good result shown with its work; a low `N` with no `M` beside it would be
a claim.

## What good and bad look like

| What you see | What it means |
|---|---|
| `ok N finding(s) across M findings` | It read the account. `M` is the denominator. |
| `?? 0 findings, but examined 0 findings — Security Hub returned nothing: it may be off in this region, have no standards enabled, or this identity may not be allowed to see it — all three look identical here — not a clean result` | **A gap, not a clean account.** The line names all three explanations because the read cannot tell them apart, and the third is the one an operator is most likely to miss: a hub that is on with no standards enabled evaluates nothing and returns nothing. Squawk will not report this as clean (invariant I15). |
| `!! An error occurred (AccessDenied…)` | The identity lacks `securityhub:GetFindings`. Not a coverage statement — nothing was read. |
| `ok N finding(s) across M findings — a FLOOR, not a total …` | **The account holds more than the read asked for.** The read stops at `cloud_max_findings` (1000) so it answers in seconds rather than paging for an hour; the count is a floor and says so. Raise it with `[services.cloudaws] cloud_max_findings = 5000` if you want more, knowing what it costs in time. |
| `!! timed out after 600s · that is stage_timeout …` | **A large estate — measured, not hypothetical.** The first live estate this met exceeded ten minutes. `get-findings` paginates a hundred findings per call, and the CLI keeps going until it has them all. Raise the budget with `[services.cloudaws] stage_timeout = 3600` in `squawk.toml`; the message names the section and a value. |
| `SQUAWK 7600` | A source did not report. On a one-stage service that means the stage above failed; the alarm exists so a failed read never reads as a clean estate. |

An estate with tens of thousands of findings returns a large JSON document,
and it is written to `raw/` in full. That is deliberate — the evidence is the
scanner's own output — but it is worth knowing before you run it on a big
account, and it is the reason for a separate evidence root.

## What is safe to send back

**Everything a cloud run writes is about your employer's estate.** Account
number, role ARN, resource IDs, region names, finding titles, and the raw
Security Hub document. It stays on that machine unless you move it. Squawk
sends nothing anywhere — it is loopback-only and has no outbound path — but a
screenshot or a paste is you moving it.

Squawk masks the account itself now — the CLI and the pages show
`********0000`, and only the evidence on disk holds the whole number. That
removes the commonest way to leak it, and it does not remove the rest of what
is on those screens.

**Do not send:**

- `doctor`'s AWS block — it prints the ARN, and the role name in it can name
  a team or an environment;
- the identity line from a run, for the same reason;
- a screenshot of the **Overview** or **Findings** — a cloud run's *target* is
  the account number, so it becomes a target name on those pages;
- anything from `raw/` — that is the Security Hub document itself;
- finding titles or resource IDs, which name real systems.

**Safe to send, and enough to tell whether it worked:**

- the exit code;
- the stage's status word — `ok`, `gap` or `error`;
- the **shape** of the coverage line, with the numbers if you are comfortable
  and `N`/`M` if you are not: `ok N finding(s) across M findings`;
- any error message **with identifiers replaced by `<redacted>`** — the AWS
  error code (`AccessDenied`, `InvalidAccessException`) is the useful part and
  carries nothing about the estate.

If in doubt, describe it rather than paste it. A sentence saying "the stage
read `gap` and said Security Hub was not enabled in that region" is worth as
much to me as the output, and gives away nothing.

## Afterwards

```sh
rm -rf ~/squawk-work
```

That removes every run, the raw documents and the log. Nothing else on the
machine was touched: Squawk installed nothing, wrote nothing outside that
directory, and holds no credential to revoke.

## Where this goes next

This is the read half. What a credentialed capability needs before it grows: profile selection without argv, a three-state read-only check
on the identity itself, Azure's Defender for Cloud, IAM Access Analyzer. None
of it is built, and the plan is explicit that it stays unbuilt until there is
a read-only identity to build it against — which is the exercise this guide
exists for.

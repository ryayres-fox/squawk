# Security policy

Squawk reads live cloud accounts, shells out to other programs, and serves a web
page. Those are three ways to be wrong that matter, so this document says how to
tell us, what counts, and what you should expect back.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting** — the *Security* tab of this
repository, *Report a vulnerability*. It opens a private thread with the
maintainer; nothing is public until there is a fix or a decision not to fix.

Do not open a public issue for a vulnerability. If private reporting is
unavailable to you, open a public issue saying only *"I have a security report
and need a private channel"* — no detail — and you will be given one.

Include, as far as you have it: what you ran, what you expected, what happened,
and the smallest thing that reproduces it. A run id and the matching evidence
directory are the most useful thing you can attach, minus anything real —
see *Before you attach evidence* below.

## What counts as a vulnerability here

The obvious ones, and one that is specific to this tool.

- **A write.** Squawk is read-only (charter I3). Any path that creates,
  modifies or deletes anything in an assessed account or target is a
  vulnerability, not a bug, however small the change.
- **A credential leaving where it belongs.** A credential on a command line, in
  evidence, in a log, on the page, or passed to a child process that should not
  have had it.
- **Anything reachable off the machine.** The server binds loopback and refuses
  a non-loopback `Host` (`421`). A request from another machine that gets an
  answer is a vulnerability.
- **Evidence that can be changed without `verify` saying so.** The whole point
  of the digest chain is that editing evidence is detectable. A way to edit,
  delete or forge evidence that `squawk verify` still passes is a
  vulnerability. Four such ways have been found and fixed; assume there are
  more.
- **A false clean.** *This is the one people do not expect.* Squawk exists to
  refuse one substitution: **a tool that did not run must never look like a
  tool that found nothing.** If you can make Squawk print a clean result — an
  empty finding list, a green stage, a zero — over something it did not read,
  could not read, or read wrongly, that is a security vulnerability in this
  tool and it is the report we most want. Two hostile reviews have found
  several; the class is sampled, not closed.

## What does not count

Not because they do not matter, but because they are not ours to fix.

- **A finding a scanner got wrong.** Squawk drives `semgrep`, `bandit`,
  `gitleaks`, `trivy`, `grype`, `syft`, `checkov` and `zap`. A false positive or
  a missed vulnerability from one of those belongs to that project. What *is*
  ours: mis-reporting what the scanner said, or reading its silence as a clean
  result.
- **Anything that needs write access to the evidence root.** A person who can
  write your evidence directory can rebuild a consistent digest chain. `verify`
  is tamper evidence for the person holding the files; it is not proof of
  authorship to a third party, and it says so every time it runs.
- **Running it against a target you do not own.** Squawk refuses public DAST
  targets and requires `SQUAWK_CLOUD_ACK=1` before a live cloud read, but it
  cannot know whether you are entitled to the account your credential chain
  resolves to. That is yours.
- **A malicious fork.** The read-only guarantee for the cloud probes is held by
  a test that inspects every command the stages build. A fork that deletes the
  test has a tool that is not this one.

## Before you attach evidence

Evidence directories hold what was scanned. Squawk masks account identifiers on
every page, in the terminal and in the exported dashboard, and strips account
ids, key ids and addresses from the errors the AWS CLI returns before they
reach evidence.

**A finding whose subject is a credential does not carry the credential.** A
secret scanner records `secret: <rule>` and lets the path and line locate it,
and since 2026-09-18 a SAST or IaC rule that finds the same thing is held to
the same standard: its matched text reads "withheld", and a quoted literal is
removed from the message too, because bandit's own wording for a hardcoded
password is to quote the password. `findings.json` and every page built from it
are safe to share on that count.

**`raw/` is not.** Each scanner's output is written exactly as it arrived,
because an evidence chain over something rewritten proves nothing — and a
scanner that quotes the string it matched leaves that string there. `raw/` is
the one part of a run to read before you attach it. If you cannot share it, describe it: a
reproduction against a synthetic target is worth more to us than a real one we
cannot look at.

## What to expect

**This is one person's tool, maintained best-effort: security issues first,
bugs triaged as time allows, no commitment on feature requests.** Being honest
about that is better than a response time nobody can keep.

| | |
|---|---|
| First reply | within a week, usually sooner |
| Triage and a decision on whether it is a vulnerability | two weeks |
| Fix for anything in *What counts* above | as fast as it can be done properly, with a test that fails against the old code |
| Public disclosure | after the fix, crediting you unless you would rather not |

If a report gets no reply in two weeks, it has been missed rather than ignored —
say so on the same thread.

## Supported versions

Pre-1.0. **The newest release is the only supported one.** There are no
backports. Squawk has no dependencies, so updating is replacing one file or
pulling one repository.

## What this tool does not defend against

Written here rather than left to be discovered.

- **No authentication.** The web UI has none, because it binds loopback and is
  single-user by design (charter I4). Anyone who can reach the port can read
  every finding. Do not put it behind a reverse proxy; tunnel to it over SSH.
- **No multi-user model.** No tenancy, no roles, no per-user evidence. Two
  people means two copies.
- **No sandbox around the scanners.** Squawk runs them as you, with your
  privileges, against a tree you chose. It does not contain them.
- **Windows is not supported.** POSIX only; see the README.

# Sample targets — using Squawk to verify Squawk

The problem with testing a tool that judges other tools is circular: you cannot
trust its verdict to check its own verdict. The way out is targets with **known
properties**, where the expected output is documented by someone other than us,
so "did the scan produce what it should" has an answer that does not come from
Squawk itself.

Two kinds of target, for two questions:

- **Known-vulnerable** answers *does it find what is there.* A false negative
  here is the tool failing silently, which is the exact thing it exists to catch.
- **Known-clean** answers *does it stay quiet when it should*, and *does the
  denominator show a real number.* A false positive here teaches the operator to
  ignore the tool, which is worse than a miss.


Run `./lab-targets.py check` for the lab, `./smoke-test.sh` for the automated
subset, or the tables below by hand on the Kali box where every scanner is
present.

## The lab, with one command

`./lab-targets.py` brings up the container targets, writes
the file corpora and holds each service to the answer written beside its
target:

```
./lab-targets.py fresh    # Juice Shop :3000, DVWA :8080, VAmPI :5000 — loopback only
./lab-targets.py build    # the corpora, under ~/squawk-lab (SQUAWK_LAB moves it)
./lab-targets.py check    # one line per assertion, with the value it saw
```

`check` says `PASS`, `FAIL` or `SKIP` per line. A scanner that is not
installed makes its stage a gap and every assertion that needed it a `SKIP`
naming it — a skip is not a pass — and the last line counts all three.
Measured on macOS on 2026-09-07, where grype is not installed:
`35 passed, 0 failed, 4 skipped`, every skip naming grype. **On Kali the same
day, with grype present: `39 passed, 0 failed, 0 skipped`.** Expectations are
shapes — which rule ids appear, which must not —
for the reason under *What "expected" means*; the counts here are what was
measured, for comparison, not what is asserted.

| Target | Kind | Get it | What it exercises | Expected — verify against this |
|---|---|---|---|---|
| **Dockerfile corpus** `corpora/dockerfiles/{bad,good}` | known-bad and known-clean IaC | `./lab-targets.py build` | checkov + trivy-config (`compliance`) on one Dockerfile each | bad: checkov names `CKV_DOCKER_2`, `_3`, `_7` (no HEALTHCHECK, root, `:latest`) and trivy `DS-0001`, `DS-0002`, `DS-0026`; measured 11. good: **none of those ids**; measured 0. |
| **k8s manifest corpus** `corpora/k8s/{bad,good}` | known-bad and known-clean IaC | same | checkov + trivy-config on one pod each | bad: `CKV_K8S_16`, `_23`, `_19` (privileged, root, hostNetwork) and trivy `KSV-0017`, `-0012`, `-0009`; measured 43. good: none of those; measured 2 — `CKV2_K8S_6` (no NetworkPolicy) and `CKV_K8S_43` (image by tag, not digest), hygiene rather than the bad one's faults. |
| **lockfile corpus** `corpora/lockfiles` | known-CVE | same | trivy-fs, syft → grype and the differential (`baggage`) | trivy: `CVE-2018-1000656` and `CVE-2019-1010083` (flask 0.12.2), `CVE-2020-8203` and `CVE-2021-23337` (lodash 4.17.15); measured 11. grype: the same advisories under their GHSA ids — `GHSA-562c-5r94-xh97` and `GHSA-5wv5-4vpf-pj6m` (flask), `GHSA-35jh-r3h4-6jhm` and `GHSA-29mw-wpgm-hmr9` (lodash); measured 10 on Kali, 21 in all. The differential stays silent. One harmless `app.py` is in it so bandit and semgrep examine a file and the run is complete, not a gap. |
| **Juice Shop image** `bkimminich/juice-shop:latest` | known-CVE image | pulled by `fresh` | trivy-image, syft → grype (`cargo`) | trivy: CVEs across the image's npm packages, measured 128 across 8 scan targets. grype: 117 on Kali, CVEs on the OS packages first; 245 in all. The differential stays silent. |
| **OWASP Juice Shop** :3000 | known-vulnerable single-page app | `./lab-targets.py fresh` | recon, liveprobe, activeprobe | recon reports `3000:/`, `/api/`, `/rest/` and **`3000:catch-all`** — it answers every path with the same page, so DVWA, phpMyAdmin and TWiki are *not* reported at paths it does not serve (fifteen endpoints, one real, before 2026-09-07). ZAP: dozens; 44 on a prior run. The active probe's crawl budget is a profile setting (`zap_active_spider_minutes`), and the run prints the one it used. |
| **DVWA** :8080 | known-vulnerable, behind a login | same | recon | `8080:/` (its login redirect) and `/dvwa/` (403 — a real directory). No probe expectation until a profile can log it in. |
| **VAmPI** :5000 | known-vulnerable REST API with an OpenAPI in its repo | same | recon, liveprobe; `zap-api-scan` later | recon: `5000:/` only — it answers unknown paths with 404, so no catch-all. liveprobe: header findings `10036` (server version) and `10021` (X-Content-Type-Options), and the URL count on the ZAP line; measured 13 findings across 5 URLs on macOS, 11 across 5 on Kali. |

## The other targets

| Target | Kind | Get it | What it exercises | Expected — verify against this |
|---|---|---|---|---|
| **Squawk itself** (this checkout) | mostly-clean | already here | SAST on a real Python tree; the denominator on code that exists | Few findings, all with stable identities; **coverage shows a real file count**, not `unknown`. Dogfood target — run it every session. |
| **TerraGoat** | known-vulnerable IaC | `git clone https://github.com/bridgecrewio/terragoat` | checkov + trivy-config on 47 Terraform files | checkov finds **hundreds** (built by checkov's authors to trip it); trivy-config finds its own set. If checkov reports 0, the parser is broken — this is how the list-form bug was found. |
| **OWASP Juice Shop** | known-vulnerable app | `./lab-targets.py fresh` (was a bare `docker run`) | recon + DAST (zap) | recon finds the app on :3000 and reports its catch-all rather than phantom apps (row above); ZAP produces dozens of findings. Already proven: 44 real ZAP findings on a prior run. |
| **A pinned old dependency** | known-CVE | now the lockfile corpus above (`flask==0.12.2` plus lodash 4.17.15) | trivy fs + syft + grype | trivy/grype find **known CVEs** (measured: 9 from flask 0.12.2 alone on 2026-08; 11 with lodash on 2026-09-07). Zero here means the vuln DB is stale or the SBOM path is broken. |
| **An empty git repo** | known-clean-but-empty | `mkdir t && cd t && git init` | the empty-denominator gate | Every scanner reports a **gap**, "examined 0", and the run raises **7600**. Never a clean zero. |
| **A tiny hand-clean repo** | known-clean | one `.py` with no issues | false-positive rate; the real-denominator path | 0 findings, but **coverage shows the file count** so the zero is trustworthy, and status is `ok`, not `gap`. **Expect trivy to gap here** ("examined 0 scan targets"): a tree with no dependency manifests gives trivy nothing to scan, and per I15 that is reported as a gap, not a clean pass. Expected, not a bug. |

## What "expected" means, and what it does not

Expectations here are **coarse on purpose**: "checkov finds many," not "checkov
finds exactly 477." An exact count is hostage to every scanner's next release. A
rule-pack update moves it, and a test that pins it goes red on an upgrade that is
actually fine. The **shape** of the answer is stable and worth asserting:
found-many vs found-none, a real denominator vs unknown, a gap vs a clean pass.
Where an exact number matters (the flask CVE count), treat a change in it as a
prompt to look, not an automatic failure.

## The discipline this encodes

Every bug this file exists to catch was found by running the tool on real code,
not by a fixture:

- checkov's list-form output reported 477 findings as **0**, and no fixture
  caught it because every fixture used the single-dict form.
- checkov paths came out as `../../../../terraform/x.tf`, a machine-dependent
  identity, until a real repo showed the leading-slash convention.
- The 7500 alarm ("attack in progress") **false-fired on 53 static IaC checks**
  because their names contain words like "exfiltration", visible only on a repo
  with realistic check names.

The rule: **a fixture is the author's idea of the format; a real target is the
format.** Use both, and when they disagree, the real target is right.

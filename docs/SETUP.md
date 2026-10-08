# Squawk — setup and first run on Kali

A runbook from a fresh Kali VM to a DAST scan firing against a containerized
target. Each step carries a **Verify** line so the instructions are testable.
The VM, host-only network, and snapshots are in [`LAB-SETUP.md`](../dev/LAB-SETUP.md);
this is the software install and the run. 16 GB RAM is comfortable for Kali +
Docker + a target + ZAP.

## Prerequisites

- Kali up per [`LAB-SETUP.md`](../dev/LAB-SETUP.md), Python 3.9+.
- A way to fetch Squawk — **`git`** (to clone the repo) or **`wget`/`curl`** (to
  pull the two raw files). Install whichever you prefer first; Kali ships curl.
- `squawk.py` and `squawk-dashboard.py` must end up in the **same directory** —
  `squawk-dashboard.py` imports its counting logic from `squawk.py` and refuses
  to run without it.

**Verify:** `python3 --version` ≥ 3.9, and both files sit side by side.

> On Apple Silicon, VirtualBox is ARM-only and can't boot the x86 Metasploitable
> 2 disk — the target is a multi-arch container instead. Same recon, same DAST.

## Fetching Squawk onto the host

```bash
git clone https://github.com/ryayres-fox/squawk.git
git -C squawk pull        # later, to update
```

**Verify:** the clone lands `squawk.py` and `squawk-dashboard.py` together at
its root.

### If the repository you are cloning is private

This box runs offensive tooling near deliberately-vulnerable targets — treat it
as compromisable and give it the **least access that still works**. Do **not** put
your GitHub account's SSH key or a broad token on it. Use a **read-only deploy
key** scoped to that one repo: if the host is popped, the blast radius is read
access to a single repo, revoked by deleting one key.

Generate a repo-scoped key on Kali (set a passphrase), and add the **public** half
as a deploy key:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/squawk_deploy -C "kali-lab read-only"
cat ~/.ssh/squawk_deploy.pub
```

On GitHub: **repo → Settings → Deploy keys → Add deploy key** → paste the public
key → leave **Allow write access unchecked**. Then bind that key to the repo host
and clone over SSH:

```bash
cat >> ~/.ssh/config <<'EOF'
Host github-squawk
  HostName github.com
  User git
  IdentityFile ~/.ssh/squawk_deploy
  IdentitiesOnly yes
EOF

git clone git@github-squawk:ryayres-fox/squawk.git
```

**Verify:** `ssh -T git@github-squawk` reports authentication succeeded
(read-only).

Alternatives, in rough order of how much they trust the host:

- **Fine-grained PAT (HTTPS), read-only, scoped to this repo, with an expiry** —
  clone with a credential helper so the token never lands in a URL or
  `.git/config`. Narrower than account auth, but a token still reads as *you*.
- **`gh auth login`** (`sudo apt install -y gh`) — convenient, but it authorizes
  your whole account on this box; fine on a trusted workstation, poor on a lab
  box you detonate things near.
- **Just the two files, no clone** — `wget`/`curl` the raw blobs via a read-only
  token if you never intend to `git pull`. You lose easy updates.

If Kali is cloned from a golden snapshot, keep the private key **out** of that
image — generate it per clone, so one leaked snapshot isn't one leaked key.

## Docker and a target

```bash
sudo apt update && sudo apt install -y docker.io
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER" && newgrp docker

docker run -d --name juice -p 127.0.0.1:3000:3000 bkimminich/juice-shop
docker run -d --name dvwa  -p 127.0.0.1:8080:80   ghcr.io/digininja/dvwa:latest   # optional
```

The port is bound to `127.0.0.1` so the target is reachable by Squawk on this box
and nothing else.

**Verify:** `docker ps` shows the target **Up**; `curl -sI http://127.0.0.1:3000`
returns a status line.

## Coming back to the lab after a reboot

The containers survive a reboot in `Exited` state **and keep their names**, so
`docker run --name juice ...` fails with a name conflict and the target is not
listening:

```
docker: Error response from daemon: Conflict. The container name "/juice" is
already in use by container "4e3e885f…".
```

**Restarting the Docker service does not fix this.** The name is held by the
container object, not by the daemon — `systemctl restart docker` deletes
nothing, so the name stays taken. It would only *start* a container that carries
a restart policy, and by default none does.

Diagnose first:

```bash
docker ps -a --filter name=juice --filter name=dvwa --filter name=vampi --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
```

`Exited (0) …` means the container exists and is simply stopped. Then:

```bash
./lab-targets.py status     # what exists, and whether it answers
./lab-targets.py fresh      # destroy and recreate  <- before a scan
./lab-targets.py up         # just start what is there
./lab-targets.py down       # remove them
./lab-targets.py build      # write the file corpora under ~/squawk-lab
./lab-targets.py check      # every service against its target: PASS, FAIL or SKIP
```

The targets are Juice Shop on :3000, DVWA on :8080 and VAmPI on :5000, each
published on 127.0.0.1 only. `check` runs each service against the target
whose answer is written beside it in [`TARGETS.md`](../dev/TARGETS.md) and prints
one line per assertion with the value it saw; a scanner that is not installed
makes its lines `SKIP`, never `PASS`.

**Use `fresh` before measuring anything.** Juice Shop records solved
challenges, so a target you have been poking at is not the target you scanned
last week. Scanning a drifted target makes the diff describe your poking rather
than the code — the container equivalent of reverting a VM snapshot between
runs. Compare clean to clean.

`up` is the convenience path when you only want the lab back. If you would
rather they return on their own after a reboot, create them with
`--restart unless-stopped` — but then accept that the target accumulates state
between scans, which is the thing `fresh` exists to prevent.

If the daemon itself is down, the script says so and gives you the command:
`sudo systemctl start docker`.

## First proof — recon (no scanners required)

Recon is built in (standard library), so it runs before any scanner is installed.

```bash
python3 squawk.py --doctor
python3 squawk.py --run recon --target http://127.0.0.1:3000
```

**Verify:** `--doctor` ends `OK: enough is present to run.` (scanners mostly
`gap`, `recon` `built-in`). The recon run reports a `recon` stage `ok` with
findings and writes an evidence directory; **Findings** in the UI lists the
discovered apps, each with a **Probe (DAST)** button.

## DAST with ZAP (via Docker)

Kali's `zaproxy` package does **not** ship the `zap-baseline.py` wrapper — that
script only comes with the ZAP Docker image / full release. So Squawk runs the
baseline from the **official ZAP image**, which needs nothing installed beyond the
Docker you already have. Squawk pulls the image on first use (slow once), runs it
with host networking so the container's `127.0.0.1` is the host's target, and
mounts the run's evidence dir for the report.

```bash
python3 squawk.py --run liveprobe --target http://127.0.0.1:3000
```

**Verify:** `--doctor` shows `zap  ok  via docker (…)`; the `liveprobe` run pulls
`ghcr.io/zaproxy/zaproxy` on first use and produces a `zap` stage with findings
(Juice Shop surfaces several — missing headers, CSP, etc.). If you *do* have a
native `zap-baseline.py` on PATH, Squawk uses that instead automatically.

## The rest of the kiosk — let Squawk provision it

For the SAST / SCA / IaC / secrets / SBOM services, don't install six tools by
hand. Squawk fetches its own toolbench — idempotent and best-effort, in the spirit
of `discover`'s `update.sh`:

```bash
python3 squawk.py --install        # or: ./install-tools.sh
```

It installs `gitleaks`, `semgrep`, `bandit`, `checkov`, `trivy`, `syft`, `grype`,
and `gh` via apt / pipx / the tools' own installers, **skipping whatever is
already present** and continuing past anything that fails (that tool just stays a
gap). ZAP needs nothing — it runs from the ZAP Docker image. Read the script
before running it; a security tool shouldn't ask you to pipe an unread installer
into a shell.

**Verify:** open a new shell (so pipx's `~/.local/bin` is on PATH), then
`python3 squawk.py --doctor` shows the scanners `ok`. A tool that didn't
install stays a gap with its reason — re-run `--install` or add it by hand.
`--run preflight --repo <a-checkout>` then produces findings.

## What gets logged

Logging is **on by default** and is not optional. Squawk writes a rotating log
to `<evidence>/squawk.log` (5 MB x 5), in UTC to match run ids.

It records the invocation, server start, every HTTP request, every run and each
stage's outcome, and — the part that matters for an audit — **every refusal by a
security control, with its reason**: a non-loopback bind, a public DAST target,
a cross-origin POST. A control that refuses something and leaves no trace cannot
be shown to have fired, by anyone, including whoever wrote it.

The log carries tool names, statuses and counts. It does **not** carry finding
detail or anything credential-shaped.

**Verify:** `--doctor` prints the log path. If it prints `Logging: OFF` the
evidence root is not writable — fix that before trusting a run, because nothing
it does is being recorded.

```bash
tail -f ~/scan-evidence/squawk.log        # watch it while you work
grep REFUSED ~/scan-evidence/squawk.log   # every time a control said no
```

## Keeping it current

Scanner binaries age slowly; their **vulnerability data ages daily**. A tool at
the right version with a month-old database quietly finds fewer CVEs than exist
and still reports a clean run — the same substitution this tool exists to
refuse. So maintenance is a first-class command rather than something you
remember to do:

```bash
python3 squawk.py --update        # or: ./install-tools.sh --update
```

It updates the OS and apt-installed tools, upgrades the pipx scanners, re-runs
the syft/grype/trivy installers, **refreshes the trivy and grype vulnerability
databases**, and pulls the ZAP image. Best-effort throughout: one failure never
stops the rest.

Squawk itself is deliberately not updated by that command — changing the code
mid-run is its own hazard. Update it when you mean to: `git -C ~/squawk pull`.

**Verify:** `--doctor` gains a *Vulnerability databases* section reporting the age
of each database, and flags any older than 7 days as **STALE — findings
under-report**. A database that was never downloaded reads as a gap, not as
fresh.

## Reaching the UI

From the Kali desktop: `python3 squawk.py --open` (→ `http://127.0.0.1:8787/`).
From your workstation, tunnel to it (preserves loopback-only):

```bash
ssh -L 8787:127.0.0.1:8787 <user>@<kali-host-only-ip>
```

**Verify:** Overview loads; **Target recon** → **Probe (DAST)** completes with
findings.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `docker: permission denied` | not in the docker group yet | `newgrp docker`, or re-login |
| `Conflict. The container name "/juice" is already in use` | the container survived a reboot in Exited state and still holds the name; restarting the docker service does not clear it | `./../dev/lab-targets.py fresh` (or `docker start juice`) — see *Coming back to the lab after a reboot* |
| target exists but `curl` returns nothing | container is `Exited`, not running | `./../dev/lab-targets.py status` then `fresh` |
| `curl` to target refuses | container down, or port not on loopback | `docker ps`; republish with `-p 127.0.0.1:PORT:PORT` |
| recon finds nothing | wrong port/scheme, or not serving | confirm the port; try `http://127.0.0.1:3000/#/` for Juice Shop |
| `Refusing DAST target` | target host is not private | use `127.0.0.1` / `192.168.x` / `10.x`; a public target needs `SQUAWK_DAST_ACK=1` |
| `zap` shows `gap` | Docker not installed (and no native `zap-baseline.py`) | install Docker — ZAP runs from its image; nothing else needed |
| ZAP writes no report / permission denied on `/zap/wrk` | evidence dir not writable by the ZAP container's `zap` user | ensure the evidence root is writable (it's your own dir by default); the container's uid 1000 matches the first Kali user |
| first `liveprobe` is very slow | pulling `ghcr.io/zaproxy/zaproxy` | one-time image pull; later runs are fast |
| `apt` stuck: `wordlists` postinst `rm: cannot remove …/seclists: Is a directory` | the package expects a symlink but `seclists` is a real dir | `sudo mv /usr/share/wordlists/seclists{,.bak} && sudo dpkg --configure -a && sudo apt -f install`; confirm it's now a symlink, then remove the `.bak` |
| `--doctor` exits non-zero | no scanner, or evidence root not writable | install one scanner; check `~/scan-evidence` is writable |
| Metasploitable 2 won't boot | x86 disk on ARM VirtualBox | expected — use a container target |

### How Squawk runs ZAP (for reference)

You don't run this by hand — Squawk's DAST stage does it — but this is the exact
invocation, so you can reproduce or debug it: the ZAP image, host networking so
the container reaches the host's target, and the run's evidence dir mounted for
the report.

```bash
docker run --rm --network host -v "<run>/raw:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://127.0.0.1:3000 \
  -J zap-baseline.json -m 2 -I
```

If a native `zap-baseline.py` is ever on PATH, Squawk uses that instead
automatically.

## Start, stop, restart

The web UI is a process that serves on loopback. It can run in the foreground,
in the background, or as a service.

| Do this | What happens |
|---|---|
| `python3 squawk.py --open` | foreground; Ctrl-C stops it |
| `python3 squawk.py --daemon --open` | background; prints URL, pid, and the log path |
| `python3 squawk.py --status` | is it running, is it answering, since when, scans in progress |
| `python3 squawk.py --stop` | clean stop; a scan in progress is recorded as *aborted* under its target |
| `python3 squawk.py --restart` | stop if running, then start in the background |
| `python3 squawk.py --install-service` | writes a systemd user unit (Kali) and prints the enable commands |
| `curl -s http://127.0.0.1:8787/healthz` | JSON: ok, version, pid, runs, scans in progress |

After `git pull`, `--restart` is the whole procedure. The pid file lives under
the evidence root (`squawk.pid`, owner-only); one server per evidence root. A
background server's output goes to `squawk-serve.log` there; the tool's own log
is still `squawk.log`. A run that was interrupted for any reason is written up as
aborted the moment it happens, or at the next server start if it was killed
outright, so it can never look like a run that found nothing.

## Subcommands

Every flag has a subcommand spelling now; both work.

```
python3 squawk.py doctor
python3 squawk.py run customs --target /path/to/tree
python3 squawk.py serve --daemon --open      # or: --daemon --open
python3 squawk.py status | stop | restart
python3 squawk.py feeds | update | install | services | install-service | version
python3 squawk.py feeds --intel            # also per-CVE detail (OSV + NVD) for the estate
python3 squawk.py prune                    # what retention would remove; a dry run
python3 squawk.py prune --apply            # carry it out
python3 squawk.py verify                   # prove the evidence has not been edited
python3 squawk.py verify --json            # the same report as one document
python3 squawk.py config show activeprobe http://127.0.0.1:3000   # the profile, applied, without running
```

## A profile — budgets and options per target

Every budget used to be a constant in the code: five spider minutes on the
live probe, ten on the active one, a stage timeout nobody could see. A
**profile** sets them per service, per target or per scanner, and the run
says what it ran under. It is a file called `squawk.toml`, found in this
order: `--profile PATH`, then `SQUAWK_PROFILE`, then `squawk.toml` in the
evidence root (which is also what the web UI's runs use). No file means the
built-ins, and the run says so: `Profile : none — built-in values`.

```toml
# ~/scan-evidence/squawk.toml — the active probe gets a real crawl budget
[defaults]
stage_timeout = 2400              # seconds; any stage without its own

[services.activeprobe]
stage_timeout = 7200              # the crawl below needs the room

[targets."http://127.0.0.1:3000"] # per target, wins over the service
zap_active_spider_minutes = 30    # -m on zap-full-scan; built-in 10

[scanners.semgrep]
extra_args = ["--config", "p/owasp-top-ten"]   # appended to the built-in command
```

The settings are `stage_timeout` (seconds), `zap_spider_minutes` (the live
probe's `-m`), `zap_active_spider_minutes` and `zap_startup_wait` (the
active probe's `-m` and `-T`, both minutes), `zap_memory_mb` (below), and
under `[scanners.<tool>]` only, `extra_args`.

**`zap_memory_mb` — ZAP's Java heap.** ZAP's launcher takes **a quarter** of
the memory it believes it has as its heap, and in a container it reads the
*host's* memory, not the container's — so on an 8 GB machine it asks for
`-Xmx1983m` however the container is limited. That is what makes a probe
feel like it has taken the machine.

Setting this writes `-Xmx<N>m` into the JVM properties file ZAP reads at
start-up. It does **not** cap the container: `docker -m` was measured to
break this image's scan outright, and it does not change ZAP's heap anyway.
ZAP confirms what it read, in the stage's log beside the report:

```
Read custom JVM args from /home/zap/.ZAP/.ZAP_JVM.properties
Using JVM args: -Xmx1024m
```

**Whether it costs you anything depends on the machine, so measure it.** The
same setting against the same app, on two boxes:

| machine | unset | at `zap_memory_mb = 1024` | what it cost |
|---|---|---|---|
| Mac, 8 GB (heap `-Xmx1983m`) | 1289 URLs, 6m 44s | 494 URLs, 6m 46s | **two thirds of the crawl** |
| Kali VM, 15.6 GB (heap ≈`-Xmx3900m`) | 499 URLs, 6m 45s | 530 URLs, 6m 42s | **nothing** |

The reason is what binds the crawl first. The spider runs for five minutes by
default (`zap_spider_minutes`); the fast machine got through 1289 URLs in that
time and was working the heap hard, so cutting it throttled the crawl. The VM
managed 499 in the same five minutes and never came near the heap, so a
smaller one changed nothing — 530 against 499 is run-to-run variance, not an
improvement.

So do not take either row as the answer for your box. Run it once with the
setting and once without, and compare the `across N URLs` on the two runs.
That number is why it is on every run. Unset by default for
that reason — and because a heap too small fails outright, saying so:

```
!! Failed to access summary file …  ·  ZAP ran with -Xmx256m, from zap_memory_mb
```

**When a probe fails and you want to know why**, `zap-baseline.py` hides
ZAP's own output unless asked. Ask, through the profile, and run it again:

```toml
[scanners.zap]
extra_args = ["-d"]        # show ZAP's debug messages
```

The stage's log beside the report then carries the real reason. Measured,
with a deliberately impossible heap:

```
Using the Automation Framework
Read custom JVM args from /home/zap/.ZAP/.ZAP_JVM.properties
Error occurred during initialization of VM
Too small maximum heap
```

Without `-d` that log holds only its first line. Take `-d` back out
afterwards: a full scan's debug output is large, and `raw/` is what retention
trims first. Everything a stage writes to stderr is kept either way, as
`raw/<stage>.err`. The most specific section wins: `[scanners.x]` over
`[targets."y"]` over `[services.z]` over `[defaults]` over the built-in.

**See it before you spend an hour on it.** `config show` prints every setting
a service's stages would run with, its built-in, and where the value came
from, and runs nothing:

```
$ python3 squawk.py config show activeprobe http://127.0.0.1:3000
Profile : /home/you/scan-evidence/squawk.toml (evidence root) — 2 value(s) differ from the built-in
Service : Active app probe (activeprobe) · target http://127.0.0.1:3000

  stage         setting                    value    built-in  from
  zap-active    stage_timeout              7200     5400      [services.activeprobe]
  zap-active    zap_active_spider_minutes  30       10        [targets."http://127.0.0.1:3000"]
  zap-active    zap_startup_wait           20       20        built-in

Nothing was run. `squawk run activeprobe` prints the same block before it runs.
```

A crawl budget that would not fit its stage timeout gets a `note:` line
here and on the run, because the timeout would end the crawl first and a
thin scan must never read as a thorough one. `run` prints the same `Profile`
block before its first stage; the manifest carries it under `profile`; and
the run page's *What ran* shows each stage's budget, where it came from,
and — on hover — the command it ran.

**What is refused, by name, before any stage runs:** a key that is not a
setting (`spider = 5` is a typo, not a budget), a `[services.x]` or
`[scanners.x]` that names nothing, a value that is not a whole number of
seconds or minutes, a value shaped like a credential or a key named like one
(`api_token = …` is refused and the value is never printed — PRODUCT rule 1),
and an `extra_args` token from the read-only list (`--delete`, `rm`,
`--force`, …). A refused profile is `Profile refused: <file>: <what>` with
`rc=2`, the same refusal as a page from the Scan button, a `REFUSED run:
profile` line in the log, and no run directory at all. **The whole file is
refused, for every service** — a `[scanners.zap]` fault stops a host audit
that never runs zap, on purpose: a profile that cannot be applied as written
is not applied in part, and a file accepted for one service and refused for
the next would read as fine. Fix or delete it and run again. A profile named by
`--profile` or `SQUAWK_PROFILE` that cannot be read is refused too, never
quietly replaced by the built-ins.

**Verify:** with the file above, `config show activeprobe
http://127.0.0.1:3000` prints the table shown; `run activeprobe --target
http://127.0.0.1:3000` prints the same `Profile` block first and its ZAP row
on the run page reads `7200 s [services.activeprobe]`.

## Proving the evidence was not edited

Every run writes `digest.json` last, holding the sha256 of every other file in
the run and the id and digest hash of the run before it anywhere in the store.
Every decision carries the hash of the decision before it. `verify` walks both.

```
python3 squawk.py verify --evidence ~/scan-evidence
```

**Verify:** one line per run, then a verdict. Three outcomes, and the exit code
is the one to read in a script:

| Exit | Means |
|---|---|
| 0 | every run verified unaltered, and the ledger chains |
| 1 | something was altered, is missing, was added, or the chain is broken — the run and the file are named |
| 3 | nothing was wrong and something could not be checked (a run written before digests carried file hashes). Not a pass |

To see it work, edit a manifest by hand and run it again: the run and the file
are named and it exits 1. Put the exact bytes back and it exits 0 — the check
is on content, not on a timestamp.

Two lines in the output matter more than they look. **`Previous :`** names the
last verify, or says `none`: a hash chain cannot vouch for its own newest link,
so the newest run and the newest decision are covered *from the next verify
on*, by comparing against what the last one recorded. Run it once after a scan
and once before you rely on the evidence. **`Relied on`** lists every run
retention removed or trimmed, by date and by whom — a record, not a proof, and
listed so you recognise the ones you did.

What it catches, each a case that once exited 0: a run whose `manifest.json`
was deleted (`missing`, not gone); a deleted `findings.json` with a forged
`pruned.json` beside it (`missing`, not pruned); a run deleted outright after a
verify (`missing … nothing records its removal`); the newest run edited with
its digest rewritten to match (`altered — digest.json was rewritten after the
verify on …`).

A finished run is sealed read-only (0400), so changing evidence takes a
deliberate `chmod` first. That is a tripwire; the digest is what detects the
change. Retention writes a tombstone carrying a removed run's digest hash before
it removes the directory, so pruning does not break the chain.

**What this does not prove:** who wrote it. There are no signatures and no keys
here, so anyone who can write the whole evidence root can rebuild a consistent
chain, or append a retention record for a run they then delete — which is why
those are listed, not trusted. It is tamper evidence for the person holding the
files, not proof of authorship to a third party. The command prints that line
every time it runs.

**`stop` stops the scanner too — process and container.** Every scanner runs
in its own process group and `squawk stop` (or a timeout, or Ctrl-C) ends the
group; every container Squawk starts carries a name, and the stop path kills it
by that name and asks `docker ps` before it claims anything. Before this, `stop`
recorded the run as aborted and the scanner it had started — an active DAST
probe, say — kept attacking the target for up to ninety minutes more; and the
first fix killed only the docker client, which detaches the container. The
serve log says `killed container squawk-zap-baseline-<run id>`, or says loudly
that it could not; the interrupted run is recorded as aborted with that reason.

# Squawk — DAST lab (Kali + target, VirtualBox)

The topology we chose: **Squawk runs on a Kali VM as an isolated scanner
appliance, pointing at a separate vulnerable target VM over a host-only
network.** Nothing scans from the host; nothing attack-related touches the
public network. This is the lab for iteration 4 (DAST) — and it exercises SAST
at the same time, on the same target's source.

```
 [ your Mac ] --ssh -L 8787--> [ Kali VM ]            [ target VM ]
   browser                      Squawk + ZAP  --host--> Metasploitable 2
   (loopback UI over tunnel)    (loopback)    only     (DVWA, Mutillidae, …)
                                  192.168.56.20         192.168.56.10
```

## The lab in use — containers on the Kali box

> The VM topology above was the plan. The lab that runs is **containers on the
> Kali guest**, because Metasploitable will not boot on ARM (decided
> 2026-09-06). One script owns it:

```
./lab-targets.py fresh     # Juice Shop :3000, DVWA :8080, VAmPI :5000 — loopback only
./lab-targets.py build     # Dockerfile, k8s and lockfile corpora under ~/squawk-lab
./lab-targets.py check     # each service against its target, held to TARGETS.md's answer
./lab-targets.py status    # what exists, and whether it answers
```

`fresh` before measuring: Juice Shop records solved challenges, so a target you
have been poking at is not the target you scanned last week. Every expected
answer, measured, is in [`TARGETS.md`](TARGETS.md). A longer probe is a
profile, not an edit: `squawk.toml` in the evidence root with
`[targets."http://127.0.0.1:3000"] zap_active_spider_minutes = 30` gives the
active probe a real crawl, and the run prints it ([`SETUP.md`](../docs/SETUP.md),
*A profile*). crAPI, and a probe of DVWA
that gets past its login, come when scan profiles exist to give a run a login
and a budget. Everything downstream — recon, the
private-target rail, DAST — is the same as in the VM topology; only where the
target lives changes.

## Why this shape

- **DAST sends real attack traffic**, so the target lives in a VM you can revert
  and on a network the host controls. Blast radius stays inside VirtualBox.
- **Squawk is loopback-only by design.** On Kali it binds `127.0.0.1` as always;
  you reach its UI from your Mac through an **SSH tunnel**, which preserves the
  loopback guarantee instead of exposing the port.
- **SAST needs source, not a running box.** You clone the target app's source on
  Kali and scan it as a `repo`; DAST hits the same app while it runs. Same app,
  both lenses.

## The target — Metasploitable 2

> **Decided 2026-09-06: not on this lab.** Metasploitable 2 is x86-only and
> will not boot on the ARM Kali VM; the emulation path (UTM/QEMU) buys an
> afternoon of packaging for findings the container targets already give.
> The lab is containers: Juice Shop today, and the rest of the set in
> [`TARGETS.md`](TARGETS.md) next. The section below is kept
> for an x86 host, where it still works as written.

Chosen because it serves several deliberately-vulnerable web apps on port 80
(**DVWA, Mutillidae, phpMyAdmin, TWiki**) plus many network services, so ZAP
produces rich, *known* results you can check outcomes against per app type.

- Download the Metasploitable 2 zip, extract, and add the `.vmdk` to a new VM
  (Linux, 512 MB+ is plenty).
- **Do NOT bridge it.** Attach a single **host-only adapter** (see below). It is
  intentionally insecure — it must never be reachable from the LAN.
- Boot, log in `msfadmin` / `msfadmin`, run `ifconfig` to read its host-only IP
  (e.g. `192.168.56.10`). Its web root is `http://192.168.56.10/`.

> **Apple Silicon caveat.** Metasploitable 2 is **x86-only and will not boot
> under ARM VirtualBox** on an M-series Mac — the same host where Kali needs the
> `grubaa64.efi` boot fix. On Apple Silicon, run an architecture-independent
> target instead: **OWASP Juice Shop** or **DVWA** as containers on the Kali
> guest (Squawk's recon finds them the same way), or emulate an x86 target with
> UTM/QEMU (correct, but slow). Everything downstream — recon, the private-target
> rail, DAST — is identical; only the target VM changes. The public
> [virtual-lab guide](https://github.com/ryayres-fox/Security/blob/main/docs/virtual-lab.md)
> covers the host-arch split in full.

## The scanner — Kali VM running Squawk

- Kali ships ZAP and most scanners; confirm/install what Squawk wants:
  `gitleaks semgrep bandit checkov trivy syft grype`, plus `zaproxy` for the
  `zap-baseline.py` script the DAST stage calls.
- Clone this repository on Kali; the app is `squawk.py` at its root.
- Attach the **same host-only adapter** as the target (so Kali ↔ target can talk)
  and, if you want internet for updates, a second NAT adapter.
- `python3 squawk.py --doctor` — it should report the tools present and a
  writable evidence root.

## VirtualBox host-only network

One host-only network both VMs share, host-controlled, no route to the internet:

```
VBoxManage hostonlyif create                      # e.g. creates vboxnet0
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0
# then in each VM's settings: Adapter -> Host-only Adapter -> vboxnet0
```

Both VMs land on `192.168.56.0/24`. Squawk's DAST safety rail treats that range as
private and allows it; a public address is refused unless `SQUAWK_DAST_ACK=1`.

## Snapshots — revert between runs

Take a **clean snapshot of the target at a serving steady state** before any
scan, and revert to it between runs so every DAST run starts from the same known
state (the kiosk-runner discipline, applied to the target):

```
VBoxManage snapshot "Metasploitable2" take clean-serving --live
VBoxManage snapshot "Metasploitable2" restore clean-serving   # between runs
VBoxManage startvm  "Metasploitable2" --type headless
```

## Reaching Squawk's UI from your Mac

Squawk binds loopback on Kali. Tunnel it:

```
ssh -L 8787:127.0.0.1:8787 user@192.168.56.20   # Kali's host-only IP
# then browse http://127.0.0.1:8787/ on your Mac — served by Squawk on Kali
```

## Running the proofs

**Discovery first — let the kiosk pull what it needs.** You do not need to know
which apps the target serves. Set the target to the bare host and run **Target
recon**; Squawk finds the reachable web apps and lists each as a one-click DAST
target:

```
# on Kali
python3 squawk.py --run recon --target http://192.168.56.10
# then open Findings in the UI: DVWA, Mutillidae, phpMyAdmin, … each with a
# "Probe (DAST)" button that launches the Live app probe against that exact URL
```

Recon is stdlib-only (no install), sends no attacks, and is still gated to a
private target you own.

**DAST** — from the recon results, click **Probe (DAST)** on an app, or run it
directly:

```
python3 squawk.py --run liveprobe --target http://192.168.56.10/mutillidae/
```

Expect ZAP to surface SQLi, XSS, CSRF, and missing headers on Mutillidae/DVWA —
the known-vulnerable outcomes that prove DAST fired and parsed correctly.

**SAST** — scan the same apps' source (DVWA and Mutillidae are on GitHub; or copy
Metasploitable's `/var/www` off the target) as a repo:

```
git clone https://github.com/digininja/DVWA /tmp/dvwa
python3 squawk.py --run preflight --repo /tmp/dvwa
```

Expect semgrep/bandit-class findings in the source — SAST proven on the same
target you just probed dynamically.

## Safety recap (the rails Squawk enforces)

- **Never bridge the target.** Host-only only. It is built to be broken into.
- **Squawk refuses a public DAST target** unless you explicitly set
  `SQUAWK_DAST_ACK=1` — aiming an active scan at something you do not own is the
  mistake this rail exists to stop.
- **The target VM's IP never enters a finding's identity**, so reverting to a
  snapshot on a different IP still diffs as the same app.
- **Every DAST scan is time-boxed** (`-m 2` spider minutes), because an unbounded
  active scan against a stateful app is a denial of service in itself.

See [`ROADMAP.md`](../docs/ROADMAP.md) for where this goes next (Docker-hosted targets,
authenticated DAST, canaries).

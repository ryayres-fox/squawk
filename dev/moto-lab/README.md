# The cloud lab, in an emulator

[`../cloud-lab`](../cloud-lab) plants a weak AWS estate in a dedicated test
account with Terraform. This folder plants the same estate in
[Moto](https://github.com/getmoto/moto), an open-source AWS emulator that runs
in Docker on your machine. You need no account and no real credential, and
there is no bill.

    ./dev/moto-lab/moto-lab.py up       # start Moto on 127.0.0.1:5000
    ./dev/moto-lab/moto-lab.py plant    # plant the estate; print the check
    ./dev/moto-lab/moto-lab.py down     # stop Moto; the estate goes with it

`plant` ends by printing two lines to paste into one shell: an `export` that
points the AWS CLI at this lab's configuration, and the `lab-targets.py check`
that holds each cloud stage to what was planted. The check reads every region
Moto offers (38), so it takes about 15 minutes.

You need Docker and the AWS CLI v2. Nothing else is installed.

## What a run here proves, and what it does not

Moto answers in AWS's shape. A stage that names what was planted here has
shown three things: it calls APIs that exist, it parses what comes back, and
its rules fire on the result. It has not shown that AWS answers the same way.
Moto is a second implementation of AWS's API, and it differs in places. Three
are listed under "The first run" below.

So the check writes `validated off AWS` in every row, never `validated`, and
the report says nothing ships on it. A release still needs a run against a
real test account. A run here is for finding bugs before that account exists,
for free, as often as you like.

## Two rails, both enforced

**Only Moto, only on this machine.** `plant` refuses an endpoint that is not
`http://`, a loopback address and a port. It also refuses one that does not
answer Moto's own state-manager API, which AWS does not have. Both checks run
before any `aws` call.

**Your AWS configuration is out of reach.** Every `aws` call that `plant`
makes runs with all of your shell's `AWS_*` variables removed.
`AWS_CONFIG_FILE` points at `.state/aws-config`, which `plant` writes, and
`AWS_SHARED_CREDENTIALS_FILE` points at `/dev/null`. The keys in that file are
the word `testing`, which Moto accepts and AWS refuses. `~/.aws` is never read.

The check runs in your shell, so the `export` line is what keeps it on Moto.
Use a fresh terminal for it, and close that terminal when you are done.

## What is planted

The same estate as `../cloud-lab`: one `aws` call for each Terraform resource.
`plant` prints which resource each call mirrors. Three things differ:

| | `../cloud-lab` | here | why |
|---|---|---|---|
| Security Hub | off unless `enable_securityhub` | on | it costs nothing here |
| Access Analyzer | planted | not planted | Moto does not emulate it |
| API stage throttling | 1 request a second | none | it caps cost in an account, and nothing here costs anything |

Squawk reads as the lab's auditor role, through `assume-role`, exactly as it
does in an account. `plant` checks that before it prints the check.

## The first run, 2026-10-16

Two runs, before and after the fixes they led to. Each run's report lands in
`.state/VALIDATION.md`.

| Stage | First run | Second run | What Moto does |
|---|---|---|---|
| inventory | passed | validated off AWS | |
| identity | passed | validated off AWS | |
| containers | **failed**: the cluster was not in the evidence | validated off AWS | |
| data services | passed | validated off AWS | |
| organization | passed | validated off AWS | |
| front door | passed | validated off AWS | |
| storage | **failed**: neither bucket rule fired | not exercised | sends an empty `PolicyStatus`, with no `IsPublic` |
| edge | **failed**: the open function URL was missed | not exercised | has no ListFunctionUrlConfigs; answers with a 404 page |
| external access | not exercised | not exercised | has no Access Analyzer; answers 500 |
| watching | not exercised | not exercised | answers GuardDuty and Config; in every region, Access Analyzer answers 500 and Inspector returns no account status |
| Security Hub | not exercised | not exercised | turns on, but has no standards or findings to read |

Four bugs, found before any account existed:

- `../cloud-lab/main.tf` attached `ViewOnlyAccess` without its
  `job-function/` path. That is no policy, and `plant` stopped on it the same
  way `terraform apply` would have.
- Squawk kept only an ECS cluster's services, so the lab's empty cluster was
  read and left no trace. This would have failed in an account too.
- Squawk read Moto's 404 page as "this function has no URL", and an answer
  with no `IsPublic` as "this bucket is private". Neither is wrong against AWS
  as it answers today, but each made a failed read look like a clean one. Both
  are now unknowns. That is why the storage and edge stages moved from
  failed to not exercised: Moto cannot answer those questions, and the check
  now says so.

## Files

- `moto-lab.py`: the three commands.
- `.state/`: the CLI configuration, the lab name, the function's zip and the
  last report. `plant` rebuilds it, and git ignores it.

The image is pinned by digest: Moto 5.2.3.dev, built 2026-08-22. To move to a
newer one, change `IMAGE` in `moto-lab.py`, run the check, and record what
changed.

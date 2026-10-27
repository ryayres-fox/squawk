#!/usr/bin/env python3
"""The cloud lab, planted in Moto instead of an AWS account.

`dev/cloud-lab` plants a weak estate in a dedicated test account with
Terraform. This plants the same estate in Moto, an open-source AWS emulator
that runs in Docker on this machine, so the cloud services can be checked
with no account, no real credential and no bill:

    ./dev/moto-lab/moto-lab.py up       # start Moto on 127.0.0.1:5000
    ./dev/moto-lab/moto-lab.py plant    # plant the estate; print the check
    ./dev/moto-lab/moto-lab.py down     # stop Moto; the estate goes with it

Each plant below names the Terraform resource it mirrors. What a run against
an emulator proves, and what it does not, is in README.md beside this file.

Two rails, both enforced rather than requested:

- Nothing is planted unless the endpoint is a loopback address and answers
  as Moto. The estate is weak on purpose; it must never land in an account.
- Every `aws` call runs with every AWS_* variable removed, AWS_CONFIG_FILE
  pointed at a file this script writes, and AWS_SHARED_CREDENTIALS_FILE at
  /dev/null. ~/.aws, and any real credential in it, is never read.
"""

import argparse
import ipaddress
import json
import os
import secrets
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, ".state")

# Pinned by digest: the image this lab was validated against. A tag can move.
IMAGE = ("motoserver/moto@sha256:"
         "91fd602a21f49cf9eb82fdf474015a3c131d40104c8297ea6a2ca920708ae32c")
CONTAINER = "squawk-moto"
ENDPOINT = "http://127.0.0.1:5000"
ACCOUNT = "123456789012"          # Moto's default account
REGION = "us-east-1"
DEPLOY = "squawk-moto-deploy"     # plants the estate, as the Terraform deploy profile does
AUDITOR = "squawk-moto-auditor"   # what Squawk reads as: the read-only auditor role
FAKE_KEY = "testing"              # Moto accepts any key pair; this is a word, not a credential
CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"   # Managed-CachingOptimized


class PlantError(RuntimeError):
    """An `aws` call the estate needs did not succeed."""


# ---- the rails --------------------------------------------------------------

def endpoint_ok(url: str) -> Tuple[bool, str]:
    """Plant only into something on this machine.

    Refuses https (Moto here speaks plain HTTP, and an https URL is far likelier
    to be AWS itself), a URL with no port, a path, and any host that is not a
    loopback address. A name other than `localhost` is refused rather than
    resolved: a resolver can be wrong, and nothing here needs one."""
    p = urlparse(url or "")
    if p.scheme != "http":
        return False, "the endpoint must start http://, got %r" % url
    try:
        port = p.port
    except ValueError:
        return False, "the port in %r is not a number" % url
    if port is None:
        return False, "name the port, e.g. %s" % ENDPOINT
    if p.path not in ("", "/") or p.query or p.username or p.password:
        return False, "the endpoint is a scheme, a host and a port, nothing more: %r" % url
    host = p.hostname or ""
    if host == "localhost":
        return True, "localhost:%d" % port
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False, "%r is not a loopback address" % host
    if not ip.is_loopback:
        return False, "%s is not a loopback address" % host
    return True, "%s:%d" % (host, port)


def is_moto(url: str, timeout: float = 5.0) -> Tuple[bool, str]:
    """Does the endpoint answer as Moto? Moto's state manager answers a GET
    with a small JSON object naming a `progression`; AWS has no such path.
    A loopback port held by something else is refused here. Proxies from the
    environment are bypassed: the question is about this machine."""
    probe = url.rstrip("/") + "/moto-api/state-manager/get-transition?model_name=squawk-probe"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(probe, timeout=timeout) as res:
            body = res.read(4096)
    except (urllib.error.URLError, OSError) as exc:
        return False, "%s did not answer: %s" % (url, getattr(exc, "reason", exc))
    try:
        data = json.loads(body)
    except ValueError:
        return False, "%s answered, but not as Moto" % url
    if not isinstance(data, dict) or "progression" not in data:
        return False, "%s answered, but not as Moto" % url
    return True, "Moto answers at %s" % url


def config_text(endpoint: str, lab: Optional[str]) -> str:
    """The AWS CLI configuration every call here reads, and nothing else.
    The deploy profile plants; the auditor profile assumes the lab's
    read-only role, so Squawk reads as it would in an AWS test account. Before
    there is a lab there is no role to name, so the auditor waits."""
    lines = [
        "# Written by dev/moto-lab/moto-lab.py for the Moto emulator at %s." % endpoint,
        "# Moto accepts any key pair: the keys below are a word, not a credential.",
        "# Point AWS_CONFIG_FILE here and ~/.aws is never read.",
        "",
        "[profile %s]" % DEPLOY,
        "region = %s" % REGION,
        "endpoint_url = %s" % endpoint,
        "aws_access_key_id = %s" % FAKE_KEY,
        "aws_secret_access_key = %s" % FAKE_KEY,
    ]
    if lab:
        lines += [
            "",
            "[profile %s]" % AUDITOR,
            "region = %s" % REGION,
            "endpoint_url = %s" % endpoint,
            "role_arn = arn:aws:iam::%s:role/%s-auditor" % (ACCOUNT, lab),
            "source_profile = %s" % DEPLOY,
        ]
    return "\n".join(lines) + "\n"


def write_config(path: str, endpoint: str, lab: Optional[str]) -> None:
    """Write the configuration readable by this user only."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(config_text(endpoint, lab))


def aws_env(config_path: str, endpoint: str,
            base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """The environment for every `aws` call: no AWS_* variable from the
    caller, so no leftover key, profile, endpoint override or credential file
    can point a call anywhere but the emulator. The endpoint is set twice,
    here and in the profile; if both were ignored, the call would reach AWS
    with a key AWS refuses, and stop."""
    env = {k: v for k, v in (os.environ if base is None else base).items()
           if not k.startswith("AWS_")}
    env.update({
        "AWS_CONFIG_FILE": config_path,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "AWS_ENDPOINT_URL": endpoint,
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_PAGER": "",
    })
    return env


def aws(env: Dict[str, str], *args: str, profile: str = DEPLOY) -> dict:
    """One `aws` call as `profile`, and its JSON answer. A failure raises
    PlantError naming the call and the CLI's last line. The arguments go as a
    list: no shell sees them."""
    cmd = ["aws", *args, "--profile", profile, "--output", "json"]
    what = " ".join(args[:2])
    try:
        res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PlantError("%s: %s" % (what, exc)) from exc
    if res.returncode != 0:
        lines = (res.stderr or res.stdout).strip().splitlines()
        raise PlantError("%s failed: %s" % (what, lines[-1] if lines else "rc=%d" % res.returncode))
    if not res.stdout.strip():
        return {}
    try:
        data = json.loads(res.stdout)
    except ValueError as exc:
        raise PlantError("%s answered with something that is not JSON" % what) from exc
    return data if isinstance(data, dict) else {}


# ---- the estate ---------------------------------------------------------------

def policy(*statements: dict) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def trust(principal: dict) -> str:
    return policy({"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"})


def console_password() -> str:
    """A throwaway password with every character class. It is neither
    printed nor kept: nobody signs in to an emulator."""
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#%^*-_=+"]
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice("".join(pools)) for _ in range(28)]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def function_zip(path: str) -> str:
    """The function's code, as edge.tf's archive_file builds it."""
    info = zipfile.ZipInfo("index.py", date_time=(2026, 1, 1, 0, 0, 0))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(info, "def handler(event, context):\n"
                          "    return {'statusCode': 200, 'body': 'squawk lab'}\n")
    return path


def plant(env: Dict[str, str], n: str, state: str) -> List[str]:
    """Plant the estate under the prefix `n`, in the order of the Terraform
    files. Returns what was NOT planted, and why, so the caller can say so."""
    def did(what: str, mirrors: str) -> None:
        print("  planted  %-34s  %s" % (what, mirrors))

    root = {"AWS": "arn:aws:iam::%s:root" % ACCOUNT}

    # main.tf -- the read-only identity Squawk reads as.
    aws(env, "iam", "create-role", "--role-name", n + "-auditor",
        "--assume-role-policy-document", trust(root))
    # ViewOnlyAccess is a job-function policy; its ARN carries that path.
    for p in ("SecurityAudit", "job-function/ViewOnlyAccess"):
        aws(env, "iam", "attach-role-policy", "--role-name", n + "-auditor",
            "--policy-arn", "arn:aws:iam::aws:policy/" + p)
    did(n + "-auditor", "main.tf aws_iam_role.auditor (+ 2 attachments)")

    # network.tf -- a security group admitting the world on SSH, attached to nothing.
    vpcs = aws(env, "ec2", "describe-vpcs", "--filters", "Name=isDefault,Values=true")
    vpc = ((vpcs.get("Vpcs") or [{}])[0]).get("VpcId")
    if not vpc:
        raise PlantError("Moto has no default VPC in %s" % REGION)
    sg = aws(env, "ec2", "create-security-group", "--group-name", n + "-ssh-world",
             "--description", "Squawk lab: SSH from anywhere, deliberately", "--vpc-id", vpc)
    aws(env, "ec2", "authorize-security-group-ingress", "--group-id", sg["GroupId"],
        "--ip-permissions", json.dumps([{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH from anywhere"}]}]))
    did(n + "-ssh-world", "network.tf aws_security_group.ssh_world")

    # iam.tf -- a console user with no MFA, and a role that can rewrite itself.
    aws(env, "iam", "create-user", "--user-name", n + "-nomfa")
    aws(env, "iam", "create-login-profile", "--user-name", n + "-nomfa",
        "--password", console_password(), "--password-reset-required")
    did(n + "-nomfa", "iam.tf aws_iam_user.nomfa (+ login profile)")
    role = aws(env, "iam", "create-role", "--role-name", n + "-escalates",
               "--assume-role-policy-document", trust(root))
    aws(env, "iam", "put-role-policy", "--role-name", n + "-escalates",
        "--policy-name", "rewrite-myself", "--policy-document", policy({
            "Effect": "Allow", "Action": ["iam:PutRolePolicy", "iam:AttachRolePolicy"],
            "Resource": role["Role"]["Arn"]}))
    did(n + "-escalates", "iam.tf aws_iam_role.escalates (+ inline policy)")

    # storage.tf -- two empty buckets with a public read policy; the second is held shut.
    for suffix, sid, restrict in (("-open", "SquawkLabPublicRead", False),
                                  ("-held", "SquawkLabHeldShut", True)):
        b = n + suffix
        aws(env, "s3api", "create-bucket", "--bucket", b)
        aws(env, "s3api", "put-public-access-block", "--bucket", b,
            "--public-access-block-configuration", json.dumps({
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": False, "RestrictPublicBuckets": restrict}))
        aws(env, "s3api", "put-bucket-policy", "--bucket", b, "--policy", policy({
            "Sid": sid, "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::%s/*" % b}))
        did(b, "storage.tf aws_s3_bucket.%s (+ block, policy)" % suffix[1:])
    aws(env, "s3api", "put-bucket-website", "--bucket", n + "-open",
        "--website-configuration", json.dumps({"IndexDocument": {"Suffix": "index.html"}}))
    did(n + "-open website", "storage.tf aws_s3_bucket_website_configuration.open")

    # edge.tf -- a function whose URL needs no authorization.
    fn_role = aws(env, "iam", "create-role", "--role-name", n + "-fn",
                  "--assume-role-policy-document", trust({"Service": "lambda.amazonaws.com"}))
    aws(env, "lambda", "create-function", "--function-name", n + "-fn",
        "--role", fn_role["Role"]["Arn"], "--runtime", "python3.12",
        "--architectures", "arm64", "--handler", "index.handler",
        "--zip-file", "fileb://" + function_zip(os.path.join(state, "fn.zip")),
        "--memory-size", "128", "--timeout", "3")
    aws(env, "lambda", "create-function-url-config", "--function-name", n + "-fn",
        "--auth-type", "NONE")
    did(n + "-fn", "edge.tf aws_lambda_function.fn (+ role, URL)")

    # data.tf -- a topic, a queue and a registry readable by anyone; a secret; a cluster.
    topic = aws(env, "sns", "create-topic", "--name", n + "-topic")["TopicArn"]
    aws(env, "sns", "set-topic-attributes", "--topic-arn", topic,
        "--attribute-name", "Policy", "--attribute-value", policy({
            "Sid": "SquawkLabAnyoneMayRead", "Effect": "Allow", "Principal": "*",
            "Action": "SNS:GetTopicAttributes", "Resource": topic}))
    did(n + "-topic", "data.tf aws_sns_topic.open (+ policy)")
    queue = aws(env, "sqs", "create-queue", "--queue-name", n + "-queue")["QueueUrl"]
    qarn = aws(env, "sqs", "get-queue-attributes", "--queue-url", queue,
               "--attribute-names", "QueueArn")["Attributes"]["QueueArn"]
    aws(env, "sqs", "set-queue-attributes", "--queue-url", queue,
        "--attributes", json.dumps({"Policy": policy({
            "Sid": "SquawkLabAnyoneMayRead", "Effect": "Allow", "Principal": "*",
            "Action": "sqs:GetQueueAttributes", "Resource": qarn})}))
    did(n + "-queue", "data.tf aws_sqs_queue.open (+ policy)")
    aws(env, "ecr", "create-repository", "--repository-name", n + "-registry")
    aws(env, "ecr", "set-repository-policy", "--repository-name", n + "-registry",
        "--policy-text", policy({
            "Sid": "SquawkLabAnyoneMayPull", "Effect": "Allow", "Principal": "*",
            "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]}))
    did(n + "-registry", "data.tf aws_ecr_repository.open (+ policy)")
    aws(env, "secretsmanager", "create-secret", "--name", n + "-placeholder",
        "--secret-string", "squawk-lab-placeholder-not-a-credential")
    did(n + "-placeholder", "data.tf aws_secretsmanager_secret.placeholder")
    aws(env, "ecs", "create-cluster", "--cluster-name", n + "-cluster")
    did(n + "-cluster", "data.tf aws_ecs_cluster.lab")

    # frontdoor.tf -- a REST API with an open method; CloudFront with no WAF.
    api = aws(env, "apigateway", "create-rest-api", "--name", n + "-api")["id"]
    res_items = aws(env, "apigateway", "get-resources", "--rest-api-id", api).get("items") or []
    top = next((r["id"] for r in res_items if r.get("path") == "/"), None)
    if not top:
        raise PlantError("the REST API has no root resource")
    common = ["--rest-api-id", api, "--resource-id", top, "--http-method", "GET"]
    aws(env, "apigateway", "put-method", *common, "--authorization-type", "NONE")
    aws(env, "apigateway", "put-integration", *common, "--type", "MOCK",
        "--request-templates", json.dumps({"application/json": '{"statusCode": 200}'}))
    aws(env, "apigateway", "put-method-response", *common, "--status-code", "200")
    aws(env, "apigateway", "put-integration-response", *common, "--status-code", "200")
    aws(env, "apigateway", "create-deployment", "--rest-api-id", api, "--stage-name", "lab")
    did(n + "-api", "frontdoor.tf aws_api_gateway_* (stage lab)")
    aws(env, "cloudfront", "create-distribution", "--distribution-config", json.dumps({
        "CallerReference": n + "-cdn",
        "Comment": "%s - deliberately without WAF, plain-HTTP origin" % n,
        "Enabled": True, "PriceClass": "PriceClass_100",
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "open-bucket-website",
            "DomainName": "%s-open.s3-website-%s.amazonaws.com" % (n, REGION),
            "CustomOriginConfig": {
                "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "http-only",
                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]}}}]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "open-bucket-website",
            "ViewerProtocolPolicy": "redirect-to-https",
            "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"],
                               "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}},
            "CachePolicyId": CACHING_OPTIMIZED},
        "Restrictions": {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0}},
        "ViewerCertificate": {"CloudFrontDefaultCertificate": True}}))
    did(n + " distribution", "frontdoor.tf aws_cloudfront_distribution.cdn")

    # Behind a flag in Terraform because it charges after its trial; free here.
    aws(env, "securityhub", "enable-security-hub")
    did("Security Hub", "analyzer.tf aws_securityhub_account.hub (enable_securityhub)")

    return [
        "%s-analyzer (analyzer.tf): Moto does not emulate IAM Access Analyzer, "
        "so the analyzer stage has nothing to read" % n,
        "API stage throttling (frontdoor.tf): it caps cost in an AWS account; "
        "nothing here costs anything",
    ]


# ---- the commands -----------------------------------------------------------

def _docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=300)


def cmd_up(args: argparse.Namespace) -> int:
    """Start Moto from the pinned image, published on loopback only."""
    ok, why = endpoint_ok(args.endpoint)
    if not ok:
        print("Refusing: %s" % why)
        return 2
    if is_moto(args.endpoint)[0]:
        print("Moto already answers at %s." % args.endpoint)
        return 0
    port = urlparse(args.endpoint).port
    host = urlparse(args.endpoint).hostname
    bind = "127.0.0.1" if host == "localhost" else host
    res = _docker("run", "-d", "--name", CONTAINER, "--restart", "no",
                  "-p", "%s:%d:5000" % (bind if ":" not in bind else "[%s]" % bind, port),
                  "-e", "MOTO_IAM_LOAD_MANAGED_POLICIES=true", IMAGE)
    if res.returncode != 0:
        lines = res.stderr.strip().splitlines()
        print("docker run failed: %s" % (lines[-1] if lines else "rc=%d" % res.returncode))
        return 1
    for _ in range(60):
        ok, why = is_moto(args.endpoint, timeout=2)
        if ok:
            print("%s (container %s, image pinned by digest)." % (why, CONTAINER))
            return 0
        time.sleep(1)
    print("Moto did not answer within a minute: %s" % why)
    return 1


def cmd_down(args: argparse.Namespace) -> int:
    """Remove the container. Moto keeps its state in memory, so the estate
    goes with it; the lab name is forgotten so the next plant starts fresh."""
    res = _docker("rm", "-f", CONTAINER)
    print("removed %s" % CONTAINER if res.returncode == 0 else
          "no container %s to remove" % CONTAINER)
    try:
        os.remove(os.path.join(args.state, "lab-name"))
    except FileNotFoundError:
        pass
    return 0


def cmd_plant(args: argparse.Namespace) -> int:
    """Plant the estate, prove the auditor profile reads as the auditor
    role, and print the check to run."""
    ok, why = endpoint_ok(args.endpoint)
    if not ok:
        print("Refusing: %s" % why)
        return 2
    ok, why = is_moto(args.endpoint)
    if not ok:
        print("Refusing: %s. Start it with: ./dev/moto-lab/moto-lab.py up" % why)
        return 2
    config = os.path.join(args.state, "aws-config")
    name_file = os.path.join(args.state, "lab-name")
    env = aws_env(config, args.endpoint)
    try:
        write_config(config, args.endpoint, None)
        who = aws(env, "sts", "get-caller-identity")
        if who.get("Account") != ACCOUNT:
            print("Refusing: the endpoint says account %r, not Moto's %s"
                  % (who.get("Account"), ACCOUNT))
            return 2
        lab = None
        if os.path.exists(name_file):
            with open(name_file, encoding="utf-8") as fh:
                old = fh.read().strip()
            try:
                aws(env, "s3api", "head-bucket", "--bucket", old + "-open")
                lab = old
                print("Lab %s is already planted in this Moto; not planting twice." % lab)
            except PlantError:
                pass                    # Moto restarted since: that estate is gone
        if lab is None:
            lab = "squawk-moto-" + secrets.token_hex(3)
            print("Planting lab %s in Moto at %s (account %s):" % (lab, args.endpoint, ACCOUNT))
            skipped = plant(env, lab, args.state)
            with open(name_file, "w", encoding="utf-8") as fh:
                fh.write(lab + "\n")
            for s in skipped:
                print("  not planted  %s" % s)
        write_config(config, args.endpoint, lab)
        me = aws(env, "sts", "get-caller-identity", profile=AUDITOR)
    except PlantError as exc:
        print("Stopped: %s" % exc)
        return 1
    arn = str(me.get("Arn", ""))
    if ":assumed-role/%s-auditor/" % lab not in arn:
        print("Stopped: the auditor profile reads as %s, not the lab's auditor role" % arn)
        return 1
    print("\nThe auditor profile reads as %s." % arn)
    print("\nRun the check from the Squawk checkout, in one shell:\n")
    print("  export AWS_CONFIG_FILE=%s AWS_SHARED_CREDENTIALS_FILE=/dev/null" % config)
    print("  ./dev/lab-targets.py check --only cloud --aws-profile %s --aws-account %s "
          "--aws-lab %s --report %s"
          % (AUDITOR, ACCOUNT, lab, os.path.join(args.state, "VALIDATION.md")))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--endpoint", default=ENDPOINT,
                    help="where Moto answers; loopback only (default %(default)s)")
    ap.add_argument("--state", default=STATE,
                    help="where the CLI configuration and lab name are kept "
                         "(default %(default)s, ignored by git)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("up", help="start Moto from the pinned image").set_defaults(fn=cmd_up)
    sub.add_parser("plant", help="plant the estate and print the check").set_defaults(
        fn=cmd_plant)
    sub.add_parser("down", help="stop Moto; the estate goes with it").set_defaults(fn=cmd_down)
    args = ap.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    sys.exit(main())

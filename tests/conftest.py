"""Make the squawk package importable under pytest from any working
directory, so the tests import the package the app runs as, and make sure no
test can run the real `aws` CLI.

The suites sit in `tests/` and the package sits beside that directory, at the
root of the checkout, which is what goes on the path.

The `aws` part. The cloud services ask who the credential chain is before
they read anything (`stages.aws_identity`), and that call runs `aws` by name.
Tests that faked the cloud readers did not fake it, so the suite ran the real
CLI 15 times per run (counted 2026-10-14 with a wrapper that logged
PYTEST_CURRENT_TEST). With no credentials and no region, that CLI connects to
the instance-metadata address, 169.254.169.254:80, before it looks for
credentials: Malcolm recorded 1,052 such attempts from the lab's Kali box in a
day, one burst per test run. On a machine with credentials it would have
called real STS under whatever profile is active. So a fake `aws` goes first
on PATH for the whole session, before any test is collected. It answers the
way the real CLI does with no credentials, so the tests' outcomes do not
change, and it records each call in SQUAWK_TEST_AWS_LOG for the guard tests.
Subprocesses inherit PATH, so the zipapp runs reach the fake too."""
import atexit
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FAKE_AWS = """#!/bin/sh
# The squawk test suite's aws. It answers like the real CLI with no
# credentials and never touches the network or an account. See conftest.py.
printf '%s\\n' "$*" >> "$SQUAWK_TEST_AWS_LOG"
printf '%s\\n' "${AWS_EC2_METADATA_DISABLED-<unset>}" >> "$SQUAWK_TEST_AWS_ENV_LOG"
if [ "$1" = "--version" ]; then
    echo "aws-cli/2.0.0 Python/3 Linux/test squawk-test-fake"
    exit 0
fi
printf '%s %s %s\\n' 'aws: [ERROR]: An error occurred (NoCredentials):' \\
    'Unable to locate credentials.' \\
    'You can configure credentials by running "aws login".' >&2
exit 253
"""

_fake_dir = tempfile.mkdtemp(prefix="squawk-test-aws-")
atexit.register(shutil.rmtree, _fake_dir, True)
with open(os.path.join(_fake_dir, "aws"), "w", encoding="utf-8") as fh:
    fh.write(FAKE_AWS)
os.chmod(os.path.join(_fake_dir, "aws"), 0o700)
os.environ["SQUAWK_TEST_AWS_LOG"] = os.path.join(_fake_dir, "calls.log")
# What each call saw for AWS_EC2_METADATA_DISABLED, one line per call, for
# TestAwsNeverAsksTheMetadataAddress.
os.environ["SQUAWK_TEST_AWS_ENV_LOG"] = os.path.join(_fake_dir, "env.log")
os.environ["PATH"] = _fake_dir + os.pathsep + os.environ.get("PATH", "")
# Belt and braces: anything that reaches botocore without the CLI still may
# not ask the metadata address.
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"

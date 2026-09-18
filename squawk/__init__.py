"""
Squawk: a local, single-user, read-only orchestrator for open-source security
scanners.

It runs a chosen set of scanners against a target you pick (a git checkout, a
directory, a container image, a running app, an AWS account's Security Hub, or
this machine), reads their evidence into one normalized model with a stable
per-finding identity, and keeps every run as immutable evidence on disk so later
runs can diff against it. The rule everything else serves: a scanner that did
not run must never look like one that found nothing.

Design commitments:
  - Standard library only. No database, no service to run, Python 3.9-safe.
  - Loopback-only, single user. It runs scanners as subprocesses and reads any
    path you point it at; that is remote code execution on a reachable port.
  - Evidence over assertion. An absent scanner is a coverage gap with a reason,
    a zero over an empty denominator is a gap, and every result shows what ran.

The package is layered; each module imports only from the ones before it:
core, probes, scanners, stages, evidence, decisions, analysis, engine, feeds,
installer, baselines, retention, runtime, web, service, cli. `squawk.py` beside this package is the
entry point, and `python3 -m squawk` works too.
"""

from squawk.analysis import *  # noqa: F403
from squawk.baselines import *  # noqa: F403
from squawk.cli import *  # noqa: F403
from squawk.cli import main  # noqa: F401
from squawk.core import *  # noqa: F403
from squawk.core import __version__  # noqa: F401
from squawk.decisions import *  # noqa: F403
from squawk.engine import *  # noqa: F403
from squawk.evidence import *  # noqa: F403
from squawk.feeds import *  # noqa: F403
from squawk.installer import *  # noqa: F403
from squawk.probes import *  # noqa: F403
from squawk.retention import *  # noqa: F403
from squawk.runtime import *  # noqa: F403
from squawk.scanners import *  # noqa: F403
from squawk.service import *  # noqa: F403
from squawk.stages import *  # noqa: F403
from squawk.web import *  # noqa: F403

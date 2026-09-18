"""Jobs in flight and the server's pid file."""

import json
import os
import threading
import time
from typing import Dict, List, Optional

from squawk.core import PID_FILENAME, Profile, RunInterrupted
from squawk.engine import execute_service
from squawk.stages import Service

# --------------------------------------------------------------------------- #
# Background job runner — a scan takes up to a couple of minutes, so the UI
# starts it in a thread and polls a status page rather than hanging the request.
# --------------------------------------------------------------------------- #


class Job:
    def __init__(self, job_id: str, service: Service, target: str) -> None:
        self.id = job_id
        self.service = service
        self.target = target
        self.status = "running"     # running | done | error
        self.run_id: Optional[str] = None
        self.run_dir: Optional[str] = None
        self.error: Optional[str] = None
        self.stages: List[dict] = []    # live per-stage progress for the UI
        # A scan can run for the best part of an hour and the page showed a
        # spinner and nothing else, so an operator could not tell a working
        # probe from a stuck one. These are what is honestly knowable while it
        # runs: when it started, and the bound each stage is running under.
        self.started_at = time.time()

    def elapsed(self) -> float:
        return max(0.0, time.time() - self.started_at)

    def on_progress(self, ev: dict) -> None:
        if ev["phase"] == "run":
            self.run_dir = ev.get("run_dir")
            self.run_id = ev.get("run_id")
            return
        if ev["phase"] == "start":
            self.stages.append({"tool": ev["tool"], "mode": ev["mode"],
                                "status": "running", "detail": "",
                                "started_at": time.time(), "timeout": None,
                                "timeout_from": "", "elapsed": None})
        elif not self.stages:
            return
        elif ev["phase"] == "budget":
            self.stages[-1].update(timeout=ev.get("timeout"),
                                   timeout_from=ev.get("timeout_from", ""))
        else:
            self.stages[-1].update(status=ev["status"], detail=ev["detail"],
                                   elapsed=ev.get("elapsed"))

    def stage_elapsed(self, stage: dict) -> float:
        """How long a stage has been running, or how long it took."""
        if stage.get("elapsed") is not None:
            return float(stage["elapsed"])
        return max(0.0, time.time() - float(stage.get("started_at") or self.started_at))


JOBS: Dict[str, Job] = {}
_JOB_SEQ = [0]
_JOB_LOCK = threading.Lock()


def start_job(service: Service, target: str, evidence_root: str, base: str,
              profile: Optional[Profile] = None) -> str:
    with _JOB_LOCK:
        _JOB_SEQ[0] += 1
        job_id = "job%d" % _JOB_SEQ[0]
    job = Job(job_id, service, target)
    JOBS[job_id] = job

    def _work() -> None:
        try:
            outcome = execute_service(service, target, evidence_root, base,
                                      progress=job.on_progress, profile=profile)
            job.run_id = str(outcome["run_id"])
            job.run_dir = str(outcome["run_dir"])
            job.status = "done"
        except RunInterrupted as exc:
            # The server is stopping and killed this job's scanner; the run
            # has already been written up as aborted with that reason. Land
            # the job the same way rather than let a BaseException print a
            # traceback into the serve log on its way out of the thread.
            job.error = str(exc)
            job.status = "error"
        except Exception as exc:  # a failed run must not take the server down
            job.error = str(exc)
            job.status = "error"

    threading.Thread(target=_work, daemon=True).start()
    return job_id


def _pid_path(root: str) -> str:
    return os.path.join(root, PID_FILENAME)


def read_pid_file(root: str) -> Optional[dict]:
    try:
        with open(_pid_path(root), encoding="utf-8") as fh:
            rec = json.load(fh)
        return rec if isinstance(rec, dict) and rec.get("pid") else None
    except (OSError, ValueError):
        return None


def write_pid_file(root: str, rec: dict) -> None:
    path = _pid_path(root)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=2, sort_keys=True)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def remove_pid_file(root: str, expected_pid: Optional[int] = None) -> None:
    """Remove the pid file, but only if it is ours (or no owner is given), so a
    dying old server never deletes a newer server's record."""
    rec = read_pid_file(root)
    if rec is None:
        return
    if expected_pid is not None and rec.get("pid") != expected_pid:
        return
    try:
        os.remove(_pid_path(root))
    except OSError:
        pass


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def running_job_for_scope(scope: str) -> "Optional[Job]":
    """A job of this scope that is still running, if there is one.

    Two cloud reads at once share more than a counter: they read the same live
    estate under the same identity, they double the API calls against the same
    rate limits, and each writes a run whose numbers the other's calls moved.
    The counter was the visible symptom (review R-15); this is the cause."""
    for job in JOBS.values():
        if job.status == "running" and getattr(job.service, "scope", "") == scope:
            return job
    return None


def _drain_jobs(seconds: float) -> int:
    """Give in-flight scans a moment to finish before the server exits; the
    ones still running are then recorded as aborted. Returns how many were."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        if not any(j.status == "running" for j in JOBS.values()):
            break
        time.sleep(0.2)
    return sum(1 for j in JOBS.values() if j.status == "running")


__all__ = [
    'JOBS',
    '_JOB_LOCK',
    '_JOB_SEQ',
    'Job',
    '_alive',
    '_drain_jobs',
    '_pid_path',
    'read_pid_file',
    'remove_pid_file',
    'running_job_for_scope',
    'start_job',
    'write_pid_file',
]

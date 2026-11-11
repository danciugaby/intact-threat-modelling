"""Minimal background job runner so long analyses (topologies, keyword searches with an
unkeyed NVD rate limit) don't hold an HTTP request open. Jobs are stored in the DB, so
status survives across gunicorn workers; execution happens in the worker that accepted
the job. The number of pending jobs per process is capped, and a job that never finishes
(e.g. lost in a restart) is reported as failed after ``JOB_TIMEOUT_SECONDS``."""
import logging
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .models import Job, db

log = logging.getLogger(__name__)


class JobQueueFull(RuntimeError):
    """Too many async jobs are already queued or running in this process."""


class JobRunner:
    def __init__(self, app, workers=2, max_pending=20):
        self.app = app
        self.max_pending = max(1, max_pending)
        self.pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="job")
        self._pending = 0
        self._lock = threading.Lock()

    @property
    def pending(self):
        return self._pending

    def submit(self, kind, request_payload, fn, *args, **kwargs):
        with self._lock:
            if self._pending >= self.max_pending:
                raise JobQueueFull(f"{self._pending} jobs already pending; retry later")
            self._pending += 1
        try:
            job = Job(kind=kind, request=request_payload, status="queued")
            db.session.add(job)
            db.session.commit()
            job_id = job.id
            self.pool.submit(self._run, job_id, fn, args, kwargs)
        except Exception:
            self._release()
            raise
        return job_id

    def _release(self):
        with self._lock:
            self._pending -= 1

    def _run(self, job_id, fn, args, kwargs):
        try:
            with self.app.app_context():
                job = db.session.get(Job, job_id)
                job.status = "running"
                db.session.commit()
                try:
                    result = fn(*args, **kwargs)
                    job = db.session.get(Job, job_id)
                    job.status, job.result = "done", result
                except Exception as exc:
                    log.error("Job %s failed: %s\n%s", job_id, exc, traceback.format_exc())
                    db.session.rollback()
                    job = db.session.get(Job, job_id)
                    job.status, job.error = "failed", f"{exc.__class__.__name__}: {str(exc)[:500]}"
                job.finished_at = datetime.now(timezone.utc)
                db.session.commit()
        finally:
            self._release()


def expire_if_stale(job, timeout_seconds):
    """Mark a queued/running job as failed once it is older than the timeout."""
    if job.status not in ("queued", "running") or not timeout_seconds or job.created_at is None:
        return job
    created = job.created_at if job.created_at.tzinfo else job.created_at.replace(tzinfo=timezone.utc)
    if (datetime.now(timezone.utc) - created).total_seconds() > timeout_seconds:
        job.status = "failed"
        job.error = (f"Job did not finish within {timeout_seconds}s; the service may have restarted. "
                     "Submit it again.")
        job.finished_at = datetime.now(timezone.utc)
        db.session.commit()
    return job

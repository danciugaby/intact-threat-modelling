"""Minimal background job runner so long analyses (topologies, keyword searches with an
unkeyed NVD rate limit) don't hold an HTTP request open. Jobs are stored in the DB, so
status survives across gunicorn workers; execution happens in the worker that accepted
the job."""
import logging
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .models import Job, db

log = logging.getLogger(__name__)


class JobRunner:
    def __init__(self, app, workers=2):
        self.app = app
        self.pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="job")

    def submit(self, kind, request_payload, fn, *args, **kwargs):
        job = Job(kind=kind, request=request_payload, status="queued")
        db.session.add(job)
        db.session.commit()
        job_id = job.id
        self.pool.submit(self._run, job_id, fn, args, kwargs)
        return job_id

    def _run(self, job_id, fn, args, kwargs):
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

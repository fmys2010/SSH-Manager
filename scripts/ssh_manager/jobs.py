# -*- coding: utf-8 -*-
"""Background jobs: a bounded in-memory output buffer per command.

A background job is owned by a session and lives only as long as the daemon
process. Output is kept in a ring buffer measured in bytes; when the budget is
exceeded the oldest chunks are dropped so a runaway command cannot exhaust
memory.
"""

import threading
import time
import uuid

from .config import format_timestamp


class Job(object):
    """One background command and its buffered output."""

    def __init__(self, job_id, session_id, command, max_bytes):
        self.id = job_id
        self.session_id = session_id
        self.command = command
        self.max_bytes = max_bytes
        self.status = "running"        # running | done | failed | killed
        self.exit_status = None
        self.error = None
        self.started_at = time.time()
        self.finished_at = None
        self.channel = None            # paramiko Channel, used by kill()
        self.killed = False
        self._chunks = []              # [seq, stream, text]
        self._seq = 0
        self._bytes = 0
        self._lock = threading.Lock()
        self._updated = threading.Condition(self._lock)

    # -- producer side -----------------------------------------------------

    def append(self, stream, text):
        if not text:
            return
        size = len(text.encode("utf-8", "replace"))
        with self._updated:
            self._seq += 1
            self._chunks.append([self._seq, stream, text])
            self._bytes += size
            while self._bytes > self.max_bytes and len(self._chunks) > 1:
                _, _, dropped = self._chunks.pop(0)
                self._bytes -= len(dropped.encode("utf-8", "replace"))
            self._updated.notify_all()

    def finish(self, status, exit_status=None, error=None):
        with self._updated:
            self.status = status
            self.exit_status = exit_status
            self.error = error
            self.finished_at = time.time()
            self.channel = None
            self._updated.notify_all()

    def kill(self):
        """Close the underlying channel; the runner records the outcome."""
        self.killed = True
        channel = self.channel
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass

    # -- consumer side -----------------------------------------------------

    @property
    def finished(self):
        return self.status != "running"

    def snapshot(self, since=0):
        """All buffered chunks newer than ``since`` plus the latest sequence."""
        with self._lock:
            chunks = [list(chunk) for chunk in self._chunks if chunk[0] > since]
            return chunks, self._seq

    def wait_for_update(self, since, timeout):
        """Block for new output or completion; returns (chunks, seq, finished)."""
        with self._updated:
            if self._seq <= since and not self.finished:
                self._updated.wait(timeout)
            chunks = [list(chunk) for chunk in self._chunks if chunk[0] > since]
            return chunks, self._seq, self.finished

    def info(self):
        end = self.finished_at or time.time()
        return {
            "job_id": self.id,
            "session_id": self.session_id,
            "command": self.command,
            "status": self.status,
            "exit_status": self.exit_status,
            "error": self.error,
            "started_at": format_timestamp(self.started_at),
            "finished_at": format_timestamp(self.finished_at) if self.finished_at else None,
            "duration_seconds": round(end - self.started_at, 3),
        }


class JobRegistry(object):
    """Daemon-wide registry of background jobs."""

    def __init__(self, max_bytes, max_finished=50):
        self.max_bytes = max_bytes
        self.max_finished = max_finished
        self._jobs = {}
        self._lock = threading.Lock()

    def create(self, session_id, command):
        job = Job(str(uuid.uuid4()), session_id, command, self.max_bytes)
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id):
        with self._lock:
            return self._jobs.get(job_id)

    def remove(self, job_id):
        with self._lock:
            self._jobs.pop(job_id, None)

    def list(self):
        with self._lock:
            jobs = list(self._jobs.values())
        jobs.sort(key=lambda job: job.started_at)
        return jobs

    def for_session(self, session_id):
        with self._lock:
            return [job for job in self._jobs.values() if job.session_id == session_id]

    def prune_session(self, session_id):
        """Kill and drop every job owned by a session (used on close)."""
        for job in self.for_session(session_id):
            job.kill()
            self.remove(job.id)

    def prune_finished(self, session_id):
        """Keep at most ``max_finished`` completed jobs per session."""
        finished = [job for job in self.for_session(session_id) if job.finished]
        if len(finished) <= self.max_finished:
            return
        finished.sort(key=lambda job: job.finished_at or 0)
        for job in finished[:len(finished) - self.max_finished]:
            self.remove(job.id)

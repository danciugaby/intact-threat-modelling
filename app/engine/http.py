"""Small HTTP helpers shared by the data-source clients: a TTL cache, a sliding-window
rate limiter and a retrying GET."""
import logging
import threading
import time
from collections import deque

import requests

log = logging.getLogger(__name__)


class TTLCache:
    def __init__(self, ttl_seconds, max_items=2048):
        self.ttl = ttl_seconds
        self.max_items = max_items
        self._data = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            expires, value = item
            if expires < time.monotonic():
                self._data.pop(key, None)
                return None
            return value

    def set(self, key, value):
        with self._lock:
            if len(self._data) >= self.max_items:
                # drop the entry closest to expiry
                oldest = min(self._data, key=lambda k: self._data[k][0])
                self._data.pop(oldest, None)
            self._data[key] = (time.monotonic() + self.ttl, value)


class RateLimiter:
    """Allow at most ``max_calls`` per ``period`` seconds across threads."""

    def __init__(self, max_calls, period):
        self.max_calls = max_calls
        self.period = period
        self._calls = deque()
        self._lock = threading.Lock()

    def acquire(self):
        while True:
            with self._lock:
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self.period:
                    self._calls.popleft()
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return
                wait = self.period - (now - self._calls[0]) + 0.05
            time.sleep(max(wait, 0.05))


class UpstreamError(RuntimeError):
    """A data source could not be reached or returned an error."""


def get_json(session, url, *, params=None, headers=None, timeout=20, retries=3,
             limiter=None, backoff=2.0):
    """GET ``url`` and return decoded JSON, retrying on 429/5xx and network errors.
    Never loops forever: raises ``UpstreamError`` after ``retries`` attempts."""
    last_err = None
    for attempt in range(1, retries + 1):
        if limiter:
            limiter.acquire()
        try:
            resp = session.get(url, params=params, headers=headers, timeout=timeout)
        except requests.RequestException as exc:
            last_err = exc
        else:
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 404:
                return None
            last_err = UpstreamError(f"{url} returned HTTP {resp.status_code}")
            if resp.status_code not in (403, 429, 500, 502, 503, 504):
                break  # not retryable
        if attempt < retries:
            delay = backoff * (2 ** (attempt - 1))
            log.warning("GET %s failed (%s); retry %d/%d in %.1fs", url, last_err, attempt, retries, delay)
            time.sleep(delay)
    raise UpstreamError(str(last_err))

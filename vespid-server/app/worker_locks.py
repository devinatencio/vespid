"""Cross-worker singleton lock helper for gunicorn background services.

Background services (alert evaluator, check scheduler, retention/host-events/
command/backup reapers, geoip updater) must run in exactly one gunicorn worker.

Gunicorn recycles workers via ``max_requests``.  The previous implementation
gated these services behind a worker-age check in ``post_fork`` (only the
``worker.age == reaper_age`` worker started them).  When that worker was
recycled, the replacement had a different age, so the services never restarted
and silently stopped running — which surfaced as stale data in the UI (e.g. a
host modal stuck on an old date while the live graph kept updating).

The fix uses a kernel-backed ``flock`` (same pattern as the fleet reaper):
every worker attempts to start each service, but only the worker that wins the
flock actually runs it.  When the owning worker exits (normal recycle, crash,
reload) the kernel releases the lock, so a replacement worker acquires it in
its own ``post_fork`` call.  A short retry covers the brief overlap during a
graceful SIGHUP reload.
"""

import fcntl
import functools
import logging
import os
import tempfile
import threading

logger = logging.getLogger(__name__)

# fd kept open for the lifetime of the process so the flock stays held.
_held_locks: dict[str, int] = {}


def acquire_worker_lock(name: str) -> bool:
    """Try to acquire an exclusive cross-worker flock named ``name``.

    Returns True if acquired (fd retained for process lifetime), or False if
    another worker already holds the lock.
    """
    if name in _held_locks:
        return True
    path = os.path.join(tempfile.gettempdir(), f"vespid_{name}.lock")
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return False
    _held_locks[name] = fd
    return True


def release_worker_lock(name: str) -> None:
    """Explicitly release a lock (mainly useful for tests)."""
    fd = _held_locks.pop(name, None)
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass


def singleton(name: str, retry_secs: float = 10.0, max_retries: int = 6):
    """Decorator: run the wrapped start function only in the worker that wins
    the named flock.

    If another worker currently holds the lock, retry a few times (covering
    the short window where an old worker is still draining during a graceful
    reload) before giving up.
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            attempt = kwargs.pop("_singleton_retries_left", max_retries)
            if acquire_worker_lock(name):
                logger.info("Acquired singleton lock '%s' (pid=%d)", name, os.getpid())
                return fn(*args, **kwargs)

            if attempt <= 0:
                # Expected outcome for every losing worker: exactly one worker
                # runs each singleton service. Not an error condition.
                logger.debug(
                    "Giving up on singleton lock '%s' (pid=%d): still held by another worker",
                    name,
                    os.getpid(),
                )
                return None
            logger.debug(
                "Singleton lock '%s' held by another worker; retry in %ss (pid=%d, %d left)",
                name,
                retry_secs,
                os.getpid(),
                attempt - 1,
            )
            timer = threading.Timer(
                retry_secs,
                lambda: wrapper(*args, _singleton_retries_left=attempt - 1, **kwargs),
            )
            timer.daemon = True
            timer.start()
            return None

        return wrapper

    return decorator

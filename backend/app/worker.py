"""The background process: folder watcher, blockchain anchoring and the job queue, exactly once.

    MEDSEAL_PROCESS_ROLE=api uvicorn app.main:app --workers 4   # HTTP only
    python -m app.worker                                       # one of these, next to them

Stops cleanly on SIGTERM/SIGINT (container stop): the running job finishes its current step and
its row records the outcome; a job cut off mid-way is reported by the stale-heartbeat check.
"""
import signal
import threading

from app.config import settings
from app.main import prepare, start_background, stop_background


def main() -> None:
    settings.process_role = "worker"
    prepare()
    start_background()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    stop.wait()
    stop_background()


if __name__ == "__main__":
    main()

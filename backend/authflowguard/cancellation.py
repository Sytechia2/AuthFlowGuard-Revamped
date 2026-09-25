"""Thread-safe cooperative cancellation for scan-owned asynchronous work."""

import asyncio
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from threading import Event, Lock
from typing import Protocol


class AsyncCloseable(Protocol):
    async def close(self) -> None:
        """Release an asynchronously owned resource."""


class ScanCancelledError(asyncio.CancelledError):
    """Raised when a scan cancellation request reaches owned async work."""


_current_control: ContextVar["CancellationControl | None"] = ContextVar(
    "authflowguard_cancellation_control", default=None
)


class CancellationControl:
    """Bridge cancellation requests into the event loop that owns scan work.

    A request may arrive before registration, from the API thread, or repeatedly.
    Registration therefore checks the flag and cancellation is delivered with the
    owning loop's thread-safe scheduler.
    """

    def __init__(self) -> None:
        self._requested = Event()
        self._lock = Lock()
        self._registrations: dict[asyncio.Task[object], asyncio.AbstractEventLoop] = {}

    def is_requested(self) -> bool:
        return self._requested.is_set()

    def request(self) -> bool:
        """Request cancellation once and interrupt every registered root task."""

        first_request = not self._requested.is_set()
        self._requested.set()
        with self._lock:
            registrations = list(self._registrations.items())
        for task, loop in registrations:
            if not loop.is_closed():
                loop.call_soon_threadsafe(task.cancel, "scan cancellation requested")
        return first_request

    def checkpoint(self) -> None:
        if self._requested.is_set():
            raise ScanCancelledError("scan cancellation requested")

    @property
    def has_active_work(self) -> bool:
        with self._lock:
            return bool(self._registrations)

    @contextmanager
    def register_current_task(self) -> Iterator[None]:
        """Register the calling task and expose this control through contextvars."""

        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("Cancellation registration requires an asyncio task")
        typed_task: asyncio.Task[object] = task
        with self._lock:
            self._registrations[typed_task] = loop
        context_token: Token[CancellationControl | None] = _current_control.set(self)
        try:
            self.checkpoint()
            yield
        finally:
            _current_control.reset(context_token)
            with self._lock:
                self._registrations.pop(typed_task, None)


def cancellation_checkpoint() -> None:
    """Check the cancellation control inherited by the current async context."""

    control = _current_control.get()
    if control is not None:
        control.checkpoint()


def current_cancellation_control() -> CancellationControl | None:
    """Return the inherited control, primarily for child-task propagation."""

    return _current_control.get()


async def close_resources(*resources: AsyncCloseable | None) -> None:
    """Close every resource in order while preserving the primary exception."""

    active_exception = sys.exception()
    errors: list[BaseException] = []
    for resource in resources:
        if resource is None:
            continue
        try:
            await resource.close()
        except BaseException as error:
            errors.append(error)
    if active_exception is None and errors:
        raise errors[0]

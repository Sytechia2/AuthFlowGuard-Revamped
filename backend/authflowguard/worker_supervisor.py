"""Spawn-compatible supervision for one bounded AuthFlowGuard worker."""

from __future__ import annotations

import multiprocessing
import os
import queue
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from multiprocessing.context import SpawnContext
from multiprocessing.process import BaseProcess
from multiprocessing.queues import Queue
from typing import Any
from uuid import UUID

from authflowguard.worker_protocol import (
    WorkerAcknowledgement,
    WorkerCommand,
    WorkerMessage,
    WorkerMessageType,
)

WorkerCallback = Callable[
    [WorkerMessage | None, int | None, bool], WorkerAcknowledgement | None
]
WorkerEntrypoint = Callable[[dict[str, Any], Any, Any, Any], None]


def _worker_entry(
    command_data: dict[str, Any],
    output: Queue[dict[str, Any]],
    control: Queue[dict[str, Any]],
    cancel_event: Any,
) -> None:
    """Import the heavy worker runtime only inside the spawned process."""

    if os.name != "nt":
        try:
            os.__dict__["setsid"]()
        except OSError:
            pass
    from authflowguard.scan_worker import execute_worker_command

    execute_worker_command(command_data, output, control, cancel_event)


@dataclass
class WorkerHandle:
    command: WorkerCommand
    process: BaseProcess
    output: Queue[dict[str, Any]]
    control: Queue[dict[str, Any]]
    cancel_event: Any
    future: Future[None]
    watcher: threading.Thread
    started_at: float
    ready: threading.Event
    forced: bool = False
    cleanup_confirmed: bool = False


class WorkerSupervisor:
    """Own spawned processes and terminate only the process tree it created."""

    def __init__(
        self,
        cancellation_grace_seconds: float = 3.0,
        entrypoint: WorkerEntrypoint = _worker_entry,
    ) -> None:
        self._context: SpawnContext = multiprocessing.get_context("spawn")
        self._grace_seconds = cancellation_grace_seconds
        self._entrypoint = entrypoint
        self._lock = threading.Lock()
        self._handles: dict[tuple[UUID, int], WorkerHandle] = {}

    def start(
        self,
        command: WorkerCommand,
        callback: WorkerCallback,
    ) -> Future[None]:
        output: Queue[dict[str, Any]] = self._context.Queue(maxsize=32)
        control: Queue[dict[str, Any]] = self._context.Queue(maxsize=32)
        cancel_event = self._context.Event()
        future: Future[None] = Future()
        process = self._context.Process(
            target=self._entrypoint,
            args=(command.model_dump(mode="json"), output, control, cancel_event),
            name=f"afg-{command.scan_id}-{command.worker_generation}",
            daemon=False,
        )
        process.start()
        handle = WorkerHandle(
            command=command,
            process=process,
            output=output,
            control=control,
            cancel_event=cancel_event,
            future=future,
            watcher=threading.current_thread(),
            started_at=time.monotonic(),
            ready=threading.Event(),
        )
        watcher = threading.Thread(
            target=self._watch,
            args=(handle, callback),
            name=f"afg-watch-{command.scan_id}",
            daemon=True,
        )
        handle.watcher = watcher
        with self._lock:
            key = (command.scan_id, command.worker_generation)
            if key in self._handles:
                process.terminate()
                process.join(timeout=1)
                raise RuntimeError("The worker generation is already active")
            self._handles[key] = handle
        watcher.start()
        if not handle.ready.wait(timeout=5):
            handle.forced = True
            self._terminate_owned_tree(handle)
            watcher.join(timeout=2)
            raise RuntimeError("The isolated worker did not acknowledge startup")
        return future

    def cancel(self, scan_id: UUID, worker_generation: int) -> bool:
        handle = self._get(scan_id, worker_generation)
        if handle is None:
            return False
        handle.cancel_event.set()
        threading.Thread(
            target=self._escalate,
            args=(handle,),
            name=f"afg-stop-{scan_id}",
            daemon=True,
        ).start()
        return True

    def is_active(self, scan_id: UUID, worker_generation: int) -> bool:
        handle = self._get(scan_id, worker_generation)
        return handle is not None and handle.process.is_alive()

    def identity(
        self, scan_id: UUID, worker_generation: int
    ) -> tuple[int, float] | None:
        handle = self._get(scan_id, worker_generation)
        if handle is None or handle.process.pid is None:
            return None
        return handle.process.pid, handle.started_at

    def shutdown(self, timeout: float = 5.0) -> None:
        with self._lock:
            handles = list(self._handles.values())
        for handle in handles:
            handle.cancel_event.set()
        deadline = time.monotonic() + timeout
        for handle in handles:
            remaining = max(0.0, deadline - time.monotonic())
            handle.process.join(timeout=remaining)
            if handle.process.is_alive():
                handle.forced = True
                self._terminate_owned_tree(handle)
                handle.process.join(timeout=1)

    def _get(self, scan_id: UUID, worker_generation: int) -> WorkerHandle | None:
        with self._lock:
            return self._handles.get((scan_id, worker_generation))

    def _watch(self, handle: WorkerHandle, callback: WorkerCallback) -> None:
        final_message: WorkerMessage | None = None
        last_sequence = 0
        while True:
            try:
                raw_message = handle.output.get(timeout=0.1)
            except queue.Empty:
                if not handle.process.is_alive():
                    break
                continue
            try:
                message = WorkerMessage.model_validate(raw_message)
            except (TypeError, ValueError):
                continue
            if (
                message.scan_id != handle.command.scan_id
                or message.worker_generation != handle.command.worker_generation
                or message.correlation_id != handle.command.correlation_id
                or message.sequence <= last_sequence
            ):
                continue
            last_sequence = message.sequence
            if message.message_type.value == "ready":
                handle.ready.set()
            elif message.message_type is WorkerMessageType.PROGRESS:
                callback(message, None, False)
                continue
            elif message.message_type in {
                WorkerMessageType.USAGE_RESERVE,
                WorkerMessageType.USAGE_DISPATCHED,
                WorkerMessageType.USAGE_SETTLE,
                WorkerMessageType.USAGE_RELEASE,
            }:
                acknowledgement = callback(message, None, False)
                if acknowledgement is not None:
                    handle.control.put(
                        acknowledgement.model_dump(mode="json"),
                        block=True,
                        timeout=5,
                    )
                continue
            if message.cleanup_confirmed:
                handle.cleanup_confirmed = True
            final_message = message
        handle.process.join(timeout=0.5)
        exit_code = handle.process.exitcode
        with self._lock:
            self._handles.pop(
                (handle.command.scan_id, handle.command.worker_generation), None
            )
        try:
            if handle.ready.is_set():
                callback(final_message, exit_code, handle.forced)
        finally:
            handle.output.close()
            handle.output.join_thread()
            handle.control.close()
            handle.control.join_thread()
            if not handle.future.done():
                handle.future.set_result(None)

    def _escalate(self, handle: WorkerHandle) -> None:
        handle.process.join(timeout=self._grace_seconds)
        if handle.process.is_alive():
            handle.forced = True
            self._terminate_owned_tree(handle)
            handle.process.join(timeout=1)

    @staticmethod
    def _terminate_owned_tree(handle: WorkerHandle) -> None:
        if os.name == "nt":
            # taskkill is PID-scoped and /T follows only this worker's descendants.
            import subprocess

            subprocess.run(
                ["taskkill", "/PID", str(handle.process.pid), "/T", "/F"],
                check=False,
                capture_output=True,
                timeout=5,
            )
        else:
            import signal

            try:
                os.__dict__["killpg"](
                    handle.process.pid,
                    signal.__dict__["SIGKILL"],
                )
            except ProcessLookupError:
                pass
        if handle.process.is_alive():
            handle.process.terminate()

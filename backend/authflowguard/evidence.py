"""Append-only local storage for redacted scan evidence and result versions."""

import json
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from pydantic import BaseModel

from authflowguard.models import (
    SCHEMA_VERSION,
    AuthProfile,
    CheckResult,
    EvidenceEvent,
    TestRunEvidence,
)
from authflowguard.scope import url_without_query_or_fragment

_SENSITIVE_KEY_NAMES = {
    "authorization",
    "body",
    "cookie",
    "cookies",
    "headers",
    "password",
    "secret",
    "set-cookie",
    "token",
    "value",
    "values",
}

_event_sink: ContextVar[Any] = ContextVar("authflowguard_event_sink", default=None)


@contextmanager
def incremental_event_sink(sink: Any) -> Iterator[None]:
    """Install a scan-local sink for completed redacted events."""

    token = _event_sink.set(sink)
    try:
        yield
    finally:
        _event_sink.reset(token)


def publish_completed_events(events: Iterable[EvidenceEvent]) -> None:
    """Flush completed events without coupling execution code to persistence."""

    sink = _event_sink.get()
    if sink is not None:
        sink(list(events))


def _redact_value(
    value: Any,
    secret_values: tuple[str, ...],
    key: str | None = None,
) -> Any:
    key_name = key.lower().replace("_", "-") if key else ""
    if key_name in _SENSITIVE_KEY_NAMES:
        return "[redacted]"
    if isinstance(value, Mapping):
        return {
            str(child_key): _redact_value(child_value, secret_values, str(child_key))
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item, secret_values, key) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item, secret_values, key) for item in value]
    if not isinstance(value, str):
        return value

    redacted = value
    for secret in secret_values:
        if secret:
            redacted = redacted.replace(secret, "[redacted]")
    if key_name == "url":
        return url_without_query_or_fragment(redacted)
    return redacted


def redact_persisted_data(
    value: Any,
    secret_values: Iterable[str] = (),
) -> Any:
    """Redact live secrets and unsafe URL data before writing local evidence."""

    return _redact_value(value, tuple(secret_values))


class EvidenceStore:
    """Store one scan in a bounded directory under a configured local root."""

    def __init__(self, root: str | Path, secret_values: Iterable[str] = ()) -> None:
        self._root = Path(root).resolve()
        self._secret_values = tuple(secret_values)

    def create_scan(
        self,
        scan_id: UUID,
        metadata: Mapping[str, Any] | BaseModel | None = None,
    ) -> Path:
        scan_dir = self._scan_dir(scan_id)
        scan_dir.mkdir(parents=True, exist_ok=True)
        metadata_path = scan_dir / "metadata.json"
        if not metadata_path.exists():
            metadata_data: Any = (
                metadata.model_dump(mode="json")
                if isinstance(metadata, BaseModel)
                else dict(metadata or {})
            )
            metadata_data = {
                "schema_version": SCHEMA_VERSION,
                "scan_id": str(scan_id),
                **metadata_data,
            }
            self._write_json(metadata_path, metadata_data)
        return scan_dir

    def scan_directory(self, scan_id: UUID) -> Path:
        """Return the validated directory for one scan."""

        return self._scan_dir(scan_id)

    def append_event(self, event: EvidenceEvent) -> None:
        scan_dir = self.create_scan(event.scan_id)
        event_data = redact_persisted_data(
            event.model_dump(mode="json"), self._secret_values
        )
        with (scan_dir / "events.ndjson").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event_data, sort_keys=True) + "\n")

    def read_events(self, scan_id: UUID) -> list[EvidenceEvent]:
        events_path = self._scan_dir(scan_id) / "events.ndjson"
        if not events_path.exists():
            return []
        with events_path.open(encoding="utf-8") as stream:
            return [
                EvidenceEvent.model_validate_json(line)
                for line in stream
                if line.strip()
            ]

    def save_evidence(self, evidence: TestRunEvidence) -> Path:
        check_dir = (
            self._scan_dir(evidence.scan_id) / "checks" / evidence.check_id.value
        )
        check_dir.mkdir(parents=True, exist_ok=True)
        evidence_data = redact_persisted_data(
            evidence.model_dump(mode="json"), self._secret_values
        )
        path = check_dir / f"evidence-{evidence.evidence_id}.json"
        self._write_json(path, evidence_data)
        return path

    def read_evidence(
        self, scan_id: UUID, check_id: str, evidence_id: UUID
    ) -> TestRunEvidence:
        path = (
            self._scan_dir(scan_id)
            / "checks"
            / check_id
            / f"evidence-{evidence_id}.json"
        )
        return TestRunEvidence.model_validate_json(path.read_text(encoding="utf-8"))

    def save_result(self, result: CheckResult) -> tuple[int, Path]:
        results_dir = self._scan_dir(result.scan_id) / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        versions = [
            int(path.stem.removeprefix("result-v"))
            for path in results_dir.glob("result-v*.json")
            if path.stem.removeprefix("result-v").isdigit()
        ]
        version = max(versions, default=0) + 1
        result_data = redact_persisted_data(
            result.model_dump(mode="json"), self._secret_values
        )
        result_data["result_version"] = version
        path = results_dir / f"result-v{version}.json"
        self._write_json(path, result_data)
        return version, path

    def save_profile(self, scan_id: UUID, profile: AuthProfile) -> Path:
        """Save the verified, nonsecret authentication profile for a scan."""

        path = self._scan_dir(scan_id) / "auth-profile.json"
        self._write_json(
            path,
            redact_persisted_data(profile.model_dump(mode="json"), self._secret_values),
        )
        return path

    def read_profile(self, scan_id: UUID) -> AuthProfile | None:
        """Read a saved authentication profile, if this scan has one."""

        path = self._scan_dir(scan_id) / "auth-profile.json"
        if not path.exists():
            return None
        return AuthProfile.model_validate_json(path.read_text(encoding="utf-8"))

    def read_results(self, scan_id: UUID) -> list[dict[str, Any]]:
        results_dir = self._scan_dir(scan_id) / "results"
        if not results_dir.exists():
            return []
        results: list[dict[str, Any]] = []
        for path in sorted(
            results_dir.glob("result-v*.json"),
            key=lambda path: int(path.stem.removeprefix("result-v")),
        ):
            results.append(json.loads(path.read_text(encoding="utf-8")))
        return results

    def read_metadata(self, scan_id: UUID) -> dict[str, Any]:
        path = self._scan_dir(scan_id) / "metadata.json"
        return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))

    def list_scan_ids(self) -> list[UUID]:
        """Return scan directories with valid UUID names, newest first."""

        if not self._root.exists():
            return []
        scan_ids: list[tuple[float, UUID]] = []
        for directory in self._root.iterdir():
            if not directory.is_dir():
                continue
            try:
                scan_id = UUID(directory.name)
            except ValueError:
                continue
            metadata_path = directory / "metadata.json"
            if not metadata_path.exists():
                continue
            scan_ids.append((metadata_path.stat().st_mtime, scan_id))
        return [scan_id for _, scan_id in sorted(scan_ids, reverse=True)]

    def read_all_evidence(self, scan_id: UUID) -> list[TestRunEvidence]:
        """Read every persisted check evidence package for one scan."""

        checks_dir = self._scan_dir(scan_id) / "checks"
        if not checks_dir.exists():
            return []
        evidence: list[TestRunEvidence] = []
        for path in sorted(checks_dir.glob("*/evidence-*.json")):
            evidence.append(
                TestRunEvidence.model_validate_json(path.read_text(encoding="utf-8"))
            )
        return evidence

    def update_metadata(self, scan_id: UUID, updates: Mapping[str, Any]) -> None:
        """Update nonsecret scan index metadata without touching evidence."""

        metadata = self.read_metadata(scan_id)
        metadata.update(redact_persisted_data(updates, self._secret_values))
        self._write_json(self._scan_dir(scan_id) / "metadata.json", metadata)

    def _scan_dir(self, scan_id: UUID) -> Path:
        scan_dir = (self._root / str(scan_id)).resolve()
        try:
            scan_dir.relative_to(self._root)
        except ValueError as error:
            raise ValueError(
                "The scan directory would leave the evidence root"
            ) from error
        return scan_dir

    def _write_json(self, path: Path, value: Any) -> None:
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

"""Runtime-only secret handling for browser execution."""

from collections.abc import Iterable


def redact_text(text: str, secret_values: Iterable[str]) -> str:
    """Replace live secret values in text without retaining them globally."""

    redacted = text
    for value in secret_values:
        if value:
            redacted = redacted.replace(value, "[redacted]")
    return redacted


class SecretReferenceNotFoundError(KeyError):
    """Raised when an action refers to a secret not supplied for this scan."""


class RuntimeSecrets:
    """Resolve live values in memory without placing them in persisted models."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values.copy()

    def resolve(self, reference_id: str) -> str:
        try:
            return self._values[reference_id]
        except KeyError as error:
            raise SecretReferenceNotFoundError(
                f"No runtime secret was supplied for reference '{reference_id}'"
            ) from error

    def discard_all(self) -> None:
        for reference_id in list(self._values):
            self._values[reference_id] = ""
        self._values.clear()

    def redaction_values(self) -> tuple[str, ...]:
        """Return values for a short-lived output-redaction scope."""

        return tuple(value for value in self._values.values() if value)

    def redact_text(self, text: str) -> str:
        """Remove any currently-held secret values from user-facing text."""
        return redact_text(text, self._values.values())

    def __len__(self) -> int:
        return len(self._values)

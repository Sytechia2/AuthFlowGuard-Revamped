"""Runtime-only secret handling for browser execution."""


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

    def redact_text(self, text: str) -> str:
        """Remove any currently-held secret values from user-facing text."""
        redacted = text
        for value in self._values.values():
            if value:
                redacted = redacted.replace(value, "[redacted]")
        return redacted

    def __len__(self) -> int:
        return len(self._values)

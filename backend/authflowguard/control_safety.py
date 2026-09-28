"""Safety rules for acting on a resolved page control.

A recorded control is found by its fingerprint where it has one and by
position otherwise, and either way a replay against the wrong page can
resolve a reference to an unrelated element. These rules decide, from a few
nonsecret facts about the element, whether an action may touch it at all.
They are pure so they can be tested without a browser; the executor gathers
the facts and enforces the result before the browser acts.
"""

import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Self

from authflowguard.models import ControlFingerprint

# Words that name an irreversible account action wherever they appear in a
# control's label.
IRREVERSIBLE_VERBS = (
    "delete",
    "remove",
    "deactivate",
    "erase",
    "terminate",
    "unsubscribe",
)
# Words that are harmless alone ("Close" on a cookie banner, "Cancel" in a
# dialog) but irreversible when they act on the account itself.
ACCOUNT_SCOPED_VERBS = ("close", "cancel", "disable")
ACCOUNT_NOUNS = ("account", "profile", "user", "membership", "subscription")

# The strict rule for code that searches a signed-in page on its own, such as
# the logout check's menu search: nothing named by any of these words is ever
# clicked, because the search chooses controls the developer never reviewed.
STRICT_DESTRUCTIVE_LABEL = re.compile(
    r"\b(" + "|".join(IRREVERSIBLE_VERBS + ACCOUNT_SCOPED_VERBS) + r")\b",
    re.IGNORECASE,
)

# The executor-level rule. Every guided, AI and saved step passes through the
# executor, so it blocks only clearly irreversible actions: an irreversible
# verb anywhere, or an account-scoped verb directly followed by an account
# noun ("Close account", "Cancel my subscription"). A lone "Close" or
# "Cancel" stays clickable.
IRREVERSIBLE_ACTION_LABEL = re.compile(
    r"\b(" + "|".join(IRREVERSIBLE_VERBS) + r")\b"
    r"|\b(" + "|".join(ACCOUNT_SCOPED_VERBS) + r")\s+"
    r"(?:(?:my|your|the|this)\s+)?"
    r"(" + "|".join(ACCOUNT_NOUNS) + r")s?\b",
    re.IGNORECASE,
)

# Effective input types (HTMLInputElement.type) that accept typed text.
TEXT_ENTRY_INPUT_TYPES = frozenset(
    {"text", "email", "tel", "url", "search", "password", "number"}
)

# Input types that may appear in a message. The effective type comes from the
# browser, but only these fixed words are ever echoed.
_DESCRIBABLE_INPUT_TYPES = frozenset(
    TEXT_ENTRY_INPUT_TYPES
    | {
        "button",
        "checkbox",
        "color",
        "date",
        "datetime-local",
        "file",
        "hidden",
        "image",
        "month",
        "radio",
        "range",
        "reset",
        "submit",
        "time",
        "week",
    }
)


@dataclass(frozen=True)
class ControlFacts:
    """Nonsecret facts about one resolved control.

    ``input_type`` is the effective type for an ``input`` (the browser reports
    ``text`` when the attribute is missing) and ``None`` for other tags.
    ``label`` is the accessible label used only for matching; it is never
    placed in a message. It never includes a text field's typed value.
    """

    tag: str
    input_type: str | None
    visible: bool
    enabled: bool
    read_only: bool
    label: str


class ControlRefusal(Enum):
    """Why an action was refused, as a fixed message template."""

    NOT_TEXT_FIELD = "{control} is {element}, not a text field, so {outcome}."
    NOT_PASSWORD_FIELD = "{control} is {element}, not a password field, so {outcome}."
    PASSWORD_FIELD_FOR_OTHER_VALUE = (
        "{control} is a password field but the value is not a password "
        "credential, so {outcome}."
    )
    NOT_VISIBLE = (
        "{control} did not become visible within the time limit, so {outcome}."
    )
    DISABLED = "{control} is disabled, so {outcome}."
    READ_ONLY = "{control} is read-only, so {outcome}."
    IRREVERSIBLE_ACTION = (
        "{control} is labelled as an irreversible account action, so {outcome}."
    )
    # The browser gave up on an action that passed the checks above. Its own
    # message is never shown: it can quote the value being typed.
    NOT_EDITABLE_IN_TIME = (
        "{control} did not become editable within the time limit, so {outcome}."
    )
    NOT_CLICKABLE_IN_TIME = (
        "{control} did not become clickable within the time limit, so {outcome}."
    )
    NO_KEY_RESPONSE_IN_TIME = (
        "{control} did not accept the key within the time limit, so {outcome}."
    )
    FILL_FAILED = "The browser could not fill {control}, so {outcome}."
    # The recorded control's fingerprint resolved to no control, or to
    # several that its recorded ordinal no longer tells apart. The control at
    # the recorded position is never used instead.
    NOT_ON_PAGE = (
        "{element} recorded for this flow as {control} is not on the page, "
        "so {outcome}."
    )
    AMBIGUOUS_ON_PAGE = (
        "{element} recorded for this flow as {control} now matches several "
        "controls on the page, so {outcome}."
    )


class ControlOutcome(Enum):
    """What was not done, as fixed wording."""

    PASSWORD_NOT_TYPED = "the password was not typed into it"
    VALUE_NOT_TYPED = "the value was not typed into it"
    NOT_CLICKED = "it was not clicked"
    KEY_NOT_PRESSED = "no key was pressed on it"
    NOT_SELECTED = "no option was selected in it"
    NOT_WAITED_FOR = "the flow did not wait for it"


_CONTROL_ID = re.compile(r"control-[1-9][0-9]{0,5}")


class SafeMessageError(Exception):
    """An error whose message is safe to show to the user.

    Subclasses build the message only from fixed wording and nonsecret
    identifiers, so it can be surfaced where other exceptions show only their
    type name. Never pass page text, typed values, URLs or another
    exception's message into one.
    """

    @property
    def safe_message(self) -> str:
        return str(self)


class UnsafeControlError(SafeMessageError):
    """An action was refused because its control is not safe to act on."""

    def __init__(
        self,
        control_id: str,
        refusal: ControlRefusal,
        outcome: ControlOutcome,
        facts: ControlFacts | None = None,
        *,
        recorded: ControlFingerprint | None = None,
    ) -> None:
        if not _CONTROL_ID.fullmatch(control_id):
            control_id = "the control"
        self.control_id = control_id
        self.refusal = refusal
        self.outcome = outcome
        # Only the fixed description is kept, never the facts' label or the
        # fingerprint's attributes.
        if recorded is not None:
            self.element = describe_recorded(recorded)
        elif facts is not None:
            self.element = describe_element(facts)
        else:
            self.element = "a control"
        self.step: int | None = None
        super().__init__(self._render())

    def at_step(self, step: int) -> Self:
        """Record the 1-based position of the refused action in its flow."""

        self.step = step
        self.args = (self._render(),)
        return self

    def _render(self) -> str:
        message = self.refusal.value.format(
            control=self.control_id,
            element=self.element,
            outcome=self.outcome.value,
        )
        if message.startswith("the "):
            message = "T" + message[1:]
        if self.step is not None:
            return f"Step {self.step}: {message}"
        return message


@contextmanager
def flow_step(step: int) -> Iterator[None]:
    """Name the 1-based step of a saved flow in any control refusal inside."""

    try:
        yield
    except UnsafeControlError as error:
        error.at_step(step)
        raise


def describe_error(error: BaseException) -> str:
    """Name an error for a user-facing list without exposing unsafe text.

    Only a ``SafeMessageError`` contributes its message; any other exception
    contributes its type name alone, because its message may hold secrets.
    """

    if isinstance(error, SafeMessageError):
        return f"{type(error).__name__}: {error.safe_message}"
    return type(error).__name__


class RecordedControlNotFoundError(UnsafeControlError):
    """A recorded control's fingerprint no longer resolves to one control.

    The page no longer has the control the flow was recorded against, so a
    saved flow that raises it is stale rather than unsafe to run.
    """


def _describe_kind(tag: str, input_type: str | None) -> str:
    """Name a control's kind with fixed words only, without an article."""

    tag = tag.lower()
    if tag == "input":
        effective_type = (input_type or "text").lower()
        if effective_type in {"button", "submit", "reset", "image"}:
            return "button"
        if effective_type in _DESCRIBABLE_INPUT_TYPES:
            return f"{effective_type} input"
        return "input"
    return {
        "button": "button",
        "a": "link",
        "select": "drop-down list",
        "textarea": "text area",
    }.get(tag, "control")


def describe_element(facts: ControlFacts) -> str:
    """Describe a control's kind with fixed words only."""

    kind = _describe_kind(facts.tag, facts.input_type)
    article = "an" if kind[0] in "aeiou" else "a"
    return f"{article} {kind}"


def describe_recorded(fingerprint: ControlFingerprint) -> str:
    """Name a recorded control's kind with fixed words only."""

    return f"the {_describe_kind(fingerprint.tag, fingerprint.input_type)}"


def is_text_entry(facts: ControlFacts) -> bool:
    tag = facts.tag.lower()
    if tag == "textarea":
        return True
    return (
        tag == "input"
        and (facts.input_type or "text").lower() in TEXT_ENTRY_INPUT_TYPES
    )


def is_password_field(facts: ControlFacts) -> bool:
    return facts.tag.lower() == "input" and (facts.input_type or "").lower() == (
        "password"
    )


def fill_refusal(facts: ControlFacts, *, password_value: bool) -> ControlRefusal | None:
    """Return why a value may not be typed into this control, if it may not.

    Kind is checked before state, so a wrong element is refused at once rather
    than after waiting for it to become visible.
    """

    if not is_text_entry(facts):
        return ControlRefusal.NOT_TEXT_FIELD
    if password_value and not is_password_field(facts):
        return ControlRefusal.NOT_PASSWORD_FIELD
    if not password_value and is_password_field(facts):
        return ControlRefusal.PASSWORD_FIELD_FOR_OTHER_VALUE
    if not facts.visible:
        return ControlRefusal.NOT_VISIBLE
    if not facts.enabled:
        return ControlRefusal.DISABLED
    if facts.read_only:
        return ControlRefusal.READ_ONLY
    return None


def names_irreversible_action(label: str) -> bool:
    return IRREVERSIBLE_ACTION_LABEL.search(label) is not None


def activation_refusal(facts: ControlFacts) -> ControlRefusal | None:
    """Return why a control may not be clicked or sent a key, if it may not."""

    if names_irreversible_action(facts.label):
        return ControlRefusal.IRREVERSIBLE_ACTION
    if not facts.visible:
        return ControlRefusal.NOT_VISIBLE
    return None

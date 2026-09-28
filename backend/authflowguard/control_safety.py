"""Safety rules for acting on a resolved page control.

Controls are referenced by position, so a replay against the wrong page can
resolve a reference to an unrelated element. These rules decide, from a few
nonsecret facts about the element, whether an action may touch it at all.
They are pure so they can be tested without a browser; the executor gathers
the facts and enforces the result before the browser acts.
"""

import re
from dataclasses import dataclass
from enum import Enum

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


class ControlOutcome(Enum):
    """What was not done, as fixed wording."""

    PASSWORD_NOT_TYPED = "the password was not typed into it"
    VALUE_NOT_TYPED = "the value was not typed into it"
    NOT_CLICKED = "it was not clicked"
    KEY_NOT_PRESSED = "no key was pressed on it"


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
        element: str = "a control",
    ) -> None:
        if not _CONTROL_ID.fullmatch(control_id):
            control_id = "The control"
        self.control_id = control_id
        self.refusal = refusal
        self.outcome = outcome
        self.element = element
        super().__init__(
            refusal.value.format(
                control=control_id, element=element, outcome=outcome.value
            )
        )


def describe_element(facts: ControlFacts) -> str:
    """Describe a control's kind with fixed words only."""

    tag = facts.tag.lower()
    if tag == "input":
        input_type = (facts.input_type or "text").lower()
        if input_type in {"button", "submit", "reset", "image"}:
            return "a button"
        if input_type in _DESCRIBABLE_INPUT_TYPES:
            article = "an" if input_type[0] in "aeiou" else "a"
            return f"{article} {input_type} input"
        return "an input"
    return {
        "button": "a button",
        "a": "a link",
        "select": "a drop-down list",
        "textarea": "a text area",
    }.get(tag, "a control")


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

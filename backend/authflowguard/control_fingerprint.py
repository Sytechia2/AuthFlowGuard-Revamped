"""Identify a recorded control by what it is rather than where it sits.

A control is referenced as ``control-N``: the Nth element matching the
control selector. Anything that shifts the page, such as a cookie banner, a
lazily rendered menu or an A/B test, makes ``control-N`` a different element.
When an action is recorded, the executor keeps a fingerprint of the control
it acted on; a replay finds the control whose fingerprint matches, wherever
it now sits, and refuses to act when none or several do.

The functions here are pure so the matching rules can be tested without a
browser. The executor reads the raw descriptions with
``DESCRIBE_CONTROLS_SCRIPT`` in one DOM revision and passes them in.
"""

import re
from collections.abc import Callable, Mapping, Sequence
from enum import Enum
from typing import Any

from authflowguard.models import BrowserAction, ControlFingerprint

# Describes every control the executor can address, in the executor's order.
# It never reads what a field holds: a text field's value may be a
# credential. A button-like input shows its value as its label, so only
# theirs is read, as the page observation already does for buttons.
DESCRIBE_CONTROLS_SCRIPT = """elements => elements.map(element => {
    const tag = element.tagName.toLowerCase();
    const inputType = tag === 'input' ? String(element.type).toLowerCase() : null;
    let text = null;
    if (tag === 'button' || tag === 'a') {
        text = element.textContent;
    } else if (['button', 'submit', 'reset'].includes(inputType)) {
        text = element.getAttribute('value');
    } else if (inputType === 'image') {
        text = element.getAttribute('alt');
    }
    const form = element.form || element.closest('form');
    return {
        tag,
        input_type: inputType,
        id: element.getAttribute('id'),
        name: element.getAttribute('name'),
        autocomplete: element.getAttribute('autocomplete'),
        placeholder: element.getAttribute('placeholder'),
        aria_label: element.getAttribute('aria-label'),
        role: element.getAttribute('role'),
        text,
        form: form ? {
            id: form.getAttribute('id'),
            name: form.getAttribute('name'),
            action: form.getAttribute('action'),
        } : null,
    };
})"""

ATTRIBUTE_LIMIT = 200
TEXT_LIMIT = 80

# Generated ids. Frameworks number the elements they create (mat-input-3,
# ember123, React's :r1: or «r1»), and the number changes whenever a control
# is added before it, which is exactly the change fingerprints must survive.
# The general rule: an id holding a digit, a colon or a guillemet is treated
# as generated and ignored when matching. A readable id without them (email,
# loginButton) is treated as stable and must match. A stable id with a digit
# (step2-email) is thus ignored too, which only costs discriminating power:
# the other attributes, the form and the ordinal still apply.
_GENERATED_ID = re.compile(r"[0-9:«»]")

Redact = Callable[[str], str]
Descriptions = Sequence[Mapping[str, Any]]


class FingerprintMiss(Enum):
    """Why a recorded fingerprint does not resolve to one control."""

    ABSENT = "absent"
    AMBIGUOUS = "ambiguous"


def is_generated_id(value: str) -> bool:
    return _GENERATED_ID.search(value) is not None


def _clean(value: object, limit: int, redact: Redact) -> str | None:
    if not isinstance(value, str):
        return None
    collapsed = " ".join(value.split())[:limit]
    return redact(collapsed) if collapsed else None


def _form_key(form: object, redact: Redact) -> str | None:
    """Name the enclosing form by its stable attributes; None outside a form."""

    if not isinstance(form, Mapping):
        return None
    parts: list[str] = []
    form_id = _clean(form.get("id"), ATTRIBUTE_LIMIT, redact)
    if form_id is not None and not is_generated_id(form_id):
        parts.append(f"id={form_id}")
    form_name = _clean(form.get("name"), ATTRIBUTE_LIMIT, redact)
    if form_name is not None:
        parts.append(f"name={form_name}")
    action = _clean(form.get("action"), ATTRIBUTE_LIMIT, redact)
    if action is not None:
        # A query, fragment or path parameter can carry a session token.
        action_path = re.split(r"[?#;]", action, maxsplit=1)[0]
        if action_path:
            parts.append(f"action={action_path}")
    return " ".join(parts)


def describe(description: Mapping[str, Any], redact: Redact) -> ControlFingerprint:
    """Build the fingerprint of one described control, as if it were unique."""

    tag = _clean(description.get("tag"), ATTRIBUTE_LIMIT, str) or "unknown"
    text = None
    if tag in {"button", "a"} or description.get("input_type") in {
        "button",
        "submit",
        "reset",
        "image",
    }:
        text = _clean(description.get("text"), TEXT_LIMIT, redact)
    return ControlFingerprint(
        tag=tag,
        input_type=_clean(description.get("input_type"), ATTRIBUTE_LIMIT, str),
        id=_clean(description.get("id"), ATTRIBUTE_LIMIT, redact),
        name=_clean(description.get("name"), ATTRIBUTE_LIMIT, redact),
        autocomplete=_clean(description.get("autocomplete"), ATTRIBUTE_LIMIT, redact),
        placeholder=_clean(description.get("placeholder"), ATTRIBUTE_LIMIT, redact),
        aria_label=_clean(description.get("aria_label"), ATTRIBUTE_LIMIT, redact),
        role=_clean(description.get("role"), ATTRIBUTE_LIMIT, redact),
        text=text,
        form=_form_key(description.get("form"), redact),
    )


def identity(fingerprint: ControlFingerprint) -> tuple[str | None, ...]:
    """The parts that must be equal for two controls to be the same one.

    A generated id is left out (see ``_GENERATED_ID``); ordinal and
    duplicates are left out because they are what tells equals apart.
    """

    stable_id = (
        fingerprint.id
        if fingerprint.id is not None and not is_generated_id(fingerprint.id)
        else None
    )
    return (
        fingerprint.tag,
        fingerprint.input_type,
        stable_id,
        fingerprint.name,
        fingerprint.autocomplete,
        fingerprint.placeholder,
        fingerprint.aria_label,
        fingerprint.role,
        fingerprint.text,
        fingerprint.form,
    )


def fingerprints_for(
    descriptions: Descriptions, redact: Redact
) -> list[ControlFingerprint]:
    """Fingerprint every control, numbering each among its identical peers."""

    described = [describe(description, redact) for description in descriptions]
    groups: dict[tuple[str | None, ...], list[int]] = {}
    for index, fingerprint in enumerate(described):
        groups.setdefault(identity(fingerprint), []).append(index)
    ordered: list[ControlFingerprint] = []
    for index, fingerprint in enumerate(described):
        peers = groups[identity(fingerprint)]
        ordered.append(
            fingerprint.model_copy(
                update={"ordinal": peers.index(index) + 1, "duplicates": len(peers)}
            )
        )
    return ordered


def fingerprints_by_control(
    descriptions: Descriptions, redact: Redact
) -> dict[str, ControlFingerprint]:
    """Fingerprints keyed by observed control id (``control-N``)."""

    return {
        f"control-{index + 1}": fingerprint
        for index, fingerprint in enumerate(fingerprints_for(descriptions, redact))
    }


def resolve(
    recorded: ControlFingerprint,
    descriptions: Descriptions,
    redact: Redact,
) -> int | FingerprintMiss:
    """Return the 0-based index of the recorded control, or why there is none.

    - one control with the recorded identity: that control, wherever it is;
    - none: ``ABSENT``. The control at the old position is never used;
    - several: the recorded ordinal picks one, but only while there are as
      many identical controls as when it was recorded. Otherwise one was
      added or removed and the ordinal no longer says which is which, so the
      result is ``AMBIGUOUS``.
    """

    wanted = identity(recorded)
    candidates = [
        index
        for index, description in enumerate(descriptions)
        if identity(describe(description, redact)) == wanted
    ]
    if not candidates:
        return FingerprintMiss.ABSENT
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) == recorded.duplicates:
        return candidates[recorded.ordinal - 1]
    return FingerprintMiss.AMBIGUOUS


def with_fingerprint(
    action: BrowserAction, fingerprints: Mapping[str, ControlFingerprint]
) -> BrowserAction:
    """Attach the fingerprint of the action's control, if it has none yet."""

    if action.control_fingerprint is not None or action.observed_control_id is None:
        return action
    fingerprint = fingerprints.get(action.observed_control_id)
    if fingerprint is None:
        return action
    return action.model_copy(update={"control_fingerprint": fingerprint})

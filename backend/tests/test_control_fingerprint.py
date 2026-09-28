"""Pure tests for matching recorded controls by fingerprint."""

from typing import Any

import pytest
from authflowguard.control_fingerprint import (
    FingerprintMiss,
    fingerprints_by_control,
    fingerprints_for,
    is_generated_id,
    resolve,
    with_fingerprint,
)
from authflowguard.control_safety import (
    ControlOutcome,
    ControlRefusal,
    RecordedControlNotFoundError,
)
from authflowguard.models import (
    BrowserAction,
    BrowserActionType,
    ControlFingerprint,
)
from pydantic import ValidationError


def keep(text: str) -> str:
    return text


def control(tag: str = "input", **attributes: Any) -> dict[str, Any]:
    """A raw description as DESCRIBE_CONTROLS_SCRIPT returns it."""

    description: dict[str, Any] = {
        "tag": tag,
        "input_type": "text" if tag == "input" else None,
        "id": None,
        "name": None,
        "autocomplete": None,
        "placeholder": None,
        "aria_label": None,
        "role": None,
        "text": None,
        "form": None,
    }
    description.update(attributes)
    return description


LOGIN_FORM = {"id": "login", "name": None, "action": "/session"}
USERNAME = control(input_type="email", name="email", form=LOGIN_FORM)
PASSWORD = control(input_type="password", name="password", form=LOGIN_FORM)
SUBMIT = control("button", text="  Sign\n in ", form=LOGIN_FORM)
BANNER = [control("button", text="Accept"), control("a", text="Privacy")]


def recorded(descriptions: list[dict[str, Any]], index: int) -> ControlFingerprint:
    return fingerprints_for(descriptions, keep)[index]


def test_a_control_is_found_wherever_it_moved() -> None:
    fingerprint = recorded([USERNAME, PASSWORD, SUBMIT], 1)

    assert resolve(fingerprint, [*BANNER, USERNAME, PASSWORD, SUBMIT], keep) == 3


def test_a_control_that_is_gone_is_absent_rather_than_the_old_position() -> None:
    fingerprint = recorded([USERNAME, PASSWORD, SUBMIT], 0)
    search = control(input_type="search", name="q")

    assert resolve(fingerprint, [search, PASSWORD, SUBMIT], keep) is (
        FingerprintMiss.ABSENT
    )


def test_identical_controls_are_told_apart_by_their_recorded_ordinal() -> None:
    code = control(name="code")
    fingerprint = recorded([code, code], 1)
    assert (fingerprint.ordinal, fingerprint.duplicates) == (2, 2)

    # The same two identical controls, shifted by a banner: still the second.
    assert resolve(fingerprint, [*BANNER, code, code], keep) == 3
    # A third identical control makes the ordinal meaningless.
    assert resolve(fingerprint, [code, code, code], keep) is FingerprintMiss.AMBIGUOUS
    # One left is the same control by every recorded attribute.
    assert resolve(fingerprint, [*BANNER, code], keep) == 2


def test_the_enclosing_form_tells_otherwise_identical_controls_apart() -> None:
    newsletter = {"id": None, "name": None, "action": "/newsletter"}
    login_email = control(input_type="email", name="email", form=LOGIN_FORM)
    newsletter_email = control(input_type="email", name="email", form=newsletter)
    fingerprint = recorded([login_email], 0)

    assert resolve(fingerprint, [newsletter_email, login_email], keep) == 1


@pytest.mark.parametrize(
    ("value", "generated"),
    [
        ("mat-input-3", True),
        (":r1:", True),
        ("«r5»", True),
        ("ember123", True),
        ("email", False),
        ("loginButton", False),
        ("user_name", False),
    ],
)
def test_generated_ids_are_recognised_by_a_general_rule(
    value: str, generated: bool
) -> None:
    assert is_generated_id(value) is generated


def test_a_generated_id_that_changes_between_loads_is_ignored() -> None:
    first_load = control(id="mat-input-0", input_type="email", name="email")
    fingerprint = recorded([first_load], 0)
    other = control(id="mat-input-0", input_type="search", name="q")
    later_load = control(id="mat-input-3", input_type="email", name="email")

    assert resolve(fingerprint, [other, later_load], keep) == 1


def test_a_stable_id_must_still_match() -> None:
    fingerprint = recorded([control(id="email", name="email")], 0)

    assert resolve(fingerprint, [control(id="login", name="email")], keep) is (
        FingerprintMiss.ABSENT
    )


def test_text_is_kept_for_buttons_and_links_only() -> None:
    field = control(text="should never be read")
    button, link, submit = fingerprints_for(
        [
            SUBMIT,
            control("a", text="Forgot password?"),
            control(input_type="submit", text="Log in"),
        ],
        keep,
    )

    assert fingerprints_for([field], keep)[0].text is None
    assert button.text == "Sign in"
    assert link.text == "Forgot password?"
    assert submit.text == "Log in"


def test_the_form_is_named_without_query_or_generated_id() -> None:
    form = {"id": "form-12", "name": "signin", "action": "/login;jsid=1?next=/x#y"}

    fingerprint = recorded([control(form=form)], 0)

    assert fingerprint.form == "name=signin action=/login"
    assert recorded([control()], 0).form is None


def test_live_attributes_are_redacted_like_saved_profiles() -> None:
    def redact(text: str) -> str:
        return text.replace("alice", "[redacted]")

    fingerprint = fingerprints_for([control(placeholder="alice@example.test")], redact)

    assert fingerprint[0].placeholder == "[redacted]@example.test"
    live = [control(placeholder="alice@example.test")]
    assert resolve(fingerprint[0], live, redact) == 0


def test_actions_are_pinned_only_when_they_lack_a_fingerprint() -> None:
    pins = fingerprints_by_control([USERNAME, PASSWORD], keep)
    action = BrowserAction(
        action_type=BrowserActionType.FILL,
        observed_control_id="control-2",
        value_reference="password",
        description="Fill the password",
    )

    pinned = with_fingerprint(action, pins)

    assert pinned.control_fingerprint == pins["control-2"]
    assert with_fingerprint(pinned, {"control-2": pins["control-1"]}) is pinned


def test_old_actions_without_a_fingerprint_still_load() -> None:
    saved = {
        "action_id": "d3dcee77-2652-47f4-bab3-24aab5204570",
        "action_type": "fill",
        "description": "Fill the username",
        "key": None,
        "observed_control_id": "control-3",
        "option_value": None,
        "schema_version": "1.0",
        "url": None,
        "value_reference": "username",
        "wait_for": None,
    }

    assert BrowserAction.model_validate(saved).control_fingerprint is None


def test_a_fingerprint_needs_a_control_reference() -> None:
    with pytest.raises(ValidationError, match="requires observed_control_id"):
        BrowserAction(
            action_type=BrowserActionType.NAVIGATE,
            url="https://app.example/login",
            control_fingerprint=ControlFingerprint(tag="input"),
            description="Open the login page",
        )
    with pytest.raises(ValidationError, match="ordinal"):
        ControlFingerprint(tag="input", ordinal=3, duplicates=2)


def test_a_missing_control_message_uses_fixed_words_only() -> None:
    fingerprint = recorded([control(input_type="password", aria_label="alice")], 0)

    error = RecordedControlNotFoundError(
        "control-16",
        ControlRefusal.NOT_ON_PAGE,
        ControlOutcome.PASSWORD_NOT_TYPED,
        recorded=fingerprint,
    ).at_step(2)

    assert str(error) == (
        "Step 2: The password input recorded for this flow as control-16 is not "
        "on the page, so the password was not typed into it."
    )

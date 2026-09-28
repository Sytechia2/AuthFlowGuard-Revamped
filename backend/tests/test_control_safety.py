"""Pure safety rules for acting on a resolved page control."""

import pytest
from authflowguard.control_safety import (
    STRICT_DESTRUCTIVE_LABEL,
    ControlFacts,
    ControlOutcome,
    ControlRefusal,
    SafeMessageError,
    UnsafeControlError,
    activation_refusal,
    describe_element,
    fill_refusal,
    names_irreversible_action,
)


def facts(
    tag: str = "input",
    input_type: str | None = "text",
    *,
    visible: bool = True,
    enabled: bool = True,
    read_only: bool = False,
    label: str = "",
) -> ControlFacts:
    return ControlFacts(
        tag=tag,
        input_type=input_type,
        visible=visible,
        enabled=enabled,
        read_only=read_only,
        label=label,
    )


@pytest.mark.parametrize(
    "control",
    [
        facts("input", "text"),
        facts("input", "email"),
        facts("input", "tel"),
        facts("input", "url"),
        facts("input", "search"),
        facts("input", "number"),
        facts("input", None),
        facts("INPUT", "EMAIL"),
        facts("textarea", None),
    ],
)
def test_text_entry_controls_accept_a_non_password_value(control: ControlFacts) -> None:
    assert fill_refusal(control, password_value=False) is None


@pytest.mark.parametrize(
    "control",
    [
        facts("button", None),
        facts("a", None),
        facts("select", None),
        facts("input", "checkbox"),
        facts("input", "radio"),
        facts("input", "hidden"),
        facts("input", "file"),
        facts("input", "submit"),
        facts("input", "date"),
    ],
)
def test_non_text_controls_never_receive_a_value(control: ControlFacts) -> None:
    for password_value in (False, True):
        assert (
            fill_refusal(control, password_value=password_value)
            is ControlRefusal.NOT_TEXT_FIELD
        )


def test_a_password_goes_only_into_a_password_field() -> None:
    assert fill_refusal(facts("input", "password"), password_value=True) is None
    assert (
        fill_refusal(facts("input", "text"), password_value=True)
        is ControlRefusal.NOT_PASSWORD_FIELD
    )
    assert (
        fill_refusal(facts("textarea", None), password_value=True)
        is ControlRefusal.NOT_PASSWORD_FIELD
    )


def test_a_password_field_receives_only_a_password() -> None:
    assert (
        fill_refusal(facts("input", "password"), password_value=False)
        is ControlRefusal.PASSWORD_FIELD_FOR_OTHER_VALUE
    )


def test_fill_requires_a_visible_enabled_writable_field() -> None:
    assert (
        fill_refusal(facts(visible=False), password_value=False)
        is ControlRefusal.NOT_VISIBLE
    )
    assert (
        fill_refusal(facts(enabled=False), password_value=False)
        is ControlRefusal.DISABLED
    )
    assert (
        fill_refusal(facts(read_only=True), password_value=False)
        is ControlRefusal.READ_ONLY
    )


def test_wrong_kind_is_reported_before_visibility() -> None:
    # A wrong element is refused at once rather than after a visibility wait.
    hidden_button = facts("button", None, visible=False)
    assert (
        fill_refusal(hidden_button, password_value=False)
        is ControlRefusal.NOT_TEXT_FIELD
    )


@pytest.mark.parametrize(
    "label",
    [
        "Delete account",
        "Remove",
        "remove item from basket",
        "Deactivate",
        "Erase my data",
        "Terminate membership",
        "Unsubscribe",
        "Close account",
        "Close my account",
        "Cancel subscription",
        "Cancel your membership",
        "Disable profile",
        "Disable users",
    ],
)
def test_irreversible_actions_are_named(label: str) -> None:
    assert names_irreversible_action(label)
    refusal = activation_refusal(facts("button", "submit", label=label))
    assert refusal is ControlRefusal.IRREVERSIBLE_ACTION


@pytest.mark.parametrize(
    "label",
    [
        "Close",
        "Cancel",
        "Dismiss",
        "Accept cookies",
        "Log in",
        "Sign out",
        "Add to Basket",
        "Close the cookie banner",
        "Disable animations",
        "Account",
        "Deleted items",
    ],
)
def test_ordinary_controls_stay_clickable(label: str) -> None:
    assert not names_irreversible_action(label)
    assert activation_refusal(facts("button", "button", label=label)) is None


def test_the_strict_rule_still_avoids_close_and_cancel() -> None:
    for label in ("Close", "Cancel", "Disable", "Delete account"):
        assert STRICT_DESTRUCTIVE_LABEL.search(label)
    assert not STRICT_DESTRUCTIVE_LABEL.search("Log out")


def test_activation_requires_visibility() -> None:
    assert (
        activation_refusal(facts("button", "submit", visible=False))
        is ControlRefusal.NOT_VISIBLE
    )


def test_elements_are_described_with_fixed_words() -> None:
    assert describe_element(facts("button", None)) == "a button"
    assert describe_element(facts("input", "submit")) == "a button"
    assert describe_element(facts("a", None)) == "a link"
    assert describe_element(facts("select", None)) == "a drop-down list"
    assert describe_element(facts("textarea", None)) == "a text area"
    assert describe_element(facts("input", "checkbox")) == "a checkbox input"
    assert describe_element(facts("input", "email")) == "an email input"
    assert describe_element(facts("input", "x-secret-value")) == "an input"
    assert describe_element(facts("custom-secret", None)) == "a control"


def test_refusal_message_uses_only_fixed_wording() -> None:
    error = UnsafeControlError(
        "control-16",
        ControlRefusal.NOT_TEXT_FIELD,
        ControlOutcome.VALUE_NOT_TYPED,
        describe_element(facts("button", None, label="Add to Basket")),
    )

    assert isinstance(error, SafeMessageError)
    assert error.safe_message == (
        "control-16 is a button, not a text field, so the value was not typed into it."
    )
    assert "Basket" not in error.safe_message


def test_refusal_message_rejects_an_unexpected_control_reference() -> None:
    error = UnsafeControlError(
        "user@example.test",
        ControlRefusal.DISABLED,
        ControlOutcome.NOT_CLICKED,
    )

    assert "user@example.test" not in str(error)
    assert str(error) == "The control is disabled, so it was not clicked."

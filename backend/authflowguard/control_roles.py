"""Decide which suggested control roles a login flow may use.

A role for a control can be suggested by the rules below or by a model that
read the page. Either way the suggestion only proposes meaning; these pure
functions decide, from nonsecret facts the page observation already holds,
whether the control can play that role at all. A model answer that maps
``password`` to a search box or ``submit`` to a "Delete account" button is
dropped here, whatever the page told the model.

Every rejection is a fixed reason code. Nothing here returns page text.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from authflowguard.control_safety import names_irreversible_action

Control = Mapping[str, object]


class ControlRole(StrEnum):
    """Every role a model may assign. Only the login roles are used so far."""

    USERNAME = "username"
    PASSWORD = "password"
    SUBMIT = "submit"
    VERIFICATION_CODE = "verification_code"
    LOGOUT = "logout"
    ACCOUNT_MENU = "account_menu"
    REGISTRATION_LINK = "registration_link"
    RESET_LINK = "reset_link"
    OTHER = "other"


# The roles a guided login needs, in the order the flow uses them.
LOGIN_ROLES = (ControlRole.USERNAME, ControlRole.PASSWORD, ControlRole.SUBMIT)
# The roles this module validates. The others are accepted from a model but
# ignored until a flow uses them.
VALIDATED_ROLES = frozenset({*LOGIN_ROLES, ControlRole.VERIFICATION_CODE})


class RoleRejection(StrEnum):
    """Why a suggested role was dropped, as a fixed code."""

    UNKNOWN_CONTROL = "unknown_control"
    NOT_PASSWORD_FIELD = "not_password_field"
    NOT_TEXT_FIELD = "not_text_field"
    NOT_BUTTON = "not_button"
    NOT_VISIBLE = "not_visible"
    IRREVERSIBLE_ACTION = "irreversible_action"
    DIFFERENT_FORM = "different_form"
    SEVERAL_CONTROLS = "several_controls_for_role"
    SEVERAL_ROLES = "several_roles_for_control"


# Attribute types (lower-cased; no attribute means text) that accept a
# username or an email address.
USERNAME_INPUT_TYPES = frozenset({"text", "email", "tel"})
VERIFICATION_CODE_INPUT_TYPES = frozenset({"text", "tel", "number"})
SUBMIT_INPUT_TYPES = frozenset({"submit", "button", "image"})


@dataclass(frozen=True)
class RoleSuggestion:
    observed_control_id: str
    role: ControlRole


@dataclass(frozen=True)
class RejectedSuggestion:
    observed_control_id: str
    role: ControlRole
    reason: RoleRejection

    def as_dict(self) -> dict[str, str]:
        return {
            "observed_control_id": self.observed_control_id,
            "role": self.role.value,
            "reason": self.reason.value,
        }


@dataclass(frozen=True)
class ValidatedRoles:
    """The one control accepted for each role, and what was dropped."""

    accepted: Mapping[ControlRole, str] = field(default_factory=dict)
    rejected: tuple[RejectedSuggestion, ...] = ()

    def control_for(self, role: ControlRole) -> str | None:
        return self.accepted.get(role)

    @property
    def has_login_set(self) -> bool:
        return all(role in self.accepted for role in LOGIN_ROLES)


def _text(control: Control, key: str) -> str | None:
    value = control.get(key)
    return value if isinstance(value, str) else None


def _tag(control: Control) -> str:
    return (_text(control, "tag") or "").lower()


def _input_type(control: Control) -> str:
    """The lower-cased type attribute; an input without one is a text field."""

    return (_text(control, "type") or "text").strip().lower()


def _is_visible(control: Control) -> bool:
    return control.get("visible") is True


def _form(control: Control) -> int | None:
    value = control.get("form_index")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _label(control: Control) -> str:
    """Every nonsecret name a control shows, for the irreversible-action rule."""

    parts = (
        _text(control, key)
        for key in ("text", "aria_label", "name", "id", "placeholder")
    )
    return " ".join(part for part in parts if part)


def is_password_input(control: Control) -> bool:
    return _tag(control) == "input" and _input_type(control) == "password"


def is_username_input(control: Control) -> bool:
    return _tag(control) == "input" and _input_type(control) in USERNAME_INPUT_TYPES


def is_submit_control(control: Control) -> bool:
    tag = _tag(control)
    if tag == "button":
        return _input_type(control) != "reset"
    return tag == "input" and _input_type(control) in SUBMIT_INPUT_TYPES


def _kind_rejection(role: ControlRole, control: Control) -> RoleRejection | None:
    """Return why the control's kind cannot play the role, checking kind first."""

    if role is ControlRole.PASSWORD:
        if not is_password_input(control):
            return RoleRejection.NOT_PASSWORD_FIELD
    elif role is ControlRole.USERNAME:
        if not is_username_input(control):
            return RoleRejection.NOT_TEXT_FIELD
    elif role is ControlRole.VERIFICATION_CODE:
        if not (
            _tag(control) == "input"
            and _input_type(control) in VERIFICATION_CODE_INPUT_TYPES
        ):
            return RoleRejection.NOT_TEXT_FIELD
        # A code may be asked for on a later step, so it can still be hidden.
        return None
    elif role is ControlRole.SUBMIT:
        if not is_submit_control(control):
            return RoleRejection.NOT_BUTTON
        if names_irreversible_action(_label(control)):
            return RoleRejection.IRREVERSIBLE_ACTION
    if not _is_visible(control):
        return RoleRejection.NOT_VISIBLE
    return None


def validate_role_suggestions(
    controls: Sequence[Control],
    suggestions: Iterable[RoleSuggestion],
) -> ValidatedRoles:
    """Keep each suggested role only if its control fits it.

    - the control must be in the observation;
    - ``password``: a visible ``input`` of type password;
    - ``username``: a visible text, email or tel ``input`` (no type is text);
    - ``submit``: a visible ``button`` (not reset) or ``input`` of type
      submit, button or image, not labelled as an irreversible action, and in
      the credentials' form when they are in one;
    - ``verification_code``: a text, tel or number ``input``;
    - one control per role and one role per control: when a role names
      several controls, or a control is given several roles, all of those
      suggestions are dropped;
    - the username must be in the password's form.

    Roles outside ``VALIDATED_ROLES`` are ignored.
    """

    by_id: dict[str, Control] = {}
    for control in controls:
        control_id = _text(control, "observed_control_id")
        if control_id is not None:
            by_id.setdefault(control_id, control)

    unique: list[RoleSuggestion] = []
    for suggestion in suggestions:
        if suggestion.role in VALIDATED_ROLES and suggestion not in unique:
            unique.append(suggestion)

    rejected: list[RejectedSuggestion] = []

    def reject(suggestion: RoleSuggestion, reason: RoleRejection) -> None:
        rejected.append(
            RejectedSuggestion(suggestion.observed_control_id, suggestion.role, reason)
        )

    roles_per_control: dict[str, set[ControlRole]] = {}
    controls_per_role: dict[ControlRole, set[str]] = {}
    for suggestion in unique:
        roles_per_control.setdefault(suggestion.observed_control_id, set()).add(
            suggestion.role
        )
        controls_per_role.setdefault(suggestion.role, set()).add(
            suggestion.observed_control_id
        )

    candidates: dict[ControlRole, str] = {}
    for suggestion in unique:
        observed = by_id.get(suggestion.observed_control_id)
        if observed is None:
            reject(suggestion, RoleRejection.UNKNOWN_CONTROL)
        elif len(controls_per_role[suggestion.role]) > 1:
            reject(suggestion, RoleRejection.SEVERAL_CONTROLS)
        elif len(roles_per_control[suggestion.observed_control_id]) > 1:
            reject(suggestion, RoleRejection.SEVERAL_ROLES)
        elif (reason := _kind_rejection(suggestion.role, observed)) is not None:
            reject(suggestion, reason)
        else:
            candidates[suggestion.role] = suggestion.observed_control_id

    # The password field is the surest sign of the login form, so it anchors
    # the form the other login controls must share.
    password = candidates.get(ControlRole.PASSWORD)
    username = candidates.get(ControlRole.USERNAME)
    if (
        password is not None
        and username is not None
        and _form(by_id[username]) != _form(by_id[password])
    ):
        del candidates[ControlRole.USERNAME]
        reject(
            RoleSuggestion(username, ControlRole.USERNAME),
            RoleRejection.DIFFERENT_FORM,
        )
        username = None

    anchor = password if password is not None else username
    anchor_form = _form(by_id[anchor]) if anchor is not None else None
    submit = candidates.get(ControlRole.SUBMIT)
    if (
        submit is not None
        and anchor_form is not None
        and _form(by_id[submit]) != anchor_form
    ):
        del candidates[ControlRole.SUBMIT]
        reject(
            RoleSuggestion(submit, ControlRole.SUBMIT),
            RoleRejection.DIFFERENT_FORM,
        )

    return ValidatedRoles(accepted=candidates, rejected=tuple(rejected))


# The conventional-form rules. They are deliberately narrow: they recognise
# only fields that say what they are through autocomplete or an email type.


def rules_is_username(control: Control) -> bool:
    name = (_text(control, "name") or "").lower()
    return control.get("autocomplete") == "username" or (
        control.get("type") == "email" and name in {"email", "username", "login"}
    )


def rules_is_password(control: Control) -> bool:
    return control.get("type") == "password" and control.get("autocomplete") in {
        None,
        "current-password",
    }


def rules_is_submit(control: Control) -> bool:
    return control.get("tag") in {"button", "input"} and control.get("type") in {
        None,
        "submit",
    }


def rules_role_suggestions(controls: Sequence[Control]) -> list[RoleSuggestion]:
    """Suggest each login role the rules find exactly one control for."""

    suggestions: list[RoleSuggestion] = []
    for role, predicate in (
        (ControlRole.USERNAME, rules_is_username),
        (ControlRole.PASSWORD, rules_is_password),
        (ControlRole.SUBMIT, rules_is_submit),
    ):
        matches = [
            control_id
            for control in controls
            if predicate(control)
            and (control_id := _text(control, "observed_control_id")) is not None
        ]
        if len(matches) == 1:
            suggestions.append(RoleSuggestion(matches[0], role))
    return suggestions

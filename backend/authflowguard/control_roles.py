"""Decide which suggested control roles a flow may use.

A role for a control can be suggested by the rules below or by a model that
read the page. Either way the suggestion only proposes meaning; these pure
functions decide, from nonsecret facts the page observation already holds,
whether the control can play that role at all. A model answer that maps
``password`` to a search box, ``submit`` or ``logout`` to a "Delete account"
button, or ``registration_link`` to another site is dropped here, whatever
the page told the model.

Every rejection is a fixed reason code. Nothing here returns page text.
"""

import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urlsplit

from authflowguard.control_safety import (
    STRICT_DESTRUCTIVE_LABEL,
    names_irreversible_action,
)
from authflowguard.models import TargetScope
from authflowguard.scope import (
    url_is_in_scope,
    url_without_query_keeping_route,
    url_without_query_or_fragment,
)

Control = Mapping[str, object]

# The labels the rules recognise. The form and logout checks search with the
# same expressions when nothing was saved for them.
REGISTRATION_LINK_LABEL = re.compile(
    r"\b(register|registration|sign\s*up|create\s+(?:an?\s+)?account)\b",
    re.IGNORECASE,
)
RESET_LINK_LABEL = re.compile(
    r"\b((?:reset|forgot|recover)\s+(?:your\s+)?password|password\s+reset)\b",
    re.IGNORECASE,
)
LOGOUT_LABEL = re.compile(r"\b(log|sign)\s*-?\s*(out|off)\b", re.IGNORECASE)
MENU_LABEL = re.compile(r"account|user|profile|menu", re.IGNORECASE)
# At most this many account menus are opened while looking for logout.
MAX_MENU_TOGGLES = 3


class ControlRole(StrEnum):
    """Every role a model may assign."""

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
# The links on the login page that open the registration and reset forms.
LINK_ROLES = (ControlRole.REGISTRATION_LINK, ControlRole.RESET_LINK)
# The controls that sign a signed-in user out, directly or from a menu.
LOGOUT_ROLES = (ControlRole.LOGOUT, ControlRole.ACCOUNT_MENU)
# The roles this module validates. ``other`` is accepted from a model but
# ignored.
VALIDATED_ROLES = frozenset(
    {*LOGIN_ROLES, ControlRole.VERIFICATION_CODE, *LINK_ROLES, *LOGOUT_ROLES}
)


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
    NOT_LINK_OR_BUTTON = "not_link_or_button"
    # A button that would submit a form (such as the login form) is not a
    # link to another form: pressing it would send the form.
    SUBMITS_FORM = "submits_form"
    NOT_MENU_TOGGLE = "not_menu_toggle"
    NO_DESTINATION = "no_destination"
    OUT_OF_SCOPE = "out_of_scope"
    SAME_PAGE = "same_page_link"
    # A multi-step login can leave an earlier step's button on the page; the
    # button that finished a previous step does not finish the next one.
    ALREADY_USED = "already_used_in_earlier_step"


# Attribute types (lower-cased; no attribute means text) that accept a
# username or an email address.
USERNAME_INPUT_TYPES = frozenset({"text", "email", "tel"})
VERIFICATION_CODE_INPUT_TYPES = frozenset({"text", "tel", "number"})
SUBMIT_INPUT_TYPES = frozenset({"submit", "button", "image"})


@dataclass(frozen=True)
class RoleContext:
    """Where the controls were observed, for the roles that lead elsewhere.

    ``page_url`` is the observed page's address; a link must lead inside
    ``target``'s permitted origins and away from that page.
    """

    target: TargetScope
    page_url: str


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


def is_link(control: Control) -> bool:
    return _tag(control) == "a"


def submits_form(control: Control) -> bool:
    """Whether pressing the button would submit the form it sits in."""

    if _form(control) is None:
        return False
    tag = _tag(control)
    if tag == "button":
        # A button without a type is a submit button inside a form.
        return _input_type(control) in {"text", "submit"}
    return tag == "input" and _input_type(control) in {"submit", "image"}


def declares_popup(control: Control) -> bool:
    """Whether the control says it opens a menu or an expandable region."""

    return control.get("has_popup") is True


def _is_menu_button(control: Control) -> bool:
    tag = _tag(control)
    if tag == "button":
        return _input_type(control) != "reset"
    return tag == "input" and _input_type(control) == "button"


def _href(control: Control) -> str | None:
    return _text(control, "href")


def _is_web_address(url: str) -> bool:
    return urlsplit(url).scheme.lower() in {"http", "https"}


def _stays_on_page(href: str, page_url: str) -> bool:
    """Whether following ``href`` leaves the observed page where it is.

    The same document with no client-side route, or with the page's own
    route, is the same page: ``#``, ``#top`` and a token-bearing fragment
    all count, because their fragment is not kept as a route.
    """

    if url_without_query_or_fragment(href) != url_without_query_or_fragment(page_url):
        return False
    href_route = urlsplit(url_without_query_keeping_route(href)).fragment
    page_route = urlsplit(url_without_query_keeping_route(page_url)).fragment
    return not href_route or href_route == page_route


def _destination_rejection(
    control: Control, context: RoleContext | None
) -> RoleRejection | None:
    """A registration or reset link must open another in-scope page."""

    href = _href(control)
    if href is None or context is None or not _is_web_address(href):
        return RoleRejection.NO_DESTINATION
    if not url_is_in_scope(href, context.target):
        return RoleRejection.OUT_OF_SCOPE
    if _stays_on_page(href, context.page_url):
        return RoleRejection.SAME_PAGE
    return None


def _logout_link_rejection(
    control: Control, context: RoleContext | None
) -> RoleRejection | None:
    """A logout link may run a script, but a web address must stay in scope."""

    href = _href(control)
    if href is None or not _is_web_address(href):
        return None
    if context is None:
        return RoleRejection.NO_DESTINATION
    if not url_is_in_scope(href, context.target):
        return RoleRejection.OUT_OF_SCOPE
    return None


def _kind_rejection(
    role: ControlRole, control: Control, context: RoleContext | None = None
) -> RoleRejection | None:
    """Return why the control's kind cannot play the role, checking kind first."""

    if role in LINK_ROLES:
        if not (is_link(control) or is_submit_control(control)):
            return RoleRejection.NOT_LINK_OR_BUTTON
        if names_irreversible_action(_label(control)):
            return RoleRejection.IRREVERSIBLE_ACTION
        if not is_link(control) and submits_form(control):
            return RoleRejection.SUBMITS_FORM
        if not _is_visible(control):
            return RoleRejection.NOT_VISIBLE
        if is_link(control):
            return _destination_rejection(control, context)
        return None
    if role is ControlRole.LOGOUT:
        if not (is_link(control) or is_submit_control(control)):
            return RoleRejection.NOT_LINK_OR_BUTTON
        # The strict rule: logout is looked for on a signed-in page, where a
        # bare "Close" or "Cancel" may act on the account.
        if STRICT_DESTRUCTIVE_LABEL.search(_label(control)):
            return RoleRejection.IRREVERSIBLE_ACTION
        if not _is_visible(control):
            return RoleRejection.NOT_VISIBLE
        if is_link(control):
            return _logout_link_rejection(control, context)
        return None
    if role is ControlRole.ACCOUNT_MENU:
        if not _is_menu_button(control):
            return RoleRejection.NOT_BUTTON
        if STRICT_DESTRUCTIVE_LABEL.search(_label(control)):
            return RoleRejection.IRREVERSIBLE_ACTION
        # Only a toggle that declares a popup is opened: any other button
        # performs its action, and a link navigates away.
        if not declares_popup(control):
            return RoleRejection.NOT_MENU_TOGGLE
        if not _is_visible(control):
            return RoleRejection.NOT_VISIBLE
        return None
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
    *,
    context: RoleContext | None = None,
    used_controls: Collection[str] = (),
) -> ValidatedRoles:
    """Keep each suggested role only if its control fits it.

    - the control must be in the observation;
    - ``password``: a visible ``input`` of type password;
    - ``username``: a visible text, email or tel ``input`` (no type is text);
    - ``submit``: a visible ``button`` (not reset) or ``input`` of type
      submit, button or image, not labelled as an irreversible action, and in
      the credentials' form when they are in one;
    - ``verification_code``: a text, tel or number ``input``;
    - ``registration_link`` and ``reset_link``: a visible link or button,
      not labelled as an irreversible action; a button must not submit the
      form it sits in, and a link must lead to a web address inside
      ``context``'s scope other than the observed page (a client-side
      route such as ``#/register`` is another page);
    - ``logout``: a visible link or button not matching the strict
      destructive rule; a link to a web address must stay in scope;
    - ``account_menu``: a visible button that declares a popup
      (``aria-haspopup`` or ``aria-expanded``), not matching the strict
      destructive rule;
    - one role per control: a control given several roles loses them all;
    - one control per role: when several controls that each pass the checks
      above claim a role, all of them are dropped; a claimant that fails its
      own checks is rejected for that reason and does not make the role
      ambiguous;
    - the username must be in the password's form;
    - ``submit`` must not be one of ``used_controls``, the controls an
      earlier step of the same flow already acted on.

    ``other`` is ignored. Without ``context`` no link can be accepted for a
    role that leads to another page.
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
    for suggestion in unique:
        roles_per_control.setdefault(suggestion.observed_control_id, set()).add(
            suggestion.role
        )

    # Each suggestion is checked on its own first. A role is ambiguous only
    # when several controls that could each play it claim it: in a live run
    # the model named both "Register" and a link back to the login page as
    # the registration link, and the correct one was lost with the invalid
    # one. Two valid claimants are still both dropped.
    fitting: list[RoleSuggestion] = []
    for suggestion in unique:
        observed = by_id.get(suggestion.observed_control_id)
        if observed is None:
            reject(suggestion, RoleRejection.UNKNOWN_CONTROL)
        elif len(roles_per_control[suggestion.observed_control_id]) > 1:
            reject(suggestion, RoleRejection.SEVERAL_ROLES)
        elif (
            suggestion.role is ControlRole.SUBMIT
            and suggestion.observed_control_id in used_controls
        ):
            reject(suggestion, RoleRejection.ALREADY_USED)
        elif (
            reason := _kind_rejection(suggestion.role, observed, context)
        ) is not None:
            reject(suggestion, reason)
        else:
            fitting.append(suggestion)

    controls_per_role: dict[ControlRole, set[str]] = {}
    for suggestion in fitting:
        controls_per_role.setdefault(suggestion.role, set()).add(
            suggestion.observed_control_id
        )

    candidates: dict[ControlRole, str] = {}
    for suggestion in fitting:
        if len(controls_per_role[suggestion.role]) > 1:
            reject(suggestion, RoleRejection.SEVERAL_CONTROLS)
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


def _name(control: Control) -> str:
    """The control's visible name, as a person reading the page sees it."""

    parts = (_text(control, "text"), _text(control, "aria_label"))
    return " ".join(part for part in parts if part)


def rules_link_suggestions(controls: Sequence[Control]) -> list[RoleSuggestion]:
    """Suggest the registration and reset links whose names say what they open.

    Links are preferred: several links naming the same destination count as
    one. Only when no link matches is a single matching button suggested.
    """

    suggestions: list[RoleSuggestion] = []
    for role, pattern in (
        (ControlRole.REGISTRATION_LINK, REGISTRATION_LINK_LABEL),
        (ControlRole.RESET_LINK, RESET_LINK_LABEL),
    ):
        matches = [
            control_id
            for control in controls
            if _is_visible(control)
            and (is_link(control) or is_submit_control(control))
            and pattern.search(_name(control))
            and (control_id := _text(control, "observed_control_id")) is not None
        ]
        by_id = {_text(control, "observed_control_id"): control for control in controls}
        links = [control_id for control_id in matches if is_link(by_id[control_id])]
        destinations = {_href(by_id[control_id]) for control_id in links}
        if links and len(destinations) == 1:
            suggestions.append(RoleSuggestion(links[0], role))
        elif not links and len(matches) == 1:
            suggestions.append(RoleSuggestion(matches[0], role))
    return suggestions


def rules_logout_suggestions(controls: Sequence[Control]) -> list[RoleSuggestion]:
    """Suggest the first visible control named for signing out.

    A control that also names an irreversible action ("Log out and delete
    account") is passed over, as the logout check's own search does.
    """

    for control in controls:
        control_id = _text(control, "observed_control_id")
        label = _label(control)
        if (
            control_id is not None
            and _is_visible(control)
            and (is_link(control) or is_submit_control(control))
            and LOGOUT_LABEL.search(label)
            and not STRICT_DESTRUCTIVE_LABEL.search(label)
        ):
            return [RoleSuggestion(control_id, ControlRole.LOGOUT)]
    return []


def rules_account_menu_suggestions(
    controls: Sequence[Control], limit: int = MAX_MENU_TOGGLES
) -> list[RoleSuggestion]:
    """Suggest, in page order, the visible menu toggles named for the account."""

    suggestions: list[RoleSuggestion] = []
    for control in controls:
        control_id = _text(control, "observed_control_id")
        label = _label(control)
        if (
            control_id is not None
            and _is_visible(control)
            and _is_menu_button(control)
            and declares_popup(control)
            and MENU_LABEL.search(label)
            and not STRICT_DESTRUCTIVE_LABEL.search(label)
        ):
            suggestions.append(RoleSuggestion(control_id, ControlRole.ACCOUNT_MENU))
            if len(suggestions) >= limit:
                break
    return suggestions

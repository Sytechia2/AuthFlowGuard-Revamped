"""Deterministic model double for offline evaluation and testing.

Provides valid BedrockActionDecision responses without invoking AWS Bedrock.
Tracks calls, observations, and simulates token usage and costs.
"""

from collections.abc import Sequence

from authflowguard.bedrock import (
    BedrockActionDecision,
    BedrockClassificationDecision,
    ObservedControlForModel,
    PageObservationForModel,
)
from authflowguard.control_roles import ControlRole, RoleSuggestion
from authflowguard.control_safety import names_irreversible_action
from authflowguard.models import ActionWaitCondition, BrowserAction, BrowserActionType

_USERNAME_HINTS = ("user", "login", "email", "e-mail", "member")
_SUBMIT_HINTS = ("sign in", "log in", "login", "submit")
_TEXT_INPUT_TYPES = (None, "text", "email", "tel")


def _describes(control: ObservedControlForModel, hints: Sequence[str]) -> bool:
    words = " ".join(
        value or ""
        for value in (
            control.name,
            control.placeholder,
            control.autocomplete,
            control.aria_label,
            control.text,
        )
    ).lower()
    return any(hint in words for hint in hints)


def _is_button(control: ObservedControlForModel) -> bool:
    return control.tag == "button" or (
        control.tag == "input" and control.control_type in ("submit", "button", "image")
    )


class DeterministicModelDouble:
    """Offline double implementing ActionSelectionClient protocol."""

    def __init__(
        self,
        scripted_actions: Sequence[BrowserAction | Exception] | None = None,
        *,
        reserved_cost_usd: float = 0.001,
        actual_cost_usd: float = 0.00015,
        input_tokens: int = 150,
        output_tokens: int = 30,
    ) -> None:
        self._scripted = (
            list(scripted_actions) if scripted_actions is not None else None
        )
        self.reserved_cost_usd = reserved_cost_usd
        self.actual_cost_usd = actual_cost_usd
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.observations: list[PageObservationForModel] = []
        self.choose_calls = 0
        self.classify_calls = 0
        self._filled_username = False
        self._filled_password = False
        self._clicked_submit = False
        self._last_url: str | None = None

    def estimate_maximum_cost(self, observation: PageObservationForModel) -> float:
        return self.reserved_cost_usd

    def choose_action(
        self, observation: PageObservationForModel
    ) -> BedrockActionDecision:
        self.choose_calls += 1
        self.observations.append(observation)

        if self._scripted is not None and len(self._scripted) > 0:
            item = self._scripted.pop(0)
            if isinstance(item, Exception):
                raise item
            return BedrockActionDecision(
                action=item,
                input_tokens=self.input_tokens,
                output_tokens=self.output_tokens,
                actual_cost_usd=self.actual_cost_usd,
                reserved_cost_usd=self.reserved_cost_usd,
            )

        # Dynamic heuristic decision based on observation
        action = self._decide_heuristically(observation)
        return BedrockActionDecision(
            action=action,
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            actual_cost_usd=self.actual_cost_usd,
            reserved_cost_usd=self.reserved_cost_usd,
        )

    def estimate_classification_cost(
        self, observation: PageObservationForModel
    ) -> float:
        return self.reserved_cost_usd

    def classify_controls(
        self, observation: PageObservationForModel
    ) -> BedrockClassificationDecision:
        """Name the login controls the way a careful model would, offline.

        The password is the visible password field; the username is the
        nearest text-like field before it, preferring one whose names say
        username or email; the submit is the first button after the password
        that says it signs in, else the first button after it. A control
        whose label names an irreversible action is never chosen.
        """

        self.classify_calls += 1
        self.observations.append(observation)
        controls = [control for control in observation.controls if control.visible]
        suggestions: list[RoleSuggestion] = []

        password_index = next(
            (
                index
                for index, control in enumerate(controls)
                if control.tag == "input" and control.control_type == "password"
            ),
            None,
        )
        if password_index is not None:
            password = controls[password_index]
            suggestions.append(
                RoleSuggestion(password.observed_control_id, ControlRole.PASSWORD)
            )
            before = [
                control
                for control in controls[:password_index]
                if control.tag == "input"
                and control.control_type in _TEXT_INPUT_TYPES
                and control.form_index == password.form_index
            ]
            username = next(
                (c for c in reversed(before) if _describes(c, _USERNAME_HINTS)),
                before[-1] if before else None,
            )
            if username is not None:
                suggestions.append(
                    RoleSuggestion(username.observed_control_id, ControlRole.USERNAME)
                )
            after = [
                control
                for control in controls[password_index + 1 :]
                if _is_button(control)
                and control.form_index == password.form_index
                and not names_irreversible_action(
                    f"{control.text or ''} {control.aria_label or ''}"
                )
            ]
            submit = next(
                (c for c in after if _describes(c, _SUBMIT_HINTS)),
                after[0] if after else None,
            )
            if submit is not None:
                suggestions.append(
                    RoleSuggestion(submit.observed_control_id, ControlRole.SUBMIT)
                )

        return BedrockClassificationDecision(
            suggestions=tuple(suggestions),
            discarded_count=0,
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            actual_cost_usd=self.actual_cost_usd,
            reserved_cost_usd=self.reserved_cost_usd,
        )

    def _decide_heuristically(
        self, observation: PageObservationForModel
    ) -> BrowserAction:
        url = observation.page_url.lower()
        if self._last_url != url:
            self._filled_username = False
            self._filled_password = False
            self._clicked_submit = False
            self._last_url = url

        # 1. If we appear to be authenticated on account/dashboard page
        if self._clicked_submit or any(
            p in url for p in ("/account", "/dashboard", "/user")
        ):
            return BrowserAction(
                action_type=BrowserActionType.WAIT,
                wait_for=ActionWaitCondition.DOM_CONTENT_LOADED,
                description="Wait for authenticated state",
            )

        # Resolve credential references dynamically
        usr_ref = "username"
        pwd_ref = "password"
        if observation.credential_references:
            user_candidates = [
                r
                for r in observation.credential_references
                if any(
                    k in r.lower()
                    for k in ("user", "member", "email", "login", "ident")
                )
            ]
            pass_candidates = [
                r
                for r in observation.credential_references
                if any(
                    k in r.lower() for k in ("pass", "secret", "token", "code", "auth")
                )
            ]
            if user_candidates:
                usr_ref = user_candidates[0]
            else:
                usr_ref = observation.credential_references[0]

            if pass_candidates:
                pwd_ref = pass_candidates[0]
            elif len(observation.credential_references) > 1:
                pwd_ref = observation.credential_references[1]

        # Find password field
        pwd_control = next(
            (
                c
                for c in observation.controls
                if c.visible
                and (c.control_type == "password" or "pass" in (c.name or "").lower())
            ),
            None,
        )

        # Find username field
        usr_control = next(
            (
                c
                for c in observation.controls
                if c.visible
                and c.tag == "input"
                and c.control_type != "password"
                and any(
                    h
                    in (
                        f"{c.name or ''} {c.observed_control_id} "
                        f"{c.aria_label or ''} {c.text or ''}"
                    ).lower()
                    for h in ("user", "login", "email", "member")
                )
            ),
            None,
        )
        if usr_control is None and pwd_control is not None:
            # Fallback to first text/email input on the page
            usr_control = next(
                (
                    c
                    for c in observation.controls
                    if c.visible
                    and c.tag == "input"
                    and c.control_type not in ("password", "hidden", "submit")
                ),
                None,
            )

        # Find submit button
        submit_control = next(
            (
                c
                for c in observation.controls
                if c.visible
                and (
                    c.tag == "button"
                    or (c.tag == "input" and c.control_type in ("submit", "button"))
                )
                and any(
                    w in f"{c.text or ''} {c.aria_label or ''} {c.name or ''}".lower()
                    for w in ("sign in", "login", "log in", "submit", "open", "enter")
                )
            ),
            None,
        )
        if submit_control is None and pwd_control is not None:
            # Fallback to any visible button or submit input
            submit_control = next(
                (
                    c
                    for c in observation.controls
                    if c.visible
                    and (
                        c.tag == "button"
                        or (c.tag == "input" and c.control_type in ("submit", "button"))
                    )
                ),
                None,
            )

        # 2. If login inputs exist on the current page
        if usr_control and not self._filled_username:
            self._filled_username = True
            return BrowserAction(
                action_type=BrowserActionType.FILL,
                observed_control_id=usr_control.observed_control_id,
                value_reference=usr_ref,
                description="Fill username",
            )

        if pwd_control and not self._filled_password:
            self._filled_password = True
            return BrowserAction(
                action_type=BrowserActionType.FILL,
                observed_control_id=pwd_control.observed_control_id,
                value_reference=pwd_ref,
                description="Fill password",
            )

        if submit_control and not self._clicked_submit:
            self._clicked_submit = True
            return BrowserAction(
                action_type=BrowserActionType.CLICK,
                observed_control_id=submit_control.observed_control_id,
                description="Click login submit button",
            )

        # 3. If no login form on current page, look for navigation link to sign in
        nav_login = next(
            (
                c
                for c in observation.controls
                if c.visible
                and any(
                    w in f"{c.text or ''} {c.aria_label or ''}".lower()
                    for w in ("sign in", "login", "log in")
                )
            ),
            None,
        )
        if nav_login:
            return BrowserAction(
                action_type=BrowserActionType.CLICK,
                observed_control_id=nav_login.observed_control_id,
                description="Click sign in navigation link",
            )

        return BrowserAction(
            action_type=BrowserActionType.WAIT,
            wait_for=ActionWaitCondition.DOM_CONTENT_LOADED,
            description="Wait for login controls or page transition",
        )

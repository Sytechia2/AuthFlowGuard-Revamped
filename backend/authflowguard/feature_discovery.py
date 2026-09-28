"""Find the registration, reset and logout controls once, after a login.

Principle: the rules or a model suggest, the gate in ``control_roles``
decides, and only what passed it is saved for the checks to replay. A model
is asked only through the caller's classifier, which exists only for a scan
using Bedrock discovery and spends within that scan's limits and cost
ledger.

- Registration and reset links are looked for on the login page, in a
  fresh signed-out browser context, and saved as the address they open. A
  link's address is its validated ``href``; a button is pressed once in that
  context and its address is where it led, if that is another in-scope page.
- Logout is looked for on the signed-in page, in the context the login was
  just verified in: a visible logout control, or one that appears after
  opening an account menu that declares a popup and does not navigate. The
  candidate flow is then run in a separate throwaway signed-in context, and
  it is saved only when the account marker is gone afterwards.

Nothing here fails a scan: a problem means nothing is saved, and the checks
fall back to their own keyword search. Nothing destructive is clicked: every
control passes the gate's strict rules and then the executor's own checks.
"""

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from playwright.async_api import Browser, BrowserContext, Page

from authflowguard.action_executor import BrowserActionExecutor
from authflowguard.auth_profiles import with_form_link, with_logout_flow
from authflowguard.cancellation import close_resources
from authflowguard.checks.session_common import protected_state
from authflowguard.control_fingerprint import with_fingerprint
from authflowguard.control_roles import (
    LINK_ROLES,
    ControlRole,
    RoleContext,
    RoleSuggestion,
    ValidatedRoles,
    rules_account_menu_suggestions,
    rules_link_suggestions,
    rules_logout_suggestions,
    validate_role_suggestions,
)
from authflowguard.control_safety import describe_error, flow_step
from authflowguard.models import (
    AuthFeature,
    AuthProfile,
    BrowserAction,
    BrowserActionType,
    ControlFingerprint,
    DiscoverySource,
    EvidenceEvent,
    EvidenceKind,
    TargetScope,
)
from authflowguard.playwright_worker import PlaywrightWorker
from authflowguard.scope import url_is_in_scope, url_without_query_keeping_route
from authflowguard.secrets import RuntimeSecrets

Control = Mapping[str, Any]

LINK_FEATURES = {
    ControlRole.REGISTRATION_LINK: AuthFeature.REGISTRATION,
    ControlRole.RESET_LINK: AuthFeature.RESET_REQUEST,
}
# How long an opened menu gets to render before it is read.
MENU_SETTLE_MS = 300
# A logout search asks a model at most this many times per scan.
MAXIMUM_LOGOUT_CLASSIFICATIONS = 3


class FeatureSource(StrEnum):
    """Who suggested the saved control."""

    RULES = "rules"
    AI = "ai"
    GUIDED = "guided"


NOTES = {
    FeatureSource.RULES: "Found by the rules from the control's label.",
    FeatureSource.AI: "Suggested by AI and accepted by the validation rules.",
    FeatureSource.GUIDED: (
        "Chosen by the developer and accepted by the validation rules."
    ),
}


@dataclass(frozen=True)
class ObservedControls:
    """A page's safe control descriptions, as a classifier reads them."""

    page_url: str
    page_title: str
    controls: Sequence[Control]


# Asks a model which controls play the given roles; returns the roles the
# gate accepted, or None when no model may be asked (limits, budget,
# configuration or failure). The caller owns the scan's limits and ledger.
RoleClassifier = Callable[
    [ObservedControls, tuple[ControlRole, ...], RoleContext],
    Awaitable[ValidatedRoles | None],
]


@dataclass(frozen=True)
class FeatureDiscoveryRequest:
    """What to look for after a verified login, and how.

    ``chosen_links`` holds a developer's guided answers: a control id, or
    None for "no such link". When it is given the rules are not asked for
    the links.
    """

    features: frozenset[AuthFeature]
    classify: RoleClassifier | None = None
    chosen_links: Mapping[ControlRole, str | None] | None = None

    def link_roles(self) -> tuple[ControlRole, ...]:
        return tuple(
            role for role in LINK_ROLES if LINK_FEATURES[role] in self.features
        )

    def without(self, features: frozenset[AuthFeature]) -> "FeatureDiscoveryRequest":
        """The same request, no longer asking for ``features``."""

        return FeatureDiscoveryRequest(
            features=self.features - features,
            classify=self.classify,
            chosen_links=self.chosen_links,
        )


@dataclass(frozen=True)
class DiscoveredFormLink:
    feature: AuthFeature
    form_url: str
    source: FeatureSource


@dataclass(frozen=True)
class DiscoveredLogout:
    steps: list[BrowserAction]
    source: FeatureSource


@dataclass
class FeatureDiscoveryResult:
    links: list[DiscoveredFormLink] = field(default_factory=list)
    logout: DiscoveredLogout | None = None
    events: list[EvidenceEvent] = field(default_factory=list)

    def apply_to(self, profile: AuthProfile) -> AuthProfile:
        """Save what was found in the profile, with where it came from."""

        for link in self.links:
            profile = with_form_link(
                profile,
                link.feature,
                link.form_url,
                _discovery_source(link.source),
                NOTES[link.source],
            )
        if self.logout is not None:
            profile = with_logout_flow(
                profile,
                self.logout.steps,
                _discovery_source(self.logout.source),
                NOTES[self.logout.source],
            )
        return profile


def _discovery_source(source: FeatureSource) -> DiscoverySource:
    return (
        DiscoverySource.GUIDED
        if source is FeatureSource.GUIDED
        else DiscoverySource.AUTOMATIC
    )


def _event(scan_id: UUID, summary: str, **details: Any) -> EvidenceEvent:
    return EvidenceEvent(
        event_id=uuid4(),
        scan_id=scan_id,
        kind=EvidenceKind.PAGE_STATE,
        summary=summary,
        redacted_details=details,
    )


def _navigate(url: str, description: str) -> BrowserAction:
    return BrowserAction(
        action_type=BrowserActionType.NAVIGATE, url=url, description=description
    )


def _click(
    control_id: str,
    description: str,
    pins: Mapping[str, ControlFingerprint],
) -> BrowserAction:
    """A click pinned to the control observed as ``control_id``."""

    return with_fingerprint(
        BrowserAction(
            action_type=BrowserActionType.CLICK,
            observed_control_id=control_id,
            description=description,
        ),
        pins,
    )


def _same_document(first: str, second: str) -> bool:
    return first.split("#", 1)[0] == second.split("#", 1)[0]


# --- Registration and reset links -------------------------------------------


async def _button_destination(
    page: Page,
    executor: BrowserActionExecutor,
    control_id: str,
    pins: Mapping[str, ControlFingerprint],
    page_url: str,
    target: TargetScope,
) -> str | None:
    """Press a validated button once and return the page it opened, if any."""

    before = url_without_query_keeping_route(page.url)
    await executor.execute(
        _click(control_id, "Open the form to learn its address", pins)
    )
    after = page.url
    destination = (
        after
        if url_is_in_scope(after, target)
        and url_without_query_keeping_route(after) != before
        else None
    )
    # Back to the login page for the next link.
    await executor.execute(_navigate(page_url, "Return to the login page"))
    return destination


async def discover_form_links(
    *,
    browser: Browser,
    scan_id: UUID,
    target: TargetScope,
    page_url: str,
    request: FeatureDiscoveryRequest,
) -> tuple[list[DiscoveredFormLink], EvidenceEvent]:
    """Find the registration and reset links on the login page, signed out."""

    roles = request.link_roles()
    context: BrowserContext | None = None
    try:
        context = await browser.new_context()
        page = await context.new_page()
        executor = BrowserActionExecutor(
            page, target, RuntimeSecrets({}), scan_id, password_references=frozenset()
        )
        await executor.execute(
            _navigate(page_url, "Open the login page to find its form links")
        )
        controls = await PlaywrightWorker().read_controls(page)
        pins = await executor.control_fingerprints()
        role_context = RoleContext(target, url_without_query_keeping_route(page.url))
        suggestions: list[RoleSuggestion]
        if request.chosen_links is not None:
            source = FeatureSource.GUIDED
            suggestions = [
                RoleSuggestion(control_id, role)
                for role, control_id in request.chosen_links.items()
                if control_id and role in roles
            ]
        else:
            source = FeatureSource.RULES
            suggestions = [
                suggestion
                for suggestion in rules_link_suggestions(controls)
                if suggestion.role in roles
            ]
        validated = validate_role_suggestions(
            controls, suggestions, context=role_context
        )
        by_id = {control["observed_control_id"]: control for control in controls}
        found: list[DiscoveredFormLink] = []
        for role in roles:
            control_id = validated.control_for(role)
            if control_id is None:
                continue
            control = by_id[control_id]
            destination: str | None
            if control.get("tag") == "a":
                href = control.get("href")
                destination = href if isinstance(href, str) else None
            else:
                destination = await _button_destination(
                    page, executor, control_id, pins, page_url, target
                )
            if destination is not None:
                found.append(
                    DiscoveredFormLink(
                        feature=LINK_FEATURES[role],
                        form_url=url_without_query_keeping_route(destination),
                        source=source,
                    )
                )
        return found, _event(
            scan_id,
            "Looked for the registration and reset links on the login page.",
            phase="form_link_discovery",
            source=source.value,
            found=[link.feature.value for link in found],
            rejected=[rejection.as_dict() for rejection in validated.rejected],
        )
    finally:
        await close_resources(context)


# --- Logout ------------------------------------------------------------------


@dataclass(frozen=True)
class _LogoutCandidate:
    steps: list[BrowserAction]
    source: FeatureSource


class _Classifications:
    """The logout search's allowance of model requests."""

    def __init__(self, classify: RoleClassifier | None) -> None:
        self._classify = classify
        self.used = 0

    @property
    def available(self) -> bool:
        return self._classify is not None and self.used < MAXIMUM_LOGOUT_CLASSIFICATIONS

    async def ask(
        self,
        page: Page,
        controls: Sequence[Control],
        roles: tuple[ControlRole, ...],
        context: RoleContext,
    ) -> ValidatedRoles:
        if self._classify is None or not self.available:
            return ValidatedRoles()
        self.used += 1
        observed = ObservedControls(
            page_url=context.page_url,
            page_title=await page.title(),
            controls=controls,
        )
        validated = await self._classify(observed, roles, context)
        return validated if validated is not None else ValidatedRoles()


def _accepted(
    controls: Sequence[Control],
    suggestions: list[RoleSuggestion],
    role: ControlRole,
    context: RoleContext,
) -> str | None:
    return validate_role_suggestions(
        controls, suggestions, context=context
    ).control_for(role)


class _MenuNavigated(Exception):
    """Opening a menu navigated, so the rest of this page was never inspected."""


async def _logout_behind_menu(
    page: Page,
    executor: BrowserActionExecutor,
    menu_id: str,
    pins: Mapping[str, ControlFingerprint],
    context: RoleContext,
    classifications: _Classifications | None,
) -> tuple[str, dict[str, ControlFingerprint]] | None:
    """Open a validated menu and find a logout control that appeared in it."""

    url_before = page.url
    await executor.execute(_click(menu_id, "Open the account menu", pins))
    await page.wait_for_timeout(MENU_SETTLE_MS)
    if page.url != url_before:
        # A menu does not navigate. The page's other controls were never
        # inspected, so the search of this page stops here.
        raise _MenuNavigated
    controls = await PlaywrightWorker().read_controls(page)
    opened_pins = await executor.control_fingerprints()
    logout_id = _accepted(
        controls, rules_logout_suggestions(controls), ControlRole.LOGOUT, context
    )
    if logout_id is None and classifications is not None:
        validated = await classifications.ask(
            page, controls, (ControlRole.LOGOUT,), context
        )
        logout_id = validated.control_for(ControlRole.LOGOUT)
    await page.keyboard.press("Escape")
    if logout_id is None:
        return None
    return logout_id, opened_pins


async def _logout_on_page(
    page: Page,
    executor: BrowserActionExecutor,
    target: TargetScope,
    classifications: _Classifications,
) -> _LogoutCandidate | None:
    """Look for logout on the current signed-in page: rules, then a model."""

    here = url_without_query_keeping_route(page.url)
    context = RoleContext(target, here)
    navigation = _navigate(here, "Open the page that holds the logout control")
    controls = await PlaywrightWorker().read_controls(page)
    pins = await executor.control_fingerprints()

    def direct(logout_id: str, source: FeatureSource) -> _LogoutCandidate:
        return _LogoutCandidate(
            [navigation, _click(logout_id, "Sign out", pins)], source
        )

    def behind_menu(
        menu_id: str,
        found: tuple[str, dict[str, ControlFingerprint]],
        source: FeatureSource,
    ) -> _LogoutCandidate:
        logout_id, opened_pins = found
        return _LogoutCandidate(
            [
                navigation,
                _click(menu_id, "Open the account menu", pins),
                _click(logout_id, "Sign out", opened_pins),
            ],
            source,
        )

    logout_id = _accepted(
        controls, rules_logout_suggestions(controls), ControlRole.LOGOUT, context
    )
    if logout_id is not None:
        return direct(logout_id, FeatureSource.RULES)

    opened_menu = False
    try:
        for suggestion in rules_account_menu_suggestions(controls):
            menu_id = _accepted(
                controls, [suggestion], ControlRole.ACCOUNT_MENU, context
            )
            if menu_id is None:
                continue
            opened_menu = True
            found = await _logout_behind_menu(
                page, executor, menu_id, pins, context, None
            )
            if found is not None:
                return behind_menu(menu_id, found, FeatureSource.RULES)

        if not classifications.available:
            return None
        if opened_menu:
            # Start the model's search from the page as it was observed.
            await executor.execute(navigation)
        validated = await classifications.ask(
            page, controls, (ControlRole.LOGOUT, ControlRole.ACCOUNT_MENU), context
        )
        logout_id = validated.control_for(ControlRole.LOGOUT)
        if logout_id is not None:
            return direct(logout_id, FeatureSource.AI)
        menu_id = validated.control_for(ControlRole.ACCOUNT_MENU)
        if menu_id is None:
            return None
        found = await _logout_behind_menu(
            page, executor, menu_id, pins, context, classifications
        )
        if found is not None:
            return behind_menu(menu_id, found, FeatureSource.AI)
        return None
    except _MenuNavigated:
        return None


async def _verify_logout(
    *,
    browser: Browser,
    scan_id: UUID,
    target: TargetScope,
    runtime_secrets: RuntimeSecrets,
    password_references: frozenset[str],
    login_steps: list[BrowserAction],
    logout_steps: list[BrowserAction],
    protected_resource: str,
    account_marker_selector: str,
) -> list[BrowserAction] | None:
    """Sign in again in a throwaway context, run the flow, expect the marker gone.

    Returns the logout steps as recorded, with the fingerprints of the
    controls they used, or None when the flow did not sign the account out.
    """

    context: BrowserContext | None = None
    try:
        context = await browser.new_context()
        page = await context.new_page()
        executor = BrowserActionExecutor(
            page,
            target,
            runtime_secrets,
            scan_id,
            password_references=password_references,
        )
        for number, step in enumerate(login_steps, start=1):
            with flow_step(number):
                await executor.execute(step.model_copy(update={"action_id": uuid4()}))
        signed_in = await protected_state(
            page, protected_resource, account_marker_selector
        )
        if not signed_in["marker_present"]:
            return None
        recorded: list[BrowserAction] = []
        for number, step in enumerate(logout_steps, start=1):
            with flow_step(number):
                result = await executor.execute(step)
            recorded.append(result.recorded(step))
        signed_out = await protected_state(
            page, protected_resource, account_marker_selector
        )
        if signed_out["marker_present"]:
            return None
        return recorded
    finally:
        await close_resources(context)


async def discover_logout(
    *,
    browser: Browser,
    page: Page,
    scan_id: UUID,
    target: TargetScope,
    runtime_secrets: RuntimeSecrets,
    password_references: frozenset[str],
    login_steps: list[BrowserAction],
    protected_resource: str,
    account_marker_selector: str,
    classify: RoleClassifier | None,
) -> tuple[DiscoveredLogout | None, EvidenceEvent]:
    """Find logout on the signed-in ``page`` and keep it only if it works.

    The protected resource is searched first and then, when it is another
    document, the application's start page, as the logout check does.
    """

    executor = BrowserActionExecutor(
        page, target, RuntimeSecrets({}), scan_id, password_references=frozenset()
    )
    classifications = _Classifications(classify)
    app_url = str(target.target_url)
    await executor.execute(
        _navigate(protected_resource, "Open the protected resource to find logout")
    )
    candidate = await _logout_on_page(page, executor, target, classifications)
    if candidate is None and not _same_document(page.url, app_url):
        await executor.execute(_navigate(app_url, "Open the start page to find logout"))
        candidate = await _logout_on_page(page, executor, target, classifications)

    def event(outcome: str) -> EvidenceEvent:
        return _event(
            scan_id,
            "Looked for the logout flow after the verified login.",
            phase="logout_discovery",
            outcome=outcome,
            source=candidate.source.value if candidate is not None else None,
            steps=len(candidate.steps) if candidate is not None else 0,
            model_requests=classifications.used,
        )

    if candidate is None:
        return None, event("not_found")
    recorded = await _verify_logout(
        browser=browser,
        scan_id=scan_id,
        target=target,
        runtime_secrets=runtime_secrets,
        password_references=password_references,
        login_steps=login_steps,
        logout_steps=candidate.steps,
        protected_resource=protected_resource,
        account_marker_selector=account_marker_selector,
    )
    if recorded is None:
        return None, event("not_verified")
    return DiscoveredLogout(recorded, candidate.source), event("verified")


async def discover_features(
    *,
    request: FeatureDiscoveryRequest | None,
    browser: Browser,
    authenticated_page: Page,
    scan_id: UUID,
    target: TargetScope,
    runtime_secrets: RuntimeSecrets,
    password_references: frozenset[str],
    login_steps: list[BrowserAction],
    login_page_url: str,
    protected_resource: str,
    account_marker_selector: str,
) -> FeatureDiscoveryResult:
    """Look for every requested feature; never raises for a discovery problem.

    A failure is recorded as a safe error event and means nothing is saved
    for that feature. Cancellation still propagates.
    """

    result = FeatureDiscoveryResult()
    if request is None or not request.features:
        return result

    if request.link_roles():
        try:
            links, event = await discover_form_links(
                browser=browser,
                scan_id=scan_id,
                target=target,
                page_url=login_page_url,
                request=request,
            )
            result.links.extend(links)
            result.events.append(event)
        except Exception as error:
            result.events.append(_failure_event(scan_id, "form_link_discovery", error))

    if AuthFeature.LOGOUT in request.features:
        try:
            logout, event = await discover_logout(
                browser=browser,
                page=authenticated_page,
                scan_id=scan_id,
                target=target,
                runtime_secrets=runtime_secrets,
                password_references=password_references,
                login_steps=login_steps,
                protected_resource=protected_resource,
                account_marker_selector=account_marker_selector,
                classify=request.classify,
            )
            result.logout = logout
            result.events.append(event)
        except Exception as error:
            result.events.append(_failure_event(scan_id, "logout_discovery", error))
    return result


def _failure_event(scan_id: UUID, phase: str, error: Exception) -> EvidenceEvent:
    return EvidenceEvent(
        event_id=uuid4(),
        scan_id=scan_id,
        kind=EvidenceKind.ERROR,
        summary="Feature discovery did not complete; the check will search instead.",
        redacted_details={"phase": phase, "error": describe_error(error)},
    )

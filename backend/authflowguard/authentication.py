"""Execute and verify a browser-based login without persisting live secrets."""

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from hashlib import sha256
from uuid import UUID

from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    async_playwright,
)
from playwright.async_api import (
    TimeoutError as PlaywrightTimeoutError,
)

from authflowguard.action_executor import ActionExecutionResult, BrowserActionExecutor
from authflowguard.auth_profiles import (
    ProtectedResourceObservation,
    build_verified_login_profile,
)
from authflowguard.automatic_actions import (
    ActionSelectionClient,
    AutomaticActionStatus,
    AutomaticBrowserController,
    ProgressCallback,
)
from authflowguard.cancellation import close_resources
from authflowguard.evaluation.cost_tracking import (
    CostLedger,
    CostLedgerStore,
    UsageSource,
)
from authflowguard.models import (
    ActionWaitCondition,
    AuthFeature,
    AuthProfile,
    BrowserAction,
    BrowserActionType,
    DiscoverySource,
    EvidenceEvent,
    ExecutionLimits,
    FeatureStatus,
    TargetScope,
    TrafficReference,
)
from authflowguard.playwright_worker import PlaywrightWorker, SafeControlDescription
from authflowguard.scope import url_is_in_scope, url_without_query_or_fragment
from authflowguard.secrets import RuntimeSecrets


class LoginFormDiscoveryError(ValueError):
    """Raised when a usable login form cannot be identified unambiguously."""


async def _proof_wait[ProofResult](
    operation: Awaitable[ProofResult],
    cancel_requested: Callable[[], bool] | None,
) -> ProofResult:
    """Bound proof operations and interrupt active Playwright waits on cancel."""

    task = asyncio.ensure_future(operation)
    try:
        for _ in range(300):
            if cancel_requested is not None and cancel_requested():
                raise LoginFormDiscoveryError("Scan cancellation was requested.")
            done, _ = await asyncio.wait({task}, timeout=0.1)
            if done:
                return task.result()
        raise LoginFormDiscoveryError("Authentication proof timed out.")
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


class StaleAuthProfileError(LoginFormDiscoveryError):
    """Raised when a saved flow no longer matches the current login page."""


@dataclass(frozen=True)
class VerifiedLoginExecution:
    """Nonsecret output of login execution and independent verification."""

    profile: AuthProfile
    events: list[EvidenceEvent]
    traffic: list[TrafficReference]


@dataclass(frozen=True)
class GuidedFlowRecording:
    """The nonsecret result of a developer-guided browser flow."""

    actions: list[BrowserAction]
    events: list[EvidenceEvent]
    traffic: list[TrafficReference]


@dataclass(frozen=True)
class GuidedPageObservation:
    """Safe page metadata shown to a developer during guided discovery."""

    event: EvidenceEvent
    controls: list[SafeControlDescription]


def _sanitize_recorded_action(
    action: BrowserAction,
    target: TargetScope,
    runtime_secrets: RuntimeSecrets,
) -> BrowserAction:
    """Copy a guided action without retaining URLs or text containing secrets."""

    if action.action_type is BrowserActionType.NAVIGATE:
        if action.url is None or not url_is_in_scope(str(action.url), target):
            raise ValueError("A guided navigation destination is outside the scope")

    if action.action_type is BrowserActionType.FILL:
        if action.value_reference is None:
            raise ValueError("A guided fill action requires a credential reference")
        runtime_secrets.resolve(action.value_reference)

    values = action.model_dump()
    if action.url is not None:
        values["url"] = url_without_query_or_fragment(str(action.url))
    values["description"] = runtime_secrets.redact_text(action.description)
    return BrowserAction.model_validate(values)


def _prepare_guided_actions(
    actions: list[BrowserAction],
    target: TargetScope,
    runtime_secrets: RuntimeSecrets,
) -> list[BrowserAction]:
    if not actions:
        raise ValueError("A guided flow requires at least one action")
    return [
        _sanitize_recorded_action(action, target, runtime_secrets) for action in actions
    ]


def _control_id(control: SafeControlDescription) -> str:
    control_id = control.get("observed_control_id")
    if control_id is None:
        raise LoginFormDiscoveryError("An observed control has no stable reference")
    return control_id


def _control_signature(control: SafeControlDescription) -> str:
    """Hash stable, nonsecret control metadata for saved-flow validation."""

    metadata = {
        key: control.get(key)
        for key in (
            "tag",
            "id",
            "name",
            "type",
            "placeholder",
            "autocomplete",
            "aria_label",
        )
    }
    serialized = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
    return sha256(serialized.encode("utf-8")).hexdigest()


async def _capture_control_signatures(
    page: Page,
    signatures: dict[str, str],
) -> None:
    controls = await PlaywrightWorker().read_controls(page)
    for control in controls:
        control_id = _control_id(control)
        signatures.setdefault(control_id, _control_signature(control))


def _select_one_control(
    controls: list[SafeControlDescription],
    description: str,
    predicate: Callable[[SafeControlDescription], bool],
) -> str:
    matches = [control for control in controls if predicate(control)]
    if len(matches) != 1:
        raise LoginFormDiscoveryError(
            f"Expected one {description} control, found {len(matches)}"
        )
    return _control_id(matches[0])


async def discover_login_form_actions(
    page: Page,
    target: TargetScope,
    username_reference: str,
    password_reference: str,
    second_factor_reference: str | None = None,
) -> list[BrowserAction]:
    """Identify an unambiguous conventional login form from safe attributes.

    This deterministic baseline supports both conventional form submissions and
    a two-step JSON flow with a visible one-time-code control. Layouts that do
    not expose these semantics still use guided discovery.
    """

    controls = await PlaywrightWorker().read_controls(page)

    def is_username(control: SafeControlDescription) -> bool:
        name = (control.get("name") or "").lower()
        return control.get("autocomplete") == "username" or (
            control.get("type") == "email" and name in {"email", "username", "login"}
        )

    def is_password(control: SafeControlDescription) -> bool:
        return control.get("type") == "password" and control.get("autocomplete") in {
            None,
            "current-password",
        }

    def is_submit(control: SafeControlDescription) -> bool:
        return control.get("tag") in {"button", "input"} and control.get("type") in {
            None,
            "submit",
        }

    username_control = _select_one_control(controls, "username", is_username)

    password_controls = [control for control in controls if is_password(control)]
    if len(password_controls) == 1:
        password_control = _control_id(password_controls[0])
        submit_control = _select_one_control(controls, "submit", is_submit)
        return [
            BrowserAction(
                action_type=BrowserActionType.NAVIGATE,
                url=target.target_url,
                description="Open the discovered login page",
            ),
            BrowserAction(
                action_type=BrowserActionType.FILL,
                observed_control_id=username_control,
                value_reference=username_reference,
                description="Fill the username from its runtime reference",
            ),
            BrowserAction(
                action_type=BrowserActionType.FILL,
                observed_control_id=password_control,
                value_reference=password_reference,
                description="Fill the password from its runtime reference",
            ),
            BrowserAction(
                action_type=BrowserActionType.CLICK,
                observed_control_id=submit_control,
                description="Submit the login form",
            ),
        ]

    def is_verification_code(control: SafeControlDescription) -> bool:
        name = (control.get("name") or "").lower()
        return control.get("autocomplete") == "one-time-code" or name in {
            "code",
            "otp",
            "verification_code",
            "verification-code",
        }

    def is_visible_continue(control: SafeControlDescription) -> bool:
        return is_submit(control) and control.get("visible") is True

    def is_verify_button(control: SafeControlDescription) -> bool:
        return (
            control.get("tag") == "button"
            and control.get("type") == "button"
            and control.get("visible") is False
        )

    code_control = _select_one_control(
        controls,
        "verification-code",
        is_verification_code,
    )
    continue_control = _select_one_control(
        controls,
        "first-step submit",
        is_visible_continue,
    )
    verify_control = _select_one_control(
        controls,
        "verification submit",
        is_verify_button,
    )
    if second_factor_reference is None:
        raise LoginFormDiscoveryError(
            "A second-factor credential reference is required for this login flow"
        )

    return [
        BrowserAction(
            action_type=BrowserActionType.NAVIGATE,
            url=target.target_url,
            description="Open the discovered login page",
        ),
        BrowserAction(
            action_type=BrowserActionType.FILL,
            observed_control_id=username_control,
            value_reference=username_reference,
            description="Fill the username for the first authentication step",
        ),
        BrowserAction(
            action_type=BrowserActionType.CLICK,
            observed_control_id=continue_control,
            description="Request the verification step",
        ),
        BrowserAction(
            action_type=BrowserActionType.WAIT,
            observed_control_id=code_control,
            wait_for=ActionWaitCondition.CONTROL_VISIBLE,
            description="Wait for the verification-code control",
        ),
        BrowserAction(
            action_type=BrowserActionType.FILL,
            observed_control_id=code_control,
            value_reference=second_factor_reference,
            description="Fill the second authentication factor",
        ),
        BrowserAction(
            action_type=BrowserActionType.CLICK,
            observed_control_id=verify_control,
            description="Verify the second authentication factor",
        ),
    ]


def _collect_result(
    result: ActionExecutionResult,
    events: list[EvidenceEvent],
    traffic: list[TrafficReference],
) -> None:
    events.extend(result.events)
    traffic.extend(result.traffic)


async def _record_marker_observation(
    recorder: PlaywrightWorker,
    scan_id: UUID,
    page: Page,
    marker_selector: str,
) -> ProtectedResourceObservation:
    marker = page.locator(marker_selector)
    try:
        await marker.first.wait_for(state="visible", timeout=1500)
    except PlaywrightTimeoutError:
        pass
    marker_present = await marker.count() > 0 and await marker.first.is_visible()
    page_evidence = await recorder.record_page_state(scan_id, page)
    page_evidence.redacted_details["account_marker_present"] = marker_present
    return ProtectedResourceObservation(
        evidence=page_evidence,
        account_marker_present=marker_present,
    )


async def _new_context(browser: Browser) -> BrowserContext:
    return await browser.new_context()


async def _execute_steps(
    *,
    page: Page,
    target: TargetScope,
    runtime_secrets: RuntimeSecrets,
    scan_id: UUID,
    steps: list[BrowserAction],
    step_control_signatures: list[dict[str, str]] | None = None,
    control_signatures_expected: dict[str, str] | None = None,
) -> tuple[list[EvidenceEvent], list[TrafficReference], dict[str, str]]:
    events: list[EvidenceEvent] = []
    traffic: list[TrafficReference] = []
    control_signatures: dict[str, str] = {}
    executor = BrowserActionExecutor(page, target, runtime_secrets, scan_id)
    recorder = PlaywrightWorker()
    for step_idx, action in enumerate(steps):
        if action.observed_control_id:
            controls = await recorder.read_controls(page)
            current_sigs = {_control_id(c): _control_signature(c) for c in controls}
            current_sig = current_sigs.get(action.observed_control_id)
            if current_sig is None:
                raise StaleAuthProfileError(
                    f"The recorded control '{action.observed_control_id}' "
                    "is missing during replay"
                )
            expected_sig = None
            if step_control_signatures and step_idx < len(step_control_signatures):
                expected_sig = step_control_signatures[step_idx].get(
                    action.observed_control_id
                )
            elif control_signatures_expected:
                expected_sig = control_signatures_expected.get(
                    action.observed_control_id
                )
            if expected_sig and current_sig != expected_sig:
                raise StaleAuthProfileError(
                    f"The recorded control '{action.observed_control_id}' "
                    "changed signature during replay"
                )
        _collect_result(await executor.execute(action), events, traffic)
        await _capture_control_signatures(page, control_signatures)
    return events, traffic, control_signatures


async def record_guided_flow(
    *,
    scan_id: UUID,
    target: TargetScope,
    runtime_secrets: RuntimeSecrets,
    actions: list[BrowserAction],
) -> GuidedFlowRecording:
    """Execute and retain a developer-guided flow as safe structured actions.

    A caller supplies actions created by the guidance UI. Fill actions must use
    local credential references; live values are resolved only by the executor.
    """

    recorded_actions = _prepare_guided_actions(actions, target, runtime_secrets)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context: BrowserContext | None = None
        try:
            context = await _new_context(browser)
            page = await context.new_page()
            events, traffic, _control_signatures = await _execute_steps(
                page=page,
                target=target,
                runtime_secrets=runtime_secrets,
                scan_id=scan_id,
                steps=recorded_actions,
            )
            return GuidedFlowRecording(
                actions=recorded_actions,
                events=events,
                traffic=traffic,
            )
        finally:
            await close_resources(context, browser)


async def observe_guidance_page(
    *,
    scan_id: UUID,
    target: TargetScope,
    observation_url: str | None = None,
) -> GuidedPageObservation:
    """Open the target once and return only safe control metadata for guidance."""

    page_url = observation_url or str(target.target_url)
    if not url_is_in_scope(page_url, target):
        raise ValueError("The guidance observation URL is outside permitted_origins")

    recorder = PlaywrightWorker()
    runtime_secrets = RuntimeSecrets({})
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context: BrowserContext | None = None
        try:
            context = await _new_context(browser)
            page = await context.new_page()
            executor = BrowserActionExecutor(page, target, runtime_secrets, scan_id)
            navigation = BrowserAction(
                action_type=BrowserActionType.NAVIGATE,
                url=page_url,
                description="Open the target page for guided discovery",
            )
            await executor.execute(navigation)
            event = await recorder.record_page_state(scan_id, page)
            controls = event.redacted_details.get("controls", [])
            return GuidedPageObservation(event=event, controls=controls)
        finally:
            await close_resources(context, browser)


async def execute_guided_verified_login_flow(
    *,
    scan_id: UUID,
    target: TargetScope,
    runtime_secrets: RuntimeSecrets,
    actions: list[BrowserAction],
    protected_resource: str,
    account_marker_selector: str,
    account_marker_description: str,
) -> VerifiedLoginExecution:
    """Record a guided login and verify it against an isolated anonymous context."""

    if not url_is_in_scope(protected_resource, target):
        raise ValueError("The protected resource is outside permitted_origins")
    if not account_marker_selector.strip():
        raise ValueError("The account marker selector must not be empty")

    recorded_actions = _prepare_guided_actions(actions, target, runtime_secrets)
    events: list[EvidenceEvent] = []
    traffic: list[TrafficReference] = []
    recorder = PlaywrightWorker()

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        authenticated_context: BrowserContext | None = None
        anonymous_context: BrowserContext | None = None
        try:
            authenticated_context = await _new_context(browser)
            authenticated_page = await authenticated_context.new_page()
            action_events, action_traffic, control_signatures = await _execute_steps(
                page=authenticated_page,
                target=target,
                runtime_secrets=runtime_secrets,
                scan_id=scan_id,
                steps=recorded_actions,
            )
            events.extend(action_events)
            traffic.extend(action_traffic)

            protected_action = BrowserAction(
                action_type=BrowserActionType.NAVIGATE,
                url=protected_resource,
                description="Open the protected resource after guided login",
            )
            protected_events, protected_traffic, _ = await _execute_steps(
                page=authenticated_page,
                target=target,
                runtime_secrets=runtime_secrets,
                scan_id=scan_id,
                steps=[protected_action],
            )
            events.extend(protected_events)
            traffic.extend(protected_traffic)
            authenticated_observation = await _record_marker_observation(
                recorder,
                scan_id,
                authenticated_page,
                account_marker_selector,
            )
            events.append(authenticated_observation.evidence)
            storage_event, session_references = await recorder.record_session_state(
                scan_id,
                authenticated_context,
                authenticated_page,
            )
            events.append(storage_event)

            anonymous_context = await _new_context(browser)
            anonymous_page = await anonymous_context.new_page()
            anonymous_action = BrowserAction(
                action_type=BrowserActionType.NAVIGATE,
                url=protected_resource,
                description="Open the protected resource anonymously",
            )
            anonymous_events, anonymous_traffic, _ = await _execute_steps(
                page=anonymous_page,
                target=target,
                runtime_secrets=RuntimeSecrets({}),
                scan_id=scan_id,
                steps=[anonymous_action],
            )
            events.extend(anonymous_events)
            traffic.extend(anonymous_traffic)
            anonymous_observation = await _record_marker_observation(
                recorder,
                scan_id,
                anonymous_page,
                account_marker_selector,
            )
            events.append(anonymous_observation.evidence)

            profile = build_verified_login_profile(
                target=target,
                login_steps=recorded_actions,
                protected_resource=protected_resource,
                account_marker_description=runtime_secrets.redact_text(
                    account_marker_description
                ),
                authenticated_observation=authenticated_observation,
                anonymous_observation=anonymous_observation,
                discovery_source=DiscoverySource.GUIDED,
                traffic=traffic,
                session_references=session_references,
                control_signatures=control_signatures,
                step_control_signatures=[
                    control_signatures.copy() for _ in recorded_actions
                ],
            )
            return VerifiedLoginExecution(
                profile=profile,
                events=events,
                traffic=traffic,
            )
        finally:
            await close_resources(anonymous_context, authenticated_context, browser)


async def revalidate_auth_profile(
    *,
    profile: AuthProfile,
    scan_id: UUID,
    runtime_secrets: RuntimeSecrets | None = None,
) -> None:
    """Confirm that a saved flow still describes the current login page."""

    login_steps = profile.authentication_steps.get(AuthFeature.LOGIN, [])
    if not login_steps:
        raise StaleAuthProfileError("The saved login flow has no login steps")
    if not profile.control_signatures and not profile.step_control_signatures:
        raise StaleAuthProfileError(
            "The saved login flow has no page-control signatures; guidance is required"
        )

    if profile.step_control_signatures:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context: BrowserContext | None = None
            try:
                context = await _new_context(browser)
                page = await context.new_page()
                executor = BrowserActionExecutor(
                    page,
                    profile.target,
                    RuntimeSecrets({}),
                    scan_id,
                )
                recorder = PlaywrightWorker()

                if runtime_secrets is not None:
                    executor = BrowserActionExecutor(
                        page, profile.target, runtime_secrets, scan_id
                    )
                for step_idx, action in enumerate(login_steps):
                    if step_idx == 1 and profile.control_signatures:
                        first_controls = await recorder.read_controls(page)
                        first_sigs = {
                            _control_id(c): _control_signature(c)
                            for c in first_controls
                        }
                        for (
                            control_id,
                            expected_sig,
                        ) in profile.control_signatures.items():
                            if first_sigs.get(control_id) != expected_sig:
                                raise StaleAuthProfileError(
                                    "The saved login flow is stale: changed "
                                    f"{control_id}"
                                )
                    if action.observed_control_id:
                        controls = await recorder.read_controls(page)
                        current_sigs = {
                            _control_id(c): _control_signature(c) for c in controls
                        }
                        expected = (
                            profile.step_control_signatures[step_idx].get(
                                action.observed_control_id
                            )
                            if step_idx < len(profile.step_control_signatures)
                            else None
                        )
                        if expected is None:
                            raise StaleAuthProfileError(
                                "The saved login flow lacks a step signature for "
                                f"'{action.observed_control_id}'"
                            )
                        current = current_sigs.get(action.observed_control_id)
                        if current is None or current != expected:
                            raise StaleAuthProfileError(
                                "The saved login flow is stale: changed "
                                f"{action.observed_control_id}"
                            )
                    if (
                        action.action_type is BrowserActionType.FILL
                        and runtime_secrets is None
                    ):
                        break
                    await executor.execute(action)
            finally:
                await close_resources(context, browser)
        return

    navigation = next(
        (
            action
            for action in login_steps
            if action.action_type is BrowserActionType.NAVIGATE
            and action.url is not None
        ),
        None,
    )
    if navigation is None or navigation.url is None:
        raise StaleAuthProfileError(
            "The saved login flow has no valid login-page navigation"
        )

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = None
        try:
            context = await _new_context(browser)
            page = await context.new_page()
            executor = BrowserActionExecutor(
                page,
                profile.target,
                RuntimeSecrets({}),
                scan_id,
            )
            await executor.execute(navigation)
            current_controls = await PlaywrightWorker().read_controls(page)
            current_signatures = {
                _control_id(control): _control_signature(control)
                for control in current_controls
            }
        finally:
            await close_resources(context, browser)

    expected_ids = set(profile.control_signatures)
    current_ids = set(current_signatures)
    missing_ids = sorted(expected_ids - current_ids)
    added_ids = sorted(current_ids - expected_ids)
    changed_ids = sorted(
        control_id
        for control_id in expected_ids & current_ids
        if profile.control_signatures[control_id] != current_signatures[control_id]
    )
    if missing_ids or added_ids or changed_ids:
        differences: list[str] = []
        if missing_ids:
            differences.append(f"missing {', '.join(missing_ids)}")
        if added_ids:
            differences.append(f"new {', '.join(added_ids)}")
        if changed_ids:
            differences.append(f"changed {', '.join(changed_ids)}")
        raise StaleAuthProfileError(
            "The saved login flow is stale: " + "; ".join(differences)
        )


async def replay_verified_auth_profile(
    *,
    profile: AuthProfile,
    scan_id: UUID,
    runtime_secrets: RuntimeSecrets,
    account_marker_selector: str,
) -> VerifiedLoginExecution:
    """Replay a saved login flow in fresh authenticated and anonymous contexts."""

    login_steps = profile.authentication_steps.get(AuthFeature.LOGIN, [])
    if not login_steps:
        raise ValueError("The auth profile has no saved login flow")
    if profile.features.get(AuthFeature.LOGIN) is not FeatureStatus.VERIFIED:
        raise ValueError("Only a verified login profile can be replayed")
    protected_check = profile.protected_resource_check
    if protected_check is None:
        raise ValueError("The auth profile has no protected resource proof")

    target = profile.target
    protected_resource = protected_check.resource
    if not url_is_in_scope(protected_resource, target):
        raise ValueError("The protected resource is outside permitted_origins")
    if not account_marker_selector.strip():
        raise ValueError("The account marker selector must not be empty")

    replayed_steps = _prepare_guided_actions(login_steps, target, runtime_secrets)
    events: list[EvidenceEvent] = []
    traffic: list[TrafficReference] = []
    recorder = PlaywrightWorker()

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        authenticated_context: BrowserContext | None = None
        anonymous_context: BrowserContext | None = None
        try:
            authenticated_context = await _new_context(browser)
            authenticated_page = await authenticated_context.new_page()
            action_events, action_traffic, _ = await _execute_steps(
                page=authenticated_page,
                target=target,
                runtime_secrets=runtime_secrets,
                scan_id=scan_id,
                steps=replayed_steps,
                step_control_signatures=profile.step_control_signatures,
                control_signatures_expected=profile.control_signatures,
            )
            events.extend(action_events)
            traffic.extend(action_traffic)
            protected_action = BrowserAction(
                action_type=BrowserActionType.NAVIGATE,
                url=protected_resource,
                description="Open the saved protected resource",
            )
            protected_events, protected_traffic, _ = await _execute_steps(
                page=authenticated_page,
                target=target,
                runtime_secrets=runtime_secrets,
                scan_id=scan_id,
                steps=[protected_action],
            )
            events.extend(protected_events)
            traffic.extend(protected_traffic)
            authenticated_observation = await _record_marker_observation(
                recorder,
                scan_id,
                authenticated_page,
                account_marker_selector,
            )
            events.append(authenticated_observation.evidence)
            storage_event, session_references = await recorder.record_session_state(
                scan_id,
                authenticated_context,
                authenticated_page,
            )
            events.append(storage_event)

            anonymous_context = await _new_context(browser)
            anonymous_page = await anonymous_context.new_page()
            anonymous_action = BrowserAction(
                action_type=BrowserActionType.NAVIGATE,
                url=protected_resource,
                description="Open the saved resource anonymously",
            )
            anonymous_events, anonymous_traffic, _ = await _execute_steps(
                page=anonymous_page,
                target=target,
                runtime_secrets=RuntimeSecrets({}),
                scan_id=scan_id,
                steps=[anonymous_action],
            )
            events.extend(anonymous_events)
            traffic.extend(anonymous_traffic)
            anonymous_observation = await _record_marker_observation(
                recorder,
                scan_id,
                anonymous_page,
                account_marker_selector,
            )
            events.append(anonymous_observation.evidence)

            source = DiscoverySource.GUIDED
            if profile.discovery_history:
                source = profile.discovery_history[-1].source
            replayed_profile = build_verified_login_profile(
                target=target,
                login_steps=replayed_steps,
                protected_resource=protected_resource,
                account_marker_description=runtime_secrets.redact_text(
                    protected_check.account_marker_description
                ),
                authenticated_observation=authenticated_observation,
                anonymous_observation=anonymous_observation,
                discovery_source=source,
                traffic=traffic,
                session_references=session_references,
                control_signatures=profile.control_signatures,
                step_control_signatures=profile.step_control_signatures,
            )
            return VerifiedLoginExecution(
                profile=replayed_profile,
                events=events,
                traffic=traffic,
            )
        finally:
            await close_resources(anonymous_context, authenticated_context, browser)


async def execute_verified_login_flow(
    *,
    scan_id: UUID,
    target: TargetScope,
    runtime_secrets: RuntimeSecrets,
    username_reference: str,
    password_reference: str,
    second_factor_reference: str | None = None,
    protected_resource: str,
    account_marker_selector: str,
    account_marker_description: str,
    discovery_source: DiscoverySource = DiscoverySource.AUTOMATIC,
) -> VerifiedLoginExecution:
    """Discover, execute, and prove a login in isolated browser contexts."""

    if not url_is_in_scope(protected_resource, target):
        raise ValueError("The protected resource is outside permitted_origins")
    if not account_marker_selector.strip():
        raise ValueError("The account marker selector must not be empty")

    events: list[EvidenceEvent] = []
    traffic: list[TrafficReference] = []
    recorder = PlaywrightWorker()

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        authenticated_context: BrowserContext | None = None
        anonymous_context: BrowserContext | None = None

        try:
            authenticated_context = await _new_context(browser)
            authenticated_page = await authenticated_context.new_page()
            authenticated_executor = BrowserActionExecutor(
                authenticated_page,
                target,
                runtime_secrets,
                scan_id,
            )
            navigation = BrowserAction(
                action_type=BrowserActionType.NAVIGATE,
                url=target.target_url,
                description="Open the target login page for discovery",
            )
            _collect_result(
                await authenticated_executor.execute(navigation), events, traffic
            )
            control_signatures: dict[str, str] = {}
            await _capture_control_signatures(authenticated_page, control_signatures)

            discovered_steps = await discover_login_form_actions(
                authenticated_page,
                target,
                username_reference,
                password_reference,
                second_factor_reference,
            )
            login_steps = [navigation, *discovered_steps[1:]]
            for action in discovered_steps[1:]:
                _collect_result(
                    await authenticated_executor.execute(action), events, traffic
                )

            protected_action = BrowserAction(
                action_type=BrowserActionType.NAVIGATE,
                url=protected_resource,
                description="Open the protected resource after login",
            )
            _collect_result(
                await authenticated_executor.execute(protected_action), events, traffic
            )
            authenticated_observation = await _record_marker_observation(
                recorder,
                scan_id,
                authenticated_page,
                account_marker_selector,
            )
            events.append(authenticated_observation.evidence)
            storage_event, session_references = await recorder.record_session_state(
                scan_id,
                authenticated_context,
                authenticated_page,
            )
            events.append(storage_event)

            anonymous_context = await _new_context(browser)
            anonymous_page = await anonymous_context.new_page()
            anonymous_executor = BrowserActionExecutor(
                anonymous_page,
                target,
                RuntimeSecrets({}),
                scan_id,
            )
            anonymous_protected_action = BrowserAction(
                action_type=BrowserActionType.NAVIGATE,
                url=protected_resource,
                description="Open the protected resource anonymously",
            )
            _collect_result(
                await anonymous_executor.execute(anonymous_protected_action),
                events,
                traffic,
            )
            anonymous_observation = await _record_marker_observation(
                recorder,
                scan_id,
                anonymous_page,
                account_marker_selector,
            )
            events.append(anonymous_observation.evidence)

            profile = build_verified_login_profile(
                target=target,
                login_steps=login_steps,
                protected_resource=protected_resource,
                account_marker_description=runtime_secrets.redact_text(
                    account_marker_description
                ),
                authenticated_observation=authenticated_observation,
                anonymous_observation=anonymous_observation,
                discovery_source=discovery_source,
                traffic=traffic,
                session_references=session_references,
                control_signatures=control_signatures,
                step_control_signatures=[
                    control_signatures.copy() for _ in login_steps
                ],
            )
            return VerifiedLoginExecution(
                profile=profile,
                events=events,
                traffic=traffic,
            )
        finally:
            await close_resources(anonymous_context, authenticated_context, browser)


async def execute_ai_verified_login_flow(
    *,
    scan_id: UUID,
    target: TargetScope,
    runtime_secrets: RuntimeSecrets,
    username_reference: str,
    password_reference: str,
    second_factor_reference: str | None = None,
    protected_resource: str,
    account_marker_selector: str,
    account_marker_description: str,
    action_client: ActionSelectionClient,
    limits: ExecutionLimits,
    cancel_requested: Callable[[], bool] | None = None,
    progress_callback: ProgressCallback | None = None,
    usage_callback: Callable[[int | None, int | None], None] | None = None,
    event_sink: Callable[[list[EvidenceEvent]], None] | None = None,
    cost_ledger_store: CostLedgerStore | None = None,
    cost_ledger: CostLedger | None = None,
    usage_source: UsageSource | str = UsageSource.NONE,
    model_id: str | None = None,
) -> VerifiedLoginExecution:
    """Discover, execute, and prove a login using Bedrock browser orchestration."""

    if not url_is_in_scope(protected_resource, target):
        raise ValueError("The protected resource is outside permitted_origins")
    if not account_marker_selector.strip():
        raise ValueError("The account marker selector must not be empty")

    events: list[EvidenceEvent] = []
    traffic: list[TrafficReference] = []
    recorder = PlaywrightWorker()

    credential_references = [username_reference, password_reference]
    if second_factor_reference is not None:
        credential_references.append(second_factor_reference)

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        authenticated_context = await _new_context(browser)
        anonymous_context: BrowserContext | None = None

        try:
            authenticated_page = await authenticated_context.new_page()

            async def completion_check(page: Page) -> bool:
                marker = page.locator(account_marker_selector)
                try:
                    await marker.first.wait_for(state="visible", timeout=1000)
                except PlaywrightTimeoutError:
                    pass
                if await marker.count() > 0 and await marker.first.is_visible():
                    return True
                return False

            controller = AutomaticBrowserController(
                page=authenticated_page,
                target=target,
                runtime_secrets=runtime_secrets,
                scan_id=scan_id,
                action_client=action_client,
                limits=limits,
                credential_references=credential_references,
                progress_callback=progress_callback,
                usage_callback=usage_callback,
                event_sink=event_sink,
                cancel_requested=cancel_requested,
                cost_ledger_store=cost_ledger_store,
                cost_ledger=cost_ledger,
                usage_source=usage_source,
                model_id=model_id,
            )

            result = await controller.run(completion_check)
            events.extend(result.events)
            traffic.extend(result.traffic)
            if event_sink is not None:
                event_sink(result.events)

            if result.status is AutomaticActionStatus.CANCELLED:
                raise LoginFormDiscoveryError("Scan cancellation was requested.")
            if result.status is not AutomaticActionStatus.COMPLETED:
                raise LoginFormDiscoveryError(
                    f"Automatic login discovery did not complete: {result.reason}"
                )

            raw_actions = result.executed_actions
            login_steps = _prepare_guided_actions(raw_actions, target, runtime_secrets)

            def check_cancelled() -> None:
                if cancel_requested is not None and cancel_requested():
                    raise LoginFormDiscoveryError("Scan cancellation was requested.")

            # Independent authentication proof
            authenticated_executor = BrowserActionExecutor(
                authenticated_page,
                target,
                runtime_secrets,
                scan_id,
            )
            protected_action = BrowserAction(
                action_type=BrowserActionType.NAVIGATE,
                url=protected_resource,
                description="Open the protected resource after login",
            )
            check_cancelled()
            _collect_result(
                await _proof_wait(
                    authenticated_executor.execute(protected_action), cancel_requested
                ),
                events,
                traffic,
            )
            check_cancelled()
            authenticated_observation = await _proof_wait(
                _record_marker_observation(
                    recorder, scan_id, authenticated_page, account_marker_selector
                ),
                cancel_requested,
            )
            events.append(authenticated_observation.evidence)

            if not authenticated_observation.account_marker_present:
                raise LoginFormDiscoveryError(
                    f"Authentication proof failed: marker '{account_marker_selector}' "
                    f"absent in authenticated context on {protected_resource}"
                )

            check_cancelled()
            storage_event, session_references = await _proof_wait(
                recorder.record_session_state(
                    scan_id, authenticated_context, authenticated_page
                ),
                cancel_requested,
            )
            events.append(storage_event)

            # Isolated fresh anonymous context check
            check_cancelled()
            anonymous_context = await _proof_wait(
                _new_context(browser), cancel_requested
            )
            anonymous_page = await _proof_wait(
                anonymous_context.new_page(), cancel_requested
            )
            anonymous_executor = BrowserActionExecutor(
                anonymous_page,
                target,
                RuntimeSecrets({}),
                scan_id,
            )
            anonymous_protected_action = BrowserAction(
                action_type=BrowserActionType.NAVIGATE,
                url=protected_resource,
                description="Open the protected resource anonymously",
            )
            check_cancelled()
            _collect_result(
                await _proof_wait(
                    anonymous_executor.execute(anonymous_protected_action),
                    cancel_requested,
                ),
                events,
                traffic,
            )
            check_cancelled()
            anonymous_observation = await _proof_wait(
                _record_marker_observation(
                    recorder, scan_id, anonymous_page, account_marker_selector
                ),
                cancel_requested,
            )
            events.append(anonymous_observation.evidence)

            if anonymous_observation.account_marker_present:
                raise LoginFormDiscoveryError(
                    f"Authentication proof failed: marker '{account_marker_selector}' "
                    f"visible in anonymous context on {protected_resource}"
                )

            check_cancelled()
            control_signatures = (
                result.step_control_signatures[1].copy()
                if len(result.step_control_signatures) > 1
                else {}
            )

            profile = build_verified_login_profile(
                target=target,
                login_steps=login_steps,
                protected_resource=protected_resource,
                account_marker_description=runtime_secrets.redact_text(
                    account_marker_description
                ),
                authenticated_observation=authenticated_observation,
                anonymous_observation=anonymous_observation,
                discovery_source=DiscoverySource.AUTOMATIC,
                traffic=traffic,
                session_references=session_references,
                control_signatures=control_signatures,
                step_control_signatures=result.step_control_signatures,
            )
            return VerifiedLoginExecution(
                profile=profile,
                events=events,
                traffic=traffic,
            )
        finally:
            if event_sink is not None:
                event_sink(events)
            await close_resources(anonymous_context, authenticated_context, browser)

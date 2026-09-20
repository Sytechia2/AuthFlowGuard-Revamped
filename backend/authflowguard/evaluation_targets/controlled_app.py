"""Controlled form-and-cookie application used for local security evaluation.

This fixture is intentionally small and deterministic. It is not an example of
production authentication: its purpose is to give AuthFlowGuard known secure
and vulnerable behaviours that can be exercised through a real browser.
"""

from __future__ import annotations

import argparse
import html
import secrets
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated
from urllib.parse import parse_qs

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

SESSION_COOKIE = "afg_evaluation_session"
KNOWN_USERNAME = "developer@example.test"
KNOWN_PASSWORD = "correct-horse-battery-staple"
LOCKOUT_THRESHOLD = 3


class EvaluationMode(StrEnum):
    """Behaviour profile exposed by the controlled application."""

    SECURE = "secure"
    VULNERABLE = "vulnerable"


@dataclass
class SessionState:
    username: str | None = None
    csrf_token: str | None = None


class ControlledApplicationState:
    """Mutable state owned by one controlled application instance."""

    def __init__(self, mode: EvaluationMode) -> None:
        self.mode = mode
        self.sessions: dict[str, SessionState] = {}
        self.users: dict[str, str] = {KNOWN_USERNAME: KNOWN_PASSWORD}
        self.failed_logins: dict[str, int] = {}

    def session_for(self, request: Request) -> tuple[str, SessionState, bool]:
        session_id = request.cookies.get(SESSION_COOKIE)
        if session_id is not None and session_id in self.sessions:
            return session_id, self.sessions[session_id], False

        session_id = secrets.token_urlsafe(24)
        session = SessionState()
        self.sessions[session_id] = session
        return session_id, session, True

    def issue_csrf_token(self, session: SessionState) -> str:
        token = secrets.token_urlsafe(24)
        session.csrf_token = token
        return token

    def consume_valid_csrf(self, session: SessionState, supplied: str) -> bool:
        expected = session.csrf_token
        session.csrf_token = None
        return expected is not None and secrets.compare_digest(expected, supplied)


def _set_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        samesite="lax",
        path="/",
    )


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>{html.escape(title)}</title></head>
  <body>
    <nav>
      <a href="/login">Login</a>
      <a href="/register">Register</a>
      <a href="/reset">Reset password</a>
    </nav>
    <main>{body}</main>
  </body>
</html>"""


def _form_page(path: str, title: str, csrf_token: str, fields: str) -> str:
    body = f"""
<h1>{html.escape(title)}</h1>
<form method="post" action="{path}">
  <input type="hidden" name="csrf_token" value="{html.escape(csrf_token)}">
  {fields}
  <button type="submit">{html.escape(title)}</button>
</form>"""
    return _page(title, body)


async def _read_form(request: Request) -> dict[str, str]:
    parsed = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
    return {name: values[-1] for name, values in parsed.items() if values}


def _form_response(
    state: ControlledApplicationState,
    request: Request,
    path: str,
    title: str,
    fields: str,
) -> HTMLResponse:
    session_id, session, created = state.session_for(request)
    token = state.issue_csrf_token(session)
    response = HTMLResponse(_form_page(path, title, token, fields))
    if created:
        _set_session_cookie(response, session_id)
    return response


def create_controlled_app(
    mode: EvaluationMode | str = EvaluationMode.SECURE,
) -> FastAPI:
    """Create an isolated controlled application in the requested mode."""

    selected_mode = EvaluationMode(mode)
    state = ControlledApplicationState(selected_mode)
    application = FastAPI(
        title=f"AuthFlowGuard controlled application ({selected_mode.value})",
        version="0.1.0",
    )
    application.state.controlled = state

    @application.get("/", include_in_schema=False)
    async def index() -> RedirectResponse:
        return RedirectResponse("/login", status_code=303)

    @application.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request) -> HTMLResponse:
        fields = """
<label>Email <input name="username" type="email" autocomplete="username"></label>
<label>Password <input name="password" type="password"
  autocomplete="current-password"></label>"""
        return _form_response(state, request, "/login", "Sign in", fields)

    @application.post("/login")
    async def login(request: Request) -> Response:
        session_id, session, created = state.session_for(request)
        form = await _read_form(request)
        if not state.consume_valid_csrf(session, form.get("csrf_token", "")):
            response = HTMLResponse(
                _page("Invalid request", "<h1>Invalid CSRF token</h1>"), 400
            )
            if created:
                _set_session_cookie(response, session_id)
            return response

        username = form.get("username", "")
        password = form.get("password", "")
        is_known = username in state.users
        is_locked = state.failed_logins.get(username, 0) >= LOCKOUT_THRESHOLD

        if selected_mode is EvaluationMode.SECURE and is_locked:
            return HTMLResponse(
                _page("Sign in unavailable", "<h1>Try again later</h1>"),
                status_code=429,
            )

        if is_known and secrets.compare_digest(state.users[username], password):
            state.failed_logins.pop(username, None)
            if selected_mode is EvaluationMode.SECURE:
                state.sessions.pop(session_id, None)
                session_id = secrets.token_urlsafe(24)
                session = SessionState(username=username)
                state.sessions[session_id] = session
            else:
                session.username = username

            redirect_response = RedirectResponse("/account", status_code=303)
            _set_session_cookie(redirect_response, session_id)
            return redirect_response

        if is_known:
            state.failed_logins[username] = state.failed_logins.get(username, 0) + 1

        if selected_mode is EvaluationMode.VULNERABLE and not is_known:
            message = "No account exists for that email address."
        elif selected_mode is EvaluationMode.VULNERABLE:
            message = "The password is incorrect."
        else:
            message = "The email address or password is incorrect."
        return HTMLResponse(
            _page("Sign in failed", f"<h1>Sign in failed</h1><p>{message}</p>"),
            status_code=401,
        )

    @application.get("/account", response_class=HTMLResponse)
    async def account(request: Request) -> HTMLResponse:
        _session_id, session, _created = state.session_for(request)
        if session.username is None:
            return HTMLResponse(
                _page("Authentication required", "<h1>Authentication required</h1>"),
                status_code=401,
            )

        token = state.issue_csrf_token(session)
        username = html.escape(session.username)
        body = f"""
<h1>Developer account</h1>
<p data-testid="account-marker">Signed in as {username}</p>
<form method="post" action="/logout">
  <input type="hidden" name="csrf_token" value="{html.escape(token)}">
  <button type="submit">Log out</button>
</form>"""
        return HTMLResponse(_page("Developer account", body))

    @application.post("/logout")
    async def logout(request: Request) -> Response:
        session_id, session, _created = state.session_for(request)
        form = await _read_form(request)
        if not state.consume_valid_csrf(session, form.get("csrf_token", "")):
            return HTMLResponse(
                _page("Invalid request", "<h1>Invalid CSRF token</h1>"), 400
            )

        response = RedirectResponse("/login", status_code=303)
        if selected_mode is EvaluationMode.SECURE:
            state.sessions.pop(session_id, None)
            response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @application.get("/register", response_class=HTMLResponse)
    async def register_form(request: Request) -> HTMLResponse:
        fields = """
<label>Email <input name="username" type="email" autocomplete="username"></label>
<label>Password <input name="password" type="password"
  autocomplete="new-password"></label>"""
        return _form_response(state, request, "/register", "Create account", fields)

    @application.post("/register")
    async def register(request: Request) -> HTMLResponse:
        _session_id, session, _created = state.session_for(request)
        form = await _read_form(request)
        if not state.consume_valid_csrf(session, form.get("csrf_token", "")):
            return HTMLResponse(
                _page("Invalid request", "<h1>Invalid CSRF token</h1>"), 400
            )

        username = form.get("username", "")
        password = form.get("password", "")
        exists = username in state.users
        if not exists and username and password:
            state.users[username] = password

        if selected_mode is EvaluationMode.VULNERABLE and exists:
            return HTMLResponse(
                _page(
                    "Registration failed", "<h1>This email is already registered</h1>"
                ),
                status_code=409,
            )
        return HTMLResponse(
            _page("Registration received", "<h1>Check your email to continue</h1>"),
            status_code=202,
        )

    @application.get("/reset", response_class=HTMLResponse)
    async def reset_form(request: Request) -> HTMLResponse:
        fields = """
<label>Email <input name="username" type="email" autocomplete="username"></label>"""
        return _form_response(state, request, "/reset", "Reset password", fields)

    @application.post("/reset")
    async def reset(request: Request) -> HTMLResponse:
        _session_id, session, _created = state.session_for(request)
        form = await _read_form(request)
        if not state.consume_valid_csrf(session, form.get("csrf_token", "")):
            return HTMLResponse(
                _page("Invalid request", "<h1>Invalid CSRF token</h1>"), 400
            )

        username = form.get("username", "")
        if selected_mode is EvaluationMode.VULNERABLE and username not in state.users:
            message = "No account exists for that email address."
        else:
            message = "If an account exists, reset instructions will be sent."
        return HTMLResponse(_page("Reset requested", f"<h1>{message}</h1>"), 202)

    return application


secure_app = create_controlled_app(EvaluationMode.SECURE)
vulnerable_app = create_controlled_app(EvaluationMode.VULNERABLE)


def main(argv: Annotated[list[str] | None, "Command-line arguments"] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=EvaluationMode, default=EvaluationMode.SECURE)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    arguments = parser.parse_args(argv)
    uvicorn.run(
        create_controlled_app(arguments.mode),
        host=arguments.host,
        port=arguments.port,
    )


if __name__ == "__main__":
    main()

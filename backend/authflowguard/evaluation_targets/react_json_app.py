"""Controlled React/JSON bearer-token application for authentication evaluation.

This fixture models a common SPA login shape: a username is submitted to a
JSON endpoint, a one-time code is requested, and a second JSON endpoint returns
a bearer token that the browser stores in localStorage. It intentionally keeps
the UI small so the authentication runner can exercise the protocol through a
real browser without persisting any token or code.
"""

from __future__ import annotations

import argparse
import html
import secrets
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

KNOWN_USERNAME = "developer@example.test"
KNOWN_VERIFICATION_CODE = "246810"
BEARER_STORAGE_KEY = "afg_bearer_token"


class EvaluationMode(StrEnum):
    """Behaviour profile exposed by the controlled application."""

    SECURE = "secure"
    VULNERABLE = "vulnerable"


@dataclass
class TokenSession:
    username: str
    token: str


class ReactJsonApplicationState:
    """Mutable state owned by one React/JSON application instance."""

    def __init__(self, mode: EvaluationMode) -> None:
        self.mode = mode
        self.pending_users: set[str] = set()
        self.tokens: dict[str, TokenSession] = {}

    def issue_token(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        self.tokens[token] = TokenSession(username=username, token=token)
        return token


def _login_page() -> str:
    return """<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Developer sign in</title></head>
  <body>
    <main>
      <h1>Developer sign in</h1>
      <form id="login-form">
        <label>Email <input id="username" name="username" type="email"
          autocomplete="username"></label>
        <button id="continue" type="submit">Continue</button>
      </form>
      <section id="verification" hidden>
        <label>Verification code <input id="verification-code" name="code"
          type="text" inputmode="numeric" autocomplete="one-time-code"></label>
        <button id="verify" type="button">Verify</button>
      </section>
      <p id="message" role="status"></p>
    </main>
    <script>
      const message = document.querySelector("#message");
      const verification = document.querySelector("#verification");
      const usernameInput = document.querySelector("#username");
      document.querySelector("#login-form").addEventListener(
        "submit", async (event) => {
        event.preventDefault();
        const response = await fetch("/api/auth/start", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({username: usernameInput.value})
        });
        const body = await response.json();
        if (!response.ok) {
          message.textContent = body.message;
          return;
        }
        verification.hidden = false;
        message.textContent = "Enter the verification code.";
        document.querySelector("#verification-code").focus();
        },
      );
      document.querySelector("#verify").addEventListener("click", async () => {
        const code = document.querySelector("#verification-code").value;
        const response = await fetch("/api/auth/verify", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({username: usernameInput.value, code})
        });
        const body = await response.json();
        if (!response.ok) {
          message.textContent = body.message;
          return;
        }
        localStorage.setItem("afg_bearer_token", body.access_token);
        window.location.href = "/account";
      });
    </script>
  </body>
</html>"""


def _account_page() -> str:
    return """<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Developer account</title></head>
  <body>
    <main><h1>Developer account</h1><p id="account-state">Loading account…</p></main>
    <script>
      const state = document.querySelector("#account-state");
      const token = localStorage.getItem("afg_bearer_token");
      fetch("/api/account", {headers: {Authorization: `Bearer ${token || ""}`}})
        .then(async (response) => {
          const body = await response.json();
          if (!response.ok) {
            state.textContent = body.message;
            return;
          }
          state.dataset.testid = "account-marker";
          state.textContent = `Signed in as ${body.username}`;
        });
    </script>
  </body>
</html>"""


def create_react_json_app(
    mode: EvaluationMode | str = EvaluationMode.SECURE,
) -> FastAPI:
    """Create an isolated two-step bearer-token evaluation application."""

    selected_mode = EvaluationMode(mode)
    state = ReactJsonApplicationState(selected_mode)
    application = FastAPI(
        title=f"AuthFlowGuard React/JSON application ({selected_mode.value})",
        version="0.1.0",
    )
    application.state.react_json = state

    @application.get("/", include_in_schema=False)
    async def index() -> HTMLResponse:
        return HTMLResponse(_login_page())

    @application.get("/login", response_class=HTMLResponse)
    async def login() -> HTMLResponse:
        return HTMLResponse(_login_page())

    @application.post("/api/auth/start")
    async def start_authentication(request: Request) -> JSONResponse:
        body = await request.json()
        username = str(body.get("username", ""))
        known = username == KNOWN_USERNAME
        state.pending_users.add(username)
        if not known and selected_mode is EvaluationMode.VULNERABLE:
            return JSONResponse(
                {"message": "No account exists for that email address."},
                status_code=401,
            )
        # The secure mode answers every email identically and rejects an
        # unknown one only at verification, with the same generic message.
        return JSONResponse({"next": "verification", "message": "Code sent."})

    @application.post("/api/auth/verify")
    async def verify_authentication(request: Request) -> JSONResponse:
        body = await request.json()
        username = str(body.get("username", ""))
        code = str(body.get("code", ""))
        known = username == KNOWN_USERNAME and username in state.pending_users
        if not known or not secrets.compare_digest(code, KNOWN_VERIFICATION_CODE):
            message = (
                "The verification code is incorrect."
                if selected_mode is EvaluationMode.VULNERABLE
                else "The email address or verification code is incorrect."
            )
            return JSONResponse({"message": message}, status_code=401)

        state.pending_users.discard(username)
        token = state.issue_token(username)
        return JSONResponse({"access_token": token, "token_type": "Bearer"})

    @application.get("/account", response_class=HTMLResponse)
    async def account() -> HTMLResponse:
        return HTMLResponse(_account_page())

    @application.get("/api/account")
    async def api_account(request: Request) -> JSONResponse:
        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        session = state.tokens.get(token) if scheme.lower() == "bearer" else None
        if session is None:
            return JSONResponse({"message": "Authentication required"}, status_code=401)
        return JSONResponse({"username": html.escape(session.username)})

    return application


secure_app = create_react_json_app(EvaluationMode.SECURE)
vulnerable_app = create_react_json_app(EvaluationMode.VULNERABLE)


def main(argv: Annotated[list[str] | None, "Command-line arguments"] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=EvaluationMode, default=EvaluationMode.SECURE)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8003)
    arguments = parser.parse_args(argv)
    uvicorn.run(
        create_react_json_app(arguments.mode),
        host=arguments.host,
        port=arguments.port,
    )


if __name__ == "__main__":
    main()

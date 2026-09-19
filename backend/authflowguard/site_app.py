"""Workshop booking desk used as an independent evaluation target."""

from __future__ import annotations

import argparse
import html
import secrets
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import parse_qs

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response


class EvaluationMode(StrEnum):
    SECURE = "secure"
    VULNERABLE = "vulnerable"


KNOWN_MEMBER_ID = "MBR-40817"
KNOWN_PASSPHRASE = "lantern-orchard-47"
SESSION_COOKIE = "desk_pass"
LOCKOUT_THRESHOLD = 3


@dataclass
class SessionState:
    member_id: str | None = None
    form_seal: str | None = None


def _shell(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>{html.escape(title)}</title></head>
  <body>
    <header>
      <strong>Riverside Workshop Desk</strong>
      <form role="search" action="/workshops">
        <label>Search workshops <input name="q" type="search"></label>
      </form>
    </header>
    <main>{body}</main>
  </body>
</html>"""


def create_site_app(
    mode: EvaluationMode | str = EvaluationMode.SECURE,
) -> FastAPI:
    selected_mode = EvaluationMode(mode)
    application = FastAPI(title=f"Workshop desk ({selected_mode.value})")
    sessions: dict[str, SessionState] = {}
    failed_logins: dict[str, int] = {}

    def session_for(request: Request) -> tuple[str, SessionState, bool]:
        session_id = request.cookies.get(SESSION_COOKIE)
        if session_id is not None and session_id in sessions:
            return session_id, sessions[session_id], False
        session_id = secrets.token_urlsafe(24)
        session = SessionState()
        sessions[session_id] = session
        return session_id, session, True

    @application.get("/", include_in_schema=False)
    async def index() -> RedirectResponse:
        return RedirectResponse("/desk/entry", status_code=303)

    @application.get("/desk/entry", response_class=HTMLResponse)
    async def entry(request: Request) -> HTMLResponse:
        session_id, session, created = session_for(request)
        session.form_seal = secrets.token_urlsafe(24)
        body = f"""
<h1>Your bookings</h1>
<form method="post" action="/desk/entry">
  <input type="hidden" name="form_seal" value="{session.form_seal}">
  <label>Member ID <input name="member_id"></label>
  <label>Passphrase <input name="passphrase" type="password"></label>
  <button type="submit">Open my bookings</button>
</form>"""
        response = HTMLResponse(_shell("Riverside Workshop Desk", body))
        if created:
            response.set_cookie(
                SESSION_COOKIE, session_id, httponly=True, samesite="lax"
            )
        return response

    @application.get("/desk/bookings", response_class=HTMLResponse)
    async def bookings(request: Request) -> HTMLResponse:
        session_id = request.cookies.get(SESSION_COOKIE)
        session = sessions.get(session_id) if session_id else None

        if session is None or session.member_id is None:
            return HTMLResponse(
                _shell("Sign-in required", "<h1>Sign in to see your bookings.</h1>"),
                status_code=401,
            )

        body = f"""
<h1>Your bookings</h1>
<p class="booking-holder" data-desk="owner">
  Booked for {html.escape(session.member_id)}
</p>
<form method="post" action="/desk/depart">
  <button type="submit">Log out of the desk</button>
</form>"""
        return HTMLResponse(_shell("Your bookings", body))

    @application.post("/desk/entry")
    async def submit_entry(request: Request) -> Response:
        session_id, session, _created = session_for(request)
        submitted = parse_qs(
            (await request.body()).decode("utf-8"), keep_blank_values=True
        )
        member_id = submitted.get("member_id", [""])[-1]
        passphrase = submitted.get("passphrase", [""])[-1]
        supplied_seal = submitted.get("form_seal", [""])[-1]

        expected_seal = session.form_seal
        session.form_seal = None
        if expected_seal is None or not secrets.compare_digest(
            expected_seal, supplied_seal
        ):
            return HTMLResponse(
                _shell("Invalid request", "<h1>That form has expired.</h1>"),
                status_code=400,
            )

        is_known = member_id == KNOWN_MEMBER_ID
        is_locked = failed_logins.get(member_id, 0) >= LOCKOUT_THRESHOLD

        if selected_mode is EvaluationMode.SECURE and is_known and is_locked:
            return HTMLResponse(
                _shell("Sign-in unavailable", "<h1>Try again later.</h1>"),
                status_code=429,
            )

        if is_known and secrets.compare_digest(passphrase, KNOWN_PASSPHRASE):
            failed_logins.pop(member_id, None)
            if selected_mode is EvaluationMode.SECURE:
                sessions.pop(session_id, None)
                new_session_id = secrets.token_urlsafe(24)
                sessions[new_session_id] = SessionState(member_id=member_id)
                response = RedirectResponse("/desk/bookings", status_code=303)
                response.set_cookie(
                    SESSION_COOKIE, new_session_id, httponly=True, samesite="lax"
                )
                return response

            session.member_id = member_id
            response = RedirectResponse("/desk/bookings", status_code=303)
            response.set_cookie(
                SESSION_COOKIE, session_id, httponly=True, samesite="lax"
            )
            return response

        if is_known:
            failed_logins[member_id] = failed_logins.get(member_id, 0) + 1

        if selected_mode is EvaluationMode.VULNERABLE and not is_known:
            message = "No member with that ID."
        elif selected_mode is EvaluationMode.VULNERABLE:
            message = "That passphrase is incorrect."
        else:
            message = "Those details don't match our records."
        return HTMLResponse(
            _shell("Sign-in failed", f"<h1>{message}</h1>"),
            status_code=401,
        )

    @application.post("/desk/depart")
    async def depart(request: Request) -> RedirectResponse:
        session_id = request.cookies.get(SESSION_COOKIE)
        response = RedirectResponse("/desk/entry", status_code=303)
        if selected_mode is EvaluationMode.SECURE:
            if session_id:
                sessions.pop(session_id, None)
            response.delete_cookie(SESSION_COOKIE)
        return response

    return application


secure_app = create_site_app(EvaluationMode.SECURE)
vulnerable_app = create_site_app(EvaluationMode.VULNERABLE)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=EvaluationMode, default=EvaluationMode.SECURE)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8005)
    arguments = parser.parse_args(argv)
    uvicorn.run(
        create_site_app(arguments.mode),
        host=arguments.host,
        port=arguments.port,
    )


if __name__ == "__main__":
    main()

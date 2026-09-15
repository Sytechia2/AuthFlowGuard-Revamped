"""Workshop booking desk used as an independent evaluation target."""

from __future__ import annotations

import argparse
import html
import secrets
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
    sessions: dict[str, str] = {}

    @application.get("/", include_in_schema=False)
    async def index() -> RedirectResponse:
        return RedirectResponse("/desk/entry", status_code=303)

    @application.get("/desk/entry", response_class=HTMLResponse)
    async def entry() -> HTMLResponse:
        body = """
<h1>Your bookings</h1>
<form method="post" action="/desk/entry">
  <label>Member ID <input name="member_id"></label>
  <label>Passphrase <input name="passphrase" type="password"></label>
  <button type="submit">Open my bookings</button>
</form>
<p>
  <a href="/desk/join">Become a member</a>
  <a href="/desk/lost-passphrase">Forgotten passphrase?</a>
</p>"""
        return HTMLResponse(_shell("Riverside Workshop Desk", body))

    @application.post("/desk/entry")
    async def submit_entry(request: Request) -> Response:
        submitted = parse_qs(
            (await request.body()).decode("utf-8"), keep_blank_values=True
        )
        member_id = submitted.get("member_id", [""])[-1]
        passphrase = submitted.get("passphrase", [""])[-1]

        if member_id == KNOWN_MEMBER_ID and secrets.compare_digest(
            passphrase, KNOWN_PASSPHRASE
        ):
            session_id = secrets.token_urlsafe(24)
            sessions[session_id] = member_id
            response = RedirectResponse("/desk/bookings", status_code=303)
            response.set_cookie(
                SESSION_COOKIE, session_id, httponly=True, samesite="lax"
            )
            return response

        return HTMLResponse(
            _shell("Sign-in failed", "<h1>Those details don't match our records.</h1>"),
            status_code=401,
        )

    @application.get("/desk/bookings", response_class=HTMLResponse)
    async def bookings(request: Request) -> HTMLResponse:
        session_id = request.cookies.get(SESSION_COOKIE)
        member_id = sessions.get(session_id) if session_id else None

        if member_id is None:
            return HTMLResponse(
                _shell("Sign-in required", "<h1>Sign in to see your bookings.</h1>"),
                status_code=401,
            )

        body = f"""
<h1>Your bookings</h1>
<p class="booking-holder" data-desk="owner">Booked for {html.escape(member_id)}</p>"""
        return HTMLResponse(_shell("Your bookings", body))

    return application


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

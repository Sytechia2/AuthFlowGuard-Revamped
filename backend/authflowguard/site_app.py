"""Workshop booking desk used as an independent evaluation target."""

from __future__ import annotations

import argparse
import html
from enum import StrEnum

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse


class EvaluationMode(StrEnum):
    SECURE = "secure"
    VULNERABLE = "vulnerable"


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

"""Generate AuthFlowGuard UI mockups with Gemini image models on Vertex AI.

This is a design aid for the team. It is not part of the AuthFlowGuard product,
and nothing under ``backend/`` imports it.

Each request sends Gemini the design system in ``DESIGN.md``, the change you
describe, and optionally screenshots of the current interface. It saves the
returned images under ``tools/ui_mockups/output/``.

Examples (from the repository root, with the interface running on :5173)::

    .venv\\Scripts\\python tools\\ui_mockups\\generate_mockup.py --screen results \\
        --scan-id 35605eb8-2a6e-4ffc-952a-0fe6c79974cd \\
        "Show each check as a row with a coloured status badge and a summary strip"

    .venv\\Scripts\\python tools\\ui_mockups\\generate_mockup.py --dry-run \\
        --image sketch.png "Turn this sketch into a Setup screen"
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DESIGN_FILE = REPO_ROOT / "DESIGN.md"
OUTPUT_DIR = Path(__file__).resolve().parent / "output"

DEFAULT_MODEL = "gemini-3-pro-image"
DEFAULT_LOCATION = "global"
INTERFACE_URL = "http://127.0.0.1:5173"
SCREENS = {
    "setup": "Setup",
    "discovery": "Discovery",
    "testing": "Testing",
    "results": "Results",
}
MAX_COUNT = 4

BRIEF = """\
You are a senior product designer producing a high-fidelity desktop UI mockup
for AuthFlowGuard, a local tool that tests how websites implement login and
sessions. Render one flat, front-on screenshot of the web application at
1440px wide: no device frame, no perspective, no hands, no decorative
background.

Rules:
- Follow the design system below exactly: its colours, Inter typography,
  radii, spacing and do/don't lists.
- When screenshots of the current interface are attached, keep their layout,
  navigation, labels and data unless the requested change says otherwise.
  Change only what the request asks for.
- Use real, readable text. Keep the existing check names, OWASP references
  (for example WSTG-IDNT-04) and status wording; never use lorem ipsum.
- Never show a password, token or secret value; masked fields only.
- Status colour must always be paired with a text label.

Design system (DESIGN.md):
{design}

Requested change:
{request}
"""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate AuthFlowGuard UI mockups with Gemini on Vertex AI."
    )
    parser.add_argument(
        "request",
        nargs="?",
        default="",
        help="What the mockup should show or change. Not needed with --prompt-file.",
    )
    parser.add_argument(
        "--prompt-file",
        type=Path,
        help="Send this file as the whole prompt instead of the built-in brief "
        "plus DESIGN.md (for example when designing a replacement look).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        help="Write into this folder instead of a new one under output/.",
    )
    parser.add_argument(
        "--name", default="mockup", help="File name stem for generated images."
    )
    parser.add_argument(
        "--screen",
        action="append",
        choices=sorted(SCREENS),
        default=[],
        help="Capture this screen from the running interface and attach it. "
        "Repeatable.",
    )
    parser.add_argument(
        "--scan-id",
        help="With --screen results, load this saved scan before capturing.",
    )
    parser.add_argument(
        "--image",
        action="append",
        type=Path,
        default=[],
        help="Attach an existing screenshot or sketch. Repeatable.",
    )
    parser.add_argument("--count", type=int, default=1, help="Variations (1-4).")
    parser.add_argument("--aspect", default="16:9", help="Aspect ratio, e.g. 16:9.")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--location", default=DEFAULT_LOCATION)
    parser.add_argument(
        "--project",
        help="Google Cloud project. Defaults to GOOGLE_CLOUD_PROJECT or the "
        "active gcloud project.",
    )
    parser.add_argument("--interface-url", default=INTERFACE_URL)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Capture screens and print the request without calling Vertex AI.",
    )
    args = parser.parse_args(argv)
    if not args.request and not args.prompt_file:
        parser.error("give a request or --prompt-file")
    if args.prompt_file and not args.prompt_file.is_file():
        parser.error(f"prompt file not found: {args.prompt_file}")
    if not 1 <= args.count <= MAX_COUNT:
        parser.error(f"--count must be between 1 and {MAX_COUNT}")
    if args.scan_id and "results" not in args.screen:
        parser.error("--scan-id needs --screen results")
    for image in args.image:
        if not image.is_file():
            parser.error(f"image not found: {image}")
    return args


def resolve_project(explicit: str | None) -> str:
    if explicit:
        return explicit
    if project := os.environ.get("GOOGLE_CLOUD_PROJECT"):
        return project
    gcloud = shutil.which("gcloud") or shutil.which("gcloud.cmd")
    if gcloud:
        result = subprocess.run(
            [gcloud, "config", "get-value", "project"],
            capture_output=True,
            text=True,
            check=False,
        )
        if project := result.stdout.strip():
            return project
    raise SystemExit(
        "No Google Cloud project found. Pass --project, set GOOGLE_CLOUD_PROJECT, "
        "or run: gcloud config set project <id>"
    )


def capture_screens(
    screens: list[str], scan_id: str | None, interface_url: str, run_dir: Path
) -> list[Path]:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    captured: list[Path] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        try:
            page.goto(interface_url, wait_until="networkidle")
        except PlaywrightError as error:
            browser.close()
            raise SystemExit(
                f"Could not open the interface at {interface_url}. Start it with "
                "'cd frontend; npm.cmd run dev'."
            ) from error
        for screen in screens:
            page.get_by_role("button", name=SCREENS[screen]).first.click()
            page.wait_for_timeout(600)
            if screen == "results" and scan_id:
                page.get_by_label("Scan ID").fill(scan_id)
                page.get_by_role("button", name="Load results").click()
                page.wait_for_timeout(1500)
            path = run_dir / f"current-{screen}.png"
            page.screenshot(path=str(path), full_page=True)
            captured.append(path)
            print(f"Captured {screen}: {path}")
        browser.close()
    return captured


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:40] or "mockup"


def generate(args: argparse.Namespace) -> int:
    label = args.request or args.prompt_file.stem
    run_dir = args.out_dir or OUTPUT_DIR / (
        datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + slugify(label)
    )
    run_dir.mkdir(parents=True, exist_ok=True)

    attachments = list(args.image)
    if args.screen:
        attachments += capture_screens(
            args.screen, args.scan_id, args.interface_url, run_dir
        )

    if args.prompt_file:
        prompt = args.prompt_file.read_text(encoding="utf-8")
    else:
        prompt = BRIEF.format(
            design=DESIGN_FILE.read_text(encoding="utf-8"), request=args.request
        )
    (run_dir / f"{args.name}-prompt.txt").write_text(prompt, encoding="utf-8")
    print(f"Attachments: {[str(path) for path in attachments] or 'none'}")
    print(f"Model: {args.model} ({args.location}), variations: {args.count}")

    if args.dry_run:
        print(f"Dry run: nothing sent. Prompt saved in {run_dir}")
        return 0

    from google import genai
    from google.genai import types

    client = genai.Client(
        vertexai=True, project=resolve_project(args.project), location=args.location
    )
    contents: list[types.Part | str] = [prompt]
    for path in attachments:
        mime_type = mimetypes.guess_type(path.name)[0] or "image/png"
        contents.append(
            types.Part.from_bytes(data=path.read_bytes(), mime_type=mime_type)
        )
    config = types.GenerateContentConfig(
        response_modalities=["TEXT", "IMAGE"],
        image_config=types.ImageConfig(aspect_ratio=args.aspect),
    )

    saved = 0
    usage_log = []
    for variation in range(1, args.count + 1):
        response = client.models.generate_content(
            model=args.model, contents=contents, config=config
        )
        usage = response.usage_metadata
        usage_log.append(usage.model_dump(exclude_none=True) if usage else {})
        notes = []
        for part in response.parts or []:
            if part.inline_data and part.inline_data.data:
                extension = mimetypes.guess_extension(
                    part.inline_data.mime_type or "image/png"
                )
                saved += 1
                stem = args.name if args.count == 1 else f"{args.name}-{variation}"
                if saved > variation:
                    stem += f"-{saved}"
                path = run_dir / f"{stem}{extension or '.png'}"
                path.write_bytes(part.inline_data.data)
                # Prompt sidecar: Impeccable's comp round records approval here.
                path.with_name(path.name + ".json").write_text(
                    json.dumps(
                        {
                            "prompt": prompt,
                            "model": args.model,
                            "location": args.location,
                            "references": [str(ref) for ref in attachments],
                            "approved": False,
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
                print(f"Saved {path}")
            elif part.text:
                notes.append(part.text)
        if notes:
            (run_dir / f"{args.name}-notes-{variation}.txt").write_text(
                "\n".join(notes), encoding="utf-8"
            )

    (run_dir / f"{args.name}-request.json").write_text(
        json.dumps(
            {
                "request": args.request or str(args.prompt_file),
                "model": args.model,
                "location": args.location,
                "attachments": [str(path) for path in attachments],
                "usage": usage_log,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    if saved == 0:
        print("The model returned no image. See notes-*.txt in", run_dir)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    return generate(parse_args(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    raise SystemExit(main())

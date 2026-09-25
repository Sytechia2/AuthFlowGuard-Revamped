"""Bedrock prices and token estimates used by cost measurement.

Prices for models that scans already use come from ``authflowguard.bedrock``,
which stays the single source of truth for them. This module adds the vision
models used for automated form-field detection, and records where every price
came from. Published prices change, so a measurement claim has to state the
price basis it used and allow that basis to be replaced without editing code.
"""

import json
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from authflowguard.bedrock import MODEL_PRICES_USD_PER_1000_TOKENS

USD_PLACES = Decimal("0.00000001")

PRODUCTION_PRICE_SOURCE = (
    "authflowguard.bedrock.MODEL_PRICES_USD_PER_1000_TOKENS (in-repo)"
)
VISION_PRICE_SOURCE = (
    "AWS Bedrock on-demand list price, recorded 2026-09-20; reconfirm against "
    "the published Bedrock pricing page before quoting a cost claim"
)

# Models in the production table that accept image input.
VISION_CAPABLE_PRODUCTION_MODELS = frozenset({"amazon.nova-lite-v1:0"})


class UnknownModelPriceError(KeyError):
    """Raised when a cost is requested for a model with no configured price."""


class PriceBookError(ValueError):
    """Raised when an external price book cannot be used as written."""


@dataclass(frozen=True)
class ModelPrice:
    """The per-token price of one model, with the origin of those numbers."""

    input_usd_per_1000_tokens: Decimal
    output_usd_per_1000_tokens: Decimal
    supports_vision: bool
    price_source: str


def _prices_from_production_table() -> dict[str, ModelPrice]:
    """Reuse the prices that live Bedrock requests are already charged at."""

    prices: dict[str, ModelPrice] = {}
    for model_id, price_pair in MODEL_PRICES_USD_PER_1000_TOKENS.items():
        input_price, output_price = price_pair
        prices[model_id] = ModelPrice(
            input_usd_per_1000_tokens=Decimal(str(input_price)),
            output_usd_per_1000_tokens=Decimal(str(output_price)),
            supports_vision=model_id in VISION_CAPABLE_PRODUCTION_MODELS,
            price_source=PRODUCTION_PRICE_SOURCE,
        )
    return prices


# Vision models that scans do not use yet. These stay separate from the
# production table so that pricing a model for measurement cannot widen what
# BedrockConfiguration accepts as a scan model.
ADDITIONAL_VISION_PRICES: dict[str, ModelPrice] = {
    "amazon.nova-pro-v1:0": ModelPrice(
        input_usd_per_1000_tokens=Decimal("0.0008"),
        output_usd_per_1000_tokens=Decimal("0.0032"),
        supports_vision=True,
        price_source=VISION_PRICE_SOURCE,
    ),
}


def _build_default_price_book() -> dict[str, ModelPrice]:
    prices = _prices_from_production_table()
    for model_id, price in ADDITIONAL_VISION_PRICES.items():
        if model_id in prices:
            raise PriceBookError(
                f"{model_id} is priced in both the production table and the "
                "vision additions. Remove the duplicate so that one source "
                "stays authoritative."
            )
        prices[model_id] = price
    return prices


DEFAULT_PRICE_BOOK: dict[str, ModelPrice] = _build_default_price_book()


def price_for(
    model_id: str,
    price_book: dict[str, ModelPrice] | None = None,
) -> ModelPrice:
    """Return the price of one model, or explain that it has none."""

    prices = DEFAULT_PRICE_BOOK if price_book is None else price_book
    try:
        return prices[model_id]
    except KeyError as error:
        known_models = ", ".join(sorted(prices)) or "none"
        raise UnknownModelPriceError(
            f"No configured price for {model_id}. Priced models: "
            f"{known_models}. Supply a price book to measure another model."
        ) from error


def cost_usd(
    model_id: str,
    input_tokens: int,
    output_tokens: int,
    price_book: dict[str, ModelPrice] | None = None,
) -> Decimal:
    """Return the cost of one priced request, to eight decimal places.

    Token counts are integers and are therefore exact. Money is derived from
    them in decimal arithmetic so that a total does not drift as entries are
    added, which binary floating point would allow.
    """

    if input_tokens < 0 or output_tokens < 0:
        raise ValueError("Token counts cannot be negative")

    price = price_for(model_id, price_book)
    total = (
        Decimal(input_tokens) / 1000 * price.input_usd_per_1000_tokens
        + Decimal(output_tokens) / 1000 * price.output_usd_per_1000_tokens
    )
    return total.quantize(USD_PLACES, rounding=ROUND_HALF_UP)


REQUIRED_PRICE_BOOK_FIELDS = frozenset(
    {
        "input_usd_per_1000_tokens",
        "output_usd_per_1000_tokens",
        "price_source",
    }
)


def load_price_book(path: Path) -> dict[str, ModelPrice]:
    """Read a price book supplied by the person running a measurement.

    The file records the prices in force on the day of the run, so that a
    published cost table is not silently tied to prices compiled into the code
    months earlier.
    """

    try:
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise PriceBookError(f"{path} is not valid JSON: {error}") from error

    if not isinstance(raw, dict) or not raw:
        raise PriceBookError(f"{path} must contain a non-empty object of models")

    prices: dict[str, ModelPrice] = {}
    for model_id, entry in raw.items():
        prices[model_id] = _read_price_entry(path, model_id, entry)
    return prices


def _read_price_entry(path: Path, model_id: str, entry: Any) -> ModelPrice:
    if not isinstance(entry, dict):
        raise PriceBookError(f"{path}: {model_id} must be an object")

    missing_fields = REQUIRED_PRICE_BOOK_FIELDS - set(entry)
    if missing_fields:
        missing_names = ", ".join(sorted(missing_fields))
        raise PriceBookError(f"{path}: {model_id} is missing {missing_names}")

    try:
        input_price = Decimal(str(entry["input_usd_per_1000_tokens"]))
        output_price = Decimal(str(entry["output_usd_per_1000_tokens"]))
    except InvalidOperation as error:
        raise PriceBookError(
            f"{path}: {model_id} has a price that is not a number"
        ) from error

    if input_price < 0 or output_price < 0:
        raise PriceBookError(f"{path}: {model_id} has a negative price")

    return ModelPrice(
        input_usd_per_1000_tokens=input_price,
        output_usd_per_1000_tokens=output_price,
        supports_vision=bool(entry.get("supports_vision", False)),
        price_source=str(entry["price_source"]),
    )


@dataclass(frozen=True)
class ImageTokenPolicy:
    """How many input tokens one screenshot is assumed to cost.

    This is used only to reserve cost before a request. Recorded cost always
    uses the token counts the model actually reported, so an uncalibrated
    policy cannot corrupt a measured total. The policy stays flagged as
    uncalibrated until it has been derived from observed usage, because a
    guessed value must not be presented as a measurement.
    """

    tokens_per_image: int
    calibrated: bool
    note: str

    @classmethod
    def uncalibrated(cls, tokens_per_image: int = 1500) -> "ImageTokenPolicy":
        return cls(
            tokens_per_image=tokens_per_image,
            calibrated=False,
            note=(
                "Placeholder used only to reserve cost before a request. Run "
                "calibrate_image_tokens against observed usage before quoting "
                "an image cost."
            ),
        )

    def estimate_image_tokens(self, image_count: int) -> int:
        if image_count < 0:
            raise ValueError("Image count cannot be negative")
        return self.tokens_per_image * image_count


def calibrate_image_tokens(
    *,
    text_only_input_tokens: int,
    with_image_input_tokens: int,
    image_count: int,
) -> ImageTokenPolicy:
    """Derive tokens-per-image by differencing two observed token counts.

    Send one request without a screenshot and an otherwise identical request
    with one, then pass both reported input-token counts here. The result is
    measured rather than assumed, which is what a published image cost has to
    rest on.
    """

    if image_count <= 0:
        raise ValueError("Calibration needs at least one image")

    difference = with_image_input_tokens - text_only_input_tokens
    if difference <= 0:
        raise ValueError(
            "The request carrying images did not report more input tokens, so "
            "tokens per image cannot be derived from these observations"
        )

    return ImageTokenPolicy(
        tokens_per_image=difference // image_count,
        calibrated=True,
        note=(
            f"Derived from observed usage: {with_image_input_tokens} minus "
            f"{text_only_input_tokens} input tokens over {image_count} image(s)"
        ),
    )

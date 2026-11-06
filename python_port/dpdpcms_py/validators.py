from __future__ import annotations

import json
from functools import lru_cache

from jsonschema import Draft7Validator

from .config import VALIDATOR_ROOT


@lru_cache(maxsize=256)
def _validator(func: str) -> Draft7Validator | None:
    path = VALIDATOR_ROOT / f"{func}.jschema"
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as handle:
        return Draft7Validator(json.load(handle))


def validate_payload(payload: dict) -> list[str]:
    func = str(payload.get("_func") or "").strip().lower()
    if not func:
        return ["_func missing"]
    # P4-02: function names map to lower-case schema files; reject anything that
    # is not a plain identifier so it can never escape VALIDATOR_ROOT.
    if not func.replace("_", "").isalnum() or not func.isascii():
        return [f"Unsupported function: {func}"]
    validator = _validator(func)
    if validator is None:
        # Fail closed: a function without a schema is never dispatched unvalidated.
        return [f"Unsupported function: {func}"]
    return [error.message for error in validator.iter_errors(payload)]

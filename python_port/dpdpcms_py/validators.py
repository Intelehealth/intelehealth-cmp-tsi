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
    func = payload.get("_func")
    if not func:
        return ["_func missing"]
    validator = _validator(str(func))
    if validator is None:
        return []
    return [error.message for error in validator.iter_errors(payload)]

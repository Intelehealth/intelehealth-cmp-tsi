"""The curl examples in the developer portal guides (portal/docs/*.md) are
requests the server would accept: a real function in the right category, and a
body that passes that function's validator schema."""

import json
import re
from pathlib import Path

import pytest
from dpdpcms_py import main
from dpdpcms_py.validators import validate_payload

GUIDES = Path(__file__).resolve().parents[2] / "portal" / "docs"
CURL = re.compile(
    r"curl -X POST https://[^/\s]+/api/v1/(?P<category>\w+)/(?P<service>\w+)/(?P<func>\w+)"
    r"(?P<rest>.*?)-d '(?P<body>.*?)'\s*\n```",
    re.S,
)


def _examples():
    for guide in sorted(GUIDES.glob("*.md")):
        for match in CURL.finditer(guide.read_text(encoding="utf-8")):
            yield pytest.param(guide.name, match, id=f"{guide.stem}:{match['func']}")


@pytest.mark.parametrize(("guide", "match"), list(_examples()))
def test_guide_example_is_a_request_the_server_accepts(guide, match):
    category, func = match["category"], match["func"]
    allowed = main.CLIENT_ALLOWED_FUNCS if category == "client" else main.PUBLIC_ALLOWED_FUNCS
    assert category in {"client", "public"}, f"{guide}: guides document the integrator API only"
    assert func in allowed, f"{guide}: {func} is not callable under /api/v1/{category}/"
    assert hasattr(main.SERVICE_REGISTRY[match["service"]], func), f"{guide}: {match['service']} has no {func}"

    payload = json.loads(match["body"])
    payload["_func"] = func
    if category == "client":
        # authenticate() binds these from the credential before validation.
        payload.setdefault("fiduciary_id", "fiduciary-from-credential")
        if "Authorization: Bearer" in match["rest"]:
            payload.setdefault("user_id", "principal-from-token")
    assert validate_payload(payload) == [], f"{guide}: the {func} example fails its schema"


def test_the_guides_have_examples_to_check():
    assert len(list(_examples())) >= 10

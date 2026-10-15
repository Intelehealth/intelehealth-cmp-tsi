"""P13-05: software composition check for the scripts vendored in web/vendor/.

pip-audit covers requirements.lock only. This covers the browser side:

  * every file in web/vendor/*.js is in vendor_manifest.json and matches its
    recorded SHA-256 (nothing swapped or added unaudited);
  * each library version is queried against OSV.dev, and the build fails on any
    advisory not listed under 'accepted' for that library;
  * an accepted advisory whose review_by date has passed fails the build, so an
    acceptance is a dated review, not a permanent waiver.

Usage: python scripts/supply_chain/vendor_audit.py [--offline]
--offline skips the OSV query (hashes and review dates are still checked).
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VENDOR = REPO / "web" / "vendor"
MANIFEST = Path(__file__).with_name("vendor_manifest.json")
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"


def load_manifest() -> list[dict]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))["libraries"]


def check_files(libraries: list[dict]) -> list[str]:
    errors = []
    listed = {lib["file"] for lib in libraries}
    for path in sorted(VENDOR.glob("*.js")):
        if path.name not in listed:
            errors.append(f"{path.name}: vendored but not in vendor_manifest.json")
    for lib in libraries:
        path = VENDOR / lib["file"]
        if not path.is_file():
            errors.append(f"{lib['file']}: listed in the manifest but missing from web/vendor/")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != lib["sha256"]:
            errors.append(f"{lib['file']}: SHA-256 {digest} does not match the manifest")
    return errors


def check_review_dates(libraries: list[dict], today: date) -> list[str]:
    errors = []
    for lib in libraries:
        for accepted in lib.get("accepted", []):
            if not accepted.get("reason"):
                errors.append(f"{lib['package']} {accepted['id']}: accepted without a reason")
            if date.fromisoformat(accepted["review_by"]) < today:
                errors.append(
                    f"{lib['package']} {accepted['id']}: acceptance expired on {accepted['review_by']}; re-review it"
                )
    return errors


def _post(url: str, body: dict) -> dict:
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed https URL
        return json.load(response)


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - fixed https URL
        return json.load(response)


def check_advisories(libraries: list[dict]) -> list[str]:
    queries = [
        {"package": {"name": lib["package"], "ecosystem": lib["ecosystem"]}, "version": lib["version"]}
        for lib in libraries
    ]
    results = _post(OSV_BATCH, {"queries": queries})["results"]
    errors = []
    for lib, result in zip(libraries, results, strict=True):
        accepted = set()
        for entry in lib.get("accepted", []):
            accepted.add(entry["id"])
            accepted.update(entry.get("aliases", []))
        for vuln in result.get("vulns", []):
            ids = {vuln["id"], *_get(OSV_VULN + vuln["id"]).get("aliases", [])}
            if not ids & accepted:
                errors.append(f"{lib['package']} {lib['version']}: unreviewed advisory {vuln['id']}")
    return errors


def main(argv: list[str]) -> int:
    libraries = load_manifest()
    errors = check_files(libraries) + check_review_dates(libraries, date.today())
    if "--offline" not in argv:
        errors += check_advisories(libraries)
    for error in errors:
        print(f"vendor-audit: {error}", file=sys.stderr)
    if not errors:
        print(f"vendor-audit: {len(libraries)} vendored libraries verified")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

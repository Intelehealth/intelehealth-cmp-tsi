from __future__ import annotations

import ipaddress
import json
import logging
import socket
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger("dpdpcms.net")

# RFC 1918 / 4193 / 3927 / restricted ranges — a webhook or gateway URL that
# resolves to any of these is almost certainly an SSRF probe.
_PRIVATE_NETS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)


def _is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETS)


def resolve_public(host: str) -> str:
    """Resolve a hostname and return an address that is safe to connect to.

    Raises ValueError when the hostname resolves only to loopback / private /
    link-local addresses, or when the host is itself a literal such an address.
    """
    if _is_private(host):
        raise ValueError(f"refused: address is not public ({host})")
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"refused: cannot resolve host {host!r}") from exc
    addresses = sorted({info[4][0] for info in infos})
    public = [addr for addr in addresses if not _is_private(addr)]
    if not public:
        raise ValueError(f"refused: {host!r} resolves only to private/loopback addresses")
    return public[0]


def validate_outbound_url(url: str, label: str = "URL") -> str:
    """SSRF guard shared by the webhook and delivery-gateway paths.

    Requires http(s), a non-embedded host, and a public (non-private, non-
    loopback, non-link-local) resolved destination. Returns the validated URL.
    """
    if not url or not isinstance(url, str):
        raise ValueError(f"{label} is required.")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"{label} must use http or https.")
    if not parsed.hostname:
        raise ValueError(f"{label} has no host.")
    if parsed.username or parsed.password:
        raise ValueError(f"{label} must not embed credentials.")
    resolve_public(parsed.hostname.lower().rstrip("."))
    return url


def post_json(
    url: str,
    payload: Any,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
) -> tuple[int | None, str]:
    """SSRF-guarded HTTP POST of a JSON body. Returns (status_code, body)."""
    validate_outbound_url(url, "URL")
    data = json.dumps(payload, default=str).encode("utf-8")
    if headers is None:
        headers = {}
    headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            return int(response.status), body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return int(exc.code), body
    except Exception as exc:  # socket/timeout/URLError — no usable response
        log.warning("Outbound POST to %s failed: %s", url, exc)
        return None, str(exc)

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import socket
import ssl
from typing import Any
from urllib.parse import ParseResult, urlparse

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


def _validated_target(url: str, label: str) -> tuple[ParseResult, str]:
    """Parse and SSRF-check `url`; returns (parsed URL, the public IP it resolved to)."""
    if not url or not isinstance(url, str):
        raise ValueError(f"{label} is required.")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"{label} must use http or https.")
    if not parsed.hostname:
        raise ValueError(f"{label} has no host.")
    if parsed.username or parsed.password:
        raise ValueError(f"{label} must not embed credentials.")
    return parsed, resolve_public(parsed.hostname.lower().rstrip("."))


def validate_outbound_url(url: str, label: str = "URL") -> str:
    """SSRF guard shared by the webhook and delivery-gateway paths.

    Requires http(s), a non-embedded host, and a public (non-private, non-
    loopback, non-link-local) resolved destination. Returns the validated URL.
    """
    _validated_target(url, label)
    return url


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to a pre-validated IP while keeping the URL's host for the Host header."""

    def __init__(self, host: str, pinned_ip: str, **kwargs: Any) -> None:
        super().__init__(host, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """As above, with TLS SNI and certificate checks against the URL's hostname."""

    def __init__(self, host: str, pinned_ip: str, **kwargs: Any) -> None:
        super().__init__(host, context=ssl.create_default_context(), **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def post_json(
    url: str,
    payload: Any,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
) -> tuple[int | None, str]:
    """SSRF-guarded HTTP POST of a JSON body. Returns (status_code, body).

    The connection goes to the exact address that passed validation, so a DNS
    answer that changes between the check and the connect (rebinding) cannot
    redirect it. Redirects are never followed: a 3xx could point anywhere,
    including a metadata endpoint, so it is reported as a failed delivery.
    """
    parsed, pinned_ip = _validated_target(url, "URL")
    data = json.dumps(payload, default=str).encode("utf-8")
    headers = dict(headers or {})
    headers.setdefault("Content-Type", "application/json")
    connection_cls = _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
    conn = connection_cls(parsed.hostname, pinned_ip, port=parsed.port, timeout=timeout)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    try:
        conn.request("POST", path, body=data, headers=headers)
        response = conn.getresponse()
        body = response.read().decode("utf-8", errors="replace")
        if 300 <= response.status < 400:
            return None, f"refused: redirect ({response.status}) to {response.getheader('Location')!r} not followed"
        return int(response.status), body
    except Exception as exc:  # socket/timeout/TLS — no usable response
        log.warning("Outbound POST to %s failed: %s", url, exc)
        return None, str(exc)
    finally:
        conn.close()

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote_plus, urlparse

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - optional at import time
    load_dotenv = None


ROOT = Path(__file__).resolve().parents[2]
PY_ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = ROOT / "web"
VALIDATOR_ROOT = WEB_ROOT / "WEB-INF" / "validator"


if load_dotenv:
    load_dotenv(ROOT / ".env")
    load_dotenv(PY_ROOT / ".env", override=True)


def _secret(name: str, minimum: int = 32) -> str:
    value = (os.getenv(name) or "").strip()
    if len(value) < minimum or value.startswith("<") or "change-me" in value.lower():
        raise RuntimeError(
            f"{name} must be set to a random value of at least {minimum} characters. "
            "Copy .env.example to .env and generate secrets with: openssl rand -hex 32"
        )
    return value


ENVIRONMENTS = ("local", "test", "staging", "production")


def _environment() -> str:
    """P14-01: TSI_DPDP_CMS_ENV is one of a fixed set, case-folded.

    Every environment-gated control (the production '*' refusal, /docs, sslmode,
    DUMMY_OTP) compares against these exact names, so a free-text value such as
    'Production' or 'prod' would slip past them. Anything else refuses to start.
    """
    value = (os.getenv("TSI_DPDP_CMS_ENV") or "local").strip().casefold()
    if value not in ENVIRONMENTS:
        raise RuntimeError(f"TSI_DPDP_CMS_ENV must be one of {', '.join(ENVIRONMENTS)}; got {value!r}.")
    return value


def _outbound_allowed_hosts(environment: str) -> tuple[str, ...]:
    """Rule 14 / P12-11: an unset allowlist fails closed outside local."""
    hosts = tuple(
        h.strip().lower().rstrip(".") for h in os.getenv("OUTBOUND_ALLOWED_HOSTS", "").split(",") if h.strip()
    )
    if not hosts and environment != "local":
        raise RuntimeError(
            "OUTBOUND_ALLOWED_HOSTS must list the approved outbound destinations (Rule 14) outside "
            "TSI_DPDP_CMS_ENV=local. Set it to '*' to leave destinations unrestricted deliberately."
        )
    # R14 (workbook v11): in production the allowlist must name the approved
    # destinations; the '*' opt-out is for local, test and staging only.
    if "*" in hosts and environment == "production":
        raise RuntimeError(
            "OUTBOUND_ALLOWED_HOSTS='*' is refused with TSI_DPDP_CMS_ENV=production: list the approved "
            "destinations (docs/security/OUTBOUND_DESTINATIONS.md)."
        )
    return hosts


@dataclass(frozen=True)
class Settings:
    db_dsn: str
    db_encryption_key: str
    jwt_secret: str
    lookup_salt: str
    allowed_origins: tuple[str, ...]
    brand_name: str
    environment: str
    export_path: Path
    bootstrap_token: str
    token_ttl_minutes: int = 480
    # ── P1 background worker (worker.py) ────────────────────────────────────
    worker_poll_seconds: int = 30
    worker_batch_size: int = 50
    # ── P1 notification delivery adapter (delivery.py) ──────────────────────
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True
    sms_gateway_url: str = ""
    push_gateway_url: str = ""
    notification_retry_limit: int = 5
    # ── P1 webhook dispatcher (webhooks.py) ─────────────────────────────────
    webhook_retry_limit: int = 5
    # ── P1 worker sweep thresholds ──────────────────────────────────────────
    alert_escalation_hours: int = 24
    purge_notice_hours: int = 48  # DPDP Rule 8(2): 48h notice before deletion
    grievance_escalation_hours: int = 24  # beyond the SLA due_date
    # Rights-portal DUMMY_OTP mode accepts a fixed code, i.e. no authentication.
    # Off unless TSI_DPDP_CMS_ENV=local or ALLOW_DUMMY_OTP=true.
    allow_dummy_otp: bool = False
    # SA-09: days a purge may stay unconfirmed before the DPO is told.
    purge_completion_sla_days: int = 30
    # CC-05: DigiLocker partner verifier for guardian identity (empty = not configured).
    digilocker_verify_url: str = ""
    # SA-06: OpenID Connect SSO for operators (all three empty = SSO disabled).
    sso_issuer: str = ""
    sso_audience: str = ""
    sso_jwks_url: str = ""
    # GR-04: grievance attachment limits.
    attachment_max_bytes: int = 5 * 1024 * 1024
    # P5-07: Rule 6(1)(e) log-retention floor for webhook_deliveries (the
    # channel of record for consent events and OTP dispatch), in days.
    webhook_delivery_retention_days: int = 365
    # SA-13: the same floor-bounded retention for notification_deliveries
    # (recipient address / device + delivery outcome).
    notification_delivery_retention_days: int = 365
    # Years of audit_logs kept in the live partitioned table (current year
    # included); older yearly partitions are detached into archive tables by
    # jobs.archive_audit_partitions, never deleted. Minimum 1.
    audit_live_years: int = 3
    # SA-14: key that signs evidence certificates. Defaults to the DB encryption
    # key so nothing new needs provisioning; a deployment may set its own
    # CERTIFICATE_SIGNING_KEY (still a server secret, never a client one).
    certificate_signing_key: str = ""
    # P5-02: IPs of reverse proxies in front of the API. X-Forwarded-For is only
    # honoured when the immediate peer is one of these, so a direct caller cannot
    # self-declare its identity and every operator behind the proxy no longer
    # shares one throttle bucket. Empty = no proxy, the socket peer is trusted.
    trusted_proxy_ips: tuple[str, ...] = ()
    # Rule 14: the destinations personal data may be sent to. When set, every
    # outbound webhook, SMS/push gateway and verifier URL - and the SMTP host -
    # must be one of these hosts or a subdomain of one (".gov.in", "example.in").
    # P12-11: outside TSI_DPDP_CMS_ENV=local the list is mandatory - the app
    # refuses to start without it. "*" is the explicit, logged choice to leave
    # destinations unrestricted. Production deployments should list the
    # in-India endpoints recorded in docs/security/OUTBOUND_DESTINATIONS.md.
    outbound_allowed_hosts: tuple[str, ...] = ()
    # P12-09: /healthz and /healthz/worker report a status only. A request
    # carrying this token in X-Health-Token also gets the detail (age, failed
    # sweeps). Empty = detail never served.
    healthz_token: str = ""

    @staticmethod
    def _dsn_from_env() -> str:
        if os.getenv("DATABASE_URL"):
            return os.environ["DATABASE_URL"]

        raw_host = os.getenv("POSTGRES_HOST", "postgresql://localhost:5432")
        host_part = raw_host.replace("jdbc:", "", 1) if raw_host.startswith("jdbc:") else raw_host
        if not host_part.startswith("postgresql://"):
            host_part = "postgresql://" + host_part.strip("/")

        parsed = urlparse(host_part)
        host = parsed.hostname or "localhost"
        port = parsed.port or 5432
        db = os.getenv("POSTGRES_DB", "tsi_cms")
        user = quote_plus(os.getenv("POSTGRES_USER", "tsi_admin"))
        password = quote_plus(_secret("POSTGRES_PASSWD", minimum=8))
        sslmode = "prefer" if _environment() == "local" else "require"
        return f"postgresql://{user}:{password}@{host}:{port}/{db}?sslmode={sslmode}"

    @classmethod
    def load(cls) -> Settings:
        brand = os.getenv("BRAND_NAME", "TSI DPDP CMS").strip() or "TSI DPDP CMS"
        if len(brand) > 12:
            raise RuntimeError("BRAND_NAME must be 12 characters or fewer.")

        allowed = tuple(origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "").split(",") if origin.strip())
        environment = _environment()
        dummy_default = "true" if environment == "local" else "false"
        return cls(
            db_dsn=cls._dsn_from_env(),
            db_encryption_key=_secret("DB_ENCRYPTION_KEY"),
            jwt_secret=_secret("JWT_SECRET"),
            lookup_salt=_secret("TSI_LOOKUP_SALT"),
            allowed_origins=allowed,
            brand_name=brand,
            environment=environment,
            export_path=Path(os.getenv("TSI_EXPORT_PATH", str(ROOT / "exports"))),
            bootstrap_token=_secret("BOOTSTRAP_TOKEN"),
            worker_poll_seconds=int(os.getenv("WORKER_POLL_SECONDS", "30")),
            worker_batch_size=int(os.getenv("WORKER_BATCH_SIZE", "50")),
            smtp_host=os.getenv("SMTP_HOST", ""),
            smtp_port=int(os.getenv("SMTP_PORT", "587")),
            smtp_username=os.getenv("SMTP_USERNAME", ""),
            smtp_password=os.getenv("SMTP_PASSWORD", ""),
            smtp_from=os.getenv("SMTP_FROM", ""),
            smtp_starttls=os.getenv("SMTP_STARTTLS", "true").lower() in {"1", "true", "yes"},
            sms_gateway_url=os.getenv("SMS_GATEWAY_URL", ""),
            push_gateway_url=os.getenv("PUSH_GATEWAY_URL", ""),
            notification_retry_limit=int(os.getenv("NOTIFICATION_RETRY_LIMIT", "5")),
            webhook_retry_limit=int(os.getenv("WEBHOOK_RETRY_LIMIT", "5")),
            alert_escalation_hours=int(os.getenv("ALERT_ESCALATION_HOURS", "24")),
            purge_notice_hours=int(os.getenv("PURGE_NOTICE_HOURS", "48")),
            grievance_escalation_hours=int(os.getenv("GRIEVANCE_ESCALATION_HOURS", "24")),
            allow_dummy_otp=os.getenv("ALLOW_DUMMY_OTP", dummy_default).lower() in {"1", "true", "yes"},
            purge_completion_sla_days=int(os.getenv("PURGE_COMPLETION_SLA_DAYS", "30")),
            digilocker_verify_url=os.getenv("DIGILOCKER_VERIFY_URL", ""),
            sso_issuer=os.getenv("SSO_ISSUER", ""),
            sso_audience=os.getenv("SSO_AUDIENCE", ""),
            sso_jwks_url=os.getenv("SSO_JWKS_URL", ""),
            attachment_max_bytes=int(os.getenv("ATTACHMENT_MAX_BYTES", str(5 * 1024 * 1024))),
            certificate_signing_key=os.getenv("CERTIFICATE_SIGNING_KEY", "") or _secret("DB_ENCRYPTION_KEY"),
            webhook_delivery_retention_days=int(os.getenv("WEBHOOK_DELIVERY_RETENTION_DAYS", "365")),
            notification_delivery_retention_days=int(os.getenv("NOTIFICATION_DELIVERY_RETENTION_DAYS", "365")),
            audit_live_years=max(int(os.getenv("AUDIT_LIVE_YEARS", "3")), 1),
            trusted_proxy_ips=tuple(ip.strip() for ip in os.getenv("TRUSTED_PROXY_IPS", "").split(",") if ip.strip()),
            outbound_allowed_hosts=_outbound_allowed_hosts(environment),
            healthz_token=(os.getenv("HEALTHZ_TOKEN") or "").strip(),
        )


settings = Settings.load()

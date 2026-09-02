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
    token_ttl_minutes: int = 480

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
        sslmode = "prefer" if os.getenv("TSI_DPDP_CMS_ENV", "local") == "local" else "require"
        return f"postgresql://{user}:{password}@{host}:{port}/{db}?sslmode={sslmode}"

    @classmethod
    def load(cls) -> Settings:
        brand = os.getenv("BRAND_NAME", "TSI DPDP CMS").strip() or "TSI DPDP CMS"
        if len(brand) > 12:
            raise RuntimeError("BRAND_NAME must be 12 characters or fewer.")

        allowed = tuple(origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "").split(",") if origin.strip())
        return cls(
            db_dsn=cls._dsn_from_env(),
            db_encryption_key=_secret("DB_ENCRYPTION_KEY"),
            jwt_secret=_secret("JWT_SECRET"),
            lookup_salt=_secret("TSI_LOOKUP_SALT"),
            allowed_origins=allowed,
            brand_name=brand,
            environment=os.getenv("TSI_DPDP_CMS_ENV", "local"),
            export_path=Path(os.getenv("TSI_EXPORT_PATH", str(ROOT / "exports"))),
        )


settings = Settings.load()

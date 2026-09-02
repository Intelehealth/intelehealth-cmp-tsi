from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ADMIN_FIDUCIARY_ID = "00000000-0000-0000-0000-000000000000"


@dataclass
class RequestContext:
    path: str
    category: str
    service: str
    payload: dict[str, Any]
    headers: dict[str, str]
    method: str = "POST"
    auth_token: dict[str, Any] | None = None
    fiduciary_id: str | None = None
    principal_user_id: str | None = None
    permissions: set[str] = field(default_factory=set)
    auth_via_principal_jwt: bool = False

    @property
    def func(self) -> str:
        return str(self.payload.get("_func", "")).lower()

    @property
    def actor_email(self) -> str | None:
        return self.auth_token.get("email") if self.auth_token else None

    @property
    def actor_name(self) -> str | None:
        return self.auth_token.get("name") if self.auth_token else None

    @property
    def actor_role(self) -> str | None:
        return self.auth_token.get("role") if self.auth_token else None

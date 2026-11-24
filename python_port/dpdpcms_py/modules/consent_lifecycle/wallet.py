from __future__ import annotations

from typing import Any

from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    Service,
)
from dpdpcms_py.modules.consent_lifecycle.service import ConsentService

# Wallet sync actions and the concrete function each one runs. dispatch()
# rewrites _func to the target BEFORE authentication, so the API-key scope map,
# the client allow-list and the admin role gate all judge the real operation -
# a READ-scoped key that sends action=GRANT_CONSENT is checked as record_consent.
WALLET_ACTIONS = {
    "GET_CONSENT_DETAILS": "get_consent_record_details",
    "REVOKE_PURPOSE": "erasure_request",
    "GLOBAL_ERASURE": "erasure_request",
    "GRANT_CONSENT": "record_consent",
    "GET_POLICY_PURPOSES": "get_active_policy",
}


def resolve_wallet_action(payload: dict) -> None:
    """Point a wallet call's _func at the function its `action` runs (in place)."""
    # The wallet client sends the action as `command`; `action` is the documented name.
    action = payload.get("action") or payload.get("command")
    if not action and str(payload.get("_func") or "").upper() in WALLET_ACTIONS:
        action = payload["_func"]
    if not action:
        return
    target = WALLET_ACTIONS.get(str(action).upper())
    if not target:
        raise ApiError(400, "Bad Request", f"Unsupported wallet action: {action}")
    payload["_func"] = target


class WalletService(Service):
    def sync(self, ctx: RequestContext) -> dict:
        return {"success": True}

    def handle(self, ctx: RequestContext) -> Any:
        func = ctx.func
        if func == "sync":
            return self.sync(ctx)
        if func == "get_active_policy":
            from dpdpcms_py.modules.consent_lifecycle.notice import PolicyService

            return PolicyService().get_active_policy(ctx)
        if func in set(WALLET_ACTIONS.values()):
            return getattr(ConsentService(), func)(ctx)
        raise ApiError(400, "Bad Request", f"Unsupported function: {func}")

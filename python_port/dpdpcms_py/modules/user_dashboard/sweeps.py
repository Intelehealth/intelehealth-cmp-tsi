from __future__ import annotations

from dpdpcms_py.kernel import db


def expire_nominations() -> dict[str, int]:
    """P6-07: sweep ACTIVE nominations whose valid_until has passed to EXPIRED.

    This makes valid_until actually mean something (a nomination dated 2030 is
    no longer returned as active today once 2030 arrives), and keeps the stored
    status in line with the effective status list_nominations already computes.
    """
    expired = db.execute(
        "UPDATE nominations SET status = 'EXPIRED', last_updated_at = NOW()"
        " WHERE status = 'ACTIVE' AND valid_until IS NOT NULL AND valid_until < NOW()"
    )
    return {"expired": expired or 0}

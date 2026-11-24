from __future__ import annotations

import json

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    Service,
    require,
    tenant_filter,
)
from dpdpcms_py.modules.administration.api import resolve_fiduciary


def _job_input_payload(raw: object) -> str | None:
    """jobs.input_payload is stored as JSON text with every principal id replaced
    by its HMAC (pii.hmac_principal_keys); free text, which could carry an id
    nothing can find, is refused."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = None
    if not isinstance(raw, (dict, list)):
        raise ApiError(400, "Bad Request", "input_payload must be a JSON object or array.")
    return json.dumps(pii.hmac_principal_keys(raw))


class JobService(Service):
    def create_job(self, ctx: RequestContext) -> dict:
        row = db.insert_returning(
            """
            INSERT INTO jobs (id, fiduciary_id, job_type, subtype, status, start_date, end_date, input_payload, created_at)
            VALUES (uuid_generate_v4(), %s, %s, %s, 'PENDING', %s, %s, %s, NOW())
            RETURNING id
            """,
            (
                require(resolve_fiduciary(ctx), "fiduciary_id"),
                require(ctx.payload.get("job_type"), "job_type"),
                ctx.payload.get("subtype"),
                ctx.payload.get("start_date"),
                ctx.payload.get("end_date"),
                _job_input_payload(ctx.payload.get("input_payload")),
            ),
        )
        return {"success": True, "job_id": str(row["id"])}

    def list_jobs(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                "SELECT * FROM jobs WHERE fiduciary_id = %s ORDER BY created_at DESC LIMIT %s",
                (require(resolve_fiduciary(ctx), "fiduciary_id"), int(ctx.payload.get("limit") or 50)),
            )
        )

    def download_file(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        row = db.one(
            f"SELECT output_file_path, subtype FROM jobs WHERE id = %s{scope}",
            (require(ctx.payload.get("job_id"), "job_id"), *scope_params),
        )
        if not row or not row.get("output_file_path"):
            return {"success": False, "message": "Export file not ready yet."}
        # P6-03/LG-07: the export is returned as BASE64 inside the authenticated
        # JSON response, because the console pages are browser navigations that
        # cannot set an Authorization header. The old behaviour (returning a
        # server-side path and downloading via ?auth= in the URL) is gone.
        import base64
        from pathlib import Path

        path = Path(str(row["output_file_path"]))
        if not path.exists():
            return {"success": False, "message": "Export file not found on disk."}
        data = path.read_bytes()
        filename = str(row.get("subtype") or path.name).lower() or path.name
        return {
            "success": True,
            "job_id": ctx.payload.get("job_id"),
            "filename": path.name,
            "content_type": "text/csv; charset=utf-8",
            "content_base64": base64.b64encode(data).decode("ascii"),
            "subtype": filename,
        }

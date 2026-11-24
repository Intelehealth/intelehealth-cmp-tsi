from __future__ import annotations

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    require,
    tenant_filter,
)

ATTACHMENT_TYPES = {"application/pdf", "image/png", "image/jpeg", "text/plain"}


class AttachmentHandlers:
    def upload_grievance_attachment(self, ctx: RequestContext) -> dict:
        """GR-04: attach supporting evidence to a grievance.

        The file arrives base64-encoded in the JSON body, is checked against an
        allow-list of types and the ATTACHMENT_MAX_BYTES limit, and is stored
        under the export path by its SHA-256, never by the caller's file name.
        """
        import base64
        import hashlib

        from dpdpcms_py.kernel.config import settings

        gid = require(ctx.payload.get("grievance_id"), "grievance_id")
        content_type = str(require(ctx.payload.get("content_type"), "content_type")).lower()
        if content_type not in ATTACHMENT_TYPES:
            raise ApiError(400, "Bad Request", f"content_type must be one of {sorted(ATTACHMENT_TYPES)}.")
        file_name = str(require(ctx.payload.get("file_name"), "file_name"))[:255]
        try:
            data = base64.b64decode(str(require(ctx.payload.get("content_base64"), "content_base64")), validate=True)
        except ValueError:
            raise ApiError(400, "Bad Request", "content_base64 is not valid base64.") from None
        if not data or len(data) > settings.attachment_max_bytes:
            raise ApiError(413, "Payload Too Large", f"Attachments must be 1 to {settings.attachment_max_bytes} bytes.")
        scope, scope_params = tenant_filter(ctx)
        if ctx.auth_via_principal_jwt:
            scope += f" AND {pii.match_sql('user_id')}"
            scope_params.extend(pii.hmac_params(ctx.principal_user_id))
        grievance = db.one(f"SELECT id, fiduciary_id FROM grievances WHERE id = %s{scope}", (gid, *scope_params))
        if not grievance:
            raise ApiError(404, "Not Found", "Grievance not found.")
        digest = hashlib.sha256(data).hexdigest()
        folder = settings.export_path / "attachments" / str(grievance["fiduciary_id"])
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / digest
        if not path.exists():
            path.write_bytes(data)
        uploader = ctx.principal_user_id or ctx.actor_email or "INTEGRATOR"
        row = db.insert_returning(
            f"""
            INSERT INTO grievance_attachments
                (grievance_id, fiduciary_id, file_name, content_type, size_bytes, sha256, storage_path,
                 uploaded_by_enc, uploaded_by_hmac)
            VALUES (%s, %s, %s, %s, %s, %s, %s, {pii.PID_VALUES})
            RETURNING id
            """,
            (
                gid,
                grievance["fiduciary_id"],
                file_name,
                content_type,
                len(data),
                digest,
                str(path),
                *pii.pid_params(uploader),
            ),
        )
        attachment = {
            "attachment_id": str(row["id"]),
            "file_name": file_name,
            "sha256": digest,
            "size_bytes": len(data),
        }
        db.execute(
            "UPDATE grievances SET attachments = COALESCE(attachments, '[]'::jsonb) || %s::jsonb, last_updated_at = NOW() WHERE id = %s",
            (db.as_jsonb([attachment]), gid),
        )
        return {"success": True, **attachment}

    def get_grievance_attachment(self, ctx: RequestContext) -> dict:
        """GR-04: read back an attachment, with the same ownership rules as upload."""
        import base64
        from pathlib import Path

        aid = require(ctx.payload.get("attachment_id"), "attachment_id")
        scope, scope_params = tenant_filter(ctx, "a.fiduciary_id")
        if ctx.auth_via_principal_jwt:
            scope += f" AND g.{pii.match_sql('user_id')}"
            scope_params.extend(pii.hmac_params(ctx.principal_user_id))
        row = db.one(
            f"""
            SELECT a.id, a.grievance_id, a.file_name, a.content_type, a.size_bytes, a.sha256,
                   a.storage_path, {pii.dec_sql("a.uploaded_by_enc")} AS uploaded_by, a.created_at
            FROM grievance_attachments a JOIN grievances g ON g.id = a.grievance_id
            WHERE a.id = %s{scope}
            """,
            (*db.bind_key(), aid, *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "Attachment not found.")
        try:
            data = Path(row["storage_path"]).read_bytes()
        except OSError:
            raise ApiError(410, "Gone", "The attachment file is no longer stored.") from None
        meta = pii.principal_row(ctx, {k: v for k, v in row.items() if k != "storage_path"}, "uploaded_by")
        return {**meta, "attachment_id": str(row["id"]), "content_base64": base64.b64encode(data).decode("ascii")}

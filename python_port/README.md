# TSI DPDP CMS Python Port

FastAPI backend for this fork. Static UI lives in `../web`, JSON Schema validators in `../web/WEB-INF/validator`, and PostgreSQL schema in `../db`.

## Run

From the repository root, copy `.env.example` to `.env` and set secrets (`openssl rand -hex 32`). Then:

```bash
cd python_port
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn dpdpcms_py.main:app --host 127.0.0.1 --port 8080
```

On macOS/Linux: `source .venv/bin/activate`.

Required environment variables: `POSTGRES_HOST`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWD`, `JWT_SECRET`, `DB_ENCRYPTION_KEY`, `TSI_LOOKUP_SALT`. Optional: `ALLOWED_ORIGINS`, `BRAND_NAME`, `TSI_EXPORT_PATH`, `TSI_DPDP_CMS_ENV`.

## Notes

- API routing mirrors the original servlet filter: `/api/v1/admin/{service}`, `/api/v1/client/{service}`, `/api/v1/public/{service}`, `/api/v1/bootstrap/setup`, and legacy `/api/v1/{service}`.
- Encrypted PII columns use PostgreSQL `pgcrypto`, same as the Java implementation.
- Static HTML is served from `web/` with optional `BRAND_NAME` substitution.

-- 20_security_gaps.sql
-- Schema support for the "Security Gaps" sheet of
-- MeitY_BRD_API_Traceability_security.xlsx:
--   * SEC-01 / SEC-03  — generic attempt throttles (recovery path, operator login)
--   * SEC-14           — single-use SSO nonces (replay protection)
--   * SEC-07           — sweep visibility for lapsed API keys
--
-- Idempotent: safe to apply to an existing deployment.

-- ============================================================
-- SEC-01 / SEC-03: attempt throttles keyed by scope + key.
-- `key` is a stable identity (an email HMAC, an operator id, or
-- a source IP string). failures counts consecutive bad attempts;
-- locked_until is the instant the key is refused until. Rows are
-- cleared on success and pruned by the worker once expired.
-- ============================================================
CREATE TABLE IF NOT EXISTS auth_throttles (
    scope         VARCHAR(40)  NOT NULL,          -- 'login:operator', 'login:ip', 'recovery:email', 'recovery:ip'
    key           VARCHAR(255) NOT NULL,
    failures      INTEGER      NOT NULL DEFAULT 0,
    locked_until  TIMESTAMPTZ,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scope, key)
);

CREATE INDEX IF NOT EXISTS idx_auth_throttles_locked
    ON auth_throttles (locked_until) WHERE locked_until IS NOT NULL;

-- ============================================================
-- SEC-14: single-use SSO login nonces. A nonce issued to the
-- browser is consumed the first time it is presented with an
-- id_token; presenting it again is rejected. Pruned by the worker
-- once the token lifetime has passed.
-- ============================================================
CREATE TABLE IF NOT EXISTS sso_login_nonces (
    nonce        VARCHAR(255) PRIMARY KEY,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sso_login_nonces_expiry
    ON sso_login_nonces (expires_at);

-- ============================================================
-- SEC-14: unused rights-app-config rows must not read as DUMMY_OTP. Align the
-- column default with the code's fail-closed EMAIL_OTP fallback for
-- deployments that applied 12_rights_app_config.sql before this migration.
-- ============================================================
ALTER TABLE rights_app_config ALTER COLUMN otp_mode SET DEFAULT 'EMAIL_OTP';
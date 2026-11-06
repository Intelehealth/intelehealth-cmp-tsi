-- ============================================================================
-- db/22_security_gaps_p7.sql
--
-- SEC-18 residual (workbook v3): update_user no longer silently nulls a
-- non-ADMIN operator's fiduciary_id (see services/admin.py), and create_user
-- already refuses the NULL-fiduciary shape. This migration handles the rows
-- that EXISTED before those guards: a non-ADMIN operator with a NULL
-- fiduciary_id defeats every tenancy check (SA-02/SA-08), so the affected
-- accounts are deactivated — blocked from logging in — instead of being left
-- live. An operator who must keep working is assigned a fiduciary_id and
-- re-activated deliberately.
--
-- Idempotent: the UPDATE touches only ACTIVE non-ADMIN rows with a NULL
-- tenant, so applying it twice is a no-op on the second pass.
-- ============================================================================

UPDATE operators
SET    status = 'INACTIVE',
       tokens_valid_after = NOW(),
       last_updated_at   = NOW()
WHERE  role <> 'ADMIN'
  AND  fiduciary_id IS NULL
  AND  status = 'ACTIVE';
-- The built-in DPO role may reveal a Data Principal identifier in the clear
-- (admin pii service, reveal_user_id). ADMIN already holds full access; the
-- other built-ins never get it. Additive only, as in db/17: permissions an
-- administrator already set are kept. Idempotent.
UPDATE roles SET permissions = (
    SELECT jsonb_agg(DISTINCT p ORDER BY p)
    FROM jsonb_array_elements_text(roles.permissions || '["pii:reveal"]'::jsonb) AS p
) WHERE code = 'DPO' AND fiduciary_id IS NULL;

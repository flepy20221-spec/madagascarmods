\set ON_ERROR_STOP on
BEGIN;
\i /home/ubuntu/cashpix-work/madagascarmods/madagascarmods-backend/migrations/008_device_aliases_and_support_codes.sql

DO $$
DECLARE
  missing_codes integer;
  duplicate_codes integer;
  missing_aliases integer;
BEGIN
  SELECT COUNT(*) INTO missing_codes
    FROM users WHERE support_code IS NULL OR btrim(support_code) = '';
  IF missing_codes <> 0 THEN
    RAISE EXCEPTION 'support_code ausente em % usuarios', missing_codes;
  END IF;

  SELECT COUNT(*) INTO duplicate_codes
    FROM (
      SELECT support_code FROM users GROUP BY support_code HAVING COUNT(*) > 1
    ) duplicates;
  IF duplicate_codes <> 0 THEN
    RAISE EXCEPTION 'foram encontrados % codigos duplicados', duplicate_codes;
  END IF;

  SELECT COUNT(*) INTO missing_aliases
    FROM users u
    WHERE u.device_account_key IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM device_account_aliases a
         WHERE a.device_account_key = u.device_account_key
           AND a.user_id = u.id
      );
  IF missing_aliases <> 0 THEN
    RAISE EXCEPTION 'faltam % aliases para chaves atuais', missing_aliases;
  END IF;
END;
$$;

SELECT
  (SELECT COUNT(*) FROM users) AS users_checked,
  (SELECT COUNT(*) FROM device_account_aliases) AS aliases_backfilled,
  (SELECT COUNT(DISTINCT support_code) FROM users) AS unique_support_codes;
ROLLBACK;

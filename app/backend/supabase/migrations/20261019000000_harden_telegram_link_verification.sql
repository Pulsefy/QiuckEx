ALTER TABLE telegram_user_mappings
  ADD COLUMN IF NOT EXISTS verification_expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS verification_attempts INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS verification_locked_until TIMESTAMPTZ;

CREATE OR REPLACE FUNCTION verify_telegram_link(
  p_telegram_id BIGINT,
  p_verification_code TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  mapping telegram_user_mappings%ROWTYPE;
  next_attempts INTEGER;
BEGIN
  SELECT * INTO mapping
  FROM telegram_user_mappings
  WHERE telegram_id = p_telegram_id
  FOR UPDATE;

  IF NOT FOUND OR mapping.is_verified THEN
    RETURN 'invalid';
  END IF;

  IF mapping.verification_locked_until > now() THEN
    RETURN 'locked';
  END IF;

  IF mapping.verification_code IS NULL
    OR mapping.verification_expires_at IS NULL
    OR mapping.verification_expires_at <= now() THEN
    UPDATE telegram_user_mappings
    SET verification_code = NULL,
        verification_expires_at = NULL
    WHERE telegram_id = p_telegram_id;
    RETURN 'expired';
  END IF;

  IF upper(mapping.verification_code) = upper(btrim(p_verification_code)) THEN
    UPDATE telegram_user_mappings
    SET is_verified = true,
        verification_code = NULL,
        verification_expires_at = NULL,
        verification_attempts = 0,
        verification_locked_until = NULL
    WHERE telegram_id = p_telegram_id;
    RETURN 'verified';
  END IF;

  next_attempts := mapping.verification_attempts + 1;
  UPDATE telegram_user_mappings
  SET verification_attempts = next_attempts,
      verification_locked_until = CASE
        WHEN next_attempts >= 5 THEN now() + interval '15 minutes'
        ELSE NULL
      END
  WHERE telegram_id = p_telegram_id;

  IF next_attempts >= 5 THEN
    RETURN 'locked';
  END IF;

  RETURN 'invalid';
END;
$$;

REVOKE ALL ON FUNCTION public.verify_telegram_link(BIGINT, TEXT) FROM PUBLIC;

DO $$
DECLARE
  role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['anon', 'authenticated'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
      EXECUTE format('REVOKE ALL ON FUNCTION public.verify_telegram_link(BIGINT, TEXT) FROM %I', role_name);
    END IF;
  END LOOP;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.verify_telegram_link(BIGINT, TEXT) TO service_role';
  END IF;
END
$$;

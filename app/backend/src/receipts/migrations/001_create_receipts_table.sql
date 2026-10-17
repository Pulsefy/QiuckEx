-- BE-105: Persistent receipt store
-- Creates the receipts table used by receipts/receipts.service.ts
-- so receipt reads/writes survive restarts and are shared across instances.

CREATE TABLE IF NOT EXISTS public.receipts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    receipt_hash        TEXT NOT NULL UNIQUE,
    transaction_hash    TEXT NOT NULL,
    stellar_account     TEXT NOT NULL,
    amount              NUMERIC(20, 7),
    asset               TEXT,
    memo                TEXT,
    status              TEXT NOT NULL DEFAULT 'pending',
    normalized_payload JSONB NOT NULL,
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT receipts_status_check CHECK (status IN ('pending', 'completed', 'failed', 'refunded'))
);

CREATE INDEX IF NOT EXISTS receipts_receipt_hash_idx
    ON public.receipts (receipt_hash);

CREATE INDEX IF NOT EXISTS receipts_transaction_hash_idx
    ON public.receipts (transaction_hash);

CREATE INDEX IF NOT EXISTS receipts_stellar_account_idx
    ON public.receipts (stellar_account);

CREATE INDEX IF NOT EXISTS receipts_created_at_idx
    ON public.receipts (created_at DESC);

-- Keep updated_at in sync on every write.
CREATE OR REPLACE FUNCTION public.set_receipts_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER TRIGGER IF EXISTS on public.receipts;
CREATE TRIGGER receipts_set_updated_at
    BEFORE UPDATE ON public.receipts
    FOR EACH ROW EXECUTE FUNCTION public.set_receipts_updated_at();

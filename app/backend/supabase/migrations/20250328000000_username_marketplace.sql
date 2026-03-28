CREATE TABLE username_marketplace (
  id                UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  username          TEXT          NOT NULL REFERENCES usernames(username) ON DELETE CASCADE,
  seller_public_key TEXT          NOT NULL,
  asking_price      NUMERIC(20,7) NOT NULL CHECK (asking_price > 0),
  status            TEXT          NOT NULL DEFAULT 'active'
                                  CHECK (status IN ('active', 'sold', 'cancelled')),
  created_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
  sold_at           TIMESTAMPTZ,
  buyer_public_key  TEXT,
  final_price       NUMERIC(20,7)
);

CREATE UNIQUE INDEX username_marketplace_active_unique
  ON username_marketplace (username)
  WHERE status = 'active';

CREATE INDEX username_marketplace_seller_idx   ON username_marketplace (seller_public_key);
CREATE INDEX username_marketplace_status_idx   ON username_marketplace (status);
CREATE INDEX username_marketplace_username_idx ON username_marketplace (username);

CREATE TABLE username_bids (
  id                UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  listing_id        UUID          NOT NULL REFERENCES username_marketplace(id) ON DELETE CASCADE,
  bidder_public_key TEXT          NOT NULL,
  bid_amount        NUMERIC(20,7) NOT NULL CHECK (bid_amount > 0),
  status            TEXT          NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending', 'accepted', 'rejected', 'cancelled')),
  created_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ   NOT NULL DEFAULT now()
);

CREATE INDEX username_bids_listing_idx ON username_bids (listing_id);
CREATE INDEX username_bids_bidder_idx  ON username_bids (bidder_public_key);
CREATE INDEX username_bids_status_idx  ON username_bids (status);

CREATE OR REPLACE FUNCTION accept_username_bid(
  p_listing_id        UUID,
  p_bid_id            UUID,
  p_seller_public_key TEXT
) RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  v_listing username_marketplace%ROWTYPE;
  v_bid     username_bids%ROWTYPE;
BEGIN
  SELECT * INTO v_listing
    FROM username_marketplace
   WHERE id = p_listing_id
     FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'LISTING_NOT_FOUND: Listing % does not exist', p_listing_id;
  END IF;

  IF v_listing.status != 'active' THEN
    RAISE EXCEPTION 'LISTING_NOT_ACTIVE: Listing is in status "%"', v_listing.status;
  END IF;

  IF v_listing.seller_public_key != p_seller_public_key THEN
    RAISE EXCEPTION 'UNAUTHORIZED: Caller is not the seller of this listing';
  END IF;

  SELECT * INTO v_bid
    FROM username_bids
   WHERE id = p_bid_id
     AND listing_id = p_listing_id
     FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'BID_NOT_FOUND: Bid % does not exist on this listing', p_bid_id;
  END IF;

  IF v_bid.status != 'pending' THEN
    RAISE EXCEPTION 'BID_NOT_PENDING: Bid is in status "%"', v_bid.status;
  END IF;

  UPDATE username_bids
     SET status = 'accepted', updated_at = now()
   WHERE id = p_bid_id;

  UPDATE username_bids
     SET status = 'rejected', updated_at = now()
   WHERE listing_id = p_listing_id
     AND id != p_bid_id
     AND status = 'pending';

  UPDATE username_marketplace
     SET status           = 'sold',
         sold_at          = now(),
         buyer_public_key = v_bid.bidder_public_key,
         final_price      = v_bid.bid_amount,
         updated_at       = now()
   WHERE id = p_listing_id;

  UPDATE usernames
     SET public_key = v_bid.bidder_public_key
   WHERE username = v_listing.username;
END;
$$;

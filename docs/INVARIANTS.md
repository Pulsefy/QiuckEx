Core Financial Invariants
INV-01: Conservation of Value

The sum of all balances (escrow + merchant + customer + fees) MUST equalthe total value deposited into the system. No value is created or destroyedoutside of explicit protocol actions.
INV-02: No Unauthorized Withdrawals

Only the designated recipient (merchant on fulfill, customer on refund,arbiter on dispute resolution) may claim payment funds. No third partycan withdraw funds from an escrow they are not a party to.
INV-03: No Overpayment

The total amount released from a payment MUST NOT exceed the originaldeposited amount plus any permitted fee adjustments. Each payment releasesat most its principal.
INV-04: No Double-Settlement

A payment can transition to a terminal state (Fulfilled, Refunded,DisputeResolved) exactly once. No payment can be fulfilled AND refunded,or settled twice.
State Machine Invariants
INV-05: Valid State Transitions Only

The payment state machine only permits:  Created → Funded → Fulfilled  Created → Funded → Disputed → DisputeResolved  Created → Funded → Refunded (after expiry)  Created → Expired (if never funded)

No backward or cross-branch transitions are valid.
INV-06: Expiry Monotonicity

A payment whose expiry timestamp has passed cannot be fulfilled. It canonly be refunded or disputed (if already in dispute).
INV-07: Nonce Uniqueness

No two payments can share the same (creator, nonce) pair. Replay of apreviously consumed nonce MUST be rejected.
INV-08: Authorization Consistency

The actor performing a transition MUST be authorized:

    Only creator can fund
    Only merchant can fulfill
    Only customer can request refund
    Only designated arbiter can resolve dispute

Edge-Case Invariants
INV-09: Zero-Amount Payment

Zero-amount payments follow the same state machine but MUST NOT resultin any token transfers.
INV-10: Fee Ceiling

Protocol fees collected per payment MUST NOT exceed the configuredmaximum fee percentage of the payment amount.
INV-11: Partial Payment Accounting

For every escrow, the accounting equation is:

    settled + refunded + outstanding + fees == paid_deposit

paid_deposit is the cumulative principal transferred into the escrow contract. While a partial escrow is pending, all paid principal is outstanding in the contract and mount_paid must never exceed mount_due. On settlement, the paid principal is split into recipient payout plus protocol fees. On refund or timeout finalization, the paid principal returns to the owner and no fee is charged.

Fee rounding is floor-based at final settlement (ee_from_bps_floor) and is applied once to the settled escrow amount, not incrementally on every partial payment. This keeps repeated partial operations from leaking value in either direction.

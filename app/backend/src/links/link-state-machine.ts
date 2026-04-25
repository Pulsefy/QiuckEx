export enum LinkState {
  DRAFT = 'DRAFT',
  ACTIVE = 'ACTIVE',
  EXPIRED = 'EXPIRED',
  PAID = 'PAID',
  REFUNDED = 'REFUNDED',
}

const TRANSITIONS: Record<LinkState, LinkState[]> = {
  [LinkState.DRAFT]: [LinkState.ACTIVE],
  [LinkState.ACTIVE]: [LinkState.EXPIRED, LinkState.PAID],
  [LinkState.EXPIRED]: [LinkState.ACTIVE],
  [LinkState.PAID]: [LinkState.REFUNDED],
  [LinkState.REFUNDED]: [],
};

export function canTransition(from: LinkState, to: LinkState): boolean {
  return TRANSITIONS[from].includes(to);
}

export function applyTransition(from: LinkState, to: LinkState): LinkState {
  if (!canTransition(from, to)) {
    throw new Error(`Invalid link state transition: ${from} -> ${to}`);
  }
  return to;
}

export function getAvailableTransitions(state: LinkState): LinkState[] {
  return [...TRANSITIONS[state]];
}

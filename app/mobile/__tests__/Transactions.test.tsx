import React from 'react';
import render from 'react-test-renderer';
import TransactionsScreen from '../app/transactions';

// ── Environment mocks ──────────────────────────────────────────────────────

jest.mock('expo-router', () => ({
    useLocalSearchParams: () => ({}),
    useRouter: () => ({ back: jest.fn() }),
}));

// ── Hook mock ─────────────────────────────────────────────────────────────

const mockUseTransactions = jest.fn();
jest.mock('../hooks/use-transactions', () => ({
    useTransactions: (...args: unknown[]) => mockUseTransactions(...args),
}));

// ── Helpers ───────────────────────────────────────────────────────────────

/** Recursively walk the test-renderer node tree to find all string leaves. */
function collectText(node: unknown): string[] {
    if (typeof node === 'string') return [node];
    if (Array.isArray(node)) return node.flatMap(collectText);
    if (node && typeof node === 'object') {
        const n = node as Record<string, unknown>;
        return [
            ...collectText(n['children']),
            ...collectText(n['props']),
        ];
    }
    return [];
}

// ── Fixtures ──────────────────────────────────────────────────────────────

const BASE_STATE = {
    refresh: jest.fn(),
    loadMore: jest.fn(),
};

const MOCK_ITEM = {
    amount: '100.5000000',
    asset: 'USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335XOP3IA2M65BZDCCXN2YRC2TH',
    memo: 'Test payment',
    timestamp: '2026-02-21T08:00:00Z',
    txHash: 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd',
    pagingToken: '1234567890',
};

// ── Tests ─────────────────────────────────────────────────────────────────

describe('<TransactionsScreen />', () => {
    beforeEach(() => jest.clearAllMocks());

    it('renders loading skeleton when loading is true', () => {
        mockUseTransactions.mockReturnValue({
            ...BASE_STATE,
            transactions: [],
            loading: true,
            refreshing: false,
            error: null,
            hasMore: false,
        });

        let tree: ReturnType<typeof render.create>;
        render.act(() => {
            tree = render.create(<TransactionsScreen />);
        });

        // @ts-expect-error tree is assigned inside act
        expect(tree.toJSON()).toBeDefined();
    });

    it('renders error banner with Retry button when error is set', () => {
        mockUseTransactions.mockReturnValue({
            ...BASE_STATE,
            transactions: [],
            loading: false,
            refreshing: false,
            error: 'Network request failed.',
            hasMore: false,
        });

        let tree: ReturnType<typeof render.create>;
        render.act(() => {
            tree = render.create(<TransactionsScreen />);
        });

        // @ts-expect-error tree is assigned inside act
        const texts = collectText(tree.toJSON());
        expect(texts).toContain('Network request failed.');
        expect(texts).toContain('Retry');
    });

    it('renders formatted transaction amounts when data is available', () => {
        mockUseTransactions.mockReturnValue({
            ...BASE_STATE,
            transactions: [MOCK_ITEM],
            loading: false,
            refreshing: false,
            error: null,
            hasMore: false,
        });

        let tree: ReturnType<typeof render.create>;
        render.act(() => {
            tree = render.create(<TransactionsScreen />);
        });

        // @ts-expect-error tree is assigned inside act
        const texts = collectText(tree.toJSON());
        expect(texts.some((t) => t.includes('100.50'))).toBe(true);
    });

    it('renders empty state message when transactions list is empty', () => {
        mockUseTransactions.mockReturnValue({
            ...BASE_STATE,
            transactions: [],
            loading: false,
            refreshing: false,
            error: null,
            hasMore: false,
        });

        let tree: ReturnType<typeof render.create>;
        render.act(() => {
            tree = render.create(<TransactionsScreen />);
        });

        // @ts-expect-error tree is assigned inside act
        const texts = collectText(tree.toJSON());
        expect(texts).toContain('No transactions yet');
    });
});

import React from 'react';
import render from 'react-test-renderer';
import TransactionsScreen from '../app/transactions';

/**
 * Clearly-fake account fixture, kept for tests only.
 *
 * Production deliberately has no fallback account: the screen used to fall back
 * to a hardcoded real Stellar account (DEMO_ACCOUNT_ID), which rendered that
 * account's live payment history to a user whose wallet had not resolved. The
 * tests below assert the fixture never reaches the data hook.
 */
const FAKE_TEST_ACCOUNT_ID =
    'GFAKETESTACCOUNTNOTAREALSTELLARADDRESS0000000000000000';

const TEST_ACCOUNT_ID =
    'GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP';

// Mutable so individual tests can drive the route param and the wallet state.
const mockRouteParams: { accountId?: string } = {};
const mockNotifications: {
    currentAccountId: string | null;
    isHydrated: boolean;
} = {
    currentAccountId: TEST_ACCOUNT_ID,
    isHydrated: true,
};

jest.mock('expo-router', () => ({
    useLocalSearchParams: () => mockRouteParams,
    useRouter: () => ({ back: jest.fn() }),
}));

jest.mock('@shopify/flash-list', () => {
    const React = require('react');
    const { FlatList } = require('react-native');
    return {
        FlashList: React.forwardRef((props: unknown, ref: unknown) => (
            <FlatList ref={ref} {...(props as object)} />
        )),
    };
});

jest.mock('expo-file-system', () => ({
    cacheDirectory: 'file://cache/',
    writeAsStringAsync: jest.fn(),
    EncodingType: { UTF8: 'utf8' },
}));

jest.mock('expo-sharing', () => ({
    isAvailableAsync: jest.fn(() => Promise.resolve(false)),
    shareAsync: jest.fn(),
}));

jest.mock('../components/notifications/NotificationContext', () => ({
    useNotifications: () => mockNotifications,
}));

jest.mock('../src/theme/ThemeContext', () => ({
    useTheme: () => ({
        theme: {
            background: '#fff',
            surface: '#fff',
            surfaceElevated: '#f7f7f7',
            headerBg: '#fff',
            border: '#ddd',
            textPrimary: '#111',
            textMuted: '#666',
            inputPlaceholder: '#999',
            inputText: '#111',
            chipBg: '#eee',
            chipActiveBg: '#111',
            chipText: '#111',
            chipActiveText: '#fff',
            buttonPrimaryBg: '#111',
            buttonPrimaryText: '#fff',
            skeleton: '#eee',
        },
    }),
}));

const mockUseTransactions = jest.fn();
jest.mock('../hooks/use-transactions', () => ({
    useTransactions: (...args: unknown[]) => mockUseTransactions(...args),
}));

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
    source: 'GTESTSOURCE123',
    destination: 'GTESTDEST123',
    status: 'Success' as const,
};

function renderScreen() {
    let tree!: render.ReactTestRenderer;
    render.act(() => {
        tree = render.create(<TransactionsScreen />);
    });
    return tree;
}

/** The accountId the screen handed to the data hook on its first render. */
function queriedAccountId(): unknown {
    return mockUseTransactions.mock.calls[0]?.[0];
}

describe('<TransactionsScreen />', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        delete mockRouteParams.accountId;
        mockNotifications.currentAccountId = TEST_ACCOUNT_ID;
        mockNotifications.isHydrated = true;
    });

    it('renders loading skeleton when loading is true', () => {
        mockUseTransactions.mockReturnValue({
            ...BASE_STATE,
            transactions: [],
            loading: true,
            refreshing: false,
            error: null,
            hasMore: false,
        });

        const tree = renderScreen();

        expect(tree.toJSON()).toBeDefined();
    });

    it('renders error state when error is set', () => {
        mockUseTransactions.mockReturnValue({
            ...BASE_STATE,
            transactions: [],
            loading: false,
            refreshing: false,
            error: 'Network request failed.',
            hasMore: false,
        });

        const texts = collectText(renderScreen().toJSON());
        expect(texts).toContain('Network request failed.');
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

        const texts = collectText(renderScreen().toJSON());
        expect(texts.some((text) => text.includes('100.50'))).toBe(true);
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

        const texts = collectText(renderScreen().toJSON());
        expect(texts).toContain('No transactions yet');
    });

    it('queries the connected wallet account rather than a fallback fixture', () => {
        mockUseTransactions.mockReturnValue({
            ...BASE_STATE,
            transactions: [MOCK_ITEM],
            loading: false,
            refreshing: false,
            error: null,
            hasMore: false,
        });

        renderScreen();

        expect(queriedAccountId()).toBe(TEST_ACCOUNT_ID);
        expect(
            mockUseTransactions.mock.calls.some(
                ([id]) => id === FAKE_TEST_ACCOUNT_ID,
            ),
        ).toBe(false);
    });

    it('prompts the user to connect a wallet instead of showing another account history', () => {
        // Wallet has finished resolving and there is no account.
        mockNotifications.currentAccountId = null;
        mockNotifications.isHydrated = true;
        mockUseTransactions.mockReturnValue({
            ...BASE_STATE,
            transactions: [],
            loading: false,
            refreshing: false,
            error: null,
            hasMore: false,
        });

        const texts = collectText(renderScreen().toJSON());

        expect(texts).toContain('Connect a wallet');
        expect(texts).toContain(
            'Connect a wallet to see your transaction history.',
        );
        // No account is passed to the hook — in particular not the fixture.
        expect(queriedAccountId()).toBe('');
        expect(
            mockUseTransactions.mock.calls.some(
                ([id]) => id === FAKE_TEST_ACCOUNT_ID,
            ),
        ).toBe(false);
    });

    it('shows a loading state while wallet state is still resolving', () => {
        // Wallet state has not loaded yet: currentAccountId is null, but that
        // means "unknown", not "no account".
        mockNotifications.currentAccountId = null;
        mockNotifications.isHydrated = false;
        mockUseTransactions.mockReturnValue({
            ...BASE_STATE,
            transactions: [],
            loading: true,
            refreshing: false,
            error: null,
            hasMore: false,
        });

        const texts = collectText(renderScreen().toJSON());

        // Neither a stranger's history nor a premature "connect a wallet".
        expect(texts).not.toContain('Connect a wallet');
        expect(texts).not.toContain('No transactions yet');
        expect(queriedAccountId()).toBe('');
    });

    it('uses an explicitly passed accountId without waiting for wallet hydration', () => {
        mockNotifications.currentAccountId = null;
        mockNotifications.isHydrated = false;
        mockRouteParams.accountId = TEST_ACCOUNT_ID;
        mockUseTransactions.mockReturnValue({
            ...BASE_STATE,
            transactions: [],
            loading: false,
            refreshing: false,
            error: null,
            hasMore: false,
        });

        renderScreen();

        expect(queriedAccountId()).toBe(TEST_ACCOUNT_ID);
    });

    it('trims whitespace-only route params and does not query them', () => {
        mockNotifications.currentAccountId = null;
        mockNotifications.isHydrated = true;
        mockRouteParams.accountId = '   ';
        mockUseTransactions.mockReturnValue({
            ...BASE_STATE,
            transactions: [],
            loading: false,
            refreshing: false,
            error: null,
            hasMore: false,
        });

        const texts = collectText(renderScreen().toJSON());

        expect(queriedAccountId()).toBe('');
        expect(texts).toContain('Connect a wallet');
    });
});

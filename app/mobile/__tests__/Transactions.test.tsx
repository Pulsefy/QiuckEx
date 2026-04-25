import React from 'react';
import render from 'react-test-renderer';
import TransactionsScreen from '../app/transactions';

jest.mock('expo-router', () => ({
    useLocalSearchParams: () => ({}),
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
    useNotifications: () => ({
        currentAccountId:
            'GAMOSFOKEYHFDGMXIEFEYBUYK3ZMFYN3PFLOTBRXFGBFGRKBKLQSLGLP',
    }),
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

        let tree: render.ReactTestRenderer;
        render.act(() => {
            tree = render.create(<TransactionsScreen />);
        });

        expect(tree!.toJSON()).toBeDefined();
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

        let tree: render.ReactTestRenderer;
        render.act(() => {
            tree = render.create(<TransactionsScreen />);
        });

        const texts = collectText(tree!.toJSON());
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

        let tree: render.ReactTestRenderer;
        render.act(() => {
            tree = render.create(<TransactionsScreen />);
        });

        const texts = collectText(tree!.toJSON());
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

        let tree: render.ReactTestRenderer;
        render.act(() => {
            tree = render.create(<TransactionsScreen />);
        });

        const texts = collectText(tree!.toJSON());
        expect(texts).toContain('No transactions yet');
    });
});

/**
 * Performance checks for the transaction history screen (MOB-70).
 *
 * Demonstrates that a large transaction history is rendered through a
 * virtualized list (bounded mount window => stable memory) and that
 * scroll position is preserved across data refresh.
 */

import React from 'react';
import render from 'react-test-renderer';
import { FlatList, ActivityIndicator } from 'react-native';
import TransactionsScreen from '../app/transactions';

jest.mock('expo-router', () => ({
    useLocalSearchParams: () => ({}),
    useRouter: () => ({ back: jest.fn() }),
}));

jest.mock('@shopify/flash-list', () => {
    const React = require('react');
    const { FlatList } = require('react-native');
    const FlashListMock = React.forwardRef(
        (props: unknown, ref: unknown) => (
            <FlatList ref={ref} {...(props as object)} />
        ),
    );
    FlashListMock.displayName = 'FlashList';
    return { FlashList: FlashListMock };
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

function makeHistory(count: number) {
    return Array.from({ length: count }, (_, i) => ({
        ...MOCK_ITEM,
        amount: `${(i % 1000) + 1}.0000000`,
        memo: `Payment ${i}`,
        timestamp: new Date(Date.UTC(2026, 0, 1) - i * 86_400_000).toISOString(),
        txHash: `hash-${i}-${'a'.repeat(48)}`,
        pagingToken: `pt-${count - i}`,
    }));
}

function renderScreen(state: Record<string, unknown>) {
    mockUseTransactions.mockReturnValue({
        ...BASE_STATE,
        ...state,
    });

    let tree!: render.ReactTestRenderer;
    render.act(() => {
        tree = render.create(<TransactionsScreen />);
    });
    return tree;
}

describe('Transaction list performance', () => {
    beforeEach(() => jest.clearAllMocks());

    it('virtualizes a large history so memory stays bounded (stable memory)', () => {
        const tree = renderScreen({
            transactions: makeHistory(10_000),
            loading: false,
            refreshing: false,
            error: null,
            hasMore: true,
            staleCache: false,
        });

        const renderedRows = tree.root.findAll(
            (node) => node.props.testID === 'transaction-row',
        );

        // Only a small window of rows is mounted even though 10,000 exist.
        expect(renderedRows.length).toBeGreaterThan(0);
        expect(renderedRows.length).toBeLessThan(100);
    });

    it('preserves scroll position across data refresh', () => {
        const tree = renderScreen({
            transactions: [MOCK_ITEM],
            loading: false,
            refreshing: false,
            error: null,
            hasMore: false,
            staleCache: false,
        });

        const list = tree.root.findByType(FlatList);
        expect(list.props.maintainVisibleContentPosition).toEqual({
            autoscrollToTopThreshold: 100,
            minIndexForVisible: 0,
        });
        // Pagination remains wired for infinite scroll.
        expect(typeof list.props.onEndReached).toBe('function');
        expect(typeof list.props.onEndReachedThreshold).toBe('number');
    });

    it('renders a load-more affordance while more history remains', () => {
        const tree = renderScreen({
            transactions: makeHistory(5),
            loading: false,
            refreshing: false,
            error: null,
            hasMore: true,
            staleCache: false,
        });

        const spinners = tree.root.findAllByType(ActivityIndicator);
        expect(spinners.length).toBeGreaterThanOrEqual(1);
    });
});

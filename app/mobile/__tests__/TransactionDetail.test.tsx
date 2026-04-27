import React from 'react';
import render from 'react-test-renderer';
import TransactionDetailScreen from '../app/transaction/[id]';

jest.mock('expo-router', () => ({
    useLocalSearchParams: () => ({
        id: '1234567890',
        amount: '100.5000000',
        asset: 'USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335XOP3IA2M65BZDCCXN2YRC2TH',
        memo: 'Test payment',
        timestamp: '2026-02-21T08:00:00Z',
        txHash: 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd',
        source: 'GTESTSOURCE12345678901234567890123456789012345678901234567890',
        destination: 'GTESTDEST1234567890123456789012345678901234567890123456789012',
        status: 'Success',
    }),
    useRouter: () => ({ back: jest.fn() }),
}));

jest.mock('react-native-safe-area-context', () => ({
    SafeAreaView: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

jest.mock('expo-clipboard', () => ({
    setStringAsync: jest.fn(() => Promise.resolve()),
}));

jest.mock('expo-haptics', () => ({
    selectionAsync: jest.fn(),
    notificationAsync: jest.fn(),
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
            textSecondary: '#666',
            textMuted: '#999',
            primary: '#111',
            primaryForeground: '#fff',
            buttonPrimaryBg: '#111',
            buttonPrimaryText: '#fff',
            link: '#0A7EA4',
            status: {
                success: '#10B981',
                successBg: '#ECFDF5',
                warning: '#F59E0B',
                warningBg: '#FFF3E5',
                error: '#EF4444',
                errorBg: '#FEF2F2',
            },
        },
        isDark: false,
    }),
}));

jest.mock('../services/cache', () => ({
    findTransactionInCache: jest.fn(() => Promise.resolve(null)),
}));

function collectText(node: unknown): string[] {
    if (typeof node === 'string') return [node];
    if (Array.isArray(node)) return node.flatMap(collectText);
    if (node && typeof node === 'object') {
        const n = node as Record<string, unknown>;
        return [...collectText(n['children']), ...collectText(n['props'])];
    }
    return [];
}

describe('<TransactionDetailScreen />', () => {
    it('renders transaction details with amount and asset', () => {
        let tree: render.ReactTestRenderer;
        render.act(() => {
            tree = render.create(<TransactionDetailScreen />);
        });

        const texts = collectText(tree!.toJSON());
        expect(texts.some((t) => t.includes('100.50'))).toBe(true);
        expect(texts.some((t) => t.includes('USDC'))).toBe(true);
        expect(texts.some((t) => t.includes('Success'))).toBe(true);
    });

    it('renders copyable fields for hash, addresses, and memo', () => {
        let tree: render.ReactTestRenderer;
        render.act(() => {
            tree = render.create(<TransactionDetailScreen />);
        });

        const texts = collectText(tree!.toJSON());
        expect(texts.some((t) => t.includes('Transaction Hash'))).toBe(true);
        expect(texts.some((t) => t.includes('Sender'))).toBe(true);
        expect(texts.some((t) => t.includes('Recipient'))).toBe(true);
        expect(texts.some((t) => t.includes('Memo'))).toBe(true);
    });

    it('renders status timeline steps', () => {
        let tree: render.ReactTestRenderer;
        render.act(() => {
            tree = render.create(<TransactionDetailScreen />);
        });

        const texts = collectText(tree!.toJSON());
        expect(texts.some((t) => t.includes('Transaction Initiated'))).toBe(true);
        expect(texts.some((t) => t.includes('Validated on Network'))).toBe(true);
        expect(texts.some((t) => t.includes('Completed'))).toBe(true);
    });

    it('renders share receipt button', () => {
        let tree: render.ReactTestRenderer;
        render.act(() => {
            tree = render.create(<TransactionDetailScreen />);
        });

        const texts = collectText(tree!.toJSON());
        expect(texts.some((t) => t.includes('Share Receipt'))).toBe(true);
    });
});

'use client';

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { getQuickexApiBase } from '@/lib/api';

type WebhookStatus = 'active' | 'disabled';
type DeliveryStatus = 'sent' | 'failed' | 'pending' | 'dlq' | 'success' | 'failure' | string;

type Webhook = {
  id: string;
  publicKey?: string;
  url: string;
  status: WebhookStatus;
  events: string[] | null;
  signingSecret?: string;
  secretPreview?: string;
  minAmountStroops?: string;
  createdAt?: string;
  updatedAt?: string;
};

type DeliveryLog = {
  id: string;
  webhookId: string;
  endpointUrl: string;
  eventType: string;
  eventId: string;
  status: DeliveryStatus;
  attempts: number;
  lastError?: string;
  httpStatus?: number;
  responseBody?: string;
  createdAt: string;
  deliveredAt?: string;
};

type DeliveryStatusDetail = {
  eventId: string;
  eventType: string;
  status: DeliveryStatus;
  attempts: number;
  maxAttempts: number;
  lastError?: string;
  dlqReason?: string;
  nextRetryAt?: string;
  httpStatus?: number;
  responseBody?: string;
  createdAt: string;
  updatedAt: string;
  deliveredAt?: string;
  replayCount: number;
  lastReplayAt?: string;
};

type ReplayLog = {
  id: string;
  eventType: string;
  eventId: string;
  status: string;
  reason?: string;
  triggeredBy: string;
  deliverySuccess?: boolean;
  createdAt: string;
};

type Stats = {
  totalSent: number;
  totalFailed: number;
  pendingRetries: number;
  lastDeliveryAt?: string;
  lastError?: string;
};

type RedeliverResponse = {
  queued: boolean;
  message: string;
  replayId?: string;
  deliverySuccess?: boolean;
};

type TestWebhookResponse = {
  success: boolean;
  webhook_id: string;
  target_url: string;
  http_status: number | null;
  response_body: string | null;
  latency_ms: number;
  sent_at: string;
  event_type: string;
  event_id: string;
  signature_included: boolean;
};

type Paginated<T> = {
  data: T[];
  next_cursor: string | null;
  has_more: boolean;
};

type WebhookApiResponse = {
  id: string;
  publicKey: string;
  webhookUrl: string;
  label?: string;
  secret?: string;
  events: string[] | null;
  minAmountStroops: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
};

type DeliveryLogApiResponse = Omit<DeliveryLog, 'webhookId' | 'endpointUrl'>;

const EVENT_TYPES = [
  'EscrowDeposited',
  'EscrowWithdrawn',
  'EscrowRefunded',
  'payment.received',
  'username.claimed',
  'recurring.payment.due',
  'recurring.payment.executed',
  'recurring.payment.failed',
  'recurring.payment.cancelled',
  'recurring.link.created',
  'recurring.link.updated',
  'recurring.link.paused',
  'recurring.link.resumed',
  'recurring.link.completed',
];

const DEFAULT_PUBLIC_KEY = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PUBLIC_KEY_REGEX = /^G[A-Z2-7]{55}$/;
const PUBLIC_KEY_STORAGE_CANDIDATES = [
  'quickex.publicKey',
  'quickex.walletPublicKey',
  'walletPublicKey',
  'publicKey',
];

const SAMPLE_WEBHOOKS: Webhook[] = [
  {
    id: 'wh_sample_payments',
    publicKey: DEFAULT_PUBLIC_KEY,
    url: 'https://integrator.example/webhooks/quickex',
    status: 'active',
    events: ['payment.received', 'recurring.payment.failed'],
    signingSecret: 'whsec_sample_redacted_value',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 26).toISOString(),
    updatedAt: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
  },
  {
    id: 'wh_sample_ops',
    publicKey: DEFAULT_PUBLIC_KEY,
    url: 'https://ops.example/hooks/contracts',
    status: 'disabled',
    events: ['EscrowDeposited', 'EscrowRefunded'],
    signingSecret: 'whsec_disabled_sample_value',
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 96).toISOString(),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 4).toISOString(),
  },
];

const SAMPLE_DELIVERIES: DeliveryLog[] = [
  {
    id: 'dlv_sample_1',
    webhookId: 'wh_sample_payments',
    endpointUrl: 'https://integrator.example/webhooks/quickex',
    eventType: 'payment.received',
    eventId: 'evt_testnet_01HZZ8',
    status: 'sent',
    attempts: 1,
    httpStatus: 200,
    responseBody: '{"ok":true}',
    createdAt: new Date(Date.now() - 1000 * 60 * 50).toISOString(),
    deliveredAt: new Date(Date.now() - 1000 * 60 * 49).toISOString(),
  },
  {
    id: 'dlv_sample_2',
    webhookId: 'wh_sample_payments',
    endpointUrl: 'https://integrator.example/webhooks/quickex',
    eventType: 'recurring.payment.failed',
    eventId: 'evt_testnet_01HZZ9',
    status: 'failed',
    attempts: 3,
    httpStatus: 503,
    lastError: 'Endpoint returned HTTP 503 Service Unavailable',
    responseBody: 'upstream temporarily unavailable',
    createdAt: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
  },
  {
    id: 'dlv_sample_3',
    webhookId: 'wh_sample_ops',
    endpointUrl: 'https://ops.example/hooks/contracts',
    eventType: 'EscrowDeposited',
    eventId: 'evt_testnet_01HZZA',
    status: 'pending',
    attempts: 1,
    httpStatus: 202,
    createdAt: new Date(Date.now() - 1000 * 60 * 14).toISOString(),
  },
];

function resolveInitialPublicKey(): string {
  if (typeof window !== 'undefined') {
    const params = new URLSearchParams(window.location.search);
    const fromQuery = params.get('publicKey')?.trim() || params.get('public_key')?.trim();
    if (fromQuery && PUBLIC_KEY_REGEX.test(fromQuery)) return fromQuery;

    for (const key of PUBLIC_KEY_STORAGE_CANDIDATES) {
      const value = window.localStorage.getItem(key)?.trim();
      if (value && PUBLIC_KEY_REGEX.test(value)) return value;
    }
  }

  const fromEnv = process.env.NEXT_PUBLIC_QUICKEX_WEBHOOK_PUBLIC_KEY?.trim();
  if (fromEnv && PUBLIC_KEY_REGEX.test(fromEnv)) return fromEnv;

  return DEFAULT_PUBLIC_KEY;
}

function getAuthHeaders(apiKey: string): HeadersInit {
  return apiKey.trim() ? { Authorization: `Bearer ${apiKey.trim()}` } : {};
}

async function apiFetch<T>(path: string, apiKey = '', init?: RequestInit): Promise<T> {
  const res = await fetch(`${getQuickexApiBase()}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeaders(apiKey),
      ...init?.headers,
    },
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({} as { message?: string }));
    throw new Error(body?.message ?? `Request failed: ${res.status}`);
  }

  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

function toWebhook(row: WebhookApiResponse): Webhook {
  return {
    id: row.id,
    publicKey: row.publicKey,
    url: row.webhookUrl,
    status: row.enabled ? 'active' : 'disabled',
    events: row.events,
    signingSecret: row.secret,
    secretPreview: redactSecret(row.secret),
    minAmountStroops: row.minAmountStroops,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function normalizeWebhookList(response: Paginated<WebhookApiResponse> | WebhookApiResponse[]): Webhook[] {
  const rows = Array.isArray(response) ? response : response.data;
  return rows.map(toWebhook);
}

function normalizeDeliveryLogs(
  response: Paginated<DeliveryLogApiResponse> | DeliveryLogApiResponse[],
  webhook: Webhook,
): DeliveryLog[] {
  const rows = Array.isArray(response) ? response : response.data;
  return rows.map((row) => ({
    ...row,
    webhookId: webhook.id,
    endpointUrl: webhook.url,
  }));
}

function redactSecret(secret?: string): string {
  if (!secret) return 'Not available after creation';
  if (secret.length <= 8) return '••••••••';
  return `${secret.slice(0, 6)}…${secret.slice(-4)}`;
}

function redactSensitiveText(value?: string | null): string {
  if (!value) return '—';
  return value
    .replace(/(whsec_|sec_|sk_live_|sk_test_)[A-Za-z0-9_\-]+/g, '$1••••••••')
    .replace(/(authorization|api[-_ ]?key|signature|secret|token)(["'\s:=]+)([^,}\]\s"']+)/gi, '$1$2••••••••')
    .slice(0, 1200);
}

function formatDate(value?: string): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function statusClasses(status: DeliveryStatus): string {
  const normalized = status.toLowerCase();
  if (['sent', 'success', 'delivered'].includes(normalized)) {
    return 'bg-success-soft text-success border-success-soft';
  }
  if (['failed', 'failure', 'dlq', 'dead_letter'].includes(normalized)) {
    return 'bg-danger-soft text-danger border-danger-soft';
  }
  return 'bg-warning-soft text-warning border-warning-soft';
}

function endpointHost(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.host;
  } catch {
    return url;
  }
}

function buildAttemptHistory(log: DeliveryLog, detail: DeliveryStatusDetail | null) {
  const attempts = Math.max(detail?.attempts ?? log.attempts ?? 1, 1);
  return Array.from({ length: attempts }, (_, index) => {
    const attemptNumber = index + 1;
    const isLast = attemptNumber === attempts;
    return {
      attemptNumber,
      status: isLast ? (detail?.status ?? log.status) : 'retried',
      httpStatus: isLast ? (detail?.httpStatus ?? log.httpStatus) : undefined,
      error: isLast ? (detail?.lastError ?? detail?.dlqReason ?? log.lastError) : undefined,
      timestamp: isLast ? (detail?.deliveredAt ?? detail?.updatedAt ?? log.deliveredAt ?? log.createdAt) : log.createdAt,
    };
  });
}

export default function WebhooksPage() {
  const [publicKey, setPublicKey] = useState(DEFAULT_PUBLIC_KEY);
  const [apiKey, setApiKey] = useState('');
  const [webhooks, setWebhooks] = useState<Webhook[]>(SAMPLE_WEBHOOKS);
  const [deliveries, setDeliveries] = useState<DeliveryLog[]>(SAMPLE_DELIVERIES);
  const [selectedWebhookId, setSelectedWebhookId] = useState<string>(SAMPLE_WEBHOOKS[0]?.id ?? '');
  const [selectedDeliveryId, setSelectedDeliveryId] = useState<string>(SAMPLE_DELIVERIES[0]?.id ?? '');
  const [selectedDeliveryDetail, setSelectedDeliveryDetail] = useState<DeliveryStatusDetail | null>(null);
  const [replayHistory, setReplayHistory] = useState<ReplayLog[]>([]);
  const [stats, setStats] = useState<Record<string, Stats>>({});
  const [loading, setLoading] = useState(false);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>('Showing sample delivery data. Enter a public key and refresh to load backend records.');
  const [statusFilter, setStatusFilter] = useState('all');
  const [eventFilter, setEventFilter] = useState('all');
  const [endpointFilter, setEndpointFilter] = useState('all');
  const [newWebhookUrl, setNewWebhookUrl] = useState('');
  const [newWebhookEvents, setNewWebhookEvents] = useState<string[]>(['payment.received']);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);

  useEffect(() => {
    setPublicKey(resolveInitialPublicKey());
    if (typeof window !== 'undefined') {
      setApiKey(window.sessionStorage.getItem('quickex.webhookApiKey') ?? '');
    }
  }, []);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.sessionStorage.setItem('quickex.webhookApiKey', apiKey);
    }
  }, [apiKey]);

  const selectedWebhook = useMemo(
    () => webhooks.find((webhook) => webhook.id === selectedWebhookId) ?? null,
    [selectedWebhookId, webhooks],
  );

  const selectedDelivery = useMemo(
    () => deliveries.find((delivery) => delivery.id === selectedDeliveryId) ?? null,
    [selectedDeliveryId, deliveries],
  );

  const availableEvents = useMemo(
    () => Array.from(new Set(deliveries.map((delivery) => delivery.eventType))).sort(),
    [deliveries],
  );

  const filteredDeliveries = useMemo(() => {
    return deliveries.filter((delivery) => {
      const statusMatches = statusFilter === 'all' || delivery.status.toLowerCase() === statusFilter;
      const eventMatches = eventFilter === 'all' || delivery.eventType === eventFilter;
      const endpointMatches = endpointFilter === 'all' || delivery.webhookId === endpointFilter;
      return statusMatches && eventMatches && endpointMatches;
    });
  }, [deliveries, endpointFilter, eventFilter, statusFilter]);

  const selectedStats = selectedWebhook ? stats[selectedWebhook.id] : undefined;

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    setNotice(null);
    setSelectedDeliveryDetail(null);
    setReplayHistory([]);

    try {
      const webhookResponse = await apiFetch<Paginated<WebhookApiResponse> | WebhookApiResponse[]>(
        `/webhooks/${encodeURIComponent(publicKey)}?limit=50`,
        apiKey,
      );
      const loadedWebhooks = normalizeWebhookList(webhookResponse);
      setWebhooks(loadedWebhooks);

      if (loadedWebhooks.length === 0) {
        setDeliveries([]);
        setSelectedWebhookId('');
        setSelectedDeliveryId('');
        setNotice('No webhook endpoints found for this public key yet. Create an endpoint to start receiving delivery logs.');
        return;
      }

      const [logGroups, statPairs] = await Promise.all([
        Promise.all(
          loadedWebhooks.map(async (webhook) => {
            const logs = await apiFetch<Paginated<DeliveryLogApiResponse> | DeliveryLogApiResponse[]>(
              `/webhooks/${encodeURIComponent(publicKey)}/${encodeURIComponent(webhook.id)}/logs?limit=50`,
              apiKey,
            );
            return normalizeDeliveryLogs(logs, webhook);
          }),
        ),
        Promise.all(
          loadedWebhooks.map(async (webhook) => {
            try {
              const stat = await apiFetch<Stats>(
                `/webhooks/${encodeURIComponent(publicKey)}/${encodeURIComponent(webhook.id)}/stats`,
                apiKey,
              );
              return [webhook.id, stat] as const;
            } catch {
              return [webhook.id, undefined] as const;
            }
          }),
        ),
      ]);

      const loadedDeliveries = logGroups.flat().sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
      setDeliveries(loadedDeliveries);
      setStats(
        Object.fromEntries(statPairs.filter((entry): entry is readonly [string, Stats] => Boolean(entry[1]))),
      );
      setSelectedWebhookId((current) => (loadedWebhooks.some((webhook) => webhook.id === current) ? current : loadedWebhooks[0].id));
      setSelectedDeliveryId((current) => (loadedDeliveries.some((delivery) => delivery.id === current) ? current : (loadedDeliveries[0]?.id ?? '')));
      setNotice(loadedDeliveries.length > 0 ? 'Loaded webhook delivery outcomes from the backend.' : 'Endpoints loaded. No deliveries have been recorded yet.');
    } catch (err) {
      setError((err as Error).message);
      setWebhooks(SAMPLE_WEBHOOKS);
      setDeliveries(SAMPLE_DELIVERIES);
      setSelectedWebhookId(SAMPLE_WEBHOOKS[0].id);
      setSelectedDeliveryId(SAMPLE_DELIVERIES[0].id);
      setNotice('Unable to reach webhook APIs, so sample data is shown for layout and testing.');
    } finally {
      setLoading(false);
    }
  }, [apiKey, publicKey]);

  useEffect(() => {
    if (!selectedDelivery || !selectedWebhook || selectedDelivery.id.startsWith('dlv_sample')) {
      setSelectedDeliveryDetail(null);
      setReplayHistory([]);
      return;
    }

    let cancelled = false;
    setDetailsLoading(true);
    setSelectedDeliveryDetail(null);
    setReplayHistory([]);

    Promise.all([
      apiFetch<DeliveryStatusDetail>(
        `/webhooks/${encodeURIComponent(publicKey)}/${encodeURIComponent(selectedWebhook.id)}/deliveries/${encodeURIComponent(selectedDelivery.eventType)}/${encodeURIComponent(selectedDelivery.eventId)}`,
        apiKey,
      ).catch(() => null),
      apiFetch<ReplayLog[]>(
        `/webhooks/${encodeURIComponent(publicKey)}/${encodeURIComponent(selectedWebhook.id)}/replays?limit=20`,
        apiKey,
      ).catch(() => []),
    ])
      .then(([detail, replays]) => {
        if (cancelled) return;
        setSelectedDeliveryDetail(detail);
        setReplayHistory(replays.filter((replay) => replay.eventId === selectedDelivery.eventId && replay.eventType === selectedDelivery.eventType));
      })
      .finally(() => {
        if (!cancelled) setDetailsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [apiKey, publicKey, selectedDelivery, selectedWebhook]);

  const handleToggleEvent = (event: string) => {
    setNewWebhookEvents((prev) => (prev.includes(event) ? prev.filter((item) => item !== event) : [...prev, event]));
  };

  const handleCreateWebhook = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!newWebhookUrl.trim()) return;
    setActionLoading('create');
    setError(null);

    try {
      const created = await apiFetch<WebhookApiResponse>(`/webhooks/${encodeURIComponent(publicKey)}`, apiKey, {
        method: 'POST',
        body: JSON.stringify({
          webhookUrl: newWebhookUrl.trim(),
          events: newWebhookEvents.length > 0 ? newWebhookEvents : null,
        }),
      });
      const next = toWebhook(created);
      setWebhooks((prev) => [next, ...prev]);
      setSelectedWebhookId(next.id);
      setNewWebhookUrl('');
      setNewWebhookEvents(['payment.received']);
      setIsCreateModalOpen(false);
      setNotice(`Endpoint created. Signing secret fingerprint: ${redactSecret(created.secret)}. Store the secret securely; it is redacted in this view.`);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setActionLoading(null);
    }
  };

  const handleDisableWebhook = async (webhook: Webhook) => {
    setActionLoading(`disable:${webhook.id}`);
    setError(null);
    try {
      const updated = await apiFetch<WebhookApiResponse>(
        `/webhooks/${encodeURIComponent(publicKey)}/${encodeURIComponent(webhook.id)}`,
        apiKey,
        {
          method: 'PUT',
          body: JSON.stringify({ enabled: false }),
        },
      );
      const next = toWebhook(updated);
      setWebhooks((prev) => prev.map((item) => (item.id === next.id ? next : item)));
      setNotice('Webhook endpoint disabled. Delivery logs remain available for inspection.');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setActionLoading(null);
    }
  };

  const handleTestWebhook = async (webhook: Webhook) => {
    setActionLoading(`test:${webhook.id}`);
    setError(null);
    try {
      const result = await apiFetch<TestWebhookResponse>(
        `/developer/webhooks/${encodeURIComponent(webhook.id)}/test`,
        apiKey,
        { method: 'POST' },
      );
      const syntheticLog: DeliveryLog = {
        id: `test_${result.event_id}`,
        webhookId: webhook.id,
        endpointUrl: webhook.url,
        eventType: result.event_type,
        eventId: result.event_id,
        status: result.success ? 'sent' : 'failed',
        attempts: 1,
        httpStatus: result.http_status ?? undefined,
        responseBody: result.response_body ?? undefined,
        createdAt: result.sent_at,
        deliveredAt: result.success ? result.sent_at : undefined,
        lastError: result.success ? undefined : result.response_body ?? 'Test delivery failed',
      };
      setDeliveries((prev) => [syntheticLog, ...prev]);
      setSelectedWebhookId(webhook.id);
      setSelectedDeliveryId(syntheticLog.id);
      setNotice(`Test delivery ${result.success ? 'succeeded' : 'failed'} in ${result.latency_ms}ms. Signature header was ${result.signature_included ? 'included' : 'omitted'}.`);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setActionLoading(null);
    }
  };

  const handleReplayDelivery = async (delivery: DeliveryLog) => {
    setActionLoading(`replay:${delivery.id}`);
    setError(null);
    try {
      const result = await apiFetch<RedeliverResponse>(
        `/webhooks/${encodeURIComponent(publicKey)}/${encodeURIComponent(delivery.webhookId)}/redeliver`,
        apiKey,
        {
          method: 'POST',
          body: JSON.stringify({ eventId: delivery.eventId, eventType: delivery.eventType }),
        },
      );
      setNotice(`${result.message}${result.replayId ? ` Replay ID: ${result.replayId}.` : ''}`);
      await loadData();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setActionLoading(null);
    }
  };

  const attemptHistory = selectedDelivery ? buildAttemptHistory(selectedDelivery, selectedDeliveryDetail) : [];

  return (
    <div className="container mx-auto max-w-7xl p-6 text-foreground">
      <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p className="text-sm font-semibold uppercase tracking-[0.2em] text-brand">Developer tools</p>
          <h1 className="mt-2 text-3xl font-black">Webhook Deliveries</h1>
          <p className="mt-2 max-w-3xl text-sm text-subtle">
            Inspect endpoint delivery outcomes, retries, response metadata, and signature verification hints for sample and testnet webhooks without leaving QuickEx.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={loadData}
            disabled={loading}
            className="rounded-xl bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? 'Refreshing…' : 'Refresh deliveries'}
          </button>
          <button
            onClick={() => setIsCreateModalOpen(true)}
            className="rounded-xl border border-border-strong px-4 py-2 text-sm font-semibold text-muted hover:bg-surface"
          >
            Create endpoint
          </button>
        </div>
      </div>

      <section className="mb-6 grid grid-cols-1 gap-4 rounded-3xl border border-border bg-card p-4 lg:grid-cols-[1fr_1fr_auto]">
        <label className="space-y-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-subtle">Public key</span>
          <input
            value={publicKey}
            onChange={(event) => setPublicKey(event.target.value.trim())}
            className="w-full rounded-xl border border-border-strong bg-background px-3 py-2 font-mono text-sm text-muted"
            placeholder="G..."
            aria-label="Stellar public key used to load webhooks"
          />
        </label>
        <label className="space-y-1">
          <span className="text-xs font-semibold uppercase tracking-wide text-subtle">Admin API key for protected actions</span>
          <input
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
            className="w-full rounded-xl border border-border-strong bg-background px-3 py-2 font-mono text-sm text-muted"
            placeholder="Optional Bearer token; stored in this browser session only"
            type="password"
            aria-label="API key for protected webhook actions"
          />
        </label>
        <div className="flex items-end">
          <p className="rounded-2xl bg-surface px-4 py-3 text-xs text-subtle">
            Secrets, signatures, authorization headers, and response bodies are redacted before display.
          </p>
        </div>
      </section>

      {error && (
        <div className="mb-4 flex items-start justify-between rounded-2xl border border-danger-soft bg-danger-soft px-4 py-3 text-sm text-danger">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="ml-4 font-bold">Dismiss</button>
        </div>
      )}
      {notice && (
        <div className="mb-4 rounded-2xl border border-border bg-surface px-4 py-3 text-sm text-muted">
          {notice}
        </div>
      )}

      <div className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="rounded-3xl border border-border bg-card p-5">
          <p className="text-xs font-semibold uppercase text-subtle">Endpoints</p>
          <p className="mt-2 text-3xl font-black">{webhooks.length}</p>
          <p className="text-sm text-subtle">{webhooks.filter((webhook) => webhook.status === 'active').length} active</p>
        </div>
        <div className="rounded-3xl border border-border bg-card p-5">
          <p className="text-xs font-semibold uppercase text-subtle">Delivered</p>
          <p className="mt-2 text-3xl font-black text-success">{deliveries.filter((delivery) => ['sent', 'success', 'delivered'].includes(delivery.status.toLowerCase())).length}</p>
          <p className="text-sm text-subtle">Successful outcomes in the current result set</p>
        </div>
        <div className="rounded-3xl border border-border bg-card p-5">
          <p className="text-xs font-semibold uppercase text-subtle">Needs attention</p>
          <p className="mt-2 text-3xl font-black text-danger">{deliveries.filter((delivery) => ['failed', 'failure', 'dlq'].includes(delivery.status.toLowerCase())).length}</p>
          <p className="text-sm text-subtle">Failed or dead-lettered deliveries</p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[320px_1fr]">
        <aside className="space-y-4">
          <section className="overflow-hidden rounded-3xl border border-border bg-card">
            <div className="border-b border-border p-4">
              <h2 className="font-bold">Endpoints</h2>
              <p className="mt-1 text-xs text-subtle">Filter delivery outcomes by receiver endpoint.</p>
            </div>
            <ul className="divide-y divide-border">
              {webhooks.length === 0 && <li className="p-4 text-center text-sm text-subtle">No endpoints found.</li>}
              {webhooks.map((webhook) => (
                <li key={webhook.id}>
                  <button
                    onClick={() => {
                      setSelectedWebhookId(webhook.id);
                      setEndpointFilter(webhook.id);
                    }}
                    className={`w-full p-4 text-left hover:bg-surface ${selectedWebhookId === webhook.id ? 'bg-brand-soft' : ''}`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-semibold" title={webhook.url}>{endpointHost(webhook.url)}</p>
                        <p className="mt-1 truncate text-xs text-subtle">{webhook.url}</p>
                      </div>
                      <span className={`shrink-0 rounded-full px-2 py-1 text-xs ${webhook.status === 'active' ? 'bg-success-soft text-success' : 'bg-surface text-subtle'}`}>
                        {webhook.status}
                      </span>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-1">
                      {(webhook.events ?? ['all events']).slice(0, 3).map((event) => (
                        <span key={event} className="rounded-full bg-surface px-2 py-1 text-[11px] text-subtle">{event}</span>
                      ))}
                      {(webhook.events?.length ?? 0) > 3 && <span className="text-[11px] text-faint">+{(webhook.events?.length ?? 0) - 3}</span>}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </section>

          {selectedWebhook && (
            <section className="rounded-3xl border border-border bg-card p-4">
              <h3 className="font-bold">Signature safety</h3>
              <dl className="mt-4 space-y-3 text-sm">
                <div>
                  <dt className="text-xs font-semibold uppercase text-subtle">Secret fingerprint</dt>
                  <dd className="mt-1 font-mono text-muted">{redactSecret(selectedWebhook.signingSecret)}</dd>
                </div>
                <div>
                  <dt className="text-xs font-semibold uppercase text-subtle">Header scheme</dt>
                  <dd className="mt-1 text-muted">HMAC-SHA256 over timestamp + payload</dd>
                </div>
                <div>
                  <dt className="text-xs font-semibold uppercase text-subtle">Expected headers</dt>
                  <dd className="mt-1 font-mono text-xs text-muted">X-QX-Signature, X-QX-Timestamp, X-QX-Event, X-QX-Event-Id</dd>
                </div>
              </dl>
              <p className="mt-4 rounded-2xl bg-warning-soft p-3 text-xs text-warning">
                Full secrets and signature values are intentionally hidden. Rotate or regenerate secrets from the API when you suspect exposure.
              </p>
            </section>
          )}
        </aside>

        <main className="space-y-6">
          <section className="rounded-3xl border border-border bg-card p-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
              <div>
                <h2 className="text-xl font-bold">Delivery outcomes</h2>
                <p className="mt-1 text-sm text-subtle">Review status, HTTP response metadata, retries, and replay options.</p>
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                <label className="text-xs font-semibold uppercase text-subtle">
                  Status
                  <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} className="mt-1 w-full rounded-xl border border-border-strong bg-background px-3 py-2 text-sm normal-case text-muted">
                    <option value="all">All statuses</option>
                    <option value="sent">Sent</option>
                    <option value="failed">Failed</option>
                    <option value="pending">Pending</option>
                    <option value="dlq">DLQ</option>
                  </select>
                </label>
                <label className="text-xs font-semibold uppercase text-subtle">
                  Event type
                  <select value={eventFilter} onChange={(event) => setEventFilter(event.target.value)} className="mt-1 w-full rounded-xl border border-border-strong bg-background px-3 py-2 text-sm normal-case text-muted">
                    <option value="all">All events</option>
                    {availableEvents.map((event) => <option key={event} value={event}>{event}</option>)}
                  </select>
                </label>
                <label className="text-xs font-semibold uppercase text-subtle">
                  Endpoint
                  <select value={endpointFilter} onChange={(event) => setEndpointFilter(event.target.value)} className="mt-1 w-full rounded-xl border border-border-strong bg-background px-3 py-2 text-sm normal-case text-muted">
                    <option value="all">All endpoints</option>
                    {webhooks.map((webhook) => <option key={webhook.id} value={webhook.id}>{endpointHost(webhook.url)}</option>)}
                  </select>
                </label>
              </div>
            </div>

            <div className="mt-4 overflow-x-auto">
              <table className="w-full min-w-[760px] text-left text-sm">
                <thead className="border-y border-border text-xs uppercase text-subtle">
                  <tr>
                    <th className="px-3 py-3 font-semibold">Status</th>
                    <th className="px-3 py-3 font-semibold">Event</th>
                    <th className="px-3 py-3 font-semibold">Endpoint</th>
                    <th className="px-3 py-3 font-semibold">HTTP</th>
                    <th className="px-3 py-3 font-semibold">Attempts</th>
                    <th className="px-3 py-3 font-semibold">Created</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filteredDeliveries.length === 0 && (
                    <tr><td colSpan={6} className="px-3 py-8 text-center text-subtle">No deliveries match these filters.</td></tr>
                  )}
                  {filteredDeliveries.map((delivery) => (
                    <tr
                      key={delivery.id}
                      onClick={() => {
                        setSelectedDeliveryId(delivery.id);
                        setSelectedWebhookId(delivery.webhookId);
                      }}
                      className={`cursor-pointer hover:bg-surface ${selectedDeliveryId === delivery.id ? 'bg-brand-soft' : ''}`}
                    >
                      <td className="px-3 py-3"><span className={`rounded-full border px-2 py-1 text-xs font-semibold ${statusClasses(delivery.status)}`}>{delivery.status}</span></td>
                      <td className="px-3 py-3">
                        <p className="font-semibold">{delivery.eventType}</p>
                        <p className="font-mono text-xs text-subtle">{delivery.eventId}</p>
                      </td>
                      <td className="px-3 py-3 text-muted">{endpointHost(delivery.endpointUrl)}</td>
                      <td className="px-3 py-3 font-mono text-muted">{delivery.httpStatus ?? '—'}</td>
                      <td className="px-3 py-3 text-muted">{delivery.attempts}</td>
                      <td className="px-3 py-3 text-subtle">{formatDate(delivery.createdAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="grid grid-cols-1 gap-6 2xl:grid-cols-[1.1fr_0.9fr]">
            <div className="rounded-3xl border border-border bg-card p-5">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <h2 className="text-xl font-bold">Delivery detail</h2>
                  <p className="mt-1 text-sm text-subtle">Request metadata, receiver response, retry schedule, and signature context.</p>
                </div>
                {selectedDelivery && (
                  <button
                    onClick={() => handleReplayDelivery(selectedDelivery)}
                    disabled={actionLoading === `replay:${selectedDelivery.id}` || selectedDelivery.id.startsWith('dlv_sample')}
                    className="rounded-xl border border-border-strong px-3 py-2 text-sm font-semibold text-muted hover:bg-surface disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {actionLoading === `replay:${selectedDelivery.id}` ? 'Replaying…' : 'Replay delivery'}
                  </button>
                )}
              </div>

              {!selectedDelivery ? (
                <div className="mt-6 rounded-2xl bg-surface p-8 text-center text-sm text-subtle">Select a delivery to inspect details.</div>
              ) : (
                <div className="mt-5 space-y-5">
                  {detailsLoading && <p className="text-sm text-subtle">Loading detailed delivery status…</p>}
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                    <div className="rounded-2xl bg-surface p-4">
                      <p className="text-xs font-semibold uppercase text-subtle">Request metadata</p>
                      <dl className="mt-3 space-y-2 text-sm">
                        <div className="flex justify-between gap-4"><dt className="text-subtle">Method</dt><dd className="font-mono">POST</dd></div>
                        <div className="flex justify-between gap-4"><dt className="text-subtle">Endpoint</dt><dd className="truncate font-mono" title={selectedDelivery.endpointUrl}>{selectedDelivery.endpointUrl}</dd></div>
                        <div className="flex justify-between gap-4"><dt className="text-subtle">Event ID</dt><dd className="font-mono">{selectedDelivery.eventId}</dd></div>
                        <div className="flex justify-between gap-4"><dt className="text-subtle">Content-Type</dt><dd className="font-mono">application/json</dd></div>
                      </dl>
                    </div>
                    <div className="rounded-2xl bg-surface p-4">
                      <p className="text-xs font-semibold uppercase text-subtle">Signature info</p>
                      <dl className="mt-3 space-y-2 text-sm">
                        <div className="flex justify-between gap-4"><dt className="text-subtle">Algorithm</dt><dd className="font-mono">HMAC-SHA256</dd></div>
                        <div className="flex justify-between gap-4"><dt className="text-subtle">Secret</dt><dd className="font-mono">{selectedWebhook ? redactSecret(selectedWebhook.signingSecret) : '—'}</dd></div>
                        <div className="flex justify-between gap-4"><dt className="text-subtle">Signature</dt><dd className="font-mono">t=••••,v1=••••••••</dd></div>
                        <div className="flex justify-between gap-4"><dt className="text-subtle">Test header</dt><dd className="font-mono">X-QX-Test when sample</dd></div>
                      </dl>
                    </div>
                  </div>

                  <div>
                    <h3 className="mb-3 font-bold">Attempt history</h3>
                    <ol className="space-y-3">
                      {attemptHistory.map((attempt) => (
                        <li key={attempt.attemptNumber} className="rounded-2xl border border-border bg-background p-4">
                          <div className="flex flex-wrap items-center justify-between gap-3">
                            <p className="font-semibold">Attempt {attempt.attemptNumber}</p>
                            <span className={`rounded-full border px-2 py-1 text-xs font-semibold ${statusClasses(attempt.status)}`}>{attempt.status}</span>
                          </div>
                          <div className="mt-3 grid grid-cols-1 gap-2 text-sm md:grid-cols-3">
                            <p><span className="text-subtle">Time:</span> {formatDate(attempt.timestamp)}</p>
                            <p><span className="text-subtle">HTTP:</span> <span className="font-mono">{attempt.httpStatus ?? '—'}</span></p>
                            <p><span className="text-subtle">Error:</span> {redactSensitiveText(attempt.error)}</p>
                          </div>
                        </li>
                      ))}
                    </ol>
                  </div>

                  <div className="rounded-2xl border border-border bg-background p-4">
                    <h3 className="font-bold">Receiver response</h3>
                    <pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap rounded-xl bg-surface p-3 font-mono text-xs text-muted">{redactSensitiveText(selectedDeliveryDetail?.responseBody ?? selectedDelivery.responseBody ?? selectedDelivery.lastError)}</pre>
                  </div>

                  {(selectedDeliveryDetail?.nextRetryAt || selectedDeliveryDetail?.dlqReason || selectedDeliveryDetail?.replayCount) && (
                    <div className="rounded-2xl border border-warning-soft bg-warning-soft p-4 text-sm text-warning">
                      {selectedDeliveryDetail.nextRetryAt && <p>Next automatic retry: {formatDate(selectedDeliveryDetail.nextRetryAt)}</p>}
                      {selectedDeliveryDetail.dlqReason && <p>DLQ reason: {redactSensitiveText(selectedDeliveryDetail.dlqReason)}</p>}
                      {selectedDeliveryDetail.replayCount > 0 && <p>Manual replays: {selectedDeliveryDetail.replayCount} (last {formatDate(selectedDeliveryDetail.lastReplayAt)})</p>}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="space-y-6">
              <section className="rounded-3xl border border-border bg-card p-5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h2 className="text-xl font-bold">Endpoint detail</h2>
                    <p className="mt-1 text-sm text-subtle">Subscription status and operational summary.</p>
                  </div>
                  {selectedWebhook && selectedWebhook.status === 'active' && (
                    <button
                      onClick={() => handleDisableWebhook(selectedWebhook)}
                      disabled={actionLoading === `disable:${selectedWebhook.id}` || selectedWebhook.id.startsWith('wh_sample')}
                      className="rounded-xl border border-danger-soft px-3 py-2 text-sm font-semibold text-danger hover:bg-danger-soft disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      Disable
                    </button>
                  )}
                </div>
                {selectedWebhook ? (
                  <div className="mt-4 space-y-4">
                    <div className="break-all rounded-2xl bg-surface p-4 font-mono text-sm text-muted">{selectedWebhook.url}</div>
                    <dl className="grid grid-cols-2 gap-3 text-sm">
                      <div><dt className="text-subtle">ID</dt><dd className="font-mono">{selectedWebhook.id}</dd></div>
                      <div><dt className="text-subtle">Status</dt><dd>{selectedWebhook.status}</dd></div>
                      <div><dt className="text-subtle">Created</dt><dd>{formatDate(selectedWebhook.createdAt)}</dd></div>
                      <div><dt className="text-subtle">Updated</dt><dd>{formatDate(selectedWebhook.updatedAt)}</dd></div>
                      <div><dt className="text-subtle">Sent</dt><dd>{selectedStats?.totalSent ?? '—'}</dd></div>
                      <div><dt className="text-subtle">Failed</dt><dd>{selectedStats?.totalFailed ?? '—'}</dd></div>
                      <div><dt className="text-subtle">Pending retries</dt><dd>{selectedStats?.pendingRetries ?? '—'}</dd></div>
                      <div><dt className="text-subtle">Last delivery</dt><dd>{formatDate(selectedStats?.lastDeliveryAt)}</dd></div>
                    </dl>
                    <div>
                      <p className="mb-2 text-xs font-semibold uppercase text-subtle">Subscribed events</p>
                      <div className="flex flex-wrap gap-2">
                        {(selectedWebhook.events ?? ['all events']).map((event) => <span key={event} className="rounded-full bg-brand-soft px-2 py-1 text-xs text-brand">{event}</span>)}
                      </div>
                    </div>
                    <button
                      onClick={() => handleTestWebhook(selectedWebhook)}
                      disabled={actionLoading === `test:${selectedWebhook.id}` || selectedWebhook.id.startsWith('wh_sample')}
                      className="w-full rounded-xl bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {actionLoading === `test:${selectedWebhook.id}` ? 'Sending test…' : 'Send signed test event'}
                    </button>
                    <p className="text-xs text-subtle">Test events use backend developer support when available and may require an admin-scoped API key.</p>
                  </div>
                ) : (
                  <p className="mt-4 text-sm text-subtle">Select an endpoint to view configuration.</p>
                )}
              </section>

              <section className="rounded-3xl border border-border bg-card p-5">
                <h2 className="text-xl font-bold">Replay audit</h2>
                <p className="mt-1 text-sm text-subtle">Manual replay history for the selected delivery.</p>
                <div className="mt-4 space-y-3">
                  {replayHistory.length === 0 && <p className="rounded-2xl bg-surface p-4 text-sm text-subtle">No replay audit entries for this delivery.</p>}
                  {replayHistory.map((replay) => (
                    <div key={replay.id} className="rounded-2xl border border-border bg-background p-4 text-sm">
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-semibold">{replay.status}</span>
                        <span className="text-xs text-subtle">{formatDate(replay.createdAt)}</span>
                      </div>
                      <p className="mt-2 text-subtle">Triggered by {replay.triggeredBy}</p>
                      {replay.reason && <p className="mt-2 text-muted">{redactSensitiveText(replay.reason)}</p>}
                    </div>
                  ))}
                </div>
              </section>
            </div>
          </section>
        </main>
      </div>

      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg overflow-hidden rounded-3xl border border-border bg-card shadow-xl">
            <div className="flex items-center justify-between border-b border-border p-5">
              <h2 className="text-lg font-bold">Create webhook endpoint</h2>
              <button onClick={() => setIsCreateModalOpen(false)} className="text-subtle hover:text-muted" aria-label="Close create webhook modal">✕</button>
            </div>
            <form onSubmit={handleCreateWebhook}>
              <div className="space-y-4 p-5">
                <label className="block">
                  <span className="mb-1 block text-sm font-medium text-muted">Endpoint URL</span>
                  <input
                    type="url"
                    required
                    value={newWebhookUrl}
                    onChange={(event) => setNewWebhookUrl(event.target.value)}
                    placeholder="https://api.yourdomain.com/webhook"
                    className="w-full rounded-xl border border-border-strong bg-background px-3 py-2 text-sm text-muted"
                  />
                </label>
                <div>
                  <p className="mb-2 text-sm font-medium text-muted">Events to send</p>
                  <div className="max-h-56 space-y-2 overflow-y-auto rounded-xl border border-border p-3">
                    {EVENT_TYPES.map((event) => (
                      <label key={event} className="flex items-center gap-2 text-sm text-muted">
                        <input
                          type="checkbox"
                          checked={newWebhookEvents.includes(event)}
                          onChange={() => handleToggleEvent(event)}
                          className="rounded text-brand focus:ring-brand"
                        />
                        {event}
                      </label>
                    ))}
                  </div>
                </div>
                <p className="rounded-2xl bg-warning-soft p-3 text-xs text-warning">
                  If the API returns a signing secret, QuickEx will only show a redacted fingerprint here. Store the original response securely.
                </p>
              </div>
              <div className="flex justify-end gap-2 border-t border-border bg-background p-5">
                <button type="button" onClick={() => setIsCreateModalOpen(false)} className="rounded-xl border border-border-strong px-4 py-2 text-sm font-semibold text-muted hover:bg-surface">Cancel</button>
                <button type="submit" disabled={!newWebhookUrl || actionLoading === 'create'} className="rounded-xl bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-50">
                  {actionLoading === 'create' ? 'Creating…' : 'Create endpoint'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

'use client';

import React, { useState } from 'react';

type WebhookStatus = 'active' | 'disabled';

interface Webhook {
  id: string;
  url: string;
  status: WebhookStatus;
  events: string[];
  signingSecret: string;
  lastDeliveryStatus?: 'success' | 'failure';
}

const EVENT_TYPES = ['payment.received', 'payment.sent', 'kyc.updated', 'account.created'];

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState<Webhook[]>([
    {
      id: 'wh_1',
      url: 'https://api.example.com/webhooks/qiuckex',
      status: 'active',
      events: ['payment.received'],
      signingSecret: 'sec_test_secret_123',
    },
  ]);
  const [selectedWebhook, setSelectedWebhook] = useState<Webhook | null>(null);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newWebhookUrl, setNewWebhookUrl] = useState('');
  const [newWebhookEvents, setNewWebhookEvents] = useState<string[]>([]);
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, boolean>>({});

  const handleCreateWebhook = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWebhookUrl) return;
    const newWebhook: Webhook = {
      id: `wh_${Date.now()}`,
      url: newWebhookUrl,
      status: 'active',
      events: newWebhookEvents.length > 0 ? newWebhookEvents : ['payment.received'],
      signingSecret: `sec_${Math.random().toString(36).substr(2, 9)}`,
    };
    setWebhooks([...webhooks, newWebhook]);
    setIsCreateModalOpen(false);
    setNewWebhookUrl('');
    setNewWebhookEvents([]);
  };

  const handleToggleEvent = (event: string) => {
    setNewWebhookEvents(prev =>
      prev.includes(event) ? prev.filter(e => e !== event) : [...prev, event]
    );
  };

  const handleDisableWebhook = (id: string) => {
    setWebhooks(prev =>
      prev.map(wh => (wh.id === id ? { ...wh, status: 'disabled' } : wh))
    );
    if (selectedWebhook?.id === id) {
      setSelectedWebhook(prev => prev ? { ...prev, status: 'disabled' } : null);
    }
  };

  const handleTestWebhook = (id: string) => {
    // Simulate test delivery
    const isSuccess = Math.random() > 0.5;
    setWebhooks(prev =>
      prev.map(wh => (wh.id === id ? { ...wh, lastDeliveryStatus: isSuccess ? 'success' : 'failure' } : wh))
    );
    if (selectedWebhook?.id === id) {
      setSelectedWebhook(prev => prev ? { ...prev, lastDeliveryStatus: isSuccess ? 'success' : 'failure' } : null);
    }
    alert(`Test delivery ${isSuccess ? 'succeeded' : 'failed'}!`);
  };

  const toggleSecret = (id: string) => {
    setRevealedSecrets(prev => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Webhook Subscriptions</h1>
        <button
          onClick={() => setIsCreateModalOpen(true)}
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md transition-colors"
        >
          Create Webhook
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* List View */}
        <div className="md:col-span-1 bg-card border border-border rounded-lg shadow-sm overflow-hidden">
          <div className="p-4 border-b border-border bg-background">
            <h2 className="font-semibold text-muted">Endpoints</h2>
          </div>
          <ul className="divide-y divide-border">
            {webhooks.length === 0 && (
              <li className="p-4 text-sm text-subtle text-center">No webhooks found.</li>
            )}
            {webhooks.map(wh => (
              <li
                key={wh.id}
                onClick={() => setSelectedWebhook(wh)}
                className={`p-4 cursor-pointer hover:bg-background transition-colors ${selectedWebhook?.id === wh.id ? 'bg-brand-soft border-l-4 border-blue-500' : ''}`}
              >
                <div className="flex justify-between items-start mb-1">
                  <span className="font-medium text-sm truncate pr-2" title={wh.url}>{wh.url}</span>
                  <span className={`text-xs px-2 py-1 rounded-full ${wh.status === 'active' ? 'bg-success-soft text-success' : 'bg-surface text-foreground'}`}>
                    {wh.status}
                  </span>
                </div>
                <div className="text-xs text-subtle flex items-center space-x-2">
                  <span>{wh.events.length} events</span>
                  {wh.lastDeliveryStatus && (
                    <span className={`flex items-center ${wh.lastDeliveryStatus === 'success' ? 'text-success' : 'text-danger'}`}>
                      <span className="mr-1">•</span>
                      Last test: {wh.lastDeliveryStatus}
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>

        {/* Detail View */}
        <div className="md:col-span-2">
          {selectedWebhook ? (
            <div className="bg-card border border-border rounded-lg shadow-sm p-6">
              <div className="flex justify-between items-start mb-6">
                <div>
                  <h2 className="text-xl font-bold mb-2 break-all">{selectedWebhook.url}</h2>
                  <div className="flex space-x-2">
                    <span className={`text-xs px-2 py-1 rounded-full ${selectedWebhook.status === 'active' ? 'bg-success-soft text-success' : 'bg-surface text-foreground'}`}>
                      {selectedWebhook.status.toUpperCase()}
                    </span>
                    <span className="text-xs px-2 py-1 rounded-full bg-surface text-muted">
                      ID: {selectedWebhook.id}
                    </span>
                  </div>
                </div>
                <div className="flex space-x-2">
                  <button
                    onClick={() => handleTestWebhook(selectedWebhook.id)}
                    className="border border-border-strong text-muted px-3 py-1.5 rounded-md hover:bg-background text-sm transition-colors"
                  >
                    Test Webhook
                  </button>
                  {selectedWebhook.status === 'active' && (
                    <button
                      onClick={() => handleDisableWebhook(selectedWebhook.id)}
                      className="border border-danger-soft text-danger px-3 py-1.5 rounded-md hover:bg-danger-soft text-sm transition-colors"
                    >
                      Disable
                    </button>
                  )}
                </div>
              </div>

              <div className="space-y-6">
                <div>
                  <h3 className="text-sm font-semibold text-muted mb-2">Subscribed Events</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedWebhook.events.map(ev => (
                      <span key={ev} className="text-xs bg-brand-soft text-brand px-2 py-1 rounded-md">
                        {ev}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <h3 className="text-sm font-semibold text-muted mb-2">Signing Secret</h3>
                  <p className="text-xs text-subtle mb-2">Use this secret to verify that webhooks were sent by QuickEx.</p>
                  <div className="flex items-center">
                    <code className="bg-surface px-3 py-2 rounded-l-md text-sm font-mono border border-border border-r-0 flex-grow">
                      {revealedSecrets[selectedWebhook.id] ? selectedWebhook.signingSecret : '••••••••••••••••••••••••••••••••'}
                    </code>
                    <button
                      onClick={() => toggleSecret(selectedWebhook.id)}
                      className="bg-surface-strong hover:bg-surface-strong text-muted px-4 py-2 rounded-r-md text-sm border border-border border-l-0 transition-colors"
                    >
                      {revealedSecrets[selectedWebhook.id] ? 'Hide' : 'Reveal'}
                    </button>
                  </div>
                </div>
                
                {selectedWebhook.lastDeliveryStatus && (
                  <div>
                    <h3 className="text-sm font-semibold text-muted mb-2">Recent Test Delivery</h3>
                    <div className={`p-3 rounded-md border text-sm ${selectedWebhook.lastDeliveryStatus === 'success' ? 'bg-success-soft border-success-soft text-success' : 'bg-danger-soft border-danger-soft text-danger'}`}>
                      {selectedWebhook.lastDeliveryStatus === 'success' 
                        ? 'Test payload delivered successfully with HTTP 200 OK.' 
                        : 'Delivery failed. Endpoint returned a non-200 status code or timed out.'}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-background border border-border rounded-lg flex items-center justify-center h-64 text-subtle">
              Select a webhook to view details
            </div>
          )}
        </div>
      </div>

      {/* Create Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 bg-background/50 flex items-center justify-center z-50 p-4">
          <div className="bg-card rounded-lg shadow-xl w-full max-w-md overflow-hidden">
            <div className="p-4 border-b border-border flex justify-between items-center">
              <h2 className="text-lg font-bold">Create Webhook Endpoint</h2>
              <button onClick={() => setIsCreateModalOpen(false)} className="text-subtle hover:text-muted">
                ✕
              </button>
            </div>
            <form onSubmit={handleCreateWebhook}>
              <div className="p-4 space-y-4">
                <div>
                  <label className="block text-sm font-medium text-muted mb-1">Endpoint URL</label>
                  <input
                    type="url"
                    required
                    value={newWebhookUrl}
                    onChange={(e) => setNewWebhookUrl(e.target.value)}
                    placeholder="https://api.yourdomain.com/webhook"
                    className="w-full border border-border-strong rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-muted mb-2">Events to send</label>
                  <div className="space-y-2 border border-border rounded-md p-3 max-h-48 overflow-y-auto">
                    {EVENT_TYPES.map(ev => (
                      <label key={ev} className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          checked={newWebhookEvents.includes(ev)}
                          onChange={() => handleToggleEvent(ev)}
                          className="rounded text-brand focus:ring-brand"
                        />
                        <span className="text-sm text-muted">{ev}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </div>
              <div className="p-4 border-t border-border bg-background flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 border border-border-strong text-muted rounded-md text-sm hover:bg-surface transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!newWebhookUrl}
                  className="px-4 py-2 bg-blue-600 text-white rounded-md text-sm hover:bg-blue-700 disabled:opacity-50 transition-colors"
                >
                  Create Endpoint
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

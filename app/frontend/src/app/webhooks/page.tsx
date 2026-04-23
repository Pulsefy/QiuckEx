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
        <div className="md:col-span-1 bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden">
          <div className="p-4 border-b border-gray-200 bg-gray-50">
            <h2 className="font-semibold text-gray-700">Endpoints</h2>
          </div>
          <ul className="divide-y divide-gray-200">
            {webhooks.length === 0 && (
              <li className="p-4 text-sm text-gray-500 text-center">No webhooks found.</li>
            )}
            {webhooks.map(wh => (
              <li
                key={wh.id}
                onClick={() => setSelectedWebhook(wh)}
                className={`p-4 cursor-pointer hover:bg-gray-50 transition-colors ${selectedWebhook?.id === wh.id ? 'bg-blue-50 border-l-4 border-blue-500' : ''}`}
              >
                <div className="flex justify-between items-start mb-1">
                  <span className="font-medium text-sm truncate pr-2" title={wh.url}>{wh.url}</span>
                  <span className={`text-xs px-2 py-1 rounded-full ${wh.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>
                    {wh.status}
                  </span>
                </div>
                <div className="text-xs text-gray-500 flex items-center space-x-2">
                  <span>{wh.events.length} events</span>
                  {wh.lastDeliveryStatus && (
                    <span className={`flex items-center ${wh.lastDeliveryStatus === 'success' ? 'text-green-600' : 'text-red-600'}`}>
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
            <div className="bg-white border border-gray-200 rounded-lg shadow-sm p-6">
              <div className="flex justify-between items-start mb-6">
                <div>
                  <h2 className="text-xl font-bold mb-2 break-all">{selectedWebhook.url}</h2>
                  <div className="flex space-x-2">
                    <span className={`text-xs px-2 py-1 rounded-full ${selectedWebhook.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>
                      {selectedWebhook.status.toUpperCase()}
                    </span>
                    <span className="text-xs px-2 py-1 rounded-full bg-gray-100 text-gray-600">
                      ID: {selectedWebhook.id}
                    </span>
                  </div>
                </div>
                <div className="flex space-x-2">
                  <button
                    onClick={() => handleTestWebhook(selectedWebhook.id)}
                    className="border border-gray-300 text-gray-700 px-3 py-1.5 rounded-md hover:bg-gray-50 text-sm transition-colors"
                  >
                    Test Webhook
                  </button>
                  {selectedWebhook.status === 'active' && (
                    <button
                      onClick={() => handleDisableWebhook(selectedWebhook.id)}
                      className="border border-red-300 text-red-600 px-3 py-1.5 rounded-md hover:bg-red-50 text-sm transition-colors"
                    >
                      Disable
                    </button>
                  )}
                </div>
              </div>

              <div className="space-y-6">
                <div>
                  <h3 className="text-sm font-semibold text-gray-700 mb-2">Subscribed Events</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedWebhook.events.map(ev => (
                      <span key={ev} className="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded-md">
                        {ev}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <h3 className="text-sm font-semibold text-gray-700 mb-2">Signing Secret</h3>
                  <p className="text-xs text-gray-500 mb-2">Use this secret to verify that webhooks were sent by QuickEx.</p>
                  <div className="flex items-center">
                    <code className="bg-gray-100 px-3 py-2 rounded-l-md text-sm font-mono border border-gray-200 border-r-0 flex-grow">
                      {revealedSecrets[selectedWebhook.id] ? selectedWebhook.signingSecret : '••••••••••••••••••••••••••••••••'}
                    </code>
                    <button
                      onClick={() => toggleSecret(selectedWebhook.id)}
                      className="bg-gray-200 hover:bg-gray-300 text-gray-700 px-4 py-2 rounded-r-md text-sm border border-gray-200 border-l-0 transition-colors"
                    >
                      {revealedSecrets[selectedWebhook.id] ? 'Hide' : 'Reveal'}
                    </button>
                  </div>
                </div>
                
                {selectedWebhook.lastDeliveryStatus && (
                  <div>
                    <h3 className="text-sm font-semibold text-gray-700 mb-2">Recent Test Delivery</h3>
                    <div className={`p-3 rounded-md border text-sm ${selectedWebhook.lastDeliveryStatus === 'success' ? 'bg-green-50 border-green-200 text-green-800' : 'bg-red-50 border-red-200 text-red-800'}`}>
                      {selectedWebhook.lastDeliveryStatus === 'success' 
                        ? 'Test payload delivered successfully with HTTP 200 OK.' 
                        : 'Delivery failed. Endpoint returned a non-200 status code or timed out.'}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-gray-50 border border-gray-200 rounded-lg flex items-center justify-center h-64 text-gray-500">
              Select a webhook to view details
            </div>
          )}
        </div>
      </div>

      {/* Create Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-md overflow-hidden">
            <div className="p-4 border-b border-gray-200 flex justify-between items-center">
              <h2 className="text-lg font-bold">Create Webhook Endpoint</h2>
              <button onClick={() => setIsCreateModalOpen(false)} className="text-gray-400 hover:text-gray-600">
                ✕
              </button>
            </div>
            <form onSubmit={handleCreateWebhook}>
              <div className="p-4 space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Endpoint URL</label>
                  <input
                    type="url"
                    required
                    value={newWebhookUrl}
                    onChange={(e) => setNewWebhookUrl(e.target.value)}
                    placeholder="https://api.yourdomain.com/webhook"
                    className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Events to send</label>
                  <div className="space-y-2 border border-gray-200 rounded-md p-3 max-h-48 overflow-y-auto">
                    {EVENT_TYPES.map(ev => (
                      <label key={ev} className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          checked={newWebhookEvents.includes(ev)}
                          onChange={() => handleToggleEvent(ev)}
                          className="rounded text-blue-600 focus:ring-blue-500"
                        />
                        <span className="text-sm text-gray-700">{ev}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </div>
              <div className="p-4 border-t border-gray-200 bg-gray-50 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 border border-gray-300 text-gray-700 rounded-md text-sm hover:bg-gray-100 transition-colors"
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

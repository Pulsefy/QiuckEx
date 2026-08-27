import { useState } from 'react';

export function usePaymentLinkForm() {
  const [state, setState] = useState({
    linkName: '',
    linkDescription: '',
    amount: '',
    currency: 'USD',
    templateId: 'simple',
    templates: [ { id: 'simple', name: 'Simple', body: '' } ],
    lineItems: [ { id: '1', description: '', quantity: 1, rate: 0 } ],
    customer: { name: '', email: '', company: '', notes: '' },
  });
  const updateLink = (p: any) => setState((s) => ({ ...s, ...p }));
  const selectTemplate = (templateId: any) => setState((s) => ({ ...s, templateId }));
  const addTemplate = (template: any) => setState((s) => ({ ...s, templates: [...s.templates, template] }));
  const updateTemplate = (id: any, patch: any) => setState((s) => ({ ...s, templates: s.templates.map((t: any) => (t.id === id ? { ...t, ...patch } : t)) }));
  const deleteTemplate = (id: any) => setState((s) => ({ ...s, templates: s.templates.filter((t: any) => t.id !== id) }));
  const addLineItem = () => setState((s) => ({ ...s, lineItems: [...s.lineItems, { id: String(Date.now()), description: '', quantity: 1, rate: 0 }] }));
  const updateLineItem = (id: any, patch: any) => setState((s) => ({ ...s, lineItems: s.lineItems.map((li: any) => (li.id === id ? { ...li, ...patch } : li)) }));
  const removeLineItem = (id: any) => setState((s) => ({ ...s, lineItems: s.lineItems.filter((li: any) => li.id !== id) }));
  const updateCustomer = (patch: any) => setState((s) => ({ ...s, customer: { ...s.customer, ...patch } }));
  return { state, updateLink, selectTemplate, addTemplate, updateTemplate, deleteTemplate, addLineItem, updateLineItem, removeLineItem, updateCustomer };
}
export type PaymentLinkForm = ReturnType< usePaymentLinkForm >;

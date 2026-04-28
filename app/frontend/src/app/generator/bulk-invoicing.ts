export type InvoiceLineItem = {
  id: string;
  description: string;
  quantity: number;
  unitPrice: number;
};

export type InvoiceTemplate = {
  id: string;
  name: string;
  asset: string;
  notes: string;
  taxRate: number;
  lineItems: InvoiceLineItem[];
};

export type CustomerProfile = {
  id: string;
  name: string;
  email: string;
  address: string;
  username: string;
};

export type InvoicePreviewRow = {
  id: string;
  customerId: string;
  customerName: string;
  email: string;
  asset: string;
  memo: string;
  notes: string;
  referenceId: string;
  subtotal: number;
  taxAmount: number;
  total: number;
  lineItems: InvoiceLineItem[];
  username?: string;
  destination?: string;
};

export const TEMPLATE_STORAGE_KEY = 'quickex.bulkInvoice.templates.v2';
export const CUSTOMER_STORAGE_KEY = 'quickex.bulkInvoice.customers.v2';

export const DEFAULT_TEMPLATES: InvoiceTemplate[] = [
  {
    id: 'template-hosting',
    name: 'Monthly Hosting',
    asset: 'USDC',
    notes: 'Net 7 payment terms. Reply to this invoice email if line items need updates.',
    taxRate: 7.5,
    lineItems: [
      { id: 'line-hosting-retainer', description: 'Hosting retainer', quantity: 1, unitPrice: 120 },
      { id: 'line-support-hours', description: 'Support hours', quantity: 3, unitPrice: 40 },
    ],
  },
];

export const DEFAULT_CUSTOMERS: CustomerProfile[] = [
  {
    id: 'customer-alex',
    name: 'Alex Carter',
    email: 'alex@example.com',
    address: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
    username: '',
  },
  {
    id: 'customer-studio',
    name: 'Maple Studio',
    email: 'billing@maplestudio.dev',
    address: '',
    username: 'maplestudio',
  },
];

export const formatCurrencyAmount = (value: number): string =>
  value.toFixed(2).replace(/\.00$/, '.00');

export const calculateTemplateSubtotal = (template: InvoiceTemplate): number =>
  template.lineItems.reduce(
    (sum, item) => sum + Number(item.quantity) * Number(item.unitPrice),
    0,
  );

export const calculateTemplateTax = (template: InvoiceTemplate): number =>
  calculateTemplateSubtotal(template) * (template.taxRate / 100);

export const calculateTemplateTotal = (template: InvoiceTemplate): number =>
  calculateTemplateSubtotal(template) + calculateTemplateTax(template);

export const buildInvoicePreview = (
  template: InvoiceTemplate,
  customer: CustomerProfile,
  index: number,
): InvoicePreviewRow => {
  const subtotal = calculateTemplateSubtotal(template);
  const taxAmount = calculateTemplateTax(template);
  const total = subtotal + taxAmount;
  const safeTemplateName = template.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const safeCustomerName = customer.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

  return {
    id: `${template.id}-${customer.id}`,
    customerId: customer.id,
    customerName: customer.name,
    email: customer.email,
    asset: template.asset,
    memo: `${template.name} for ${customer.name}`,
    notes: template.notes,
    referenceId: `${safeTemplateName || 'invoice'}-${safeCustomerName || 'customer'}-${index + 1}`,
    subtotal,
    taxAmount,
    total,
    lineItems: template.lineItems.map((item) => ({ ...item })),
    username: customer.username || undefined,
    destination: customer.address || undefined,
  };
};

export const toBulkLinkPayload = (invoice: InvoicePreviewRow) => ({
  amount: Number(invoice.total.toFixed(2)),
  asset: invoice.asset,
  memo: invoice.memo,
  referenceId: invoice.referenceId,
  username: invoice.username,
  destination: invoice.destination,
});

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

export type BulkCsvDraftRow = {
  id: string;
  customerName: string;
  email: string;
  amount: string;
  asset: string;
  memo: string;
  referenceId: string;
  username: string;
  destination: string;
  acceptedAssets: string;
  errors: string[];
};

export type BulkCsvParseResult = {
  fileErrors: string[];
  rows: BulkCsvDraftRow[];
};

type BulkCsvColumns = Record<string, string>;

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

const STELLAR_ADDRESS_PATTERN = /^G[A-Z2-7]{55}$/;
const ASSET_CODE_PATTERN = /^[A-Z0-9]{1,12}$/;

const CSV_COLUMN_ALIASES: Record<string, keyof BulkCsvColumns> = {
  amount: 'amount',
  asset: 'asset',
  memo: 'memo',
  referenceid: 'referenceId',
  reference_id: 'referenceId',
  reference: 'referenceId',
  username: 'username',
  destination: 'destination',
  address: 'destination',
  stellaraddress: 'destination',
  stellar_address: 'destination',
  acceptedassets: 'acceptedAssets',
  accepted_assets: 'acceptedAssets',
  customer: 'customerName',
  customername: 'customerName',
  customer_name: 'customerName',
  name: 'customerName',
  email: 'email',
};

function normalizeCsvHeader(header: string): keyof BulkCsvColumns | null {
  const normalized = header.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_');
  return CSV_COLUMN_ALIASES[normalized] ?? null;
}

export function parseCsvLine(line: string): string[] {
  const values: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const next = line[index + 1];

    if (char === '"') {
      if (inQuotes && next === '"') {
        current += '"';
        index += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (char === ',' && !inQuotes) {
      values.push(current.trim());
      current = '';
      continue;
    }

    current += char;
  }

  values.push(current.trim());
  return values;
}

function toBulkCsvDraftRow(columns: BulkCsvColumns, index: number): BulkCsvDraftRow {
  const row: BulkCsvDraftRow = {
    id: `csv-row-${index}-${Math.random().toString(36).slice(2, 8)}`,
    customerName: columns.customerName ?? '',
    email: columns.email ?? '',
    amount: columns.amount ?? '',
    asset: (columns.asset ?? 'USDC').toUpperCase(),
    memo: columns.memo ?? '',
    referenceId: columns.referenceId ?? '',
    username: columns.username ?? '',
    destination: columns.destination ?? '',
    acceptedAssets: columns.acceptedAssets ?? '',
    errors: [],
  };

  return validateBulkCsvDraftRow(row);
}

export function validateBulkCsvDraftRow(row: BulkCsvDraftRow): BulkCsvDraftRow {
  const nextRow = {
    ...row,
    customerName: row.customerName.trim(),
    email: row.email.trim(),
    amount: row.amount.trim(),
    asset: row.asset.trim().toUpperCase() || 'USDC',
    memo: row.memo.trim(),
    referenceId: row.referenceId.trim(),
    username: row.username.trim(),
    destination: row.destination.trim(),
    acceptedAssets: row.acceptedAssets.trim(),
    errors: [] as string[],
  };

  const parsedAmount = Number(nextRow.amount);

  if (!nextRow.amount || Number.isNaN(parsedAmount) || parsedAmount <= 0) {
    nextRow.errors.push('Enter a valid positive amount.');
  }

  if (!ASSET_CODE_PATTERN.test(nextRow.asset)) {
    nextRow.errors.push('Asset codes must be 1-12 uppercase letters or numbers.');
  }

  if (!nextRow.username && !nextRow.destination) {
    nextRow.errors.push('Add either a QuickEx username or a Stellar destination.');
  }

  if (nextRow.destination && !STELLAR_ADDRESS_PATTERN.test(nextRow.destination)) {
    nextRow.errors.push('Destination must be a valid Stellar G-address.');
  }

  if (nextRow.acceptedAssets) {
    const invalidAcceptedAssets = nextRow.acceptedAssets
      .split('|')
      .map((item) => item.trim().toUpperCase())
      .filter((item) => item.length > 0)
      .some((item) => !ASSET_CODE_PATTERN.test(item));

    if (invalidAcceptedAssets) {
      nextRow.errors.push('Accepted assets must use pipe-separated asset codes like XLM|USDC.');
    }
  }

  return nextRow;
}

export function parseBulkInvoiceCsv(csvContent: string): BulkCsvParseResult {
  const lines = csvContent
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (lines.length === 0) {
    return {
      fileErrors: ['Upload a CSV file with a header row and at least one invoice row.'],
      rows: [],
    };
  }

  const rawHeaders = parseCsvLine(lines[0]);
  const headers = rawHeaders.map(normalizeCsvHeader);

  if (!headers.includes('amount')) {
    return {
      fileErrors: ['The CSV must include an "amount" column.'],
      rows: [],
    };
  }

  const unsupportedHeaders = rawHeaders.filter((header, index) => headers[index] === null);
  const fileErrors =
    unsupportedHeaders.length > 0
      ? [
          `Ignored unsupported columns: ${unsupportedHeaders.join(', ')}.`,
        ]
      : [];

  const rows = lines.slice(1).map((line, index) => {
    const values = parseCsvLine(line);
    const columns: BulkCsvColumns = {};

    headers.forEach((header, headerIndex) => {
      if (!header) {
        return;
      }
      columns[header] = values[headerIndex] ?? '';
    });

    return toBulkCsvDraftRow(columns, index);
  });

  return {
    fileErrors,
    rows,
  };
}

export function toBulkLinkPayloadFromCsvRow(row: BulkCsvDraftRow) {
  return {
    amount: Number(Number(row.amount).toFixed(2)),
    asset: row.asset,
    memo: row.memo || undefined,
    referenceId: row.referenceId || undefined,
    username: row.username || undefined,
    destination: row.destination || undefined,
    acceptedAssets: row.acceptedAssets
      ? row.acceptedAssets
          .split('|')
          .map((item) => item.trim().toUpperCase())
          .filter((item) => item.length > 0)
      : undefined,
  };
}

export function buildGeneratedLinksCsv(
  links: Array<{
    id: string;
    url: string;
    canonical: string;
    amount: string;
    asset: string;
    username?: string;
    destination?: string;
    referenceId?: string;
  }>,
): string {
  const headers = [
    'referenceId',
    'id',
    'amount',
    'asset',
    'username',
    'destination',
    'url',
    'canonical',
  ];

  const escapeCell = (value: string) => `"${value.replace(/"/g, '""')}"`;

  const rows = links.map((link) =>
    [
      link.referenceId ?? '',
      link.id,
      link.amount,
      link.asset,
      link.username ?? '',
      link.destination ?? '',
      link.url,
      link.canonical,
    ]
      .map((cell) => escapeCell(cell))
      .join(','),
  );

  return [headers.join(','), ...rows].join('\n');
}

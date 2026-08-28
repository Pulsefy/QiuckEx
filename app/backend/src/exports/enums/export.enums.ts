export enum ExportStatus {
  QUEUED = 'queued',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
}

export enum ExportType {
  TRANSACTIONS = 'transactions',
  LINKS = 'links',
  PAYMENTS = 'payments',
}

export enum ExportFormat {
  CSV = 'csv',
  JSON = 'json',
}

export enum ExportDeliveryMethod {
  WEBHOOK = 'webhook',
  EMAIL = 'email',
  DOWNLOAD = 'download',
}

/**
 * Backend origin for browser calls. Override in `.env.local`:
 * `NEXT_PUBLIC_QUICKEX_API_URL=https://api.example.com`
 */
export const getQuickexApiBase = (): string =>
  process.env.NEXT_PUBLIC_QUICKEX_API_URL?.replace(/\/$/, "") ??
  "http://localhost:4000";

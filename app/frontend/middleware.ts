import { NextRequest, NextResponse } from "next/server";

const CSP_HEADER_VALUE = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://horizon-testnet.stellar.org",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https:",
  "font-src 'self' data:",
  "connect-src 'self' https: wss:",
  "frame-ancestors 'none'",
].join("; ");

export async function middleware(request: NextRequest) {
  const pathname = request.nextUrl.pathname;

  if (pathname.startsWith("/_next/static") || pathname.startsWith("/_next/image")) {
    const staticRes = NextResponse.next();
    staticRes.headers.set("Content-Security-Policy", CSP_HEADER_VALUE);
    return staticRes;
  }

  const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
  const correlationId = request.headers.get("x-correlation-id") ?? undefined;

  const baseResponse = NextResponse.next();
  baseResponse.headers.set("Content-Security-Policy", CSP_HEADER_VALUE);
  baseResponse.headers.set("x-request-id", requestId);
  if (correlationId) {
    baseResponse.headers.set("x-correlation-id", correlationId);
  }

  if (request.method !== "GET") {
    return baseResponse;
  }

  const acceptHeader = request.headers.get("accept") ?? "";
  if (!acceptHeader.includes("text/html")) {
    return baseResponse;
  }

  const response = await fetch(request);
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("text/html")) {
    return baseResponse;
  }

  const html = await response.text();
  const payload = JSON.stringify({ requestId, correlationId });
  const injection = `<script>window.__REQUEST_HEADERS__=${payload};</script>`;
  const body = html.includes("</head>")
    ? html.replace("</head>", `${injection}</head>`)
    : html.includes("<body>")
    ? html.replace("<body>", `<body>${injection}`)
    : `${injection}${html}`;

  const headers = new Headers(response.headers);
  headers.set("Content-Security-Policy", CSP_HEADER_VALUE);
  headers.set("x-request-id", requestId);
  if (correlationId) {
    headers.set("x-correlation-id", correlationId);
  }

  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export const config = {
  matcher: ["/((?!_next/static|_next/image).*)"],
};

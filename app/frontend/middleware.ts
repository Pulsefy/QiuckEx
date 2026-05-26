import { NextRequest, NextResponse } from "next/server";

export async function middleware(request: NextRequest) {
  const pathname = request.nextUrl.pathname;

  if (pathname.startsWith("/_next/static") || pathname.startsWith("/_next/image")) {
    return NextResponse.next();
  }

  const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
  const correlationId = request.headers.get("x-correlation-id") ?? undefined;

  const baseResponse = NextResponse.next();
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

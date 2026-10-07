import http from "node:http";
import https from "node:https";

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade"
]);

function positiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export function parseBridgeUpstream(rawValue, { allowInsecureLocalhost = false } = {}) {
  const value = String(rawValue || "").trim();
  if (!value) throw new Error("BRIDGE_UPSTREAM_URL is required in bridge mode.");
  const upstream = new URL(value);
  const isLocalHttp = upstream.protocol === "http:"
    && ["127.0.0.1", "localhost", "::1"].includes(upstream.hostname);
  if (upstream.protocol !== "https:" && !(allowInsecureLocalhost && isLocalHttp)) {
    throw new Error("BRIDGE_UPSTREAM_URL must use HTTPS.");
  }
  if (upstream.username || upstream.password || upstream.search || upstream.hash) {
    throw new Error("BRIDGE_UPSTREAM_URL cannot contain credentials, a query, or a fragment.");
  }
  upstream.pathname = upstream.pathname.replace(/\/+$/u, "");
  return upstream;
}

function forwardedHeader(value) {
  if (Array.isArray(value)) return value.join(", ");
  return typeof value === "string" ? value : undefined;
}

function requestHeaders(request, target) {
  const headers = {};
  for (const [name, value] of Object.entries(request.headers)) {
    if (!HOP_BY_HOP_HEADERS.has(name.toLowerCase()) && name.toLowerCase() !== "host" && value !== undefined) {
      headers[name] = value;
    }
  }
  headers.host = target.host;
  headers["x-forwarded-host"] = forwardedHeader(request.headers.host) || "unknown";
  headers["x-forwarded-proto"] = forwardedHeader(request.headers["x-forwarded-proto"]) || "https";
  headers["x-forwarded-for"] = forwardedHeader(request.headers["x-forwarded-for"])
    || request.socket.remoteAddress
    || "unknown";
  headers["x-daybreak-bridge"] = "render-azure-v1";
  return headers;
}

function responseHeaders(headers) {
  const filtered = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!HOP_BY_HOP_HEADERS.has(name.toLowerCase()) && value !== undefined) filtered[name] = value;
  }
  filtered["x-daybreak-bridge"] = "render-azure-v1";
  return filtered;
}

export function createBridgeServer({
  upstreamUrl,
  timeoutMs = 120_000,
  allowInsecureLocalhost = false
}) {
  const upstream = parseBridgeUpstream(upstreamUrl, { allowInsecureLocalhost });
  const basePath = upstream.pathname === "/" ? "" : upstream.pathname;
  const transport = upstream.protocol === "https:" ? https : http;
  const normalizedTimeout = positiveInteger(timeoutMs, 120_000);

  const server = http.createServer((request, response) => {
    const incoming = new URL(request.url || "/", "http://bridge.local");
    const target = new URL(upstream);
    target.pathname = `${basePath}${incoming.pathname}` || "/";
    target.search = incoming.search;

    let responseStarted = false;
    const upstreamRequest = transport.request(target, {
      method: request.method,
      headers: requestHeaders(request, target),
      timeout: normalizedTimeout
    }, (upstreamResponse) => {
      responseStarted = true;
      response.writeHead(
        upstreamResponse.statusCode || 502,
        responseHeaders(upstreamResponse.headers)
      );
      upstreamResponse.pipe(response);
      upstreamResponse.on("error", () => response.destroy());
    });

    upstreamRequest.on("timeout", () => upstreamRequest.destroy(new Error("upstream_timeout")));
    upstreamRequest.on("error", () => {
      if (responseStarted || response.headersSent) {
        response.destroy();
        return;
      }
      response.writeHead(502, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "x-daybreak-bridge": "render-azure-v1"
      });
      response.end(JSON.stringify({ ok: false, error: "azure_upstream_unavailable" }));
    });
    request.on("aborted", () => upstreamRequest.destroy());
    request.pipe(upstreamRequest);
  });

  server.requestTimeout = normalizedTimeout + 10_000;
  server.headersTimeout = Math.min(60_000, normalizedTimeout);
  return server;
}

export function startBridgeServer({ upstreamUrl, port, host = "0.0.0.0", timeoutMs }) {
  const server = createBridgeServer({ upstreamUrl, timeoutMs });
  server.listen(port, host, () => {
    console.log(`Render-to-Azure compatibility bridge listening on ${host}:${port}.`);
  });
  return server;
}

const upstreamUrl = process.env.BRIDGE_UPSTREAM_URL?.trim();

if (upstreamUrl) {
  const { startBridgeServer } = await import("./bridge.mjs");
  startBridgeServer({
    upstreamUrl,
    port: Number(process.env.PORT || 8787),
    host: process.env.HOST || "0.0.0.0",
    timeoutMs: Number(process.env.BRIDGE_TIMEOUT_MS || 120_000)
  });
} else {
  await import("./server.js");
}

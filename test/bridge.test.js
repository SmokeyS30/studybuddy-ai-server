import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";
import { createBridgeServer, parseBridgeUpstream } from "../bridge.mjs";

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server.address().port;
}

async function close(server) {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

test("bridge streams method, path, headers, and body to a base path", async () => {
  const upstream = http.createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      response.writeHead(201, { "content-type": "application/json", connection: "close" });
      response.end(JSON.stringify({
        method: request.method,
        url: request.url,
        authorization: request.headers.authorization,
        bridge: request.headers["x-daybreak-bridge"],
        body: Buffer.concat(chunks).toString("utf8")
      }));
    });
  });
  const upstreamPort = await listen(upstream);
  const bridge = createBridgeServer({
    upstreamUrl: `http://127.0.0.1:${upstreamPort}/keepup`,
    allowInsecureLocalhost: true
  });
  const bridgePort = await listen(bridge);

  try {
    const response = await fetch(`http://127.0.0.1:${bridgePort}/v1/test?mode=1`, {
      method: "POST",
      headers: { authorization: "Bearer example", "content-type": "text/plain" },
      body: "unchanged-body"
    });
    assert.equal(response.status, 201);
    assert.equal(response.headers.get("x-daybreak-bridge"), "render-azure-v1");
    assert.deepEqual(await response.json(), {
      method: "POST",
      url: "/keepup/v1/test?mode=1",
      authorization: "Bearer example",
      bridge: "render-azure-v1",
      body: "unchanged-body"
    });
  } finally {
    await close(bridge);
    await close(upstream);
  }
});

test("bridge rejects unsafe upstream URLs", () => {
  assert.throws(() => parseBridgeUpstream("http://example.com"), /must use HTTPS/u);
  assert.throws(() => parseBridgeUpstream("https://user:pass@example.com"), /cannot contain credentials/u);
});

test("bridge returns a bounded error when Azure is unavailable", async () => {
  const bridge = createBridgeServer({
    upstreamUrl: "http://127.0.0.1:9",
    allowInsecureLocalhost: true,
    timeoutMs: 100
  });
  const bridgePort = await listen(bridge);
  try {
    const response = await fetch(`http://127.0.0.1:${bridgePort}/health`);
    assert.equal(response.status, 502);
    assert.deepEqual(await response.json(), { ok: false, error: "azure_upstream_unavailable" });
  } finally {
    await close(bridge);
  }
});

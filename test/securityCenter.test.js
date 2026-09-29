import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createAgentSignature, SecurityCenter } from "../securityCenter.js";

const NOW = Date.parse("2026-09-29T16:00:00.000Z");
const SECRET = "test-secret-that-is-at-least-thirty-two-characters";

async function makeCenter(overrides = {}) {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), "daybreak-sentinel-"));
  const center = new SecurityCenter({
    dataDir,
    ingestSecret: SECRET,
    dashboardUsername: "sentinel",
    dashboardPassword: "a-long-test-password",
    now: () => NOW,
    ...overrides
  });
  await center.initialize();
  return center;
}

function event(overrides = {}) {
  return {
    schemaVersion: 1,
    agentId: "personal-mac",
    agentVersion: "1.0.0",
    platform: "macos",
    commandId: null,
    observedAt: new Date(NOW).toISOString(),
    checks: {
      firewall: { status: "ok", detail: "Application firewall is enabled." },
      fileVault: { status: "fail", detail: "FileVault is not enabled." }
    },
    ...overrides
  };
}

function signedRequest(payload, nonce = "abcdefghijklmnop", requestPath = "/api/security/v1/events") {
  const rawBody = Buffer.from(JSON.stringify(payload));
  const timestamp = String(Math.floor(NOW / 1000));
  const signature = createAgentSignature({
    secret: SECRET,
    method: "POST",
    requestPath,
    timestamp,
    nonce,
    rawBody
  });
  return {
    rawBody,
    headers: {
      "x-security-timestamp": timestamp,
      "x-security-nonce": nonce,
      "x-security-signature": signature
    }
  };
}

test("accepts an authenticated security report and calculates risk", async () => {
  const center = await makeCenter();
  const result = await center.ingest(signedRequest(event()));

  assert.equal(result.accepted, true);
  assert.equal(result.risk.score, 25);
  assert.equal(result.risk.level, "medium");
  assert.equal(center.snapshot().agents[0].agentId, "personal-mac");
});

test("rejects a replayed nonce", async () => {
  const center = await makeCenter();
  const request = signedRequest(event());
  await center.ingest(request);

  await assert.rejects(
    center.ingest(request),
    (error) => error.code === "security_event_replayed" && error.statusCode === 409
  );
});

test("rejects forged signatures", async () => {
  const center = await makeCenter();
  const request = signedRequest(event());
  request.headers["x-security-signature"] = "0".repeat(64);

  await assert.rejects(
    center.ingest(request),
    (error) => error.code === "security_signature_invalid" && error.statusCode === 401
  );
});

test("rejects fields outside the privacy allowlist", async () => {
  const center = await makeCenter();
  const payload = event({
    checks: {
      firewall: { status: "ok" },
      processList: { status: "warn", detail: "private process names" }
    }
  });

  await assert.rejects(
    center.ingest(signedRequest(payload)),
    (error) => error.code === "security_check_unknown"
  );
});

test("requires the configured dashboard credentials", async () => {
  const center = await makeCenter();
  const valid = `Basic ${Buffer.from("sentinel:a-long-test-password").toString("base64")}`;
  const invalid = `Basic ${Buffer.from("sentinel:wrong-password").toString("base64")}`;

  assert.equal(center.authenticateDashboard(valid), true);
  assert.equal(center.authenticateDashboard(invalid), false);
  assert.equal(center.authenticateDashboard(undefined), false);
});

test("creates and verifies short-lived dashboard CSRF tokens", async () => {
  const center = await makeCenter();
  const token = center.createCsrfToken();

  assert.equal(center.verifyCsrfToken(token), true);
  assert.equal(center.verifyCsrfToken(`${token}tampered`), false);
});

test("queues only an allowlisted scan command and completes it with a report", async () => {
  const center = await makeCenter();
  await center.ingest(signedRequest(event(), "initialagentnonce"));
  const queued = await center.queueScan("personal-mac");
  assert.equal(queued.action, "scan_now");

  const pollPath = "/api/security/v1/commands/poll";
  const poll = await center.pollCommands({
    ...signedRequest({ agentId: "personal-mac" }, "pollcommandnonce1", pollPath),
    requestPath: pollPath
  });
  assert.equal(poll.command.id, queued.id);
  assert.equal(poll.command.action, "scan_now");

  await center.ingest(signedRequest(event({ commandId: queued.id }), "reportcommandnonce"));
  assert.equal(center.snapshot().recentCommands[0].status, "completed");
});

test("stores bounded AI analysis separately from the signed event", async () => {
  const center = await makeCenter();
  const accepted = await center.ingest(signedRequest(event()));
  await center.attachAiAnalysis(accepted.eventId, {
    summary: "Review the failed control.",
    priority: "medium",
    recommendations: ["Verify the setting locally."]
  });

  assert.equal(center.getEvent(accepted.eventId).aiAnalysis.priority, "medium");
});

test("escapes event values rendered into the dashboard", async () => {
  const center = await makeCenter();
  await center.ingest(signedRequest(event({
    checks: {
      firewall: { status: "ok", detail: "<script>alert(1)</script>" }
    }
  })));

  const html = center.renderDashboard();
  assert.equal(html.includes("<script>"), false);
  assert.equal(html.includes("Daybreak Sentinel"), true);
});

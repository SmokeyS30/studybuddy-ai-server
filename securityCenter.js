import crypto from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

const DEFAULT_CLOCK_SKEW_SECONDS = 300;
const DEFAULT_MAX_EVENTS = 500;
const MAX_EVENT_BYTES = 64 * 1024;
const COMMAND_TTL_MS = 60 * 60 * 1000;
const COMMAND_RETRY_MS = 15 * 60 * 1000;
const CSRF_TTL_MS = 10 * 60 * 1000;
const ALLOWED_STATUSES = new Set(["ok", "warn", "fail", "unknown"]);
const ALLOWED_CHECKS = new Set([
  "automaticUpdates",
  "backups",
  "fileVault",
  "firewall",
  "gatekeeper",
  "listenerBaseline",
  "privacyShield",
  "remoteLogin",
  "sip",
  "stealthMode",
  "vpn"
]);
const ALLOWED_PLATFORMS = new Set(["macos", "linux", "windows", "ios", "unknown"]);

export class SecurityCenterError extends Error {
  constructor(code, message, statusCode = 400) {
    super(message);
    this.name = "SecurityCenterError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

export class SecurityCenter {
  constructor({
    dataDir,
    ingestSecret = "",
    dashboardUsername = "",
    dashboardPassword = "",
    clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS,
    maxEvents = DEFAULT_MAX_EVENTS,
    now = () => Date.now()
  }) {
    this.dataDir = dataDir;
    this.stateFile = path.join(dataDir, "security-events.json");
    this.ingestSecret = String(ingestSecret).trim();
    this.dashboardUsername = String(dashboardUsername).trim();
    this.dashboardPassword = String(dashboardPassword);
    this.clockSkewSeconds = positiveInteger(clockSkewSeconds, DEFAULT_CLOCK_SKEW_SECONDS);
    this.maxEvents = positiveInteger(maxEvents, DEFAULT_MAX_EVENTS);
    this.now = now;
    this.state = emptyState();
    this.operationQueue = Promise.resolve();
  }

  get ingestionConfigured() {
    return this.ingestSecret.length >= 32;
  }

  get dashboardConfigured() {
    return Boolean(this.dashboardUsername && this.dashboardPassword.length >= 12);
  }

  async initialize() {
    await mkdir(this.dataDir, { recursive: true });
    try {
      const parsed = JSON.parse(await readFile(this.stateFile, "utf8"));
      this.state = {
        version: 1,
        events: Array.isArray(parsed.events) ? parsed.events.slice(0, this.maxEvents) : [],
        nonces: parsed.nonces && typeof parsed.nonces === "object" ? parsed.nonces : {},
        commands: Array.isArray(parsed.commands) ? parsed.commands.slice(0, 100) : []
      };
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      this.state = emptyState();
      await this.persist();
    }

    await this.enqueue(async () => {
      this.removeExpiredNonces();
      this.expireCommands();
      await this.persist();
    });
  }

  status() {
    return {
      ingestionConfigured: this.ingestionConfigured,
      dashboardConfigured: this.dashboardConfigured,
      eventCount: this.state.events.length,
      latestObservedAt: this.state.events[0]?.observedAt || null
    };
  }

  authenticateDashboard(authorizationHeader) {
    if (!this.dashboardConfigured || typeof authorizationHeader !== "string") return false;
    const match = authorizationHeader.match(/^Basic\s+(.+)$/i);
    if (!match) return false;

    let decoded;
    try {
      decoded = Buffer.from(match[1], "base64").toString("utf8");
    } catch {
      return false;
    }
    const separator = decoded.indexOf(":");
    if (separator < 1) return false;
    const username = decoded.slice(0, separator);
    const password = decoded.slice(separator + 1);
    return safeEqual(username, this.dashboardUsername) && safeEqual(password, this.dashboardPassword);
  }

  async ingest({ headers, rawBody, method = "POST", requestPath = "/api/security/v1/events" }) {
    if (!this.ingestionConfigured) {
      throw new SecurityCenterError(
        "security_ingest_not_configured",
        "Security event ingestion is not configured.",
        503
      );
    }
    if (!Buffer.isBuffer(rawBody) || rawBody.length === 0 || rawBody.length > MAX_EVENT_BYTES) {
      throw new SecurityCenterError("security_event_size_invalid", "The security event has an invalid size.", 413);
    }

    const { payload, nonce } = this.verifyAgentRequest({ headers, rawBody, method, requestPath });
    const event = validateEvent(payload, new Date(this.now()).toISOString());

    return this.enqueue(async () => {
      this.removeExpiredNonces();
      this.consumeNonce(nonce);
      if (event.commandId) {
        const command = this.state.commands.find((candidate) => candidate.id === event.commandId && candidate.agentId === event.agentId);
        if (command && command.action === "scan_now") {
          command.status = "completed";
          command.completedAt = event.receivedAt;
        }
      }
      this.state.events.unshift(event);
      this.state.events = this.state.events.slice(0, this.maxEvents);
      await this.persist();
      return {
        accepted: true,
        eventId: event.id,
        receivedAt: event.receivedAt,
        risk: event.risk
      };
    });
  }

  async pollCommands({ headers, rawBody, method = "POST", requestPath = "/api/security/v1/commands/poll" }) {
    const { payload, nonce } = this.verifyAgentRequest({ headers, rawBody, method, requestPath });
    const agentId = validateShortText(payload.agentId, "agentId", 3, 80, /^[A-Za-z0-9._-]+$/);

    return this.enqueue(async () => {
      this.removeExpiredNonces();
      this.consumeNonce(nonce);
      this.expireCommands();
      const now = this.now();
      const command = this.state.commands.find((candidate) => {
        if (candidate.agentId !== agentId || candidate.status === "completed" || candidate.status === "expired") return false;
        if (!candidate.deliveredAt) return true;
        return now - Date.parse(candidate.deliveredAt) >= COMMAND_RETRY_MS;
      });
      if (!command) {
        await this.persist();
        return { command: null };
      }
      command.status = "delivered";
      command.deliveredAt = new Date(now).toISOString();
      await this.persist();
      return {
        command: {
          id: command.id,
          action: command.action,
          expiresAt: command.expiresAt
        }
      };
    });
  }

  createCsrfToken() {
    if (!this.dashboardConfigured) return "";
    const timestamp = String(Math.floor(this.now() / 1000));
    const nonce = crypto.randomBytes(18).toString("base64url");
    const signature = crypto.createHmac("sha256", this.dashboardPassword).update(`${timestamp}.${nonce}`).digest("hex");
    return `${timestamp}.${nonce}.${signature}`;
  }

  verifyCsrfToken(token) {
    const match = typeof token === "string" && token.match(/^(\d{10})\.([A-Za-z0-9_-]{16,64})\.([a-f0-9]{64})$/i);
    if (!match || !this.dashboardConfigured) return false;
    const timestamp = Number(match[1]) * 1000;
    if (Math.abs(this.now() - timestamp) > CSRF_TTL_MS) return false;
    const expected = crypto.createHmac("sha256", this.dashboardPassword).update(`${match[1]}.${match[2]}`).digest("hex");
    return safeEqual(match[3].toLowerCase(), expected);
  }

  async queueScan(agentId) {
    const validatedAgentId = validateShortText(agentId, "agentId", 3, 80, /^[A-Za-z0-9._-]+$/);
    return this.enqueue(async () => {
      if (!this.state.events.some((event) => event.agentId === validatedAgentId)) {
        throw new SecurityCenterError("security_agent_not_found", "The security agent was not found.", 404);
      }
      this.expireCommands();
      const existing = this.state.commands.find((command) =>
        command.agentId === validatedAgentId && command.action === "scan_now" && ["pending", "delivered"].includes(command.status)
      );
      if (existing) return existing;
      const createdAt = new Date(this.now()).toISOString();
      const command = {
        id: crypto.randomUUID(),
        agentId: validatedAgentId,
        action: "scan_now",
        status: "pending",
        createdAt,
        expiresAt: new Date(this.now() + COMMAND_TTL_MS).toISOString(),
        deliveredAt: null,
        completedAt: null
      };
      this.state.commands.unshift(command);
      this.state.commands = this.state.commands.slice(0, 100);
      await this.persist();
      return command;
    });
  }

  async acknowledgeEvent(eventId) {
    if (!/^[a-f0-9-]{36}$/i.test(String(eventId))) {
      throw new SecurityCenterError("security_event_id_invalid", "The security event identifier is invalid.");
    }
    return this.enqueue(async () => {
      const event = this.state.events.find((candidate) => candidate.id === eventId);
      if (!event) throw new SecurityCenterError("security_event_not_found", "The security event was not found.", 404);
      event.acknowledgedAt = new Date(this.now()).toISOString();
      await this.persist();
      return event;
    });
  }

  getEvent(eventId) {
    return this.state.events.find((candidate) => candidate.id === eventId) || null;
  }

  async attachAiAnalysis(eventId, analysis) {
    return this.enqueue(async () => {
      const event = this.state.events.find((candidate) => candidate.id === eventId);
      if (!event) throw new SecurityCenterError("security_event_not_found", "The security event was not found.", 404);
      event.aiAnalysis = analysis;
      event.aiAnalyzedAt = new Date(this.now()).toISOString();
      await this.persist();
      return event;
    });
  }

  verifyAgentRequest({ headers, rawBody, method, requestPath }) {
    if (!this.ingestionConfigured) {
      throw new SecurityCenterError(
        "security_ingest_not_configured",
        "Security agent authentication is not configured.",
        503
      );
    }
    const timestampValue = singleHeader(headers, "x-security-timestamp");
    const nonce = singleHeader(headers, "x-security-nonce");
    const signature = singleHeader(headers, "x-security-signature");
    if (!/^\d{10}$/.test(timestampValue || "")) {
      throw new SecurityCenterError("security_timestamp_invalid", "The security request timestamp is invalid.", 401);
    }
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce || "")) {
      throw new SecurityCenterError("security_nonce_invalid", "The security request nonce is invalid.", 401);
    }
    if (!/^[a-f0-9]{64}$/i.test(signature || "")) {
      throw new SecurityCenterError("security_signature_invalid", "The security request signature is invalid.", 401);
    }
    const timestamp = Number(timestampValue) * 1000;
    if (Math.abs(this.now() - timestamp) > this.clockSkewSeconds * 1000) {
      throw new SecurityCenterError("security_timestamp_expired", "The security request timestamp is outside the allowed window.", 401);
    }
    const expected = createAgentSignature({
      secret: this.ingestSecret,
      method,
      requestPath,
      timestamp: timestampValue,
      nonce,
      rawBody
    });
    if (!safeEqual(signature.toLowerCase(), expected)) {
      throw new SecurityCenterError("security_signature_invalid", "The security request signature is invalid.", 401);
    }
    let payload;
    try {
      payload = JSON.parse(rawBody.toString("utf8"));
    } catch {
      throw new SecurityCenterError("security_event_invalid_json", "The security request is not valid JSON.");
    }
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new SecurityCenterError("security_event_invalid", "The security request must be an object.");
    }
    return { payload, nonce };
  }

  consumeNonce(nonce) {
    if (this.state.nonces[nonce]) {
      throw new SecurityCenterError("security_event_replayed", "The security request has already been received.", 409);
    }
    this.state.nonces[nonce] = this.now() + this.clockSkewSeconds * 1000;
  }

  expireCommands() {
    const now = this.now();
    for (const command of this.state.commands) {
      if (command.status !== "completed" && Date.parse(command.expiresAt) <= now) command.status = "expired";
    }
  }

  snapshot() {
    const latestByAgent = new Map();
    for (const event of this.state.events) {
      if (!latestByAgent.has(event.agentId)) latestByAgent.set(event.agentId, event);
    }
    return {
      generatedAt: new Date(this.now()).toISOString(),
      eventCount: this.state.events.length,
      agents: [...latestByAgent.values()],
      recentEvents: this.state.events.slice(0, 100),
      recentCommands: this.state.commands.slice(0, 20)
    };
  }

  renderDashboard() {
    const snapshot = this.snapshot();
    const agents = snapshot.agents;
    const csrfToken = this.createCsrfToken();
    const highestRisk = agents.reduce((highest, event) => Math.max(highest, event.risk.score), 0);
    const lastSeen = agents
      .map((event) => event.observedAt)
      .sort()
      .at(-1) || "No reports yet";
    const agentRows = agents.map((event) => `<tr>
      <td>${escapeHtml(event.agentId)}</td>
      <td>${escapeHtml(event.platform)}</td>
      <td>${escapeHtml(event.observedAt)}</td>
      <td><span class="risk ${escapeHtml(event.risk.level)}">${escapeHtml(event.risk.level)} (${event.risk.score})</span></td>
      <td>
        <form method="post" action="/api/security/v1/actions">
          <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
          <input type="hidden" name="agentId" value="${escapeHtml(event.agentId)}">
          <button type="submit" name="action" value="scan_now">Request fresh scan</button>
        </form>
      </td>
    </tr>`).join("");
    const rows = snapshot.recentEvents.map((event) => {
      const checks = Object.entries(event.checks)
        .map(([name, check]) => `<span class="check ${escapeHtml(check.status)}" title="${escapeHtml(check.detail)}">${escapeHtml(labelFor(name))}: ${escapeHtml(check.status)}</span>`)
        .join(" ");
      const analysis = event.aiAnalysis
        ? `<div class="analysis"><strong>AI-assisted review:</strong> ${escapeHtml(event.aiAnalysis.summary)}<ul>${(Array.isArray(event.aiAnalysis.recommendations) ? event.aiAnalysis.recommendations : []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul><small>Advisory only; no recommendation is executed automatically.</small></div>`
        : "";
      const acknowledgement = event.acknowledgedAt ? `<small>Acknowledged ${escapeHtml(event.acknowledgedAt)}</small>` : "";
      return `<tr>
        <td>${escapeHtml(event.observedAt)}</td>
        <td>${escapeHtml(event.agentId)}</td>
        <td><span class="risk ${escapeHtml(event.risk.level)}">${escapeHtml(event.risk.level)} (${event.risk.score})</span></td>
        <td>${checks}${analysis}</td>
        <td>
          ${acknowledgement}
          <form method="post" action="/api/security/v1/actions">
            <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
            <input type="hidden" name="eventId" value="${escapeHtml(event.id)}">
            ${event.acknowledgedAt ? "" : '<button type="submit" name="action" value="acknowledge_event">Acknowledge</button>'}
            ${event.aiAnalysis ? "" : '<button type="submit" name="action" value="analyze_event">AI review</button>'}
          </form>
        </td>
      </tr>`;
    }).join("");
    const commandRows = snapshot.recentCommands.map((command) => `<tr>
      <td>${escapeHtml(command.createdAt)}</td>
      <td>${escapeHtml(command.agentId)}</td>
      <td>${escapeHtml(command.action)}</td>
      <td>${escapeHtml(command.status)}</td>
    </tr>`).join("");

    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="60">
  <title>Daybreak Sentinel</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif; background: #08111f; color: #e8f0ff; }
    * { box-sizing: border-box; }
    body { margin: 0; background: radial-gradient(circle at top, #16355f 0, #08111f 42rem); min-height: 100vh; }
    main { width: min(1120px, calc(100% - 28px)); margin: 0 auto; padding: 28px 0 64px; }
    h1 { margin: 0; font-size: clamp(1.7rem, 5vw, 2.7rem); }
    .subtitle { color: #a9bad3; margin: 8px 0 24px; }
    .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; }
    .card, .panel { background: rgba(13, 29, 50, .9); border: 1px solid #27496f; border-radius: 16px; box-shadow: 0 14px 36px rgba(0,0,0,.25); }
    .card { padding: 18px; }
    .metric { font-size: 1.75rem; font-weight: 750; margin-top: 7px; overflow-wrap: anywhere; }
    .label { color: #9fb2cb; font-size: .78rem; letter-spacing: .09em; text-transform: uppercase; }
    .panel { margin-top: 18px; overflow: hidden; }
    .panel h2 { font-size: 1.05rem; margin: 0; padding: 18px; border-bottom: 1px solid #27496f; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; min-width: 760px; }
    th, td { padding: 14px 16px; text-align: left; border-bottom: 1px solid #1c3552; vertical-align: top; }
    th { color: #9fb2cb; font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; }
    .check, .risk { display: inline-block; border-radius: 999px; padding: 4px 8px; margin: 2px; font-size: .76rem; font-weight: 650; background: #233b58; }
    .ok, .secure, .low { background: #124d3c; color: #9bf1d2; }
    .warn, .medium { background: #5c4715; color: #ffe094; }
    .fail, .high, .critical { background: #612b35; color: #ffb6c3; }
    .unknown { background: #38445a; color: #d1d9e8; }
    button { margin: 4px 4px 4px 0; border: 1px solid #4c78a9; border-radius: 9px; background: #193e67; color: #eef6ff; padding: 8px 10px; font-weight: 650; cursor: pointer; }
    button:hover { background: #245485; }
    form { margin: 4px 0; }
    .analysis { margin-top: 10px; padding: 10px; border-left: 3px solid #6ea7df; background: #102942; border-radius: 6px; max-width: 620px; }
    .analysis ul { margin: 7px 0; padding-left: 20px; }
    .empty { padding: 38px 18px; color: #a9bad3; text-align: center; }
    footer { color: #8193ad; font-size: .78rem; padding-top: 18px; }
  </style>
</head>
<body>
  <main>
    <h1>Daybreak Sentinel</h1>
    <p class="subtitle">Private device posture, alerts, AI-assisted review, and allowlisted fresh-scan requests. No remote shell or arbitrary commands.</p>
    <section class="cards">
      <article class="card"><div class="label">Reporting agents</div><div class="metric">${agents.length}</div></article>
      <article class="card"><div class="label">Stored reports</div><div class="metric">${snapshot.eventCount}</div></article>
      <article class="card"><div class="label">Highest current risk</div><div class="metric">${highestRisk}</div></article>
      <article class="card"><div class="label">Latest observation</div><div class="metric" style="font-size:1rem">${escapeHtml(lastSeen)}</div></article>
    </section>
    <section class="panel">
      <h2>Devices</h2>
      ${agentRows ? `<div class="table-wrap"><table><thead><tr><th>Agent</th><th>Platform</th><th>Last seen</th><th>Risk</th><th>Control</th></tr></thead><tbody>${agentRows}</tbody></table></div>` : `<div class="empty">No enrolled devices yet.</div>`}
    </section>
    <section class="panel">
      <h2>Recent posture reports</h2>
      ${rows ? `<div class="table-wrap"><table><thead><tr><th>Observed</th><th>Agent</th><th>Risk</th><th>Checks and analysis</th><th>Review</th></tr></thead><tbody>${rows}</tbody></table></div>` : `<div class="empty">No device has reported yet. Install and configure an agent to begin.</div>`}
    </section>
    <section class="panel">
      <h2>Recent control requests</h2>
      ${commandRows ? `<div class="table-wrap"><table><thead><tr><th>Created</th><th>Agent</th><th>Action</th><th>Status</th></tr></thead><tbody>${commandRows}</tbody></table></div>` : `<div class="empty">No control requests have been queued.</div>`}
    </section>
    <footer>Auto-refreshes every 60 seconds. Reports intentionally exclude IP addresses, usernames, process names, file paths, file contents, and browsing data.</footer>
  </main>
</body>
</html>`;
  }

  removeExpiredNonces() {
    const now = this.now();
    for (const [nonce, expiresAt] of Object.entries(this.state.nonces)) {
      if (!Number.isFinite(expiresAt) || expiresAt <= now) delete this.state.nonces[nonce];
    }
  }

  async persist() {
    const temporaryPath = `${this.stateFile}.${crypto.randomUUID()}.tmp`;
    await writeFile(temporaryPath, JSON.stringify(this.state, null, 2), { mode: 0o600 });
    await rename(temporaryPath, this.stateFile);
  }

  enqueue(operation) {
    const result = this.operationQueue.then(operation, operation);
    this.operationQueue = result.catch(() => {});
    return result;
  }
}

export function createAgentSignature({ secret, method, requestPath, timestamp, nonce, rawBody }) {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody || "");
  return crypto
    .createHmac("sha256", secret)
    .update(`${String(method).toUpperCase()}\n${requestPath}\n${timestamp}\n${nonce}\n`, "utf8")
    .update(body)
    .digest("hex");
}

function validateEvent(payload, receivedAt) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new SecurityCenterError("security_event_invalid", "The security event must be an object.");
  }
  if (payload.schemaVersion !== 1) {
    throw new SecurityCenterError("security_schema_unsupported", "The security event schema version is unsupported.");
  }
  const agentId = validateShortText(payload.agentId, "agentId", 3, 80, /^[A-Za-z0-9._-]+$/);
  const agentVersion = validateShortText(payload.agentVersion, "agentVersion", 1, 30, /^[A-Za-z0-9._-]+$/);
  const platform = typeof payload.platform === "string" ? payload.platform : "unknown";
  if (!ALLOWED_PLATFORMS.has(platform)) {
    throw new SecurityCenterError("security_platform_invalid", "The security event platform is invalid.");
  }
  const commandId = payload.commandId === undefined || payload.commandId === null
    ? null
    : validateShortText(payload.commandId, "commandId", 36, 36, /^[a-f0-9-]+$/i);
  const observedTimestamp = Date.parse(payload.observedAt);
  if (!Number.isFinite(observedTimestamp)) {
    throw new SecurityCenterError("security_observed_at_invalid", "The security event observation time is invalid.");
  }
  if (!payload.checks || typeof payload.checks !== "object" || Array.isArray(payload.checks)) {
    throw new SecurityCenterError("security_checks_invalid", "The security checks must be an object.");
  }

  const checks = {};
  for (const [name, value] of Object.entries(payload.checks)) {
    if (!ALLOWED_CHECKS.has(name)) {
      throw new SecurityCenterError("security_check_unknown", `Unsupported security check: ${name}`);
    }
    if (!value || typeof value !== "object" || !ALLOWED_STATUSES.has(value.status)) {
      throw new SecurityCenterError("security_check_invalid", `Invalid result for security check: ${name}`);
    }
    checks[name] = {
      status: value.status,
      detail: sanitizeDetail(value.detail)
    };
  }
  if (Object.keys(checks).length === 0) {
    throw new SecurityCenterError("security_checks_empty", "At least one security check is required.");
  }

  return {
    id: crypto.randomUUID(),
    schemaVersion: 1,
    agentId,
    agentVersion,
    platform,
    commandId,
    observedAt: new Date(observedTimestamp).toISOString(),
    receivedAt,
    acknowledgedAt: null,
    aiAnalysis: null,
    aiAnalyzedAt: null,
    checks,
    risk: scoreRisk(checks)
  };
}

function scoreRisk(checks) {
  let score = 0;
  const findings = [];
  for (const [name, check] of Object.entries(checks)) {
    if (check.status === "fail") {
      score += 25;
      findings.push(`${labelFor(name)} needs attention`);
    } else if (check.status === "warn") {
      score += 10;
      findings.push(`${labelFor(name)} should be reviewed`);
    } else if (check.status === "unknown") {
      score += 5;
      findings.push(`${labelFor(name)} could not be verified`);
    }
  }
  score = Math.min(score, 100);
  const level = score >= 70 ? "critical" : score >= 45 ? "high" : score >= 20 ? "medium" : score > 0 ? "low" : "secure";
  return { score, level, findings };
}

function singleHeader(headers, name) {
  const value = headers?.[name];
  return Array.isArray(value) ? value[0] : value;
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  if (leftBuffer.length !== rightBuffer.length) return false;
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function validateShortText(value, label, minimum, maximum, pattern) {
  if (typeof value !== "string" || value.length < minimum || value.length > maximum || !pattern.test(value)) {
    throw new SecurityCenterError("security_identity_invalid", `The security event ${label} is invalid.`);
  }
  return value;
}

function sanitizeDetail(value) {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") {
    throw new SecurityCenterError("security_detail_invalid", "Security check details must be text.");
  }
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 160);
}

function positiveInteger(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : fallback;
}

function labelFor(name) {
  return ({
    automaticUpdates: "Automatic updates",
    backups: "Backups",
    fileVault: "FileVault",
    firewall: "Firewall",
    gatekeeper: "Gatekeeper",
    listenerBaseline: "Listener baseline",
    privacyShield: "Privacy Shield",
    remoteLogin: "Remote Login",
    sip: "System Integrity Protection",
    stealthMode: "Stealth mode",
    vpn: "VPN"
  })[name] || name;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function emptyState() {
  return { version: 1, events: [], nonces: {}, commands: [] };
}

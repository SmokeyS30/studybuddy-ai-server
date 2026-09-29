#!/usr/bin/env node

import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

const AGENT_VERSION = "1.0.0";
const DEFAULT_CONFIG_PATH = "/Library/Application Support/DaybreakSentinel/agent.conf";
const DEFAULT_REPORT_INTERVAL_SECONDS = 3600;
const args = new Set(process.argv.slice(2));
const configArgumentIndex = process.argv.indexOf("--config");
const configPath = configArgumentIndex >= 0 ? process.argv[configArgumentIndex + 1] : DEFAULT_CONFIG_PATH;

if (!configPath) fail("--config requires a file path.");

const config = parseConfig(await readFile(configPath, "utf8"));
const serverUrl = required(config, "SENTINEL_SERVER_URL");
const ingestSecret = required(config, "SENTINEL_INGEST_SECRET");
const agentId = required(config, "SENTINEL_AGENT_ID");
const statePath = config.SENTINEL_STATE_PATH || path.join(path.dirname(configPath), "agent-state.json");
const reportIntervalSeconds = positiveInteger(config.SENTINEL_REPORT_INTERVAL_SECONDS, DEFAULT_REPORT_INTERVAL_SECONDS);

if (ingestSecret.length < 32) fail("SENTINEL_INGEST_SECRET must contain at least 32 characters.");
if (!/^[A-Za-z0-9._-]{3,80}$/.test(agentId)) {
  fail("SENTINEL_AGENT_ID must be 3-80 letters, numbers, dots, underscores, or hyphens.");
}

const baseUrl = new URL(serverUrl);
if (baseUrl.protocol !== "https:" && !["localhost", "127.0.0.1", "::1"].includes(baseUrl.hostname)) {
  fail("SENTINEL_SERVER_URL must use HTTPS except during localhost testing.");
}

if (args.has("--dry-run")) {
  process.stdout.write(`${JSON.stringify(buildReport(null), null, 2)}\n`);
  process.exit(0);
}

const state = await readState();
let command = null;
if (args.has("--poll")) command = await pollCommand();
const reportDue = !state.lastReportedAt || Date.now() - Date.parse(state.lastReportedAt) >= reportIntervalSeconds * 1000;
if (!reportDue && command?.action !== "scan_now") process.exit(0);

const result = await signedJsonRequest("/api/security/v1/events", buildReport(command?.id || null));
await writeState({ lastReportedAt: result.receivedAt || new Date().toISOString() });
process.stdout.write(`Daybreak Sentinel report accepted at ${result.receivedAt}. Risk: ${result.risk?.level || "unknown"}.\n`);

async function pollCommand() {
  const result = await signedJsonRequest("/api/security/v1/commands/poll", { agentId });
  if (!result.command) return null;
  if (result.command.action !== "scan_now") fail("Daybreak Sentinel received an unsupported command.");
  return result.command;
}

function buildReport(commandId) {
  return {
    schemaVersion: 1,
    agentId,
    agentVersion: AGENT_VERSION,
    platform: "macos",
    observedAt: new Date().toISOString(),
    commandId,
    checks: {
      firewall: checkFirewall(),
      stealthMode: checkStealthMode(),
      fileVault: checkFileVault(),
      gatekeeper: checkGatekeeper(),
      sip: checkSystemIntegrityProtection(),
      automaticUpdates: checkAutomaticUpdates(),
      backups: checkBackups(),
      remoteLogin: checkRemoteLogin(),
      vpn: checkVpn(),
      privacyShield: checkPrivacyShield(),
      listenerBaseline: checkListenerBaseline()
    }
  };
}

async function signedJsonRequest(requestPath, payload) {
  const endpoint = new URL(requestPath, baseUrl);
  const rawBody = JSON.stringify(payload);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomBytes(24).toString("base64url");
  const signature = crypto
    .createHmac("sha256", ingestSecret)
    .update(`POST\n${requestPath}\n${timestamp}\n${nonce}\n${rawBody}`, "utf8")
    .digest("hex");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);
  let response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Security-Timestamp": timestamp,
        "X-Security-Nonce": nonce,
        "X-Security-Signature": signature
      },
      body: rawBody,
      signal: controller.signal
    });
  } catch (error) {
    fail(`Unable to contact Daybreak Sentinel: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    clearTimeout(timeout);
  }
  if (!response.ok) {
    let code = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      if (typeof body?.code === "string") code = `${code} (${body.code})`;
    } catch {
      // Keep the bounded status-only error. Never print a remote HTML body.
    }
    fail(`Daybreak Sentinel rejected the request: ${code}`);
  }
  return response.json();
}

function checkFirewall() {
  const result = run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]);
  if (!result.ok) return unknown("Firewall status could not be verified.");
  return /^Firewall is enabled\./im.test(result.output)
    ? ok("Application firewall is enabled.")
    : failCheck("Application firewall is disabled.");
}

function checkStealthMode() {
  const result = run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getstealthmode"]);
  if (!result.ok) return unknown("Stealth mode could not be verified.");
  return /^Firewall stealth mode is on/im.test(result.output)
    ? ok("Firewall stealth mode is enabled.")
    : warn("Firewall stealth mode is disabled.");
}

function checkFileVault() {
  const result = run("/usr/bin/fdesetup", ["status"]);
  if (!result.ok) return unknown("FileVault status could not be verified.");
  return /^FileVault is On\./im.test(result.output)
    ? ok("FileVault is enabled.")
    : failCheck("FileVault is not enabled.");
}

function checkGatekeeper() {
  const result = run("/usr/sbin/spctl", ["--status"]);
  if (!result.ok) return unknown("Gatekeeper status could not be verified.");
  return /^assessments enabled/im.test(result.output)
    ? ok("Gatekeeper assessments are enabled.")
    : failCheck("Gatekeeper assessments are disabled.");
}

function checkSystemIntegrityProtection() {
  const result = run("/usr/bin/csrutil", ["status"]);
  if (!result.ok) return unknown("System Integrity Protection could not be verified.");
  return /System Integrity Protection status:\s*enabled\./i.test(result.output)
    ? ok("System Integrity Protection is enabled.")
    : failCheck("System Integrity Protection is not fully enabled.");
}

function checkAutomaticUpdates() {
  const result = run("/usr/sbin/softwareupdate", ["--schedule"]);
  if (!result.ok) return unknown("Automatic update checking could not be verified.");
  return /automatic checking(?: for updates)? is (?:turned )?on/i.test(result.output)
    ? ok("Automatic update checking is enabled.")
    : warn("Automatic update checking is disabled.");
}

function checkBackups() {
  const result = run("/usr/bin/tmutil", ["latestbackup"]);
  if (!result.ok || /failed|error/i.test(result.output)) {
    return warn("A current Time Machine backup could not be verified.");
  }
  return ok("A Time Machine backup destination responded.");
}

function checkRemoteLogin() {
  const result = run("/usr/sbin/systemsetup", ["-getremotelogin"]);
  if (!result.ok || /need administrator access/i.test(result.output)) {
    return unknown("Remote Login status could not be verified.");
  }
  return /Remote Login:\s*Off/i.test(result.output)
    ? ok("Remote Login is disabled.")
    : warn("Remote Login is enabled; confirm that this is intentional and restricted.");
}

function checkVpn() {
  const candidates = ["/usr/local/bin/mullvad", "/opt/homebrew/bin/mullvad"];
  const executable = candidates.find((candidate) => existsSync(candidate));
  if (!executable) return unknown("Mullvad CLI was not found.");
  const result = run(executable, ["status", "--json"]);
  if (!result.ok) return unknown("Mullvad tunnel status could not be verified.");
  try {
    const status = JSON.parse(result.output);
    if (status.state === "connected") return ok("Mullvad reports a connected tunnel.");
    if (["connecting", "disconnecting"].includes(status.state)) return warn("Mullvad reports a changing tunnel state.");
    if (status.state === "disconnected") return warn("Mullvad reports that the tunnel is disconnected.");
  } catch {
    return unknown("Mullvad returned an unrecognized status.");
  }
  return unknown("Mullvad tunnel status could not be classified.");
}

function checkPrivacyShield() {
  const monitorDir = "/Library/Application Support/LocalPrivacyShield/monitor";
  if (existsSync("/Users/Shared/com.local.macspoof2.pause")) return warn("Privacy Shield monitoring is paused.");
  try {
    const state = JSON.parse(readFileSyncSafe(path.join(monitorDir, "state.json")));
    const lastTick = Number(state.last_tick || 0) * 1000;
    if (!lastTick || Date.now() - lastTick > 2 * 60 * 60 * 1000) return warn("Privacy Shield monitoring has not reported recently.");
    return state.last_result === "ok"
      ? ok("Privacy Shield monitoring reports that its latest checks passed.")
      : warn("Privacy Shield monitoring reports that attention is required.");
  } catch {
    return unknown("Privacy Shield state could not be verified.");
  }
}

function checkListenerBaseline() {
  const monitorDir = "/Library/Application Support/LocalPrivacyShield/monitor";
  try {
    const digest = JSON.parse(readFileSyncSafe(path.join(monitorDir, "digest.json")));
    const newCount = digest.new_ports && typeof digest.new_ports === "object" ? Object.keys(digest.new_ports).length : 0;
    if (newCount > 0) return warn(`${newCount} new network-facing socket signatures await review.`);
    return ok("No new network-facing socket signatures await review.");
  } catch {
    return unknown("The listener baseline could not be verified.");
  }
}

function readFileSyncSafe(filePath) {
  const result = spawnSync("/bin/cat", [filePath], { encoding: "utf8", timeout: 5_000, maxBuffer: 256 * 1024 });
  if (result.error || result.status !== 0) throw new Error("unavailable");
  return result.stdout;
}

function run(command, commandArgs) {
  const result = spawnSync(command, commandArgs, {
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 32 * 1024,
    windowsHide: true
  });
  return {
    ok: !result.error && result.status === 0,
    output: `${result.stdout || ""}\n${result.stderr || ""}`.trim()
  };
}

async function readState() {
  try {
    const value = JSON.parse(await readFile(statePath, "utf8"));
    return { lastReportedAt: typeof value.lastReportedAt === "string" ? value.lastReportedAt : null };
  } catch {
    return { lastReportedAt: null };
  }
}

async function writeState(value) {
  const temporaryPath = `${statePath}.${crypto.randomUUID()}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await chmod(temporaryPath, 0o600);
  await rename(temporaryPath, statePath);
}

function parseConfig(contents) {
  const parsed = {};
  for (const sourceLine of contents.split(/\r?\n/)) {
    const line = sourceLine.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    const separator = line.indexOf("=");
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (/^[A-Z0-9_]+$/.test(key)) parsed[key] = value;
  }
  return parsed;
}

function required(source, key) {
  const value = source[key];
  if (!value) fail(`${key} is required in ${configPath}.`);
  return value;
}

function positiveInteger(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : fallback;
}

function ok(detail) {
  return { status: "ok", detail };
}

function warn(detail) {
  return { status: "warn", detail };
}

function failCheck(detail) {
  return { status: "fail", detail };
}

function unknown(detail) {
  return { status: "unknown", detail };
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

// Daybreak Sentinel — GitHub repository security agent.
//
// Polls the GitHub REST API on a schedule, evaluates the security posture of
// every repository the token can see (repos are discovered via /user/repos on
// every scan, so newly created repos are picked up automatically with no
// configuration change), and ingests the result as a Sentinel event through
// the same HMAC-signed ingest path external agents use.
//
// The agent also honors "scan_now" commands queued from the Sentinel
// dashboard ("Request fresh scan"), so Edward can trigger an on-demand scan.
//
// Required: a fine-grained GitHub personal access token with read-only
// access to the repositories to watch. Recommended permissions:
//   Dependabot alerts: read, Secret scanning alerts: read,
//   Code scanning alerts: read, Actions: read, Administration: read,
//   Contents: read, Metadata: read (mandatory).
// Configure with GITHUB_SENTINEL_TOKEN. If the token is absent the agent
// logs once and stays idle; the rest of the server is unaffected.

import crypto from "node:crypto";
import { createAgentSignature } from "./securityCenter.js";

const DEFAULT_INTERVAL_MS = 3_600_000; // 1 hour
const INITIAL_DELAY_MS = 60_000; // let the server finish booting first
const FETCH_TIMEOUT_MS = 15_000;
const EVENTS_PATH = "/api/security/v1/events";
const COMMANDS_PATH = "/api/security/v1/commands/poll";

// Push authors that are expected and never flagged.
const EXPECTED_PUSH_AUTHORS = new Set(["dependabot[bot]", "github-actions[bot]"]);

export class GitHubSentinel {
  constructor({
    securityCenter,
    ingestSecret = "",
    token = "",
    agentId = "github-monitor",
    agentVersion = "1.0.0",
    platform = "linux",
    intervalMs = DEFAULT_INTERVAL_MS,
    enabled = true,
    apiBase = "https://api.github.com",
    userAgent = "daybreak-sentinel-github-agent/1.0",
  } = {}) {
    this.securityCenter = securityCenter;
    this.ingestSecret = String(ingestSecret || "");
    this.token = String(token || "").trim();
    this.agentId = agentId;
    this.agentVersion = agentVersion;
    this.platform = platform;
    this.intervalMs = intervalMs;
    this.enabled = enabled;
    this.apiBase = String(apiBase || "").replace(/\/+$/, "");
    this.userAgent = userAgent;
    this.lastScanAt = 0;
    this.scanning = false;
    this.timer = null;
  }

  get configured() {
    return Boolean(this.token) && this.enabled !== false;
  }

  start() {
    if (!this.configured) {
      console.warn(
        "[github-sentinel] GITHUB_SENTINEL_TOKEN is not set; GitHub monitoring is idle. " +
          "Set the token to have Daybreak Sentinel watch your repositories."
      );
      return false;
    }
    // First scan shortly after boot, then on the regular interval.
    setTimeout(() => this.tick().catch((error) => this.logError("initial scan", error)), INITIAL_DELAY_MS);
    this.timer = setInterval(
      () => this.tick().catch((error) => this.logError("scheduled scan", error)),
      this.intervalMs
    );
    if (this.timer.unref) this.timer.unref();
    console.log(`[github-sentinel] watching GitHub repositories every ${Math.round(this.intervalMs / 60000)} min.`);
    return true;
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  logError(context, error) {
    console.warn(`[github-sentinel] ${context} failed: ${error && error.message ? error.message : error}`);
  }

  // One scheduler tick: honor a pending scan_now command first, otherwise run
  // on the regular interval.
  async tick() {
    if (this.scanning) return;
    let command = null;
    try {
      command = await this.pollCommand();
    } catch (error) {
      this.logError("command poll", error);
    }
    const due = Date.now() - this.lastScanAt >= this.intervalMs;
    if (command && command.action === "scan_now") {
      await this.runScan(command.id);
    } else if (due) {
      await this.runScan(null);
    }
  }

  async pollCommand() {
    const rawBody = Buffer.from(JSON.stringify({ agentId: this.agentId }), "utf8");
    const result = await this.securityCenter.pollCommands({
      headers: this.signedHeaders(rawBody, "POST", COMMANDS_PATH),
      rawBody,
      method: "POST",
      requestPath: COMMANDS_PATH,
    });
    return result.command;
  }

  signedHeaders(rawBody, method, requestPath) {
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = crypto.randomBytes(18).toString("base64url");
    const signature = createAgentSignature({
      secret: this.ingestSecret,
      method,
      requestPath,
      timestamp,
      nonce,
      rawBody,
    });
    return {
      "x-security-timestamp": timestamp,
      "x-security-nonce": nonce,
      "x-security-signature": signature,
    };
  }

  async runScan(commandId) {
    if (this.scanning) return null;
    this.scanning = true;
    try {
      const checks = await this.buildChecks();
      const result = await this.ingest(checks, commandId);
      this.lastScanAt = Date.now();
      console.log(
        `[github-sentinel] scan ingested: risk=${result.risk.level} (${result.risk.score}).`
      );
      return result;
    } catch (error) {
      this.logError("scan", error);
      return null;
    } finally {
      this.scanning = false;
    }
  }

  async ingest(checks, commandId) {
    const payload = {
      schemaVersion: 1,
      agentId: this.agentId,
      agentVersion: this.agentVersion,
      platform: this.platform,
      commandId: commandId || null,
      observedAt: new Date().toISOString(),
      checks,
    };
    const rawBody = Buffer.from(JSON.stringify(payload), "utf8");
    return this.securityCenter.ingest({
      headers: this.signedHeaders(rawBody, "POST", EVENTS_PATH),
      rawBody,
      method: "POST",
      requestPath: EVENTS_PATH,
    });
  }

  // --- GitHub API ---

  async gh(path) {
    const url = `${this.apiBase}${path}`;
    try {
      const response = await fetch(url, {
        method: "GET",
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${this.token}`,
          "X-GitHub-Api-Version": "2022-11-28",
          "User-Agent": this.userAgent,
        },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      const text = await response.text();
      let data = null;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        data = null;
      }
      return { ok: response.ok, status: response.status, data, headers: response.headers };
    } catch (error) {
      return { ok: false, status: 0, data: null, error };
    }
  }

  async listRepos() {
    const repos = [];
    let url = "/user/repos?per_page=100&affiliation=owner&sort=full_name";
    const seen = new Set();
    for (let page = 0; page < 10 && url; page++) {
      const path = url.startsWith("http") ? url.slice(this.apiBase.length) : url;
      const result = await this.gh(path);
      if (!result.ok || !Array.isArray(result.data)) {
        throw new Error(`listing repositories failed (HTTP ${result.status})`);
      }
      for (const repo of result.data) {
        if (repo && repo.full_name && !seen.has(repo.full_name)) {
          seen.add(repo.full_name);
          repos.push(repo);
        }
      }
      url = nextPage(result.headers);
    }
    return repos;
  }

  async scanRepo(repo) {
    const full = repo.full_name;
    const defaultBranch = repo.default_branch || "main";
    const [dependabot, secrets, codeScanning, protection, keys, collaborators, events, runs] =
      await Promise.all([
        this.gh(`/repos/${full}/dependabot/alerts?state=open&per_page=100`),
        this.gh(`/repos/${full}/secret-scanning/alerts?state=open&per_page=100`),
        this.gh(`/repos/${full}/code-scanning/alerts?state=open&per_page=100`),
        this.gh(`/repos/${full}/branches/${encodeURIComponent(defaultBranch)}/protection`),
        this.gh(`/repos/${full}/keys?per_page=100`),
        this.gh(`/repos/${full}/collaborators?per_page=100&affiliation=direct`),
        this.gh(`/repos/${full}/events?per_page=30`),
        this.gh(`/repos/${full}/actions/runs?status=failure&per_page=5`),
      ]);
    return { repo, full, defaultBranch, dependabot, secrets, codeScanning, protection, keys, collaborators, events, runs };
  }

  // --- Check evaluation ---

  async buildChecks() {
    let repos;
    try {
      repos = await this.listRepos();
    } catch (error) {
      // The token is invalid or GitHub is unreachable: surface it on the
      // dashboard instead of failing silently.
      return {
        githubDependabot: check("unknown", `Repository list unavailable: ${shortError(error)}`),
        githubSecretScanning: check("unknown", `Repository list unavailable: ${shortError(error)}`),
        githubCodeScanning: check("unknown", `Repository: ${shortError(error)}`),
        githubBranchProtection: check("unknown", `Repository list unavailable: ${shortError(error)}`),
        githubDeployKeys: check("unknown", `Repository list unavailable: ${shortError(error)}`),
        githubCollaborators: check("unknown", `Repository list unavailable: ${shortError(error)}`),
        githubPushActivity: check("unknown", `Repository list unavailable: ${shortError(error)}`),
        githubActions: check("unknown", `Repository list unavailable: ${shortError(error)}`),
      };
    }

    const scanned = [];
    for (const repo of repos) {
      try {
        scanned.push(await this.scanRepo(repo));
      } catch (error) {
        this.logError(`scan of ${repo.full_name}`, error);
      }
    }

    return {
      githubDependabot: this.dependabotCheck(scanned),
      githubSecretScanning: this.secretScanningCheck(scanned),
      githubCodeScanning: this.codeScanningCheck(scanned),
      githubBranchProtection: this.branchProtectionCheck(scanned),
      githubDeployKeys: this.deployKeysCheck(scanned),
      githubCollaborators: this.collaboratorsCheck(scanned),
      githubPushActivity: this.pushActivityCheck(scanned),
      githubActions: this.actionsCheck(scanned),
    };
  }

  dependabotCheck(scanned) {
    const parts = [];
    let worst = "ok";
    for (const s of scanned) {
      const name = shortName(s.full);
      if (!s.dependabot.ok) {
        worst = escalate(worst, "unknown");
        parts.push(`${name}: query failed (HTTP ${s.dependabot.status})`);
        continue;
      }
      const alerts = Array.isArray(s.dependabot.data) ? s.dependabot.data : [];
      if (!alerts.length) continue;
      const sev = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const alert of alerts) {
        const level = String(alert?.security_advisory?.severity || "unknown").toLowerCase();
        if (level in sev) sev[level]++;
        else sev.low++;
      }
      const level = sev.critical || sev.high ? "fail" : "warn";
      worst = escalate(worst, level);
      const pkg = alerts
        .slice(0, 3)
        .map((a) => a?.dependency?.package?.name || "a dependency")
        .join(", ");
      parts.push(
        `${name}: ${alerts.length} open (${sev.critical} critical, ${sev.high} high, ${sev.medium} medium, ${sev.low} low) e.g. ${pkg}`
      );
    }
    if (!parts.length) return check("ok", `No open Dependabot alerts across ${scanned.length} repos.`);
    return check(worst, truncate(parts.join("; "), 400));
  }

  secretScanningCheck(scanned) {
    const parts = [];
    let worst = "ok";
    for (const s of scanned) {
      const name = shortName(s.full);
      if (!s.secrets.ok) {
        worst = escalate(worst, "unknown");
        parts.push(`${name}: query failed (HTTP ${s.secrets.status})`);
        continue;
      }
      const alerts = Array.isArray(s.secrets.data) ? s.secrets.data : [];
      if (!alerts.length) continue;
      worst = escalate(worst, "fail");
      const kinds = [...new Set(alerts.slice(0, 5).map((a) => a?.secret_type_display_name || "secret"))].join(", ");
      parts.push(`${name}: ${alerts.length} open (${kinds})`);
    }
    if (!parts.length) return check("ok", `No open secret-scanning alerts across ${scanned.length} repos.`);
    return check(worst, truncate(parts.join("; "), 400));
  }

  codeScanningCheck(scanned) {
    const parts = [];
    let worst = "ok";
    let notEnabled = 0;
    for (const s of scanned) {
      const name = shortName(s.full);
      if (s.codeScanning.status === 404) {
        notEnabled++;
        continue;
      }
      if (!s.codeScanning.ok) {
        worst = escalate(worst, "unknown");
        parts.push(`${name}: query failed (HTTP ${s.codeScanning.status})`);
        continue;
      }
      const alerts = Array.isArray(s.codeScanning.data) ? s.codeScanning.data : [];
      if (!alerts.length) continue;
      const severe = alerts.filter((a) =>
        ["critical", "high", "error"].includes(String(a?.rule?.severity || "").toLowerCase())
      ).length;
      worst = escalate(worst, severe ? "fail" : "warn");
      parts.push(`${name}: ${alerts.length} open (${severe} severe)`);
    }
    if (!parts.length) {
      if (notEnabled === scanned.length && scanned.length)
        return check("unknown", "Code scanning is not enabled on any scanned repo.");
      return check("ok", `No open code-scanning alerts across ${scanned.length} repos.`);
    }
    return check(worst, truncate(parts.join("; "), 400));
  }

  branchProtectionCheck(scanned) {
    const unprotected = scanned.filter((s) => s.protection.status === 404).map((s) => shortName(s.full));
    const failed = scanned.filter((s) => !s.protection.ok && s.protection.status !== 404);
    if (failed.length)
      return check("unknown", truncate(`Protection query failed for: ${failed.map((s) => shortName(s.full)).join(", ")}`, 400));
    if (!unprotected.length)
      return check("ok", `Default branch is protected on all ${scanned.length} repos.`);
    // Solo developers often push straight to main; that is a workflow choice,
    // not an incident, so this stays a warning.
    return check(
      "warn",
      `No branch protection on: ${unprotected.join(", ")}. Direct pushes to the default branch are allowed.`
    );
  }

  deployKeysCheck(scanned) {
    const parts = [];
    let worst = "ok";
    for (const s of scanned) {
      const name = shortName(s.full);
      if (!s.keys.ok) {
        worst = escalate(worst, "unknown");
        parts.push(`${name}: query failed (HTTP ${s.keys.status})`);
        continue;
      }
      const keys = Array.isArray(s.keys.data) ? s.keys.data : [];
      if (!keys.length) continue;
      worst = escalate(worst, "warn");
      parts.push(`${name}: ${keys.map((k) => `"${k.title || "untitled"}"${k.read_only === false ? " (write)" : ""}`).join(", ")}`);
    }
    if (!parts.length) return check("ok", `No deploy keys on any of ${scanned.length} repos.`);
    return check(worst, truncate(`Deploy keys present — ${parts.join("; ")}`, 400));
  }

  collaboratorsCheck(scanned) {
    const parts = [];
    let worst = "ok";
    for (const s of scanned) {
      const name = shortName(s.full);
      const owner = s.repo?.owner?.login;
      if (!s.collaborators.ok) {
        worst = escalate(worst, "unknown");
        parts.push(`${name}: query failed (HTTP ${s.collaborators.status})`);
        continue;
      }
      const others = (Array.isArray(s.collaborators.data) ? s.collaborators.data : []).filter(
        (c) => c.login && c.login !== owner
      );
      if (!others.length) continue;
      worst = escalate(worst, "warn");
      parts.push(`${name}: ${others.map((c) => c.login).join(", ")}`);
    }
    if (!parts.length) return check("ok", `No outside collaborators on any of ${scanned.length} repos.`);
    return check(worst, truncate(`Outside collaborators: ${parts.join("; ")}`, 400));
  }

  pushActivityCheck(scanned) {
    const since = Date.now() - 24 * 3600 * 1000;
    const parts = [];
    let worst = "ok";
    let total = 0;
    for (const s of scanned) {
      const name = shortName(s.full);
      if (!s.events.ok) {
        worst = escalate(worst, "unknown");
        parts.push(`${name}: event query failed (HTTP ${s.events.status})`);
        continue;
      }
      const pushes = (Array.isArray(s.events.data) ? s.events.data : []).filter(
        (e) => e.type === "PushEvent" && Date.parse(e.created_at) >= since
      );
      total += pushes.length;
      const owner = s.repo?.owner?.login;
      const strangers = [...new Set(pushes.map((p) => p.actor?.login).filter(Boolean))].filter(
        (login) => login !== owner && !EXPECTED_PUSH_AUTHORS.has(login)
      );
      if (strangers.length) {
        worst = escalate(worst, "warn");
        parts.push(`${name}: pushes by unexpected authors: ${strangers.join(", ")}`);
      }
    }
    if (worst === "warn") return check("warn", truncate(parts.join("; "), 400));
    if (parts.length) return check("unknown", truncate(parts.join("; "), 400));
    return check("ok", `${total} pushes in the last 24h across ${scanned.length} repos, all by expected authors.`);
  }

  actionsCheck(scanned) {
    const parts = [];
    let worst = "ok";
    for (const s of scanned) {
      const name = shortName(s.full);
      if (!s.runs.ok) {
        worst = escalate(worst, "unknown");
        parts.push(`${name}: runs query failed (HTTP ${s.runs.status})`);
        continue;
      }
      const runs = Array.isArray(s.runs.data?.workflow_runs) ? s.runs.data.workflow_runs : [];
      if (!runs.length) continue;
      worst = escalate(worst, "warn");
      parts.push(`${name}: ${runs.length} failed (${runs.slice(0, 3).map((r) => r.name || r.head_branch || "run").join(", ")})`);
    }
    if (!parts.length) return check("ok", `No failed workflow runs recently across ${scanned.length} repos.`);
    return check(worst, truncate(parts.join("; "), 400));
  }
}

// --- small helpers ---

function check(status, detail) {
  return { status, detail: truncate(String(detail || ""), 500) };
}

function escalate(current, next) {
  const rank = { ok: 0, warn: 1, unknown: 2, fail: 3 };
  return rank[next] > rank[current] ? next : current;
}

function truncate(value, max) {
  const s = String(value);
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

function shortName(fullName) {
  return String(fullName || "").split("/").pop() || String(fullName || "");
}

function shortError(error) {
  const message = error && error.message ? error.message : String(error);
  return truncate(message, 120);
}

function nextPage(headers) {
  const link = headers && typeof headers.get === "function" ? headers.get("link") : null;
  if (!link) return null;
  for (const part of String(link).split(",")) {
    const match = part.match(/<([^>]+)>\s*;\s*rel="next"/);
    if (match) return match[1];
  }
  return null;
}

export { DEFAULT_INTERVAL_MS };

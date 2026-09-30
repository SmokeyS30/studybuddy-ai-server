import http from "node:http";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { APP_ATTEST_HEADERS, AppAttestError, AppAttestManager } from "./appAttest.js";
import { SecurityAIAnalyzer, SecurityAIError } from "./securityAI.js";
import { SecurityCenter, SecurityCenterError } from "./securityCenter.js";
import { GitHubSentinel } from "./githubSentinel.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER_VERSION = "1.4.0";
const SERVER_STARTED_AT = new Date().toISOString();

loadDotEnv(path.join(__dirname, ".env"));

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || (process.env.PORT ? "0.0.0.0" : "127.0.0.1");
const DATA_DIR = path.resolve(__dirname, process.env.STUDYBUDDY_DATA_DIR || "./data");
const PROFILE_FILE = path.join(DATA_DIR, "profiles.json");
const SECURITY_DATA_DIR = path.resolve(process.env.SECURITY_DATA_DIR || path.join(DATA_DIR, "security"));
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-5.6-terra";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "*")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
// Default to "enforce": in "monitor" mode requests that fail App Attest are
// still served, so anyone who finds the server URL can call the AI routes with
// no authentication and burn OpenAI budget. Override explicitly with
// APP_ATTEST_MODE=monitor|off when a permissive mode is really needed.
const APP_ATTEST_MODE = process.env.APP_ATTEST_MODE || "enforce";
const APP_ATTEST_TEAM_ID = process.env.APP_ATTEST_TEAM_ID || "S6L62N62M4";
const APP_ATTEST_BUNDLE_ID = process.env.APP_ATTEST_BUNDLE_ID || "com.smokeys30.studybuddy";
const APP_ATTEST_ALLOW_DEVELOPMENT = parseBoolean(
  process.env.APP_ATTEST_ALLOW_DEVELOPMENT,
  HOST === "127.0.0.1" || HOST === "localhost"
);
const PROTECTED_API_PATHS = new Set([
  "/api/tutor/mistake",
  "/api/tutor/chat",
  "/api/learning/attempt",
  "/api/study-path"
]);

// Daybreak Sentinel routes share the same per-IP limiter. Unlike the tutor
// routes they include GETs (the dashboard), so they are matched by prefix.
function isRateLimitedRoute(method, requestPath) {
  if (method === "POST" && PROTECTED_API_PATHS.has(requestPath)) return true;
  return requestPath === "/security" || requestPath.startsWith("/api/security/");
}

// --- Per-IP rate limiting for the protected API routes ---
// Bounds how much OpenAI spend a single caller can trigger, even if they
// somehow pass (or bypass) App Attest. 30 requests/minute/IP caps worst-case
// abuse at roughly $0.30/min per source instead of unbounded. Tune with
// TUTOR_RATE_LIMIT_MAX / TUTOR_RATE_LIMIT_WINDOW_MS. Loopback callers (local
// dev) are exempt.
function positiveIntEnv(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}
const RATE_LIMIT_MAX_REQUESTS = positiveIntEnv(process.env.TUTOR_RATE_LIMIT_MAX, 30);
const RATE_LIMIT_WINDOW_MS = positiveIntEnv(process.env.TUTOR_RATE_LIMIT_WINDOW_MS, 60_000);
const rateLimitBuckets = new Map();

function clientIp(request) {
  const forwarded = request.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    // Behind a single trusted proxy (e.g. Render) the proxy appends the real
    // client IP, so the last entry is the one the caller cannot forge.
    const parts = forwarded.split(",").map((part) => part.trim()).filter(Boolean);
    if (parts.length) return parts[parts.length - 1];
  }
  return request.socket?.remoteAddress || "unknown";
}

function isLoopbackIp(ip) {
  return ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1";
}

function checkRateLimit(ip) {
  const now = Date.now();
  let bucket = rateLimitBuckets.get(ip);
  if (!bucket) {
    bucket = [];
    rateLimitBuckets.set(ip, bucket);
  }
  while (bucket.length && now - bucket[0] > RATE_LIMIT_WINDOW_MS) bucket.shift();
  if (bucket.length >= RATE_LIMIT_MAX_REQUESTS) {
    const retryAfterMs = RATE_LIMIT_WINDOW_MS - (now - bucket[0]);
    return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil(retryAfterMs / 1000)) };
  }
  bucket.push(now);
  return { allowed: true, retryAfterSeconds: 0 };
}

// Periodically drop fully-expired buckets so the map cannot grow without
// bound on a long-lived server.
setInterval(() => {
  const now = Date.now();
  for (const [ip, bucket] of rateLimitBuckets) {
    while (bucket.length && now - bucket[0] > RATE_LIMIT_WINDOW_MS) bucket.shift();
    if (!bucket.length) rateLimitBuckets.delete(ip);
  }
}, 5 * 60 * 1000);

const EXAM_BLUEPRINTS = {
  "comptia-a-plus-core-1-220-1201": {
    name: "CompTIA A+ Core 1",
    code: "220-1201",
    domains: ["Mobile Devices", "Networking", "Hardware", "Virtualization and Cloud Computing", "Hardware and Network Troubleshooting"],
    labTypes: ["networking diagram", "printer troubleshooting", "cable troubleshooting", "wireless setup", "hardware triage"]
  },
  "comptia-a-plus-core-2-220-1202": {
    name: "CompTIA A+ Core 2",
    code: "220-1202",
    domains: ["Operating Systems", "Security", "Software Troubleshooting", "Operational Procedures"],
    labTypes: ["Windows desktop", "Linux terminal", "ticket system", "malware response", "account hardening"]
  },
  "comptia-security-plus-sy0-701": {
    name: "CompTIA Security+",
    code: "SY0-701",
    domains: ["General Security Concepts", "Threats, Vulnerabilities, and Mitigations", "Security Architecture", "Security Operations", "Security Program Management and Oversight"],
    labTypes: ["log analysis", "firewall rules", "incident response", "cloud responsibility", "risk analysis"]
  }
};

const SYSTEM_PROMPT = [
  "You are StudyBuddy AI Tutor, a Socratic certification coach for CompTIA A+ 220-1201, A+ 220-1202, and Security+ SY0-701.",
  "You help students learn from mistakes, build confidence, and study for the real exam using original explanations and legal study guidance.",
  "Do not provide actual exam dumps, copied proprietary question banks, or claims that content is from the live CompTIA exam.",
  "Do not simply reveal answers. Teach by asking guiding questions, diagnosing the misconception, and assigning targeted practice.",
  "Keep responses practical, exam-focused, and specific to the student's selected exam, domain, confidence, and mistake history.",
  "Return strict JSON with keys: coachMessage, mistakePattern, guidingQuestions, assignments, nextAction."
].join(" ");

await ensureDataFile();

const appAttest = new AppAttestManager({
  dataDir: DATA_DIR,
  mode: APP_ATTEST_MODE,
  teamIdentifier: APP_ATTEST_TEAM_ID,
  bundleIdentifier: APP_ATTEST_BUNDLE_ID,
  allowDevelopmentEnvironment: APP_ATTEST_ALLOW_DEVELOPMENT
});
await appAttest.initialize();

const securityCenter = new SecurityCenter({
  dataDir: SECURITY_DATA_DIR,
  ingestSecret: process.env.SECURITY_INGEST_SECRET,
  dashboardUsername: process.env.SECURITY_DASHBOARD_USERNAME,
  dashboardPassword: process.env.SECURITY_DASHBOARD_PASSWORD,
  clockSkewSeconds: process.env.SECURITY_CLOCK_SKEW_SECONDS,
  maxEvents: process.env.SECURITY_MAX_EVENTS
});
await securityCenter.initialize();

const securityAI = new SecurityAIAnalyzer({
  enabled: parseBoolean(process.env.SECURITY_AI_ENABLED, false),
  apiKey: process.env.OPENAI_API_KEY,
  model: process.env.SECURITY_AI_MODEL || OPENAI_MODEL
});

// Daybreak Sentinel GitHub agent: watches every repository the token can see
// (repos are re-discovered on each scan, so new repos are covered
// automatically) and ingests posture findings as Sentinel events. Idle unless
// GITHUB_SENTINEL_TOKEN is set; safe to leave enabled by default.
const githubSentinel = new GitHubSentinel({
  securityCenter,
  ingestSecret: process.env.SECURITY_INGEST_SECRET,
  token: process.env.GITHUB_SENTINEL_TOKEN,
  enabled: parseBoolean(process.env.GITHUB_SENTINEL_ENABLED, true),
  intervalMs: positiveIntEnv(process.env.GITHUB_SENTINEL_INTERVAL_MS, 3_600_000),
});
githubSentinel.start();

const server = http.createServer(async (request, response) => {
  try {
    const requestPath = new URL(request.url || "/", "http://studybuddy.local").pathname;
    const isSecurityRoute = requestPath === "/security" || requestPath.startsWith("/api/security/");
    if (!isSecurityRoute) setCorsHeaders(request, response);

    if (request.method === "OPTIONS") {
      response.writeHead(204);
      response.end();
      return;
    }

    if (isRateLimitedRoute(request.method, requestPath)) {
      // Reject abusive callers before doing any expensive work (body parsing,
      // attestation verification, OpenAI calls, dashboard auth). Runs before
      // the App Attest check and before the Sentinel handlers on purpose.
      const callerIp = clientIp(request);
      if (!isLoopbackIp(callerIp)) {
        const limit = checkRateLimit(callerIp);
        if (!limit.allowed) {
          response.setHeader("Retry-After", String(limit.retryAfterSeconds));
          sendJson(response, 429, {
            error: "Rate limit exceeded. Please slow down and try again.",
            retryAfterSeconds: limit.retryAfterSeconds
          });
          return;
        }
      }
    }

    if (request.method === "POST" && requestPath === "/api/security/v1/events") {
      const rawBody = await readBody(request, 64 * 1024);
      const result = await securityCenter.ingest({
        headers: request.headers,
        rawBody,
        method: request.method,
        requestPath
      });
      setSecurityResponseHeaders(response);
      sendJson(response, 202, result);
      return;
    }

    if (request.method === "POST" && requestPath === "/api/security/v1/commands/poll") {
      const rawBody = await readBody(request, 8 * 1024);
      const result = await securityCenter.pollCommands({
        headers: request.headers,
        rawBody,
        method: request.method,
        requestPath
      });
      setSecurityResponseHeaders(response);
      sendJson(response, 200, result);
      return;
    }

    if (request.method === "POST" && requestPath === "/api/security/v1/actions") {
      if (!securityCenter.dashboardConfigured) {
        setSecurityResponseHeaders(response);
        sendJson(response, 503, { error: "Security dashboard is not configured." });
        return;
      }
      if (!securityCenter.authenticateDashboard(request.headers.authorization)) {
        sendDashboardUnauthorized(response);
        return;
      }
      if (!String(request.headers["content-type"] || "").toLowerCase().startsWith("application/x-www-form-urlencoded")) {
        throw new SecurityCenterError("security_action_content_type_invalid", "The dashboard action content type is invalid.", 415);
      }
      const form = new URLSearchParams((await readBody(request, 8 * 1024)).toString("utf8"));
      if (!securityCenter.verifyCsrfToken(form.get("csrf"))) {
        throw new SecurityCenterError("security_action_csrf_invalid", "The dashboard action could not be verified.", 403);
      }
      const action = form.get("action");
      if (action === "scan_now") {
        await securityCenter.queueScan(form.get("agentId"));
      } else if (action === "acknowledge_event") {
        await securityCenter.acknowledgeEvent(form.get("eventId"));
      } else if (action === "analyze_event") {
        const event = securityCenter.getEvent(form.get("eventId"));
        if (!event) throw new SecurityCenterError("security_event_not_found", "The security event was not found.", 404);
        const analysis = await securityAI.analyze(event);
        await securityCenter.attachAiAnalysis(event.id, analysis);
      } else {
        throw new SecurityCenterError("security_action_invalid", "The dashboard action is not supported.");
      }
      setSecurityResponseHeaders(response);
      sendRedirect(response, "/security");
      return;
    }

    if (request.method === "GET" && (requestPath === "/security" || requestPath === "/api/security/v1/status")) {
      if (!securityCenter.dashboardConfigured) {
        setSecurityResponseHeaders(response);
        sendJson(response, 503, { error: "Security dashboard is not configured." });
        return;
      }
      if (!securityCenter.authenticateDashboard(request.headers.authorization)) {
        sendDashboardUnauthorized(response);
        return;
      }
      setSecurityResponseHeaders(response);
      if (requestPath === "/security") {
        sendHtml(response, 200, securityCenter.renderDashboard());
      } else {
        sendJson(response, 200, securityCenter.snapshot());
      }
      return;
    }

    if (request.method === "GET" && requestPath === "/health") {
      sendJson(response, 200, {
        ok: true,
        service: "StudyBuddy AI Server",
        version: SERVER_VERSION,
        startedAt: SERVER_STARTED_AT,
        host: HOST,
        port: PORT,
        model: OPENAI_MODEL,
        openaiConfigured: isOpenAIConfigured(),
        appAttest: appAttest.status(),
        storage: {
          persistentPathConfigured: DATA_DIR === "/var/data" || DATA_DIR.startsWith("/var/data/")
        },
        exams: Object.values(EXAM_BLUEPRINTS).map((exam) => `${exam.name} ${exam.code}`)
      });
      return;
    }

    if (request.method === "POST" && requestPath === "/api/app-attest/challenge") {
      const payload = parseJson(await readBody(request));
      sendJson(response, 200, await appAttest.issueChallenge(payload.purpose));
      return;
    }

    if (request.method === "POST" && requestPath === "/api/app-attest/register") {
      const payload = parseJson(await readBody(request));
      sendJson(response, 201, await appAttest.register(payload));
      return;
    }

    if (request.method === "POST" && PROTECTED_API_PATHS.has(requestPath)) {
      // Rate limiting already ran above (see isRateLimitedRoute gate).
      const rawBody = await readBody(request);
      const verification = await appAttest.verifyProtectedRequest({
        method: request.method,
        requestPath,
        rawBody,
        headers: request.headers
      });
      response.setHeader("X-StudyBuddy-App-Attest-Status", verification.status);
      const payload = parseJson(rawBody);

      if (requestPath === "/api/tutor/mistake") {
        const context = payload;
        const profileStore = await readProfiles();
        const profile = getProfile(profileStore, context.studentId);
        learnFromMistake(profile, context);

        const fallback = buildTutorResponse(context, profile, "local");
        const aiResponse = await buildOpenAITutorResponse(context, profile, fallback);
        await writeProfiles(profileStore);
        sendJson(response, 200, aiResponse);
        return;
      }

      if (requestPath === "/api/tutor/chat") {
        const profileStore = await readProfiles();
        const profile = getProfile(profileStore, payload.context?.studentId);

        const chatResponse = await buildChatResponse(payload.context, payload.messages || [], profile);
        await writeProfiles(profileStore);
        sendJson(response, 200, chatResponse);
        return;
      }

      if (requestPath === "/api/learning/attempt") {
        const profileStore = await readProfiles();
        const profile = getProfile(profileStore, payload.studentId);
        learnFromAttempt(profile, payload);

        const weakestDomain = (payload.weakDomains || [])[0] || findWeakestDomain(profile, payload.examID);
        await writeProfiles(profileStore);
        sendJson(response, 200, buildAttemptResponse(payload, weakestDomain));
        return;
      }

      if (requestPath === "/api/study-path") {
        const profileStore = await readProfiles();
        const profile = getProfile(profileStore, payload.studentId);
        sendJson(response, 200, buildStudyPath(payload, profile));
        return;
      }
    }

    sendJson(response, 404, { error: "Route not found" });
  } catch (error) {
    if (error instanceof SecurityAIError) {
      setSecurityResponseHeaders(response);
      sendJson(response, error.statusCode, {
        error: "AI-assisted security review unavailable",
        code: error.code
      });
      return;
    }

    if (error instanceof SecurityCenterError) {
      setSecurityResponseHeaders(response);
      sendJson(response, error.statusCode, {
        error: "Security event rejected",
        code: error.code
      });
      return;
    }

    if (error instanceof AppAttestError) {
      sendJson(response, error.statusCode, {
        error: "App Attest verification failed",
        code: error.code
      });
      return;
    }

    console.error(
      "[StudyBuddy AI server] Unhandled request error:",
      error instanceof Error ? error.stack || error.message : String(error)
    );
    sendJson(response, 500, {
      error: "StudyBuddy AI server error"
    });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`StudyBuddy AI server running on http://${HOST}:${PORT}`);
  console.log(`App Attest mode: ${appAttest.status().mode}`);
});

/*
 * AI tutor and adaptive-learning helpers
 */

function loadDotEnv(envPath) {
  try {
    const contents = readFileSync(envPath, "utf8");
    for (const line of contents.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
      const [key, ...rest] = trimmed.split("=");
      if (!process.env[key]) {
        process.env[key] = rest.join("=").trim();
      }
    }
  } catch {
    // .env is optional.
  }
}

async function ensureDataFile() {
  await mkdir(DATA_DIR, { recursive: true });
  try {
    await readFile(PROFILE_FILE, "utf8");
  } catch {
    await writeFile(PROFILE_FILE, JSON.stringify({ profiles: {} }, null, 2));
  }
}

async function readProfiles() {
  const data = await readFile(PROFILE_FILE, "utf8");
  return JSON.parse(data);
}

async function writeProfiles(profileStore) {
  await writeFile(PROFILE_FILE, JSON.stringify(profileStore, null, 2));
}

function getProfile(profileStore, studentId) {
  const id = studentId || "anonymous";
  profileStore.profiles[id] ||= {
    studentId: id,
    createdAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
    exams: {}
  };
  profileStore.profiles[id].lastSeenAt = new Date().toISOString();
  return profileStore.profiles[id];
}

function getExamProfile(profile, examID) {
  const id = examID || "unknown-exam";
  profile.exams[id] ||= {
    examID: id,
    attempts: [],
    domains: {},
    mistakeLog: []
  };
  return profile.exams[id];
}

function getDomainStats(examProfile, domainTitle) {
  const title = domainTitle || "General";
  examProfile.domains[title] ||= {
    seen: 0,
    correct: 0,
    missed: 0,
    guessed: 0,
    pbqMissed: 0,
    confidence: {},
    objectives: {},
    lastMistakeAt: null
  };
  return examProfile.domains[title];
}

function learnFromMistake(profile, context = {}) {
  const examProfile = getExamProfile(profile, context.examID);
  const domainStats = getDomainStats(examProfile, context.domainTitle);
  const wasCorrect = Boolean(context.wasCorrect);
  const confidence = context.confidence || "Not marked";

  domainStats.seen += 1;
  domainStats.correct += wasCorrect ? 1 : 0;
  domainStats.missed += wasCorrect ? 0 : 1;
  domainStats.guessed += confidence.toLowerCase().includes("guess") ? 1 : 0;
  domainStats.pbqMissed += !wasCorrect && context.isPerformanceBased ? 1 : 0;
  domainStats.confidence[confidence] = (domainStats.confidence[confidence] || 0) + 1;
  domainStats.objectives[context.objective || "General review"] = (domainStats.objectives[context.objective || "General review"] || 0) + (wasCorrect ? 0 : 1);
  domainStats.lastMistakeAt = wasCorrect ? domainStats.lastMistakeAt : new Date().toISOString();

  examProfile.mistakeLog.unshift({
    at: new Date().toISOString(),
    domainTitle: context.domainTitle,
    objective: context.objective,
    wasCorrect,
    confidence,
    isPerformanceBased: Boolean(context.isPerformanceBased),
    itemKind: context.itemKind,
    prompt: context.questionPrompt
  });

  examProfile.mistakeLog = examProfile.mistakeLog.slice(0, 100);
}

function learnFromAttempt(profile, upload = {}) {
  const examProfile = getExamProfile(profile, upload.examID);
  const attempt = upload.attempt || {};
  examProfile.attempts.unshift({
    at: new Date().toISOString(),
    title: attempt.title,
    scaledScore: attempt.scaledScore,
    passingScore: attempt.passingScore,
    percent: attempt.percent,
    pbqPercent: attempt.pbqPercent,
    guessedCount: attempt.guessedCount,
    flaggedCount: attempt.flaggedCount,
    weakDomains: upload.weakDomains || []
  });
  examProfile.attempts = examProfile.attempts.slice(0, 25);

  for (const [domainID, percent] of Object.entries(attempt.domainPercents || {})) {
    const domainStats = getDomainStats(examProfile, domainID);
    domainStats.seen += 1;
    if (percent >= 0.75) {
      domainStats.correct += 1;
    } else {
      domainStats.missed += 1;
      domainStats.lastMistakeAt = new Date().toISOString();
    }
  }
}

function buildTutorResponse(context = {}, profile, source) {
  const exam = EXAM_BLUEPRINTS[context.examID] || {
    name: context.examName || "StudyBuddy exam",
    code: context.examCode || "",
    labTypes: ["hands-on lab"]
  };
  const weakestDomain = findWeakestDomain(profile, context.examID) || context.domainTitle || "this objective";
  const isPBQ = Boolean(context.isPerformanceBased);
  const missed = !context.wasCorrect;
  const pattern = missed
    ? mistakePatternFor(context)
    : "The answer was correct, so reinforce the reasoning and watch for overconfidence.";

  return {
    sessionId: crypto.randomUUID(),
    coachMessage: missed
      ? `Let's slow this down. For ${exam.name} ${exam.code}, your miss points to ${context.domainTitle || weakestDomain}. I want you to explain the clue in the scenario before choosing a tool or control.`
      : `Good answer. Now prove it: explain why the correct choice fits the scenario and why the strongest distractor does not.`,
    mistakePattern: pattern,
    guidingQuestions: guidingQuestionsFor(context),
    assignments: [
      {
        type: "questions",
        title: "Targeted question set",
        detail: `Answer 30 original ${context.domainTitle || weakestDomain} questions with no hints, then review only missed items.`,
        count: 30
      },
      {
        type: "flashcards",
        title: "Spaced flashcards",
        detail: `Review weak terms from ${context.domainTitle || weakestDomain}; guessed cards return sooner.`,
        count: 12
      },
      {
        type: "pbq",
        title: isPBQ ? "PBQ redo" : "PBQ transfer drill",
        detail: `Complete one ${exam.labTypes[0]} scenario and narrate each decision before submitting.`,
        count: 1
      },
      {
        type: "lab",
        title: "Hands-on reinforcement",
        detail: `Spend ${Math.min(Math.max(context.targetStudyMinutes || 30, 15), 60)} minutes in a ${exam.labTypes[1] || "hands-on"} lab mapped to this weakness.`,
        count: 1
      },
      {
        type: "video",
        title: "Video review",
        detail: "Watch one objective-matched lesson, then write three clues that would reveal this topic on exam day.",
        count: 1
      }
    ],
    nextAction: "Answer the guiding questions out loud before starting the assigned practice.",
    source
  };
}

function buildAttemptResponse(upload = {}, weakestDomain) {
  return {
    sessionId: crypto.randomUUID(),
    coachMessage: `Attempt saved. StudyBuddy will prioritize ${weakestDomain || "your lowest objective"} next.`,
    mistakePattern: "Full-attempt analytics updated the adaptive learning profile.",
    guidingQuestions: [
      "Which objective cost you the most points?",
      "Were those misses knowledge gaps, rushed reading, or confidence errors?",
      "What evidence would prove the right answer next time?"
    ],
    assignments: [
      {
        type: "questions",
        title: "Weak objective recovery",
        detail: `Complete 30 questions from ${weakestDomain || "the lowest scoring objective"}.`,
        count: 30
      },
      {
        type: "pbq",
        title: "PBQ pressure drill",
        detail: "Complete one PBQ before doing any multiple-choice review.",
        count: 1
      }
    ],
    nextAction: "Open the weakest objective and complete the assigned recovery set.",
    source: "local"
  };
}

function mistakePatternFor(context) {
  if (context.isPerformanceBased) {
    return "PBQ workflow error: the student may be moving too fast before reading every constraint.";
  }
  if ((context.itemKind || "").toLowerCase().includes("multiple")) {
    return "Multi-select trap: the student may be choosing true statements instead of all required answers.";
  }
  if ((context.confidence || "").toLowerCase().includes("guess")) {
    return "Confidence gap: the student guessed, so the answer does not yet show durable mastery.";
  }
  return "Scenario-reading gap: the student likely recognized familiar terms but missed the deciding clue.";
}

function guidingQuestionsFor(context) {
  const domain = context.domainTitle || "this objective";
  if ((context.examCode || "").includes("1201") && domain.toLowerCase().includes("network")) {
    return [
      "What symptom tells you whether this is DHCP, DNS, gateway, wireless, or physical layer?",
      "What command or tool would prove your theory with the least disruption?",
      "Which answer sounds true but does not match the first troubleshooting step?"
    ];
  }
  if ((context.examCode || "").includes("1202")) {
    return [
      "What evidence source would you check before changing the system?",
      "Which option fixes the issue while respecting least privilege, documentation, and user impact?",
      "What verification step proves the problem is actually resolved?"
    ];
  }
  if ((context.examCode || "").includes("701")) {
    return [
      "What risk or control objective is the question really testing?",
      "Which option reduces risk without creating a larger operational problem?",
      "What log, policy, or architecture clue eliminates the strongest distractor?"
    ];
  }
  return [
    `What clue in the scenario points to ${domain}?`,
    "Which answer is merely true, and which answer best fits the constraint?",
    "What would you do first if this were a real ticket or incident?"
  ];
}

function findWeakestDomain(profile, examID) {
  const examProfile = profile?.exams?.[examID];
  if (!examProfile) return null;

  return Object.entries(examProfile.domains)
    .map(([domain, stats]) => {
      const total = Math.max(stats.correct + stats.missed, 1);
      return { domain, missRate: stats.missed / total, seen: stats.seen };
    })
    .sort((a, b) => b.missRate - a.missRate || b.seen - a.seen)[0]?.domain || null;
}

function buildStudyPath(payload = {}, profile) {
  const exam = EXAM_BLUEPRINTS[payload.examID] || {
    name: payload.examName || "StudyBuddy exam",
    code: payload.examCode || "",
    domains: []
  };
  const days = Math.min(Math.max(Number(payload.daysAvailable || 10), 1), 60);
  const minutes = Math.min(Math.max(Number(payload.minutesPerDay || 45), 15), 180);
  const weakest = findWeakestDomain(profile, payload.examID);

  const plan = Array.from({ length: days }, (_, index) => {
    const domain = weakest || exam.domains[index % Math.max(exam.domains.length, 1)] || "Mixed review";
    return {
      day: index + 1,
      focus: index === days - 1 ? "Final exam simulation" : domain,
      tasks: index === days - 1
        ? ["Real Exam Mode", "Review flagged questions", "Mistake notebook", "Light flashcards"]
        : ["Objective reading", "Spaced flashcards", "Targeted quiz", "PBQ or lab drill"],
      minutes
    };
  });

  return {
    exam: `${exam.name} ${exam.code}`.trim(),
    days,
    adaptiveFocus: weakest || "Start with the highest-weight objective until the first scored attempt is saved.",
    plan
  };
}

async function buildOpenAITutorResponse(context, profile, fallback) {
  if (!isOpenAIConfigured()) {
    return fallback;
  }

  try {
    const ai = await callOpenAI({
      task: "mistake_tutor",
      context,
      learnerProfile: summarizeProfile(profile, context.examID),
      fallbackShape: fallback
    });
    return normalizeTutorResponse(ai, "openai", fallback);
  } catch (error) {
    return {
      ...fallback,
      coachMessage: `${fallback.coachMessage} The OpenAI call failed, so this is local fallback coaching. Server detail: ${error instanceof Error ? error.message : String(error)}`,
      source: "local-fallback"
    };
  }
}

async function buildChatResponse(context = {}, messages = [], profile) {
  const lastUserMessage = [...messages].reverse().find((message) => message.role === "user")?.content || "";
  const fallback = {
    sessionId: crypto.randomUUID(),
    reply: `Let's reason it out. In ${context.examCode || "this exam"}, what clue in the scenario matters most here, and what answer would that clue eliminate first?`,
    source: "local"
  };

  if (!isOpenAIConfigured()) {
    return fallback;
  }

  try {
    const ai = await callOpenAI({
      task: "follow_up_chat",
      context,
      learnerProfile: summarizeProfile(profile, context.examID),
      messages,
      instruction: `Reply to the student's follow-up as a Socratic tutor. Student said: ${lastUserMessage}`
    });
    const text = typeof ai === "string" ? ai : ai.reply || ai.coachMessage || fallback.reply;
    return {
      sessionId: crypto.randomUUID(),
      reply: text,
      source: "openai"
    };
  } catch {
    return fallback;
  }
}

async function callOpenAI(payload) {
  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${(process.env.OPENAI_API_KEY || "").trim()}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: OPENAI_MODEL,
      input: [
        {
          role: "system",
          content: [{ type: "input_text", text: SYSTEM_PROMPT }]
        },
        {
          role: "user",
          content: [{ type: "input_text", text: JSON.stringify(payload) }]
        }
      ],
      max_output_tokens: 1100
    })
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error?.message || `OpenAI request failed with status ${response.status}`);
  }

  const text = extractOutputText(data);
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function isOpenAIConfigured() {
  return openAIKeyStatus() === "configured";
}

function openAIKeyStatus() {
  const key = (process.env.OPENAI_API_KEY || "").trim();
  if (!key) return "missing";
  if (!key.startsWith("sk-")) return "invalid-prefix";
  return "configured";
}

function extractOutputText(data) {
  if (typeof data.output_text === "string" && data.output_text.trim()) {
    return data.output_text;
  }

  const chunks = [];
  for (const item of data.output || []) {
    for (const content of item.content || []) {
      if (content.text) chunks.push(content.text);
    }
  }
  return chunks.join("\n").trim();
}

function normalizeTutorResponse(ai, source, fallback) {
  if (typeof ai === "string") {
    return {
      ...fallback,
      coachMessage: ai,
      source
    };
  }

  return {
    sessionId: crypto.randomUUID(),
    coachMessage: ai.coachMessage || fallback.coachMessage,
    mistakePattern: ai.mistakePattern || fallback.mistakePattern,
    guidingQuestions: Array.isArray(ai.guidingQuestions) && ai.guidingQuestions.length ? ai.guidingQuestions : fallback.guidingQuestions,
    assignments: Array.isArray(ai.assignments) && ai.assignments.length ? ai.assignments : fallback.assignments,
    nextAction: ai.nextAction || fallback.nextAction,
    source
  };
}

function summarizeProfile(profile, examID) {
  const examProfile = profile?.exams?.[examID];
  if (!examProfile) {
    return { summary: "No prior attempts for this exam yet." };
  }

  const domains = Object.entries(examProfile.domains).map(([domain, stats]) => ({
    domain,
    seen: stats.seen,
    missed: stats.missed,
    correct: stats.correct,
    guessed: stats.guessed,
    pbqMissed: stats.pbqMissed,
    topMissedObjectives: Object.entries(stats.objectives || {})
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([objective, misses]) => ({ objective, misses }))
  }));

  return {
    attemptCount: examProfile.attempts.length,
    recentAttempts: examProfile.attempts.slice(0, 5),
    weakestDomain: findWeakestDomain(profile, examID),
    domains
  };
}

async function readBody(request, maximumBytes = 1_048_576) {
  const chunks = [];
  let totalBytes = 0;
  for await (const chunk of request) {
    totalBytes += chunk.length;
    if (totalBytes > maximumBytes) {
      throw new AppAttestError("request_too_large", "The request body is too large.", 413);
    }
    chunks.push(chunk);
  }

  return Buffer.concat(chunks);
}

function parseJson(rawBody) {
  const raw = rawBody.toString("utf8");
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new AppAttestError("request_invalid_json", "The request body is not valid JSON.", 400);
  }
}

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, { "Content-Type": "application/json" });
  response.end(JSON.stringify(payload));
}

function sendHtml(response, statusCode, html) {
  response.writeHead(statusCode, { "Content-Type": "text/html; charset=utf-8" });
  response.end(html);
}

function sendRedirect(response, location) {
  response.writeHead(303, { Location: location });
  response.end();
}

function setSecurityResponseHeaders(response) {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
}

function sendDashboardUnauthorized(response) {
  setSecurityResponseHeaders(response);
  response.setHeader("WWW-Authenticate", 'Basic realm="Daybreak Sentinel", charset="UTF-8"');
  sendJson(response, 401, { error: "Authentication required." });
}

function setCorsHeaders(request, response) {
  const requestOrigin = request.headers.origin;
  const allowOrigin = ALLOWED_ORIGINS.includes("*") || !requestOrigin
    ? "*"
    : ALLOWED_ORIGINS.includes(requestOrigin) ? requestOrigin : ALLOWED_ORIGINS[0];
  response.setHeader("Access-Control-Allow-Origin", allowOrigin);
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  response.setHeader(
    "Access-Control-Allow-Headers",
    ["Content-Type", "Authorization", ...Object.values(APP_ATTEST_HEADERS)].join(",")
  );
  response.setHeader("Access-Control-Expose-Headers", "X-StudyBuddy-App-Attest-Status");
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  return ["1", "true", "yes", "on"].includes(String(value).trim().toLowerCase());
}

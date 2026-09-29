const SYSTEM_PROMPT = [
  "You are Daybreak Sentinel, a defensive security triage assistant.",
  "Analyze only the supplied allowlisted posture checks.",
  "Do not claim a compromise from an unknown or failed check.",
  "Do not provide shell commands, remote-access changes, credential changes, file deletion, process termination, exploit steps, or offensive guidance.",
  "Recommend only cautious verification and reversible operating-system settings.",
  "Return strict JSON with keys summary, priority, and recommendations.",
  "priority must be informational, low, medium, high, or critical; recommendations must be an array of at most five short strings."
].join(" ");

const PRIORITIES = new Set(["informational", "low", "medium", "high", "critical"]);

export class SecurityAIError extends Error {
  constructor(code, message, statusCode = 503) {
    super(message);
    this.name = "SecurityAIError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

export class SecurityAIAnalyzer {
  constructor({ enabled = false, apiKey = "", model = "", fetchImpl = globalThis.fetch }) {
    this.enabled = Boolean(enabled);
    this.apiKey = String(apiKey).trim();
    this.model = String(model).trim();
    this.fetchImpl = fetchImpl;
  }

  get configured() {
    return this.enabled && this.apiKey.startsWith("sk-") && Boolean(this.model) && typeof this.fetchImpl === "function";
  }

  async analyze(event) {
    if (!this.configured) {
      throw new SecurityAIError("security_ai_not_configured", "AI-assisted security review is not configured.");
    }

    const safeInput = {
      platform: event.platform,
      observedAt: event.observedAt,
      risk: event.risk,
      checks: Object.fromEntries(
        Object.entries(event.checks).map(([name, check]) => [name, { status: check.status, detail: check.detail }])
      )
    };
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20_000);
    let response;
    try {
      response = await this.fetchImpl("https://api.openai.com/v1/responses", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: this.model,
          input: [
            { role: "system", content: [{ type: "input_text", text: SYSTEM_PROMPT }] },
            { role: "user", content: [{ type: "input_text", text: JSON.stringify(safeInput) }] }
          ],
          max_output_tokens: 500
        }),
        signal: controller.signal
      });
    } catch {
      throw new SecurityAIError("security_ai_unavailable", "AI-assisted security review is temporarily unavailable.", 502);
    } finally {
      clearTimeout(timeout);
    }

    let data;
    try {
      data = await response.json();
    } catch {
      throw new SecurityAIError("security_ai_invalid_response", "AI-assisted security review returned an invalid response.", 502);
    }
    if (!response.ok) {
      throw new SecurityAIError("security_ai_request_failed", "AI-assisted security review could not be completed.", 502);
    }

    const text = extractOutputText(data).replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new SecurityAIError("security_ai_invalid_json", "AI-assisted security review returned invalid JSON.", 502);
    }
    return normalizeAnalysis(parsed);
  }
}

function normalizeAnalysis(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new SecurityAIError("security_ai_invalid_shape", "AI-assisted security review returned an invalid result.", 502);
  }
  const summary = boundedText(value.summary, 600);
  const priority = PRIORITIES.has(value.priority) ? value.priority : "informational";
  const recommendations = Array.isArray(value.recommendations)
    ? value.recommendations.slice(0, 5).map((item) => boundedText(item, 240)).filter(Boolean)
    : [];
  if (!summary) {
    throw new SecurityAIError("security_ai_missing_summary", "AI-assisted security review did not include a summary.", 502);
  }
  return { summary, priority, recommendations };
}

function boundedText(value, maximum) {
  if (typeof value !== "string") return "";
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, maximum);
}

function extractOutputText(data) {
  if (typeof data.output_text === "string" && data.output_text.trim()) return data.output_text;
  const chunks = [];
  for (const item of data.output || []) {
    for (const content of item.content || []) {
      if (typeof content.text === "string") chunks.push(content.text);
    }
  }
  return chunks.join("\n").trim();
}

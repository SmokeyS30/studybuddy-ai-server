import assert from "node:assert/strict";
import test from "node:test";
import { SecurityAIAnalyzer } from "../securityAI.js";

const event = {
  agentId: "private-device-name",
  platform: "macos",
  observedAt: "2026-09-29T16:00:00.000Z",
  risk: { score: 25, level: "medium", findings: ["Firewall needs attention"] },
  checks: {
    firewall: { status: "fail", detail: "Application firewall is disabled." }
  }
};

test("sends only sanitized posture fields for explicit AI review", async () => {
  let requestBody;
  const analyzer = new SecurityAIAnalyzer({
    enabled: true,
    apiKey: "sk-test-value",
    model: "test-model",
    fetchImpl: async (_url, options) => {
      requestBody = JSON.parse(options.body);
      return {
        ok: true,
        async json() {
          return {
            output_text: JSON.stringify({
              summary: "The firewall check needs attention.",
              priority: "medium",
              recommendations: ["Verify the firewall setting locally."]
            })
          };
        }
      };
    }
  });

  const result = await analyzer.analyze(event);
  const serializedPrompt = JSON.stringify(requestBody.input);
  assert.equal(serializedPrompt.includes("private-device-name"), false);
  assert.equal(result.priority, "medium");
  assert.deepEqual(result.recommendations, ["Verify the firewall setting locally."]);
});

test("fails closed when AI review is disabled", async () => {
  const analyzer = new SecurityAIAnalyzer({ enabled: false, apiKey: "sk-test-value", model: "test-model" });

  await assert.rejects(
    analyzer.analyze(event),
    (error) => error.code === "security_ai_not_configured" && error.statusCode === 503
  );
});

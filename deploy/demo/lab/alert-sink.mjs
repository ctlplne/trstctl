import { timingSafeEqual } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import http from "node:http";

const limit = 128 * 1024;
const opsGenieKey = readFileSync("/lab-runtime/opsgenie-api-key");
const pagerDutyKey = readFileSync("/lab-runtime/pagerduty-routing-key");
const equal = (actual, expected) => {
  const value = Buffer.from(actual);
  return value.length === expected.length && timingSafeEqual(value, expected);
};
const json = (res, status, body) => {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
};
const record = (entry) => appendFileSync(
  "/lab-evidence/alerts.ndjson",
  `${JSON.stringify({ observed_at: new Date().toISOString(), ...entry })}\n`,
  { mode: 0o600 },
);

http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    return json(res, 200, { ready: true, channels: ["opsgenie", "pagerduty"] });
  }
  const opsGenie = req.method === "POST" && req.url === "/v2/alerts";
  const pagerDuty = req.method === "POST" && req.url === "/v2/enqueue";
  if (!opsGenie && !pagerDuty) return json(res, 404, { error: "not found" });

  const chunks = [];
  let size = 0;
  let oversized = false;
  req.on("data", (chunk) => {
    size += chunk.length;
    if (size > limit) oversized = true;
    else if (!oversized) chunks.push(chunk);
  });
  req.on("end", () => {
    if (oversized) return json(res, 413, { error: "request too large" });
    try {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (opsGenie) {
        const auth = req.headers.authorization ?? "";
        if (!auth.startsWith("GenieKey ") || !equal(auth.slice(9), opsGenieKey)) {
          return json(res, 401, { error: "unauthorized" });
        }
        if (typeof body.alias !== "string" || !body.alias.startsWith("trstctl-") || typeof body.message !== "string") {
          return json(res, 400, { error: "invalid alert" });
        }
        record({
          channel: "opsgenie",
          message: body.message.slice(0, 160),
          alias: body.alias.slice(0, 128),
          entity: String(body.entity ?? "").slice(0, 128),
          priority: String(body.priority ?? ""),
          authentication: "exact GenieKey matched; value discarded",
        });
        return json(res, 202, { result: "Request will be processed", requestId: `local-${Date.now()}` });
      }
      if (typeof body.routing_key !== "string" || !equal(body.routing_key, pagerDutyKey)) {
        return json(res, 401, { error: "unauthorized" });
      }
      if (body.event_action !== "trigger" || typeof body.dedup_key !== "string" ||
          !body.dedup_key.startsWith("trstctl-") || typeof body.payload?.summary !== "string") {
        return json(res, 400, { error: "invalid event" });
      }
      record({
        channel: "pagerduty",
        summary: body.payload.summary.slice(0, 160),
        dedup_key: body.dedup_key.slice(0, 128),
        kind: String(body.payload.custom_details?.kind ?? "").slice(0, 80),
        severity: String(body.payload.severity ?? ""),
        authentication: "exact routing key matched; value discarded",
      });
      return json(res, 202, { status: "success", message: "Event processed", dedup_key: body.dedup_key });
    } catch {
      return json(res, 400, { error: "invalid JSON" });
    }
  });
}).listen(18082, "127.0.0.1", () => console.log("partner lab incident sink listening on 127.0.0.1:18082"));

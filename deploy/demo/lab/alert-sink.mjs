import { appendFileSync } from "node:fs";
import http from "node:http";

const limit = 128 * 1024;
http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ ready: true }));
  }
  if (req.method !== "POST" || req.url !== "/v2/alerts") {
    res.writeHead(404); return res.end();
  }
  const auth = req.headers.authorization ?? "";
  const chunks = [];
  let size = 0;
  req.on("data", (chunk) => {
    size += chunk.length;
    if (size > limit) req.destroy(new Error("request too large"));
    else chunks.push(chunk);
  });
  req.on("end", () => {
    try {
      if (!auth.startsWith("GenieKey ") || auth.length <= "GenieKey ".length) {
        res.writeHead(401); return res.end();
      }
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      appendFileSync("/lab-evidence/alerts.ndjson", `${JSON.stringify({
        observed_at: new Date().toISOString(),
        message: String(body.message ?? "").slice(0, 160),
        alias: String(body.alias ?? "").slice(0, 128),
        entity: String(body.entity ?? "").slice(0, 128),
        priority: String(body.priority ?? ""),
        source: String(body.source ?? ""),
        authentication: "GenieKey present; value discarded",
      })}\n`, { mode: 0o600 });
      res.writeHead(202, { "content-type": "application/json" });
      res.end(JSON.stringify({ result: "Request will be processed", requestId: `local-${Date.now()}` }));
    } catch {
      res.writeHead(400); res.end();
    }
  });
}).listen(18082, "127.0.0.1", () => console.log("partner lab alert sink listening on 127.0.0.1:18082"));

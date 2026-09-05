import http from "node:http";

const limit = 64 * 1024;
const upstream = "http://pebble-challtestsrv:8055";
let presented = 0;
let cleaned = 0;

function reply(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") return reply(res, 200, { ready: true, presented, cleaned });
  if (req.method !== "POST" || !["/present", "/cleanup"].includes(req.url)) return reply(res, 404, { error: "not found" });
  const chunks = [];
  let size = 0;
  req.on("data", (chunk) => {
    size += chunk.length;
    if (size > limit) req.destroy(new Error("request too large"));
    else chunks.push(chunk);
  });
  req.on("end", async () => {
    try {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const action = req.url.slice(1);
      if (body.action !== action || typeof body.name !== "string" || typeof body.value !== "string") {
        return reply(res, 400, { error: "invalid DNS webhook request" });
      }
      const host = body.name.endsWith(".") ? body.name : `${body.name}.`;
      const endpoint = action === "present" ? "/set-txt" : "/clear-txt";
      const payload = action === "present" ? { host, value: body.value } : { host };
      const response = await fetch(upstream + endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) return reply(res, 502, { error: `challenge server returned HTTP ${response.status}` });
      if (action === "present") presented += 1;
      else cleaned += 1;
      return reply(res, 200, { ok: true, action, host });
    } catch (error) {
      return reply(res, 500, { error: String(error?.message ?? error) });
    }
  });
}).listen(8056, "127.0.0.1", () => console.log("partner lab DNS webhook listening on 127.0.0.1:8056"));

import http from "node:http";
import { readFileSync } from "node:fs";
import { createPrivateKey, sign } from "node:crypto";

const host = process.env.OIDC_HOST || "127.0.0.1";
const port = Number(process.env.OIDC_PORT || "19081");
const issuer = process.env.OIDC_ISSUER || `http://${host}:${port}`;
const clientID = process.env.OIDC_CLIENT_ID || "trstctl-demo-ui";
const tenant = process.env.OIDC_TENANT || "11111111-1111-4111-8111-111111111111";
const defaultSubject = process.env.OIDC_SUBJECT || "demo-admin";
const defaultEmail = process.env.OIDC_EMAIL || "demo-admin@trstctl.local";
const defaultName = process.env.OIDC_NAME || "Demo Admin";
const keyID = process.env.OIDC_KEY_ID || "trstctl-demo-idp";
const keyPath = process.env.OIDC_PRIVATE_KEY || "/demo-oidc/idp-private.pem";
const jwksPath = process.env.OIDC_JWKS || "/demo-oidc/jwks.json";

const privateKey = createPrivateKey(readFileSync(keyPath, "utf8"));
const jwks = readFileSync(jwksPath, "utf8");

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function json(res, status, body) {
  const raw = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(raw),
    "cache-control": "no-store",
  });
  res.end(raw);
}

function redirect(res, location) {
  res.writeHead(302, { location, "cache-control": "no-store" });
  res.end();
}

function signIDToken(claims) {
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: keyID }));
  const payload = b64url(JSON.stringify(claims));
  const signingInput = `${header}.${payload}`;
  const signature = sign("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

function decodeCode(code) {
  return JSON.parse(Buffer.from(code, "base64url").toString("utf8"));
}

function encodeCode(payload) {
  return Buffer.from(JSON.stringify(payload)).toString("base64url");
}

async function readForm(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || "/", issuer);
    if (req.method === "GET" && url.pathname === "/healthz") {
      return json(res, 200, { status: "ok" });
    }
    if (req.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
      return json(res, 200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
      });
    }
    if (req.method === "GET" && url.pathname === "/jwks") {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      return res.end(jwks);
    }
    if (req.method === "GET" && url.pathname === "/authorize") {
      const redirectURI = url.searchParams.get("redirect_uri");
      const state = url.searchParams.get("state") || "";
      const nonce = url.searchParams.get("nonce") || "";
      const subject = url.searchParams.get("login_as") || defaultSubject;
      if (!redirectURI) {
        return json(res, 400, { error: "invalid_request", error_description: "redirect_uri is required" });
      }
      const code = encodeCode({
        sub: subject,
        email: subject === defaultSubject ? defaultEmail : `${subject}@trstctl.local`,
        name: subject === defaultSubject ? defaultName : subject,
        tenant,
        nonce,
      });
      const target = new URL(redirectURI);
      target.searchParams.set("code", code);
      target.searchParams.set("state", state);
      return redirect(res, target.toString());
    }
    if (req.method === "POST" && url.pathname === "/token") {
      const form = await readForm(req);
      if (form.get("client_id") && form.get("client_id") !== clientID) {
        return json(res, 400, { error: "invalid_client" });
      }
      const code = form.get("code") || "";
      if (!code) {
        return json(res, 400, { error: "invalid_grant" });
      }
      const login = decodeCode(code);
      const now = Math.floor(Date.now() / 1000);
      const idToken = signIDToken({
        iss: issuer,
        aud: clientID,
        sub: login.sub,
        email: login.email,
        name: login.name,
        tenant: login.tenant,
        nonce: login.nonce,
        iat: now,
        exp: now + 3600,
      });
      return json(res, 200, { id_token: idToken, token_type: "Bearer", expires_in: 3600 });
    }
    return json(res, 404, { error: "not_found" });
  } catch (err) {
    return json(res, 500, { error: "server_error", error_description: err.message });
  }
});

server.listen(port, host, () => {
  console.log(`demo OIDC IdP listening on ${issuer}`);
});

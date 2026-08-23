import http from "node:http";
import { readFileSync } from "node:fs";
import { createHash, createPrivateKey, randomBytes, sign, timingSafeEqual } from "node:crypto";

const host = process.env.OIDC_HOST || "127.0.0.1";
const port = Number(process.env.OIDC_PORT || "18081");
const issuer = process.env.OIDC_ISSUER || `http://${host}:${port}`;
const clientID = process.env.OIDC_CLIENT_ID || "trstctl-local-eval-ui";
const configuredRedirectURI = process.env.OIDC_REDIRECT_URI;
const tenant = process.env.OIDC_TENANT || "11111111-1111-4111-8111-111111111111";
const subject = process.env.OIDC_SUBJECT || "eval-admin";
const email = process.env.OIDC_EMAIL || "eval-admin@trstctl.local";
const displayName = process.env.OIDC_NAME || "Evaluation Admin";
const keyID = process.env.OIDC_KEY_ID || "trstctl-local-eval-idp";
const keyPath = process.env.OIDC_PRIVATE_KEY || "/local-oidc/idp-private.pem";
const jwksPath = process.env.OIDC_JWKS || "/local-oidc/jwks.json";
const authorizationCodeTTL = 2 * 60 * 1000;
const maxAuthorizationCodes = 256;
const maxFormBytes = 16 * 1024;

if (!configuredRedirectURI) {
  throw new Error("OIDC_REDIRECT_URI is required; the local IdP must allow exactly one callback");
}

const privateKey = createPrivateKey(readFileSync(keyPath, "utf8"));
const jwks = readFileSync(jwksPath, "utf8");
const authorizationCodes = new Map();

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function responseHeaders(contentType) {
  return {
    "content-type": contentType,
    "cache-control": "no-store",
    pragma: "no-cache",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  };
}

function json(res, status, body) {
  const raw = JSON.stringify(body);
  res.writeHead(status, { ...responseHeaders("application/json"), "content-length": Buffer.byteLength(raw) });
  res.end(raw);
}

function redirect(res, location) {
  res.writeHead(302, { ...responseHeaders("text/plain; charset=utf-8"), location });
  res.end();
}

function signIDToken(claims) {
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: keyID }));
  const payload = b64url(JSON.stringify(claims));
  const signingInput = `${header}.${payload}`;
  const signature = sign("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

function constantTimeEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function cleanupExpiredCodes(now = Date.now()) {
  for (const [code, record] of authorizationCodes) {
    if (now - record.createdAt > authorizationCodeTTL) authorizationCodes.delete(code);
  }
}

async function readForm(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxFormBytes) throw new Error("request_too_large");
    chunks.push(chunk);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

function authorize(url, res) {
  const redirectURI = url.searchParams.get("redirect_uri") || "";
  const requestedClientID = url.searchParams.get("client_id") || "";
  const responseType = url.searchParams.get("response_type") || "";
  const scope = (url.searchParams.get("scope") || "").split(/\s+/);
  const state = url.searchParams.get("state") || "";
  const nonce = url.searchParams.get("nonce") || "";
  const codeChallenge = url.searchParams.get("code_challenge") || "";
  const codeChallengeMethod = url.searchParams.get("code_challenge_method") || "";

  // Never redirect an error to an untrusted URL. The local evaluator has one
  // client and one callback, so an exact allowlist is both simpler and safer.
  if (redirectURI !== configuredRedirectURI) {
    return json(res, 400, { error: "invalid_request", error_description: "redirect_uri is not allowed" });
  }
  if (requestedClientID !== clientID || responseType !== "code" || !scope.includes("openid")) {
    return json(res, 400, { error: "invalid_request", error_description: "client_id, response_type=code, and openid scope are required" });
  }
  if (!state || !nonce) {
    return json(res, 400, { error: "invalid_request", error_description: "state and nonce are required" });
  }
  if (codeChallengeMethod !== "S256" || !/^[A-Za-z0-9_-]{43,128}$/.test(codeChallenge)) {
    return json(res, 400, { error: "invalid_request", error_description: "PKCE S256 is required" });
  }

  cleanupExpiredCodes();
  if (authorizationCodes.size >= maxAuthorizationCodes) {
    return json(res, 503, { error: "temporarily_unavailable" });
  }
  const code = randomBytes(32).toString("base64url");
  authorizationCodes.set(code, {
    clientID,
    redirectURI,
    nonce,
    codeChallenge,
    createdAt: Date.now(),
  });
  const target = new URL(configuredRedirectURI);
  target.searchParams.set("code", code);
  target.searchParams.set("state", state);
  return redirect(res, target.toString());
}

async function exchange(req, res) {
  let form;
  try {
    form = await readForm(req);
  } catch {
    return json(res, 413, { error: "invalid_request", error_description: "token request is too large" });
  }
  const code = form.get("code") || "";
  const record = authorizationCodes.get(code);
  // Consume an opaque code exactly once, including on a bad verifier. An
  // attacker cannot safely probe one code repeatedly and a browser retry cannot
  // accidentally mint a second session credential.
  authorizationCodes.delete(code);

  if (!record || Date.now() - record.createdAt > authorizationCodeTTL) {
    return json(res, 400, { error: "invalid_grant" });
  }
  if (
    form.get("grant_type") !== "authorization_code" ||
    form.get("client_id") !== record.clientID ||
    form.get("redirect_uri") !== record.redirectURI
  ) {
    return json(res, 400, { error: "invalid_grant" });
  }
  const codeVerifier = form.get("code_verifier") || "";
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier)) {
    return json(res, 400, { error: "invalid_grant" });
  }
  const calculatedChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
  if (!constantTimeEqual(calculatedChallenge, record.codeChallenge)) {
    return json(res, 400, { error: "invalid_grant" });
  }

  const now = Math.floor(Date.now() / 1000);
  const idToken = signIDToken({
    iss: issuer,
    aud: clientID,
    sub: subject,
    email,
    name: displayName,
    tenant,
    nonce: record.nonce,
    iat: now,
    exp: now + 3600,
  });
  return json(res, 200, { id_token: idToken, token_type: "Bearer", expires_in: 3600 });
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
        code_challenge_methods_supported: ["S256"],
      });
    }
    if (req.method === "GET" && url.pathname === "/jwks") {
      res.writeHead(200, responseHeaders("application/json"));
      return res.end(jwks);
    }
    if (req.method === "GET" && url.pathname === "/authorize") return authorize(url, res);
    if (req.method === "POST" && url.pathname === "/token") return exchange(req, res);
    return json(res, 404, { error: "not_found" });
  } catch {
    return json(res, 500, { error: "server_error" });
  }
});

server.requestTimeout = 10_000;
server.headersTimeout = 10_000;
server.listen(port, host, () => {
  console.log(`local evaluation OIDC IdP listening on ${issuer}`);
});

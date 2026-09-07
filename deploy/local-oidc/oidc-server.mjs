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

// Provider-operator sign-in (opt-in). A licensed deployment's provider plane
// accepts bearer tokens from an offline-pinned IdP that carries role and MFA
// claims. This local IdP mints such a token for exactly one registered provider
// client when OIDC_PROVIDER_CLIENT_ID is set: GET /provider/sign-in shows who
// you are signing in as and a single-use form; POST /provider/token with that
// form's nonce returns the bearer. Like the tenant flow, it asks no password:
// this IdP is a loopback-only evaluation stand-in, never an internet identity.
const providerClientID = process.env.OIDC_PROVIDER_CLIENT_ID || "";
const providerSubject = process.env.OIDC_PROVIDER_SUBJECT || "provider-admin";
const providerEmail = process.env.OIDC_PROVIDER_EMAIL || "provider-admin@trstctl.local";
const providerName = process.env.OIDC_PROVIDER_NAME || "Provider Admin";
const providerRoles = (process.env.OIDC_PROVIDER_ROLES || "provider-admin").split(",").map((r) => r.trim()).filter(Boolean);
const providerMFA = (process.env.OIDC_PROVIDER_MFA || "mfa").split(",").map((r) => r.trim()).filter(Boolean);
const providerSignInNonces = new Map();
const providerNonceTTL = 5 * 60 * 1000;
const maxProviderNonces = 256;

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

function html(res, status, body) {
  res.writeHead(status, { ...responseHeaders("text/html; charset=utf-8"), "content-length": Buffer.byteLength(body) });
  res.end(body);
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function providerSignInPage(res) {
  for (const [nonce, createdAt] of providerSignInNonces) {
    if (Date.now() - createdAt > providerNonceTTL) providerSignInNonces.delete(nonce);
  }
  if (providerSignInNonces.size >= maxProviderNonces) {
    return json(res, 503, { error: "temporarily_unavailable" });
  }
  const nonce = randomBytes(24).toString("base64url");
  providerSignInNonces.set(nonce, Date.now());
  return html(res, 200, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Provider operator sign-in</title></head>
<body style="font-family:system-ui;max-width:40rem;margin:3rem auto;line-height:1.5">
<h1>Provider operator sign-in</h1>
<p>Local evaluation identity provider for <code>${escapeHTML(issuer)}</code>. Signing in as
<strong>${escapeHTML(providerName)}</strong> (<code>${escapeHTML(providerEmail)}</code>) with roles
<code>${escapeHTML(providerRoles.join(", "))}</code> and MFA proof <code>${escapeHTML(providerMFA.join(", "))}</code>
for client <code>${escapeHTML(providerClientID)}</code>.</p>
<form method="post" action="/provider/token"><input type="hidden" name="nonce" value="${escapeHTML(nonce)}">
<button type="submit">Sign in and show the operator token</button></form>
<p>Paste the token into the console's Provider page (<code>/provider</code>). It expires after one hour.</p>
</body></html>`);
}

async function providerToken(req, res) {
  let form;
  try {
    form = await readForm(req);
  } catch {
    return json(res, 413, { error: "invalid_request", error_description: "token request is too large" });
  }
  const nonce = form.get("nonce") || "";
  const createdAt = providerSignInNonces.get(nonce);
  providerSignInNonces.delete(nonce);
  if (!createdAt || Date.now() - createdAt > providerNonceTTL) {
    return json(res, 400, { error: "invalid_grant", error_description: "sign-in form nonce is missing, used, or expired" });
  }
  const now = Math.floor(Date.now() / 1000);
  const token = signIDToken({
    iss: issuer,
    aud: providerClientID,
    sub: providerSubject,
    email: providerEmail,
    name: providerName,
    roles: providerRoles,
    amr: providerMFA,
    iat: now,
    exp: now + 3600,
  });
  if ((req.headers.accept || "").includes("application/json") || form.get("format") === "json") {
    return json(res, 200, { access_token: token, token_type: "Bearer", expires_in: 3600 });
  }
  return html(res, 200, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Provider operator token</title></head>
<body style="font-family:system-ui;max-width:40rem;margin:3rem auto;line-height:1.5">
<h1>Operator token issued</h1><p>Copy the token below into the console's Provider page. It is shown once and expires in one hour.</p>
<pre style="white-space:pre-wrap;word-break:break-all;border:1px solid #999;padding:1rem">${escapeHTML(token)}</pre>
</body></html>`);
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
    if (providerClientID && req.method === "GET" && url.pathname === "/provider/sign-in") return providerSignInPage(res);
    if (providerClientID && req.method === "POST" && url.pathname === "/provider/token") return providerToken(req, res);
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

import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";

const outDir = process.env.OIDC_KEY_DIR || "/demo-oidc";
const privateKeyPath = `${outDir}/idp-private.pem`;
const jwksPath = `${outDir}/jwks.json`;
const kid = process.env.OIDC_KEY_ID || "trstctl-demo-idp";

mkdirSync(outDir, { recursive: true });

if (!existsSync(privateKeyPath) || !existsSync(jwksPath)) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = kid;
  jwk.alg = "RS256";
  jwk.use = "sig";

  writeFileSync(privateKeyPath, privatePem, { mode: 0o600 });
  writeFileSync(jwksPath, JSON.stringify({ keys: [jwk] }, null, 2) + "\n", { mode: 0o644 });
}

console.log(`demo OIDC JWKS ready at ${jwksPath}`);

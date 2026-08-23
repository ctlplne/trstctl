import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";

const commonDir = process.env.OIDC_KEY_DIR || "/local-oidc";
const privateKeyDir = process.env.OIDC_PRIVATE_KEY_DIR || commonDir;
const jwksDir = process.env.OIDC_JWKS_DIR || commonDir;
const privateKeyPath = `${privateKeyDir}/idp-private.pem`;
const jwksPath = `${jwksDir}/jwks.json`;
const keyID = process.env.OIDC_KEY_ID || "trstctl-local-eval-idp";

mkdirSync(privateKeyDir, { recursive: true, mode: 0o700 });
mkdirSync(jwksDir, { recursive: true, mode: 0o755 });

function pairMatches() {
  if (!existsSync(privateKeyPath) || !existsSync(jwksPath)) return false;
  try {
    const privateKey = createPrivateKey(readFileSync(privateKeyPath));
    const publicJWK = createPublicKey(privateKey).export({ format: "jwk" });
    const document = JSON.parse(readFileSync(jwksPath, "utf8"));
    const published = document?.keys?.find((key) => key.kid === keyID);
    return Boolean(published && published.kty === publicJWK.kty && published.n === publicJWK.n && published.e === publicJWK.e);
  } catch {
    return false;
  }
}

// One Compose init job owns this directory. A partial pair is never reusable:
// regenerate both files and rename complete temporary files into place so the
// control plane cannot read a JWKS that does not match the IdP's private key.
if (!pairMatches()) {
  const suffix = randomBytes(8).toString("hex");
  const privateKeyTemp = `${privateKeyPath}.${suffix}.tmp`;
  const jwksTemp = `${jwksPath}.${suffix}.tmp`;
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = keyID;
  jwk.alg = "RS256";
  jwk.use = "sig";

  try {
    writeFileSync(privateKeyTemp, privatePem, { mode: 0o600 });
    writeFileSync(jwksTemp, `${JSON.stringify({ keys: [jwk] }, null, 2)}\n`, { mode: 0o644 });
    renameSync(privateKeyTemp, privateKeyPath);
    renameSync(jwksTemp, jwksPath);
  } catch (error) {
    for (const path of [privateKeyTemp, jwksTemp]) {
      if (existsSync(path)) unlinkSync(path);
    }
    throw error;
  }
}

console.log(`local evaluation OIDC public keys are ready at ${jwksPath}`);

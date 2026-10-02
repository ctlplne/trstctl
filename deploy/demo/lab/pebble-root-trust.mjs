import { createHash, X509Certificate } from "node:crypto";

const certificatePattern = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const maxTrustedRoots = 32;

function parseRoots(input, label) {
  const text = String(input ?? "");
  if (!text.trim()) return [];
  const blocks = text.match(certificatePattern) ?? [];
  if (!blocks.length || text.replace(certificatePattern, "").trim()) {
    throw new Error(`${label} must contain only PEM certificates`);
  }
  return blocks.map((block) => {
    const certificate = new X509Certificate(block);
    if (!certificate.ca || certificate.subject !== certificate.issuer || !certificate.verify(certificate.publicKey)) {
      throw new Error(`${label} contains a certificate that is not a self-signed CA root`);
    }
    return {
      fingerprint: createHash("sha256").update(certificate.raw).digest("hex"),
      pem: `${certificate.toString().trim()}\n`,
    };
  });
}

// Retained listeners can still serve a valid certificate from the preceding
// Pebble instance while the restarted CA issues from a new root. Keep the
// authenticated roots for an overlap window, as a real CA rotation requires.
// A bounded bundle prevents accidental unbounded growth or a silent trust skip.
export function mergePebbleRoots(previousPEM, currentPEM) {
  const current = parseRoots(currentPEM, "current Pebble root");
  if (current.length !== 1) throw new Error("current Pebble root must contain exactly one certificate");
  const trusted = new Map();
  for (const root of [...parseRoots(previousPEM, "retained Pebble roots"), current[0]]) {
    trusted.set(root.fingerprint, root.pem);
  }
  if (trusted.size > maxTrustedRoots) {
    throw new Error(`retained Pebble root limit (${maxTrustedRoots}) reached; retire old lab certificates before pruning trust`);
  }
  return {
    bundlePEM: [...trusted.values()].join(""),
    currentPEM: current[0].pem,
    currentFingerprint: current[0].fingerprint,
    trustedFingerprints: [...trusted.keys()],
  };
}

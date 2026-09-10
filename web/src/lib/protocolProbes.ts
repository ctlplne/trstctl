import { translateNow } from "@/i18n/I18nProvider";
import {
  previewTransportIsIsolated,
  previewRefusal,
  type ProtocolRuntimeStatus,
  type ProtocolRuntimeStatusList,
  type ESTQualificationCheck,
  type ESTQualificationResult,
  type SCEPQualificationCheck,
  type SCEPQualificationResult,
} from "./api";

// These are the shipped browser diagnostics, not stock-client conformance
// evidence. Loading is deferred; responder checks and refusal behavior are
// unchanged from the typed API implementation.
interface ProtocolProbeSpec {
  protocol: string;
  endpoint: string;
  method?: "GET" | "HEAD";
  credentials?: RequestCredentials;
  accept?: string;
  methodMismatchMeansServed?: boolean;
  successDetail: string;
  methodMismatchDetail?: string;
}

const protocolStatusProbes: ProtocolProbeSpec[] = [
  {
    protocol: "acme",
    endpoint: "/directory",
    accept: "application/json",
    successDetail: "ACME directory responded.",
  },
  {
    protocol: "est",
    endpoint: "/.well-known/est/cacerts",
    credentials: "omit",
    accept: "application/pkcs7-mime, application/pkcs7, */*",
    successDetail: "EST CA-certs responder returned a chain.",
  },
  {
    protocol: "scep",
    endpoint: "/scep?operation=GetCACaps",
    accept: "text/plain, */*",
    successDetail: "SCEP capabilities responder returned caps.",
  },
  {
    protocol: "cmp",
    endpoint: "/cmp",
    method: "GET",
    methodMismatchMeansServed: true,
    successDetail: "CMP responder accepted the probe.",
    methodMismatchDetail: "CMP route is mounted and expects a PKIMessage request.",
  },
  {
    protocol: "ssh",
    endpoint: "/ssh/ca",
    accept: "text/plain, */*",
    successDetail: "SSH CA public-key endpoint responded.",
  },
  {
    protocol: "tsa",
    endpoint: "/tsa",
    method: "GET",
    methodMismatchMeansServed: true,
    successDetail: "TSA responder accepted the probe.",
    methodMismatchDetail: "TSA route is mounted and expects a timestamp request.",
  },
];

async function protocolProbe(spec: ProtocolProbeSpec): Promise<ProtocolRuntimeStatus> {
  if (previewTransportIsIsolated()) {
    return {
      protocol: spec.protocol,
      endpoint: spec.endpoint,
      enabled: false,
      served: false,
      get detail() {
        return translateNow("preview.probesDisabled");
      },
    };
  }
  try {
    const res = await fetch(spec.endpoint, {
      method: spec.method ?? "GET",
      credentials: spec.credentials ?? "include",
      headers: { Accept: spec.accept ?? "*/*" },
    });
    const methodMismatchServed = spec.methodMismatchMeansServed === true && res.status === 405;
    const candidateStatus = res.ok || methodMismatchServed;
    const contentMatches = candidateStatus && (await protocolProbeContentMatches(spec, res));
    const ok = candidateStatus && contentMatches;
    return {
      protocol: spec.protocol,
      endpoint: spec.endpoint,
      enabled: ok,
      served: ok,
      status_code: res.status,
      detail: ok
        ? methodMismatchServed
          ? (spec.methodMismatchDetail ?? "Responder is mounted and expects a protocol request.")
          : spec.successDetail
        : candidateStatus
          ? "Unexpected responder content; protocol status could not be verified."
          : protocolProbeFailureDetail(res),
    };
  } catch {
    return {
      protocol: spec.protocol,
      endpoint: spec.endpoint,
      enabled: false,
      served: false,
      get detail() {
        return translateNow("source.responder.probe.failed.before.an.http.stat.e6657440c5");
      },
    };
  }
}

async function protocolProbeContentMatches(spec: ProtocolProbeSpec, res: Response): Promise<boolean> {
  const mediaType = (res.headers.get("Content-Type") ?? "").split(";", 1)[0].trim().toLowerCase();
  const bytes = new Uint8Array(await res.arrayBuffer());
  if (bytes.byteLength === 0 || bytes.byteLength > 1 << 20) return false;
  const text = new TextDecoder().decode(bytes);

  switch (spec.protocol) {
    case "acme": {
      if (mediaType !== "application/json") return false;
      try {
        const directory = JSON.parse(text) as Record<string, unknown>;
        return ["newNonce", "newAccount", "newOrder", "keyChange", "revokeCert"].every(
          (field) => typeof directory[field] === "string" && (directory[field] as string).length > 0,
        );
      } catch {
        return false;
      }
    }
    case "est": {
      if (mediaType !== "application/pkcs7-mime" || res.headers.get("Content-Transfer-Encoding")?.toLowerCase() !== "base64") return false;
      const encoded = text.replace(/\s/g, "");
      if (!encoded || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) return false;
      try {
        const der = globalThis.atob(encoded);
        return der.length > 1 && der.charCodeAt(0) === 0x30;
      } catch {
        return false;
      }
    }
    case "scep": {
      if (mediaType !== "text/plain") return false;
      const capabilities = new Set(
        text
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean),
      );
      return ["POSTPKIOperation", "SHA-256", "SCEPStandard"].every((capability) => capabilities.has(capability));
    }
    case "cmp":
      return res.status === 405 && mediaType === "text/plain" && text.trim() === "cmp: POST required (RFC 6712)";
    case "ssh":
      return mediaType === "text/plain" && /^(?:ssh-(?:rsa|ed25519)|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/]+={0,3}(?:\s|$)/.test(text.trim());
    case "tsa":
      return (
        res.status === 405 &&
        mediaType === "text/plain" &&
        (res.headers.get("Allow") ?? "")
          .split(",")
          .map((method) => method.trim().toUpperCase())
          .includes("POST") &&
        text.trim() === "method not allowed"
      );
    default:
      return false;
  }
}

export async function estQualification(): Promise<ESTQualificationResult> {
  const ca = await protocolProbe(protocolStatusProbes.find((spec) => spec.protocol === "est")!);
  const checks: ESTQualificationCheck[] = [
    {
      id: "ca-chain",
      method: "GET",
      endpoint: "/.well-known/est/cacerts",
      expected: "HTTP 200 with a base64 PKCS#7 CA chain",
      status_code: ca.status_code,
      passed: ca.served,
      detail: ca.served ? translateNow("protocols.estCheck.caPassed") : (ca.detail ?? translateNow("protocols.estCheck.caFailed")),
    },
  ];

  if (previewTransportIsIsolated()) {
    checks.push(
      {
        id: "csr-rules",
        method: "GET",
        endpoint: "/.well-known/est/csrattrs",
        expected: "HTTP 204 or a valid CSR-attributes response",
        passed: false,
        detail: translateNow("preview.probesDisabled"),
      },
      {
        id: "auth-gate",
        method: "POST",
        endpoint: "/.well-known/est/simpleenroll",
        expected: "HTTP 401 with a Bearer authentication challenge",
        passed: false,
        detail: translateNow("preview.probesDisabled"),
      },
    );
    return { checked_at: new Date().toISOString(), passed: false, checks };
  }

  try {
    const response = await fetch("/.well-known/est/csrattrs", {
      method: "GET",
      credentials: "omit",
      headers: { Accept: "application/csrattrs, */*" },
    });
    const passed = response.status === 204;
    checks.push({
      id: "csr-rules",
      method: "GET",
      endpoint: "/.well-known/est/csrattrs",
      expected: "HTTP 204 or a valid CSR-attributes response",
      status_code: response.status,
      passed,
      detail: passed ? translateNow("protocols.estCheck.csrPassed") : translateNow("protocols.estCheck.csrHTTPFailed", { status: response.status }),
    });
  } catch {
    checks.push({
      id: "csr-rules",
      method: "GET",
      endpoint: "/.well-known/est/csrattrs",
      expected: "HTTP 204 or a valid CSR-attributes response",
      passed: false,
      detail: translateNow("protocols.estCheck.csrNetworkFailed"),
    });
  }

  try {
    const response = await fetch("/.well-known/est/simpleenroll", {
      method: "POST",
      credentials: "omit",
      headers: { Accept: "application/pkcs7-mime, */*", "Content-Type": "application/pkcs10" },
    });
    const challenge = response.headers.get("WWW-Authenticate") ?? "";
    const passed = response.status === 401 && /^Bearer(?:\s|$)/i.test(challenge);
    checks.push({
      id: "auth-gate",
      method: "POST",
      endpoint: "/.well-known/est/simpleenroll",
      expected: "HTTP 401 with a Bearer authentication challenge",
      status_code: response.status,
      passed,
      detail: passed
        ? translateNow("protocols.estCheck.authPassed")
        : response.status === 401
          ? translateNow("protocols.estCheck.authChallengeFailed")
          : translateNow("protocols.estCheck.authHTTPFailed", { status: response.status }),
    });
  } catch {
    checks.push({
      id: "auth-gate",
      method: "POST",
      endpoint: "/.well-known/est/simpleenroll",
      expected: "HTTP 401 with a Bearer authentication challenge",
      passed: false,
      detail: translateNow("protocols.estCheck.authNetworkFailed"),
    });
  }

  return {
    checked_at: new Date().toISOString(),
    passed: checks.every((check) => check.passed),
    checks,
  };
}

function isDefiniteLengthDERSequence(bytes: Uint8Array): boolean {
  if (bytes.byteLength < 3 || bytes.byteLength > 1 << 20 || bytes[0] !== 0x30) return false;
  const firstLength = bytes[1];
  if (firstLength < 0x80) return 2 + firstLength === bytes.byteLength;
  const lengthOctets = firstLength & 0x7f;
  if (lengthOctets === 0 || lengthOctets > 4 || bytes.byteLength < 2 + lengthOctets) return false;
  if (bytes[2] === 0) return false;
  let contentLength = 0;
  for (let index = 0; index < lengthOctets; index += 1) contentLength = contentLength * 256 + bytes[2 + index];
  return 2 + lengthOctets + contentLength === bytes.byteLength;
}

export async function scepQualification(): Promise<SCEPQualificationResult> {
  if (previewTransportIsIsolated()) throw previewRefusal();

  const checks: SCEPQualificationCheck[] = [];
  try {
    const response = await fetch("/scep?operation=GetCACaps", {
      method: "GET",
      credentials: "omit",
      headers: { Accept: "text/plain" },
    });
    const mediaType = (response.headers.get("Content-Type") ?? "").split(";", 1)[0].trim().toLowerCase();
    const capabilities = new Set(
      (await response.text())
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean),
    );
    const passed =
      response.status === 200 &&
      mediaType === "text/plain" &&
      ["POSTPKIOperation", "SHA-256", "SCEPStandard"].every((capability) => capabilities.has(capability));
    checks.push({
      id: "capabilities",
      method: "GET",
      endpoint: "/scep?operation=GetCACaps",
      expected: "HTTP 200 with POSTPKIOperation, SHA-256, and SCEPStandard",
      status_code: response.status,
      passed,
      detail: passed
        ? translateNow("protocols.scepCheck.capabilitiesPassed")
        : translateNow("protocols.scepCheck.capabilitiesHTTPFailed", { status: response.status }),
    });
  } catch {
    checks.push({
      id: "capabilities",
      method: "GET",
      endpoint: "/scep?operation=GetCACaps",
      expected: "HTTP 200 with POSTPKIOperation, SHA-256, and SCEPStandard",
      passed: false,
      detail: translateNow("protocols.scepCheck.capabilitiesNetworkFailed"),
    });
  }

  try {
    const response = await fetch("/scep?operation=GetCACert", {
      method: "GET",
      credentials: "omit",
      headers: { Accept: "application/x-x509-ca-cert, application/x-x509-ca-ra-cert" },
    });
    const mediaType = (response.headers.get("Content-Type") ?? "").split(";", 1)[0].trim().toLowerCase();
    const bytes = new Uint8Array(await response.arrayBuffer());
    const passed =
      response.status === 200 &&
      (mediaType === "application/x-x509-ca-cert" || mediaType === "application/x-x509-ca-ra-cert") &&
      isDefiniteLengthDERSequence(bytes);
    checks.push({
      id: "ca-material",
      method: "GET",
      endpoint: "/scep?operation=GetCACert",
      expected: "HTTP 200 with a structurally valid CA certificate or CA/RA bundle",
      status_code: response.status,
      passed,
      detail: passed ? translateNow("protocols.scepCheck.caPassed") : translateNow("protocols.scepCheck.caHTTPFailed", { status: response.status }),
    });
  } catch {
    checks.push({
      id: "ca-material",
      method: "GET",
      endpoint: "/scep?operation=GetCACert",
      expected: "HTTP 200 with a structurally valid CA certificate or CA/RA bundle",
      passed: false,
      detail: translateNow("protocols.scepCheck.caNetworkFailed"),
    });
  }

  try {
    const response = await fetch("/scep?operation=PKIOperation", {
      method: "POST",
      credentials: "omit",
      headers: { Accept: "text/plain", "Content-Type": "application/x-pki-message" },
    });
    const mediaType = (response.headers.get("Content-Type") ?? "").split(";", 1)[0].trim().toLowerCase();
    const body = await response.text();
    const passed = response.status === 400 && mediaType === "text/plain" && body.trim() === "scep: empty PKIOperation body";
    checks.push({
      id: "empty-message-gate",
      method: "POST",
      endpoint: "/scep?operation=PKIOperation",
      expected: "HTTP 400 before an empty PKI message can reach enrollment",
      status_code: response.status,
      passed,
      detail: passed ? translateNow("protocols.scepCheck.emptyPassed") : translateNow("protocols.scepCheck.emptyHTTPFailed", { status: response.status }),
    });
  } catch {
    checks.push({
      id: "empty-message-gate",
      method: "POST",
      endpoint: "/scep?operation=PKIOperation",
      expected: "HTTP 400 before an empty PKI message can reach enrollment",
      passed: false,
      detail: translateNow("protocols.scepCheck.emptyNetworkFailed"),
    });
  }

  return { checked_at: new Date().toISOString(), passed: checks.every((check) => check.passed), checks };
}

function protocolProbeFailureDetail(res: Response): string {
  if (res.status === 404) return "Responder path was not mounted by this control plane.";
  if (res.status === 503) return "Responder is mounted but currently unavailable.";
  if (res.status === 401 || res.status === 403) return "Responder rejected the browser session.";
  return res.statusText || `Responder returned HTTP ${res.status}.`;
}

export async function protocolStatuses(): Promise<ProtocolRuntimeStatusList> {
  return {
    source: "public_responder_probe",
    checked_at: new Date().toISOString(),
    items: await Promise.all(protocolStatusProbes.map((spec) => protocolProbe(spec))),
  };
}

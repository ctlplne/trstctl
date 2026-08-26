import type { EnrollmentToken } from "@/lib/api";

export interface AgentInstallPlan {
  command: string;
  blockedReason?: string;
}

interface AgentInstallPlanInput {
  origin: string;
  agentName: string;
  roles?: EnrollmentToken["roles"];
  multiline?: boolean;
}

/** Build the single agent command used by every console enrollment journey. */
export function buildAgentInstallPlan({ origin, agentName, roles = [], multiline = false }: AgentInstallPlanInput): AgentInstallPlan {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return { command: "", blockedReason: "The console URL is not a valid enrollment base URL. Open trstctl from its configured HTTPS address." };
  }

  const loopback = isLoopbackHostname(url.hostname);
  const loopbackHTTP = url.protocol === "http:" && loopback;
  if (url.protocol !== "https:" && !loopbackHTTP) {
    return {
      command: "",
      blockedReason:
        "Agent enrollment is blocked on this page because bootstrap tokens need HTTPS. Open trstctl from its configured HTTPS address; plain HTTP is allowed only on this machine's loopback address.",
    };
  }

  const connection = loopback ? { server: "localhost:19443", serverName: "localhost" } : { server: `${url.hostname}:9443`, serverName: url.hostname };
  const args = [
    "trstctl-agent",
    `--enroll-url ${shellArg(url.origin)}`,
    ...(loopbackHTTP ? ["--allow-insecure-loopback-enrollment"] : []),
    "--bootstrap-token-file ./trstctl-bootstrap-token",
    `--server ${shellArg(connection.server)}`,
    `--server-name ${shellArg(connection.serverName)}`,
    `--name ${shellArg(agentName.trim() || "edge-agent-1")}`,
    "--ca-bundle ./trstctl-ca.pem",
    "--inventory-cert-roots /etc/ssl,/etc/pki/tls/certs",
    "--inventory-os-trust-roots /etc/ssl/certs",
    "--inventory-private-key-roots /etc/ssl/private,/etc/ssh",
    ...(roles.includes("network") ? ["--relay-claim"] : []),
  ];
  return { command: args.join(multiline ? " \\\n  " : " ") };
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

function shellArg(value: string): string {
  if (/^[A-Za-z0-9._:/@-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\\''")}'`;
}

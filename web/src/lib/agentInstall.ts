import type { EnrollmentToken } from "@/lib/api";

export interface AgentInstallPlan {
  command: string;
  blockedReason?: string;
}

interface AgentInstallPlanInput {
  origin: string;
  agentName: string;
  roles?: EnrollmentToken["roles"];
  agentServer?: string;
  agentServerName?: string;
  multiline?: boolean;
}

/** Build the single agent command used by every console enrollment journey. */
export function buildAgentInstallPlan({
  origin,
  agentName,
  roles = [],
  agentServer,
  agentServerName,
  multiline = false,
}: AgentInstallPlanInput): AgentInstallPlan {
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

  const server = agentServer?.trim() ?? "";
  const serverName = agentServerName?.trim() ?? "";
  if (!server || !serverName) {
    return {
      command: "",
      blockedReason:
        "Agent enrollment is not ready because this control plane did not publish its agent endpoint. Set agent_channel.public_address (TRSTCTL_AGENT_CHANNEL_PUBLIC_ADDRESS) and reload the console.",
    };
  }

  const args = [
    "trstctl-agent",
    `--enroll-url ${shellArg(url.origin)}`,
    ...(loopbackHTTP ? ["--allow-insecure-loopback-enrollment"] : []),
    "--bootstrap-token-file ./trstctl-bootstrap-token",
    `--server ${shellArg(server)}`,
    `--server-name ${shellArg(serverName)}`,
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

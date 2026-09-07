// Enrolls a provider customer's own host agent for the lab's customer listener.
// Run once per customer tenant after the provider has provisioned it:
//   TRSTCTL_LAB_CUSTOMER_TOKEN_FILE=/secure/acme.token docker compose ... run --rm lab-customer-enroll
// The token file holds an API token scoped to the customer tenant (minted with
// `trstctl token create --tenant <customer tenant id>` on the control plane).
// The helper mints a one-time agent enrollment token inside that tenant, writes
// it and the agent arguments into the front-door state volume (0600, service
// uid), and the front-door entrypoint starts the customer agent from them.
// Nothing is printed except sanitized progress.
import { chmodSync, chownSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const server = process.env.TRSTCTL_LAB_SERVER || "https://trstctl:8443";
const tokenFile = process.env.TRSTCTL_LAB_CUSTOMER_TOKEN_FILE_IN || "/customer/token";
const agentName = process.env.TRSTCTL_LAB_CUSTOMER_AGENT_NAME || "customer-edge-agent";
const stateDir = "/frontdoors-state/customer";
if (!existsSync(tokenFile)) {
  console.error(`customer enroll: token file ${tokenFile} is missing; mount the customer tenant's API token file read-only`);
  process.exit(2);
}
const bearer = readFileSync(tokenFile, "utf8").trim();
if (!bearer) {
  console.error("customer enroll: the mounted token file is empty; set TRSTCTL_LAB_CUSTOMER_TOKEN_FILE to the customer tenant's 0600 API token file");
  process.exit(2);
}
mkdirSync(stateDir, { recursive: true, mode: 0o700 });
chownSync(stateDir, 65532, 65532);
const bootstrapPath = `${stateDir}/bootstrap.token`;
const argsPath = `${stateDir}/args`;
if (existsSync(`${stateDir}/agent.crt`) || existsSync(bootstrapPath)) {
  console.log("customer enroll: the customer agent is already enrolled or its token is already staged; nothing to do");
  process.exit(0);
}
const response = await fetch(`${server}/api/v1/agents/enrollment-tokens`, {
  method: "POST",
  headers: { authorization: `Bearer ${bearer}`, "content-type": "application/json", "idempotency-key": `lab-customer-enroll-${agentName}-${Date.now()}` },
  body: JSON.stringify({ allowed_identity: agentName, roles: ["host"] }),
});
if (!response.ok) {
  console.error(`customer enroll: enrollment token request failed with HTTP ${response.status}`);
  process.exit(1);
}
const minted = await response.json();
if (typeof minted.token !== "string" || minted.token.length < 20) {
  console.error("customer enroll: enrollment token response was empty");
  process.exit(1);
}
writeFileSync(bootstrapPath, minted.token, { mode: 0o600, flag: "wx" });
writeFileSync(argsPath, [
  "--enroll-url=https://localhost:8443",
  `--bootstrap-token-file=${bootstrapPath.replace("/frontdoors-state", "/lab/state")}`,
  "--server=127.0.0.1:9443",
  "--server-name=localhost",
  `--name=${agentName}`,
  "--ca-bundle=/lab/state/ca-bundle.pem",
  "--cert=/lab/state/customer/agent.crt",
  "--key=/lab/state/customer/agent.key",
  "--relay-claim",
  "--relay-poll-every=1s",
  "",
].join("\n"), { mode: 0o600 });
for (const path of [bootstrapPath, argsPath]) {
  chownSync(path, 65532, 65532);
  chmodSync(path, 0o600);
}
console.log(`customer enroll: one-time enrollment token staged for ${agentName}; the front-door agent watcher starts it within seconds`);

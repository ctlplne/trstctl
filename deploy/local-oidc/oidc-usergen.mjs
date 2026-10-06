import { existsSync, mkdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { randomBytes, scryptSync } from "node:crypto";

const usersPath = process.env.OIDC_USERS_FILE || "/local-oidc-private/users.json";
const credentialsPath = process.env.OIDC_CREDENTIALS_FILE || "/local-oidc-private/operator-credentials.json";
const tenant = process.env.OIDC_TENANT || "11111111-1111-4111-8111-111111111111";
const operators = [
  { subject: "eval-admin", email: "eval-admin@trstctl.local", name: "Evaluation Admin" },
  { subject: "eval-custodian-1", email: "eval-custodian-1@trstctl.local", name: "Evaluation Custodian 1" },
  { subject: "eval-custodian-2", email: "eval-custodian-2@trstctl.local", name: "Evaluation Custodian 2" },
];

if (usersPath === credentialsPath) throw new Error("OIDC user verifier and initial credential paths must differ");
mkdirSync(dirname(usersPath), { recursive: true, mode: 0o700 });
mkdirSync(dirname(credentialsPath), { recursive: true, mode: 0o700 });
process.umask(0o077);

function privateFile(path) {
  const info = statSync(path);
  if (!info.isFile() || (info.mode & 0o077) !== 0) throw new Error(`${path} must be a private regular file (0600)`);
  return JSON.parse(readFileSync(path, "utf8"));
}

const existingUsers = existsSync(usersPath);
const existingCredentials = existsSync(credentialsPath);
if (existingUsers !== existingCredentials) {
  throw new Error("local OIDC credential pair is incomplete; inspect the private volume before recovery");
}
if (existingUsers) {
  const users = privateFile(usersPath);
  const credentials = privateFile(credentialsPath);
  if (users.version !== 1 || users.generation !== credentials.generation ||
      users.tenant !== tenant || !Array.isArray(users.users) || !Array.isArray(credentials.users) ||
      users.users.length !== operators.length || credentials.users.length !== operators.length ||
      !operators.every((operator, index) => users.users[index]?.subject === operator.subject &&
        credentials.users[index]?.subject === operator.subject)) {
    throw new Error("local OIDC credentials do not match this evaluation identity roster; refusing silent rotation");
  }
  console.log("local evaluation OIDC operator identities are ready (existing private credential pair)");
} else {
  const generation = randomBytes(16).toString("base64url");
  const users = [];
  const credentials = [];
  for (const operator of operators) {
    const password = randomBytes(32).toString("base64url");
    const salt = randomBytes(16);
    const verifier = scryptSync(password, salt, 32);
    users.push({ ...operator, salt: salt.toString("base64url"), password_hash: verifier.toString("base64url") });
    credentials.push({ subject: operator.subject, password });
    salt.fill(0);
    verifier.fill(0);
  }
  const suffix = randomBytes(8).toString("hex");
  const usersTemp = `${usersPath}.${suffix}.tmp`;
  const credentialsTemp = `${credentialsPath}.${suffix}.tmp`;
  try {
    writeFileSync(usersTemp, JSON.stringify({ version: 1, generation, tenant, users }, null, 2) + "\n", { mode: 0o600, flag: "wx" });
    writeFileSync(credentialsTemp, JSON.stringify({ version: 1, generation, users: credentials }, null, 2) + "\n", { mode: 0o600, flag: "wx" });
    renameSync(usersTemp, usersPath);
    renameSync(credentialsTemp, credentialsPath);
  } catch (error) {
    for (const path of [usersTemp, credentialsTemp]) if (existsSync(path)) unlinkSync(path);
    throw error;
  }
  console.log("local evaluation OIDC operator identities are ready (new private credential pair)");
}

import { randomBytes } from "node:crypto";
import { chmodSync, chownSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

for (const path of ["/lab-runtime", "/lab-evidence"]) {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chownSync(path, 65532, 65532);
  chmodSync(path, 0o700);
}
const keyPath = "/lab-runtime/opsgenie-api-key";
if (!existsSync(keyPath)) {
  writeFileSync(keyPath, randomBytes(24).toString("base64url"), { mode: 0o600, flag: "wx" });
}
chownSync(keyPath, 65532, 65532);
chmodSync(keyPath, 0o600);
// Licensed profile: the operator's 0600 license file is bind-mounted read-only
// here and copied once into the run-owned runtime volume for the service uid.
// The host file keeps its owner and mode; the copy is 0400 for uid 65532.
const licenseIn = process.env.TRSTCTL_LAB_LICENSE_IN || "";
if (licenseIn) {
  if (!existsSync(licenseIn)) {
    console.error(`licensed lab: TRSTCTL_LAB_LICENSE_IN=${licenseIn} is not readable inside lab-init`);
    process.exit(2);
  }
  const licenseOut = "/lab-runtime/license.json";
  writeFileSync(licenseOut, readFileSync(licenseIn), { mode: 0o400 });
  chownSync(licenseOut, 65532, 65532);
  chmodSync(licenseOut, 0o400);
  console.log("partner lab: operator license copied into the runtime volume for the control plane and the signer");
}
console.log("partner lab runtime directories and file-backed synthetic alert credential are ready");

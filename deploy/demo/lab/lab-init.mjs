import { randomBytes } from "node:crypto";
import { chmodSync, chownSync, existsSync, mkdirSync, writeFileSync } from "node:fs";

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
console.log("partner lab runtime directories and file-backed synthetic alert credential are ready");

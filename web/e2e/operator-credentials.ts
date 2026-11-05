import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";

export interface DemoOperatorCredentials {
  subject: string;
  password: string;
}

/** Read only the generated administrator from an owner-only fixture file.
 * Check and read the same descriptor, refuse links/non-files, and bound reads.
 * Parser errors never include credential bytes in public CI output. */
export function loadDemoOperatorCredentials(path: string): DemoOperatorCredentials {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  const bytes = Buffer.alloc(64 * 1024 + 1);
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || (info.mode & 0o077) !== 0) {
      throw new Error("The demo operator credentials must be a private regular file (0600)");
    }
    if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
      throw new Error("The demo operator credentials must belong to this user");
    }
    let size = 0;
    while (size < bytes.length) {
      const n = readSync(fd, bytes, size, bytes.length - size, null);
      if (n === 0) break;
      size += n;
    }
    if (size > 64 * 1024) throw new Error("The demo operator credentials file is too large");
    let record: unknown;
    try {
      record = JSON.parse(bytes.subarray(0, size).toString("utf8"));
    } catch {
      throw new Error("The demo operator credentials file is not valid JSON");
    }
    if (record === null || typeof record !== "object") throw new Error("The demo operator credentials format is invalid");
    const document = record as { version?: unknown; users?: unknown };
    if (document.version !== 1 || !Array.isArray(document.users)) throw new Error("The demo operator credentials format is invalid");
    const admin: unknown = document.users.find(
      (entry: unknown) => entry !== null && typeof entry === "object" && (entry as { subject?: unknown }).subject === "eval-admin",
    );
    if (admin === undefined) throw new Error("The demo credentials file has no eval-admin operator");
    const password = (admin as { password?: unknown }).password;
    if (typeof password !== "string" || password.length === 0 || password.length > 1024) throw new Error("The demo administrator credential is invalid");
    return { subject: "eval-admin", password };
  } finally {
    bytes.fill(0);
    closeSync(fd);
  }
}

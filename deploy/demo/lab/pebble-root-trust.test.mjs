import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { mergePebbleRoots } from "./pebble-root-trust.mjs";

const firstRoot = readFileSync(fileURLToPath(new URL("./certs/pebble.minica.crt", import.meta.url)), "utf8");

test("retained Pebble roots survive a CA restart without duplicate trust entries", () => {
  const directory = mkdtempSync(join(tmpdir(), "trstctl-pebble-root-test-"));
  try {
    const key = join(directory, "root.key");
    const certificate = join(directory, "root.crt");
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
      "-nodes", "-keyout", key, "-out", certificate, "-subj", "/CN=Pebble Root After Restart", "-days", "2"],
    { stdio: "ignore" });
    const secondRoot = readFileSync(certificate, "utf8");
    const first = mergePebbleRoots("", firstRoot);
    const afterRestart = mergePebbleRoots(first.bundlePEM, secondRoot);
    assert.equal(afterRestart.trustedFingerprints.length, 2);
    assert.equal(afterRestart.trustedFingerprints[0], first.currentFingerprint);
    assert.notEqual(afterRestart.currentFingerprint, first.currentFingerprint);
    assert.equal(afterRestart.bundlePEM.match(/-----BEGIN CERTIFICATE-----/g)?.length, 2);
    const again = mergePebbleRoots(afterRestart.bundlePEM, secondRoot);
    assert.deepEqual(again.trustedFingerprints, afterRestart.trustedFingerprints);
    assert.equal(again.bundlePEM, afterRestart.bundlePEM);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("Pebble trust import refuses malformed or non-root certificates", () => {
  assert.throws(() => mergePebbleRoots("not a certificate", firstRoot), /PEM certificates/);
  assert.throws(() => mergePebbleRoots(firstRoot, ""), /exactly one/);
  assert.throws(() => mergePebbleRoots(firstRoot, `${firstRoot}\n${firstRoot}`), /exactly one/);
  const directory = mkdtempSync(join(tmpdir(), "trstctl-pebble-leaf-test-"));
  try {
    const key = join(directory, "leaf.key");
    const certificate = join(directory, "leaf.crt");
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
      "-nodes", "-keyout", key, "-out", certificate, "-subj", "/CN=Not A CA",
      "-addext", "basicConstraints=critical,CA:FALSE", "-days", "2"], { stdio: "ignore" });
    assert.throws(() => mergePebbleRoots(readFileSync(certificate, "utf8"), firstRoot), /self-signed CA root/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

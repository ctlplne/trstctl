import { rm } from "node:fs/promises";
import { demoAuthStatePath } from "./global-setup";

export default async function globalTeardown(): Promise<void> {
  await rm(demoAuthStatePath, { force: true });
}

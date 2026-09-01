import { chmod, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { chromium, type FullConfig } from "@playwright/test";
import { signIn } from "./helpers";

export const demoAuthStatePath = resolve(process.cwd(), "test-results", ".auth", "demo-user.json");

export default async function globalSetup(config: FullConfig): Promise<void> {
  const configuredBaseURL = config.projects[0]?.use.baseURL;
  const baseURL = typeof configuredBaseURL === "string" ? configuredBaseURL : "https://127.0.0.1:9443";
  await mkdir(dirname(demoAuthStatePath), { recursive: true, mode: 0o700 });

  const browser = await chromium.launch();
  try {
    const context = await browser.newContext({ baseURL, ignoreHTTPSErrors: true });
    const page = await context.newPage();
    await signIn(page);
    await context.storageState({ path: demoAuthStatePath });
    await chmod(demoAuthStatePath, 0o600);
    await context.close();
  } finally {
    await browser.close();
  }
}

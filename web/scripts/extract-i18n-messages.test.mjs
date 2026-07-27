import assert from "node:assert/strict";
import test from "node:test";

import { astCandidates } from "./extract-i18n-messages.mjs";

test("extracts copy from guarded JSX expressions and warning fields", () => {
  const source = `
    const transport = { warning: "Connection is not encrypted." };
    const view = (
      <section>
        <p>{"Direct customer copy"}</p>
        <p>{ready ? "Ready to rotate" : \`Waiting for \${count} approvals\`}</p>
        <p>{error || "No recent refusals"}</p>
        <button aria-label={\`Pause fleet run \${runID}\`} />
        <span className={"layout-only"}>{t("message.key")}</span>
      </section>
    );
  `;

  const values = astCandidates("fixture.tsx", source)
    .map(({ value }) => value.replace(/\s+/g, " ").trim())
    .filter(Boolean)
    .sort();

  assert.deepEqual(values, [
    "Connection is not encrypted.",
    "Direct customer copy",
    "No recent refusals",
    "Pause fleet run {value1}",
    "Ready to rotate",
    "Waiting for {value1} approvals",
  ]);
});

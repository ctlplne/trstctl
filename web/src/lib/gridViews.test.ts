import { beforeEach, describe, expect, it } from "vitest";
import {
  gridStorageName,
  readGridPreferences,
  sanitizeViewMetadata,
  writeGridPreferences,
} from "@/lib/gridViews";

describe("grid view storage safety (SEC-005)", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("keeps only primitive display metadata and drops secrets or row payloads", () => {
    const safe = sanitizeViewMetadata({
      label: "Expires soon",
      count: 3,
      pinned: true,
      cleared: null,
      token: "session-token",
      bearer: "Bearer abc.def.ghi",
      password: "hunter2",
      trst_token: "trst_secret",
      privateKey: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
      rowPayload: { id: "cert-1", pem: "secret" },
      payload: { rows: [{ id: "cert-2" }] },
      tags: ["prod"],
    });

    expect(safe).toEqual({
      label: "Expires soon",
      count: 3,
      pinned: true,
      cleared: null,
    });
  });

  it("persists sanitized grid metadata rather than row payloads or auth material", () => {
    writeGridPreferences("certificates", {
      columnOrder: ["subject", "expires_at"],
      visibleColumnIds: ["subject"],
      views: [
        {
          id: "view-1",
          name: "Expiring",
          createdAt: "2026-06-20T00:00:00Z",
          columnOrder: ["subject"],
          visibleColumnIds: ["subject"],
          metadata: {
            description: "operator display preference",
            rowPayload: { subject: "CN=svc", bearer: "Bearer abc" },
            secret: "should-not-persist",
          },
        },
      ],
    });

    const raw = localStorage.getItem(gridStorageName("certificates"));
    expect(raw).toBeTruthy();
    expect(raw).not.toContain("should-not-persist");
    expect(raw).not.toContain("Bearer abc");
    expect(raw).not.toContain("rowPayload");

    expect(readGridPreferences("certificates").views[0].metadata).toEqual({
      description: "operator display preference",
    });
  });
});

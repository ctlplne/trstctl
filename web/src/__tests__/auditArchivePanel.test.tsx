import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuditArchivePanel } from "@/pages/audit/AuditArchivePanel";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    auditArchives: vi.fn(),
    downloadAuditArchive: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <AuditArchivePanel />
    </QueryClientProvider>,
  );
}

const segment = {
  id: "audit-archive-" + "a".repeat(64),
  first_record: 1,
  last_record: 42,
  boundary_sequence: 9,
  chain_head: "f".repeat(64),
  archived_at: "2026-10-31T12:00:00Z",
};

describe("A234 archived audit segments panel", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
  });

  it("lists the tenant's segments without a locator and downloads the exact signed bytes", async () => {
    apiMock.auditArchives.mockResolvedValue({ items: [segment] });
    apiMock.downloadAuditArchive.mockResolvedValue({
      segment_id: segment.id,
      format: "jws",
      bundle: "header.payload.signature",
      sha256: "0".repeat(64),
      first_record: 1,
      last_record: 42,
      prev_hash: "",
      chain_head: segment.chain_head,
    });
    const created: Blob[] = [];
    const createObjectURL = vi.fn((blob: Blob) => {
      created.push(blob);
      return "blob:segment";
    });
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", { ...URL, createObjectURL, revokeObjectURL });
    try {
      const user = userEvent.setup();
      renderPanel();
      expect(await screen.findByText("1–42")).toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: "Download" }));
      await waitFor(() => expect(apiMock.downloadAuditArchive).toHaveBeenCalledWith(segment.id));
      await waitFor(() => expect(created).toHaveLength(1));
      const saved = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onerror = reject;
        reader.onload = () => resolve(String(reader.result));
        reader.readAsText(created[0]);
      });
      expect(saved).toBe("header.payload.signature");
      expect(revokeObjectURL).toHaveBeenCalledWith("blob:segment");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("explains a refused list instead of showing an empty archive", async () => {
    apiMock.auditArchives.mockRejectedValue(new Error("forbidden: audit:archive.read required"));
    renderPanel();
    expect(await screen.findByText("Archived segments are unavailable")).toBeInTheDocument();
    expect(screen.queryByText("No segments have been archived for this tenant.")).toBeNull();
  });
});

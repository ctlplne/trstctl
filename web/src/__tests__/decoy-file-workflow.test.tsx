import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DecoyFileWorkflow } from "@/pages/secrets/DecoyFileWorkflow";

const { apiMock, can } = vi.hoisted(() => ({
  apiMock: { listDecoyFiles: vi.fn(), retireDecoyFile: vi.fn() },
  can: { value: true },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});
vi.mock("@/components/rbac", () => ({ useCan: () => can.value }));

const opened = {
  id: "f1",
  kind: "file" as const,
  name: "decoy file id_ed25519_backup",
  placement: "web-1:/root/.ssh/id_ed25519_backup",
  file_host: "web-1",
  file_path: "/root/.ssh/id_ed25519_backup",
  file_key_fingerprint: "SHA256:q6o1fixturefingerprint",
  state: "triggered" as const,
  created_at: "2026-11-12T00:00:00Z",
  triggered_at: "2026-11-12T02:00:00Z",
  trigger_method: "open, pid 31, seen by fanotify",
  trigger_path: "/root/.ssh/id_ed25519_backup",
  trigger_subject: "cat on web-1",
  readers: 2,
  reads: 3,
  last_read_at: "2026-11-12T03:00:00Z",
};

describe("Q6-O1 decoy files", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    can.value = true;
    apiMock.listDecoyFiles.mockResolvedValue({ items: [opened], next_cursor: "" });
  });

  it("lists each decoy file with its host, its key and the program that first opened it, and retires it", async () => {
    apiMock.retireDecoyFile.mockResolvedValue({ ...opened, state: "revoked" });
    render(<DecoyFileWorkflow />);
    const item = (await screen.findByText("/root/.ssh/id_ed25519_backup")).closest("li") as HTMLElement;
    expect(within(item).getByText("Host web-1")).toBeInTheDocument();
    expect(within(item).getByText("Key SHA256:q6o1fixturefingerprint")).toBeInTheDocument();
    expect(within(item).getByText(/First opened by cat on web-1 at .* \(open, pid 31, seen by fanotify\)/)).toBeInTheDocument();
    expect(within(item).getByText(/2 programs opened it 3 times; last at/)).toBeInTheDocument();
    expect(within(item).getByText("triggered")).toBeInTheDocument();
    await userEvent.click(within(item).getByRole("button", { name: "Stop alerting" }));
    expect(apiMock.retireDecoyFile).toHaveBeenCalledWith("f1");
    await waitFor(() => expect(apiMock.listDecoyFiles).toHaveBeenCalledTimes(2));
  });

  it("says how to plant decoys when none are planted", async () => {
    apiMock.listDecoyFiles.mockResolvedValue({ items: [], next_cursor: "" });
    render(<DecoyFileWorkflow />);
    expect(await screen.findByText(/Start a host agent with --decoy-ssh-keys/)).toBeInTheDocument();
  });

  it("shows nothing, and asks for nothing, to a caller who may not plant decoys", () => {
    can.value = false;
    const { container } = render(<DecoyFileWorkflow />);
    expect(container).toBeEmptyDOMElement();
    expect(apiMock.listDecoyFiles).not.toHaveBeenCalled();
  });
});

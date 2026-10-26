import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppQueryProvider } from "@/lib/query";
import { KubernetesTrustRolloutsPanel } from "@/pages/workloads/KubernetesTrustRolloutsPanel";
import type { KubernetesTrustRollout } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    kubernetesTrustRollouts: vi.fn(),
    startKubernetesTrustRollout: vi.fn(),
    pauseKubernetesTrustRollout: vi.fn(),
    resumeKubernetesTrustRollout: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const canary = "sha256:" + "a".repeat(64);
const second = "sha256:" + "b".repeat(64);

function rollout(state: KubernetesTrustRollout["state"]): KubernetesTrustRollout {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    name: "platform-roots",
    ca_bundle_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    bundle_sha256: "c".repeat(64),
    config_map_name: "platform-roots",
    key: "ca-bundle.pem",
    namespaces: ["apps"],
    state,
    verified_clusters: 1,
    created_at: "2026-10-26T12:00:00Z",
    updated_at: "2026-10-26T12:01:00Z",
    clusters: [
      { cluster_id: canary, position: 0, canary: true, state: "verified", report_id: "22222222-2222-4222-8222-222222222222" },
      { cluster_id: second, position: 1, canary: false, state: "dispatched" },
    ],
  };
}

function renderPanel() {
  return render(
    <AppQueryProvider>
      <KubernetesTrustRolloutsPanel knownClusters={[canary, second]} />
    </AppQueryProvider>,
  );
}

// A138: the console lists each rollout with every cluster's verified state,
// pauses a running rollout, and starts one with the first selected cluster as
// the canary.
describe("Kubernetes trust-bundle rollouts", () => {
  beforeEach(() => {
    apiMock.kubernetesTrustRollouts.mockReset().mockResolvedValue({ items: [rollout("running")] });
    apiMock.startKubernetesTrustRollout.mockReset().mockResolvedValue(rollout("running"));
    apiMock.pauseKubernetesTrustRollout.mockReset().mockResolvedValue(rollout("paused"));
    apiMock.resumeKubernetesTrustRollout.mockReset().mockResolvedValue(rollout("running"));
  });

  it("shows each cluster's state and pauses a running rollout", async () => {
    renderPanel();
    const item = (await screen.findByText("platform-roots")).closest("li") as HTMLElement;
    expect(within(item).getByText("1 of 2 clusters verified")).toBeInTheDocument();
    expect(within(item).getByText("canary")).toBeInTheDocument();
    expect(within(item).getByText("report 22222222")).toBeInTheDocument();
    await userEvent.click(within(item).getByRole("button", { name: /pause/i }));
    await waitFor(() => expect(apiMock.pauseKubernetesTrustRollout).toHaveBeenCalledWith("11111111-1111-4111-8111-111111111111"));
    expect(apiMock.kubernetesTrustRollouts.mock.calls.length).toBeGreaterThan(1);
  });

  it("starts a rollout with the first selected cluster as the canary", async () => {
    renderPanel();
    await screen.findByText("platform-roots");
    const start = screen.getByRole("button", { name: /start rollout/i });
    expect(start).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/TrustBundle name/), "edge-roots");
    await userEvent.type(screen.getByLabelText(/CA certificates/), "-----BEGIN CERTIFICATE-----");
    await userEvent.type(screen.getByLabelText(/^Namespaces/), "apps payments");
    const boxes = screen.getAllByRole("checkbox");
    await userEvent.click(boxes[1]);
    await userEvent.click(boxes[0]);
    expect(start).toBeEnabled();
    await userEvent.click(start);
    await waitFor(() =>
      expect(apiMock.startKubernetesTrustRollout).toHaveBeenCalledWith({
        name: "edge-roots",
        ca_bundle_pem: "-----BEGIN CERTIFICATE-----",
        namespaces: ["apps", "payments"],
        clusters: [canary, second],
      }),
    );
  });
});

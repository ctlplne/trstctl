import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DecoyKubernetesWorkflow } from "@/pages/secrets/DecoyKubernetesWorkflow";

const { apiMock, can } = vi.hoisted(() => ({
  apiMock: { listKubernetesDecoys: vi.fn(), registerKubernetesDecoy: vi.fn(), retireKubernetesDecoy: vi.fn() },
  can: { value: true },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});
vi.mock("@/components/rbac", () => ({ useCan: () => can.value }));

const decoy = {
  id: "k1",
  kind: "kubernetes" as const,
  name: "ci deployer bait",
  placement: "ci namespace",
  k8s_cluster: "prod-eu",
  k8s_namespace: "ci",
  k8s_service_account: "ci-deployer",
  k8s_secret: "ci-deployer-token",
  state: "triggered" as const,
  created_at: "2026-11-12T00:00:00Z",
  triggered_at: "2026-11-12T01:00:00Z",
  trigger_method: "token Secret read: get secrets (200)",
  trigger_subject: "alice@example.com from 10.0.0.7",
};

describe("Q6-O2 Kubernetes token decoys", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    can.value = true;
    apiMock.listKubernetesDecoys.mockResolvedValue({ items: [decoy], next_cursor: "" });
  });

  it("registers with one retry-safe key and shows the manifest, the audit rules and the webhook to point at", async () => {
    apiMock.registerKubernetesDecoy.mockRejectedValueOnce(new Error("network"));
    apiMock.registerKubernetesDecoy.mockResolvedValueOnce({
      ...decoy,
      id: "k2",
      state: "active",
      manifest: "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: ci-deployer\n",
      audit_policy: '- level: Metadata\n  users: ["system:serviceaccount:ci:ci-deployer"]\n',
    });
    render(<DecoyKubernetesWorkflow />);
    await userEvent.type(await screen.findByLabelText("Cluster"), "prod-eu");
    await userEvent.type(screen.getByLabelText("Namespace"), "ci");
    await userEvent.type(screen.getByLabelText("Service account"), "ci-deployer");
    await userEvent.type(screen.getByLabelText("Label"), "ci deployer bait");
    await userEvent.type(screen.getByLabelText(/Where you plant it/), "ci namespace");
    await userEvent.click(screen.getByRole("button", { name: "Register decoy" }));
    await userEvent.click(screen.getByRole("button", { name: "Register decoy" }));
    await waitFor(() => expect(apiMock.registerKubernetesDecoy).toHaveBeenCalledTimes(2));
    const [first, second] = apiMock.registerKubernetesDecoy.mock.calls;
    expect(first[1]).toBe(second[1]);
    expect(first[0]).toEqual({ cluster: "prod-eu", namespace: "ci", service_account: "ci-deployer", name: "ci deployer bait", placement: "ci namespace" });
    expect(await screen.findByText(/kind: ServiceAccount/)).toBeInTheDocument();
    expect(screen.getByText(/system:serviceaccount:ci:ci-deployer/)).toBeInTheDocument();
    expect(screen.getByText(/kubernetes\/clusters\/prod-eu\/audit-events with a token that holds only decoys:events.report/)).toBeInTheDocument();
  });

  it("lists each decoy with who first read it, and retires it", async () => {
    apiMock.retireKubernetesDecoy.mockResolvedValue({ ...decoy, state: "revoked" });
    render(<DecoyKubernetesWorkflow />);
    const item = (await screen.findByText("ci/ci-deployer on prod-eu")).closest("li") as HTMLElement;
    expect(within(item).getByText(/First by alice@example.com from 10.0.0.7 at .*: token Secret read: get secrets \(200\)/)).toBeInTheDocument();
    await userEvent.click(within(item).getByRole("button", { name: "Stop watching" }));
    expect(apiMock.retireKubernetesDecoy).toHaveBeenCalledWith("k1");
  });

  it("shows nothing, and asks for nothing, to a caller who may not plant decoys", () => {
    can.value = false;
    const { container } = render(<DecoyKubernetesWorkflow />);
    expect(container).toBeEmptyDOMElement();
    expect(apiMock.listKubernetesDecoys).not.toHaveBeenCalled();
  });
});

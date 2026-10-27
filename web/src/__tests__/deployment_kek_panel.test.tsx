import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { DeploymentKEKPanel } from "@/components/DeploymentKEKPanel";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    deploymentKEK: vi.fn(),
    rotateDeploymentKEK: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

const keyFile = {
  served: true,
  generation: 0,
  custody: "key_file",
  rotation_authority: "operator_tenant",
  can_rotate: true,
  detail: "The deployment KEK is the local key file (generation 0); it has never rotated.",
};

// A198: the operator tenant rotates the deployment key onto a configured
// wrapper and watches the rotation; any other tenant sees the status and why
// it cannot rotate.
describe("Deployment key panel", () => {
  beforeEach(() => {
    apiMock.deploymentKEK.mockReset().mockResolvedValue(keyFile);
    apiMock.rotateDeploymentKEK.mockReset().mockResolvedValue({
      ...keyFile,
      rotation: {
        operation_id: "op-1",
        status: "running",
        stage: "hot_state",
        next_generation: 1,
        next_wrapper_kind: "local_file",
        next_wrapper_id: "deploy-wrap-1",
        tenants_total: 4,
        tenants_done: 1,
        containers_rewrapped: 12,
        history_events_rewrapped: 0,
        files_rewrapped: 0,
        containers_verified: 0,
        verify_passes: 0,
      },
      detail: "A rotation is re-wrapping every stored data key under the next generation; requests are served throughout.",
    });
  });

  it("lets the operator tenant rotate onto a wrapper and shows the progress", async () => {
    const { container } = render(
      <AppQueryProvider>
        <DeploymentKEKPanel />
      </AppQueryProvider>,
    );
    expect(await screen.findByText("Generation 0")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Configured local wrapper ID/), { target: { value: "deploy-wrap-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Rotate" }));
    await waitFor(() => expect(apiMock.rotateDeploymentKEK).toHaveBeenCalledWith({ wrapper_kind: "local_file", wrapper_id: "deploy-wrap-1" }));
    expect(await screen.findByText("Generation 0, moving to 1")).toBeInTheDocument();
    expect(screen.getByText("Re-wrapping stored data keys")).toBeInTheDocument();
    expect(screen.getByText("1 of 4")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("tells another tenant who may rotate instead of offering the form", async () => {
    apiMock.deploymentKEK.mockResolvedValue({ ...keyFile, can_rotate: false, rotation_authority: "another_tenant" });
    render(
      <AppQueryProvider>
        <DeploymentKEKPanel />
      </AppQueryProvider>,
    );
    expect(await screen.findByText("Only the deployment's operator tenant can rotate this key.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Rotate" })).not.toBeInTheDocument();
  });
});

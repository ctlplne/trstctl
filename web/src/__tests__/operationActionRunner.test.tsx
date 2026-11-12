import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { ApiError } from "@/lib/api";
import { OperationActionRunner } from "@/pages/operations/OperationActionRunner";

const { preview, run } = vi.hoisted(() => ({ preview: vi.fn(), run: vi.fn() }));
vi.mock("@/lib/operationActionsApi", () => ({ previewOperationAction: preview, runOperationAction: run }));

const renew = {
  action: "retry" as const,
  available: true,
  scope: "renew orders through its bound issuer and deliver the new certificate to lb",
  method: "POST",
  path: "/api/v1/identities/id-1/transitions",
  preview_path: "/api/v1/identities/id-1/transitions/preview",
  body: { to: "renewing", reason: "retry of operation connector_delivery:d-1" },
};

describe("operation actions run in place (A245-L4)", () => {
  afterEach(() => {
    cleanup();
    preview.mockReset();
    run.mockReset();
  });

  it("reviews the exact request through the route's preview, then runs it", async () => {
    preview.mockResolvedValue({ ready: true, blockers: [] });
    run.mockResolvedValue({ id: "id-1" });
    const onDone = vi.fn();
    render(<OperationActionRunner action={renew} label="Retry" onDone={onDone} />);
    fireEvent.click(screen.getByRole("button", { name: "Review Retry" }));
    await waitFor(() => expect(preview).toHaveBeenCalledWith(renew.preview_path, renew.body));
    expect(await screen.findByText("The review found nothing blocking it.")).toBeInTheDocument();
    expect(run).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Run Retry now" }));
    await waitFor(() => expect(run).toHaveBeenCalledWith("POST", renew.path, renew.body));
    expect(await screen.findByText("Retry was sent. The ledger shows its progress.")).toBeInTheDocument();
    expect(onDone).toHaveBeenCalled();
  });

  it("names the blockers the review found and shows the route's refusal, an approval it waits for included", async () => {
    preview.mockResolvedValue({ ready: false, blockers: ["the issuer is paused"] });
    run.mockRejectedValue(new ApiError(403, "approval_required:id-1 request_id=ap-9"));
    render(<OperationActionRunner action={renew} label="Retry" onDone={() => undefined} />);
    fireEvent.click(screen.getByRole("button", { name: "Review Retry" }));
    expect(await screen.findByText("The review found: the issuer is paused")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Run Retry now" }));
    expect(await screen.findByText(/approval_required:id-1 request_id=ap-9/)).toBeInTheDocument();
  });

  it("asks before running a route with no review, and offers nothing for an unavailable action", async () => {
    run.mockResolvedValue({});
    const rollback = {
      action: "rollback" as const,
      available: true,
      scope: "restore the certificate lb held before this delivery",
      method: "POST",
      path: "/api/v1/connectors/targets/t-1/rollback",
      body: { identity_id: "id-1", reason: "rollback of operation connector_delivery:d-1" },
    };
    const { unmount } = render(<OperationActionRunner action={rollback} label="Rollback" onDone={() => undefined} />);
    fireEvent.click(screen.getByRole("button", { name: "Prepare Rollback" }));
    expect(screen.getByText("This route has no separate review. Running it will restore the certificate lb held before this delivery.")).toBeInTheDocument();
    expect(preview).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Run Rollback now" }));
    await waitFor(() => expect(run).toHaveBeenCalledWith("POST", rollback.path, rollback.body));
    unmount();
    render(
      <OperationActionRunner
        action={{ action: "retry", available: false, scope: "x", reason: "the delivery did not fail" }}
        label="Retry"
        onDone={() => undefined}
      />,
    );
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});

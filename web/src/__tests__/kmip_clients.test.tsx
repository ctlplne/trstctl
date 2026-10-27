import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { KMIPClients } from "@/pages/secrets/KMIPClients";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    kmipClients: vi.fn(),
    registerKMIPClient: vi.fn(),
    issueKMIPClientEnrollment: vi.fn(),
    removeKMIPClient: vi.fn(),
  },
}));

vi.mock("@/lib/bootstrapApi", async (orig) => {
  const actual = await orig<typeof import("@/lib/bootstrapApi")>();
  return { ...actual, bootstrapApi: apiMock };
});

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

const enrolled = {
  id: "11111111-1111-4111-8111-111111111111",
  name: "storage array",
  state: "enrolled" as const,
  fingerprint: "ab".repeat(32),
  subject: "CN=array-a",
  created_at: "2026-10-27T12:00:00Z",
  detail: "KMIP requests that present this certificate are answered for this tenant.",
};

// A197: a tenant registers its own KMIP clients on the Transit page. The
// one-time enrollment is shown once with its username and password, each
// client shows its state and bound certificate, and a client can get a new
// enrollment or be removed.
describe("KMIP clients", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    apiMock.kmipClients.mockReset().mockResolvedValue({ items: [enrolled] });
    apiMock.registerKMIPClient.mockReset().mockResolvedValue({
      client: {
        id: "22222222-2222-4222-8222-222222222222",
        name: "backup appliance",
        state: "awaiting_enrollment",
        created_at: "2026-10-27T13:00:00Z",
        enrollment_expires_at: "2026-10-28T13:00:00Z",
        detail: "Configure the client with the enrollment's username and password.",
      },
      enrollment: { username: "22222222-2222-4222-8222-222222222222", password: "one-time-secret", expires_at: "2026-10-28T13:00:00Z" },
    });
    apiMock.removeKMIPClient.mockReset().mockResolvedValue(undefined);
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  it("registers a client, shows its one-time enrollment, and removes a client", async () => {
    const { container } = render(
      <AppQueryProvider>
        <KMIPClients />
      </AppQueryProvider>,
    );
    expect(await screen.findByText("storage array")).toBeInTheDocument();
    expect(screen.getByText("Enrolled")).toBeInTheDocument();
    expect(screen.getByText(/CN=array-a/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Client name"), { target: { value: "backup appliance" } });
    fireEvent.click(screen.getByRole("button", { name: "Register client" }));
    await waitFor(() => expect(apiMock.registerKMIPClient).toHaveBeenCalledWith({ name: "backup appliance" }));
    expect(await screen.findByText(/password: one-time-secret/)).toBeInTheDocument();
    expect(screen.getByText("Awaiting enrollment")).toBeInTheDocument();

    const row = screen.getByText("storage array").closest("li");
    expect(row).not.toBeNull();
    fireEvent.click(within(row as HTMLElement).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(apiMock.removeKMIPClient).toHaveBeenCalledWith(enrolled.id));
    await waitFor(() => expect(screen.queryByText("storage array")).not.toBeInTheDocument());
    expect(await axe(container)).toHaveNoViolations();
  });
});

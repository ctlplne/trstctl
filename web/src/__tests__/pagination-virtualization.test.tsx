import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { Certificates } from "@/pages/Certificates";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    certificatePage: vi.fn(),
    certificateHealth: vi.fn(),
    getCertificate: vi.fn(),
    ingestCertificate: vi.fn(),
    rogueCertificates: vi.fn(),
    submitCertificateTransparency: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: apiMock };
});

function certificates(start: number, count: number) {
  return Array.from({ length: count }, (_, offset) => {
    const index = start + offset;
    return {
      id: `cert-${index}`,
      subject: `CN=cert-${index}.example.com`,
      issuer: "CN=Pagination CA",
      status: "active",
      fingerprint: `fingerprint-${index}`,
    };
  });
}

describe("pagination virtualization", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
  });

  it("consumes next_cursor, accumulates the next page, and windows the large table", async () => {
    apiMock.certificatePage
      .mockResolvedValueOnce({ items: certificates(0, 70), next_cursor: "cursor-2" })
      .mockResolvedValueOnce({ items: certificates(70, 70), next_cursor: "" });

    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <ToastProvider>
          <Certificates />
        </ToastProvider>
      </MemoryRouter>,
    );

    expect(await screen.findByText("CN=cert-0.example.com")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /load next page/i }));

    await waitFor(() =>
      expect(apiMock.certificatePage).toHaveBeenNthCalledWith(2, {
        query: undefined,
        signal: expect.any(AbortSignal),
        limit: 20,
        cursor: "cursor-2",
        expiringBefore: undefined,
      }),
    );

    const viewport = screen.getByTestId("data-grid-scroll-viewport");
    await waitFor(() => expect(viewport).toHaveAttribute("data-virtualized", "true"));
    expect(viewport).toHaveAttribute("data-total-rows", "140");
    expect(screen.getByText("CN=cert-0.example.com")).toBeInTheDocument();
    expect(screen.queryByText("CN=cert-139.example.com")).not.toBeInTheDocument();
    expect(viewport.querySelectorAll("tbody tr").length).toBeLessThan(40);

    Object.defineProperty(viewport, "scrollTop", { configurable: true, value: 130 * 52 });
    fireEvent.scroll(viewport);

    await waitFor(() => expect(screen.getByText("CN=cert-130.example.com")).toBeInTheDocument());
    expect(screen.queryByText("CN=cert-0.example.com")).not.toBeInTheDocument();
    expect(screen.getByText(/no more certificate pages/i)).toBeInTheDocument();
  });
});

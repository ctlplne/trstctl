import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, renderHook, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Certificates } from "@/pages/Certificates";
import { ToastProvider } from "@/components/ToastProvider";
import { QueryClientProvider } from "@tanstack/react-query";
import { createAppQueryClient } from "@/lib/query";
import { useCertificateInventory } from "@/pages/certificates/useCertificateInventory";
import type { CertificatePage } from "@/lib/api";

const { apiMock } = vi.hoisted(() => ({ apiMock: { certificatePage: vi.fn(), getCertificate: vi.fn(), owners: vi.fn(), identities: vi.fn() } }));
vi.mock("@/lib/api", async (original) => ({ ...(await original<typeof import("@/lib/api")>()), api: apiMock }));
function page(name: string, next?: string): CertificatePage {
  return { items: [{ id: name, subject: `CN=${name}`, fingerprint: name, serial: name, status: "active" }], next_cursor: next } as CertificatePage;
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
function mount() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <Certificates />
      </ToastProvider>
    </MemoryRouter>,
  );
}
const search = () => screen.getByRole("searchbox", { name: /Search/ });
describe("certificate inventory server search", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    apiMock.owners.mockResolvedValue([]);
    apiMock.identities.mockResolvedValue([]);
  });
  it("finds a certificate outside the loaded page and keeps search usable for no matches", async () => {
    apiMock.certificatePage.mockImplementation(({ query }: { query?: string }) =>
      Promise.resolve(query === "known-serial" ? page("known-serial") : query ? { items: [] } : page("first-page-only", "unrelated-next")),
    );
    mount();
    await screen.findByText("CN=first-page-only");
    fireEvent.change(search(), { target: { value: "known-serial" } });
    expect(await screen.findByText("CN=known-serial")).toBeInTheDocument();
    expect(apiMock.certificatePage).toHaveBeenCalledWith(expect.objectContaining({ query: "known-serial", cursor: undefined }));
    expect(screen.queryByText("CN=first-page-only")).not.toBeInTheDocument();
    fireEvent.change(search(), { target: { value: "does-not-exist" } });
    expect(await screen.findByText("No certificates match your search.")).toBeInTheDocument();
    expect(search()).toHaveValue("does-not-exist");
    fireEvent.change(search(), { target: { value: "" } });
    expect(await screen.findByText("CN=first-page-only")).toBeInTheDocument();
  });
  it("does not append an old page into a newer query and resets the cursor", async () => {
    const oldPage = deferred<CertificatePage>();
    apiMock.certificatePage.mockImplementation(({ query, cursor }: { query?: string; cursor?: string }) =>
      cursor ? oldPage.promise : Promise.resolve(query ? page("second-search") : page("first-search", "first-cursor")),
    );
    mount();
    await screen.findByText("CN=first-search");
    fireEvent.click(screen.getByRole("button", { name: "Load next page" }));
    await waitFor(() => expect(apiMock.certificatePage).toHaveBeenCalledWith(expect.objectContaining({ cursor: "first-cursor" })));
    fireEvent.change(search(), { target: { value: "second-search" } });
    expect(await screen.findByText("CN=second-search")).toBeInTheDocument();
    await act(async () => oldPage.resolve(page("late-old-result")));
    expect(screen.queryByText("CN=late-old-result")).not.toBeInTheDocument();
    expect(screen.queryByText("CN=first-search")).not.toBeInTheDocument();
    expect(apiMock.certificatePage).toHaveBeenLastCalledWith(expect.objectContaining({ query: "second-search", cursor: undefined }));
  });
  it("does not replace a newer search with a late first-page response", async () => {
    const oldSearch = deferred<CertificatePage>();
    apiMock.certificatePage.mockImplementation(({ query }: { query?: string }) =>
      query === "slow-search" ? oldSearch.promise : Promise.resolve(query ? page("fast-search") : page("initial")),
    );
    mount();
    await screen.findByText("CN=initial");
    fireEvent.change(search(), { target: { value: "slow-search" } });
    await waitFor(() => expect(apiMock.certificatePage).toHaveBeenCalledWith(expect.objectContaining({ query: "slow-search" })));
    // The same searchbox must stay mounted and editable while the request runs.
    fireEvent.change(search(), { target: { value: "fast-search" } });
    expect(await screen.findByText("CN=fast-search")).toBeInTheDocument();
    await act(async () => oldSearch.resolve(page("slow-search")));
    expect(screen.queryByText("CN=slow-search")).not.toBeInTheDocument();
    expect(within(screen.getByLabelText("Inventoried certificates")).getByRole("searchbox", { name: /Search/ })).toHaveValue("fast-search");
  });
  it("clears hidden bulk selections when the search changes", async () => {
    apiMock.certificatePage.mockImplementation(({ query }: { query?: string }) => Promise.resolve(page(query || "initial")));
    mount();
    const checkbox = await screen.findByRole("checkbox", { name: "Select CN=initial" });
    fireEvent.click(checkbox);
    expect(screen.getByRole("button", { name: /Revoke selected/ })).toBeInTheDocument();
    fireEvent.change(search(), { target: { value: "other" } });
    expect(screen.queryByRole("button", { name: /Revoke selected/ })).not.toBeInTheDocument();
    await screen.findByText("CN=other");
    fireEvent.change(search(), { target: { value: "" } });
    expect(await screen.findByRole("checkbox", { name: "Select CN=initial" })).not.toBeChecked();
  });
  it("keeps a failed search distinct from no matches and allows recovery", async () => {
    apiMock.certificatePage.mockImplementation(({ query }: { query?: string }) =>
      query === "broken" ? Promise.reject(new Error("search unavailable")) : Promise.resolve(page(query || "initial")),
    );
    mount();
    await screen.findByText("CN=initial");
    fireEvent.change(search(), { target: { value: "broken" } });
    expect(screen.queryByText("No more certificate pages")).not.toBeInTheDocument();
    expect(await screen.findByRole("alert")).toHaveTextContent("search unavailable");
    expect(screen.queryByText("No certificates match your search.")).not.toBeInTheDocument();
    fireEvent.change(search(), { target: { value: "recovered" } });
    expect(await screen.findByText("CN=recovered")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
  it("refreshes cached searches after revocation without changing another tenant's cache", async () => {
    const client = createAppQueryClient();
    const unrelatedKey = ["certificate-inventory", "tenant-b", "operator", { query: "active", limit: 20 }];
    const initial = page("serial");
    client.setQueryData(unrelatedKey, { pages: [initial], pageParams: [undefined] });
    let revoked = false;
    apiMock.certificatePage.mockImplementation(({ query }: { query?: string }) =>
      Promise.resolve(revoked && query === "active" ? { items: [] } : { items: [{ ...initial.items[0], status: revoked ? "revoked" : "active" }] }),
    );
    const { result, rerender } = renderHook(({ query }) => useCertificateInventory(["tenant-a", "operator"], query, 20), {
      initialProps: { query: "active" },
      wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>,
    });
    await waitFor(() => expect(result.current.certificates[0]?.status).toBe("active"));
    rerender({ query: "serial" });
    await waitFor(() => expect(result.current.certificates[0]?.status).toBe("active"));
    revoked = true;
    await act(async () => result.current.refresh({ ...initial.items[0], status: "revoked" }));
    await waitFor(() => expect(result.current.certificates[0]?.status).toBe("revoked"));
    const cached = client.getQueryData<{ pages: CertificatePage[] }>(["certificate-inventory", "tenant-a", "operator", { query: "active", limit: 20 }]);
    expect(cached?.pages[0].items[0].status).toBe("revoked");
    expect(client.getQueryData(unrelatedKey)).toEqual({ pages: [initial], pageParams: [undefined] });
    expect(client.getQueryState(unrelatedKey)?.isInvalidated).toBe(false);
    rerender({ query: "active" });
    await waitFor(() => expect(apiMock.certificatePage).toHaveBeenLastCalledWith(expect.objectContaining({ query: "active" })));
    await waitFor(() => expect(result.current.certificates).toEqual([]));
  });
});

// React + fixed HTTP doubles only. No browser, signer or TLS proof is claimed.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { AppQueryProvider } from "@/lib/query";
import { FirstCertificateStep } from "@/pages/wizard/FirstCertificateStep";
import { bindFirstCertificatePrincipal } from "@/lib/firstCertificateMemory";
import { installWizardWireFixture, wizardFixtureCSR, wizardFixturePrincipal } from "@/test/wizardWireFixture";

vi.mock("@/auth/AuthProvider", () => ({ useAuth: () => ({ user: { tenant_id: "t1", subject: "operator-1" }, preview: false }) }));
const callbacks = { createOwner: vi.fn(), attestOwner: vi.fn(), transitionIdentity: vi.fn() };
const onRecorded = vi.fn();
function mount() {
  return render(
    <MemoryRouter>
      <AppQueryProvider>
        <FirstCertificateStep onRecorded={onRecorded} />
      </AppQueryProvider>
    </MemoryRouter>,
  );
}
async function fill(withCSR = true) {
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText("Service name"), "payments");
  await user.type(screen.getByLabelText("Application ID"), "APP");
  await user.type(screen.getByLabelText("Environment"), "test");
  await user.type(screen.getByLabelText("Alert contact"), "ops@example.test");
  await user.click(screen.getByLabelText("I confirm this application owns the certificate"));
  if (withCSR) await user.type(screen.getByLabelText("Public certificate request (CSR)"), wizardFixtureCSR);
  await user.click(screen.getByRole("button", { name: "Issue certificate" }));
  return user;
}
function overrideResults(transform: (response: Record<string, unknown>) => Response) {
  const original = globalThis.fetch;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: RequestInfo | URL, init?: RequestInit) => {
      const response = await original(path, init);
      if (String(path).includes("issuance-result?") && response.ok) return transform((await response.json()) as Record<string, unknown>);
      return response;
    }),
  );
}
beforeEach(() => {
  vi.clearAllMocks();
  callbacks.createOwner.mockResolvedValue({ id: "owner-1", ownership_complete: true, ownership_current: false });
  callbacks.attestOwner.mockResolvedValue({ id: "owner-1", ownership_complete: true, ownership_current: true });
  callbacks.transitionIdentity.mockResolvedValue({});
  installWizardWireFixture(callbacks);
});

describe("first-leaf wizard result admission", () => {
  it("requires the public CSR before creating even an owner", async () => {
    mount();
    await fill(false);
    expect(await screen.findByText(/Supply one public CSR PEM block/)).toBeInTheDocument();
    expect(callbacks.createOwner).not.toHaveBeenCalled();
    expect(callbacks.transitionIdentity).not.toHaveBeenCalled();
  });
  it("does not announce a certificate or expose downloads for an accepted transition with a pending result", async () => {
    overrideResults(
      (body) => new Response(JSON.stringify({ identity_id: body.identity_id, request_key: body.request_key, state: "pending" }), { status: 200 }),
    );
    mount();
    await fill();
    await waitFor(() => expect(callbacks.transitionIdentity).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/An accepted identity transition does not confirm/)).toBeInTheDocument();
    expect(onRecorded.mock.calls.filter(([record]) => record !== null)).toEqual([]);
    expect(screen.queryByRole("button", { name: "Download leaf certificate" })).not.toBeInTheDocument();
  });
  it("reports an exact-result error without substituting the newest certificate from inventory", async () => {
    overrideResults(() => new Response("{}", { status: 409 }));
    mount();
    await fill();
    expect(await screen.findByText(/exact result could not be confirmed/i)).toBeInTheDocument();
    expect(onRecorded.mock.calls.filter(([record]) => record !== null)).toEqual([]);
    expect(screen.queryByRole("button", { name: "Download leaf certificate" })).not.toBeInTheDocument();
  });
  it("locks edits and reuses the same CSR/transition keys after a lost response", async () => {
    callbacks.transitionIdentity.mockRejectedValueOnce(new TypeError("lost response"));
    mount();
    const user = await fill();
    expect(await screen.findByRole("alert")).toHaveTextContent(/uncertain/i);
    const csrInput = screen.getByLabelText("Public certificate request (CSR)");
    expect(csrInput).toHaveAttribute("readonly");
    await user.click(screen.getByRole("button", { name: "Retry the same issuance attempt" }));
    await screen.findByRole("button", { name: "Download leaf certificate" });
    expect(callbacks.createOwner).toHaveBeenCalledTimes(1);
    expect(callbacks.attestOwner).toHaveBeenCalledTimes(1);
    expect(callbacks.transitionIdentity.mock.calls[0]).toEqual(callbacks.transitionIdentity.mock.calls[1]);
    expect(callbacks.transitionIdentity.mock.calls[0][0].subject_csr_pem).toBe(wizardFixtureCSR);
    const transitions = vi.mocked(fetch).mock.calls.filter(([path]) => String(path).endsWith("/transitions"));
    expect(new Headers(transitions[0][1]?.headers).get("Idempotency-Key")).toBe(new Headers(transitions[1][1]?.headers).get("Idempotency-Key"));
  });
  it("rereads the same retained attempt after route unmount without submitting it again", async () => {
    const first = mount();
    await fill();
    await screen.findByRole("button", { name: "Download leaf certificate" });
    first.unmount();
    onRecorded.mockClear();
    mount();
    await screen.findByRole("button", { name: "Download leaf certificate" });
    expect(callbacks.createOwner).toHaveBeenCalledTimes(1);
    expect(callbacks.transitionIdentity).toHaveBeenCalledTimes(1);
    expect(onRecorded.mock.calls.some(([record]) => record?.result.state === "issued")).toBe(true);
  });
  it("explains loss of volatile recovery after a simulated document reset without any automatic mutation", async () => {
    const first = mount();
    await fill();
    await screen.findByRole("button", { name: "Download leaf certificate" });
    first.unmount();
    bindFirstCertificatePrincipal(null);
    bindFirstCertificatePrincipal(wizardFixturePrincipal);
    callbacks.createOwner.mockClear();
    callbacks.transitionIdentity.mockClear();
    mount();
    expect(await screen.findByText(/Reloading, signing out or closing the tab can lose the request keys/)).toBeInTheDocument();
    expect(callbacks.createOwner).not.toHaveBeenCalled();
    expect(callbacks.transitionIdentity).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Download leaf certificate" })).not.toBeInTheDocument();
  });
  it("downloads only the real returned public bytes and names only their observed issuer", async () => {
    const blobs: Blob[] = [];
    Object.defineProperty(URL, "createObjectURL", {
      configurable: true,
      value: vi.fn((blob: Blob) => {
        blobs.push(blob);
        return "blob:fixture";
      }),
    });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    mount();
    const user = await fill();
    await user.click(await screen.findByRole("button", { name: "Download leaf certificate" }));
    expect(screen.getByText(/Issuer recorded on the certificate: Observed fixture issuer/)).toBeInTheDocument();
    const actual = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = reject;
      reader.onload = () => resolve(String(reader.result));
      reader.readAsText(blobs[0]);
    });
    expect(actual).toBe("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n");
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:fixture");
    expect(screen.getByText(/does not add trust to this host or prove deployment/)).toBeInTheDocument();
  });
  it("does not accept private-key material even if a server response labels itself issued", async () => {
    overrideResults(
      (body) => new Response(JSON.stringify({ ...body, certificate_pem: "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----" }), { status: 200 }),
    );
    mount();
    await fill();
    expect(await screen.findByText(/exact result could not be confirmed/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Download leaf certificate" })).not.toBeInTheDocument();
  });
});

it("corrects a proven rejected CSR without replacing the owner or identity", async () => {
  const original = globalThis.fetch;
  const posts: Array<{ path: string; key: string; body: Record<string, unknown> }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: RequestInfo | URL, init?: RequestInit) => {
      const url = String(path);
      if (init?.method === "POST") {
        const key = new Headers(init.headers).get("Idempotency-Key")!;
        const body = JSON.parse(String(init.body)) as Record<string, unknown>;
        posts.push({ path: url, key, body });
        if (url.endsWith("/transitions") && body.subject_csr_pem === wizardFixtureCSR) {
          const identity = url.split("/").at(-2)!;
          const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(body.subject_csr_pem)))), (byte) =>
            byte.toString(16).padStart(2, "0"),
          ).join("");
          return new Response(
            JSON.stringify({
              code: "identity_csr_rejected_before_transition",
              disposition: {
                tenant_id: wizardFixturePrincipal.tenantId,
                subject: wizardFixturePrincipal.subject,
                identity_id: identity,
                request_key: key,
                to: body.to,
                reason: body.reason,
                subject_csr_sha256: digest,
              },
            }),
            { status: 400 },
          );
        }
      }
      return original(path, init);
    }),
  );
  mount();
  const user = await fill();
  const edit = await screen.findByRole("button", { name: "Correct the rejected CSR" });
  expect(screen.queryByRole("button", { name: "Download leaf certificate" })).not.toBeInTheDocument();
  await user.click(edit);
  const field = screen.getByLabelText("Public certificate request (CSR)");
  expect(field).not.toHaveAttribute("readonly");
  expect(screen.getByLabelText("Service name")).toHaveAttribute("readonly");
  await user.clear(field);
  await user.type(field, wizardFixtureCSR.replace("AQID", "AQIE"));
  await user.click(screen.getByRole("button", { name: "Submit the corrected CSR for this identity" }));
  await screen.findByRole("button", { name: "Download leaf certificate" });
  const transitions = posts.filter((post) => post.path.endsWith("/transitions"));
  expect(transitions).toHaveLength(2);
  expect(transitions[1].path).toBe(transitions[0].path);
  expect(transitions[1].key).not.toBe(transitions[0].key);
  expect(posts.filter((post) => post.path === "/api/v1/identities")).toHaveLength(1);
  expect(callbacks.createOwner).toHaveBeenCalledTimes(1);
  expect(callbacks.attestOwner).toHaveBeenCalledTimes(1);
});

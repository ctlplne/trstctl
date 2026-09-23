import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import LDAPLoginForm from "@/pages/login/LDAPLoginForm";
import { UnauthorizedError } from "@/lib/apiTransport";

const { meMock } = vi.hoisted(() => ({ meMock: vi.fn() }));
vi.mock("@/lib/bootstrapApi", async (orig) => ({
  ...(await orig<typeof import("@/lib/bootstrapApi")>()),
  bootstrapApi: { me: meMock },
}));

const fetchMock = vi.fn<typeof fetch>();
const assign = vi.fn();
const originalLocation = window.location;
const session = { subject: "fixture-operator", tenant_id: "fixture-tenant", roles: ["admin"], permissions: ["*"] };
const unavailable = "Sign-in could not be completed. Try again; if it continues, contact your administrator.";
const rejected = "Your directory username or password was not accepted. Check them and try again.";
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
async function fill(username = "fixture-operator", password = "fixture-password") {
  const user = userEvent.setup();
  await user.type(await screen.findByLabelText("Directory username"), username);
  await user.type(screen.getByLabelText("Password"), password);
  return user;
}
beforeEach(() => {
  fetchMock.mockReset();
  meMock.mockReset();
  assign.mockReset();
  meMock.mockResolvedValue(session);
  vi.stubGlobal("fetch", fetchMock);
  Object.defineProperty(window, "location", { configurable: true, value: { ...originalLocation, assign } });
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  Object.defineProperty(window, "location", { configurable: true, value: originalLocation });
});

describe("directory sign-in submission", () => {
  it("explains empty fields without sending credentials", async () => {
    render(<LDAPLoginForm />);
    await userEvent.click(await screen.findByRole("button", { name: "Sign in with LDAP" }));
    expect(await screen.findByText("Enter your directory username.")).toBeInTheDocument();
    expect(screen.getByText("Enter your password.")).toBeInTheDocument();
    expect(screen.getByLabelText("Directory username")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByLabelText("Password")).toHaveAttribute("aria-invalid", "true");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(meMock).not.toHaveBeenCalled();
    expect(assign).not.toHaveBeenCalled();
  });

  it("preserves password whitespace, prevents duplicate submits, and waits for a verified session", async () => {
    const posted = deferred<Response>();
    const verified = deferred<typeof session>();
    fetchMock.mockReturnValue(posted.promise);
    meMock.mockReturnValue(verified.promise);
    render(<LDAPLoginForm returnTo="/certificates?status=expiring#inventory" />);
    const user = await fill("  fixture-operator  ", "  fixture password  ");
    const button = screen.getByRole("button", { name: "Sign in with LDAP" });
    await user.dblClick(button);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toBe("/auth/ldap/login");
    expect(options).toMatchObject({ method: "POST", credentials: "same-origin", cache: "no-store" });
    expect(JSON.parse(String(options?.body))).toEqual({ username: "fixture-operator", password: "  fixture password  " });
    expect(button).toBeDisabled();
    expect(screen.getByLabelText("Directory username")).toBeDisabled();
    expect(screen.getByLabelText("Password")).toBeDisabled();
    expect(meMock).not.toHaveBeenCalled();
    expect(assign).not.toHaveBeenCalled();
    await act(async () => posted.resolve(new Response("<!doctype html><title>Console</title>", { status: 200 })));
    await waitFor(() => expect(meMock).toHaveBeenCalledTimes(1));
    expect(assign).not.toHaveBeenCalled();
    expect(button).toBeDisabled();
    await act(async () => verified.resolve(session));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/certificates?status=expiring#inventory"));
    expect(assign).toHaveBeenCalledTimes(1);
    expect(screen.getByLabelText("Password")).toHaveValue("");
  });

  it("refuses HTML success when no operator session was created", async () => {
    fetchMock.mockResolvedValue(new Response("<!doctype html><title>Login</title>", { status: 200 }));
    meMock.mockRejectedValue(new UnauthorizedError());
    render(<LDAPLoginForm />);
    const user = await fill();
    await user.click(screen.getByRole("button", { name: "Sign in with LDAP" }));
    expect(await screen.findByText(unavailable)).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toHaveValue("");
    expect(screen.getByRole("button", { name: "Sign in with LDAP" })).toBeEnabled();
    expect(assign).not.toHaveBeenCalled();
  });

  it.each([
    [401, rejected],
    [
      403,
      "Your sign-in provider verified your account, but it is not assigned to a trstctl tenant. Ask your administrator to check your tenant mapping and membership. Then sign in again.",
    ],
    [429, "Too many sign-in attempts. Wait a moment and try again."],
    [503, unavailable],
  ])("handles HTTP %s without rendering a server response or retaining the password", async (status, message) => {
    fetchMock.mockResolvedValue(new Response("fixture-server-detail-do-not-render", { status }));
    render(<LDAPLoginForm />);
    const user = await fill();
    await user.click(screen.getByRole("button", { name: "Sign in with LDAP" }));
    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(screen.queryByText("fixture-server-detail-do-not-render")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Directory username")).toHaveValue("fixture-operator");
    expect(screen.getByLabelText("Password")).toHaveValue("");
    expect(screen.getByRole("button", { name: "Sign in with LDAP" })).toBeEnabled();
    expect(meMock).not.toHaveBeenCalled();
    expect(assign).not.toHaveBeenCalled();
  });

  it("allows a corrected retry after credential rejection", async () => {
    fetchMock.mockResolvedValueOnce(new Response("", { status: 401 })).mockResolvedValueOnce(new Response("", { status: 200 }));
    render(<LDAPLoginForm />);
    const user = await fill();
    await user.click(screen.getByRole("button", { name: "Sign in with LDAP" }));
    expect(await screen.findByText(rejected)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Password"), "fixture-corrected-password");
    await user.click(screen.getByRole("button", { name: "Sign in with LDAP" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/"));
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body)).password).toBe("fixture-corrected-password");
    expect(screen.queryByText(rejected)).not.toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toHaveValue("");
  });

  it("recovers from a network failure without exposing its error text", async () => {
    fetchMock.mockRejectedValue(new Error("fixture-sensitive-transport-detail"));
    render(<LDAPLoginForm />);
    const user = await fill();
    await user.click(screen.getByRole("button", { name: "Sign in with LDAP" }));
    expect(await screen.findByText(unavailable)).toBeInTheDocument();
    expect(screen.queryByText("fixture-sensitive-transport-detail")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toHaveValue("");
    expect(meMock).not.toHaveBeenCalled();
    expect(assign).not.toHaveBeenCalled();
  });

  it.each([
    "https://outside.example/path",
    "//outside.example/path",
    "/\\outside.example/path",
    "/login?return_to=/certificates",
    "/auth/logout",
    "/path with spaces",
    "/path\u0000hidden",
    "/path\nhidden",
    "/%61uth/login",
    "/%2foutside.example/",
    "/%5coutside.example/",
    "/%0a/outside.example",
    "/policy?x=%0d%0aLocation:outside",
    "/policy#%7fhidden",
    "/LOGIN",
    "/login/",
    "/AUTH/login",
    "/auth",
    "/x/../auth/login",
    "/x%2f..%2fauth/login",
    "/auth%2flogout",
    "/%61uth%3flogin",
    "/auth//login",
    "/%",
    "/policy?x=%zz",
    "/policy?x=" + "a".repeat(4096),
    "/policy?x=" + "é".repeat(2048),
  ])("keeps unsafe or authentication return target %s at the local home", async (returnTo) => {
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    render(<LDAPLoginForm returnTo={returnTo} />);
    const user = await fill();
    await user.click(screen.getByRole("button", { name: "Sign in with LDAP" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/"));
    expect(assign).toHaveBeenCalledTimes(1);
    expect(meMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    "/policy?tab=rules&owner=a%20b#history",
    "/certificates?name=%E2%9C%93#inventory",
    "/policy?next=%2Fauth%2Flogin#history",
    "/policy#%E2%9C%93",
    "/policy?x=" + "a".repeat(4086),
  ])("preserves a bounded local destination including its encoded query and fragment", async (returnTo) => {
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    render(<LDAPLoginForm returnTo={returnTo} />);
    const user = await fill();
    await user.click(screen.getByRole("button", { name: "Sign in with LDAP" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith(returnTo));
    expect(assign).toHaveBeenCalledTimes(1);
  });
});

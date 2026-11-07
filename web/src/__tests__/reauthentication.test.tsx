import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { MemoryRouter } from "react-router-dom";
import { AuthProvider } from "@/auth/AuthProvider";
import { IntlProvider } from "@/i18n/I18nProvider";
import { Login } from "@/pages/Login";
import { Reauthenticated } from "@/pages/Reauthenticated";
import { REAUTH_MESSAGE, ReauthenticationNotice } from "@/components/ReauthenticationNotice";
import { ReauthenticationRequiredError, UnauthorizedError, req, stepUpChallenge } from "@/lib/apiTransport";

// A277: a high-risk access template answers 401 with an RFC 9470 step-up
// challenge. The console tells it from a signed-out session, offers a fresh
// sign-in in its own window so the approved request survives, and the login
// page in that window offers only the methods that can prove a fresh sign-in.

const { bootstrapMock } = vi.hoisted(() => ({
  bootstrapMock: { me: vi.fn(), authMethods: vi.fn(), logout: vi.fn() },
}));
vi.mock("@/lib/bootstrapApi", async (orig) => ({
  ...(await orig<typeof import("@/lib/bootstrapApi")>()),
  bootstrapApi: bootstrapMock,
}));

const originalLocation = window.location;
const assign = vi.fn();
beforeEach(() => {
  vi.clearAllMocks();
  bootstrapMock.me.mockRejectedValue(new UnauthorizedError());
  bootstrapMock.logout.mockResolvedValue(undefined);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  Object.defineProperty(window, "location", { configurable: true, value: originalLocation });
});

describe("the step-up challenge", () => {
  it("is read from WWW-Authenticate and kept apart from a signed-out session", async () => {
    expect(stepUpChallenge(`Bearer error="insufficient_user_authentication", error_description="A fresh sign-in is required", max_age="300"`)).toEqual({
      maxAgeSeconds: 300,
    });
    expect(stepUpChallenge(`Bearer realm="trstctl"`)).toBeNull();
    expect(stepUpChallenge(null)).toBeNull();
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ detail: "this access template requires a fresh sign-in", error: "insufficient_user_authentication", max_age: 300 }), {
        status: 401,
        headers: { "WWW-Authenticate": `Bearer error="insufficient_user_authentication", max_age="300"`, "Content-Type": "application/problem+json" },
      }),
    );
    const refused = await req("/api/v1/access/sessions", { method: "POST" }).catch((err: unknown) => err);
    expect(refused).toBeInstanceOf(ReauthenticationRequiredError);
    expect((refused as ReauthenticationRequiredError).maxAgeSeconds).toBe(300);
    expect(refused).not.toBeInstanceOf(UnauthorizedError);
    fetchMock.mockResolvedValueOnce(new Response("", { status: 401 }));
    await expect(req("/api/v1/access/sessions")).rejects.toBeInstanceOf(UnauthorizedError);
  });
});

describe("the fresh sign-in notice", () => {
  function mount(onSignedIn = vi.fn()) {
    const view = render(
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <ReauthenticationNotice maxAgeSeconds={300} onSignedIn={onSignedIn} />
      </IntlProvider>,
    );
    return { view, onSignedIn };
  }

  it("opens the fresh sign-in in its own window and hears only this origin's report", async () => {
    const open = vi.spyOn(window, "open").mockReturnValue({} as Window);
    const { view, onSignedIn } = mount();
    expect(screen.getByRole("status")).toHaveTextContent("This needs a fresh sign-in: sign in again (within the last 5 min), then try again.");
    expect(await axe(view.container)).toHaveNoViolations();
    await userEvent.click(screen.getByRole("button", { name: "Sign in again" }));
    expect(open).toHaveBeenCalledWith("/login?reauth=1&return_to=%2Freauthenticated", "trstctl-reauthenticate", "popup,width=520,height=720");
    act(() => {
      window.dispatchEvent(new MessageEvent("message", { data: { type: REAUTH_MESSAGE }, origin: "https://elsewhere.example" }));
    });
    expect(onSignedIn).not.toHaveBeenCalled();
    act(() => {
      window.dispatchEvent(new MessageEvent("message", { data: { type: REAUTH_MESSAGE }, origin: window.location.origin }));
    });
    expect(onSignedIn).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("status")).toHaveTextContent("You signed in again. Try again now.");
    expect(screen.queryByRole("button", { name: "Sign in again" })).not.toBeInTheDocument();
  });

  it("offers a new tab when the browser blocks the window", async () => {
    vi.spyOn(window, "open").mockReturnValue(null);
    mount();
    await userEvent.click(screen.getByRole("button", { name: "Sign in again" }));
    const link = screen.getByRole("link", { name: "Sign in again in a new tab" });
    expect(link).toHaveAttribute("href", "/login?reauth=1&return_to=%2Freauthenticated");
    expect(link).toHaveAttribute("rel", "noreferrer");
    expect(link).toHaveAttribute("target", "_blank");
  });

  it("the window it opens reports back to its opener on this origin and closes", () => {
    const postMessage = vi.fn();
    const close = vi.spyOn(window, "close").mockImplementation(() => undefined);
    const opener = Object.getOwnPropertyDescriptor(window, "opener");
    Object.defineProperty(window, "opener", { configurable: true, value: { closed: false, postMessage } });
    try {
      render(
        <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
          <Reauthenticated />
        </IntlProvider>,
      );
      expect(postMessage).toHaveBeenCalledWith({ type: REAUTH_MESSAGE }, window.location.origin);
      expect(close).toHaveBeenCalled();
      expect(screen.getByRole("status")).toHaveTextContent("You signed in again.");
    } finally {
      if (opener) Object.defineProperty(window, "opener", opener);
      else Object.defineProperty(window, "opener", { configurable: true, value: null });
    }
  });

  it("a sign-in in another tab reports on this origin's channel, without an opener", async () => {
    const { view, onSignedIn } = mount();
    const close = vi.spyOn(window, "close").mockImplementation(() => undefined);
    render(
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <Reauthenticated />
      </IntlProvider>,
    );
    await waitFor(() => expect(onSignedIn).toHaveBeenCalledTimes(1));
    expect(close).not.toHaveBeenCalled();
    expect(view.container).toHaveTextContent("You signed in again. Try again now.");
  });

  it("never messages an opener that has closed", () => {
    const postMessage = vi.fn();
    const opener = Object.getOwnPropertyDescriptor(window, "opener");
    Object.defineProperty(window, "opener", { configurable: true, value: { closed: true, postMessage } });
    try {
      render(
        <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
          <Reauthenticated />
        </IntlProvider>,
      );
      expect(postMessage).not.toHaveBeenCalled();
      expect(screen.getByRole("status")).toHaveTextContent("You signed in again.");
    } finally {
      if (opener) Object.defineProperty(window, "opener", opener);
      else Object.defineProperty(window, "opener", { configurable: true, value: null });
    }
  });
});

describe("the login page's fresh sign-in mode", () => {
  function renderLogin(entry: string) {
    Object.defineProperty(window, "location", { configurable: true, value: { ...originalLocation, assign } });
    render(
      <AuthProvider>
        <MemoryRouter initialEntries={[entry]}>
          <Login />
        </MemoryRouter>
      </AuthProvider>,
    );
  }

  it("asks the provider to sign the person in again and hides methods that reuse an earlier sign-in", async () => {
    bootstrapMock.authMethods.mockResolvedValue({ oidc: true, saml: true, ldap: true, kerberos: true, ntlm: true });
    renderLogin(`/login?${new URLSearchParams({ reauth: "1", return_to: "/reauthenticated" })}`);
    await userEvent.click(await screen.findByRole("button", { name: "Continue with SSO" }));
    expect(assign).toHaveBeenCalledWith(`/auth/login?${new URLSearchParams({ return_to: "/reauthenticated", reauth: "1" })}`);
    expect(screen.getByText("Sign in again")).toBeInTheDocument();
    expect(await screen.findByLabelText("Directory username")).toBeInTheDocument();
    for (const name of ["Continue with SAML", "Continue with Kerberos", "Continue with Windows sign-in (NTLM)"]) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
  });

  it("says when the provider reused an earlier sign-in", async () => {
    bootstrapMock.authMethods.mockResolvedValue({ oidc: true, saml: false, ldap: false });
    renderLogin("/login?reauth=1&error=reauthentication_not_proven&return_to=%2Freauthenticated");
    expect(await screen.findByText("Your identity provider did not sign you in again")).toBeInTheDocument();
  });

  it("says when nothing configured can prove a fresh sign-in", async () => {
    bootstrapMock.authMethods.mockResolvedValue({ oidc: false, saml: true, ldap: false });
    renderLogin("/login?reauth=1");
    await waitFor(() =>
      expect(
        screen.getByText("No sign-in method here can prove a fresh sign-in. Ask your administrator to enable OIDC or directory sign-in."),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: "Continue with SAML" })).not.toBeInTheDocument();
  });
});

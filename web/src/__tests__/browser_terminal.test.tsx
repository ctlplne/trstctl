import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { BrowserTerminal } from "@/components/access/BrowserTerminal";
import { PodTerminal } from "@/components/access/PodTerminal";

// A259: the browser terminal shows what the gateway session prints, sends
// what is typed in batches with their own idempotency keys, and closes its
// terminal when it goes away; on a Kubernetes session it opens in the pod
// the operator names. It never holds a ticket or a credential.

const fake = vi.hoisted(() => ({
  written: [] as Array<Uint8Array | string>,
  typed: null as ((data: string) => void) | null,
  disposed: 0,
}));

vi.mock("@xterm/xterm", () => ({
  Terminal: class {
    open() {}
    write(data: Uint8Array | string) {
      fake.written.push(data);
    }
    onData(listener: (data: string) => void) {
      fake.typed = listener;
      return { dispose() {} };
    }
    focus() {}
    dispose() {
      fake.disposed += 1;
    }
  },
}));
vi.mock("@xterm/xterm/css/xterm.css", () => ({}));

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    openPAMTerminal: vi.fn(),
    readPAMTerminal: vi.fn(),
    writePAMTerminal: vi.fn(),
    closePAMTerminal: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

afterEach(() => {
  vi.clearAllMocks();
  fake.written.length = 0;
  fake.typed = null;
  fake.disposed = 0;
});

const decoded = () => fake.written.map((chunk) => (typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk))).join("");

describe("browser terminal", () => {
  it("shows the session's output, sends what is typed and closes its terminal", async () => {
    apiMock.openPAMTerminal.mockResolvedValue({ id: "t-1", session_id: "s-1", cols: 100, rows: 30 });
    apiMock.writePAMTerminal.mockResolvedValue({ id: "t-1", session_id: "s-1" });
    apiMock.closePAMTerminal.mockResolvedValue({ id: "t-1", session_id: "s-1" });
    let releaseEnd: () => void = () => undefined;
    const end = new Promise<void>((resolve) => {
      releaseEnd = resolve;
    });
    apiMock.readPAMTerminal.mockResolvedValueOnce({ data: btoa("alice@host:~$ "), next: 14 }).mockImplementationOnce(async () => {
      await end;
      return { data: btoa("browser-42\r\n"), next: 26, closed: true, exit_status: 0 };
    });

    const view = render(<BrowserTerminal sessionID="s-1" onClose={() => undefined} />);
    await waitFor(() => expect(decoded()).toContain("alice@host:~$ "));
    expect(apiMock.openPAMTerminal).toHaveBeenCalledWith("s-1", { cols: 100, rows: 30 }, expect.stringMatching(/^pam-terminal:s-1:/));
    expect(screen.getByRole("status")).toHaveTextContent("Connected. The gateway signs in for you and records the session.");

    fake.typed?.("echo browser-$((40+2))\r");
    await waitFor(() => expect(apiMock.writePAMTerminal).toHaveBeenCalledTimes(1));
    expect(apiMock.writePAMTerminal).toHaveBeenCalledWith("s-1", "t-1", btoa("echo browser-$((40+2))\r"), "pam-terminal-input:t-1:1");

    releaseEnd();
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("The shell exited with status 0."));
    expect(decoded()).toContain("browser-42");
    expect(apiMock.readPAMTerminal).toHaveBeenLastCalledWith("s-1", "t-1", 14, 20);
    expect(await axe(view.container)).toHaveNoViolations();

    view.unmount();
    expect(apiMock.closePAMTerminal).toHaveBeenCalledWith("s-1", "t-1");
    expect(fake.disposed).toBe(1);
  });

  it("says why a terminal could not be opened", async () => {
    apiMock.openPAMTerminal.mockRejectedValue(new Error("the session was not opened for the browser"));
    render(<BrowserTerminal sessionID="s-2" onClose={() => undefined} />);
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("The terminal could not be opened: the session was not opened for the browser"));
    expect(apiMock.readPAMTerminal).not.toHaveBeenCalled();
  });

  it("opens a terminal in the pod named on a Kubernetes session", async () => {
    const user = userEvent.setup();
    apiMock.openPAMTerminal.mockResolvedValue({ id: "t-3", session_id: "s-3", cols: 100, rows: 30 });
    apiMock.readPAMTerminal.mockImplementation(() => new Promise(() => undefined));
    apiMock.closePAMTerminal.mockResolvedValue({ id: "t-3", session_id: "s-3" });
    const view = render(<PodTerminal sessionID="s-3" />);
    expect(screen.getByRole("button", { name: "Open terminal" })).toBeDisabled();
    expect(await axe(view.container)).toHaveNoViolations();

    await user.type(screen.getByRole("textbox", { name: "Namespace" }), "team-a");
    await user.type(screen.getByRole("textbox", { name: "Pod" }), "web-0");
    await user.type(screen.getByRole("textbox", { name: "Container (optional)" }), "app");
    await user.click(screen.getByRole("button", { name: "Open terminal" }));
    await waitFor(() =>
      expect(apiMock.openPAMTerminal).toHaveBeenCalledWith(
        "s-3",
        { cols: 100, rows: 30, namespace: "team-a", pod: "web-0", container: "app" },
        expect.stringMatching(/^pam-terminal:s-3:/),
      ),
    );
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Connected. The gateway signs in for you and records the session."));

    await user.click(screen.getByRole("button", { name: "Close terminal" }));
    expect(apiMock.closePAMTerminal).toHaveBeenCalledWith("s-3", "t-3");
    expect(screen.getByRole("textbox", { name: "Namespace" })).toHaveValue("team-a");
  });
});

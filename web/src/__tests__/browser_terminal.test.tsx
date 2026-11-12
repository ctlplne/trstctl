import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
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
    listPAMSessionPods: vi.fn(),
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
    expect(apiMock.openPAMTerminal).toHaveBeenCalledWith("s-1", { cols: 100, rows: 30 }, expect.stringMatching(/^pam-terminal:s-1:/), expect.any(AbortSignal));
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

  it("opens a terminal in a typed pod when the session's account may not list pods", async () => {
    const user = userEvent.setup();
    apiMock.listPAMSessionPods.mockRejectedValue(new Error("the session's account may not list pods in default"));
    apiMock.openPAMTerminal.mockResolvedValue({ id: "t-3", session_id: "s-3", cols: 100, rows: 30 });
    apiMock.readPAMTerminal.mockImplementation(() => new Promise(() => undefined));
    apiMock.closePAMTerminal.mockResolvedValue({ id: "t-3", session_id: "s-3" });
    const view = render(<PodTerminal sessionID="s-3" />);
    expect(screen.getByRole("button", { name: "Open terminal" })).toBeDisabled();
    expect(await screen.findByText(/The pods could not be listed: .*Name the pod and container instead\./)).toBeInTheDocument();
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
        expect.any(AbortSignal),
      ),
    );
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Connected. The gateway signs in for you and records the session."));

    await user.click(screen.getByRole("button", { name: "Close terminal" }));
    expect(apiMock.closePAMTerminal).toHaveBeenCalledWith("s-3", "t-3");
    expect(screen.getByRole("textbox", { name: "Namespace" })).toHaveValue("team-a");
  });
});

it("lists the pods the session's account can see and opens the chosen container (A259-L4)", async () => {
  const user = userEvent.setup();
  apiMock.listPAMSessionPods.mockImplementation(async (_sessionID: string, namespace?: string) =>
    namespace === "team-b"
      ? { namespace: "team-b", pods: [] }
      : {
          namespace: "team-a",
          truncated: true,
          pods: [
            { name: "batch-1", phase: "Succeeded", containers: ["job"] },
            { name: "web-2", phase: "Running", containers: ["app", "proxy"] },
          ],
        },
  );
  apiMock.openPAMTerminal.mockResolvedValue({ id: "t-4", session_id: "s-4", cols: 100, rows: 30 });
  apiMock.readPAMTerminal.mockImplementation(() => new Promise(() => undefined));
  const view = render(<PodTerminal sessionID="s-4" />);
  const podPicker = await screen.findByRole("combobox", { name: "Pod" });
  expect(apiMock.listPAMSessionPods).toHaveBeenCalledWith("s-4", undefined);
  expect(screen.getByRole("textbox", { name: "Namespace" })).toHaveValue("team-a");
  expect(podPicker).toHaveValue("batch-1");
  expect(screen.getByRole("option", { name: "web-2 (Running)" })).toBeInTheDocument();
  expect(screen.getByRole("combobox", { name: "Container" })).toHaveValue("job");
  expect(screen.getByText("Showing the first 500 pods.")).toBeInTheDocument();
  expect(screen.queryByRole("textbox", { name: "Pod" })).not.toBeInTheDocument();
  expect(await axe(view.container)).toHaveNoViolations();

  await user.selectOptions(podPicker, "web-2");
  const containerPicker = screen.getByRole("combobox", { name: "Container" });
  expect(containerPicker).toHaveValue("app");
  expect(
    within(containerPicker)
      .getAllByRole("option")
      .map((option) => option.textContent),
  ).toEqual(["app", "proxy"]);
  await user.selectOptions(containerPicker, "proxy");
  await user.click(screen.getByRole("button", { name: "Open terminal" }));
  await waitFor(() =>
    expect(apiMock.openPAMTerminal).toHaveBeenCalledWith(
      "s-4",
      { cols: 100, rows: 30, namespace: "team-a", pod: "web-2", container: "proxy" },
      expect.stringMatching(/^pam-terminal:s-4:/),
      expect.any(AbortSignal),
    ),
  );
  view.unmount();

  // Another namespace is listed on request; an empty one says so.
  render(<PodTerminal sessionID="s-5" />);
  await screen.findByRole("combobox", { name: "Pod" });
  const namespace = screen.getByRole("textbox", { name: "Namespace" });
  await user.clear(namespace);
  await user.type(namespace, "team-b");
  await user.click(screen.getByRole("button", { name: "List pods" }));
  await waitFor(() => expect(apiMock.listPAMSessionPods).toHaveBeenLastCalledWith("s-5", "team-b"));
  expect(await screen.findByText("This session's account can see no pods in team-b.")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Open terminal" })).toBeDisabled();
});

it("sends a complete SSH exec request and cancels it on unmount before startup", async () => {
  apiMock.openPAMTerminal.mockImplementation(() => new Promise(() => undefined));
  const view = render(<BrowserTerminal sessionID="s-ssh" sshCommand="rm /owned/file" onClose={() => undefined} />);
  await waitFor(() =>
    expect(apiMock.openPAMTerminal).toHaveBeenCalledWith(
      "s-ssh",
      { cols: 100, rows: 30, ssh_command: "rm /owned/file" },
      expect.any(String),
      expect.any(AbortSignal),
    ),
  );
  const signal = apiMock.openPAMTerminal.mock.calls[0][3] as AbortSignal;
  expect(signal.aborted).toBe(false);
  view.unmount();
  expect(signal.aborted).toBe(true);
});

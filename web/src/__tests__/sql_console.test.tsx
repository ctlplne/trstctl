import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { SqlConsole } from "@/components/access/SqlConsole";

// A259 part 2: the database console runs SQL through the control plane, shows
// the last result's rows (NULL stays NULL), the database's own refusal, and
// never holds a ticket or a credential.

const { apiMock } = vi.hoisted(() => ({ apiMock: { runPAMQuery: vi.fn() } }));

vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

afterEach(() => vi.clearAllMocks());

describe("database console", () => {
  it("runs SQL and shows the rows, NULLs and the database's refusals", async () => {
    const user = userEvent.setup();
    apiMock.runPAMQuery
      .mockResolvedValueOnce({ columns: ["id", "note"], rows: [["1", null]], command_tag: "SELECT 1" })
      .mockResolvedValueOnce({ columns: [], rows: [], error: { code: "42501", message: "permission denied for table pam_smoke" } });
    const view = render(<SqlConsole sessionID="s-1" onClose={() => undefined} />);
    const sql = screen.getByRole("textbox", { name: "SQL" });
    expect(screen.getByRole("button", { name: "Run" })).toBeDisabled();

    await user.type(sql, "SELECT id, note FROM pam_smoke");
    await user.click(screen.getByRole("button", { name: "Run" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("1 row SELECT 1"));
    expect(apiMock.runPAMQuery).toHaveBeenCalledWith(
      "s-1",
      { sql: "SELECT id, note FROM pam_smoke" },
      expect.stringMatching(/^pam-query:s-1:/),
      expect.any(AbortSignal),
    );
    const table = screen.getByRole("table", { name: "Result of the last statement" });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((cell) => cell.textContent),
    ).toEqual(["id", "note"]);
    expect(
      within(table)
        .getAllByRole("cell")
        .map((cell) => cell.textContent),
    ).toEqual(["1", "NULL"]);
    expect(await axe(view.container)).toHaveNoViolations();

    await user.clear(sql);
    await user.type(sql, "INSERT INTO pam_smoke VALUES (2)");
    await user.click(screen.getByRole("button", { name: "Run" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("The database refused it (42501): permission denied for table pam_smoke"));
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    const keys = apiMock.runPAMQuery.mock.calls.map((call) => call[2]);
    expect(new Set(keys).size).toBe(2);
  });

  it("says when the console could not run the SQL", async () => {
    const user = userEvent.setup();
    apiMock.runPAMQuery.mockRejectedValue(new Error("the session's connection ended"));
    render(<SqlConsole sessionID="s-2" onClose={() => undefined} />);
    await user.type(screen.getByRole("textbox", { name: "SQL" }), "SELECT 1");
    await user.click(screen.getByRole("button", { name: "Run" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("The console could not run it: the session's connection ended"));
  });
});

describe("database consoles for MySQL, MongoDB and Redis (A259-L5)", () => {
  it("sends SQL from a MySQL session's console and shows its refusal with the error number", async () => {
    const user = userEvent.setup();
    apiMock.runPAMQuery.mockResolvedValue({ columns: [], rows: [], error: { code: "1142 (42000)", message: "INSERT command denied" } });
    render(<SqlConsole sessionID="s-my" engine="mysql" onClose={() => undefined} />);
    expect(screen.getByText("One SQL statement at a time.")).toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: "SQL" }), "INSERT INTO app.notes VALUES (2, 'no')");
    await user.click(screen.getByRole("button", { name: "Run" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("The database refused it (1142 (42000)): INSERT command denied"));
    expect(apiMock.runPAMQuery.mock.calls[0][1]).toEqual({ sql: "INSERT INTO app.notes VALUES (2, 'no')" });
  });

  it("sends a Redis command and shows an array reply by position, with a nil as redis-cli does", async () => {
    const user = userEvent.setup();
    apiMock.runPAMQuery.mockResolvedValue({
      columns: ["#", "value"],
      rows: [
        ["1", "hello"],
        ["2", null],
      ],
      command_tag: "MGET",
    });
    const view = render(<SqlConsole sessionID="s-redis" engine="redis" onClose={() => undefined} />);
    const command = screen.getByRole("textbox", { name: "Command" });
    expect(screen.getByText(/One command as redis-cli takes it/)).toBeInTheDocument();
    await user.type(command, "MGET a256:one a256:two");
    await user.click(screen.getByRole("button", { name: "Run" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("2 rows MGET"));
    expect(apiMock.runPAMQuery.mock.calls[0][1]).toEqual({ command: "MGET a256:one a256:two" });
    const table = screen.getByRole("table");
    expect(
      within(table)
        .getAllByRole("cell")
        .map((cell) => cell.textContent),
    ).toEqual(["1", "hello", "2", "(nil)"]);
    expect(await axe(view.container)).toHaveNoViolations();
  });

  it("sends a MongoDB command document and shows each document", async () => {
    const user = userEvent.setup();
    apiMock.runPAMQuery.mockResolvedValue({ columns: ["document"], rows: [['{"_id":1,"note":"kept"}']], command_tag: "find" });
    render(<SqlConsole sessionID="s-mongo" engine="mongodb" onClose={() => undefined} />);
    const command = screen.getByRole("textbox", { name: "Command document (JSON)" });
    expect(screen.getByText(/It runs on the provider's database unless it names \$db\./)).toBeInTheDocument();
    await user.click(command);
    await user.paste('{"find": "notes", "filter": {"_id": 1}}');
    await user.click(screen.getByRole("button", { name: "Run" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("1 row find"));
    expect(apiMock.runPAMQuery.mock.calls[0][1]).toEqual({ command: '{"find": "notes", "filter": {"_id": 1}}' });
    expect(screen.getByRole("cell", { name: '{"_id":1,"note":"kept"}' })).toBeInTheDocument();
  });
});

it("aborts the actual held HTTP query on cancel and on unmount", async () => {
  const user = userEvent.setup();
  let signal: AbortSignal | undefined;
  apiMock.runPAMQuery.mockImplementation(
    (_session, _sql, _key, abort: AbortSignal) =>
      new Promise((_resolve, reject) => {
        signal = abort;
        abort.addEventListener("abort", () => reject(new DOMException("Canceled", "AbortError")), { once: true });
      }),
  );
  const view = render(<SqlConsole sessionID="cancel-session" onClose={() => undefined} />);
  await user.type(screen.getByRole("textbox", { name: "SQL" }), "DROP TABLE held");
  await user.click(screen.getByRole("button", { name: "Run" }));
  expect(signal?.aborted).toBe(false);
  await user.click(screen.getByRole("button", { name: "Cancel query" }));
  expect(signal?.aborted).toBe(true);
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Query request canceled"));
  await user.click(screen.getByRole("button", { name: "Run" }));
  expect(signal?.aborted).toBe(false);
  view.unmount();
  expect(signal?.aborted).toBe(true);
});

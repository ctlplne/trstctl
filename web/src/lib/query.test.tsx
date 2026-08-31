import { afterEach, describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import { AppQueryProvider, invalidateAppQueryKeys, liveRefetchInterval, useApiQuery } from "@/lib/query";

afterEach(() => {
  vi.useRealTimers();
  setVisibility("visible");
});

/** S-C5 live tiles: the visibility-aware polling contract (certctl PERF-H1).
 * Hidden tabs poll nothing; visible tabs poll at the tile's cadence; returning
 * to visibility refreshes live queries immediately — and ONLY live ones. */

function setVisibility(state: "visible" | "hidden") {
  Object.defineProperty(document, "visibilityState", { configurable: true, get: () => state });
  act(() => {
    document.dispatchEvent(new Event("visibilitychange"));
  });
}

function LiveProbe({ loader }: { loader: () => Promise<string> }) {
  const query = useApiQuery(["live-probe"], loader, { live: { intervalMs: 30_000 } });
  return <p data-testid="live-probe">{query.data ?? "loading"}</p>;
}

function StaticProbe({ loader }: { loader: () => Promise<string> }) {
  const query = useApiQuery(["static-probe"], loader);
  return <p data-testid="static-probe">{query.data ?? "loading"}</p>;
}

function ControlledProbe({ tenant, loader }: { tenant: string; loader: (context: { signal: AbortSignal }) => Promise<string> }) {
  const query = useApiQuery(["controlled-probe", tenant], loader, { live: { intervalMs: 30_000 } });
  return (
    <>
      <p data-testid="controlled-probe">{query.data ?? "loading"}</p>
      <button onClick={query.refetch}>Refresh evidence</button>
    </>
  );
}

describe("visibility-aware live queries (S-C5)", () => {
  it("joins an in-flight read across explicit refresh and visibility changes", async () => {
    let finish!: (value: string) => void;
    let signal!: AbortSignal;
    const loader = vi.fn((context: { signal: AbortSignal }) => {
      signal = context.signal;
      return new Promise<string>((resolve) => {
        finish = resolve;
      });
    });
    const view = render(
      <AppQueryProvider>
        <ControlledProbe tenant="t1" loader={loader} />
      </AppQueryProvider>,
    );
    await waitFor(() => expect(loader).toHaveBeenCalledTimes(1));
    act(() => {
      screen.getByRole("button", { name: "Refresh evidence" }).click();
    });
    setVisibility("hidden");
    setVisibility("visible");
    expect(loader).toHaveBeenCalledTimes(1);
    expect(signal.aborted).toBe(false);
    await act(async () => {
      finish("snapshot one");
    });
    await screen.findByText("snapshot one");
    act(() => {
      screen.getByRole("button", { name: "Refresh evidence" }).click();
    });
    expect(loader).toHaveBeenCalledTimes(2);
    act(() => {
      screen.getByRole("button", { name: "Refresh evidence" }).click();
    });
    setVisibility("hidden");
    setVisibility("visible");
    expect(loader).toHaveBeenCalledTimes(2);
    expect(signal.aborted).toBe(false);
    view.unmount();
    expect(signal.aborted).toBe(true);
  });

  it("does not show an old tenant's late response after the query key changes", async () => {
    let finishOld!: (value: string) => void;
    let oldSignal!: AbortSignal;
    const oldLoader = vi.fn(({ signal }: { signal: AbortSignal }) => {
      oldSignal = signal;
      return new Promise<string>((resolve) => {
        finishOld = resolve;
      });
    });
    const newLoader = vi.fn().mockResolvedValue("tenant two");
    const view = render(
      <AppQueryProvider>
        <ControlledProbe tenant="t1" loader={oldLoader} />
      </AppQueryProvider>,
    );
    await waitFor(() => expect(oldLoader).toHaveBeenCalledTimes(1));
    view.rerender(
      <AppQueryProvider>
        <ControlledProbe tenant="t2" loader={newLoader} />
      </AppQueryProvider>,
    );
    await screen.findByText("tenant two");
    expect(oldSignal.aborted).toBe(true);
    await act(async () => {
      finishOld("tenant one");
    });
    expect(screen.getByTestId("controlled-probe")).toHaveTextContent("tenant two");
  });

  it("pauses real interval polling while hidden and catches up on return", async () => {
    vi.useFakeTimers();
    const loader = vi.fn().mockResolvedValue("current");
    render(
      <AppQueryProvider>
        <ControlledProbe tenant="t1" loader={loader} />
      </AppQueryProvider>,
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(25);
    });
    expect(loader).toHaveBeenCalledTimes(1);
    setVisibility("hidden");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(90_000);
    });
    expect(loader).toHaveBeenCalledTimes(1);
    setVisibility("visible");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(25);
    });
    expect(loader).toHaveBeenCalledTimes(2);
  });
  it("polls at the tile cadence while visible and not at all while hidden", () => {
    setVisibility("visible");
    expect(liveRefetchInterval(30_000)).toBe(30_000);
    setVisibility("hidden");
    expect(liveRefetchInterval(30_000)).toBe(false);
    setVisibility("visible");
  });

  it("refreshes live queries — and only live queries — on return to visibility", async () => {
    const liveLoader = vi.fn().mockResolvedValue("live");
    const staticLoader = vi.fn().mockResolvedValue("static");
    render(
      <AppQueryProvider>
        <LiveProbe loader={liveLoader} />
        <StaticProbe loader={staticLoader} />
      </AppQueryProvider>,
    );
    await waitFor(() => expect(screen.getByTestId("live-probe")).toHaveTextContent("live"));
    await waitFor(() => expect(screen.getByTestId("static-probe")).toHaveTextContent("static"));
    expect(liveLoader).toHaveBeenCalledTimes(1);
    expect(staticLoader).toHaveBeenCalledTimes(1);

    setVisibility("hidden");
    setVisibility("visible");

    await waitFor(() => expect(liveLoader).toHaveBeenCalledTimes(2));
    // The non-live query is untouched by the visibility catch-up.
    expect(staticLoader).toHaveBeenCalledTimes(1);
  });

  it("refreshes exact cross-page keys after a local-state mutation", async () => {
    const loader = vi.fn().mockResolvedValue("current");
    render(
      <AppQueryProvider>
        <StaticProbe loader={loader} />
      </AppQueryProvider>,
    );
    await waitFor(() => expect(loader).toHaveBeenCalledTimes(1));

    act(() => invalidateAppQueryKeys([["static-probe"]]));

    await waitFor(() => expect(loader).toHaveBeenCalledTimes(2));
  });
});

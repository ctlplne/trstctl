import { describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor } from "@testing-library/react";
import { AppQueryProvider, invalidateAppQueryKeys, liveRefetchInterval, useApiQuery } from "@/lib/query";

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

describe("visibility-aware live queries (S-C5)", () => {
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

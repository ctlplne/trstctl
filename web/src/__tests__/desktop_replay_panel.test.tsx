import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppQueryProvider } from "@/lib/query";
import { IntlProvider } from "@/i18n/I18nProvider";
import { DesktopReplay } from "@/components/access/DesktopReplay";
import { desktopLines } from "./fixtures/desktopReplayFixture";
const { apiMock } = vi.hoisted(() => ({ apiMock: { pamRecordingVerify: vi.fn(), pamRecordingFrames: vi.fn() } }));
vi.mock("@/lib/api", async (original) => {
  const actual = await original<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});
const draw = vi.fn();
beforeEach(() => {
  for (const mock of Object.values(apiMock)) mock.mockReset();
  draw.mockReset();
  vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue({ clearRect: vi.fn(), drawImage: draw } as unknown as CanvasRenderingContext2D);
  vi.stubGlobal(
    "Image",
    class {
      onload: (() => void) | null = null;
      onerror: (() => void) | null = null;
      set src(_value: string) {
        queueMicrotask(() => this.onload?.());
      }
    },
  );
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function mount(active = false) {
  render(
    <AppQueryProvider>
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <DesktopReplay sessionID="desktop-session" active={active} />
      </IntlProvider>
    </AppQueryProvider>,
  );
}
it("verifies before reading and renders complete frames with seek controls", async () => {
  apiMock.pamRecordingVerify.mockResolvedValue({ verified: true, scope: "desktop_pixels", chunks: 1 });
  apiMock.pamRecordingFrames
    .mockResolvedValueOnce({ session_id: "desktop-session", status: "sealed", next: 1, frames: [...desktopLines(), ...desktopLines(2)] })
    .mockResolvedValue({ session_id: "desktop-session", status: "sealed", next: 1, frames: [] });
  const user = userEvent.setup();
  mount();
  await user.click(screen.getByRole("button", { name: "Load verified replay" }));
  expect(await screen.findByRole("img", { name: "Recorded desktop screen" })).toBeInTheDocument();
  await waitFor(() => expect(draw).toHaveBeenCalledTimes(13));
  fireEvent.change(screen.getByRole("slider"), { target: { value: "1" } });
  await waitFor(() => expect(draw).toHaveBeenCalledTimes(26));
  expect(apiMock.pamRecordingVerify.mock.invocationCallOrder[0]).toBeLessThan(apiMock.pamRecordingFrames.mock.invocationCallOrder[0]);
});
it("does not read or draw an unverified recording", async () => {
  apiMock.pamRecordingVerify.mockResolvedValue({ verified: false, scope: "desktop_pixels", chunks: 1 });
  const user = userEvent.setup();
  mount();
  await user.click(screen.getByRole("button", { name: "Load verified replay" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("could not be verified");
  expect(apiMock.pamRecordingFrames).not.toHaveBeenCalled();
  expect(draw).not.toHaveBeenCalled();
});
it("waits for sealing and states image-redaction limits", () => {
  mount(true);
  expect(screen.getByRole("button", { name: "Load verified replay" })).toBeDisabled();
  expect(screen.getByText(/text masking does not redact pixels/)).toBeInTheDocument();
});

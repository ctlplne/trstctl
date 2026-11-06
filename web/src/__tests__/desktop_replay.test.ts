import { describe, expect, it } from "vitest";
import { desktopReplayFrames } from "@/lib/desktopReplay";
import { desktopLines } from "./fixtures/desktopReplayFixture";

describe("bounded desktop replay", () => {
  it("publishes complete lossless PNG frames in recording order", () => {
    const frames = desktopReplayFrames([...desktopLines(), ...desktopLines(2)]);
    expect(frames).toHaveLength(2);
    expect(frames[0]).toMatchObject({ key: "1:1", width: 320, height: 208, milliseconds: 0 });
    expect(frames[0].tiles).toHaveLength(13);
    expect(frames[1].milliseconds).toBe(1000);
  });
  it("refuses missing rows, duplicated rows, foreign codecs and oversized image metadata", () => {
    expect(() => desktopReplayFrames(desktopLines().slice(1))).toThrow();
    expect(() => desktopReplayFrames(desktopLines().slice(0, -1))).toThrow();
    for (const change of [{ width: 1281 }, { rows: 17 }, { height: 1025 }, { y: 65535 }, { codec: "svg" }, { last: true }, { frame: -1 }]) {
      const lines = desktopLines();
      Object.assign(lines[0].desktop, change);
      expect(() => desktopReplayFrames(lines)).toThrow();
    }
    const duplicate = desktopLines();
    duplicate.splice(1, 0, duplicate[0]);
    expect(() => desktopReplayFrames(duplicate)).toThrow();
  });
  it("rejects malformed image envelopes before a browser can allocate them", () => {
    for (const data of ["data:image/svg+xml;base64,AAAA", "AAAA", "A".repeat(200001), "<script>"]) {
      const lines = desktopLines();
      lines[0].d = data;
      expect(() => desktopReplayFrames(lines)).toThrow();
    }
    for (let i = 0; i < 32; i++) {
      const lines = desktopLines();
      const raw = atob(lines[0].d);
      const bytes = Array.from(raw, (c) => c.charCodeAt(0));
      bytes[i % 24] ^= 128;
      lines[0].d = btoa(String.fromCharCode(...bytes));
      expect(() => desktopReplayFrames(lines)).toThrow();
    }
  });
});

export interface DesktopTile {
  y: number;
  rows: number;
  data: string;
}
export interface DesktopReplayFrame {
  key: string;
  width: number;
  height: number;
  milliseconds: number;
  tiles: DesktopTile[];
}
const integer = (value: unknown, min: number, max: number): value is number => Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= max;

/** Treat even signed image metadata as untrusted. Decode dimensions before any
 * browser image allocation, and publish only complete, contiguous frames. */
export function desktopReplayFrames(lines: Record<string, unknown>[]): DesktopReplayFrame[] {
  const complete: DesktopReplayFrame[] = [];
  const pending = new Map<string, DesktopReplayFrame>();
  for (const line of lines) {
    if (line.e !== "desktop") continue;
    const tile = line.desktop;
    if (!tile || typeof tile !== "object" || Array.isArray(tile)) throw new Error("invalid desktop recording");
    const p = tile as Record<string, unknown>;
    if (
      !integer(line.c, 1, 1_000_000) ||
      !integer(p.frame, 1, Number.MAX_SAFE_INTEGER) ||
      !integer(p.width, 320, 1280) ||
      !integer(p.height, 200, 1024) ||
      !integer(p.y, 0, 1023) ||
      !integer(p.rows, 1, 16) ||
      p.y + p.rows > p.height ||
      p.codec !== "png" ||
      typeof p.last !== "boolean" ||
      !integer(line.t, 0, 86_400_000) ||
      typeof line.d !== "string" ||
      line.d.length > 200_000 ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(line.d)
    )
      throw new Error("invalid desktop recording");
    const raw = atob(line.d);
    const signature = [137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82];
    if (raw.length < 33 || signature.some((value, i) => raw.charCodeAt(i) !== value)) throw new Error("invalid desktop PNG");
    const dimension = (at: number) => raw.charCodeAt(at) * 0x1000000 + raw.charCodeAt(at + 1) * 65536 + raw.charCodeAt(at + 2) * 256 + raw.charCodeAt(at + 3);
    if (dimension(16) !== p.width || dimension(20) !== p.rows) throw new Error("invalid desktop PNG dimensions");
    const key = String(line.c) + ":" + String(p.frame);
    let frame = pending.get(key);
    if (!frame) {
      if (p.y !== 0 || pending.size >= 16) throw new Error("incomplete desktop frame");
      frame = { key, width: p.width, height: p.height, milliseconds: line.t, tiles: [] };
      pending.set(key, frame);
    }
    const previous = frame.tiles.at(-1);
    if (frame.width !== p.width || frame.height !== p.height || p.y !== (previous ? previous.y + previous.rows : 0) || p.last !== (p.y + p.rows === p.height))
      throw new Error("noncontiguous desktop frame");
    frame.tiles.push({ y: p.y, rows: p.rows, data: line.d });
    if (p.last) {
      complete.push(frame);
      pending.delete(key);
    }
  }
  if (pending.size !== 0) throw new Error("incomplete desktop recording");
  return complete;
}

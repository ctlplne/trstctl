import { useEffect, useId, useRef, useState } from "react";
import { api } from "@/lib/api";
import { desktopReplayFrames, type DesktopReplayFrame } from "@/lib/desktopReplay";
import { useApiQuery } from "@/lib/query";
import { useTranslation } from "@/i18n/I18nProvider";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Num } from "@/components/typography";

const emptyFrames: DesktopReplayFrame[] = [];

async function loadReplay(id: string): Promise<DesktopReplayFrame[]> {
  const verification = await api.pamRecordingVerify(id);
  if (!verification.verified || verification.scope !== "desktop_pixels") throw new Error("unverified desktop recording");
  const lines: Record<string, unknown>[] = [];
  let from = 0;
  let bytes = 0;
  for (let page = 0; page < 1000; page++) {
    const data = await api.pamRecordingFrames(id, from);
    if (data.status !== "sealed") throw new Error("recording is not sealed");
    for (const line of data.frames) {
      bytes += JSON.stringify(line).length;
      if (bytes > 64 * 1024 * 1024) throw new Error("desktop replay exceeds browser memory bound");
      lines.push(line);
    }
    if (data.next <= from || data.frames.length === 0) return desktopReplayFrames(lines);
    from = data.next;
  }
  throw new Error("desktop recording exceeds replay page bound");
}

export function DesktopReplay({ sessionID, active }: { sessionID: string; active: boolean }) {
  const { t } = useTranslation();
  const [opened, setOpened] = useState(false);
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [imageError, setImageError] = useState(false);
  const slider = useId();
  const canvas = useRef<HTMLCanvasElement>(null);
  const query = useApiQuery(["desktop-recording-replay", sessionID], () => loadReplay(sessionID), { enabled: opened, retry: false });
  const frames = query.data ?? emptyFrames;
  const frame = frames[index];
  useEffect(() => {
    if (!playing || index + 1 >= frames.length) return;
    const timer = setTimeout(() => setIndex(index + 1), Math.max(10, frames[index + 1].milliseconds - frames[index].milliseconds));
    return () => clearTimeout(timer);
  }, [playing, index, frames]);
  useEffect(() => {
    if (!frame || !canvas.current) return;
    let cancelled = false;
    const context = canvas.current.getContext("2d");
    if (!context) return;
    Promise.all(
      frame.tiles.map(
        (tile) =>
          new Promise<{ image: HTMLImageElement; y: number }>((resolve, reject) => {
            const image = new Image();
            image.onload = () => resolve({ image, y: tile.y });
            image.onerror = reject;
            image.src = "data:image/png;base64," + tile.data;
          }),
      ),
    ).then(
      (tiles) => {
        if (!cancelled) {
          context.clearRect(0, 0, frame.width, frame.height);
          for (const tile of tiles) context.drawImage(tile.image, 0, tile.y);
        }
      },
      () => {
        if (!cancelled) setImageError(true);
      },
    );
    return () => {
      cancelled = true;
    };
  }, [frame]);
  return (
    <section className="grid gap-3 border-t border-border px-5 py-4" aria-label={t("admin.access.desktop.replay")}>
      <h3 className="text-body font-semibold">{t("admin.access.desktop.replay")}</h3>
      <p className="text-caption text-muted-foreground">{t("admin.access.desktop.replayHelp")}</p>
      <Button
        type="button"
        variant="outline"
        disabled={active || query.fetching}
        onClick={() => {
          setOpened(true);
          if (opened) query.refetch();
        }}
      >
        {t("admin.access.desktop.load")}
      </Button>
      {active ? <p>{t("admin.access.desktop.awaitSeal")}</p> : null}
      {query.error || imageError ? <p role="alert">{t("admin.access.desktop.replayFailed")}</p> : null}
      {frame ? (
        <>
          <canvas
            ref={canvas}
            width={frame.width}
            height={frame.height}
            className="h-auto max-w-full rounded-control border border-border"
            role="img"
            aria-label={t("admin.access.desktop.screen")}
          />
          <label htmlFor={slider}>
            {t("admin.access.desktop.position")} <Num>{(frame.milliseconds / 1000).toFixed(1)}</Num>
          </label>
          <Input
            id={slider}
            type="range"
            min={0}
            max={Math.max(0, frames.length - 1)}
            value={index}
            onChange={(event) => {
              setPlaying(false);
              setIndex(Number(event.target.value));
            }}
          />
          <Button
            type="button"
            variant="outline"
            disabled={frames.length < 2}
            onClick={() => {
              if (index + 1 >= frames.length) {
                setIndex(0);
                setPlaying(true);
              } else setPlaying(!playing);
            }}
          >
            {t(playing && index + 1 < frames.length ? "admin.access.desktop.pause" : "admin.access.desktop.play")}
          </Button>
        </>
      ) : null}
      {opened && !query.fetching && !query.error && frames.length === 0 ? <p>{t("admin.access.desktop.noFrames")}</p> : null}
    </section>
  );
}

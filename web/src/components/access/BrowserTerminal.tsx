import { useEffect, useRef, useState } from "react";
import { useTranslation } from "@/i18n/I18nProvider";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";

// A259: a terminal on a privileged SSH session opened for the browser, or an
// exec in a pod on a Kubernetes one (exec names the pod). The control plane
// holds the session's ticket and opens the shell through the session's
// gateway; this component only shows the terminal's output, read by
// long-polling, and sends what is typed. No credential or ticket reaches the
// browser.

const COLS = 100;
const ROWS = 30;
const INPUT_FLUSH_MS = 30;

type XtermTerminal = {
  open(element: HTMLElement): void;
  write(data: Uint8Array | string): void;
  onData(listener: (data: string) => void): { dispose(): void };
  focus(): void;
  dispose(): void;
};

function decodeBase64(data: string): Uint8Array {
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function encodeBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export type PodExec = { namespace: string; pod: string; container?: string };

export function BrowserTerminal({ sessionID, exec, onClose }: { sessionID: string; exec?: PodExec; onClose: () => void }) {
  const { t } = useTranslation();
  const namespace = exec?.namespace;
  const pod = exec?.pod;
  const container = exec?.container;
  const host = useRef<HTMLDivElement | null>(null);
  const [state, setState] = useState<"opening" | "open" | "ended" | "failed">("opening");
  const [exitStatus, setExitStatus] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let stopped = false;
    let terminal: XtermTerminal | null = null;
    let terminalID: string | null = null;
    let pending = "";
    let flushTimer: ReturnType<typeof setTimeout> | null = null;
    let typed = 0;
    const flush = () => {
      flushTimer = null;
      if (!terminalID || !pending) return;
      const data = encodeBase64(pending);
      pending = "";
      typed += 1;
      void api.writePAMTerminal(sessionID, terminalID, data, `pam-terminal-input:${terminalID}:${typed}`).catch(() => undefined);
    };
    (async () => {
      try {
        const [{ Terminal }] = await Promise.all([import("@xterm/xterm"), import("@xterm/xterm/css/xterm.css")]);
        if (stopped || !host.current) return;
        terminal = new Terminal({ cols: COLS, rows: ROWS, screenReaderMode: true, convertEol: false }) as unknown as XtermTerminal;
        terminal.open(host.current);
        const opened = await api.openPAMTerminal(
          sessionID,
          { cols: COLS, rows: ROWS, ...(namespace && pod ? { namespace, pod, ...(container ? { container } : {}) } : {}) },
          `pam-terminal:${sessionID}:${crypto.randomUUID()}`,
        );
        if (stopped) {
          void api.closePAMTerminal(sessionID, opened.id).catch(() => undefined);
          return;
        }
        terminalID = opened.id;
        setState("open");
        terminal.onData((data) => {
          pending += data;
          if (!flushTimer) flushTimer = setTimeout(flush, INPUT_FLUSH_MS);
        });
        terminal.focus();
        let next = 0;
        while (!stopped) {
          const out = await api.readPAMTerminal(sessionID, opened.id, next, 20);
          if (stopped) break;
          if (out.data) terminal.write(decodeBase64(out.data));
          next = out.next;
          if (out.closed) {
            setExitStatus(out.exit_status ?? null);
            setState("ended");
            break;
          }
        }
      } catch (err) {
        if (!stopped) {
          setError(err instanceof Error ? err.message : String(err));
          setState("failed");
        }
      }
    })();
    return () => {
      stopped = true;
      if (flushTimer) clearTimeout(flushTimer);
      if (terminalID) void api.closePAMTerminal(sessionID, terminalID).catch(() => undefined);
      terminal?.dispose();
    };
  }, [sessionID, namespace, pod, container]);

  return (
    <section aria-labelledby={`pam-terminal-${sessionID}`} className="grid gap-2">
      <div className="flex items-center justify-between gap-2">
        <h3 id={`pam-terminal-${sessionID}`} className="text-sm font-semibold">
          {t("admin.access.terminal.title")}
        </h3>
        <Button type="button" variant="outline" onClick={onClose}>
          {t("admin.access.terminal.close")}
        </Button>
      </div>
      <p role="status" aria-live="polite" className="text-sm text-muted-foreground">
        {state === "opening"
          ? t("admin.access.terminal.opening")
          : state === "open"
            ? t("admin.access.terminal.open")
            : state === "ended"
              ? exitStatus === null
                ? t("admin.access.terminal.ended")
                : t("admin.access.terminal.exited", { status: exitStatus })
              : t("admin.access.terminal.failed", { error: error ?? "" })}
      </p>
      <div ref={host} data-testid="pam-terminal" className="overflow-auto rounded-panel border border-border bg-black p-2" />
    </section>
  );
}

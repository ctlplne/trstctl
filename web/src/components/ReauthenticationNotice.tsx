import { useEffect, useRef, useState } from "react";
import { useTranslation } from "@/i18n/I18nProvider";
import { Button } from "@/components/ui/button";

// A277: a high-risk access template answers 401 with a step-up challenge.
// The person signs in again in a separate window or tab, so the approved
// request this page holds survives; that window reports back on this origin
// (a BroadcastChannel, or a message to its opener) and the person retries.

export const REAUTH_MESSAGE = "trstctl:reauthenticated";
export const REAUTH_CHANNEL = "trstctl-reauthentication";
const REAUTH_PATH = `/login?${new URLSearchParams({ reauth: "1", return_to: "/reauthenticated" }).toString()}`;

/** reportReauthenticated tells every waiting page on this origin that the
 * person signed in again. */
export function reportReauthenticated() {
  if (typeof BroadcastChannel !== "undefined") {
    const channel = new BroadcastChannel(REAUTH_CHANNEL);
    channel.postMessage({ type: REAUTH_MESSAGE });
    channel.close();
  }
  const opener = window.opener as Window | null;
  if (opener && !opener.closed) opener.postMessage({ type: REAUTH_MESSAGE }, window.location.origin);
}

export function ReauthenticationNotice({ maxAgeSeconds, onSignedIn }: { maxAgeSeconds: number; onSignedIn?: () => void }) {
  const { t } = useTranslation();
  const [blocked, setBlocked] = useState(false);
  const [signedIn, setSignedIn] = useState(false);
  const reported = useRef(false);
  useEffect(() => {
    const signedInAgain = () => {
      setSignedIn(true);
      setBlocked(false);
      if (!reported.current) {
        reported.current = true;
        onSignedIn?.();
      }
    };
    const isReport = (data: unknown) => (data as { type?: unknown } | null)?.type === REAUTH_MESSAGE;
    function onMessage(event: MessageEvent) {
      if (event.origin === window.location.origin && isReport(event.data)) signedInAgain();
    }
    window.addEventListener("message", onMessage);
    const channel = typeof BroadcastChannel !== "undefined" ? new BroadcastChannel(REAUTH_CHANNEL) : null;
    if (channel) channel.onmessage = (event: MessageEvent) => isReport(event.data) && signedInAgain();
    return () => {
      window.removeEventListener("message", onMessage);
      channel?.close();
    };
  }, [onSignedIn]);
  const minutes = Math.max(1, Math.round(maxAgeSeconds / 60));
  return (
    <div role="status" className="grid gap-2 rounded-control border border-status-warning/30 bg-status-warning/10 px-3 py-2 text-sm">
      <p>{signedIn ? t("auth.reauth.signedIn") : t("auth.reauth.required", { minutes })}</p>
      {!signedIn ? (
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            size="sm"
            onClick={() => {
              reported.current = false;
              setBlocked(window.open(REAUTH_PATH, "trstctl-reauthenticate", "popup,width=520,height=720") === null);
            }}
          >
            {t("auth.reauth.action")}
          </Button>
          {blocked ? (
            <span>
              {t("auth.reauth.popupBlocked")}{" "}
              <a href={REAUTH_PATH} target="_blank" rel="noreferrer" className="underline">
                {t("auth.reauth.openTab")}
              </a>
            </span>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

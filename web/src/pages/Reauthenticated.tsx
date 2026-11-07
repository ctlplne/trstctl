import { useEffect } from "react";
import { translateNow } from "@/i18n/I18nProvider";
import { reportReauthenticated } from "@/components/ReauthenticationNotice";

/** Reauthenticated is where a fresh sign-in window lands (A277): it tells the
 * page that asked, on this origin only, and closes itself when a script
 * opened it. */
export function Reauthenticated() {
  useEffect(() => {
    reportReauthenticated();
    const opener = window.opener as Window | null;
    if (opener && !opener.closed) window.close();
  }, []);
  return (
    <main className="flex min-h-screen items-center justify-center bg-muted/30 p-6">
      <p role="status" className="max-w-sm text-center text-body">
        {translateNow("auth.reauth.done")}
      </p>
    </main>
  );
}

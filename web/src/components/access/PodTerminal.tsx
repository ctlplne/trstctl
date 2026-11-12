import { useEffect, useId, useState } from "react";

import { BrowserTerminal, type PodExec } from "@/components/access/BrowserTerminal";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type PAMSessionPods } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

// A259 part 3: on a Kubernetes session opened for the browser, the operator
// chooses a pod and its container and works in it through the browser
// terminal: the control plane opens an exec of sh through the session's
// gateway, which adds the session's own token and records the stream. No
// token or ticket reaches the browser.
//
// A259-L4: the pods and containers are listed from the cluster, through the
// same gateway as the session's own account, in its provider's namespace
// first. When the account cannot list them, the pod and container are typed.

const plain = { autoComplete: "off", spellCheck: false } as const;

type Listing = { state: "listing" } | { state: "listed"; pods: PAMSessionPods } | { state: "failed"; error: unknown };

export function PodTerminal({ sessionID }: { sessionID: string }) {
  const { t } = useTranslation();
  const ids = { namespace: useId(), pod: useId(), container: useId(), hint: useId() };
  const [namespace, setNamespace] = useState("");
  // asked is the namespace the list is asked for (none: the session
  // provider's); each ask lists again.
  const [asked, setAsked] = useState<{ namespace?: string; n: number }>({ n: 0 });
  const [listing, setListing] = useState<Listing>({ state: "listing" });
  const [pod, setPod] = useState("");
  const [container, setContainer] = useState("");
  const [open, setOpen] = useState<PodExec | null>(null);

  useEffect(() => {
    let cancelled = false;
    setListing({ state: "listing" });
    api.listPAMSessionPods(sessionID, asked.namespace).then(
      (pods) => {
        if (cancelled) return;
        setListing({ state: "listed", pods });
        setNamespace(pods.namespace);
        setPod(pods.pods[0]?.name ?? "");
        setContainer(pods.pods[0]?.containers[0] ?? "");
      },
      (error: unknown) => {
        if (!cancelled) setListing({ state: "failed", error });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [sessionID, asked]);

  if (open) return <BrowserTerminal sessionID={sessionID} exec={open} onClose={() => setOpen(null)} />;
  const listed = listing.state === "listed" ? listing.pods : null;
  const chosen = listed?.pods.find((candidate) => candidate.name === pod);
  const name = namespace.trim();
  const podName = pod.trim();
  const containerName = container.trim();
  return (
    <form
      aria-labelledby={`pam-pod-${sessionID}`}
      aria-describedby={ids.hint}
      className="grid gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        if (name && podName) setOpen({ namespace: name, pod: podName, ...(containerName ? { container: containerName } : {}) });
      }}
    >
      <h3 id={`pam-pod-${sessionID}`} className="text-sm font-semibold">
        {t("admin.access.pod.title")}
      </h3>
      <p id={ids.hint} className="text-xs text-muted-foreground">
        {t("admin.access.pod.hint")}
      </p>
      <div className="flex flex-wrap items-end gap-2">
        <label htmlFor={ids.namespace} className="grid gap-1 text-sm">
          {t("admin.access.pod.namespace")}
          <Input id={ids.namespace} value={namespace} onChange={(event) => setNamespace(event.target.value)} {...plain} required />
        </label>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={!name || listing.state === "listing"}
          onClick={() => setAsked((previous) => ({ namespace: name, n: previous.n + 1 }))}
        >
          {t("admin.access.pod.list")}
        </Button>
      </div>
      {listing.state === "listing" ? (
        <p role="status" className="text-sm text-muted-foreground">
          {t("admin.access.pod.listing")}
        </p>
      ) : null}
      {listing.state === "failed" ? (
        <p role="status" className="text-sm">
          {t("admin.access.pod.typeInstead", { reason: apiProblemMessage(listing.error, t("admin.access.pod.noAnswer")) })}
        </p>
      ) : null}
      {listed && listed.pods.length === 0 ? (
        <p role="status" className="text-sm">
          {t("admin.access.pod.none", { namespace: listed.namespace })}
        </p>
      ) : null}
      {listed && listed.pods.length > 0 ? (
        <div className="grid gap-2 md:grid-cols-2">
          <label htmlFor={ids.pod} className="grid gap-1 text-sm">
            {t("admin.access.pod.name")}
            <Select
              id={ids.pod}
              value={pod}
              onChange={(event) => {
                setPod(event.target.value);
                setContainer(listed.pods.find((candidate) => candidate.name === event.target.value)?.containers[0] ?? "");
              }}
            >
              {listed.pods.map((candidate) => (
                <option key={candidate.name} value={candidate.name}>
                  {candidate.phase ? t("admin.access.pod.option", { name: candidate.name, phase: candidate.phase }) : candidate.name}
                </option>
              ))}
            </Select>
          </label>
          <label htmlFor={ids.container} className="grid gap-1 text-sm">
            {t("admin.access.pod.containerListed")}
            <Select id={ids.container} value={container} onChange={(event) => setContainer(event.target.value)}>
              {(chosen?.containers ?? []).map((candidate) => (
                <option key={candidate} value={candidate}>
                  {candidate}
                </option>
              ))}
            </Select>
          </label>
          {listed.truncated ? <p className="text-xs text-muted-foreground md:col-span-2">{t("admin.access.pod.truncated")}</p> : null}
        </div>
      ) : null}
      {listing.state === "failed" ? (
        <div className="grid gap-2 md:grid-cols-2">
          <label htmlFor={ids.pod} className="grid gap-1 text-sm">
            {t("admin.access.pod.name")}
            <Input id={ids.pod} value={pod} onChange={(event) => setPod(event.target.value)} {...plain} required />
          </label>
          <label htmlFor={ids.container} className="grid gap-1 text-sm">
            {t("admin.access.pod.container")}
            <Input id={ids.container} value={container} onChange={(event) => setContainer(event.target.value)} {...plain} />
          </label>
        </div>
      ) : null}
      <div>
        <Button type="submit" size="sm" disabled={!name || !podName}>
          {t("admin.access.openTerminal")}
        </Button>
      </div>
    </form>
  );
}

import { useEffect, useState, type FormEvent } from "react";
import { KeyRound, Loader2, RefreshCw } from "lucide-react";
import { StatusBadge } from "@/components/StatusBadge";
import { TenantWrapperFields, type TenantWrapperKind } from "@/components/TenantCustodyPanels";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type DeploymentKEKStatus } from "@/lib/api";
import type { StatusTone } from "@/lib/statusVocab";

// A198: the deployment KEK — the key that protects every stored credential of a
// tenant that has not moved to its own key domain — and its rotation onto a key
// under an operator wrapper. Only the operator tenant may rotate; a rotation
// keeps running in the background, so the panel refreshes while one does.
export function DeploymentKEKPanel() {
  const { t, formatDateTime } = useTranslation();
  const [status, setStatus] = useState<DeploymentKEKStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [requestFailed, setRequestFailed] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [wrapperID, setWrapperID] = useState("");
  const [wrapperKind, setWrapperKind] = useState<TenantWrapperKind>("local_file");

  async function refreshStatus() {
    setLoading(true);
    setRequestFailed(false);
    try {
      setStatus(await api.deploymentKEK());
    } catch {
      setRequestFailed(true);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    api
      .deploymentKEK()
      .then((next) => {
        if (active) setStatus(next);
      })
      .catch(() => {
        if (active) setRequestFailed(true);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const running = status?.rotation?.status === "running";
  useEffect(() => {
    if (!running) return undefined;
    const timer = window.setInterval(() => {
      api
        .deploymentKEK()
        .then(setStatus)
        .catch(() => setRequestFailed(true));
    }, 5000);
    return () => window.clearInterval(timer);
  }, [running]);

  async function rotate(target: { wrapper_kind: TenantWrapperKind; wrapper_id: string }) {
    setBusy(true);
    setRequestFailed(false);
    setNotice(null);
    try {
      setStatus(await api.rotateDeploymentKEK(target));
      setNotice(t("platform.deploymentKEK.noticeStarted"));
    } catch {
      setRequestFailed(true);
    } finally {
      setBusy(false);
    }
  }

  function startRotation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const exactWrapperID = wrapperID.trim();
    if (!exactWrapperID) return;
    void rotate({ wrapper_kind: wrapperKind, wrapper_id: exactWrapperID });
  }

  const rotation = status?.rotation;
  const rotating = Boolean(rotation && (rotation.status === "running" || rotation.status === "failed"));
  const stopped = rotation?.status === "failed";
  const custodyLabels: Record<string, string> = {
    key_file: t("platform.deploymentKEK.custodyKeyFile"),
    local_file: t("platform.deploymentKEK.custodyLocalFile"),
    pkcs11: t("platform.deploymentKEK.custodyPKCS11"),
  };
  const stageLabels: Record<string, string> = {
    settling: t("platform.deploymentKEK.stageSettling"),
    hot_state: t("platform.deploymentKEK.stageHotState"),
    history: t("platform.deploymentKEK.stageHistory"),
    files: t("platform.deploymentKEK.stageFiles"),
    verify: t("platform.deploymentKEK.stageVerify"),
    completed: t("platform.deploymentKEK.stageCompleted"),
  };
  const badge = stopped
    ? { value: "stopped", label: t("platform.deploymentKEK.stateStopped"), tone: "critical" as StatusTone }
    : rotating
      ? { value: "rotating", label: t("platform.deploymentKEK.stateRotating"), tone: "warning" as StatusTone }
      : status && status.generation > 0
        ? { value: "rotated", label: custodyLabels[status.custody] ?? status.custody, tone: "success" as StatusTone }
        : { value: "key_file", label: t("platform.deploymentKEK.custodyKeyFile"), tone: "neutral" as StatusTone };

  return (
    <section className="ui-panel p-comfortable" aria-labelledby="deployment-kek-heading">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 id="deployment-kek-heading" className="text-title font-semibold">
            {t("platform.deploymentKEK.heading")}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">{t("platform.deploymentKEK.description")}</p>
        </div>
        {status ? <StatusBadge value={badge.value} label={badge.label} tone={badge.tone} /> : null}
      </div>

      {loading ? (
        <p className="mt-4 flex items-center gap-2 text-sm text-muted-foreground" role="status">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
          {t("platform.deploymentKEK.loading")}
        </p>
      ) : null}
      {requestFailed ? (
        <div className="mt-4 rounded-control border border-destructive/30 bg-destructive/10 p-3 text-sm" role="alert">
          <p className="font-semibold text-destructive">{t("platform.deploymentKEK.requestFailed")}</p>
          <p className="mt-1 text-muted-foreground">{t("platform.deploymentKEK.requestRecovery")}</p>
        </div>
      ) : null}
      {notice ? (
        <p className="mt-4 rounded-control border border-status-success/30 bg-status-success/10 p-3 text-sm text-status-success" role="status">
          {notice}
        </p>
      ) : null}

      {status ? (
        <div className="mt-4 grid gap-4">
          {stopped && rotation?.failure ? (
            <div className="rounded-control border border-destructive/30 bg-destructive/10 p-3 text-sm" role="alert">
              <p className="font-semibold text-destructive">{rotation.failure}</p>
              <p className="mt-1 text-muted-foreground">{t("platform.deploymentKEK.stoppedRecovery")}</p>
            </div>
          ) : null}
          <dl className="grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-4">
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.deploymentKEK.custody")}</dt>
              <dd>{custodyLabels[status.custody] ?? status.custody}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.deploymentKEK.wrapper")}</dt>
              <dd className="font-mono text-xs">{status.wrapper_id || t("platform.deploymentKEK.keyFileOnly")}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.deploymentKEK.generation")}</dt>
              <dd>
                {rotating && rotation?.next_generation
                  ? t("platform.deploymentKEK.generationRotating", { generation: status.generation, next: rotation.next_generation })
                  : t("platform.deploymentKEK.generationValue", { generation: status.generation })}
              </dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">{t("platform.deploymentKEK.rotatedAt")}</dt>
              <dd>{status.rotated_at ? formatDateTime(status.rotated_at) : t("platform.deploymentKEK.neverRotated")}</dd>
            </div>
            {rotation ? (
              <>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("platform.deploymentKEK.stage")}</dt>
                  <dd>{stageLabels[rotation.stage] ?? rotation.stage}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("platform.deploymentKEK.tenants")}</dt>
                  <dd>{t("platform.deploymentKEK.tenantsValue", { done: rotation.tenants_done, total: rotation.tenants_total })}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("platform.deploymentKEK.rewrapped")}</dt>
                  <dd>
                    {t("platform.deploymentKEK.rewrappedValue", {
                      stored: rotation.containers_rewrapped,
                      history: rotation.history_events_rewrapped,
                      files: rotation.files_rewrapped,
                    })}
                  </dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">{t("platform.deploymentKEK.verified")}</dt>
                  <dd>
                    {rotation.verified_at
                      ? t("platform.deploymentKEK.verifiedValue", { count: rotation.containers_verified, at: formatDateTime(rotation.verified_at) })
                      : t("platform.deploymentKEK.notVerified")}
                  </dd>
                </div>
              </>
            ) : null}
          </dl>
          <p className="rounded-control border border-border bg-muted/40 p-3 text-sm text-muted-foreground">{status.detail}</p>

          {status.can_rotate ? (
            <form
              className="grid gap-3 rounded-control border border-border p-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end"
              onSubmit={startRotation}
              aria-labelledby="deployment-kek-rotate-heading"
            >
              <div className="grid gap-1 text-sm sm:col-span-2">
                <h3 id="deployment-kek-rotate-heading" className="font-semibold">
                  {stopped ? t("platform.deploymentKEK.resumeHeading") : t("platform.deploymentKEK.rotateHeading")}
                </h3>
                <p className="text-muted-foreground">{t("platform.deploymentKEK.rotateHelp")}</p>
              </div>
              <TenantWrapperFields
                idPrefix="deployment-kek"
                kind={wrapperKind}
                onKind={setWrapperKind}
                wrapperID={wrapperID}
                onWrapperID={setWrapperID}
                help={t("platform.deploymentKEK.wrapperHelp")}
              />
              <Button type="submit" disabled={busy || running || !wrapperID.trim()}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                {stopped ? t("platform.deploymentKEK.resume") : t("platform.deploymentKEK.rotate")}
              </Button>
            </form>
          ) : (
            <p className="text-sm text-muted-foreground">
              {status.rotation_authority === "not_configured" ? t("platform.deploymentKEK.authorityNotConfigured") : t("platform.deploymentKEK.authorityOther")}
            </p>
          )}
          <div>
            <Button type="button" variant="outline" onClick={() => void refreshStatus()} disabled={loading || busy}>
              <RefreshCw className="h-4 w-4" aria-hidden="true" />
              {t("platform.deploymentKEK.refresh")}
            </Button>
          </div>
        </div>
      ) : null}
    </section>
  );
}

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { ErrorState } from "@/components/StatePrimitives";
import { useCan } from "@/components/rbac";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type KubernetesDecoy, type KubernetesDecoyRegistration } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

// Q6-O2: a Kubernetes service account token decoy. trstctl holds no token: the
// operator applies the returned manifest and audit rules, and the cluster's
// audit webhook reports each read of the token Secret and each use of the
// token. Only people who can plant decoys see this registry.
export function DecoyKubernetesWorkflow() {
  const { t } = useTranslation();
  const canWrite = useCan("secrets:write");
  const [cluster, setCluster] = useState("");
  const [namespace, setNamespace] = useState("");
  const [account, setAccount] = useState("");
  const [name, setName] = useState("");
  const [placement, setPlacement] = useState("");
  const [items, setItems] = useState<KubernetesDecoy[]>([]);
  const [registered, setRegistered] = useState<KubernetesDecoyRegistration | null>(null);
  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Kept as its cause and worded at render, so the refresh does not change
  // with the translator.
  const [readFailure, setReadFailure] = useState<{ cause: unknown } | null>(null);

  const refresh = useCallback(async () => {
    try {
      const decoys = await api.listKubernetesDecoys();
      setItems(decoys.items);
      setReadFailure(null);
    } catch (cause) {
      setReadFailure({ cause });
    }
  }, []);

  useEffect(() => {
    if (canWrite) void refresh();
  }, [canWrite, refresh]);

  if (!canWrite) return null;

  async function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    // The same key on a retry returns the same registration.
    const key = pendingKey ?? crypto.randomUUID();
    setPendingKey(key);
    try {
      const result = await api.registerKubernetesDecoy(
        { cluster: cluster.trim(), namespace: namespace.trim(), service_account: account.trim(), name: name.trim(), placement: placement.trim() },
        key,
      );
      setRegistered(result);
      setPendingKey(null);
      await refresh();
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.decoyK8s.registerFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function retire(id: string) {
    setBusy(true);
    setError(null);
    try {
      await api.retireKubernetesDecoy(id);
      await refresh();
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.decoyK8s.retireFailed")));
    } finally {
      setBusy(false);
    }
  }

  const webhookURL = registered
    ? `${window.location.origin}/api/v1/secrets/honeytokens/kubernetes/clusters/${encodeURIComponent(registered.k8s_cluster)}/audit-events`
    : "";
  const ready = cluster.trim() && namespace.trim() && account.trim() && name.trim() && placement.trim();

  return (
    <section aria-labelledby="decoy-k8s-heading" className="grid gap-4 border-y border-border py-4">
      <div>
        <h2 id="decoy-k8s-heading" className="text-title font-semibold">
          {t("secrets.decoyK8s.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.decoyK8s.description")}</p>
      </div>
      {error ? <ErrorState title={t("secrets.decoyK8s.error")}>{error}</ErrorState> : null}
      {readFailure ? (
        <ErrorState title={t("secrets.decoyK8s.error")}>{apiProblemMessage(readFailure.cause, t("secrets.decoyK8s.readFailed"))}</ErrorState>
      ) : null}
      <form onSubmit={(event) => void register(event)} className="grid max-w-xl gap-3">
        <Field label={t("secrets.decoyK8s.cluster")} description={t("secrets.decoyK8s.clusterHelp")}>
          {(control) => <Input {...control} value={cluster} maxLength={128} required onChange={(event) => setCluster(event.target.value)} />}
        </Field>
        <Field label={t("secrets.decoyK8s.namespace")}>
          {(control) => <Input {...control} value={namespace} maxLength={63} required onChange={(event) => setNamespace(event.target.value)} />}
        </Field>
        <Field label={t("secrets.decoyK8s.serviceAccount")} description={t("secrets.decoyK8s.serviceAccountHelp")}>
          {(control) => <Input {...control} value={account} maxLength={253} required onChange={(event) => setAccount(event.target.value)} />}
        </Field>
        <Field label={t("secrets.decoys.name")}>
          {(control) => <Input {...control} value={name} maxLength={128} required onChange={(event) => setName(event.target.value)} />}
        </Field>
        <Field label={t("secrets.decoys.placement")} description={t("secrets.decoys.placementHelp")}>
          {(control) => <Input {...control} value={placement} maxLength={256} required onChange={(event) => setPlacement(event.target.value)} />}
        </Field>
        <Button type="submit" disabled={busy || !ready}>
          {t("secrets.decoyK8s.register")}
        </Button>
      </form>
      {registered ? (
        <div className="grid gap-2 text-sm">
          <h3 className="font-semibold">{t("secrets.decoyK8s.manifest")}</h3>
          <pre className="overflow-x-auto rounded-control border border-border p-3 font-mono text-xs">{registered.manifest}</pre>
          <h3 className="font-semibold">{t("secrets.decoyK8s.auditRules")}</h3>
          <pre className="overflow-x-auto rounded-control border border-border p-3 font-mono text-xs">{registered.audit_policy}</pre>
          <p className="break-all">{t("secrets.decoyK8s.webhook", { url: webhookURL })}</p>
        </div>
      ) : null}
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("secrets.decoyK8s.empty")}</p>
      ) : (
        <ul className="grid gap-3">
          {items.map((item) => (
            <li key={item.id} className="rounded-control border border-border p-3 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <strong>{t("secrets.decoyK8s.where", { namespace: item.k8s_namespace, account: item.k8s_service_account, cluster: item.k8s_cluster })}</strong>
                <span className={item.state === "triggered" ? "font-semibold text-destructive" : "text-muted-foreground"}>{item.state}</span>
              </div>
              <p>
                {item.name} · {item.placement} · {item.k8s_secret}
              </p>
              {item.triggered_at && item.trigger_subject ? (
                <p className="break-all">
                  {t("secrets.decoyK8s.first", { reader: item.trigger_subject, at: formatDateTime(item.triggered_at), method: item.trigger_method ?? "" })}
                </p>
              ) : null}
              {item.state !== "revoked" ? (
                <Button type="button" variant="outline" className="mt-2" onClick={() => void retire(item.id)} disabled={busy}>
                  {t("secrets.decoys.retire")}
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

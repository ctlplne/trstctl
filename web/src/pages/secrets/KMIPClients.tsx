import { useState, type FormEvent } from "react";
import { KeyRound, Loader2, Trash2 } from "lucide-react";
import { useCan } from "@/components/rbac";
import { ErrorState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, type KMIPClient, type KMIPClientEnrollment, type KMIPClientList } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { RevealPanel } from "./SecretsPageParts";

const stateTone: Record<KMIPClient["state"], "success" | "warning" | "neutral"> = {
  enrolled: "success",
  enrolled_reenrolling: "success",
  awaiting_enrollment: "neutral",
  enrollment_expired: "warning",
};

// KMIPClients lets a tenant register the KMIP clients it trusts on the shared
// listener (A197). Registering shows a one-time enrollment: the client's first
// KMIP request presents its certificate with that username and password, which
// binds the certificate to this tenant.
export function KMIPClients() {
  const { t } = useTranslation();
  const canRead = useCan("keys:read");
  const canWrite = useCan("keys:write");
  const queryClient = useQueryClient();
  const clientQuery = useApiQuery(["kmip-clients"], () => api.kmipClients(), { enabled: canRead });
  const [name, setName] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [enrollment, setEnrollment] = useState<KMIPClientEnrollment | null>(null);

  function remember(updated: KMIPClient) {
    queryClient.setQueryData<KMIPClientList>(["kmip-clients"], (current) => ({
      items: [...(current?.items ?? []).filter((client) => client.id !== updated.id), updated],
    }));
  }

  async function run(key: string, action: () => Promise<void>) {
    setError(null);
    setBusy(key);
    try {
      await action();
    } catch (failure) {
      setError(apiProblemMessage(failure, t("secrets.kmipClients.failed")));
    } finally {
      setBusy(null);
    }
  }

  function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void run("register", async () => {
      const created = await api.registerKMIPClient({ name: name.trim() });
      remember(created.client);
      setEnrollment(created);
      setName("");
    });
  }

  function reenroll(client: KMIPClient) {
    void run(client.id, async () => {
      const issued = await api.issueKMIPClientEnrollment(client.id);
      remember(issued.client);
      setEnrollment(issued);
    });
  }

  function remove(client: KMIPClient) {
    if (!window.confirm(t("secrets.kmipClients.removeConfirm", { name: client.name }))) return;
    void run(client.id, async () => {
      await api.removeKMIPClient(client.id);
      queryClient.setQueryData<KMIPClientList>(["kmip-clients"], (current) => ({
        items: (current?.items ?? []).filter((item) => item.id !== client.id),
      }));
    });
  }

  const stateLabels: Record<KMIPClient["state"], string> = {
    enrolled: t("secrets.kmipClients.state.enrolled"),
    enrolled_reenrolling: t("secrets.kmipClients.state.enrolled_reenrolling"),
    awaiting_enrollment: t("secrets.kmipClients.state.awaiting_enrollment"),
    enrollment_expired: t("secrets.kmipClients.state.enrollment_expired"),
  };
  const clients = clientQuery.data?.items ?? [];
  return (
    <section aria-labelledby="kmip-clients-heading" className="grid gap-3 border-t border-border pt-3">
      <div>
        <h3 id="kmip-clients-heading" className="font-medium">
          {t("secrets.kmipClients.heading")}
        </h3>
        <p className="text-muted-foreground">{t("secrets.kmipClients.description")}</p>
      </div>
      {canWrite ? (
        <form className="flex flex-wrap items-end gap-2" onSubmit={register}>
          <Field label={t("secrets.kmipClients.name")} description={t("secrets.kmipClients.nameDescription")}>
            {(control) => <Input {...control} value={name} maxLength={128} onChange={(event) => setName(event.target.value)} />}
          </Field>
          <Button type="submit" disabled={busy !== null || name.trim() === ""}>
            {busy === "register" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
            {t("secrets.kmipClients.register")}
          </Button>
        </form>
      ) : null}
      {enrollment ? (
        <RevealPanel
          title={t("secrets.kmipClients.enrollmentTitle", { name: enrollment.client.name })}
          value={`username: ${enrollment.enrollment.username}\npassword: ${enrollment.enrollment.password}`}
          onDismiss={() => setEnrollment(null)}
        >
          {t("secrets.kmipClients.enrollmentDescription", { expires: enrollment.enrollment.expires_at })}
        </RevealPanel>
      ) : null}
      {error ? <ErrorState title={t("secrets.kmipClients.failed")}>{error}</ErrorState> : null}
      {clientQuery.error ? (
        <ErrorState title={t("secrets.kmipClients.unavailable")}>{clientQuery.error}</ErrorState>
      ) : clients.length === 0 ? (
        <p className="text-muted-foreground">{t("secrets.kmipClients.empty")}</p>
      ) : (
        <ul className="grid gap-2">
          {clients.map((client) => (
            <li key={client.id} className="grid gap-1 border-s-2 border-border ps-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium">{client.name}</span>
                <StatusBadge value={client.state} label={stateLabels[client.state]} tone={stateTone[client.state]} />
              </div>
              {client.fingerprint ? (
                <p className="break-all font-mono text-caption text-muted-foreground">
                  {client.subject ? t("secrets.kmipClients.certificate", { subject: client.subject, fingerprint: client.fingerprint }) : client.fingerprint}
                </p>
              ) : null}
              <p className="text-muted-foreground">{client.detail}</p>
              {canWrite ? (
                <div className="flex flex-wrap gap-2">
                  <Button type="button" size="sm" variant="outline" disabled={busy !== null} onClick={() => reenroll(client)}>
                    {t("secrets.kmipClients.newEnrollment")}
                  </Button>
                  <Button type="button" size="sm" variant="outline" disabled={busy !== null} onClick={() => remove(client)}>
                    <Trash2 className="h-4 w-4" aria-hidden="true" />
                    {t("secrets.kmipClients.remove")}
                  </Button>
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

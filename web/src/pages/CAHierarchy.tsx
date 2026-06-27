import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Building2, CheckCircle2, Cloud, FileKey2, Globe2, Home, KeyRound, LockKeyhole, Plus, RefreshCw, Server, ShieldCheck, X, XCircle } from "lucide-react";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { CAOverview } from "@/components/ca";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { api, ApiError, type CACeremonyStartRequest, type CAKeyCeremony, type ExternalCA, type Issuer, type IssuerRequest, type ManagedKey, type Profile } from "@/lib/api";
import { defaultIssuerConfigValues, issuerTypes, splitPEMChain, type IssuerConfigField, type IssuerTypeConfig } from "@/lib/issuerCatalog";

type Notice = { kind: "permission" | "error"; message: string };
type ProbeState = { issuerID: string; issuerName: string; status: "pending" | "passed" | "failed"; message: string };

const rootCeremonyRequest: CACeremonyStartRequest = {
  operation: "create_root",
  threshold: 2,
  spec: {
    common_name: "Trust Root CA",
    max_path_len: 1,
    signature_algorithm: "ECDSA-P256",
    ttl_seconds: 315_360_000,
  },
};

const managedKeyRequest = { algorithm: "ECDSA-P256" };

export function CAHierarchy() {
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [ceremony, setCeremony] = useState<CAKeyCeremony | null>(null);
  const [ceremonyBusy, setCeremonyBusy] = useState(false);
  const [ceremonyError, setCeremonyError] = useState<string | null>(null);
  const [managedKey, setManagedKey] = useState<ManagedKey | null>(null);
  const [keyBusy, setKeyBusy] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [issuerDialogType, setIssuerDialogType] = useState<IssuerTypeConfig | null>(null);
  const [issuerBusy, setIssuerBusy] = useState(false);
  const [issuerError, setIssuerError] = useState<string | null>(null);
  const [probe, setProbe] = useState<ProbeState | null>(null);

  async function load() {
    setLoading(true);
    setNotice(null);
    try {
      setIssuers(await api.issuers());
    } catch (err) {
      setIssuers([]);
      setNotice(noticeForError(err, "Could not load issuers"));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    let cancelled = false;
    Promise.resolve()
      .then(() => api.profiles())
      .then((list) => {
        if (!cancelled) setProfiles(list);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  const sortedIssuers = useMemo(() => [...issuers].sort((a, b) => a.name.localeCompare(b.name)), [issuers]);

  async function startRootCeremony() {
    setCeremonyBusy(true);
    setCeremonyError(null);
    try {
      setCeremony(await api.createCACeremony(rootCeremonyRequest));
    } catch (err) {
      setCeremonyError(errorText(err, "Could not start ceremony"));
    } finally {
      setCeremonyBusy(false);
    }
  }

  async function approveCeremony(id: string) {
    setCeremonyBusy(true);
    setCeremonyError(null);
    try {
      setCeremony(await api.approveCACeremony(id));
    } catch (err) {
      setCeremonyError(errorText(err, "Could not approve ceremony"));
    } finally {
      setCeremonyBusy(false);
    }
  }

  async function generateManagedKey() {
    setKeyBusy(true);
    setKeyError(null);
    try {
      setManagedKey(await api.generateManagedKey(managedKeyRequest));
    } catch (err) {
      setKeyError(errorText(err, "Could not generate managed key"));
    } finally {
      setKeyBusy(false);
    }
  }

  async function runManagedKeyAction(action: "rotate" | "revoke" | "zeroize", keyId: string) {
    setKeyBusy(true);
    setKeyError(null);
    try {
      const next =
        action === "rotate"
          ? await api.rotateManagedKey(keyId)
          : action === "revoke"
            ? await api.revokeManagedKey(keyId)
            : await api.zeroizeManagedKey(keyId);
      setManagedKey(next);
    } catch (err) {
      setKeyError(errorText(err, `Could not ${action} managed key`));
    } finally {
      setKeyBusy(false);
    }
  }

  async function createIssuerFromCatalog(type: IssuerTypeConfig, name: string, chainPEM: string) {
    setIssuerBusy(true);
    setIssuerError(null);
    try {
      const req: IssuerRequest = {
        name,
        kind: "x509_ca",
        internal: type.internal,
        chain: splitPEMChain(chainPEM),
      };
      await api.createIssuer(req);
      setIssuerDialogType(null);
      await load();
    } catch (err) {
      setIssuerError(errorText(err, "Could not create issuer"));
    } finally {
      setIssuerBusy(false);
    }
  }

  async function testIssuerConnection(issuer: Issuer) {
    setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "pending", message: "connection pending" });
    if (issuer.internal) {
      setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "passed", message: "connection passed" });
      return;
    }
    try {
      const externalCAs = await api.externalCAs();
      const upstream = findExternalCAForIssuer(issuer, externalCAs);
      if (upstream && externalCAAvailable(upstream)) {
        setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "passed", message: "connection passed" });
        return;
      }
      setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "failed", message: "connection failed" });
    } catch (err) {
      setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "failed", message: errorText(err, "connection failed") });
    }
  }

  return (
    <section aria-labelledby="ca-heading" className="grid gap-6">
      <PageHeader
        titleId="ca-heading"
        title="CA hierarchy"
        description="Your certificate authorities — roots and intermediates — and their issuers, with multi-person approval ceremonies (no single admin can act alone) and custody controls for the signing keys."
        actions={
          <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      <CAOverview issuers={sortedIssuers} profiles={profiles} />

      <IssuerCatalog onConfigure={(type) => setIssuerDialogType(type)} />

      {probe && <ProbeBanner probe={probe} onDismiss={() => setProbe(null)} />}

      <section aria-labelledby="issuer-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <ShieldCheck className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="issuer-heading" className="text-title font-semibold">
              Issuer visibility
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              This view shows issuer name, kind, public key, custody boundary, and chain metadata. The ceremony and managed-key panels below drive the
              corresponding protected workflows.
            </p>
          </div>
        </div>
        {loading && <LoadingState>Loading issuers...</LoadingState>}
        {renderNotice(notice)}
        {!loading && !notice && sortedIssuers.length === 0 && (
          <EmptyState
            icon={<Server className="h-5 w-5" aria-hidden="true" />}
            title="No issuers yet"
            primaryAction={{
              label: "Connect first issuer",
              onClick: () => {
                const firstIssuerType = issuerTypes.find((type) => !type.internal) ?? issuerTypes[0];
                if (firstIssuerType) setIssuerDialogType(firstIssuerType);
              },
              icon: <Plus className="h-4 w-4" />,
            }}
            secondaryAction={{ label: "Create a profile", to: "/profiles", icon: <ShieldCheck className="h-4 w-4" /> }}
          >
            Add a local authority or upstream CA before certificates can be issued from constrained profiles.
          </EmptyState>
        )}
        {!loading && !notice && sortedIssuers.length > 0 && <IssuerTable issuers={sortedIssuers} probe={probe} onTestConnection={(issuer) => void testIssuerConnection(issuer)} />}
      </section>

      <section aria-labelledby="ceremony-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <FileKey2 className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="ceremony-heading" className="text-title font-semibold">
              CA key ceremony
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              Start a root CA ceremony, then record a second custodian approval before using the ceremony for a signer-backed authority action.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" onClick={() => void startRootCeremony()} disabled={ceremonyBusy}>
            Start root ceremony
          </Button>
          <span className="text-sm text-muted-foreground">Default request: Trust Root CA, 2 approvals, ECDSA-P256.</span>
        </div>
        {ceremonyError && <ErrorState title="Ceremony action failed">{ceremonyError}</ErrorState>}
        {ceremony ? (
          <CeremonyPanel ceremony={ceremony} busy={ceremonyBusy} onApprove={(id) => void approveCeremony(id)} />
        ) : (
          <EmptyState title="No ceremony loaded">Start a ceremony to see its purpose, approval threshold, and status.</EmptyState>
        )}
      </section>

      <section aria-labelledby="custody-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <KeyRound className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="custody-heading" className="text-title font-semibold">
              Managed key custody
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              Private key bytes never enter the browser. This panel shows returned key metadata and drives custody actions by key id.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" onClick={() => void generateManagedKey()} disabled={keyBusy}>
            Generate managed key
          </Button>
          <span className="text-sm text-muted-foreground">Default algorithm: ECDSA-P256.</span>
        </div>
        {keyError && <ErrorState title="Managed-key action failed">{keyError}</ErrorState>}
        {managedKey ? (
          <ManagedKeyPanel
            managedKey={managedKey}
            busy={keyBusy}
            onAction={(action, keyId) => void runManagedKeyAction(action, keyId)}
          />
        ) : (
          <EmptyState title="No managed key loaded">Generate a managed key to inspect its public metadata and lifecycle state.</EmptyState>
        )}
      </section>

      {issuerDialogType && (
        <CreateIssuerDialog
          type={issuerDialogType}
          busy={issuerBusy}
          error={issuerError}
          onClose={() => {
            setIssuerDialogType(null);
            setIssuerError(null);
          }}
          onSubmit={(name, chainPEM) => void createIssuerFromCatalog(issuerDialogType, name, chainPEM)}
        />
      )}
    </section>
  );
}

function CeremonyPanel({ busy, ceremony, onApprove }: { busy: boolean; ceremony: CAKeyCeremony; onApprove: (id: string) => void }) {
  const complete = ceremony.approvals >= ceremony.threshold || ceremony.status === "approved";
  return (
    <section aria-labelledby="active-ceremony-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="active-ceremony-heading" className="text-title font-semibold">
            Active ceremony
          </h3>
          <p className="mt-1 font-mono text-xs">{ceremony.id}</p>
        </div>
        <Button type="button" variant="outline" disabled={busy || complete} onClick={() => onApprove(ceremony.id)} aria-label={`Approve ceremony ${ceremony.id}`}>
          Approve
        </Button>
      </div>
      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <KeyValue label="Purpose" value={ceremony.purpose} mono />
        <KeyValue label="Approvals" value={`${ceremony.approvals} / ${ceremony.threshold} approvals`} />
        <KeyValue label="Status" value={ceremony.status} />
        <KeyValue label="Opened by" value={ceremony.opener || "-"} />
      </dl>
    </section>
  );
}

function IssuerCatalog({ onConfigure }: { onConfigure: (type: IssuerTypeConfig) => void }) {
  return (
    <section aria-labelledby="issuer-catalog-heading" className="grid gap-3 border-y border-border py-4">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-start gap-3">
          <Server className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="issuer-catalog-heading" className="text-title font-semibold">
              Issuer catalog
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">Available CA integrations and local signing authority templates.</p>
          </div>
        </div>
      </div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {issuerTypes.map((type) => (
          <IssuerCatalogCard key={type.id} type={type} onConfigure={onConfigure} />
        ))}
      </div>
    </section>
  );
}

function IssuerCatalogCard({ onConfigure, type }: { type: IssuerTypeConfig; onConfigure: (type: IssuerTypeConfig) => void }) {
  return (
    <article className="ui-panel grid min-h-40 gap-3 p-comfortable">
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-control border border-border bg-muted/40">
            <IssuerIcon icon={type.icon} />
          </span>
          <div className="min-w-0">
            <h3 className="truncate text-sm font-semibold">{type.name}</h3>
            <p className="text-xs text-muted-foreground">{type.internal ? "internal" : "external"}</p>
          </div>
        </div>
        <Button type="button" size="sm" variant="outline" onClick={() => onConfigure(type)} aria-label={`Configure ${type.name}`}>
          <Plus className="h-4 w-4" aria-hidden="true" />
          Configure
        </Button>
      </div>
      <p className="text-sm text-muted-foreground">{type.description}</p>
      <div className="flex flex-wrap gap-1.5">
        {type.configFields.slice(0, 3).map((field) => (
          <span key={field.key} className="rounded-control border border-border px-2 py-1 text-xs text-muted-foreground">
            {field.label}
          </span>
        ))}
      </div>
    </article>
  );
}

function CreateIssuerDialog({
  busy,
  error,
  onClose,
  onSubmit,
  type,
}: {
  type: IssuerTypeConfig;
  busy: boolean;
  error: string | null;
  onClose: () => void;
  onSubmit: (name: string, chainPEM: string) => void;
}) {
  const [name, setName] = useState("");
  const [chainPEM, setChainPEM] = useState("");
  const [config, setConfig] = useState<Record<string, string>>(() => defaultIssuerConfigValues(type));

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onSubmit(name.trim(), chainPEM.trim());
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 p-4">
      <div
        aria-labelledby="issuer-create-heading"
        role="dialog"
        aria-modal="true"
        className="max-h-[min(42rem,calc(100vh-2rem))] w-full max-w-3xl overflow-hidden rounded-panel border border-border bg-card shadow-elevation2"
      >
        <header className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
          <div className="min-w-0">
            <h2 id="issuer-create-heading" className="truncate text-title font-semibold">
              Configure {type.name} issuer
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">{type.internal ? "Local signing authority" : "External CA integration"}</p>
          </div>
          <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label="Close issuer form">
            <X className="h-4 w-4" aria-hidden="true" />
          </Button>
        </header>
        <form className="grid max-h-[calc(100vh-8rem)] overflow-y-auto" onSubmit={submit}>
          <div className="grid gap-5 p-5">
            {error && <ErrorState title="Issuer create failed">{error}</ErrorState>}
            <div className="grid gap-4 md:grid-cols-2">
              <LabeledInput id="issuer-name" label="Issuer name" value={name} required onChange={setName} placeholder="Production ACME" />
              <div className="grid gap-2">
                <label className="text-sm font-medium" htmlFor="issuer-kind">
                  Issuer kind
                </label>
                <input
                  id="issuer-kind"
                  value="x509_ca"
                  readOnly
                  className="h-10 rounded-control border border-border bg-muted/40 px-3 text-sm text-muted-foreground"
                />
              </div>
            </div>
            <div className="grid gap-2">
              <label className="text-sm font-medium" htmlFor="issuer-chain">
                CA chain PEM
              </label>
              <textarea
                id="issuer-chain"
                required
                rows={5}
                value={chainPEM}
                onChange={(event) => setChainPEM(event.target.value)}
                className="min-h-32 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs outline-none transition-colors placeholder:text-muted-foreground focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
                placeholder="-----BEGIN CERTIFICATE-----"
              />
            </div>
            <IssuerConfigForm fields={type.configFields} values={config} onChange={(key, value) => setConfig((current) => ({ ...current, [key]: value }))} />
          </div>
          <footer className="flex flex-wrap justify-end gap-2 border-t border-border px-5 py-4">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy || name.trim() === "" || chainPEM.trim() === ""}>
              Create issuer
            </Button>
          </footer>
        </form>
      </div>
    </div>
  );
}

function IssuerConfigForm({
  fields,
  onChange,
  values,
}: {
  fields: IssuerConfigField[];
  values: Record<string, string>;
  onChange: (key: string, value: string) => void;
}) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {fields.map((field) => (
        <IssuerConfigFieldControl key={field.key} field={field} value={values[field.key] ?? ""} onChange={(value) => onChange(field.key, value)} />
      ))}
    </div>
  );
}

function IssuerConfigFieldControl({ field, onChange, value }: { field: IssuerConfigField; value: string; onChange: (value: string) => void }) {
  const id = `issuer-config-${field.key}`;
  if (field.type === "select") {
    return (
      <div className="grid gap-2">
        <FieldLabel field={field} id={id} />
        <select
          id={id}
          required={field.required}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none transition-colors focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
        >
          <option value="">Select</option>
          {field.options?.map((option) => (
            <option key={option} value={option}>
              {option || "default"}
            </option>
          ))}
        </select>
      </div>
    );
  }
  if (field.type === "textarea") {
    return (
      <div className="grid gap-2 md:col-span-2">
        <FieldLabel field={field} id={id} />
        <textarea
          id={id}
          required={field.required}
          value={value}
          rows={4}
          onChange={(event) => onChange(event.target.value)}
          placeholder={field.placeholder}
          className="rounded-control border border-border bg-background px-3 py-2 text-sm outline-none transition-colors placeholder:text-muted-foreground focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
        />
      </div>
    );
  }
  return (
    <LabeledInput
      id={id}
      label={field.label}
      value={value}
      required={field.required}
      type={field.type === "password" ? "password" : field.type === "number" ? "number" : "text"}
      placeholder={field.placeholder}
      onChange={onChange}
    />
  );
}

function LabeledInput({
  id,
  label,
  onChange,
  placeholder,
  required,
  type = "text",
  value,
}: {
  id: string;
  label: string;
  value: string;
  type?: "text" | "password" | "number";
  required?: boolean;
  placeholder?: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="grid gap-2">
      <label className="text-sm font-medium" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        type={type}
        required={required}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none transition-colors placeholder:text-muted-foreground focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
      />
    </div>
  );
}

function FieldLabel({ field, id }: { field: IssuerConfigField; id: string }) {
  return (
    <label className="text-sm font-medium" htmlFor={id}>
      {field.label}
    </label>
  );
}

function ProbeBanner({ onDismiss, probe }: { probe: ProbeState; onDismiss: () => void }) {
  const passed = probe.status === "passed";
  const pending = probe.status === "pending";
  const Icon = passed ? CheckCircle2 : pending ? RefreshCw : XCircle;
  return (
    <div className="ui-panel flex items-start justify-between gap-3 p-comfortable text-sm" role="status">
      <div className="flex min-w-0 items-start gap-2">
        <Icon className={pending ? "mt-0.5 h-4 w-4 shrink-0 animate-spin text-muted-foreground" : passed ? "mt-0.5 h-4 w-4 shrink-0 text-emerald-600" : "mt-0.5 h-4 w-4 shrink-0 text-destructive"} aria-hidden="true" />
        <p className="min-w-0 break-words font-medium">{`${probe.issuerName}: ${probe.message}`}</p>
      </div>
      <Button type="button" variant="ghost" size="sm" onClick={onDismiss}>
        Dismiss
      </Button>
    </div>
  );
}

function ManagedKeyPanel({
  busy,
  managedKey,
  onAction,
}: {
  busy: boolean;
  managedKey: ManagedKey;
  onAction: (action: "rotate" | "revoke" | "zeroize", keyId: string) => void;
}) {
  return (
    <section aria-labelledby="managed-key-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="managed-key-heading" className="text-title font-semibold">
            Managed key
          </h3>
          <p className="mt-1 font-mono text-xs">{managedKey.key_id}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onAction("rotate", managedKey.key_id)} aria-label={`Rotate key ${managedKey.key_id}`}>
            Rotate
          </Button>
          <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onAction("revoke", managedKey.key_id)} aria-label={`Revoke key ${managedKey.key_id}`}>
            Revoke
          </Button>
          <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onAction("zeroize", managedKey.key_id)} aria-label={`Zeroize key ${managedKey.key_id}`}>
            Zeroize
          </Button>
        </div>
      </div>
      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <KeyValue label="Algorithm" value={managedKey.algorithm} />
        <KeyValue label="Version" value={`Version ${managedKey.version}`} />
        <KeyValue label="State" value={managedKey.state} />
        <KeyValue label="Public DER" value={managedKey.public_der ? `${managedKey.public_der.length} bytes` : "-"} />
      </dl>
    </section>
  );
}

function KeyValue({ label, mono = false, value }: { label: string; mono?: boolean; value: string }) {
  return (
    <div>
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "font-medium"}>{value}</dd>
    </div>
  );
}

function IssuerTable({
  issuers,
  onTestConnection,
  probe,
}: {
  issuers: Issuer[];
  probe: ProbeState | null;
  onTestConnection: (issuer: Issuer) => void;
}) {
  return (
    <div className="ui-panel overflow-x-auto">
      <table className="ui-table min-w-[60rem]">
        <caption className="sr-only">Issuer list</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Kind</th>
            <th scope="col">Internal</th>
            <th scope="col">Chain</th>
            <th scope="col">Public key</th>
            <th scope="col">Certificates</th>
            <th scope="col">Connection</th>
          </tr>
        </thead>
        <tbody>
          {issuers.map((issuer) => (
            <tr key={issuer.id} className="align-top">
              <td className="font-medium">{issuer.name}</td>
              <td>{issuer.kind}</td>
              <td>{issuer.internal ? "internal" : "external"}</td>
              <td>{issuer.chain?.length ? issuer.chain.join(" -> ") : "-"}</td>
              <td className="max-w-sm break-all font-mono text-xs">{issuer.public_key || "-"}</td>
              <td>
                <a className="text-brand-accent underline" href={`/certificates?issuer=${encodeURIComponent(issuer.id)}`}>
                  Certificates for {issuer.name}
                </a>
              </td>
              <td>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={probe?.issuerID === issuer.id && probe.status === "pending"}
                  onClick={() => onTestConnection(issuer)}
                  aria-label={`Test connection ${issuer.name}`}
                >
                  Test
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IssuerIcon({ icon }: { icon: IssuerTypeConfig["icon"] }) {
  const className = "h-4 w-4 text-brand-accent";
  switch (icon) {
    case "building":
      return <Building2 className={className} aria-hidden="true" />;
    case "cloud":
      return <Cloud className={className} aria-hidden="true" />;
    case "globe":
      return <Globe2 className={className} aria-hidden="true" />;
    case "home":
      return <Home className={className} aria-hidden="true" />;
    case "lock":
      return <LockKeyhole className={className} aria-hidden="true" />;
    case "server":
      return <Server className={className} aria-hidden="true" />;
    case "key":
    default:
      return <KeyRound className={className} aria-hidden="true" />;
  }
}

function findExternalCAForIssuer(issuer: Issuer, externalCAs: ExternalCA[]): ExternalCA | undefined {
  const issuerName = issuer.name.trim().toLowerCase();
  return externalCAs.find((externalCA) => externalCA.id === issuer.id || externalCA.name.trim().toLowerCase() === issuerName);
}

function externalCAAvailable(externalCA: ExternalCA): boolean {
  const status = externalCA.status.trim().toLowerCase();
  return status !== "" && !["disabled", "down", "error", "failed", "unavailable"].some((bad) => status.includes(bad));
}

function renderNotice(notice: Notice | null) {
  if (!notice) return null;
  if (notice.kind === "permission") {
    return <PermissionDeniedState>{notice.message}</PermissionDeniedState>;
  }
  return <ErrorState title="Issuer metadata unavailable">{notice.message}</ErrorState>;
}

function errorText(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || fallback;
    } catch {
      return err.body || fallback;
    }
  }
  return err instanceof Error ? err.message : fallback;
}

function noticeForError(err: unknown, fallback: string): Notice {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return {
        kind: err.status === 403 ? "permission" : "error",
        message: problem.detail || problem.title || fallback,
      };
    } catch {
      return { kind: err.status === 403 ? "permission" : "error", message: err.body || fallback };
    }
  }
  return { kind: "error", message: err instanceof Error ? err.message : fallback };
}

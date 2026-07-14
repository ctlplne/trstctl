import { type FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { Eye, GitCompare, Plus } from "lucide-react";
import { api, ApiError, type Profile } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";

type ProfileSpec = Record<string, unknown>;
type BuilderMode = "guided" | "json";

interface BuilderFields {
  allowedKeyAlgorithms: string[];
  minRsaBits: number;
  minEcdsaBits: number;
  allowedEkus: string[];
  maxValidity: string;
  allowedProtocols: string[];
  allowedDnsSuffixes: string;
}

const keyAlgorithms = ["ECDSA", "RSA", "Ed25519", "Hybrid-ML-DSA-44-ECDSA-P256", "ML-DSA-65", "SLH-DSA-SHA2-128s"] as const;
const extendedKeyUsages = ["serverAuth", "clientAuth"] as const;
const enrollmentProtocols = ["api", "acme", "est", "scep", "cmp"] as const;

const defaultBuilder: BuilderFields = {
  allowedKeyAlgorithms: ["ECDSA"],
  minRsaBits: 3072,
  minEcdsaBits: 256,
  allowedEkus: ["serverAuth"],
  maxValidity: "2160h",
  allowedProtocols: ["api", "acme"],
  allowedDnsSuffixes: "example.com",
};

export function Profiles() {
  const { t } = useTranslation();
  const [items, setItems] = useState<Profile[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [selected, setSelected] = useState<Profile | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setItems(await api.profiles());
      setError(null);
    } catch (err) {
      setError(apiProblemMessage(err, "Could not load profiles"));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const profileGroups = useMemo(() => {
    const groups = new Map<string, Profile[]>();
    for (const item of items ?? []) {
      const versions = groups.get(item.name) ?? [];
      versions.push(item);
      groups.set(item.name, versions);
    }
    return Array.from(groups.entries())
      .map(([name, versions]) => ({
        name,
        versions: versions.slice().sort((a, b) => a.version - b.version),
        active: versions.find((p) => p.active) ?? versions.slice().sort((a, b) => b.version - a.version)[0],
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [items]);

  async function loadVersion(profile: Profile) {
    setDetailLoading(true);
    setDetailError(null);
    try {
      setSelected(await api.getProfileVersion(profile.name, profile.version));
    } catch (err) {
      setDetailError(apiProblemMessage(err, "Could not load profile version"));
    } finally {
      setDetailLoading(false);
    }
  }

  const profileColumns: DataGridColumn<(typeof profileGroups)[number]>[] = [
    { id: "name", header: "Name", className: "font-medium", cell: (group) => group.name },
    {
      id: "versions",
      header: "Versions",
      cell: (group) => (
        <div className="flex flex-wrap gap-2">
          {group.versions.map((p) => (
            <Button
              key={`${p.name}:${p.version}`}
              type="button"
              variant={p.active ? "default" : "outline"}
              size="sm"
              aria-label={`View ${p.name} version ${p.version}`}
              onClick={() => void loadVersion(p)}
            >
              <Eye className="h-3.5 w-3.5" aria-hidden="true" />v{p.version}
              {p.active ? " active" : ""}
            </Button>
          ))}
        </div>
      ),
    },
    { id: "active", header: "Active version", cell: (group) => `v${group.active.version}` },
    { id: "createdby", header: "Created by", cell: (group) => group.active.created_by ?? "-" },
    {
      id: "evidence",
      header: "Evidence",
      className: "text-muted-foreground",
      cell: () => "Prior versions stay resolvable for audit; issuing through a bound profile uses the recorded version.",
    },
  ];

  return (
    <section aria-labelledby="profiles-heading" className="grid gap-6">
      <PageHeader
        titleId="profiles-heading"
        title={t("nav.item.profiles")}
        description="Versioned rulebooks for what may be issued: key strength, allowed key usages (EKUs), maximum validity, enrollment protocols, and which DNS names (SANs) are permitted."
        actions={
          <Button type="button" onClick={() => setShowForm((s) => !s)}>
            <Plus className="h-4 w-4" aria-hidden="true" />
            {translateNow("source.new.profile.fcf4f3f4d5")}</Button>
        }
      />

      {showForm && (
        <ProfileForm
          onDone={() => {
            setShowForm(false);
            void load();
          }}
        />
      )}

      {error && <ErrorState title={translateNow("source.profile.list.unavailable.3759c2905e")}>{error}</ErrorState>}

      {!items && <LoadingState>{translateNow("source.loading.profiles.12a7541833")}</LoadingState>}

      {items && items.length === 0 && !showForm && (
        <EmptyState title={translateNow("source.no.profiles.yet.bd4729eb8f")}>{translateNow("source.create.a.certificate.profile.before.issuin.cdb32f2c2e")}</EmptyState>
      )}

      {items && items.length > 0 && (
        <DataGrid ariaLabel="Certificate profile versions" rows={profileGroups} columns={profileColumns} getRowId={(group) => group.name} state="ready" />
      )}

      {detailLoading && <LoadingState>{translateNow("source.loading.profile.version.dc6b63b7c9")}</LoadingState>}
      {detailError && <ErrorState title={translateNow("source.profile.version.unavailable.ec6a0646c4")}>{detailError}</ErrorState>}
      {selected && <ProfileVersionDetail profile={selected} listedProfiles={items ?? []} />}
    </section>
  );
}

function ProfileForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [mode, setMode] = useState<BuilderMode>("guided");
  const [fields, setFields] = useState<BuilderFields>(defaultBuilder);
  const [specText, setSpecText] = useState(formatSpec(buildProfileSpec(defaultBuilder)));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const builderSpec = buildProfileSpec(fields);

  function switchMode(next: BuilderMode) {
    if (next === "json") setSpecText(formatSpec(builderSpec));
    setMode(next);
    setError(null);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const profileName = name.trim();
    if (!profileName) {
      setError("Profile name is required.");
      return;
    }
    const validation = mode === "guided" ? validateBuilder(fields) : null;
    if (validation) {
      setError(validation);
      return;
    }
    let spec: ProfileSpec;
    try {
      spec = mode === "guided" ? builderSpec : parseSpecText(specText);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      return;
    }

    setBusy(true);
    try {
      await api.createProfile({ name: profileName, spec });
      onDone();
    } catch (err) {
      setError(apiProblemMessage(err, "Could not create profile"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4 border-y border-border py-4">
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,0.7fr)]">
        <div className="space-y-4">
          <div className="space-y-1">
            <label htmlFor="profile-name" className="block text-sm font-medium">
              {translateNow("source.profile.name.d3663280e1")}</label>
            <input
              id="profile-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
              placeholder={translateNow("source.web.server.e4d165cf07")}
              required
            />
          </div>

          <div className="flex flex-wrap gap-2" role="group" aria-label={translateNow("source.profile.authoring.mode.4bba88d160")}>
            <Button type="button" variant={mode === "guided" ? "default" : "outline"} size="sm" onClick={() => switchMode("guided")}>
              {translateNow("source.guided.builder.16111a6ae3")}</Button>
            <Button type="button" variant={mode === "json" ? "default" : "outline"} size="sm" onClick={() => switchMode("json")}>
              {translateNow("source.json.editor.b58c887f78")}</Button>
          </div>

          {mode === "guided" ? (
            <GuidedFields fields={fields} onChange={setFields} />
          ) : (
            <div className="space-y-1">
              <label htmlFor="profile-spec" className="block text-sm font-medium">
                {translateNow("source.json.spec.d53195334c")}</label>
              <textarea
                id="profile-spec"
                value={specText}
                onChange={(e) => setSpecText(e.target.value)}
                className="min-h-64 w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm"
                required
              />
            </div>
          )}
        </div>

        <section aria-labelledby="profile-preview-heading" className="border-y border-border py-3">
          <h2 id="profile-preview-heading" className="text-sm font-semibold">
            {translateNow("source.spec.preview.73cee36c4b")}</h2>
          <p className="mt-1 text-xs text-muted-foreground">{translateNow("source.this.json.is.sent.to.the.profile.workflow.37a80f1c5b")}</p>
          <pre data-testid="profile-spec-preview" className="mt-3 max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs">
            {mode === "guided" ? formatSpec(builderSpec) : specText}
          </pre>
        </section>
      </div>

      {error && <ErrorState title={translateNow("source.profile.rejected.e9c8593d8e")}>{error}</ErrorState>}
      <Button type="submit" disabled={busy}>
        {translateNow("source.create.profile.61d30d997d")}</Button>
    </form>
  );
}

function GuidedFields({ fields, onChange }: { fields: BuilderFields; onChange: (fields: BuilderFields) => void }) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <CheckboxSet
        legend="Allowed key algorithms"
        values={keyAlgorithms}
        selected={fields.allowedKeyAlgorithms}
        onToggle={(value) => onChange({ ...fields, allowedKeyAlgorithms: toggleValue(fields.allowedKeyAlgorithms, value) })}
      />
      <CheckboxSet
        legend="Allowed EKUs"
        values={extendedKeyUsages}
        selected={fields.allowedEkus}
        onToggle={(value) => onChange({ ...fields, allowedEkus: toggleValue(fields.allowedEkus, value) })}
      />
      <label className="space-y-1 text-sm font-medium">
        <span>{translateNow("source.minimum.rsa.bits.746e102467")}</span>
        <input
          type="number"
          min={0}
          step={256}
          value={fields.minRsaBits}
          onChange={(e) => onChange({ ...fields, minRsaBits: Number(e.target.value || 0) })}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
        />
      </label>
      <label className="space-y-1 text-sm font-medium">
        <span>{translateNow("source.minimum.ecdsa.bits.12eb67ca2f")}</span>
        <input
          type="number"
          min={0}
          step={1}
          value={fields.minEcdsaBits}
          onChange={(e) => onChange({ ...fields, minEcdsaBits: Number(e.target.value || 0) })}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
        />
      </label>
      <label className="space-y-1 text-sm font-medium">
        <span>{translateNow("source.maximum.validity.e745f2ab18")}</span>
        <input
          value={fields.maxValidity}
          onChange={(e) => onChange({ ...fields, maxValidity: e.target.value })}
          placeholder={translateNow("source.2160h.87eea7a9f3")}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
        />
      </label>
      <label className="space-y-1 text-sm font-medium">
        <span>{translateNow("source.allowed.dns.suffixes.c2747c3707")}</span>
        <input
          value={fields.allowedDnsSuffixes}
          onChange={(e) => onChange({ ...fields, allowedDnsSuffixes: e.target.value })}
          placeholder={translateNow("source.example.com.internal.example.501943e23c")}
          className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
        />
      </label>
      <div className="md:col-span-2">
        <CheckboxSet
          legend="Allowed enrollment protocols"
          values={enrollmentProtocols}
          selected={fields.allowedProtocols}
          onToggle={(value) => onChange({ ...fields, allowedProtocols: toggleValue(fields.allowedProtocols, value) })}
        />
      </div>
    </div>
  );
}

function CheckboxSet({
  legend,
  values,
  selected,
  onToggle,
}: {
  legend: string;
  values: readonly string[];
  selected: string[];
  onToggle: (value: string) => void;
}) {
  return (
    <fieldset className="space-y-2">
      <legend className="text-sm font-medium">{legend}</legend>
      <div className="flex flex-wrap gap-3">
        {values.map((value) => (
          <label key={value} className="inline-flex items-center gap-2 text-sm">
            <input type="checkbox" checked={selected.includes(value)} onChange={() => onToggle(value)} className="h-4 w-4 rounded border-border" />
            <span>{value}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function ProfileVersionDetail({ profile, listedProfiles }: { profile: Profile; listedProfiles: Profile[] }) {
  const [compareVersion, setCompareVersion] = useState(defaultCompareVersion(profile, listedProfiles));
  const [compare, setCompare] = useState<Profile | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const diffRows = compare ? diffProfileSpecs(profile.spec ?? {}, compare.spec ?? {}) : [];

  useEffect(() => {
    setCompare(null);
    setError(null);
    setCompareVersion(defaultCompareVersion(profile, listedProfiles));
  }, [profile, listedProfiles]);

  async function loadComparison(e: FormEvent) {
    e.preventDefault();
    const version = Number(compareVersion);
    if (!Number.isInteger(version) || version <= 0) {
      setError("Compare version must be a positive integer.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      setCompare(await api.getProfileVersion(profile.name, version));
    } catch (err) {
      setError(apiProblemMessage(err, "Could not load comparison version"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section aria-labelledby="profile-detail-heading" className="grid gap-4 border-y border-border py-4">
      <div>
        <h2 id="profile-detail-heading" className="text-title font-semibold">
          {profile.name} {" "}{translateNow("source.version.5ca4f3850c")}{" "}{profile.version}
        </h2>
        <p className="mt-1 text-sm text-muted-foreground">
          {profile.active ? "Active version." : "Historical version."} Certificates already bound to a profile keep audit evidence for the version that
          evaluated issuance; creating a new profile version does not rewrite past decisions.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <section aria-labelledby="selected-profile-spec-heading">
          <h3 id="selected-profile-spec-heading" className="mb-2 text-sm font-semibold">
            {translateNow("source.selected.spec.757c23e3eb")}</h3>
          <pre className="max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs">{formatSpec(profile.spec ?? {})}</pre>
        </section>
        <section aria-labelledby="profile-diff-heading">
          <h3 id="profile-diff-heading" className="mb-2 text-sm font-semibold">
            {translateNow("source.profile.diff.e8bc2bbc32")}</h3>
          <form onSubmit={loadComparison} className="mb-3 flex flex-wrap items-end gap-2">
            <label className="space-y-1 text-sm font-medium">
              <span>{translateNow("source.compare.with.version.96965654cd")}</span>
              <input
                value={compareVersion}
                onChange={(e) => setCompareVersion(e.target.value)}
                inputMode="numeric"
                className="h-9 w-36 rounded-md border border-border bg-background px-3 text-sm"
              />
            </label>
            <Button type="submit" variant="outline" disabled={loading}>
              <GitCompare className="h-4 w-4" aria-hidden="true" />
              {translateNow("source.diff.version.b5aedae8c4")}</Button>
          </form>
          {loading && <LoadingState>{translateNow("source.loading.comparison.58742d9f20")}</LoadingState>}
          {error && <ErrorState title={translateNow("source.profile.comparison.unavailable.70eb2b404e")}>{error}</ErrorState>}
          {compare && (
            <div className="space-y-2">
              <p className="text-sm text-muted-foreground">
                {translateNow("source.comparing.selected.v.4b46e29d45")}{profile.version} {" "}{translateNow("source.to.v.0969544edf")}{compare.version}.
              </p>
              {diffRows.length === 0 ? (
                <p className="text-sm text-muted-foreground">{translateNow("source.no.spec.differences.de9813046a")}</p>
              ) : (
                <div className="ui-panel overflow-x-auto">
                  <table className="ui-table min-w-[36rem]">
                    <thead>
                      <tr>
                        <th scope="col">{translateNow("source.change.c0bf75bd78")}</th>
                        <th scope="col">{translateNow("source.path.62fa5a5b0d")}</th>
                        <th scope="col">{translateNow("source.selected.57fd7a0cf3")}</th>
                        <th scope="col">{translateNow("source.compared.17c858fc6d")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {diffRows.map((row) => (
                        <tr key={`${row.kind}:${row.path}`}>
                          <td className="font-medium">{row.kind}</td>
                          <td className="font-mono">{row.path}</td>
                          <td className="font-mono">{row.before}</td>
                          <td className="font-mono">{row.after}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </section>
      </div>
    </section>
  );
}

function buildProfileSpec(fields: BuilderFields): ProfileSpec {
  const spec: ProfileSpec = {};
  if (fields.allowedKeyAlgorithms.length > 0) spec.allowed_key_algorithms = fields.allowedKeyAlgorithms;
  if (fields.allowedKeyAlgorithms.includes("RSA") && fields.minRsaBits > 0) spec.min_rsa_bits = fields.minRsaBits;
  if (fields.allowedKeyAlgorithms.includes("ECDSA") && fields.minEcdsaBits > 0) spec.min_ecdsa_bits = fields.minEcdsaBits;
  if (fields.allowedEkus.length > 0) spec.allowed_ekus = fields.allowedEkus;
  if (fields.maxValidity.trim()) spec.max_validity = fields.maxValidity.trim();
  if (fields.allowedProtocols.length > 0) spec.allowed_protocols = fields.allowedProtocols;
  const suffixes = splitList(fields.allowedDnsSuffixes);
  if (suffixes.length > 0) spec.allowed_dns_suffixes = suffixes;
  return spec;
}

function validateBuilder(fields: BuilderFields): string | null {
  if (fields.allowedKeyAlgorithms.length === 0) return "Choose at least one allowed key algorithm.";
  if (fields.allowedKeyAlgorithms.includes("RSA") && fields.minRsaBits < 2048) {
    return "RSA profiles should require at least 2048 bits.";
  }
  if (fields.allowedKeyAlgorithms.includes("ECDSA") && fields.minEcdsaBits < 224) {
    return "ECDSA profiles should require at least 224 bits.";
  }
  if (!/^\d+(ns|us|ms|s|m|h)$/.test(fields.maxValidity.trim())) {
    return "Maximum validity must be a Go-style duration such as 2160h.";
  }
  return null;
}

function parseSpecText(text: string): ProfileSpec {
  const parsed = JSON.parse(text) as unknown;
  if (!isPlainObject(parsed)) throw new Error("JSON spec must be an object.");
  return parsed;
}

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
}

function toggleValue(values: string[], value: string): string[] {
  return values.includes(value) ? values.filter((v) => v !== value) : [...values, value];
}

function formatSpec(spec: unknown): string {
  return JSON.stringify(spec ?? {}, null, 2);
}

function defaultCompareVersion(profile: Profile, listedProfiles: Profile[]): string {
  const sameName = listedProfiles.filter((p) => p.name === profile.name && p.version !== profile.version);
  const active = sameName.find((p) => p.active);
  if (active) return String(active.version);
  const closest = sameName.slice().sort((a, b) => Math.abs(a.version - profile.version) - Math.abs(b.version - profile.version))[0];
  return closest ? String(closest.version) : String(Math.max(1, profile.version - 1 || profile.version + 1));
}

function apiProblemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.retryAfterSeconds != null) return `${fallback}: retry in ${err.retryAfterSeconds}s.`;
    const body = err.body.trim();
    if (body) {
      try {
        const problem = JSON.parse(body) as { detail?: string; title?: string };
        const message = problem.detail || problem.title;
        if (message) return `${fallback}: ${message}`;
      } catch {
        return `${fallback}: ${body}`;
      }
    }
    return `${fallback}: ${err.message}`;
  }
  return `${fallback}: ${err instanceof Error ? err.message : String(err)}`;
}

interface DiffRow {
  kind: "Added" | "Removed" | "Changed";
  path: string;
  before: string;
  after: string;
}

function diffProfileSpecs(before: ProfileSpec, after: ProfileSpec): DiffRow[] {
  const left = flattenSpec(before);
  const right = flattenSpec(after);
  const paths = Array.from(new Set([...left.keys(), ...right.keys()])).sort();
  const rows: DiffRow[] = [];
  for (const pathName of paths) {
    const beforeValue = left.get(pathName);
    const afterValue = right.get(pathName);
    if (beforeValue === afterValue) continue;
    if (beforeValue == null) {
      rows.push({ kind: "Added", path: pathName, before: "-", after: afterValue ?? "-" });
      continue;
    }
    if (afterValue == null) {
      rows.push({ kind: "Removed", path: pathName, before: beforeValue, after: "-" });
      continue;
    }
    rows.push({ kind: "Changed", path: pathName, before: beforeValue, after: afterValue });
  }
  return rows;
}

function flattenSpec(value: unknown, prefix = "", out = new Map<string, string>()): Map<string, string> {
  if (isPlainObject(value)) {
    const entries = Object.entries(value);
    if (entries.length === 0 && prefix) out.set(prefix, "{}");
    for (const [key, child] of entries) {
      flattenSpec(child, prefix ? `${prefix}.${key}` : key, out);
    }
    return out;
  }
  out.set(prefix || "(root)", formatFlatValue(value));
  return out;
}

function formatFlatValue(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function isPlainObject(value: unknown): value is ProfileSpec {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

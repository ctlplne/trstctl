import { useEffect, useMemo, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { CheckCircle2, Cloud, Network, ShieldCheck } from "lucide-react";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { api, type DiscoveryCapability, type DiscoveryPlanPreview, type DiscoverySegmentCoverage, type DiscoverySource } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useApiQuery } from "@/lib/query";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";

const primaryKinds = ["network", "ssh", "adcs", "cloud_certificate", "cloud_secret", "secret_store"] as const;
export type PrimaryKind = (typeof primaryKinds)[number];
const noProviders: NonNullable<DiscoveryCapability["providers"]> = [];
const networkFieldPaths = [
  "segment",
  "relay_agent_id",
  "targets",
  "cidrs",
  "ranges",
  "ports",
  "exclude_targets",
  "exclude_cidrs",
  "exclude_ports",
  "allow_rfc1918",
  "allow_loopback",
] as const;
const cloudFieldPaths = [
  "providers[].provider",
  "providers[].region",
  "providers[].endpoint",
  "providers[].allow_private_endpoint",
  "providers[].private_egress_cidrs",
  "providers[].access_key_id_ref",
  "providers[].secret_access_key_ref",
  "providers[].session_token_ref",
  "providers[].vault_url",
  "providers[].token_ref",
  "providers[].project",
  "providers[].location",
] as const;
const secretFieldPaths = [
  ...cloudFieldPaths,
  "providers[].api_version",
  "providers[].mount",
  "providers[].path_prefix",
  "providers[].tag_key",
  "providers[].tag_value",
  "providers[].label_key",
  "providers[].label_value",
  "providers[].name_prefix",
  "providers[].inspect_content",
] as const;

/** This is the deliberate React adapter side of the server-owned source
 * contract. The live page compares it with the served manifest and fails
 * visibly if either side adds or drops a field. */
export const sourceWizardFieldPaths: Record<PrimaryKind, readonly string[]> = {
  network: networkFieldPaths,
  ssh: networkFieldPaths,
  adcs: ["url", "configuration_dn", "bind_dn", "password_ref", "relay_agent_id", "enrollment_endpoints", "allow_private_endpoint", "private_egress_cidrs"],
  cloud_certificate: cloudFieldPaths,
  cloud_secret: secretFieldPaths,
  secret_store: secretFieldPaths,
};

export function sourceWizardContractProblems(capabilities: DiscoveryCapability[]): string[] {
  const problems: string[] = [];
  for (const capability of capabilities) {
    if (!primaryKinds.includes(capability.kind as PrimaryKind) || capability.setup_surface !== "source_wizard") continue;
    const expected = new Set(sourceWizardFieldPaths[capability.kind as PrimaryKind]);
    const served = new Set(capability.configuration.map((field) => field.path));
    for (const path of served) if (!expected.has(path)) problems.push(`${capability.kind}: unsupported served field ${path}`);
    for (const path of expected) if (!served.has(path)) problems.push(`${capability.kind}: console field is absent from served contract ${path}`);
  }
  for (const kind of primaryKinds) {
    if (!capabilities.some((capability) => capability.kind === kind && capability.setup_surface === "source_wizard")) {
      problems.push(`${kind}: typed source-wizard capability is absent`);
    }
  }
  return problems.sort();
}
const examples = {
  agentID: "Agent UUID",
  scope: "production-edge",
  sourceName: "Production edge TLS",
  adcsPasswordRef: "env:TRSTCTL_ADCS_BIND_PASSWORD",
  awsAccessKeyRef: "env:TRSTCTL_DISCOVERY_AWS_ACCESS_KEY_ID",
  awsSecretKeyRef: "env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY",
  awsSessionTokenRef: "env:TRSTCTL_DISCOVERY_AWS_SESSION_TOKEN",
  discoveryTokenRef: "env:TRSTCTL_DISCOVERY_TOKEN",
  region: "us-east-1",
  apiURL: "https://…",
  vaultURL: "https://vault.example",
  gcpLocation: "global",
} as const;

const setupSchema = z
  .object({
    name: z.string().trim().min(2, translateNow("discovery.setup.validation.name")),
    kind: z.enum(primaryKinds),
    segment: z.string().trim(),
    relayAgentID: z.string().trim(),
    targets: z.string(),
    cidrs: z.string(),
    addressRanges: z.string(),
    ports: z.string(),
    excludeTargets: z.string(),
    excludeCIDRs: z.string(),
    excludePorts: z.string(),
    allowRFC1918: z.boolean(),
    allowLoopback: z.boolean(),
    provider: z.string().trim(),
    region: z.string().trim(),
    endpoint: z.string().trim(),
    vaultURL: z.string().trim(),
    project: z.string().trim(),
    location: z.string().trim(),
    tokenRef: z.string().trim(),
    accessKeyIDRef: z.string().trim(),
    secretAccessKeyRef: z.string().trim(),
    sessionTokenRef: z.string().trim(),
    apiVersion: z.string().trim(),
    mount: z.string().trim(),
    pathPrefix: z.string().trim(),
    namePrefix: z.string().trim(),
    inspectContent: z.boolean(),
    allowPrivateEndpoint: z.boolean(),
    privateEgressCIDRs: z.string(),
    adcsURL: z.string().trim(),
    configurationDN: z.string().trim(),
    bindDN: z.string().trim(),
    passwordRef: z.string().trim(),
    adcsEnrollmentEndpoints: z.string(),
    tagKey: z.string().trim(),
    tagValue: z.string().trim(),
    labelKey: z.string().trim(),
    labelValue: z.string().trim(),
  })
  .superRefine((value, ctx) => {
    if (value.kind === "network" || value.kind === "ssh") {
      requireField(ctx, value.segment, "segment", translateNow("discovery.setup.validation.scope"));
      if (!value.targets.trim() && !value.cidrs.trim() && !value.addressRanges.trim()) {
        ctx.addIssue({ code: "custom", path: ["targets"], message: translateNow("discovery.setup.validation.target") });
      }
      try {
        parsePorts(value.ports);
      } catch (error) {
        ctx.addIssue({ code: "custom", path: ["ports"], message: error instanceof Error ? error.message : translateNow("discovery.setup.validation.ports") });
      }
      if (value.excludePorts.trim()) {
        try {
          parsePorts(value.excludePorts);
        } catch (error) {
          ctx.addIssue({
            code: "custom",
            path: ["excludePorts"],
            message: error instanceof Error ? error.message : translateNow("discovery.setup.validation.excludedPorts"),
          });
        }
      }
      return;
    }
    if (value.kind === "adcs") {
      requireField(ctx, value.adcsURL, "adcsURL", translateNow("discovery.setup.validation.adcsUrl"));
      requireField(ctx, value.configurationDN, "configurationDN", translateNow("discovery.setup.validation.configurationDn"));
      requireField(ctx, value.bindDN, "bindDN", translateNow("discovery.setup.validation.bindDn"));
      requireField(ctx, value.passwordRef, "passwordRef", translateNow("discovery.setup.validation.passwordRef"));
      try {
        parseADCSEndpoints(value.adcsEnrollmentEndpoints);
      } catch (error) {
        ctx.addIssue({
          code: "custom",
          path: ["adcsEnrollmentEndpoints"],
          message: error instanceof Error ? error.message : translateNow("discovery.setup.validation.adcsEndpoints"),
        });
      }
      if (value.allowPrivateEndpoint && !splitList(value.privateEgressCIDRs).length) {
        ctx.addIssue({ code: "custom", path: ["privateEgressCIDRs"], message: translateNow("discovery.setup.validation.privateCidr") });
      }
      return;
    }
    requireField(ctx, value.provider, "provider", translateNow("discovery.setup.validation.provider"));
    if (value.provider.startsWith("aws-")) {
      requireField(ctx, value.region, "region", translateNow("discovery.setup.validation.awsRegion"));
      requireField(ctx, value.accessKeyIDRef, "accessKeyIDRef", translateNow("discovery.setup.validation.accessKeyRef"));
      requireField(ctx, value.secretAccessKeyRef, "secretAccessKeyRef", translateNow("discovery.setup.validation.secretKeyRef"));
    }
    if (value.provider === "azure-keyvault" || value.provider === "azure-key-vault") {
      requireField(ctx, value.vaultURL, "vaultURL", translateNow("discovery.setup.validation.vaultUrl"));
      requireField(ctx, value.tokenRef, "tokenRef", translateNow("discovery.setup.validation.tokenRef"));
    }
    if (value.provider === "gcp-certmanager") {
      requireField(ctx, value.project, "project", translateNow("discovery.setup.validation.gcpProject"));
      requireField(ctx, value.location, "location", translateNow("discovery.setup.validation.gcpLocation"));
      requireField(ctx, value.tokenRef, "tokenRef", translateNow("discovery.setup.validation.tokenRef"));
    }
    if (value.provider === "gcp-secret-manager") {
      requireField(ctx, value.project, "project", translateNow("discovery.setup.validation.gcpProject"));
      requireField(ctx, value.tokenRef, "tokenRef", translateNow("discovery.setup.validation.tokenRef"));
    }
    if (value.provider === "hashicorp-vault") {
      requireField(ctx, value.vaultURL, "vaultURL", translateNow("discovery.setup.validation.vaultUrl"));
      requireField(ctx, value.mount, "mount", translateNow("discovery.setup.validation.mount"));
      requireField(ctx, value.tokenRef, "tokenRef", translateNow("discovery.setup.validation.tokenRef"));
    }
    if (value.allowPrivateEndpoint && !splitList(value.privateEgressCIDRs).length) {
      ctx.addIssue({ code: "custom", path: ["privateEgressCIDRs"], message: translateNow("discovery.setup.validation.privateCidr") });
    }
  });

type SetupValues = z.infer<typeof setupSchema>;

const defaults: SetupValues = {
  name: "",
  kind: "network",
  segment: "",
  relayAgentID: "",
  targets: "",
  cidrs: "",
  addressRanges: "",
  ports: "443, 8443",
  excludeTargets: "",
  excludeCIDRs: "",
  excludePorts: "",
  allowRFC1918: false,
  allowLoopback: false,
  provider: "",
  region: "",
  endpoint: "",
  vaultURL: "",
  project: "",
  location: "",
  tokenRef: "",
  accessKeyIDRef: "",
  secretAccessKeyRef: "",
  sessionTokenRef: "",
  apiVersion: "v1",
  mount: "secret",
  pathPrefix: "",
  namePrefix: "",
  inspectContent: false,
  allowPrivateEndpoint: false,
  privateEgressCIDRs: "",
  adcsURL: "ldaps://",
  configurationDN: "",
  bindDN: "",
  passwordRef: "",
  adcsEnrollmentEndpoints: "",
  tagKey: "",
  tagValue: "",
  labelKey: "",
  labelValue: "",
};

const setupSteps: CarouselStep[] = [
  {
    id: "configure",
    label: translateNow("discovery.setup.step.scope"),
    description: translateNow("discovery.setup.step.scopeDescription"),
  },
  {
    id: "review",
    label: translateNow("discovery.setup.step.review"),
    description: translateNow("discovery.setup.step.reviewDescription"),
  },
];

export function SourceSetup({ onCreated }: { onCreated: (source: DiscoverySource) => Promise<void> | void }) {
  const { t } = useTranslation();
  const capabilities = useApiQuery(["discovery-capabilities"], api.discoveryCapabilities);
  const coverage = useApiQuery(["discovery-coverage"], () => api.discoveryCoverage());
  const [step, setStep] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [previewing, setPreviewing] = useState(false);
  const [planPreview, setPlanPreview] = useState<DiscoveryPlanPreview | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const form = useForm<SetupValues>({ resolver: zodResolver(setupSchema), defaultValues: defaults, mode: "onTouched" });
  const values = useWatch({ control: form.control, defaultValue: defaults }) as SetupValues;
  const available = useMemo(
    () => (capabilities.data?.items ?? []).filter((item) => item.setup_surface === "source_wizard" && primaryKinds.includes(item.kind as PrimaryKind)),
    [capabilities.data?.items],
  );
  const contractProblems = useMemo(() => sourceWizardContractProblems(capabilities.data?.items ?? []), [capabilities.data?.items]);
  const capability = available.find((item) => item.kind === values.kind);
  const providers = capability?.providers ?? noProviders;
  const declaredScopes = useMemo(
    () => (coverage.data?.segments ?? []).filter((segment) => segment.status !== "excluded").sort((left, right) => left.name.localeCompare(right.name)),
    [coverage.data?.segments],
  );
  const selectedScope = declaredScopes.find((segment) => segment.name === values.segment.trim());
  const willDeclareScope = (values.kind === "network" || values.kind === "ssh") && values.segment.trim() !== "" && !selectedScope;

  useEffect(() => {
    const firstProvider = providers[0]?.id ?? "";
    const currentProvider = form.getValues("provider");
    if (!providers.some((provider) => provider.id === currentProvider) && currentProvider !== firstProvider) {
      form.setValue("provider", firstProvider, { shouldValidate: step > 0 });
    }
  }, [form, providers, step, values.kind]);

  if (capabilities.loading) return <LoadingState>{t("discovery.setup.loading")}</LoadingState>;
  if (!capabilities.error && contractProblems.length > 0) {
    return (
      <ErrorState title={t("discovery.setup.contractMismatchTitle")}>
        <p>{t("discovery.setup.contractMismatchBody")}</p>
        <details className="mt-3 text-sm text-muted-foreground">
          <summary className="cursor-pointer font-medium text-foreground">{t("discovery.setup.contractMismatchDetails")}</summary>
          <ul className="mt-2 list-disc space-y-1 ps-5 font-mono text-xs">
            {contractProblems.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        </details>
      </ErrorState>
    );
  }
  if (capabilities.error || available.length === 0) {
    return (
      <ErrorState title={t("discovery.setup.unavailableTitle")}>
        <p>{t("discovery.setup.unavailableBody")}</p>
        <Button type="button" variant="outline" size="sm" className="mt-3" onClick={capabilities.refetch}>
          {t("discovery.setup.retryCapability")}
        </Button>
      </ErrorState>
    );
  }

  async function review() {
    const valid = await form.trigger();
    if (!valid) return;
    setPreviewing(true);
    setSubmitError(null);
    try {
      const current = setupSchema.parse(form.getValues());
      if ((current.kind === "network" || current.kind === "ssh") && !declaredScopes.some((segment) => segment.name === current.segment)) {
        await api.createDiscoverySegment({
          name: current.segment,
          ranges: scopeDeclarations(current),
          staleness_hours: 168,
        });
        coverage.refetch();
      }
      const preview = await api.previewDiscoveryPlan({ name: current.name, kind: current.kind, config: buildConfig(current) });
      setPlanPreview(preview);
      setStep(1);
    } catch (error) {
      setPlanPreview(null);
      setSubmitError(apiProblemMessage(error, t("discovery.setup.previewError")));
    } finally {
      setPreviewing(false);
    }
  }

  async function submit(valid: SetupValues) {
    setSubmitting(true);
    setSubmitError(null);
    try {
      const created = await api.createDiscoverySource({ name: valid.name, kind: valid.kind, config: buildConfig(valid) });
      await onCreated(created);
      form.reset(defaults);
      setPlanPreview(null);
      setStep(0);
    } catch (error) {
      setSubmitError(apiProblemMessage(error, t("discovery.setup.saveError")));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form aria-label={t("discovery.setup.formLabel")} onSubmit={form.handleSubmit(submit)}>
      <StepShell
        steps={setupSteps}
        currentIndex={step}
        onPrevious={
          step > 0
            ? () => {
                setStep(0);
                setPlanPreview(null);
              }
            : undefined
        }
        onNext={step === 0 ? review : undefined}
        nextLabel={previewing ? t("discovery.setup.validating") : willDeclareScope ? t("discovery.setup.declareAndReview") : t("discovery.setup.step.review")}
        nextDisabled={previewing}
      >
        {step === 0 ? (
          <div className="grid gap-5">
            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_18rem]">
              <Field label={t("discovery.setup.sourceName")} error={form.formState.errors.name?.message} required>
                {(control) => <Input {...control} {...form.register("name")} placeholder={examples.sourceName} />}
              </Field>
              <Field label={t("discovery.setup.kind")} error={form.formState.errors.kind?.message} required>
                {(control) => (
                  <Select
                    {...control}
                    {...form.register("kind")}
                    onChange={(event) => {
                      form.register("kind").onChange(event);
                      setStep(0);
                    }}
                  >
                    {available.map((item) => (
                      <option key={item.kind} value={item.kind}>
                        {item.label}
                      </option>
                    ))}
                  </Select>
                )}
              </Field>
            </div>

            {capability ? <CapabilityExplanation capability={capability} /> : null}
            {values.kind === "network" || values.kind === "ssh" ? (
              <NetworkFields
                form={form}
                kind={values.kind}
                values={values}
                declaredScopes={declaredScopes}
                scopesLoading={coverage.loading}
                scopesError={coverage.error}
              />
            ) : null}
            {values.kind === "adcs" ? <ADCSFields form={form} /> : null}
            {values.kind === "cloud_certificate" || values.kind === "cloud_secret" || values.kind === "secret_store" ? (
              <CloudFields form={form} providers={providers} />
            ) : null}
            {submitError ? (
              <p role="alert" className="rounded-control border border-risk-critical/40 bg-risk-critical/10 p-3 text-sm">
                {submitError}
              </p>
            ) : null}
          </div>
        ) : (
          <div className="grid gap-5">
            <section aria-label={t("discovery.setup.planLabel")} className="grid gap-3 rounded-panel border border-border bg-muted/25 p-4">
              <div className="flex items-start gap-3">
                <ShieldCheck className="mt-0.5 h-5 w-5 text-brand-accent" aria-hidden="true" />
                <div>
                  <h3 className="font-semibold">{t("discovery.setup.planTitle")}</h3>
                  <p className="mt-1 text-sm text-muted-foreground">{t("discovery.setup.planBody")}</p>
                </div>
              </div>
              <dl className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                {previewItems(planPreview).map((item) => (
                  <div key={item.label} className="min-w-0 border-s-2 border-border ps-3">
                    <dt className="text-caption text-muted-foreground">{item.label}</dt>
                    <dd className="mt-0.5 break-words font-medium">{item.value}</dd>
                  </div>
                ))}
              </dl>
              {planPreview?.normalized_targets?.length ? (
                <details className="text-sm text-muted-foreground">
                  <summary className="cursor-pointer font-medium text-foreground">
                    {t("discovery.setup.normalizedTargets")}{" "}
                    {planPreview.preview_truncated ? t("discovery.setup.firstTargets", { count: String(planPreview.normalized_targets.length) }) : ""}
                  </summary>
                  <pre className="mt-2 max-h-56 overflow-auto whitespace-pre-wrap rounded-control bg-background p-3 font-mono text-xs">
                    {planPreview.normalized_targets.join("\n")}
                  </pre>
                </details>
              ) : null}
              <details className="text-sm text-muted-foreground">
                <summary className="cursor-pointer font-medium text-foreground">{t("discovery.setup.exactRedactedConfig")}</summary>
                <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap rounded-control bg-background p-3 font-mono text-xs">
                  {JSON.stringify(redactConfig(buildConfig(values)), null, 2)}
                </pre>
              </details>
            </section>
            {submitError ? (
              <p role="alert" className="rounded-control border border-risk-critical/40 bg-risk-critical/10 p-3 text-sm">
                {submitError}
              </p>
            ) : null}
            <Button type="submit" className="justify-self-start" disabled={submitting}>
              <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
              {submitting ? t("discovery.setup.saving") : t("discovery.setup.save")}
            </Button>
          </div>
        )}
      </StepShell>
    </form>
  );
}

function CapabilityExplanation({ capability }: { capability: DiscoveryCapability }) {
  const { t } = useTranslation();
  return (
    <section
      aria-label={t("discovery.setup.purposeLabel")}
      className="grid gap-3 rounded-panel border border-brand-accent/25 bg-brand-accent/5 p-4 md:grid-cols-2"
    >
      <div className="flex gap-3">
        {capability.execution.includes("relay") ? (
          <Network className="mt-0.5 h-5 w-5 shrink-0 text-brand-accent" aria-hidden="true" />
        ) : (
          <Cloud className="mt-0.5 h-5 w-5 shrink-0 text-brand-accent" aria-hidden="true" />
        )}
        <div>
          <h3 className="font-semibold">{t("discovery.setup.purposeTitle")}</h3>
          <p className="mt-1 text-sm text-muted-foreground">{capability.purpose}</p>
        </div>
      </div>
      <div>
        <h3 className="font-semibold">{t("discovery.setup.dataBoundaryTitle")}</h3>
        <p className="mt-1 text-sm text-muted-foreground">{capability.data_handling}</p>
        <p className="mt-2 text-caption text-muted-foreground">
          {t("discovery.setup.requires")} {capability.permission} · {capability.execution} · {capability.edition}
        </p>
      </div>
    </section>
  );
}

function NetworkFields({
  form,
  kind,
  values,
  declaredScopes,
  scopesLoading,
  scopesError,
}: {
  form: ReturnType<typeof useForm<SetupValues>>;
  kind: "network" | "ssh";
  values: SetupValues;
  declaredScopes: DiscoverySegmentCoverage[];
  scopesLoading: boolean;
  scopesError: string | null;
}) {
  const { t } = useTranslation();
  const portPreset = kind === "ssh" ? "22" : "443, 8443";
  const selectedScope = declaredScopes.find((segment) => segment.name === values.segment.trim());
  const proposedDeclarations = scopeDeclarations(values);
  return (
    <div className="grid gap-4">
      <div className="grid gap-4 lg:grid-cols-2">
        <Field label={t("discovery.setup.scope")} description={t("discovery.setup.scopeDescription")} error={form.formState.errors.segment?.message} required>
          {(control) => <Input {...control} {...form.register("segment")} placeholder={examples.scope} />}
        </Field>
        <Field label={t("discovery.setup.relay")} description={t("discovery.setup.relayDescription")} error={form.formState.errors.relayAgentID?.message}>
          {(control) => <Input {...control} {...form.register("relayAgentID")} className="font-mono text-xs" placeholder={examples.agentID} />}
        </Field>
      </div>
      {scopesLoading ? (
        <p role="status" className="text-sm text-muted-foreground">
          {t("discovery.setup.scopesLoading")}
        </p>
      ) : null}
      {scopesError ? (
        <p role="status" className="rounded-control border border-status-warning/40 bg-status-warning/10 p-3 text-sm">
          {t("discovery.setup.scopesUnavailable")}
        </p>
      ) : null}
      {declaredScopes.length > 0 ? (
        <section aria-label={t("discovery.setup.existingScopes")} className="grid gap-2 rounded-panel border border-border p-4">
          <div>
            <h3 className="font-medium">{t("discovery.setup.existingScopes")}</h3>
            <p className="mt-1 text-sm text-muted-foreground">{t("discovery.setup.existingScopesDescription")}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {declaredScopes.map((segment) => (
              <Button
                key={segment.name}
                type="button"
                size="sm"
                variant={selectedScope?.name === segment.name ? "default" : "outline"}
                aria-pressed={selectedScope?.name === segment.name}
                onClick={() => form.setValue("segment", segment.name, { shouldDirty: true, shouldValidate: true })}
              >
                {segment.name}
              </Button>
            ))}
          </div>
          {selectedScope ? (
            <p className="text-caption text-muted-foreground">{t("discovery.setup.scopeBoundary", { boundary: selectedScope.ranges.join(", ") })}</p>
          ) : null}
        </section>
      ) : null}
      {values.segment.trim() && !selectedScope ? (
        <section role="note" className="rounded-panel border border-brand-accent/25 bg-brand-accent/5 p-4 text-sm">
          <strong>{t("discovery.setup.newScopeTitle", { scope: values.segment.trim() })}</strong>
          <p className="mt-1 text-muted-foreground">{t("discovery.setup.newScopeBody")}</p>
          <p className="mt-2 break-words font-mono text-xs text-muted-foreground">
            {proposedDeclarations.length > 0 ? proposedDeclarations.join(" · ") : t("discovery.setup.newScopeEmpty")}
          </p>
        </section>
      ) : null}
      <details className="rounded-panel border border-border p-4">
        <summary className="cursor-pointer font-medium">{t("discovery.setup.rangesAndExclusions")}</summary>
        <p className="mt-2 text-sm text-muted-foreground">{t("discovery.setup.rangesAndExclusionsDescription")}</p>
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <Field
            label={t("discovery.setup.ipRanges")}
            description={t("discovery.setup.ipRangesDescription")}
            error={form.formState.errors.addressRanges?.message}
          >
            {(control) => <Textarea {...control} {...form.register("addressRanges")} className="min-h-24 font-mono text-xs" />}
          </Field>
          <Field
            label={t("discovery.setup.excludedTargets")}
            description={t("discovery.setup.excludedTargetsDescription")}
            error={form.formState.errors.excludeTargets?.message}
          >
            {(control) => <Textarea {...control} {...form.register("excludeTargets")} className="min-h-24 font-mono text-xs" />}
          </Field>
          <Field label={t("discovery.setup.excludedCidrs")} error={form.formState.errors.excludeCIDRs?.message}>
            {(control) => <Textarea {...control} {...form.register("excludeCIDRs")} className="min-h-24 font-mono text-xs" />}
          </Field>
          <Field label={t("discovery.setup.excludedPorts")} error={form.formState.errors.excludePorts?.message}>
            {(control) => <Input {...control} {...form.register("excludePorts")} className="font-mono text-xs" placeholder="8080, 9000-9010" />}
          </Field>
        </div>
      </details>
      <div className="grid gap-4 lg:grid-cols-2">
        <Field label={t("discovery.setup.targets")} description={t("discovery.setup.targetsDescription")} error={form.formState.errors.targets?.message}>
          {(control) => (
            <Textarea
              {...control}
              {...form.register("targets")}
              className="min-h-28 font-mono text-xs"
              placeholder="api.example.com&#10;10.20.30.40"
            />
          )}
        </Field>
        <Field label={t("discovery.setup.cidrs")} description={t("discovery.setup.cidrsDescription")} error={form.formState.errors.cidrs?.message}>
          {(control) => <Textarea {...control} {...form.register("cidrs")} className="min-h-28 font-mono text-xs" placeholder="10.20.30.0/24" />}
        </Field>
      </div>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_16rem]">
        <Field label={t("discovery.setup.ports")} description={t("discovery.setup.portsDescription")} error={form.formState.errors.ports?.message} required>
          {(control) => <Input {...control} {...form.register("ports")} className="font-mono text-xs" placeholder={portPreset} />}
        </Field>
        <Field label={t("discovery.setup.safePreset")}>
          {(control) => (
            <Select
              {...control}
              defaultValue={kind === "ssh" ? "ssh" : "tls"}
              onChange={(event) =>
                form.setValue("ports", event.target.value === "ssh" ? "22" : event.target.value === "web" ? "443, 8443, 9443" : "443, 8443", {
                  shouldValidate: true,
                })
              }
            >
              <option value="tls">{t("discovery.setup.presetTls")}</option>
              <option value="web">{t("discovery.setup.presetWeb")}</option>
              <option value="ssh">{t("discovery.setup.presetSsh")}</option>
            </Select>
          )}
        </Field>
      </div>
      <label htmlFor="source-setup-rfc1918" className="flex items-start gap-3 text-sm">
        <Checkbox {...form.register("allowRFC1918")} id="source-setup-rfc1918" className="mt-0.5" />
        <span>
          <strong>{t("discovery.setup.allowRfc1918")}</strong>
          <span className="mt-0.5 block text-muted-foreground">{t("discovery.setup.allowRfc1918Description")}</span>
        </span>
      </label>
      <details className="rounded-panel border border-border p-4">
        <summary className="cursor-pointer font-medium">{t("discovery.setup.loopbackBoundary")}</summary>
        <label htmlFor="source-setup-loopback" className="mt-3 flex items-start gap-3 text-sm">
          <Checkbox {...form.register("allowLoopback")} id="source-setup-loopback" className="mt-0.5" />
          <span>
            <strong>{t("discovery.setup.allowLoopback")}</strong>
            <span className="mt-0.5 block text-muted-foreground">{t("discovery.setup.allowLoopbackDescription")}</span>
          </span>
        </label>
      </details>
    </div>
  );
}

function ADCSFields({ form }: { form: ReturnType<typeof useForm<SetupValues>> }) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Field label={t("discovery.setup.directoryUrl")} error={form.formState.errors.adcsURL?.message} required>
        {(control) => <Input {...control} {...form.register("adcsURL")} className="font-mono text-xs" />}
      </Field>
      <Field label={t("discovery.setup.relay")} error={form.formState.errors.relayAgentID?.message}>
        {(control) => <Input {...control} {...form.register("relayAgentID")} className="font-mono text-xs" placeholder={examples.agentID} />}
      </Field>
      <Field label={t("discovery.setup.configurationDn")} error={form.formState.errors.configurationDN?.message} required>
        {(control) => (
          <Input {...control} {...form.register("configurationDN")} className="font-mono text-xs" placeholder="CN=Configuration,DC=corp,DC=example" />
        )}
      </Field>
      <Field label={t("discovery.setup.bindIdentity")} error={form.formState.errors.bindDN?.message} required>
        {(control) => (
          <Input
            {...control}
            {...form.register("bindDN")}
            className="font-mono text-xs"
            placeholder="CN=trstctl-reader,OU=Service Accounts,DC=corp,DC=example"
          />
        )}
      </Field>
      <Field
        label={t("discovery.setup.passwordRef")}
        description={t("discovery.setup.passwordRefDescription")}
        error={form.formState.errors.passwordRef?.message}
        required
      >
        {(control) => <Input {...control} {...form.register("passwordRef")} className="font-mono text-xs" placeholder={examples.adcsPasswordRef} />}
      </Field>
      <details className="rounded-panel border border-border p-4 lg:col-span-2">
        <summary className="cursor-pointer font-medium">{t("discovery.setup.adcsAdvanced")}</summary>
        <div className="mt-4 grid gap-4">
          <Field
            label={t("discovery.setup.adcsEndpoints")}
            description={t("discovery.setup.adcsEndpointsDescription")}
            error={form.formState.errors.adcsEnrollmentEndpoints?.message}
          >
            {(control) => <Textarea {...control} {...form.register("adcsEnrollmentEndpoints")} className="min-h-24 font-mono text-xs" />}
          </Field>
          <label htmlFor="source-setup-adcs-private" className="flex items-start gap-3 text-sm">
            <Checkbox {...form.register("allowPrivateEndpoint")} id="source-setup-adcs-private" className="mt-0.5" />
            <span>
              <strong>{t("discovery.setup.allowPrivateEndpoint")}</strong>
              <span className="mt-0.5 block text-muted-foreground">{t("discovery.setup.allowPrivateEndpointDescription")}</span>
            </span>
          </label>
          {form.watch("allowPrivateEndpoint") ? (
            <Field label={t("discovery.setup.privateCidrs")} error={form.formState.errors.privateEgressCIDRs?.message} required>
              {(control) => <Textarea {...control} {...form.register("privateEgressCIDRs")} className="min-h-24 font-mono text-xs" />}
            </Field>
          ) : null}
        </div>
      </details>
    </div>
  );
}

function CloudFields({ form, providers }: { form: ReturnType<typeof useForm<SetupValues>>; providers: DiscoveryCapability["providers"] }) {
  const { t } = useTranslation();
  const provider = form.watch("provider");
  const isAWS = provider.startsWith("aws-");
  const isAzure = provider === "azure-keyvault" || provider === "azure-key-vault";
  const isGCP = provider.startsWith("gcp-");
  const isVault = provider === "hashicorp-vault";
  const providerContract = providers?.find((item) => item.id === provider);
  return (
    <div className="grid gap-4">
      <div className="grid gap-4 lg:grid-cols-2">
        <Field label={t("discovery.setup.provider")} description={providerContract?.least_privilege} error={form.formState.errors.provider?.message} required>
          {(control) => (
            <Select {...control} {...form.register("provider")}>
              {(providers ?? []).map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t("discovery.setup.endpoint")} description={t("discovery.setup.endpointDescription")} error={form.formState.errors.endpoint?.message}>
          {(control) => <Input {...control} {...form.register("endpoint")} className="font-mono text-xs" placeholder={examples.apiURL} />}
        </Field>
      </div>
      {providerContract ? (
        <p className="rounded-control border border-border bg-muted/30 p-3 text-sm">
          <strong>{t("discovery.setup.leastPrivilege")}</strong> {providerContract.least_privilege}
          <span className="mt-1 block text-muted-foreground">
            <strong>{t("discovery.setup.credentialPath")}</strong> {providerContract.preferred_credential}
          </span>
        </p>
      ) : null}
      {isAWS ? (
        <div className="grid gap-4 lg:grid-cols-2">
          <Field label={t("discovery.setup.region")} error={form.formState.errors.region?.message} required>
            {(control) => <Input {...control} {...form.register("region")} placeholder={examples.region} />}
          </Field>
          <div />
          <Field label={t("discovery.setup.accessKeyRef")} error={form.formState.errors.accessKeyIDRef?.message} required>
            {(control) => <Input {...control} {...form.register("accessKeyIDRef")} className="font-mono text-xs" placeholder={examples.awsAccessKeyRef} />}
          </Field>
          <Field label={t("discovery.setup.secretKeyRef")} error={form.formState.errors.secretAccessKeyRef?.message} required>
            {(control) => <Input {...control} {...form.register("secretAccessKeyRef")} className="font-mono text-xs" placeholder={examples.awsSecretKeyRef} />}
          </Field>
          <Field label={t("discovery.setup.sessionTokenRef")} error={form.formState.errors.sessionTokenRef?.message}>
            {(control) => <Input {...control} {...form.register("sessionTokenRef")} className="font-mono text-xs" placeholder={examples.awsSessionTokenRef} />}
          </Field>
          {form.watch("kind") !== "cloud_certificate" ? (
            <>
              <Field label={t("discovery.setup.tagKey")} error={form.formState.errors.tagKey?.message}>
                {(control) => <Input {...control} {...form.register("tagKey")} />}
              </Field>
              <Field label={t("discovery.setup.tagValue")} error={form.formState.errors.tagValue?.message}>
                {(control) => <Input {...control} {...form.register("tagValue")} />}
              </Field>
            </>
          ) : null}
        </div>
      ) : null}
      {isAzure || isVault ? (
        <Field label={isVault ? t("discovery.setup.vaultUrl") : t("discovery.setup.keyVaultUrl")} error={form.formState.errors.vaultURL?.message} required>
          {(control) => <Input {...control} {...form.register("vaultURL")} className="font-mono text-xs" placeholder={examples.vaultURL} />}
        </Field>
      ) : null}
      {isGCP ? (
        <div className="grid gap-4 lg:grid-cols-2">
          <Field label={t("discovery.setup.project")} error={form.formState.errors.project?.message} required>
            {(control) => <Input {...control} {...form.register("project")} />}
          </Field>
          {provider === "gcp-certmanager" ? (
            <Field label={t("discovery.setup.location")} error={form.formState.errors.location?.message} required>
              {(control) => <Input {...control} {...form.register("location")} placeholder={examples.gcpLocation} />}
            </Field>
          ) : null}
          {provider === "gcp-secret-manager" ? (
            <>
              <Field label={t("discovery.setup.labelKey")} error={form.formState.errors.labelKey?.message}>
                {(control) => <Input {...control} {...form.register("labelKey")} />}
              </Field>
              <Field label={t("discovery.setup.labelValue")} error={form.formState.errors.labelValue?.message}>
                {(control) => <Input {...control} {...form.register("labelValue")} />}
              </Field>
            </>
          ) : null}
        </div>
      ) : null}
      {!isAWS ? (
        <Field
          label={t("discovery.setup.tokenRef")}
          description={t("discovery.setup.tokenRefDescription")}
          error={form.formState.errors.tokenRef?.message}
          required
        >
          {(control) => <Input {...control} {...form.register("tokenRef")} className="font-mono text-xs" placeholder={examples.discoveryTokenRef} />}
        </Field>
      ) : null}
      {isVault ? (
        <div className="grid gap-4 lg:grid-cols-3">
          <Field label={t("discovery.setup.mount")} error={form.formState.errors.mount?.message} required>
            {(control) => <Input {...control} {...form.register("mount")} />}
          </Field>
          <Field label={t("discovery.setup.pathPrefix")} error={form.formState.errors.pathPrefix?.message}>
            {(control) => <Input {...control} {...form.register("pathPrefix")} />}
          </Field>
          <Field label={t("discovery.setup.apiVersion")} error={form.formState.errors.apiVersion?.message}>
            {(control) => <Input {...control} {...form.register("apiVersion")} />}
          </Field>
        </div>
      ) : null}
      <Field label={t("discovery.setup.namePrefix")} description={t("discovery.setup.namePrefixDescription")} error={form.formState.errors.namePrefix?.message}>
        {(control) => <Input {...control} {...form.register("namePrefix")} />}
      </Field>
      {form.watch("kind") === "cloud_secret" || form.watch("kind") === "secret_store" ? (
        <label
          htmlFor="source-setup-inspect-content"
          className="flex items-start gap-3 rounded-panel border border-risk-warning/35 bg-risk-warning/5 p-4 text-sm"
        >
          <Checkbox {...form.register("inspectContent")} id="source-setup-inspect-content" className="mt-0.5" />
          <span>
            <strong>{t("discovery.setup.inspectContent")}</strong>
            <span className="mt-0.5 block text-muted-foreground">{t("discovery.setup.inspectContentDescription")}</span>
          </span>
        </label>
      ) : null}
      <details className="rounded-panel border border-border p-4">
        <summary className="cursor-pointer font-medium">{t("discovery.setup.privateEndpointBoundary")}</summary>
        <label htmlFor="source-setup-cloud-private" className="mt-3 flex items-start gap-3 text-sm">
          <Checkbox {...form.register("allowPrivateEndpoint")} id="source-setup-cloud-private" className="mt-0.5" />
          <span>
            <strong>{t("discovery.setup.allowPrivateEndpoint")}</strong>
            <span className="mt-0.5 block text-muted-foreground">{t("discovery.setup.allowPrivateEndpointDescription")}</span>
          </span>
        </label>
        {form.watch("allowPrivateEndpoint") ? (
          <Field className="mt-4" label={t("discovery.setup.privateCidrs")} error={form.formState.errors.privateEgressCIDRs?.message} required>
            {(control) => <Textarea {...control} {...form.register("privateEgressCIDRs")} className="min-h-24 font-mono text-xs" />}
          </Field>
        ) : null}
      </details>
    </div>
  );
}

function requireField(ctx: z.RefinementCtx, value: string, path: keyof SetupValues, message: string) {
  if (!value.trim()) ctx.addIssue({ code: "custom", path: [path], message });
}

function parseADCSEndpoints(value: string): Array<{ enrollment_service: string; kind: string; url: string }> {
  if (!value.trim()) return [];
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line, index) => {
      const [enrollmentService, kind, url, ...extra] = line.split("|").map((part) => part.trim());
      if (extra.length || !enrollmentService || !kind || !url) {
        throw new Error(translateNow("discovery.setup.validation.adcsEndpointLine", { line: String(index + 1) }));
      }
      if (!["web_enrollment", "ndes", "ndes_admin"].includes(kind)) {
        throw new Error(translateNow("discovery.setup.validation.adcsEndpointKind", { line: String(index + 1) }));
      }
      try {
        const parsed = new URL(url);
        if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new Error("scheme");
      } catch {
        throw new Error(translateNow("discovery.setup.validation.adcsEndpointUrl", { line: String(index + 1) }));
      }
      return { enrollment_service: enrollmentService, kind, url };
    });
}

function splitList(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(/[\n,]+/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );
}

export function parsePorts(value: string): number[] {
  const out = new Set<number>();
  for (const token of splitList(value)) {
    const range = token.match(/^(\d+)-(\d+)$/);
    if (range) {
      const start = Number(range[1]);
      const end = Number(range[2]);
      if (start < 1 || end > 65535 || start > end || end - start > 255) {
        throw new Error(translateNow("discovery.setup.validation.portRange", { range: token }));
      }
      for (let port = start; port <= end; port += 1) out.add(port);
    } else {
      const port = Number(token);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(translateNow("discovery.setup.validation.port", { port: token }));
      }
      out.add(port);
    }
    if (out.size > 512) throw new Error(translateNow("discovery.setup.validation.portLimit"));
  }
  if (out.size === 0) throw new Error(translateNow("discovery.setup.validation.portRequired"));
  return [...out].sort((a, b) => a - b);
}

function normalizedTargets(values: SetupValues): string[] {
  const direct = splitList(values.targets);
  const ports = parsePorts(values.ports || (values.kind === "ssh" ? "22" : "443"));
  const out = new Set<string>();
  for (const target of direct) {
    if (/^\[[^\]]+\]:\d+$/.test(target) || /^[^:]+:\d+$/.test(target)) out.add(target);
    else for (const port of ports) out.add(target.includes(":") ? `[${target}]:${port}` : `${target}:${port}`);
  }
  return [...out];
}

/** scopeDeclarations turns the operator's plain target inputs into the durable
 * denominator that the server will enforce. Ports are intentionally removed:
 * a declared scope answers "which hosts and ranges are authorized", while the
 * source plan separately answers "which ports will this scan touch". */
export function scopeDeclarations(values: SetupValues): string[] {
  const declarations = new Set<string>();
  for (const raw of splitList(values.targets)) {
    const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(raw);
    if (bracketed) {
      declarations.add(bracketed[1]);
      continue;
    }
    const hostPort = /^([^:]+):\d+$/.exec(raw);
    declarations.add(hostPort ? hostPort[1] : raw);
  }
  for (const value of [...splitList(values.cidrs), ...splitList(values.addressRanges)]) declarations.add(value);
  return [...declarations];
}

function buildConfig(values: SetupValues): Record<string, unknown> {
  if (values.kind === "network" || values.kind === "ssh") {
    return compact({
      targets: normalizedTargets(values),
      cidrs: splitList(values.cidrs),
      ranges: splitList(values.addressRanges),
      ports: parsePorts(values.ports || (values.kind === "ssh" ? "22" : "443")),
      exclude_targets: splitList(values.excludeTargets),
      exclude_cidrs: splitList(values.excludeCIDRs),
      exclude_ports: values.excludePorts.trim() ? parsePorts(values.excludePorts) : [],
      segment: values.segment,
      relay_agent_id: values.relayAgentID,
      allow_rfc1918: values.allowRFC1918,
      allow_loopback: values.allowLoopback,
    });
  }
  if (values.kind === "adcs") {
    return compact({
      url: values.adcsURL,
      configuration_dn: values.configurationDN,
      bind_dn: values.bindDN,
      password_ref: values.passwordRef,
      relay_agent_id: values.relayAgentID,
      enrollment_endpoints: parseADCSEndpoints(values.adcsEnrollmentEndpoints),
      allow_private_endpoint: values.allowPrivateEndpoint,
      private_egress_cidrs: splitList(values.privateEgressCIDRs),
    });
  }
  const providerBase = compact({
    provider: values.provider,
    endpoint: values.endpoint,
    name_prefix: values.namePrefix,
    inspect_content: values.inspectContent,
    allow_private_endpoint: values.allowPrivateEndpoint,
    private_egress_cidrs: splitList(values.privateEgressCIDRs),
  });
  let provider: Record<string, unknown>;
  if (values.provider.startsWith("aws-")) {
    provider = compact({
      ...providerBase,
      region: values.region,
      access_key_id_ref: values.accessKeyIDRef,
      secret_access_key_ref: values.secretAccessKeyRef,
      session_token_ref: values.sessionTokenRef,
      tag_key: values.tagKey,
      tag_value: values.tagValue,
    });
  } else if (values.provider === "azure-keyvault" || values.provider === "azure-key-vault") {
    provider = compact({ ...providerBase, vault_url: values.vaultURL, token_ref: values.tokenRef });
  } else if (values.provider === "gcp-certmanager") {
    provider = compact({ ...providerBase, project: values.project, location: values.location, token_ref: values.tokenRef });
  } else if (values.provider === "gcp-secret-manager") {
    provider = compact({
      ...providerBase,
      project: values.project,
      token_ref: values.tokenRef,
      label_key: values.labelKey,
      label_value: values.labelValue,
    });
  } else if (values.provider === "hashicorp-vault") {
    provider = compact({
      ...providerBase,
      vault_url: values.vaultURL,
      token_ref: values.tokenRef,
      api_version: values.apiVersion,
      mount: values.mount,
      path_prefix: values.pathPrefix,
    });
  } else {
    provider = providerBase;
  }
  return { providers: [provider] };
}

function compact(input: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(input).filter(([, value]) => value !== "" && value !== false && (!Array.isArray(value) || value.length > 0)));
}

function redactConfig(config: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(
    JSON.stringify(config, (key, value) => (key.endsWith("_ref") && typeof value === "string" ? `${value.split(":")[0] || "reference"}:…` : value)),
  ) as Record<string, unknown>;
}

function previewItems(preview: DiscoveryPlanPreview | null): Array<{ label: string; value: string }> {
  if (!preview) return [];
  return [
    { label: translateNow("discovery.setup.preview.connectionOrigin"), value: preview.connection_origin },
    { label: translateNow("discovery.setup.preview.normalizedTargets"), value: String(preview.normalized_target_count) },
    { label: translateNow("discovery.setup.preview.excludedTargets"), value: String(preview.excluded_target_count) },
    {
      label: translateNow("discovery.setup.preview.boundedExecution"),
      value: translateNow("discovery.setup.preview.boundedExecutionValue", {
        workers: String(preview.concurrency || 1),
        queue: String(preview.queue_depth || 0),
        seconds: String(preview.estimated_upper_seconds),
      }),
    },
    { label: translateNow("discovery.setup.preview.scope"), value: preview.segment || translateNow("discovery.setup.preview.providerScope") },
    { label: translateNow("discovery.setup.preview.permission"), value: preview.permission },
    { label: translateNow("discovery.setup.preview.childJobs"), value: String(preview.child_job_count) },
    {
      label: translateNow("discovery.setup.preview.externalEffects"),
      value: preview.side_effects
        ? translateNow("discovery.setup.preview.externalEffectsPresent")
        : translateNow("discovery.setup.preview.externalEffectsNone"),
    },
  ];
}

// SPDX-License-Identifier: BUSL-1.1

import { lazy, Suspense, useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useAuth } from "@/auth/AuthProvider";
import { translateNow } from "@/i18n/I18nProvider";
import { api } from "@/lib/api";
import type { EdgeDelegationList, EdgeSegmentPolicyInput, EdgeSegmentPolicyList } from "@/lib/api-types.gen";
import { hasPermission } from "@/lib/access";
import { newIdempotencyKey } from "@/lib/apiTransport";
import { useApiQuery, useQueryClient } from "@/lib/query";

const certificatePEM = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const keyProviders = ["tpm2", "pkcs11", "software"] as const;
const EdgeDelegationActions = lazy(() => import("./EdgeDelegationActions").then((module) => ({ default: module.EdgeDelegationActions })));
const setupSchema = z
  .object({
    mode: z.enum(["existing", "declare"]),
    segmentID: z.string().trim(),
    segmentName: z.string().trim(),
    segmentRange: z.string().trim(),
    enabled: z.boolean(),
    rootPEM: z.string().trim(),
    permittedDomains: z.string().trim(),
    excludedDomains: z.string().trim(),
    providers: z.array(z.enum(keyProviders)).min(1),
  })
  .superRefine((values, context) => {
    if (values.mode === "existing" && !z.string().uuid().safeParse(values.segmentID).success) {
      context.addIssue({ code: "custom", path: ["segmentID"], message: translateNow("edge.setup.segmentIdError") });
    }
    if (values.mode === "declare" && (!values.segmentName || !values.segmentRange)) {
      context.addIssue({ code: "custom", path: ["segmentName"], message: translateNow("edge.setup.declarationError") });
    }
    if (!values.enabled) return;
    const roots = values.rootPEM.match(certificatePEM) ?? [];
    if (!roots.length || values.rootPEM.replace(certificatePEM, "").trim()) {
      context.addIssue({ code: "custom", path: ["rootPEM"], message: translateNow("edge.setup.rootError") });
    }
    if (!values.permittedDomains.split(",").some((domain) => domain.trim())) {
      context.addIssue({ code: "custom", path: ["permittedDomains"], message: translateNow("edge.setup.domainError") });
    }
  });

type SetupValues = z.infer<typeof setupSchema>;
type ReviewedSetup = { values: SetupValues; input: EdgeSegmentPolicyInput; declarationKey: string; policyKey: string };

function splitDomains(value: string): string[] {
  return value
    .split(",")
    .map((domain) => domain.trim())
    .filter(Boolean);
}

function policyInput(values: SetupValues): EdgeSegmentPolicyInput {
  return {
    enabled: values.enabled,
    attestation_roots_pem: values.enabled ? (values.rootPEM.match(certificatePEM) ?? []).map((root) => root.trim()) : [],
    permitted_dns_domains: values.enabled ? splitDomains(values.permittedDomains) : [],
    excluded_dns_domains: values.enabled ? splitDomains(values.excludedDomains) : [],
    allowed_key_providers: values.providers,
  };
}

// B6: the constrained edge sub-CA, shown for what it is — the one deliberate
// exception to signing living only in the isolated signer, bounded hard.
//
// The panel leads with the BOUNDS: which segments opted in (off by default),
// what attestation roots vouch for their hosts, and the name constraints and
// expiry each delegation carries in its certificate. One honesty rule shapes
// the copy: issuances made while a host is unreachable are INVISIBLE until its
// journal reconciles, so an empty issuance list is not evidence of an idle CA
// — and the panel says so instead of letting silence read as inactivity.
export function EdgeDelegationsPanel() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const policyQuery = useApiQuery(["edge-segment-policies"], api.edgeSegmentPolicies);
  const delegationQuery = useApiQuery(["edge-delegations"], api.edgeDelegations);
  const policies = policyQuery.data;
  const delegations = delegationQuery.data;
  const unavailable = policyQuery.error || delegationQuery.error;
  const canConfigure = hasPermission(user, "issuers:write");
  const canDeclare = hasPermission(user, "discovery:write");
  const [open, setOpen] = useState(false);
  const [actionsOpen, setActionsOpen] = useState(false);
  const [reviewed, setReviewed] = useState<ReviewedSetup | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const form = useForm<SetupValues>({
    resolver: zodResolver(setupSchema),
    defaultValues: {
      mode: "existing",
      segmentID: "",
      segmentName: "",
      segmentRange: "",
      enabled: true,
      rootPEM: "",
      permittedDomains: "",
      excludedDomains: "",
      providers: ["tpm2"],
    },
  });
  const mode = useWatch({ control: form.control, name: "mode" });
  const enabled = useWatch({ control: form.control, name: "enabled" });

  function changePolicy(policy: EdgeSegmentPolicyList["items"][number]) {
    form.reset({
      mode: "existing",
      segmentID: policy.segment_id,
      segmentName: "",
      segmentRange: "",
      enabled: policy.enabled,
      rootPEM: "",
      permittedDomains: (policy.permitted_dns_domains ?? []).join(", "),
      excludedDomains: (policy.excluded_dns_domains ?? []).join(", "),
      providers: policy.allowed_key_providers,
    });
    setReviewed(null);
    setSaveError(null);
    setOpen(true);
  }

  async function saveReviewed() {
    if (!reviewed || busy) return;
    setBusy(true);
    setSaveError(null);
    try {
      const segmentID =
        reviewed.values.mode === "existing"
          ? reviewed.values.segmentID
          : (
              await api.createDiscoverySegment(
                {
                  name: reviewed.values.segmentName,
                  ranges: [reviewed.values.segmentRange],
                  staleness_hours: 168,
                },
                reviewed.declarationKey,
              )
            ).id;
      const saved = await api.setEdgeSegmentPolicy(segmentID, reviewed.input, reviewed.policyKey);
      queryClient.setQueryData<EdgeSegmentPolicyList>(["edge-segment-policies"], (previous) => ({
        items: [...(previous?.items ?? []).filter((item) => item.segment_id !== saved.segment_id), saved],
        guidance: previous?.guidance ?? "",
      }));
      void queryClient.invalidateQueries({ queryKey: ["edge-segment-policies"] });
      setNotice(translateNow("edge.setup.saved"));
      setReviewed(null);
      setOpen(false);
      form.reset();
    } catch (error) {
      // Keep both keys and the exact reviewed payload. A lost response must not
      // declare another segment or widen a policy on Retry.
      setSaveError(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="ui-panel p-comfortable" aria-labelledby="edge-delegations-heading">
      <h2 id="edge-delegations-heading" className="text-title font-semibold">
        {translateNow("source.edge.delegations.b6edge00001")}
      </h2>
      {canConfigure ? (
        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            className="rounded-md border border-border px-3 py-2 text-caption"
            onClick={() => {
              setOpen(true);
              setNotice(null);
            }}
          >
            {translateNow("edge.setup.configure")}
          </button>
          <button type="button" className="rounded-md border border-border px-3 py-2 text-caption" onClick={() => setActionsOpen(true)}>
            {translateNow("edge.actions.mint")}
          </button>
        </div>
      ) : null}
      {actionsOpen && canConfigure && policies && delegations ? (
        <Suspense fallback={<p className="mt-3 text-caption">{translateNow("source.loading.4f9d1e0e3a")}</p>}>
          <EdgeDelegationActions
            policies={policies.items ?? []}
            delegations={delegations.items ?? []}
            onClose={() => setActionsOpen(false)}
            onChanged={() => {
              void queryClient.invalidateQueries({ queryKey: ["edge-delegations"] });
              void queryClient.invalidateQueries({ queryKey: ["edge-segment-policies"] });
            }}
          />
        </Suspense>
      ) : null}
      {notice ? (
        <p role="status" className="mt-2 text-caption">
          {notice}
        </p>
      ) : null}
      {open && canConfigure ? (
        <div className="mt-4 rounded-lg border border-border p-comfortable">
          {reviewed ? (
            <div>
              <h3 className="text-title font-semibold">{translateNow("edge.setup.reviewTitle")}</h3>
              <dl className="mt-2 grid gap-2 text-caption">
                <div>
                  <dt>{translateNow("edge.setup.scope")}</dt>
                  <dd>
                    {reviewed.values.mode === "existing" ? (
                      reviewed.values.segmentID
                    ) : (
                      <>
                        <span>{reviewed.values.segmentName}</span>
                        <span aria-hidden="true"> · </span>
                        <span>{reviewed.values.segmentRange}</span>
                      </>
                    )}
                  </dd>
                </div>
                <div>
                  <dt>{translateNow("source.edge.enabled.b6edge00011")}</dt>
                  <dd>{reviewed.input.enabled ? translateNow("source.edge.on.b6edge00016") : translateNow("source.edge.off.b6edge00017")}</dd>
                </div>
                <div>
                  <dt>{translateNow("edge.setup.domains")}</dt>
                  <dd>{(reviewed.input.permitted_dns_domains ?? []).join(", ")}</dd>
                </div>
                <div>
                  <dt>{translateNow("edge.setup.excluded")}</dt>
                  <dd>{(reviewed.input.excluded_dns_domains ?? []).join(", ") || "—"}</dd>
                </div>
                <div>
                  <dt>{translateNow("edge.setup.providers")}</dt>
                  <dd>{(reviewed.input.allowed_key_providers ?? []).join(", ")}</dd>
                </div>
                <div>
                  <dt>{translateNow("edge.setup.root")}</dt>
                  <dd>
                    <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all">{(reviewed.input.attestation_roots_pem ?? []).join("\n")}</pre>
                  </dd>
                </div>
              </dl>
              {saveError ? (
                <p role="alert" className="mt-2 text-caption text-status-danger">
                  {saveError}
                </p>
              ) : null}
              <div className="mt-3 flex gap-2">
                <button type="button" className="rounded-md border border-border px-3 py-2 text-caption" onClick={() => setReviewed(null)} disabled={busy}>
                  {translateNow("edge.setup.edit")}
                </button>
                <button
                  type="button"
                  className="rounded-md bg-primary px-3 py-2 text-caption text-primary-foreground"
                  onClick={() => void saveReviewed()}
                  disabled={busy}
                >
                  {translateNow("edge.setup.save")}
                </button>
              </div>
            </div>
          ) : (
            <form
              onSubmit={form.handleSubmit((values) => {
                setReviewed({ values, input: policyInput(values), declarationKey: newIdempotencyKey(), policyKey: newIdempotencyKey() });
                setSaveError(null);
              })}
              className="grid gap-3 text-caption"
            >
              <h3 className="text-title font-semibold">{translateNow("edge.setup.configure")}</h3>
              <label htmlFor="edge-segment-mode">{translateNow("edge.setup.mode")}</label>
              <select id="edge-segment-mode" {...form.register("mode")} className="rounded-md border border-border p-2">
                <option value="existing">{translateNow("edge.setup.existing")}</option>
                {canDeclare ? <option value="declare">{translateNow("edge.setup.declare")}</option> : null}
              </select>
              {mode === "existing" ? (
                <>
                  <label htmlFor="edge-segment-id">{translateNow("edge.setup.segmentID")}</label>
                  <input id="edge-segment-id" {...form.register("segmentID")} className="rounded-md border border-border p-2" />
                  {form.formState.errors.segmentID ? <span role="alert">{form.formState.errors.segmentID.message}</span> : null}
                </>
              ) : (
                <>
                  <label htmlFor="edge-segment-name">{translateNow("edge.setup.segmentName")}</label>
                  <input id="edge-segment-name" {...form.register("segmentName")} className="rounded-md border border-border p-2" />
                  {form.formState.errors.segmentName ? <span role="alert">{form.formState.errors.segmentName.message}</span> : null}
                  <label htmlFor="edge-segment-range">{translateNow("edge.setup.segmentRange")}</label>
                  <input id="edge-segment-range" {...form.register("segmentRange")} className="rounded-md border border-border p-2" />
                </>
              )}
              <label className="flex items-center gap-2">
                <input type="checkbox" {...form.register("enabled")} />
                {translateNow("edge.setup.enable")}
              </label>
              {enabled ? (
                <>
                  <label htmlFor="edge-root-pem">{translateNow("edge.setup.root")}</label>
                  <textarea id="edge-root-pem" {...form.register("rootPEM")} rows={5} className="rounded-md border border-border p-2 font-mono text-xs" />
                  {form.formState.errors.rootPEM ? <span role="alert">{form.formState.errors.rootPEM.message}</span> : null}
                  <label htmlFor="edge-domains">{translateNow("edge.setup.domains")}</label>
                  <input id="edge-domains" {...form.register("permittedDomains")} className="rounded-md border border-border p-2" />
                  {form.formState.errors.permittedDomains ? <span role="alert">{form.formState.errors.permittedDomains.message}</span> : null}
                  <label htmlFor="edge-excluded">{translateNow("edge.setup.excluded")}</label>
                  <input id="edge-excluded" {...form.register("excludedDomains")} className="rounded-md border border-border p-2" />
                </>
              ) : null}
              <fieldset className="flex flex-wrap gap-3">
                <legend>{translateNow("edge.setup.providers")}</legend>
                {keyProviders.map((provider) => (
                  <label key={provider} className="flex items-center gap-1">
                    <input type="checkbox" value={provider} {...form.register("providers")} />
                    {provider}
                  </label>
                ))}
              </fieldset>
              <p className="text-muted-foreground">{translateNow("edge.setup.custodyWarning")}</p>
              {mode === "existing" && enabled ? <p className="text-muted-foreground">{translateNow("edge.setup.rootReentry")}</p> : null}
              <div className="flex gap-2">
                <button type="button" className="rounded-md border border-border px-3 py-2" onClick={() => setOpen(false)}>
                  {translateNow("edge.setup.cancel")}
                </button>
                <button type="submit" className="rounded-md bg-primary px-3 py-2 text-primary-foreground">
                  {translateNow("edge.setup.review")}
                </button>
              </div>
            </form>
          )}
        </div>
      ) : null}
      {unavailable ? (
        <p className="mt-2 max-w-3xl text-caption text-muted-foreground">{translateNow("source.edge.unavailable.b6edge00002")}</p>
      ) : !policies || !delegations ? (
        <p className="mt-2 text-caption text-muted-foreground">{translateNow("source.loading.4f9d1e0e3a")}</p>
      ) : (policies.items ?? []).length === 0 && (delegations.items ?? []).length === 0 ? (
        <p className="mt-2 max-w-3xl text-caption text-muted-foreground">{translateNow("source.edge.none.b6edge00003")}</p>
      ) : (
        <>
          {(policies.items ?? []).length > 0 ? (
            <div className="mt-4 overflow-x-auto">
              <h3 className="text-caption font-medium text-muted-foreground">{translateNow("source.edge.segments.b6edge00004")}</h3>
              <table className="mt-2 w-full text-caption">
                <thead>
                  <tr className="text-left text-muted-foreground">
                    <th className="pr-4 font-medium">{translateNow("source.edge.segment.b6edge00010")}</th>
                    <th className="pr-4 font-medium">{translateNow("source.edge.enabled.b6edge00011")}</th>
                    <th className="pr-4 font-medium">{translateNow("source.edge.attestation.roots.b6edge00012")}</th>
                    <th className="pr-4 font-medium">{translateNow("source.edge.allowed.custody.aud2600018")}</th>
                    <th className="pr-4 font-medium">{translateNow("source.edge.constraints.b6edge00007")}</th>
                  </tr>
                </thead>
                <tbody>
                  {(policies.items ?? []).map((p) => (
                    <tr key={p.segment_id} className="border-t border-border/60">
                      <td className="py-1 pr-4">
                        <span>{p.segment_name || p.segment_id}</span>
                        {p.segment_name ? <span className="block font-mono text-xs text-muted-foreground">{p.segment_id}</span> : null}
                        {canConfigure ? (
                          <button type="button" className="mt-1 underline" onClick={() => changePolicy(p)}>
                            {translateNow("edge.setup.change")}
                          </button>
                        ) : null}
                      </td>
                      <td className="py-1 pr-4">{p.enabled ? translateNow("source.edge.on.b6edge00016") : translateNow("source.edge.off.b6edge00017")}</td>
                      <td className="py-1 pr-4 tabular-nums">{p.attestation_roots}</td>
                      <td className="py-1 pr-4 font-mono text-xs">{(p.allowed_key_providers ?? ["tpm2"]).join(", ")}</td>
                      <td className="py-1 pr-4 font-mono text-xs">
                        {(p.permitted_dns_domains ?? []).join(", ")}
                        {(p.excluded_dns_domains ?? []).length > 0 ? (
                          <>
                            {" "}
                            {translateNow("source.edge.excluding.b6edge00013")} {(p.excluded_dns_domains ?? []).join(", ")}
                          </>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
          {(delegations.items ?? []).length > 0 ? (
            <div className="mt-4 overflow-x-auto">
              <h3 className="text-caption font-medium text-muted-foreground">{translateNow("source.edge.live.b6edge00005")}</h3>
              <table className="mt-2 w-full text-caption">
                <thead>
                  <tr className="text-left text-muted-foreground">
                    <th className="pr-4 font-medium">{translateNow("source.edge.host.b6edge00006")}</th>
                    <th className="pr-4 font-medium">{translateNow("source.edge.segment.b6edge00010")}</th>
                    <th className="pr-4 font-medium">{translateNow("source.edge.status.b6edge00008")}</th>
                    <th className="pr-4 font-medium">{translateNow("source.edge.constraints.b6edge00007")}</th>
                    <th className="pr-4 font-medium">{translateNow("source.edge.expires.b6edge00009")}</th>
                    <th className="pr-4 font-medium">{translateNow("source.edge.custody.aud2600019")}</th>
                    <th className="pr-4 font-medium">{translateNow("source.edge.assurance.aud2600020")}</th>
                  </tr>
                </thead>
                <tbody>
                  {(delegations.items ?? []).map((d) => (
                    <tr key={d.id} className="border-t border-border/60">
                      <td className="py-1 pr-4">{d.host}</td>
                      <td className="py-1 pr-4">{d.segment_id}</td>
                      <td
                        className={
                          d.status === "active" ? "py-1 pr-4" : d.status === "revoked" ? "py-1 pr-4 text-status-danger" : "py-1 pr-4 text-status-warning"
                        }
                      >
                        {d.status}
                      </td>
                      <td className="py-1 pr-4 font-mono text-xs">{(d.permitted_dns_domains ?? []).join(", ")}</td>
                      <td className="py-1 pr-4 tabular-nums">{new Date(d.not_after).toISOString().slice(0, 10)}</td>
                      <td className="py-1 pr-4 font-mono text-xs">
                        {d.key_provider} · {d.key_storage} ·{" "}
                        {d.key_exportable ? translateNow("source.edge.exportable.aud2600021") : translateNow("source.edge.nonexportable.aud2600022")}
                      </td>
                      <td className="py-1 pr-4">{edgeCustodyAssuranceLabel(d.custody_assurance)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
          <p className="mt-3 max-w-3xl text-xs text-muted-foreground">{translateNow("source.edge.reconcile.note.b6edge00015")}</p>
        </>
      )}
    </section>
  );
}

export function edgeCustodyAssuranceLabel(value: EdgeDelegationList["items"][number]["custody_assurance"]): string {
  switch (value) {
    case "hardware_key_attested":
      return translateNow("source.edge.assurance.hardware.aud2600023");
    case "host_attested_operator_claim":
      return translateNow("source.edge.assurance.operator.claim.aud2600024");
    case "host_attested_software_exception":
      return translateNow("source.edge.assurance.software.exception.aud2600025");
  }
}

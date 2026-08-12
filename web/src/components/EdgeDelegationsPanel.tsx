// SPDX-License-Identifier: MPL-2.0

import { useEffect, useState } from "react";
import { translateNow } from "@/i18n/I18nProvider";
import { api } from "@/lib/api";
import type { EdgeDelegationList, EdgeSegmentPolicyList } from "@/lib/api-types.gen";

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
  const [policies, setPolicies] = useState<EdgeSegmentPolicyList | null>(null);
  const [delegations, setDelegations] = useState<EdgeDelegationList | null>(null);
  const [unavailable, setUnavailable] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    Promise.all([api.edgeSegmentPolicies(), api.edgeDelegations()])
      .then(([p, d]) => {
        if (active) {
          setPolicies(p);
          setDelegations(d);
          setUnavailable(null);
        }
      })
      .catch((err) => {
        if (active) setUnavailable(err instanceof Error ? err.message : String(err));
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <section className="ui-panel p-comfortable" aria-labelledby="edge-delegations-heading">
      <h2 id="edge-delegations-heading" className="text-title font-semibold">
        {translateNow("source.edge.delegations.b6edge00001")}
      </h2>
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
                      <td className="py-1 pr-4">{p.segment_name || p.segment_id}</td>
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

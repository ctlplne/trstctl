// SPDX-License-Identifier: MPL-2.0

import { useEffect, useState } from "react";
import { optionalApiCall } from "@/lib/optionalApi";
import { translateNow } from "@/i18n/I18nProvider";
import { type CryptoReadiness } from "@/lib/api";

// M2: sequence the crypto migration by dependency, not by severity alone.
//
// The CBOM already says which algorithms are weak. It cannot say which change is
// hard. Ordered by severity alone, a forgotten lab box exhibiting RSA-1024
// outranks a load balancer twelve services authenticate through — and the
// migration gets planned in the wrong order by a table that looked
// authoritative.
//
// The rows here are ordered urgent-first, then by how many parties actually
// depend on the asset, and every dependent names the resource it was reached
// through so a recommendation can be checked rather than trusted.
//
// The panel never says "safe". Dependents are what DISCOVERY HAS OBSERVED, so an
// asset with zero of them renders identically to one sitting on a resource
// nothing has scanned. Calling the first case safe would turn a coverage gap
// into a green light.
function readCryptoReadiness(): Promise<CryptoReadiness> {
  return optionalApiCall<CryptoReadiness>("cryptoReadiness", { items: [], unlocated: 0, urgent: 0, guidance: "" });
}

export function CryptoReadinessPanel() {
  const [data, setData] = useState<CryptoReadiness | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Guard the ARRAY, not just the object — the same lesson the unowned queue
  // learned. A response whose shape is present but whose items are absent is
  // exactly what a fixture or a partial payload looks like, and reading .length
  // on it takes down the whole page rather than hiding one panel.
  const items = data?.items ?? [];

  useEffect(() => {
    let active = true;
    readCryptoReadiness()
      .then((r) => {
        if (active) {
          setData(r);
          setError(null);
        }
      })
      .catch((err) => {
        if (active) setError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <section className="ui-panel p-comfortable" aria-labelledby="crypto-readiness-heading">
      <h2 id="crypto-readiness-heading" className="text-title font-semibold">
        {translateNow("source.crypto.readiness.m2seq00001")}
      </h2>
      {error ? (
        <p className="mt-2 text-caption text-status-danger">{error}</p>
      ) : !data ? (
        <p className="mt-2 text-caption text-muted-foreground">{translateNow("source.loading.4f9d1e0e3a")}</p>
      ) : (
        <>
          <dl className="mt-4 grid gap-4 sm:grid-cols-3">
            <div>
              <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.crypto.assets.m2seq00002")}</dt>
              <dd className="text-title font-semibold tabular-nums">{items.length}</dd>
            </div>
            <div>
              <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.urgent.m2seq00003")}</dt>
              <dd className={(data.urgent ?? 0) > 0 ? "text-title font-semibold tabular-nums text-status-danger" : "text-title font-semibold tabular-nums"}>
                {data.urgent ?? 0}
              </dd>
            </div>
            <div>
              <dt className="text-caption font-medium text-muted-foreground">{translateNow("source.unplaceable.m2seq00004")}</dt>
              {/* Its own number, never folded into a total. A usage the CBOM
                  could not place has no computable blast radius; absorbing it
                  would read as coverage the table does not have. */}
              <dd className={(data.unlocated ?? 0) > 0 ? "text-title font-semibold tabular-nums text-status-warning" : "text-title font-semibold tabular-nums"}>
                {data.unlocated ?? 0}
              </dd>
            </div>
          </dl>

          {items.length > 0 ? (
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-caption">
                <thead>
                  <tr>
                    <th scope="col">{translateNow("source.crypto.asset.m2seq00005")}</th>
                    <th scope="col">{translateNow("source.dependents.m2seq00006")}</th>
                    <th scope="col">{translateNow("source.owners.m2seq00007")}</th>
                    <th scope="col">{translateNow("source.sequencing.m2seq00008")}</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((row) => (
                    <tr key={row.asset.id}>
                      <td className="max-w-[14rem]">
                        <span className={row.quantum_vulnerable || row.out_of_policy ? "font-medium text-status-danger" : "font-medium"}>{row.asset.name}</span>
                        {row.unlocated ? (
                          <span className="mt-1 block text-xs text-status-warning">{translateNow("source.no.location.m2seq00009")}</span>
                        ) : (
                          <span className="mt-1 block text-xs text-muted-foreground">{(row.exhibitors ?? []).map((e) => e.name).join(", ")}</span>
                        )}
                      </td>
                      <td className="tabular-nums align-top">
                        {(row.dependents ?? []).length}
                        {/* Each dependent names the resource it was reached
                            through — a sequencing claim nobody can check is one
                            nobody should act on. */}
                        {(row.dependents ?? []).length > 0 ? (
                          <ul className="mt-1 list-disc pl-4 text-xs text-muted-foreground">
                            {(row.dependents ?? []).slice(0, 4).map((d) => (
                              <li key={d.node.id}>
                                {d.node.name}{" "}
                                <span className="opacity-70">{translateNow("source.crypto.readiness.via.m2crp00001", { value1: d.via.name })}</span>
                              </li>
                            ))}
                          </ul>
                        ) : null}
                      </td>
                      <td className="align-top text-xs text-muted-foreground">{(row.owners ?? []).join(", ") || "—"}</td>
                      <td className="max-w-[26rem] align-top text-xs text-muted-foreground">{row.recommendation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
          <p className="mt-4 max-w-3xl text-xs text-muted-foreground">{data.guidance}</p>
        </>
      )}
    </section>
  );
}

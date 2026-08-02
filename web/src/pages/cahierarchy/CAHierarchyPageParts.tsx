import { StatusBadge } from "@/components/StatusBadge";
import { translateNow } from "@/i18n/I18nProvider";
import type { CAAuthority } from "@/lib/api";

// S-C12 (extracted per R-09 before editing the CAHierarchy monolith): the
// authorities list showed `parent_id` as an opaque uuid in a detail field, so
// reconstructing "what signs what" meant matching ids by eye across rows. The
// served list already carries the whole tree; this renders it as one.

export type CALineageNode = { authority: CAAuthority; depth: number; children: CALineageNode[] };

/** Build the forest. Roots are authorities with no parent — plus any whose
 * parent is not in the served page, which would otherwise vanish from the
 * tree entirely (a missing ancestor must not hide a live CA). */
export function buildCALineage(authorities: CAAuthority[]): CALineageNode[] {
  const byID = new Map(authorities.map((authority) => [authority.id, authority]));
  const childrenOf = new Map<string, CAAuthority[]>();
  const roots: CAAuthority[] = [];

  for (const authority of authorities) {
    const parent = authority.parent_id;
    if (!parent || !byID.has(parent)) {
      roots.push(authority);
      continue;
    }
    childrenOf.set(parent, [...(childrenOf.get(parent) ?? []), authority]);
  }

  const seen = new Set<string>();
  const build = (authority: CAAuthority, depth: number): CALineageNode => {
    // A cycle would otherwise recurse forever; a CA that already appeared is
    // rendered as a leaf rather than trusted to terminate.
    seen.add(authority.id);
    const children = (childrenOf.get(authority.id) ?? []).filter((child) => !seen.has(child.id)).map((child) => build(child, depth + 1));
    return { authority, depth, children };
  };

  const forest = roots.map((root) => build(root, 0));
  // A pure cycle (a → b → a) has no root at all, so nothing above would reach
  // it. Surface those authorities at the top level rather than losing them:
  // never hide a live CA because its parent data is malformed.
  for (const authority of authorities) {
    if (!seen.has(authority.id)) forest.push(build(authority, 0));
  }
  return forest;
}

/** Flatten for rendering while keeping depth, so the tree is a list with
 * indentation rather than nested scroll containers. */
export function flattenCALineage(nodes: CALineageNode[]): CALineageNode[] {
  return nodes.flatMap((node) => [node, ...flattenCALineage(node.children)]);
}

export function isOfflineRoot(authority: CAAuthority): boolean {
  const kind = (authority.kind ?? "").toLowerCase();
  return kind.includes("offline");
}

export function CALineageTree({ authorities }: { authorities: CAAuthority[] }) {
  const rows = flattenCALineage(buildCALineage(authorities));
  if (rows.length === 0) return null;
  return (
    <ul aria-label={translateNow("ca.lineage.label")} className="grid gap-1">
      {rows.map(({ authority, depth }) => (
        <li
          key={authority.id}
          className="flex flex-wrap items-center gap-2 rounded-panel border border-border px-3 py-2 text-sm"
          style={{ marginInlineStart: `${depth * 1.25}rem` }}
        >
          {depth > 0 ? (
            <span aria-hidden="true" className="text-muted-foreground">
              └
            </span>
          ) : null}
          <span className="font-medium">{authority.common_name}</span>
          <StatusBadge vocabulary="lifecycle" value={authority.status || "unknown"} />
          {isOfflineRoot(authority) ? (
            <StatusBadge vocabulary="lifecycle" value="offline_root" label={translateNow("ca.lineage.offlineRoot")} tone="neutral" />
          ) : null}
          {depth === 0 ? <span className="text-caption text-muted-foreground">{translateNow("ca.lineage.root")}</span> : null}
          <span className="break-all font-mono text-xs text-muted-foreground">{authority.id}</span>
        </li>
      ))}
    </ul>
  );
}

// H5 (the CA calendar): the authorities list printed `not_after` as a raw string
// and the health language called anything more than 90 days out "healthy" — the
// leaf yardstick. That reads a root expiring in 30 months as fine, which is the
// one case where it is already late to start, because replacing a trust anchor
// means distributing it to every relying party first.
//
// The served authority now carries its horizon (band, months left, renew-by,
// and whether leaves are already being truncated). These render it.

/** Tone for a horizon band. Severity is computed server-side from runway, so the
 * console maps it rather than re-deciding what "healthy" means. */
function horizonTone(horizon: NonNullable<CAAuthority["horizon"]>): "critical" | "warning" | "info" | "success" {
  if (horizon.expired || horizon.severity === "critical") return "critical";
  if (horizon.validity_compressed || horizon.severity === "warning") return "warning";
  if (horizon.band_months != null) return "info";
  return "success";
}

/** Short band label: "3 mo", "24 mo", "Expired", or "Beyond planning horizon"
 * for an authority further out than the widest alerting band. */
export function caHorizonLabel(horizon: NonNullable<CAAuthority["horizon"]>): string {
  if (horizon.expired) return translateNow("source.expired.424a2551d3");
  if (horizon.band_months == null) return translateNow("source.beyond.planning.horizon.99e839df1f");
  return `${horizon.months_remaining} / ${horizon.band_months} mo`;
}

/** The horizon band as a badge. An authority with no recorded expiry says so
 * rather than being rendered as healthy — an unknown expiry is a real state. */
export function CAHorizonBadge({ authority }: { authority: CAAuthority }) {
  const horizon = authority.horizon;
  if (!horizon) {
    return <span className="text-xs text-muted-foreground">{translateNow("source.no.recorded.expiry.0511b89b6b")}</span>;
  }
  return (
    <div className="grid gap-1">
      <StatusBadge value={horizon.band_months != null ? `${horizon.band_months}mo` : "planning"} label={caHorizonLabel(horizon)} tone={horizonTone(horizon)} />
      {horizon.validity_compressed ? (
        <span className="text-2xs text-status-warning">{translateNow("source.leaves.are.being.truncated.to.this.authori.db6d7cf6b7")}</span>
      ) : null}
    </div>
  );
}

/** The renew-by date, i.e. when leaves under this authority stop getting their
 * full validity. Stated with the leaf validity it assumes, so the date means
 * something. */
export function CAHorizonRenewBy({ authority }: { authority: CAAuthority }) {
  const horizon = authority.horizon;
  if (!horizon?.renew_by) return <span className="text-muted-foreground">-</span>;
  return (
    <span className="whitespace-nowrap">
      {horizon.renew_by.slice(0, 10)}
      <span className="ml-1 text-2xs text-muted-foreground">
        {translateNow("source.assumes.value1.day.leaves.4477a854ad", { value1: horizon.leaf_validity_days })}
      </span>
    </span>
  );
}

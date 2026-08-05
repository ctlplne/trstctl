import { type OwnershipConflict, type OwnershipConflictList } from "@/lib/api";
import { useApiQuery } from "@/lib/query";
import { optionalApiCall } from "@/lib/optionalApi";
import { translateNow } from "@/i18n/I18nProvider";

// OwnershipConflictsPanel shows the ownership an import refused to overwrite (I2).
//
// This panel is the whole reason the import is trustworthy. An import that
// silently reconciled would show nothing here and would still be wrong: the
// eleven rows it overwrote are the only ones anybody needed to look at, and
// they would be indistinguishable from the four hundred it got right.
//
// Each row says which way it went, because "refused" and "applied" are
// different work. A list whose entries all read like completed changes is worse
// than no list.
function readOwnershipConflicts(): Promise<OwnershipConflictList> {
  return optionalApiCall<OwnershipConflictList>("ownershipConflicts", { items: [], refused: 0, guidance: "" });
}

export function OwnershipConflictsPanel() {
  // Optional-method guard: a console can outlive the server build that served
  // it, and a panel that assumes a client method takes the whole Owners page
  // down rather than hiding itself.
  const conflicts = useApiQuery(["ownership-conflicts"], readOwnershipConflicts);
  const items: OwnershipConflict[] = conflicts.data?.items ?? [];
  if (items.length === 0) return null;
  return (
    <section aria-labelledby="ownership-conflicts-heading" className="ui-panel space-y-3 p-comfortable">
      <h2 id="ownership-conflicts-heading" className="text-title font-semibold">
        {translateNow("source.ownership.conflicts.i2own00001")}
      </h2>
      <p className="text-sm">
        {translateNow("source.ownership.conflicts.blurb.i2own00002", { value1: String(items.length) })}
      </p>
      <ul className="space-y-2 text-sm">
        {items.slice(0, 25).map((item) => (
          <li key={item.id} className="border-b border-border pb-2 last:border-0">
            <span className="font-mono text-xs">{item.field}</span>{" "}
            <span className="text-caption text-muted-foreground">
              {item.current_attested
                ? translateNow("source.ownership.conflicts.attested.i2own00003")
                : translateNow("source.ownership.conflicts.applied.i2own00004")}
            </span>
            <span className="mt-1 block text-caption text-muted-foreground">
              {item.current_value || "—"} ({item.current_source || translateNow("source.ownership.conflicts.unknown.i2own00005")}) → {item.incoming_value} (
              {item.incoming_source}, {item.incoming_ref})
            </span>
            <span className="mt-1 block text-caption text-muted-foreground">{item.why}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

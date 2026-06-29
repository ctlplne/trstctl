import { SectionCard, DashboardGrid, AttentionList, AttentionRow } from "@/components/dashboard";
import { StatTile } from "@/components/charts";
import { RiskScore, useRisk } from "@/components/risk";
import { useTranslation } from "@/i18n/I18nProvider";
import type { Identity, CredentialRisk, NHIInventory as NHIInventoryResponse, Owner } from "@/lib/api";

function humanize(value: string): string {
	const words = value.replace(/_/g, " ").split(" ");
	const acronyms: Record<string, string> = { api: "API", iam: "IAM", oauth: "OAuth", ssh: "SSH", nhi: "NHI" };
	return words
		.map((word, index) => {
			const acronym = acronyms[word.toLowerCase()];
			if (acronym) return acronym;
			if (index === 0) return word.charAt(0).toUpperCase() + word.slice(1);
			return word;
		})
		.join(" ");
}

function kindCounts(identities: Identity[]): Array<[string, number]> {
	const map = new Map<string, number>();
	for (const identity of identities) map.set(identity.kind, (map.get(identity.kind) ?? 0) + 1);
	return [...map.entries()].sort((a, b) => b[1] - a[1]);
}

function inventoryKindCounts(inventory?: NHIInventoryResponse): Array<[string, number]> {
	if (!inventory) return [];
	const map = new Map<string, number>();
	for (const [kind, raw] of Object.entries(inventory.summary ?? {})) {
		const count = Number(raw);
		if (Number.isFinite(count) && count > 0) map.set(kind, count);
	}
	if (map.size === 0) {
		for (const item of inventory.items ?? []) map.set(item.kind, (map.get(item.kind) ?? 0) + 1);
	}
	return [...map.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

export function NhiInventory({ identities, inventory, risks = [] }: { identities: Identity[]; inventory?: NHIInventoryResponse; risks?: CredentialRisk[] }) {
	const { t } = useTranslation();
	const kinds = inventory ? inventoryKindCounts(inventory) : kindCounts(identities);
	const highRisk = risks.filter((risk) => risk.score >= 70).length;
	const total = inventory?.items?.length ?? identities.length;
	return (
		<SectionCard title={t("nhi.inventory.title")} description={t("nhi.inventory.description")}>
			<DashboardGrid>
				<StatTile label={t("nhi.inventory.total")} value={total} />
				{kinds.map(([kind, count]) => (
					<StatTile key={kind} label={humanize(kind)} value={count} />
				))}
				<StatTile label={t("nhi.inventory.highRisk")} value={highRisk} tone={highRisk ? "high" : undefined} />
			</DashboardGrid>
		</SectionCard>
	);
}

export function OrphanGovernance({ owners = [] }: { owners?: Owner[] }) {
  const { data: risks } = useRisk();
  const orphans = risks.filter((risk) => !risk.owner_active);
  const coverage = risks.length ? Math.round(((risks.length - orphans.length) / risks.length) * 100) : 100;
  return (
    <div className="grid gap-4">
      <DashboardGrid>
        <StatTile label="Credentials" value={risks.length} />
        <StatTile label="Registered owners" value={owners.length} />
        <StatTile label="Orphaned" value={orphans.length} tone={orphans.length ? "high" : undefined} />
        <StatTile label="Ownership coverage" value={`${coverage}%`} />
      </DashboardGrid>
      <SectionCard title="Orphaned credentials" description="machine identities whose human custodian is gone or inactive">
        {orphans.length === 0 ? (
          <p className="text-caption text-muted-foreground">Every credential has an active owner.</p>
        ) : (
          <AttentionList ariaLabel="Orphaned credentials">
            {orphans.map((risk) => (
              <AttentionRow key={risk.credential_id}>
                <span className="flex-1 truncate font-mono text-caption">{risk.subject}</span>
                <span className="w-24 truncate text-caption text-muted-foreground">{risk.kind}</span>
                <RiskScore score={risk.score} />
              </AttentionRow>
            ))}
          </AttentionList>
        )}
      </SectionCard>
    </div>
  );
}

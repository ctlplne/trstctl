import { useEffect, useMemo, useState } from "react";
import { useApiQuery } from "@/lib/query";
import { DataGrid } from "@/components/DataGrid";
import { api } from "@/lib/api";
import type { PAMServiceDependentReviewEntry, PAMServiceDependentReviewPage, PAMServiceDependentRotationIntent } from "@/lib/api-types.gen";
import { useTranslation } from "@/i18n/I18nProvider";
import { CredentialChip } from "@/components/CredentialChip";
import { Num } from "@/components/typography";
import { Button } from "@/components/ui/button";

type Props = {
  intent: PAMServiceDependentRotationIntent;
  digest: string;
  access?: "operator" | "approver";
  onReadiness?: (digest: string | null) => void;
  readPage?: (id: string, number: number, access: "operator" | "approver") => Promise<PAMServiceDependentReviewPage>;
};
type Observation = { digest: string; entries: number; agents: string[] };
const isDigest = (v: unknown) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
function pageEntries(page: PAMServiceDependentReviewPage): PAMServiceDependentReviewEntry[] | null {
  if (page.entries === null) return [];
  if (!Array.isArray(page.entries)) return null;
  for (const value of page.entries) {
    if (!value || typeof value !== "object") return null;
    const entry = value as Partial<PAMServiceDependentReviewEntry>;
    if (
      !entry.ref ||
      !["services", "tasks", "iis"].includes(entry.ref.family) ||
      typeof entry.ref.name !== "string" ||
      !entry.ref.name ||
      typeof entry.probe_id !== "string" ||
      !entry.probe_id ||
      !entry.host?.binding?.agent_id ||
      entry.ref.agent_id !== entry.host.binding.agent_id
    )
      return null;
    if (
      !page.hosts.some(
        (h) =>
          h.binding.agent_id === entry.ref!.agent_id &&
          h.inventory_run_id === entry.host!.inventory_run_id &&
          h.inventory_digest === entry.host!.inventory_digest,
      )
    )
      return null;
  }
  return page.entries as PAMServiceDependentReviewEntry[];
}

function readNativeReviewPage(id: string, number: number, access: "operator" | "approver") {
  return access === "approver" ? api.pamServiceReconciliationReviewPage(id, number) : api.pamServiceDependentReviewPage(id, number);
}

export function PAMDependentManifestPages(props: Props) {
  if (!props.intent.plan.manifest) return null;
  return <ManifestPages key={JSON.stringify([props.intent.plan.id, props.digest, props.access])} {...props} />;
}
function ManifestPages({ intent, digest, access = "operator", onReadiness, readPage = readNativeReviewPage }: Props) {
  const { t } = useTranslation();
  const seal = intent.plan.manifest!;
  const [number, setNumber] = useState(0);
  const [observed, setObserved] = useState<Record<number, Observation>>({});
  const [expired, setExpired] = useState(true);
  const validSeal =
    isDigest(digest) &&
    seal.version === 1 &&
    seal.id === intent.plan.id &&
    Number.isSafeInteger(seal.page_count) &&
    seal.page_count > 0 &&
    Number.isSafeInteger(seal.entry_count) &&
    seal.entry_count > 0 &&
    Number.isSafeInteger(seal.host_count) &&
    seal.host_count > 0 &&
    isDigest(seal.digest) &&
    isDigest(seal.header_digest) &&
    isDigest(seal.tail_digest) &&
    seal.expires_at === intent.plan.expires_at;
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const check = () => {
      const remaining = new Date(seal.expires_at).getTime() - Date.now();
      setExpired(!Number.isFinite(remaining) || remaining <= 0);
      if (Number.isFinite(remaining) && remaining > 0) timer = setTimeout(check, Math.min(remaining, 2147483647));
    };
    check();
    return () => clearTimeout(timer);
  }, [seal.expires_at]);
  const query = useApiQuery(["pam-dependent-review-page", access, intent.plan.id, digest, number], () => readPage(intent.plan.id, number, access), {
    enabled: validSeal,
    retry: false,
    gcTime: 0,
  });
  const current = useMemo(() => {
    const page = query.data;
    if (
      !validSeal ||
      !page ||
      query.error ||
      query.fetching ||
      page.version !== 1 ||
      page.id !== intent.plan.id ||
      page.page_number !== number ||
      page.header_digest !== seal.header_digest ||
      !isDigest(page.digest) ||
      !Array.isArray(page.hosts) ||
      !page.hosts.length
    )
      return null;
    if (
      page.previous_digest !== (number === 0 ? seal.header_digest : observed[number - 1]?.digest) ||
      (number === seal.page_count - 1 && page.digest !== seal.tail_digest) ||
      (observed[number] && observed[number].digest !== page.digest)
    )
      return null;
    if (
      page.hosts.some(
        (h) =>
          !h?.binding?.agent_id || h.binding.account?.account_id !== intent.plan.account.account_id || !h.inventory_run_id || !isDigest(h.inventory_digest),
      )
    )
      return null;
    const entries = pageEntries(page);
    return entries ? { page, entries } : null;
  }, [
    query.data,
    query.error,
    query.fetching,
    validSeal,
    intent.plan.id,
    intent.plan.account.account_id,
    seal.header_digest,
    seal.page_count,
    seal.tail_digest,
    number,
    observed,
  ]);
  useEffect(() => {
    if (!current) return;
    const next = { digest: current.page.digest, entries: current.entries.length, agents: current.page.hosts.map((h) => h.binding.agent_id) };
    setObserved((previous) => (previous[number]?.digest === next.digest ? previous : { ...previous, [number]: next }));
  }, [current, number]);
  const observations = Object.values(observed);
  const ready =
    !!current &&
    !expired &&
    observations.length === seal.page_count &&
    observations.reduce((sum, p) => sum + p.entries, 0) === seal.entry_count &&
    new Set(observations.flatMap((p) => p.agents)).size === seal.host_count;
  useEffect(() => {
    onReadiness?.(ready ? digest : null);
  }, [ready, digest, onReadiness]);
  const offset = Object.entries(observed).reduce((sum, [n, p]) => (Number(n) < number ? sum + p.entries : sum), 0);
  const failed = !validSeal || (!query.loading && !query.fetching && !current);
  return (
    <section className="grid gap-3 rounded-control border border-border p-3" aria-label={t("admin.access.rotation.pagedReview")}>
      <p>{t("admin.access.rotation.pageSummary", { page: number + 1, pages: seal.page_count, entries: seal.entry_count, hosts: seal.host_count })}</p>
      <CredentialChip value={seal.digest} fullValue />
      <DataGrid<PAMServiceDependentReviewEntry>
        ariaLabel={t("admin.access.rotation.pagedReview")}
        rows={current?.entries ?? []}
        getRowId={(entry) => JSON.stringify(entry.ref)}
        state={failed ? "error" : query.loading || query.fetching ? "loading" : undefined}
        stateTitle={failed ? t("admin.access.rotation.pageUnavailable") : current?.entries.length === 0 ? t("admin.access.rotation.hostOnlyPage") : undefined}
        emptyStateHeadingAs="h4"
        stateMessage={
          failed && validSeal ? (
            <Button type="button" variant="outline" onClick={query.refetch}>
              {t("admin.access.dependents.retry")}
            </Button>
          ) : undefined
        }
        columns={[
          { id: "position", header: t("admin.access.rotation.position"), cell: (entry) => <Num>{offset + (current?.entries.indexOf(entry) ?? 0) + 1}</Num> },
          {
            id: "dependent",
            header: t("admin.access.rotation.dependent"),
            cell: (entry) => (
              <span className="break-all">
                {entry.ref.family}: {entry.ref.name}
              </span>
            ),
          },
          { id: "host", header: t("admin.access.rotation.reviewHost"), cell: (entry) => <CredentialChip value={entry.ref.agent_id} /> },
          { id: "probe", header: t("admin.access.rotation.reviewProbe"), cell: (entry) => entry.probe_id },
        ]}
      />
      {current ? (
        <details>
          <summary>{t("admin.access.rotation.pageSources")}</summary>
          <dl className="grid gap-2">
            {current.page.hosts.map((host) => (
              <div key={host.binding.agent_id}>
                <dt>
                  <CredentialChip value={host.binding.agent_id} fullValue />
                </dt>
                <dd>
                  <CredentialChip value={host.inventory_run_id} fullValue />
                  <CredentialChip value={host.inventory_digest} fullValue />
                  <p>{host.observed_at}</p>
                </dd>
              </div>
            ))}
          </dl>
          <CredentialChip value={current.page.digest} fullValue />
        </details>
      ) : null}
      {expired ? <p role="status">{t("admin.access.rotation.reviewExpired")}</p> : ready ? <p role="status">{t("admin.access.rotation.pagesLoaded")}</p> : null}
      <div className="flex gap-2">
        <Button type="button" variant="outline" disabled={number === 0 || query.fetching} onClick={() => setNumber((n) => n - 1)}>
          {t("admin.access.rotation.previousReviewPage")}
        </Button>
        <Button type="button" variant="outline" disabled={!current || number >= seal.page_count - 1} onClick={() => setNumber((n) => n + 1)}>
          {t("admin.access.rotation.nextReviewPage")}
        </Button>
      </div>
    </section>
  );
}

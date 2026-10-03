import { useEffect, useMemo, useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm, useWatch } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/StatePrimitives";
import { useCan } from "@/components/rbac";
import { formatDateTime } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import {
  api,
  type AWSHoneyAccountCatalog,
  type AWSHoneyToken,
  type AWSHoneyTokenCreateRequest,
  type AWSHoneyTokenCreateResponse,
  type AWSHoneyTokenDetail,
  type AWSHoneyTokenList,
  type AWSHoneyTokenPreview,
} from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useApiQuery, useQueryClient } from "@/lib/query";
import { RevealPanel } from "./SecretsPageParts";

type DecoyForm = { accountID: string; name: string; placement: string; ttlSeconds: number };

const visibleStates = ["active", "triggered", "retiring", "retirement_failed", "revoked", "failed"] as const;
function isVisibleState(value: string): value is AWSHoneyToken["state"] {
  return visibleStates.some((state) => state === value);
}

// The secret access key is kept only in component memory and discarded when the
// reveal panel closes. Inventory, scan coverage, and incidents are metadata.
export function AWSHoneyTokenWorkflow() {
  const { t } = useTranslation();
  const canWrite = useCan("secrets:write");
  const queryClient = useQueryClient();
  const accountQuery = useApiQuery(["aws-honey", "accounts"], () => api.listAWSHoneyAccounts());
  const inventoryQuery = useApiQuery(["aws-honey", "inventory"], () => api.listAWSHoneyTokens());
  const catalog: AWSHoneyAccountCatalog | null = accountQuery.data;
  const [extraItems, setExtraItems] = useState<AWSHoneyToken[]>([]);
  const [extraCursor, setExtraCursor] = useState<string | null>(null);
  const [selectedID, setSelectedID] = useState("");
  const detailQuery = useApiQuery(["aws-honey", "detail", selectedID], () => api.getAWSHoneyToken(selectedID), { enabled: Boolean(selectedID) });
  const selected: AWSHoneyTokenDetail | null = detailQuery.data;
  const items = [...(inventoryQuery.data?.items ?? []), ...extraItems.filter((item) => !inventoryQuery.data?.items.some((first) => first.id === item.id))];
  const nextCursor = extraCursor ?? inventoryQuery.data?.next_cursor ?? "";
  const schema = useMemo(
    () =>
      z
        .object({
          accountID: z.string().min(1, t("secrets.awsHoney.accountRequired")),
          name: z.string().trim().min(1, t("secrets.awsHoney.nameInvalid")).max(128, t("secrets.awsHoney.nameInvalid")),
          placement: z.string().trim().min(1, t("secrets.awsHoney.placementInvalid")).max(256, t("secrets.awsHoney.placementInvalid")),
          ttlSeconds: z.number().int(t("secrets.awsHoney.ttlInvalid")).positive(t("secrets.awsHoney.ttlInvalid")),
        })
        .superRefine((value, context) => {
          const attached = catalog?.accounts.find((entry) => entry.id === value.accountID);
          if (attached && (value.ttlSeconds < 2 * attached.poll_interval_seconds || value.ttlSeconds > attached.max_ttl_seconds)) {
            context.addIssue({ code: "custom", path: ["ttlSeconds"], message: t("secrets.awsHoney.ttlInvalid") });
          }
        }),
    [catalog, t],
  );
  const {
    control,
    register,
    handleSubmit,
    setValue,
    reset,
    formState: { errors: formErrors },
  } = useForm<DecoyForm>({
    resolver: zodResolver(schema),
    mode: "onTouched",
    defaultValues: { accountID: "", name: "", placement: "", ttlSeconds: 86400 },
  });
  const accountID = useWatch({ control, name: "accountID" });
  const [revealed, setRevealed] = useState<AWSHoneyTokenCreateResponse | null>(null);
  const [preview, setPreview] = useState<AWSHoneyTokenPreview | null>(null);
  const [reviewedRequest, setReviewedRequest] = useState<AWSHoneyTokenCreateRequest | null>(null);
  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!accountID && catalog?.accounts[0]) {
      setValue("accountID", catalog.accounts[0].id);
      setValue("ttlSeconds", Math.min(86400, catalog.accounts[0].max_ttl_seconds));
    }
  }, [accountID, catalog, setValue]);

  function refresh() {
    setExtraItems([]);
    setExtraCursor(null);
    void queryClient.invalidateQueries({ queryKey: ["aws-honey"] });
  }

  function updateInventory(item: AWSHoneyToken) {
    queryClient.setQueryData<AWSHoneyTokenList>(["aws-honey", "inventory"], (current) => ({
      items: [item, ...(current?.items ?? []).filter((other) => other.id !== item.id)],
      next_cursor: current?.next_cursor ?? "",
    }));
  }

  function updateInventoryState(id: string, state: string) {
    if (!isVisibleState(state)) return;
    queryClient.setQueryData<AWSHoneyTokenList>(["aws-honey", "inventory"], (current) =>
      current ? { ...current, items: current.items.map((item) => (item.id === id ? { ...item, state } : item)) } : current,
    );
    setExtraItems((current) => current.map((item) => (item.id === id ? { ...item, state } : item)));
  }

  function invalidatePreview() {
    setPreview(null);
    setReviewedRequest(null);
    setPendingKey(null);
  }

  const account = catalog?.accounts.find((entry) => entry.id === accountID);

  function stateLabel(state: AWSHoneyToken["state"]) {
    switch (state) {
      case "active":
        return t("secrets.awsHoney.stateActive");
      case "triggered":
        return t("secrets.awsHoney.stateTriggered");
      case "retiring":
        return t("secrets.awsHoney.stateRetiring");
      case "retirement_failed":
        return t("secrets.awsHoney.stateRetirementFailed");
      case "revoked":
        return t("secrets.awsHoney.stateRevoked");
      default:
        return t("secrets.awsHoney.stateFailed");
    }
  }

  function actionLabel(action: string) {
    switch (action) {
      case "iam.create_tagged_user":
        return t("secrets.awsHoney.actionCreateUser");
      case "iam.install_and_verify_deny_all":
        return t("secrets.awsHoney.actionDenyAll");
      case "iam.create_access_key":
        return t("secrets.awsHoney.actionCreateKey");
      case "cloudtrail.queue_monitor":
        return t("secrets.awsHoney.actionMonitor");
      default:
        return action;
    }
  }

  async function review(values: DecoyForm) {
    if (!catalog?.accounts.some((entry) => entry.id === values.accountID)) return;
    setBusy(true);
    setError(null);
    try {
      const request = { account_id: values.accountID, name: values.name, placement: values.placement, ttl_seconds: values.ttlSeconds };
      const result = await api.previewAWSHoneyToken(request);
      setReviewedRequest(request);
      setPreview(result);
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.awsHoney.reviewFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function plant() {
    if (!reviewedRequest || !preview) return;
    setBusy(true);
    setError(null);
    const key = pendingKey ?? crypto.randomUUID();
    setPendingKey(key);
    try {
      const created = await api.createAWSHoneyToken(
        {
          ...reviewedRequest,
          preview_fingerprint: preview.preview_fingerprint,
        },
        key,
      );
      setRevealed(created);
      setPendingKey(null);
      setPreview(null);
      setReviewedRequest(null);
      reset({ accountID: reviewedRequest.account_id, name: "", placement: "", ttlSeconds: reviewedRequest.ttl_seconds });
      updateInventory({
        id: created.id,
        kind: "aws",
        name: created.name,
        placement: created.placement,
        state: "active",
        created_at: created.created_at,
        aws_access_key_id: created.aws_access_key_id,
        aws_account_config_id: created.aws_account_config_id,
        aws_account_id: created.aws_account_id,
        aws_lease_id: created.aws_lease_id,
        aws_poll_interval_seconds: created.aws_poll_interval_seconds,
        aws_regions: created.aws_regions,
        alarm_generation: created.alarm_generation,
      });
      setSelectedID(created.id);
      void queryClient.invalidateQueries({ queryKey: ["aws-honey"] });
    } catch (cause) {
      setPreview(null);
      setReviewedRequest(null);
      setError(apiProblemMessage(cause, t("secrets.awsHoney.plantFailed")));
    } finally {
      setBusy(false);
    }
  }

  function inspect(id: string) {
    setSelectedID(id);
    setError(null);
    if (selectedID === id) detailQuery.refetch();
  }

  async function retire(id: string) {
    setBusy(true);
    try {
      const detail = await api.retireAWSHoneyToken(id);
      queryClient.setQueryData(["aws-honey", "detail", id], detail);
      updateInventoryState(id, detail.state);
      if (revealed?.id === id) setRevealed(null);
      void queryClient.invalidateQueries({ queryKey: ["aws-honey"] });
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.awsHoney.retireFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function rearm(id: string) {
    setBusy(true);
    try {
      const detail = await api.rearmAWSHoneyToken(id);
      queryClient.setQueryData(["aws-honey", "detail", id], detail);
      updateInventoryState(id, detail.state);
      void queryClient.invalidateQueries({ queryKey: ["aws-honey"] });
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.awsHoney.rearmFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function loadMore() {
    if (!nextCursor) return;
    setBusy(true);
    try {
      const result = await api.listAWSHoneyTokens(nextCursor);
      setExtraItems((current) => [...current, ...result.items]);
      setExtraCursor(result.next_cursor ?? "");
    } catch (cause) {
      setError(apiProblemMessage(cause, t("secrets.awsHoney.readFailed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="aws-honeytoken-heading" className="grid gap-4 border-y border-border py-4">
      <div>
        <h2 id="aws-honeytoken-heading" className="text-title font-semibold">
          {t("secrets.awsHoney.heading")}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("secrets.awsHoney.description")}</p>
        {catalog ? <p className="mt-1 max-w-3xl text-xs text-muted-foreground">{t("secrets.awsHoney.reviewDetectionScope")}</p> : null}
      </div>
      {error || accountQuery.errorValue || inventoryQuery.errorValue || detailQuery.errorValue ? (
        <ErrorState title={t("secrets.awsHoney.error")}>
          {error || apiProblemMessage(accountQuery.errorValue || inventoryQuery.errorValue || detailQuery.errorValue, t("secrets.awsHoney.readFailed"))}
        </ErrorState>
      ) : null}
      {catalog && catalog.accounts.length === 0 ? <p className="text-sm text-muted-foreground">{t("secrets.awsHoney.noAccount")}</p> : null}
      {canWrite && account ? (
        <form onSubmit={handleSubmit(review)} className="grid max-w-xl gap-3">
          <label className="grid gap-1 text-sm">
            <span>{t("secrets.awsHoney.account")}</span>
            <select
              className="rounded-md border border-border bg-background px-3 py-2"
              aria-label={t("secrets.awsHoney.account")}
              {...register("accountID", {
                onChange: (event) => {
                  const next = catalog?.accounts.find((entry) => entry.id === event.target.value);
                  if (next) setValue("ttlSeconds", Math.min(86400, next.max_ttl_seconds));
                  invalidatePreview();
                },
              })}
            >
              {catalog?.accounts.map((entry) => (
                <option key={entry.id} value={entry.id}>
                  {entry.id} ({entry.account_id})
                </option>
              ))}
            </select>
            {formErrors.accountID ? (
              <span role="alert" className="text-xs text-destructive">
                {formErrors.accountID.message}
              </span>
            ) : null}
          </label>
          <p className="text-xs text-muted-foreground">
            {t("secrets.awsHoney.regions")}: {account.regions.join(", ")}
          </p>
          <label className="grid gap-1 text-sm">
            <span>{t("secrets.honeytokens.name")}</span>
            <input
              className="rounded-md border border-border bg-background px-3 py-2"
              aria-label={t("secrets.honeytokens.name")}
              maxLength={128}
              {...register("name", { onChange: invalidatePreview })}
            />
            {formErrors.name ? (
              <span role="alert" className="text-xs text-destructive">
                {formErrors.name.message}
              </span>
            ) : null}
          </label>
          <label className="grid gap-1 text-sm">
            <span>{t("secrets.honeytokens.placement")}</span>
            <input
              className="rounded-md border border-border bg-background px-3 py-2"
              aria-label={t("secrets.honeytokens.placement")}
              maxLength={256}
              {...register("placement", { onChange: invalidatePreview })}
            />
            {formErrors.placement ? (
              <span role="alert" className="text-xs text-destructive">
                {formErrors.placement.message}
              </span>
            ) : null}
          </label>
          <label className="grid gap-1 text-sm">
            <span>{t("secrets.awsHoney.ttl")}</span>
            <input
              className="rounded-md border border-border bg-background px-3 py-2"
              aria-label={t("secrets.awsHoney.ttl")}
              type="number"
              min={2 * account.poll_interval_seconds}
              max={account.max_ttl_seconds}
              {...register("ttlSeconds", { valueAsNumber: true, onChange: invalidatePreview })}
            />
            {formErrors.ttlSeconds ? (
              <span role="alert" className="text-xs text-destructive">
                {formErrors.ttlSeconds.message}
              </span>
            ) : null}
          </label>
          <Button type="submit" disabled={busy}>
            {t("secrets.awsHoney.review")}
          </Button>
        </form>
      ) : null}
      {preview ? (
        <section aria-label={t("secrets.awsHoney.reviewHeading")} className="grid max-w-2xl gap-2 rounded-control border border-border p-4 text-sm">
          <h3 className="font-semibold">{t("secrets.awsHoney.reviewHeading")}</h3>
          <p>{t("secrets.awsHoney.reviewNoEffects")}</p>
          {!preview.remote_authority_checked ? <p>{t("secrets.awsHoney.remoteUnchecked")}</p> : null}
          <p>
            {preview.name} · {preview.placement} · {preview.aws_account_id} · {preview.ttl_seconds} {t("secrets.awsHoney.seconds")}
          </p>
          <p>
            {t("secrets.awsHoney.regions")}: {preview.regions.join(", ")}
          </p>
          <p>{t("secrets.awsHoney.reviewDetectionScope")}</p>
          <h4 className="font-medium">{t("secrets.awsHoney.iamActions")}</h4>
          <ul className="list-disc pl-5">
            {preview.iam_actions.map((action) => (
              <li key={action}>{actionLabel(action)}</li>
            ))}
          </ul>
          <p>
            {t("secrets.awsHoney.recovery")}: {t("secrets.awsHoney.reviewRecovery")}
          </p>
          <p>
            {t("secrets.awsHoney.verification")}: {t("secrets.awsHoney.reviewVerification")}
          </p>
          <Button type="button" disabled={busy || !preview.ready} onClick={() => void plant()}>
            {t("secrets.awsHoney.plant")}
          </Button>
        </section>
      ) : null}
      {revealed ? (
        <div className="grid gap-2">
          <p className="text-sm">
            {t("secrets.awsHoney.accessKeyID")}: <code>{revealed.access_key_id}</code>
          </p>
          <RevealPanel title={t("secrets.awsHoney.revealTitle")} value={revealed.secret_access_key} onDismiss={() => setRevealed(null)}>
            {t("secrets.awsHoney.revealHelp")}
          </RevealPanel>
        </div>
      ) : null}
      <div className="flex items-center justify-between gap-3">
        <h3 className="font-semibold">{t("secrets.awsHoney.inventory")}</h3>
        <Button type="button" variant="outline" disabled={busy} onClick={() => void refresh()}>
          {t("secrets.honeytokens.refresh")}
        </Button>
      </div>
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("secrets.awsHoney.empty")}</p>
      ) : (
        <ul className="grid gap-3">
          {items.map((item) => (
            <li key={item.id} className="rounded-control border border-border p-3 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <strong>{item.name}</strong>
                <span className={item.state === "triggered" || item.state === "retirement_failed" ? "font-semibold text-destructive" : "text-muted-foreground"}>
                  {stateLabel(item.state)}
                </span>
              </div>
              <p>
                {item.aws_access_key_id} · {item.placement}
              </p>
              <p>
                {t("secrets.honeytokens.created")}: {formatDateTime(item.created_at)}
              </p>
              <div className="mt-2 flex gap-2">
                <Button type="button" variant="outline" disabled={busy} onClick={() => void inspect(item.id)}>
                  {t("secrets.awsHoney.inspect")}
                </Button>
                {canWrite && item.state !== "revoked" && item.state !== "retiring" ? (
                  <Button type="button" variant="outline" disabled={busy} onClick={() => void retire(item.id)}>
                    {t(item.state === "retirement_failed" ? "secrets.awsHoney.retryRetire" : "secrets.awsHoney.retire")}
                  </Button>
                ) : null}
                {canWrite && item.state === "triggered" ? (
                  <Button type="button" variant="outline" disabled={busy} onClick={() => void rearm(item.id)}>
                    {t("secrets.awsHoney.rearm")}
                  </Button>
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      )}
      {nextCursor ? (
        <Button type="button" variant="outline" disabled={busy} onClick={() => void loadMore()}>
          {t("secrets.honeytokens.loadMore")}
        </Button>
      ) : null}
      {selected ? (
        <section aria-label={t("secrets.awsHoney.investigation")} className="grid gap-2 rounded-control border border-border p-3 text-sm">
          <div className="flex items-center justify-between gap-2">
            <h3 className="font-semibold">
              {selected.name} · {selected.aws_access_key_id}
            </h3>
            <Button type="button" variant="outline" disabled={busy} onClick={() => void inspect(selected.id)}>
              {t("secrets.honeytokens.refresh")}
            </Button>
          </div>
          <p>
            {t("secrets.awsHoney.iamStatus")}:{" "}
            {selected.lease.revocation_status === "completed"
              ? t("secrets.awsHoney.iamRemoved")
              : selected.lease.revocation_status === "pending"
                ? t("secrets.awsHoney.iamPending")
                : selected.lease.revocation_status === "failed"
                  ? t("secrets.awsHoney.iamFailed")
                  : t("secrets.awsHoney.iamPresent")}
          </p>
          {selected.monitoring.map((scan) => (
            <p key={scan.region}>
              {scan.region}: {t("secrets.awsHoney.lastScan")} {scan.last_success_at ? formatDateTime(scan.last_success_at) : t("secrets.awsHoney.never")};{" "}
              {t("secrets.awsHoney.watermark")} {formatDateTime(scan.watermark)} · {t("secrets.awsHoney.monitorStatus")}:{" "}
              {scan.delivery_status || t("secrets.awsHoney.never")}
              {scan.delivery_error ? t("secrets.awsHoney.monitorErrorDetail", { error: scan.delivery_error }) : ""}
              {scan.gap_since ? t("secrets.awsHoney.gapDetail", { time: formatDateTime(scan.gap_since) }) : ""}
            </p>
          ))}
          <h4 className="font-semibold">{t("secrets.awsHoney.events")}</h4>
          {selected.uses.length === 0 ? (
            <p>{t("secrets.awsHoney.noEvents")}</p>
          ) : (
            <ul className="grid gap-2">
              {selected.uses.map((use) => (
                <li key={use.event_id} className="rounded border border-border p-2">
                  {formatDateTime(use.event_time)} · {use.region} · {use.event_source}/{use.event_name} · {use.source_ip_address} ·{" "}
                  {use.error_code || t("secrets.awsHoney.noError")}
                </li>
              ))}
            </ul>
          )}
        </section>
      ) : null}
    </section>
  );
}

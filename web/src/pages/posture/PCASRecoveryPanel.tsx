import { useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useFieldArray, useForm } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { ApiError } from "@/lib/apiTransport";
import { useTranslation } from "@/i18n/I18nProvider";
import { pcasApi, type PCASChain, type PCASRecoveryApprover } from "@/lib/pcasApi";
import { useApiQuery, useQueryClient } from "@/lib/query";

const publicDER = z
  .string()
  .trim()
  .min(1)
  .refine((value) => {
    try {
      return atob(value).length > 0;
    } catch {
      return false;
    }
  });
const approverSchema = z.object({ ID: z.string().trim().min(1), PubDER: publicDER }).strict();
const policySchema = z
  .object({
    threshold: z.number().int().positive(),
    trustRootDER: publicDER,
    roster: z.array(approverSchema).min(1),
  })
  .superRefine((value, issue) => {
    if (
      value.threshold > value.roster.length ||
      new Set(value.roster.map((member) => member.ID)).size !== value.roster.length ||
      new Set(value.roster.map((member) => member.PubDER)).size !== value.roster.length
    ) {
      issue.addIssue({ code: "custom", path: ["roster"], message: "" });
    }
  });
type PolicyValues = z.infer<typeof policySchema>;

const authorizationSchema = z
  .object({
    Statement: z
      .object({
        DeploymentScope: z.string().min(1),
        IdentityID: z.string().min(1),
        TenantID: z.string().min(1),
        Epoch: z.number().int().positive(),
        SuccessorAlg: z.string().min(1),
        SuccessorPub: publicDER,
        Nonce: z.string().min(1),
      })
      .strict(),
    Threshold: z.number().int().positive(),
    Roster: z.array(approverSchema).min(1),
    RosterSig: publicDER,
    Approvals: z.array(z.object({ ApproverID: z.string().min(1), Signature: publicDER }).strict()).min(1),
  })
  .strict();
type Authorization = z.infer<typeof authorizationSchema>;
const authorizationFormSchema = z.object({ authorizationJSON: z.string().trim().min(1) });
type AuthorizationValues = z.infer<typeof authorizationFormSchema>;

type Predecessor = { epoch: number; algorithm: string; publicDER: string; scope: string };

// Chain records are base64 JSON artifacts. A malformed readback disables the
// recovery action; it never falls back to an operator-typed predecessor.
function predecessorFromChain(chain: PCASChain | null): Predecessor | null {
  if (!chain?.genesis) return null;
  if (chain.records.length === 0) {
    return {
      epoch: chain.genesis.epoch,
      algorithm: chain.genesis.algorithm,
      publicDER: chain.genesis.public_key,
      scope: chain.genesis.deployment_scope,
    };
  }
  try {
    const last = JSON.parse(atob(chain.records[chain.records.length - 1])) as {
      Fields?: { Epoch?: unknown; SuccessorAlg?: unknown; SuccessorPub?: unknown; DeploymentScope?: unknown };
    };
    const fields = last.Fields;
    if (
      !fields ||
      typeof fields.Epoch !== "number" ||
      !Number.isSafeInteger(fields.Epoch) ||
      fields.Epoch !== chain.records.length ||
      typeof fields.SuccessorAlg !== "string" ||
      typeof fields.SuccessorPub !== "string" ||
      typeof fields.DeploymentScope !== "string" ||
      !fields.SuccessorPub ||
      fields.DeploymentScope !== chain.genesis.deployment_scope
    )
      return null;
    return { epoch: fields.Epoch, algorithm: fields.SuccessorAlg, publicDER: fields.SuccessorPub, scope: fields.DeploymentScope };
  } catch {
    return null;
  }
}

function servedRecoveryProof(chain: PCASChain | null, epoch: number): string | null {
  if (!chain || !epoch || chain.records.length < epoch) return null;
  try {
    const record = JSON.parse(atob(chain.records[epoch - 1])) as {
      Fields?: { Epoch?: unknown };
      Authorization?: unknown;
      InclusionProof?: unknown;
    };
    if (record.Fields?.Epoch !== epoch || !record.Authorization || typeof record.InclusionProof !== "string" || !record.InclusionProof) return null;
    return record.InclusionProof;
  } catch {
    return null;
  }
}

function matchingAuthorization(
  auth: Authorization,
  chain: PCASChain,
  policy: {
    threshold: number;
    roster: PCASRecoveryApprover[];
  },
  successor: { tenant_id: string; epoch: number; algorithm: string; public_key_der: string; deployment_scope: string },
): boolean {
  const statement = auth.Statement;
  return (
    successor.tenant_id === chain.genesis?.tenant_id &&
    statement.IdentityID === chain.identity_id &&
    statement.TenantID === chain.genesis?.tenant_id &&
    statement.DeploymentScope === successor.deployment_scope &&
    statement.Epoch === successor.epoch &&
    statement.SuccessorAlg === successor.algorithm &&
    statement.SuccessorPub === successor.public_key_der &&
    auth.Threshold === policy.threshold &&
    auth.Roster.length === policy.roster.length &&
    auth.Roster.every((member, index) => member.ID === policy.roster[index].ID && member.PubDER === policy.roster[index].PubDER) &&
    new Set(auth.Approvals.map((approval) => approval.ApproverID)).size >= policy.threshold &&
    auth.Approvals.every((approval) => policy.roster.some((member) => member.ID === approval.ApproverID))
  );
}

export function PCASRecoveryPanel({ identityID }: { identityID: string }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [policyReview, setPolicyReview] = useState<PolicyValues | null>(null);
  const [prepareReview, setPrepareReview] = useState("");
  const [algorithm, setAlgorithm] = useState("ECDSA-P384");
  const [prepareRequestID, setPrepareRequestID] = useState("");
  const [readPrepared, setReadPrepared] = useState(false);
  const [recoveryReview, setRecoveryReview] = useState<{ source: string; binding: string; authorization: Authorization } | null>(null);
  const [recoveryRequestID, setRecoveryRequestID] = useState("");
  const [requestedEpoch, setRequestedEpoch] = useState(0);
  const [busy, setBusy] = useState(false);
  const [operationError, setOperationError] = useState("");
  const chain = useApiQuery(["pcas-recovery-chain", identityID], () => pcasApi.chain(identityID), { enabled: Boolean(identityID), retry: false });
  const policy = useApiQuery(["pcas-recovery-policy", identityID], () => pcasApi.recoveryPolicy(identityID), { enabled: Boolean(identityID), retry: false });
  const predecessor = predecessorFromChain(chain.data);
  const successorEpoch = predecessor ? predecessor.epoch + 1 : 0;
  const prepareStatus = useApiQuery(["pcas-recovery-prepare", prepareRequestID], () => pcasApi.requestStatus(prepareRequestID), {
    enabled: Boolean(prepareRequestID),
    retry: false,
    live: { intervalMs: 5000 },
  });
  const successor = useApiQuery(["pcas-recovery-successor", identityID, successorEpoch], () => pcasApi.recoverySuccessor(identityID, successorEpoch), {
    enabled: Boolean(identityID && successorEpoch && (readPrepared || prepareStatus.data?.status === "delivered")),
    retry: false,
  });
  const recoveryStatus = useApiQuery(["pcas-recovery-request", recoveryRequestID], () => pcasApi.requestStatus(recoveryRequestID), {
    enabled: Boolean(recoveryRequestID),
    retry: false,
    live: { intervalMs: 5000 },
  });
  const policyForm = useForm<PolicyValues>({
    resolver: zodResolver(policySchema),
    mode: "onTouched",
    defaultValues: {
      threshold: 2,
      trustRootDER: "",
      roster: [
        { ID: "", PubDER: "" },
        { ID: "", PubDER: "" },
      ],
    },
  });
  const members = useFieldArray({ control: policyForm.control, name: "roster" });
  const authorizationForm = useForm<AuthorizationValues>({
    resolver: zodResolver(authorizationFormSchema),
    mode: "onTouched",
    defaultValues: { authorizationJSON: "" },
  });
  const noPolicy = policy.errorValue instanceof ApiError && policy.errorValue.status === 404;
  const prepareBinding = JSON.stringify([identityID, predecessor, policy.data?.updated_at, algorithm]);
  const recoveryBinding = JSON.stringify([identityID, predecessor, policy.data?.updated_at, successor.data?.event_id]);
  const recoveryProof = servedRecoveryProof(chain.data, requestedEpoch);

  const reviewPolicy = policyForm.handleSubmit((values) => {
    setPolicyReview(values);
    setOperationError("");
  });
  const savePolicy = policyForm.handleSubmit(async (values) => {
    if (!policyReview || JSON.stringify(policyReview) !== JSON.stringify(values)) {
      setPolicyReview(null);
      setOperationError(t("pcas.error.reviewChanged"));
      return;
    }
    setBusy(true);
    setOperationError("");
    try {
      const saved = await pcasApi.configureRecoveryPolicy({
        identity_id: identityID,
        threshold: values.threshold,
        roster: values.roster,
        trust_root_der: values.trustRootDER,
      });
      queryClient.setQueryData(["pcas-recovery-policy", identityID], {
        identity_id: identityID,
        threshold: values.threshold,
        roster: values.roster,
        trust_root_der: values.trustRootDER,
        updated_at: saved.updated_at,
      });
      await queryClient.invalidateQueries({ queryKey: ["pcas-recovery-policy", identityID] });
      setPolicyReview(null);
      setRecoveryReview(null);
    } catch (cause) {
      setOperationError(cause instanceof Error ? cause.message : t("pcas.recovery.policyError"));
    } finally {
      setBusy(false);
    }
  });

  async function prepare() {
    if (!predecessor || !policy.data || prepareReview !== prepareBinding) {
      setPrepareReview("");
      setOperationError(t("pcas.error.reviewChanged"));
      return;
    }
    setBusy(true);
    setOperationError("");
    try {
      const accepted = await pcasApi.prepareRecoverySuccessor({
        identity_id: identityID,
        deployment_scope: predecessor.scope,
        epoch: successorEpoch,
        algorithm,
      });
      setPrepareRequestID(accepted.request_id);
      setReadPrepared(false);
      setPrepareReview("");
      await queryClient.invalidateQueries({ queryKey: ["pcas-recovery-prepare", accepted.request_id] });
    } catch (cause) {
      setOperationError(cause instanceof Error ? cause.message : t("pcas.recovery.prepareError"));
    } finally {
      setBusy(false);
    }
  }

  const reviewRecovery = authorizationForm.handleSubmit((values) => {
    setOperationError("");
    if (!chain.data || !policy.data || !successor.data || !predecessor) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(values.authorizationJSON);
    } catch {
      setOperationError(t("pcas.recovery.authorizationInvalid"));
      return;
    }
    const checked = authorizationSchema.safeParse(parsed);
    if (!checked.success || !matchingAuthorization(checked.data, chain.data, policy.data, successor.data)) {
      setOperationError(t("pcas.recovery.authorizationMismatch"));
      return;
    }
    setRecoveryReview({ source: values.authorizationJSON, binding: recoveryBinding, authorization: checked.data });
  });

  const submitRecovery = authorizationForm.handleSubmit(async (values) => {
    if (
      !recoveryReview ||
      recoveryReview.source !== values.authorizationJSON ||
      recoveryReview.binding !== recoveryBinding ||
      !predecessor ||
      !policy.data ||
      !successor.data
    ) {
      setRecoveryReview(null);
      setOperationError(t("pcas.error.reviewChanged"));
      return;
    }
    setBusy(true);
    setOperationError("");
    try {
      const accepted = await pcasApi.requestRecovery({
        identity_id: identityID,
        deployment_scope: predecessor.scope,
        target_algorithm: successor.data.algorithm,
        successor_handle: successor.data.handle,
        predecessor_epoch: predecessor.epoch,
        epoch: successor.data.epoch,
        predecessor_algorithm: predecessor.algorithm,
        predecessor_public_der: predecessor.publicDER,
        trust_root_der: policy.data.trust_root_der,
        authorization: recoveryReview.authorization,
      });
      setRecoveryRequestID(accepted.request_id);
      setRequestedEpoch(successor.data.epoch);
      setRecoveryReview(null);
    } catch (cause) {
      setOperationError(cause instanceof Error ? cause.message : t("pcas.recovery.requestError"));
    } finally {
      setBusy(false);
    }
  });

  return (
    <section className="grid gap-4 border-t border-border pt-4" aria-labelledby="pcas-recovery-heading">
      <div>
        <h3 id="pcas-recovery-heading" className="font-semibold">
          {t("pcas.recovery.title")}
        </h3>
        <p className="text-sm text-muted-foreground">{t("pcas.recovery.description")}</p>
      </div>
      {chain.error ? (
        <p role="alert" className="text-sm text-destructive">
          {chain.error}
        </p>
      ) : null}
      {!predecessor && !chain.loading ? <p role="alert">{t("pcas.recovery.chainUnavailable")}</p> : null}
      {predecessor ? (
        <p className="text-sm">
          {t("pcas.recovery.current")}: <code>{predecessor.algorithm}</code> · {t("pcas.epoch")} {predecessor.epoch}
          {" → "}
          {t("pcas.epoch")} {successorEpoch}
        </p>
      ) : null}
      {policy.data ? (
        <div className="grid gap-1 rounded-panel border border-border bg-background p-3 text-sm">
          <strong>{t("pcas.recovery.enforcedPolicy")}</strong>
          <p>{t("pcas.recovery.quorum", { threshold: policy.data.threshold, count: policy.data.roster.length })}</p>
          <p>
            {t("pcas.recovery.trustRoot")}: <code className="break-all">{policy.data.trust_root_der}</code>
          </p>
          <ul>
            {policy.data.roster.map((member) => (
              <li key={member.ID}>
                <code>{member.ID}</code> · <code className="break-all">{member.PubDER}</code>
              </li>
            ))}
          </ul>
          <p>
            {t("pcas.recovery.updated")}: {policy.data.updated_at}
          </p>
        </div>
      ) : null}
      {noPolicy ? <p>{t("pcas.recovery.noPolicy")}</p> : null}
      {policy.error && !noPolicy ? (
        <p role="alert" className="text-sm text-destructive">
          {policy.error}
        </p>
      ) : null}
      <form
        className="grid gap-3 rounded-panel border border-border p-3"
        onSubmit={(event) => {
          event.preventDefault();
          void reviewPolicy();
        }}
      >
        <h4 className="font-semibold">{t("pcas.recovery.configure")}</h4>
        <Field label={t("pcas.recovery.threshold")} error={policyForm.formState.errors.threshold ? t("pcas.recovery.invalidPolicy") : undefined} required>
          {(control) => <Input {...control} type="number" min="1" step="1" {...policyForm.register("threshold", { valueAsNumber: true })} />}
        </Field>
        <Field label={t("pcas.recovery.trustRoot")} error={policyForm.formState.errors.trustRootDER ? t("pcas.recovery.invalidDER") : undefined} required>
          {(control) => <Input {...control} {...policyForm.register("trustRootDER")} />}
        </Field>
        {members.fields.map((member, index) => (
          <div key={member.id} className="grid gap-2 rounded-panel border border-border p-3 md:grid-cols-[1fr_2fr_auto]">
            <Field
              label={t("pcas.recovery.custodian", { index: index + 1 })}
              error={policyForm.formState.errors.roster?.[index]?.ID ? t("pcas.recovery.invalidPolicy") : undefined}
              required
            >
              {(control) => <Input {...control} {...policyForm.register(`roster.${index}.ID`)} />}
            </Field>
            <Field
              label={t("pcas.recovery.publicDER", { index: index + 1 })}
              error={policyForm.formState.errors.roster?.[index]?.PubDER ? t("pcas.recovery.invalidDER") : undefined}
              required
            >
              {(control) => <Input {...control} {...policyForm.register(`roster.${index}.PubDER`)} />}
            </Field>
            <Button
              type="button"
              variant="outline"
              disabled={busy || members.fields.length === 1}
              onClick={() => {
                members.remove(index);
                setPolicyReview(null);
              }}
            >
              {t("pcas.retirement.remove")}
            </Button>
          </div>
        ))}
        <Button
          type="button"
          variant="outline"
          disabled={busy}
          onClick={() => {
            members.append({ ID: "", PubDER: "" });
            setPolicyReview(null);
          }}
        >
          {t("pcas.recovery.addCustodian")}
        </Button>
        {policyForm.formState.errors.roster?.root ? <p role="alert">{t("pcas.recovery.invalidPolicy")}</p> : null}
        <Button type="submit" disabled={busy}>
          {t("pcas.recovery.reviewPolicy")}
        </Button>
        {policyReview ? (
          <div className="grid gap-2 rounded-panel border border-border bg-background p-3 text-sm">
            <strong>{t("pcas.recovery.policyReview")}</strong>
            <p>{t("pcas.recovery.quorum", { threshold: policyReview.threshold, count: policyReview.roster.length })}</p>
            <p>
              {t("pcas.recovery.trustRoot")}: <code className="break-all">{policyReview.trustRootDER}</code>
            </p>
            <ul>
              {policyReview.roster.map((member) => (
                <li key={member.ID}>
                  <code>{member.ID}</code> · <code className="break-all">{member.PubDER}</code>
                </li>
              ))}
            </ul>
            <Button type="button" disabled={busy} onClick={() => void savePolicy()}>
              {t("pcas.recovery.savePolicy")}
            </Button>
          </div>
        ) : null}
      </form>
      {predecessor && policy.data ? (
        <div className="grid gap-3 rounded-panel border border-border p-3">
          <h4 className="font-semibold">{t("pcas.recovery.prepareTitle")}</h4>
          <Field label={t("pcas.recovery.algorithm")} required>
            {(control) => (
              <Select
                {...control}
                value={algorithm}
                onChange={(event) => {
                  setAlgorithm(event.target.value);
                  setPrepareReview("");
                }}
              >
                <option value="ECDSA-P384">{t("pcas.recovery.algP384")}</option>
                <option value="ECDSA-P521">{t("pcas.recovery.algP521")}</option>
              </Select>
            )}
          </Field>
          <Button
            type="button"
            disabled={busy}
            onClick={() => {
              setPrepareReview(prepareBinding);
              setOperationError("");
            }}
          >
            {t("pcas.recovery.reviewPrepare")}
          </Button>
          {prepareReview === prepareBinding ? (
            <div className="grid gap-2 rounded-panel border border-border bg-background p-3 text-sm">
              <strong>{t("pcas.recovery.prepareReview")}</strong>
              <p>
                <code>{identityID}</code> · <code>{predecessor.scope}</code> · {algorithm} · {t("pcas.epoch")} {successorEpoch}
              </p>
              <Button type="button" disabled={busy} onClick={() => void prepare()}>
                {t("pcas.recovery.prepare")}
              </Button>
            </div>
          ) : null}
          <Button
            type="button"
            variant="outline"
            disabled={busy}
            onClick={() => {
              setReadPrepared(true);
              successor.refetch();
            }}
          >
            {t("pcas.recovery.readPrepared")}
          </Button>
          {prepareRequestID ? (
            <p>
              {t("pcas.recovery.prepareStatus")}: <code>{prepareRequestID}</code> · {prepareStatus.data?.status ?? t("pcas.recovery.pending")}
            </p>
          ) : null}
          {successor.data ? (
            <div className="grid gap-1 rounded-panel border border-border bg-background p-3 text-sm">
              <strong>{t("pcas.recovery.prepared")}</strong>
              <p>
                {t("pcas.recovery.tenant")}: <code>{successor.data.tenant_id}</code>
              </p>
              <p>
                {successor.data.algorithm} · {t("pcas.epoch")} {successor.data.epoch} · <code>{successor.data.handle}</code>
              </p>
              <p>
                {t("pcas.recovery.preparedKey")}: <code className="break-all">{successor.data.public_key_der}</code>
              </p>
              <p>
                {t("pcas.recovery.signedReceipt")}: <code className="break-all">{successor.data.event_id}</code> ·{" "}
                <code className="break-all">{successor.data.signer_signature}</code>
              </p>
            </div>
          ) : null}
          {successor.error && !(successor.errorValue instanceof ApiError && successor.errorValue.status === 404) ? <p role="alert">{successor.error}</p> : null}
        </div>
      ) : null}
      {predecessor && policy.data && successor.data ? (
        <form
          className="grid gap-3 rounded-panel border border-border p-3"
          onSubmit={(event) => {
            event.preventDefault();
            void reviewRecovery();
          }}
        >
          <h4 className="font-semibold">{t("pcas.recovery.requestTitle")}</h4>
          <p className="text-sm text-muted-foreground">{t("pcas.recovery.authorizationHelp")}</p>
          <Field
            label={t("pcas.recovery.authorization")}
            error={authorizationForm.formState.errors.authorizationJSON ? t("pcas.recovery.authorizationInvalid") : undefined}
            required
          >
            {(control) => <Textarea {...control} rows={8} {...authorizationForm.register("authorizationJSON")} />}
          </Field>
          <Button type="submit" disabled={busy}>
            {t("pcas.recovery.reviewRequest")}
          </Button>
          {recoveryReview ? (
            <div className="grid gap-2 rounded-panel border border-border bg-background p-3 text-sm">
              <strong>{t("pcas.recovery.requestReview")}</strong>
              <p>
                <code>{identityID}</code> · {predecessor.algorithm} {predecessor.epoch} → {successor.data.algorithm} {successor.data.epoch}
              </p>
              <p>{t("pcas.recovery.quorum", { threshold: recoveryReview.authorization.Threshold, count: recoveryReview.authorization.Roster.length })}</p>
              <p>{t("pcas.recovery.approvalCount", { count: new Set(recoveryReview.authorization.Approvals.map((approval) => approval.ApproverID)).size })}</p>
              <Button type="button" disabled={busy} onClick={() => void submitRecovery()}>
                {t("pcas.recovery.queue")}
              </Button>
            </div>
          ) : null}
        </form>
      ) : null}
      {recoveryRequestID ? (
        <div className="grid gap-2 rounded-panel border border-border bg-background p-3 text-sm">
          <p>
            {t("pcas.recovery.requestStatus")}: <code>{recoveryRequestID}</code> · {recoveryStatus.data?.status ?? t("pcas.recovery.pending")}
          </p>
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              recoveryStatus.refetch();
              chain.refetch();
            }}
          >
            {t("pcas.recovery.refreshProof")}
          </Button>
          {recoveryProof ? (
            <details>
              <summary>{t("pcas.recovery.proofAttached")}</summary>
              <code className="break-all">{recoveryProof}</code>
            </details>
          ) : null}
          {recoveryStatus.data?.status === "delivered" ? <p>{t("pcas.recovery.proofInstruction")}</p> : null}
        </div>
      ) : null}
      {operationError ? (
        <p role="alert" className="text-sm text-destructive">
          {operationError}
        </p>
      ) : null}
    </section>
  );
}

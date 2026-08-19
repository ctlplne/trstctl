import { useCallback, useEffect, useMemo, useState } from "react";
import { Send } from "lucide-react";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useAuth } from "@/auth/AuthProvider";
import { DataGrid, type DataGridColumn, type DataGridState } from "@/components/DataGrid";
import { EmptyState } from "@/components/EmptyState";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardTitle } from "@/components/ui/card";
import { StepShell, type CarouselStep } from "@/components/wizard/StepShell";
import { api, ApiError, type IssuanceRequest, type Owner, type Profile } from "@/lib/api";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";

function problemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || fallback;
    } catch {
      return err.body || fallback;
    }
  }
  return err instanceof Error ? err.message : String(err);
}

function profileKey(profile: Profile): string {
  return `${profile.name}:${profile.version}`;
}

/** S-C5b pilot: the request form is schema-first — zod owns the field
 * contract (react-hook-form wires inputs and per-field errors), so validation
 * copy lives in one place and the submit handler only ever sees valid,
 * trimmed values. API failures stay separate in submitError. */
const requestFormSchema = z.object({
  profileKey: z.string().min(1, "Choose an issuance profile."),
  name: z.string().trim().min(1, "Credential name is required."),
  ownerId: z.string().uuid("Choose an owner."),
  purpose: z.string().trim(),
  // B1: the requester's own PKCS#10. Optional, because the deprecated
  // server-side-keygen path still works for one release train — but supplying it
  // is what makes "your private key never reaches the control plane" true for
  // this request. The real validation is server-side; this only catches an
  // obviously wrong paste before a round trip.
  subjectCSRPEM: z
    .string()
    .trim()
    .refine((value) => value === "" || value.startsWith("-----BEGIN CERTIFICATE REQUEST-----"), {
      get message() {
        return translateNow("request.csr.invalid");
      },
    }),
});
type RequestFormValues = z.infer<typeof requestFormSchema>;

function requesterFor(user: ReturnType<typeof useAuth>["user"]): string {
  // The server binds issuance.request.opened.requester to Principal.Subject.
  // Email is presentation data and can change; filtering an immutable request
  // by it makes a successful request disappear immediately (AUD-78).
  return user?.subject || user?.email || "";
}

function requestStage(request: IssuanceRequest): string {
  switch (request.status) {
    case "requested":
      return "Awaiting approval";
    case "approved":
      return "Approved";
    case "denied":
      return "Denied";
    case "expired":
      return "Expired";
    case "cancelled":
      return "Cancelled";
    case "issued":
      return "Issued";
  }
}

function formatDate(value?: string): string {
  return formatDateTimePolicy(value);
}

export function RequestCredential() {
  const { user } = useAuth();
  const { t } = useTranslation();
  const [step, setStep] = useState(0);
  const [profiles, setProfiles] = useState<Profile[] | null>(null);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [owners, setOwners] = useState<Owner[] | null>(null);
  const [ownerError, setOwnerError] = useState<string | null>(null);
  const [ownerQuery, setOwnerQuery] = useState("");
  const [requests, setRequests] = useState<IssuanceRequest[] | null>(null);
  const [requestError, setRequestError] = useState<string | null>(null);
  const {
    control,
    register,
    handleSubmit,
    setValue,
    reset,
    formState: { errors },
  } = useForm<RequestFormValues>({
    resolver: zodResolver(requestFormSchema),
    mode: "onTouched",
    defaultValues: { profileKey: "", name: "", ownerId: "", purpose: "", subjectCSRPEM: "" },
  });
  // useWatch (not useForm's watch) is the subscription-safe read the React
  // Compiler lint accepts — each field re-renders on its own changes only.
  const selectedProfileKey = useWatch({ control, name: "profileKey" });
  const name = useWatch({ control, name: "name" });
  const ownerId = useWatch({ control, name: "ownerId" });
  const purpose = useWatch({ control, name: "purpose" });
  const [busy, setBusy] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const requester = requesterFor(user);
  const requesterLabel = user?.email || requester;

  const loadProfiles = useCallback(async () => {
    try {
      setProfiles(await api.profiles());
      setProfileError(null);
    } catch (err) {
      setProfiles([]);
      setProfileError(problemMessage(err, "Could not load profiles"));
    }
  }, []);

  const loadRequests = useCallback(async () => {
    try {
      const result = await api.issuanceRequests();
      setRequests(result.items);
      setRequestError(null);
    } catch (err) {
      setRequests([]);
      setRequestError(problemMessage(err, "Could not load requests"));
    }
  }, []);

  const loadOwners = useCallback(async () => {
    try {
      setOwners((await api.owners()).sort((a, b) => a.name.localeCompare(b.name)));
      setOwnerError(null);
    } catch (err) {
      setOwners([]);
      setOwnerError(problemMessage(err, "Could not load owners"));
    }
  }, []);

  useEffect(() => {
    void loadProfiles();
    void loadOwners();
    void loadRequests();
  }, [loadOwners, loadProfiles, loadRequests]);

  const activeProfiles = useMemo(() => (profiles ?? []).filter((profile) => profile.active !== false).sort((a, b) => a.name.localeCompare(b.name)), [profiles]);

  useEffect(() => {
    if (!selectedProfileKey && activeProfiles.length > 0) setValue("profileKey", profileKey(activeProfiles[0]));
  }, [activeProfiles, selectedProfileKey, setValue]);

  const selectedProfile = activeProfiles.find((profile) => profileKey(profile) === selectedProfileKey) ?? null;
  const selectedOwner = (owners ?? []).find((owner) => owner.id === ownerId) ?? null;
  const matchingOwners = useMemo(() => {
    const query = ownerQuery.trim().toLocaleLowerCase();
    if (!query) return owners ?? [];
    return (owners ?? []).filter((owner) => [owner.name, owner.kind, owner.email ?? "", owner.id].some((value) => value.toLocaleLowerCase().includes(query)));
  }, [ownerQuery, owners]);
  const myRequests = useMemo(
    () => (requests ?? []).filter((request) => request.requester === requester).sort((a, b) => b.created_at.localeCompare(a.created_at)),
    [requester, requests],
  );

  const requestColumns = useMemo<Array<DataGridColumn<IssuanceRequest>>>(
    () => [
      {
        id: "name",
        header: "Credential",
        cell: (request) => <span className="font-medium">{request.subject}</span>,
      },
      {
        id: "profile",
        header: "Profile",
        cell: (request) => request.profile || "—",
      },
      {
        id: "stage",
        header: "Request stage",
        cell: (request) => requestStage(request),
      },
      {
        id: "status",
        header: "Status",
        cell: (request) => <StatusBadge vocabulary="lifecycle" value={request.status} />,
      },
      {
        id: "requested",
        header: "Requested",
        cell: (request) => formatDate(request.created_at),
      },
    ],
    [],
  );

  const submit = handleSubmit(async (values) => {
    setSubmitError(null);
    setNotice(null);
    if (!selectedProfile) {
      setSubmitError("Choose an issuance profile.");
      return;
    }

    setBusy(true);
    try {
      const created = await api.createIssuanceRequest({
        subject: values.name,
        profile: `${selectedProfile.name}:${selectedProfile.version}`,
        owner_id: values.ownerId,
        justification: values.purpose,
        origin: "console",
        // The CSR belongs to the request, not to whoever approves it: an
        // approver should not have to re-supply key material they never had.
        ...(values.subjectCSRPEM ? { csr_pem: values.subjectCSRPEM } : {}),
      });
      setRequests((current) => {
        const rows = current ?? [];
        return [created, ...rows.filter((request) => request.id !== created.id)];
      });
      setNotice(`Request accepted for ${created.subject}. It is awaiting approval; no certificate has been minted yet.`);
      reset({ profileKey: values.profileKey, ownerId: values.ownerId, name: "", purpose: "", subjectCSRPEM: "" });
      setStep(0);
    } catch (err) {
      setSubmitError(problemMessage(err, "Could not submit request"));
    } finally {
      setBusy(false);
    }
  });

  const wizardSteps: CarouselStep[] = [
    { id: "profile", label: t("request.wizard.profile.label"), description: t("request.wizard.profile.description") },
    { id: "details", label: t("request.wizard.details.label"), description: t("request.wizard.details.description") },
    { id: "review", label: t("request.wizard.review.label"), description: t("request.wizard.review.description") },
  ];
  const nextDisabled = step === 0 ? !selectedProfile : step === 1 ? !name.trim() || !selectedOwner : true;
  const nextLabel = step === 0 ? t("request.wizard.nextDetails") : t("request.wizard.nextReview");

  const requestGridState: DataGridState = requestError ? "error" : requests == null ? "loading" : myRequests.length ? "ready" : "empty";

  return (
    <section aria-labelledby="request-credential-heading" className="grid gap-6">
      <PageHeader
        title={t("nav.item.requestCredential")}
        titleId="request-credential-heading"
        description="Choose a rule, name the machine, and submit for approval. A request cannot approve or mint its own certificate."
        technicalDetails="Exact evidence includes the selected profile version, owner, requester subject, CSR fingerprint, policy decision, approval events, Idempotency-Key, issuance event, and certificate chain. When you supply a CSR, the private key stays with the requester."
      />

      {notice && (
        <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-body text-status-success">
          {notice}
        </p>
      )}

      <section aria-labelledby="new-request-heading">
        <h2 id="new-request-heading" className="sr-only">
          {translateNow("source.new.request.5977ded363")}
        </h2>
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,0.6fr)]">
          <form aria-labelledby="new-request-heading" className="grid gap-4" onSubmit={submit}>
            {ownerError && <ErrorState title={t("request.wizard.ownerUnavailable")}>{ownerError}</ErrorState>}
            <StepShell
              steps={wizardSteps}
              currentIndex={step}
              nextDisabled={nextDisabled}
              nextLabel={nextLabel}
              onNext={step < 2 ? () => setStep((current) => Math.min(current + 1, 2)) : undefined}
              onPrevious={() => setStep((current) => Math.max(current - 1, 0))}
            >
              {step === 0 && (
                <div className="grid gap-4">
                  {profileError && <ErrorState title={translateNow("source.profile.list.unavailable.3759c2905e")}>{profileError}</ErrorState>}
                  {profiles == null && !profileError && <LoadingState>{translateNow("source.loading.profiles.12a7541833")}</LoadingState>}
                  {profiles && activeProfiles.length === 0 && (
                    <EmptyState title={translateNow("source.no.active.profiles.d3f9395f41")}>
                      {translateNow("source.create.or.activate.a.certificate.profile.b.246493dc15")}
                    </EmptyState>
                  )}
                  <Field className="max-w-xl" label={translateNow("source.profile.d696a35bdd")} required>
                    {(control) => (
                      <Select {...control} {...register("profileKey")} disabled={activeProfiles.length === 0} required>
                        {activeProfiles.map((profile) => (
                          <option key={profileKey(profile)} value={profileKey(profile)}>
                            {translateNow("source.value1.v.value2.value3.b49c34f739", {
                              value1: profile.name,
                              value2: profile.version,
                              value3: profile.active ? " active" : "",
                            })}
                          </option>
                        ))}
                      </Select>
                    )}
                  </Field>
                  {selectedProfile && (
                    <dl className="grid max-w-xl gap-2 rounded-panel border border-border bg-muted/40 p-3 text-body">
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-caption text-muted-foreground">{translateNow("source.profile.d696a35bdd")}</dt>
                        <dd className="font-medium">
                          {translateNow("source.value1.v.value2.5a7805046a", { value1: selectedProfile.name, value2: selectedProfile.version })}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between gap-3">
                        <dt className="text-caption text-muted-foreground">{translateNow("source.status.920e413c7d")}</dt>
                        <dd>
                          <StatusBadge
                            vocabulary="lifecycle"
                            value={selectedProfile.active === false ? "retired" : "issued"}
                            label={selectedProfile.active === false ? "inactive" : "active"}
                          />
                        </dd>
                      </div>
                    </dl>
                  )}
                </div>
              )}

              {step === 1 && (
                <div className="grid max-w-xl gap-4">
                  {owners == null && !ownerError && <LoadingState>{translateNow("source.loading.owners.8fcc1cacd9")}</LoadingState>}
                  {owners && owners.length === 0 && !ownerError && (
                    <EmptyState title={t("request.wizard.noOwnersTitle")}>{t("request.wizard.noOwnersHelp")}</EmptyState>
                  )}
                  <Field label={translateNow("source.credential.name.911c43d9f0")} error={errors.name?.message} required>
                    {(control) => <Input {...control} {...register("name")} placeholder={translateNow("source.payments.api.682a1c47a1")} required />}
                  </Field>
                  <Field label={t("request.wizard.ownerSearch")}>
                    {(control) => (
                      <Input
                        {...control}
                        value={ownerQuery}
                        onChange={(event) => setOwnerQuery(event.target.value)}
                        placeholder={translateNow("source.owner.name.id.email.or.kind.d0081dd7f1")}
                        disabled={owners == null || owners.length === 0 || ownerError != null}
                      />
                    )}
                  </Field>
                  <Field label={translateNow("source.owner.4b1b8aa360")} description={t("request.wizard.ownerHint")} error={errors.ownerId?.message} required>
                    {(control) => (
                      <Select {...control} {...register("ownerId")} disabled={owners == null || owners.length === 0 || ownerError != null} required>
                        <option value="" disabled>
                          {t("request.wizard.ownerPlaceholder")}
                        </option>
                        {matchingOwners.length === 0 && ownerQuery.trim() && (
                          <option value="__no_owner_match__" disabled>
                            {t("request.wizard.ownerNoMatch")}
                          </option>
                        )}
                        {matchingOwners.map((owner) => (
                          <option key={owner.id} value={owner.id}>
                            {t("request.wizard.ownerOption", { name: owner.name, kind: owner.kind })}
                          </option>
                        ))}
                      </Select>
                    )}
                  </Field>
                  <Field label={translateNow("source.business.purpose.286d11d720")}>
                    {(control) => (
                      <Textarea
                        {...control}
                        {...register("purpose")}
                        className="min-h-20"
                        placeholder={translateNow("source.service.tls.for.staging.7d9f743b3b")}
                      />
                    )}
                  </Field>
                  {/* B1: pasting a CSR is the fallback for a host with no agent.
                      The target shape is the agent generating the key on the host
                      and submitting the request itself over its own outbound
                      channel — the operator never touches key material. The help
                      text says so, so this form is not mistaken for the
                      destination. */}
                  <Field label={t("request.csr.label")} description={t("request.csr.help")} error={errors.subjectCSRPEM?.message}>
                    {(control) => (
                      <Textarea
                        {...control}
                        {...register("subjectCSRPEM")}
                        className="min-h-24 font-mono text-xs"
                        placeholder={translateNow("source.begin.certificate.request.929bb0afef")}
                        spellCheck={false}
                      />
                    )}
                  </Field>
                  <div className="grid gap-1 rounded-panel border border-border bg-muted/40 p-3 text-caption">
                    <span className="text-muted-foreground">{t("request.csr.generate")}</span>
                    <code className="break-all font-mono text-xs">
                      {translateNow("source.openssl.req.new.newkey.ec.pkeyopt.ec.param.c1a1d7efe2", { value1: name.trim() || "service" })}
                    </code>
                    <span className="text-muted-foreground">{t("request.csr.omitted")}</span>
                  </div>
                </div>
              )}

              {step === 2 && (
                <div className="grid max-w-xl gap-4">
                  <dl className="grid gap-2 rounded-panel border border-border bg-muted/40 p-3 text-body">
                    <div className="flex items-center justify-between gap-3">
                      <dt className="text-caption text-muted-foreground">{translateNow("source.profile.d696a35bdd")}</dt>
                      <dd className="font-medium">
                        {selectedProfile
                          ? translateNow("source.value1.v.value2.5a7805046a", { value1: selectedProfile.name, value2: selectedProfile.version })
                          : "—"}
                      </dd>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <dt className="text-caption text-muted-foreground">{translateNow("source.credential.name.911c43d9f0")}</dt>
                      <dd className="font-medium">{name.trim() || "—"}</dd>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <dt className="text-caption text-muted-foreground">{translateNow("source.owner.4b1b8aa360")}</dt>
                      <dd className="text-end">
                        {selectedOwner ? t("request.wizard.ownerOption", { name: selectedOwner.name, kind: selectedOwner.kind }) : "—"}
                        {selectedOwner && <code className="block font-mono text-xs text-muted-foreground">{selectedOwner.id}</code>}
                      </dd>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <dt className="text-caption text-muted-foreground">{translateNow("source.business.purpose.286d11d720")}</dt>
                      <dd className="text-end">{purpose.trim() || "—"}</dd>
                    </div>
                    <div className="flex items-center justify-between gap-3">
                      <dt className="text-caption text-muted-foreground">{translateNow("source.requester.b5687cf04a")}</dt>
                      <dd>{requesterLabel || translateNow("source.no.session.principal.ffe06f6da5")}</dd>
                    </div>
                  </dl>
                  {submitError && <ErrorState title={translateNow("source.request.failed.cfce761bef")}>{submitError}</ErrorState>}
                  <div>
                    <Button type="submit" loading={busy} disabled={activeProfiles.length === 0 || !selectedOwner}>
                      <Send className="h-4 w-4" aria-hidden="true" />
                      {translateNow("source.submit.request.917e144e4b")}
                    </Button>
                  </div>
                </div>
              )}
            </StepShell>
          </form>

          <Card className="grid content-start gap-3 p-comfortable text-body">
            <CardTitle>{translateNow("source.request.boundary.4ba2298c84")}</CardTitle>
            <dl className="grid gap-2">
              <div>
                <dt className="text-caption text-muted-foreground">{translateNow("source.requester.b5687cf04a")}</dt>
                <dd>{requesterLabel || translateNow("source.no.session.principal.ffe06f6da5")}</dd>
              </div>
              <div>
                <dt className="text-caption text-muted-foreground">{translateNow("source.mutation.c26ee0e4b9")}</dt>
                <dd>{translateNow("source.idempotent.credential.request.94e8630aea")}</dd>
              </div>
              <div>
                <dt className="text-caption text-muted-foreground">{translateNow("source.result.6e7d50e84f")}</dt>
                <dd>accepted request; approval and issuance remain separate states</dd>
              </div>
            </dl>
          </Card>
        </div>
      </section>

      <DataGrid
        ariaLabel="My credential requests"
        rows={myRequests}
        columns={requestColumns}
        getRowId={(request) => request.id}
        state={requestGridState}
        stateTitle={requestError ? "Request status unavailable" : "No requests yet"}
        stateMessage={requestError ?? "Self-service requests created by this session principal appear here after the backend accepts them."}
      />
    </section>
  );
}

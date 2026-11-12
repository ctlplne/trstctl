import { useEffect, useRef, useState, type FormEvent } from "react";
import { X } from "lucide-react";
import { Dialog } from "@/components/Dialog";
import { useCan } from "@/components/rbac";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { translateNow, useTranslation } from "@/i18n/I18nProvider";
import { api, type CAAuthority, type CACeremonyPlanPreview, type CACeremonyStartRequest, type CAKeyCeremony, type CAUpstreamStandingApproval } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

const DAY_SECONDS = 86400;
// The longest a standing approval may last; the server refuses longer.
const MAX_VALID_DAYS = 90;

const DEFAULT_SPEC = { common_name: "SPIRE Server CA", max_path_len: 0, ttl_seconds: DAY_SECONDS, signature_algorithm: "ecdsa-p256" };

type GrantInput = { principal: string; trustDomain: string; validDays: string; specJSON: string };
type ApprovalSpec = NonNullable<CACeremonyStartRequest["spec"]>;
type Notice = { tone: "status" | "alert"; text: string };

function emptyGrant(): GrantInput {
  return { principal: "", trustDomain: "", validDays: "30", specJSON: JSON.stringify(DEFAULT_SPEC, null, 2) };
}

/**
 * OD-8: an authority's standing approvals for SPIRE upstream CA requests. Two
 * custodians approve one grant_upstream_standing_approval ceremony naming a
 * SPIRE server's principal, its trust domain, the CA spec and how long the
 * approval lasts. Until it expires or is revoked, that server's upstream
 * authority plugin has its CA signed without a ceremony each time, as long as
 * each CA names only the approved trust domain and stays within the approved
 * spec and lifetime. Every signing is counted and in the audit trail.
 */
export function StandingApprovalsDialog({ authority, onClose }: { authority: CAAuthority; onClose: () => void }) {
  const { t, formatDateTime } = useTranslation();
  const canWrite = useCan("issuers:write");
  const [items, setItems] = useState<CAUpstreamStandingApproval[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [reloads, setReloads] = useState(0);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [busy, setBusy] = useState(false);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [revokeReason, setRevokeReason] = useState("");
  const [grant, setGrant] = useState<GrantInput>(emptyGrant);
  const [review, setReview] = useState<{ input: string; request: CACeremonyStartRequest; preview: CACeremonyPlanPreview } | null>(null);
  const [ceremony, setCeremony] = useState<CAKeyCeremony | null>(null);
  const [grantError, setGrantError] = useState<string | null>(null);
  const principalRef = useRef<HTMLInputElement>(null);
  const titleId = "standing-approvals-heading";
  const reviewedInput = JSON.stringify(grant);
  const reviewCurrent = review !== null && review.input === reviewedInput && review.preview.ready;
  const approved = ceremony !== null && ceremony.status === "pending" && ceremony.approvals >= ceremony.threshold;

  useEffect(() => {
    let cancelled = false;
    api.listUpstreamStandingApprovals(authority.id).then(
      (list) => {
        if (cancelled) return;
        setItems(list);
        setLoadError(null);
      },
      (err: unknown) => {
        if (!cancelled) setLoadError(apiProblemMessage(err, translateNow("caHierarchy.standingApprovals.loadFailed")));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [authority.id, reloads]);

  function editGrant(change: Partial<GrantInput>) {
    setGrant((current) => ({ ...current, ...change }));
    // A changed grant is a different ceremony: review and open it again.
    setCeremony(null);
  }

  function grantRequest(): CACeremonyStartRequest | string {
    const principal = grant.principal.trim();
    const trustDomain = grant.trustDomain.trim();
    const days = Number(grant.validDays.trim());
    if (principal === "") return t("caHierarchy.standingApprovals.principalRequired");
    if (trustDomain === "") return t("caHierarchy.standingApprovals.trustDomainRequired");
    if (!Number.isInteger(days) || days < 1 || days > MAX_VALID_DAYS) return t("caHierarchy.standingApprovals.validDaysInvalid", { max: MAX_VALID_DAYS });
    let spec: unknown;
    try {
      spec = JSON.parse(grant.specJSON.trim());
    } catch {
      return t("caHierarchy.standingApprovals.specInvalid");
    }
    if (typeof spec !== "object" || spec === null || Array.isArray(spec)) return t("caHierarchy.standingApprovals.specInvalid");
    return {
      operation: "grant_upstream_standing_approval",
      authority_id: authority.id,
      principal,
      trust_domain: trustDomain,
      valid_for_seconds: days * DAY_SECONDS,
      spec: spec as ApprovalSpec,
      threshold: 2,
    };
  }

  async function reviewGrant() {
    const request = grantRequest();
    if (typeof request === "string") {
      setGrantError(request);
      return;
    }
    setBusy(true);
    setGrantError(null);
    try {
      const preview = await api.previewCACeremony(request);
      setReview({ input: reviewedInput, request, preview });
      if (!preview.ready) setGrantError(t("caHierarchy.standingApprovals.previewBlocked"));
    } catch (err) {
      setGrantError(apiProblemMessage(err, t("caHierarchy.standingApprovals.previewFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function openCeremony() {
    if (!reviewCurrent || !review) return;
    setBusy(true);
    setGrantError(null);
    try {
      setCeremony(await api.createCACeremony(review.request));
    } catch (err) {
      setGrantError(apiProblemMessage(err, t("caHierarchy.standingApprovals.openFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function refreshCeremony() {
    if (!ceremony) return;
    setBusy(true);
    setGrantError(null);
    try {
      setCeremony(await api.caCeremony(ceremony.id));
    } catch (err) {
      setGrantError(apiProblemMessage(err, t("caHierarchy.standingApprovals.refreshFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function submitGrant(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!reviewCurrent || !review || !ceremony || !approved) {
      setGrantError(t("caHierarchy.standingApprovals.approvalRequired"));
      return;
    }
    const request = review.request;
    setBusy(true);
    setGrantError(null);
    try {
      const granted = await api.grantUpstreamStandingApproval(authority.id, {
        ceremony_id: ceremony.id,
        principal: request.principal ?? "",
        trust_domain: request.trust_domain ?? "",
        valid_for_seconds: request.valid_for_seconds ?? 0,
        spec: request.spec as ApprovalSpec,
      });
      setNotice({
        tone: "status",
        text: t("caHierarchy.standingApprovals.grantedNotice", { principal: granted.principal, trustDomain: granted.trust_domain }),
      });
      setGrant(emptyGrant());
      setReview(null);
      setCeremony(null);
      setReloads((count) => count + 1);
    } catch (err) {
      setGrantError(apiProblemMessage(err, t("caHierarchy.standingApprovals.grantFailed")));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(item: CAUpstreamStandingApproval) {
    const reason = revokeReason.trim();
    if (reason === "") {
      setNotice({ tone: "alert", text: t("caHierarchy.standingApprovals.reasonRequired") });
      return;
    }
    setBusy(true);
    setNotice(null);
    try {
      await api.revokeUpstreamStandingApproval(authority.id, item.id, reason);
      setNotice({ tone: "status", text: t("caHierarchy.standingApprovals.revokedNotice", { principal: item.principal, trustDomain: item.trust_domain }) });
      setRevoking(null);
      setRevokeReason("");
    } catch (err) {
      setNotice({ tone: "alert", text: apiProblemMessage(err, t("caHierarchy.standingApprovals.revokeFailed")) });
    } finally {
      setBusy(false);
      setReloads((count) => count + 1);
    }
  }

  function lifetime(seconds: number): string {
    if (seconds % 3600 === 0) return t("caHierarchy.standingApprovals.lifetimeHours", { hours: seconds / 3600 });
    return t("caHierarchy.standingApprovals.lifetimeMinutes", { minutes: Math.ceil(seconds / 60) });
  }

  function statusText(item: CAUpstreamStandingApproval): string {
    if (item.status === "revoked") return t("caHierarchy.standingApprovals.status.revoked");
    if (item.status === "expired") return t("caHierarchy.standingApprovals.status.expired");
    return t("caHierarchy.standingApprovals.status.active");
  }

  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      initialFocusRef={canWrite ? principalRef : undefined}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-3xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 id={titleId} className="truncate text-title font-semibold">
            {t("caHierarchy.standingApprovals.title", { authority: authority.common_name })}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">{t("caHierarchy.standingApprovals.description")}</p>
        </div>
        <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label={t("caHierarchy.standingApprovals.close")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>
      <div className="grid gap-4 p-5 text-sm">
        {loadError && <ErrorState title={t("caHierarchy.standingApprovals.errorTitle")}>{loadError}</ErrorState>}
        {notice && (
          <p role={notice.tone} className={notice.tone === "alert" ? "text-sm text-destructive" : "text-sm"}>
            {notice.text}
          </p>
        )}
        {items !== null && items.length === 0 && <p className="text-muted-foreground">{t("caHierarchy.standingApprovals.none")}</p>}
        {items !== null && items.length > 0 && (
          <table className="ui-table" aria-label={t("caHierarchy.standingApprovals.tableLabel")}>
            <thead>
              <tr>
                <th scope="col">{t("caHierarchy.standingApprovals.principal")}</th>
                <th scope="col">{t("caHierarchy.standingApprovals.trustDomain")}</th>
                <th scope="col">{t("caHierarchy.standingApprovals.maxLifetime")}</th>
                <th scope="col">{t("caHierarchy.standingApprovals.expires")}</th>
                <th scope="col">{t("caHierarchy.standingApprovals.signings")}</th>
                <th scope="col">{t("caHierarchy.standingApprovals.state")}</th>
                <th scope="col">
                  <span className="sr-only">{t("caHierarchy.standingApprovals.actions")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id}>
                  <td className="font-mono">{item.principal}</td>
                  <td className="font-mono">{item.trust_domain}</td>
                  <td>{lifetime(item.spec.ttl_seconds ?? 0)}</td>
                  <td>{formatDateTime(item.expires_at)}</td>
                  <td>
                    {item.last_signed_at
                      ? t("caHierarchy.standingApprovals.signingsLast", { count: item.signings, time: formatDateTime(item.last_signed_at) })
                      : item.signings}
                  </td>
                  <td>
                    {statusText(item)}
                    {item.status === "revoked" && item.revoke_reason ? <span className="block text-xs text-muted-foreground">{item.revoke_reason}</span> : null}
                  </td>
                  <td>
                    {item.status === "active" && canWrite ? (
                      revoking === item.id ? (
                        <div className="grid gap-2">
                          <Field label={t("caHierarchy.standingApprovals.revokeReason")}>
                            {(control) => (
                              <Input {...control} value={revokeReason} maxLength={1024} onChange={(event) => setRevokeReason(event.target.value)} />
                            )}
                          </Field>
                          <div className="flex gap-2">
                            <Button type="button" size="sm" variant="destructive" disabled={busy} onClick={() => void revoke(item)}>
                              {t("caHierarchy.standingApprovals.confirmRevoke")}
                            </Button>
                            <Button
                              type="button"
                              size="sm"
                              variant="ghost"
                              disabled={busy}
                              onClick={() => {
                                setRevoking(null);
                                setRevokeReason("");
                              }}
                            >
                              {t("caHierarchy.standingApprovals.cancelRevoke")}
                            </Button>
                          </div>
                        </div>
                      ) : (
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          disabled={busy}
                          aria-label={t("caHierarchy.standingApprovals.revokeLabel", { principal: item.principal, trustDomain: item.trust_domain })}
                          onClick={() => {
                            setRevoking(item.id);
                            setRevokeReason("");
                          }}
                        >
                          {t("caHierarchy.standingApprovals.revoke")}
                        </Button>
                      )
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {canWrite && (
          <form
            className="grid gap-3 rounded-control border border-border p-4"
            onSubmit={(event) => void submitGrant(event)}
            aria-labelledby="standing-approval-grant-heading"
          >
            <h3 id="standing-approval-grant-heading" className="text-sm font-semibold">
              {t("caHierarchy.standingApprovals.grantHeading")}
            </h3>
            {grantError && <ErrorState title={t("caHierarchy.standingApprovals.grantErrorTitle")}>{grantError}</ErrorState>}
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label={t("caHierarchy.standingApprovals.principal")}>
                {(control) => (
                  <Input {...control} ref={principalRef} value={grant.principal} onChange={(event) => editGrant({ principal: event.target.value })} />
                )}
              </Field>
              <Field label={t("caHierarchy.standingApprovals.trustDomain")}>
                {(control) => (
                  <Input
                    {...control}
                    value={grant.trustDomain}
                    placeholder={t("caHierarchy.standingApprovals.trustDomainPlaceholder")}
                    onChange={(event) => editGrant({ trustDomain: event.target.value })}
                  />
                )}
              </Field>
              <Field label={t("caHierarchy.standingApprovals.validDays")}>
                {(control) => (
                  <Input
                    {...control}
                    type="number"
                    min={1}
                    max={MAX_VALID_DAYS}
                    value={grant.validDays}
                    onChange={(event) => editGrant({ validDays: event.target.value })}
                  />
                )}
              </Field>
            </div>
            <p className="text-caption text-muted-foreground">{t("caHierarchy.standingApprovals.principalHelp")}</p>
            <Field label={t("caHierarchy.standingApprovals.spec")} description={t("caHierarchy.standingApprovals.specHelp")}>
              {(control) => (
                <Textarea
                  {...control}
                  rows={5}
                  value={grant.specJSON}
                  onChange={(event) => editGrant({ specJSON: event.target.value })}
                  className="font-mono text-xs"
                />
              )}
            </Field>
            <div className="flex flex-wrap items-center gap-2">
              <Button type="button" variant="outline" disabled={busy} onClick={() => void reviewGrant()}>
                {t("caHierarchy.standingApprovals.review")}
              </Button>
              <Button type="button" disabled={busy || !reviewCurrent || ceremony !== null} onClick={() => void openCeremony()}>
                {t("caHierarchy.standingApprovals.open")}
              </Button>
              <Button type="button" variant="outline" disabled={busy || ceremony === null} onClick={() => void refreshCeremony()}>
                {t("caHierarchy.standingApprovals.refresh")}
              </Button>
              {ceremony && (
                <span className="text-caption">
                  {t("caHierarchy.standingApprovals.ceremonyProgress", { id: ceremony.id, approvals: ceremony.approvals, threshold: ceremony.threshold })}
                </span>
              )}
            </div>
            {review && (
              <p className="text-caption">
                {t("caHierarchy.standingApprovals.reviewFingerprint")}: <code className="break-all">{review.preview.request_fingerprint}</code>
                {review.input !== reviewedInput && <span className="ml-2">{t("caHierarchy.standingApprovals.reviewStale")}</span>}
              </p>
            )}
            <p className="text-caption text-muted-foreground">{t("caHierarchy.standingApprovals.ceremonyHelp")}</p>
            <footer className="flex justify-end">
              <Button type="submit" disabled={busy || !reviewCurrent || !approved}>
                {t("caHierarchy.standingApprovals.grant")}
              </Button>
            </footer>
          </form>
        )}
        <footer className="flex justify-end border-t border-border pt-4">
          <Button type="button" variant="ghost" onClick={onClose}>
            {t("caHierarchy.standingApprovals.closeButton")}
          </Button>
        </footer>
      </div>
    </Dialog>
  );
}

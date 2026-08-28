import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode, type RefObject } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Building2,
  CheckCircle2,
  Cloud,
  Copy,
  FileKey2,
  Globe2,
  Home,
  KeyRound,
  LockKeyhole,
  Plus,
  RefreshCw,
  Server,
  ShieldCheck,
  X,
  XCircle,
} from "lucide-react";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { Dialog } from "@/components/Dialog";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { PageTabs, tabPanelProps } from "@/components/PageTabs";
import { CAOverview } from "@/components/ca";
import { EdgeDelegationsPanel } from "@/components/EdgeDelegationsPanel";
import { ErrorState, LoadingState, PermissionDeniedState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { useToast } from "@/components/ToastProvider";
import { Button } from "@/components/ui/button";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import { CAHorizonBadge, CAHorizonRenewBy, CALineageTree } from "./cahierarchy/CAHierarchyPageParts";
import { CACeremonyReviewDialog, CARotationReviewDialog, CeremonyDetailDialog, CeremonyPanel } from "./cahierarchy/CAHierarchyCeremonyParts";
import {
  api,
  ApiError,
  type CADiscovery,
  type CAAuthority,
  type CAAuthorityRotation,
  type CAAuthorityRotationPlanPreview,
  type CAAuthorityRotationRequest,
  type CACeremonyPlanPreview,
  type CACeremonyStartRequest,
  type CAIntermediateCSR,
  type CAIssuedIntermediate,
  type CAIssuedLeaf,
  type CAKeyCeremony,
  type ExternalCA,
  type ExternalCAIssuedCertificate,
  type ExternalCAIssueRequest,
  type Issuer,
  type IssuerCapabilityMatrix,
  type RetirementChecklist,
  type IssuerRequest,
  type ManagedKey,
  type Profile,
} from "@/lib/api";
import { defaultIssuerConfigValues, issuerTypes, splitPEMChain, type IssuerConfigField, type IssuerTypeConfig } from "@/lib/issuerCatalog";
import { apiProblemMessage } from "@/lib/apiProblem";
import { useCapabilityExecution } from "@/lib/capabilities";

type Notice = { kind: "permission" | "error"; message: string };
type ProbeState = { issuerID: string; issuerName: string; status: "pending" | "passed" | "failed"; message: string };
type OfflineCAForm = { certificatePEM: string; commonName: string; dnsDomains: string; maxPathLen: string; ttlDays: string };
type OfflineIntermediateForm = OfflineCAForm & { parentID: string };
type ExistingCAForm = OfflineCAForm & { signerHandle: string };
type ExternalCAIssueForm = { caID: string; commonName: string; dnsNames: string; profileName: string; ttlDays: string; csrPEM: string };
type ExternalCAIssueResult = {
  state: "outbox-pending" | "external-ca-issued";
  caID: string;
  path: string;
  certificate?: ExternalCAIssuedCertificate;
};
type CAWorkspaceTab = "overview" | "authorities" | "lifecycle" | "imports" | "custody";
type CeremonyReviewState = {
  onCreated: (ceremony: CAKeyCeremony) => void;
  onError: (message: string) => void;
  preview: CACeremonyPlanPreview;
  request: CACeremonyStartRequest;
};
type RotationReviewState = {
  predecessorID: string;
  preview: CAAuthorityRotationPlanPreview;
  request: CAAuthorityRotationRequest;
};

const caWorkspaceTabIDs: readonly CAWorkspaceTab[] = ["overview", "authorities", "lifecycle", "imports", "custody"];

function caWorkspaceTabFromSearchParam(value: string | null): CAWorkspaceTab {
  return caWorkspaceTabIDs.includes(value as CAWorkspaceTab) ? (value as CAWorkspaceTab) : "overview";
}

const rootCeremonyRequest: CACeremonyStartRequest = {
  operation: "create_root",
  threshold: 2,
  spec: {
    common_name: "Trust Root CA",
    max_path_len: 1,
    signature_algorithm: "ECDSA-P256",
    ttl_seconds: 315_360_000,
  },
};

const managedKeyRequest = { algorithm: "ECDSA-P256" };
const offlineRootDefaults: OfflineCAForm = {
  certificatePEM: "",
  commonName: "Offline Root CA",
  dnsDomains: "example.internal",
  maxPathLen: "1",
  ttlDays: "3650",
};
const offlineIntermediateDefaults: OfflineIntermediateForm = {
  parentID: "",
  certificatePEM: "",
  commonName: "Offline Issuing Intermediate",
  dnsDomains: "example.internal",
  maxPathLen: "0",
  ttlDays: "825",
};
const existingCADefaults: ExistingCAForm = {
  certificatePEM: "",
  commonName: "Imported Existing CA",
  dnsDomains: "example.internal",
  maxPathLen: "0",
  signerHandle: "",
  ttlDays: "825",
};
const externalCAIssueDefaults: ExternalCAIssueForm = {
  caID: "",
  commonName: "service.example.com",
  dnsNames: "service.example.com",
  profileName: "",
  ttlDays: "30",
  csrPEM: "",
};

// RetirementChecklistPanel explains why a CA key cannot be destroyed yet (H4).
//
// It explains the gate; it is not the gate. The refusal is enforced in the
// isolated signer, and the served guidance says so — an operator who believes
// this panel is the control will route around it, have the key destroyed by
// hand, and the evidence chain the whole feature exists to produce never gets
// written.
//
// An unlicensed deployment returns 501 rather than an empty list, so a failure
// to load renders NOTHING rather than a reassuring zero: "no outstanding
// dependents" is permission to destroy, and it must never appear because a
// request failed.
function RetirementChecklistPanel({ keyId }: { keyId: string }) {
  const [checklist, setChecklist] = useState<RetirementChecklist | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [finalEpoch, setFinalEpoch] = useState("1");
  const [confirmed, setConfirmed] = useState(false);

  async function refresh() {
    try {
      const next = await api.caRetirementChecklist(keyId);
      setChecklist(next);
      setLoadError(false);
      return next;
    } catch {
      setChecklist(null);
      setLoadError(true);
      return null;
    }
  }

  useEffect(() => {
    let active = true;
    setChecklist(null);
    setLoadError(false);
    if (!keyId || typeof api.caRetirementChecklist !== "function") return;
    api
      .caRetirementChecklist(keyId)
      .then((res) => {
        if (active) {
          setChecklist(res);
          setLoadError(false);
        }
      })
      .catch(() => {
        if (active) {
          setChecklist(null);
          setLoadError(true);
        }
      });
    return () => {
      active = false;
    };
  }, [keyId]);

  async function requestRetirement() {
    const epoch = Number(finalEpoch);
    if (!confirmed || !Number.isSafeInteger(epoch) || epoch <= 0) return;
    setBusy(true);
    setRequestError(null);
    try {
      await api.retireCAKey(keyId, { final_epoch: epoch, confirm_irreversible: true });
      await refresh();
      setConfirmed(false);
    } catch (err) {
      setRequestError(errorText(err, translateNow("source.retirement.request.failed.h4ret00015")));
    } finally {
      setBusy(false);
    }
  }

  if (loadError) {
    return (
      <section aria-labelledby="retirement-heading" className="ui-panel space-y-3 p-comfortable">
        <h3 id="retirement-heading" className="text-title font-semibold">
          {translateNow("source.retirement.checklist.h4ret00001")}
        </h3>
        <p className="text-sm text-destructive" role="alert">
          {translateNow("source.retirement.unavailable.h4ret00014")}
        </p>
        <Button type="button" variant="outline" onClick={() => void refresh()}>
          {translateNow("source.retirement.refresh.h4ret00007")}
        </Button>
      </section>
    );
  }
  if (!checklist) return null;
  const epoch = Number(finalEpoch);
  const destroyed = checklist.retirement_status === "destroyed";
  const recordHref = checklist.destruction_record ? `data:application/json;charset=utf-8,${encodeURIComponent(checklist.destruction_record)}` : "";
  return (
    <section aria-labelledby="retirement-heading" className="ui-panel space-y-3 p-comfortable">
      <h3 id="retirement-heading" className="text-title font-semibold">
        {translateNow("source.retirement.checklist.h4ret00001")}
      </h3>
      <p className="text-sm">
        {checklist.blocked
          ? translateNow("source.retirement.blocked.h4ret00002", { value1: String(checklist.outstanding?.length ?? 0) })
          : translateNow("source.retirement.clear.h4ret00003")}
      </p>
      {(checklist.outstanding?.length ?? 0) > 0 && (
        <ul className="space-y-1 text-sm">
          {(checklist.outstanding ?? []).map((dep) => (
            <li key={`${dep.kind}:${dep.ref}`} className="flex justify-between gap-3">
              <span className="font-mono text-xs">{dep.ref}</span>
              <span className="text-muted-foreground">{dep.kind}</span>
            </li>
          ))}
        </ul>
      )}
      <dl className="grid gap-1 text-sm sm:grid-cols-2">
        <dt className="text-muted-foreground">{translateNow("source.retirement.status.h4ret00004")}</dt>
        <dd className="font-mono">{checklist.retirement_status || translateNow("source.retirement.not.requested.h4ret00005")}</dd>
      </dl>
      {checklist.refusal_record && (
        <details className="text-sm">
          <summary>{translateNow("source.retirement.signed.refusal.h4ret00013")}</summary>
          <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all text-xs">{checklist.refusal_record}</pre>
        </details>
      )}
      {checklist.destruction_record && (
        <div className="space-y-2">
          <a className="text-sm font-medium text-brand-accent underline" download={`trstctl-ca-key-${keyId}-destruction-record.json`} href={recordHref}>
            {translateNow("source.retirement.download.record.h4ret00012")}
          </a>
          <details className="text-sm">
            <summary>{translateNow("source.retirement.record.preview.h4ret00016")}</summary>
            <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-all text-xs">{checklist.destruction_record}</pre>
          </details>
        </div>
      )}
      {!destroyed && (
        <div className="grid gap-3 rounded-md border border-destructive/40 p-3">
          <label className="grid gap-1 text-sm" htmlFor={`retirement-final-epoch-${keyId}`}>
            {translateNow("source.retirement.final.epoch.h4ret00006")}
            <input
              className="ui-input"
              id={`retirement-final-epoch-${keyId}`}
              min={1}
              onChange={(event) => setFinalEpoch(event.target.value)}
              type="number"
              value={finalEpoch}
            />
          </label>
          <label className="flex items-start gap-2 text-sm">
            <input checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} type="checkbox" />
            <span>{translateNow("source.retirement.confirm.h4ret00008")}</span>
          </label>
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              variant="destructive"
              disabled={busy || !confirmed || !Number.isSafeInteger(epoch) || epoch <= 0}
              onClick={() => void requestRetirement()}
            >
              {translateNow("source.retirement.irreversible.action.h4ret00009")}
            </Button>
            <Button type="button" variant="outline" disabled={busy} onClick={() => void refresh()}>
              {translateNow("source.retirement.refresh.h4ret00007")}
            </Button>
          </div>
          {requestError && (
            <p className="text-sm text-destructive" role="alert">
              {requestError}
            </p>
          )}
        </div>
      )}
      <p className="text-caption text-muted-foreground">{checklist.guidance}</p>
    </section>
  );
}

function RetirementWorkspace({ candidates }: { candidates: CAAuthority[] }) {
  const [keyId, setKeyId] = useState(candidates[0]?.id ?? "");

  useEffect(() => {
    if (!candidates.some((candidate) => candidate.id === keyId)) {
      setKeyId(candidates[0]?.id ?? "");
    }
  }, [candidates, keyId]);

  if (candidates.length === 0 || !keyId) return null;
  return (
    <div className="space-y-3">
      <label className="grid gap-1 text-sm" htmlFor="retirement-key-selector">
        {translateNow("source.retirement.checklist.h4ret00001")}
        <select className="ui-input" id="retirement-key-selector" onChange={(event) => setKeyId(event.target.value)} value={keyId}>
          {candidates.map((candidate) => (
            <option key={candidate.id} value={candidate.id}>
              {candidate.common_name} ({candidate.status})
            </option>
          ))}
        </select>
      </label>
      <RetirementChecklistPanel keyId={keyId} />
    </div>
  );
}

export function CAHierarchy() {
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = caWorkspaceTabFromSearchParam(searchParams.get("tab"));
  const externalCAList = useCapabilityExecution("F4", "listExternalCAs");
  const externalCAIssue = useCapabilityExecution("F4", "issueExternalCA");
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  // R2: the served capability matrix. Null means it could not be read, and the
  // table says "unknown" rather than implying revocation is unavailable — an
  // absent answer and a negative answer are different facts.
  const [capabilities, setCapabilities] = useState<IssuerCapabilityMatrix | null>(null);
  // The capability matrix is keyed by AUTHORITY KIND ("letsencrypt",
  // "digicert"), and Issuer.kind is "x509_ca" | "ssh_ca" — a different axis
  // entirely. Without the external-CA registry to bridge them, every capability
  // cell looked the authority up by a key that can never match and rendered
  // "matrix unavailable", which told the operator the census was broken when it
  // was the lookup that was.
  const [externalCARegistry, setExternalCARegistry] = useState<ExternalCA[]>([]);
  const [externalCAError, setExternalCAError] = useState<string | null>(null);
  const [caDiscovery, setCADiscovery] = useState<CADiscovery | null>(null);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [loading, setLoading] = useState(true);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [ceremony, setCeremony] = useState<CAKeyCeremony | null>(null);
  const [ceremonyBusy, setCeremonyBusy] = useState(false);
  const [ceremonyError, setCeremonyError] = useState<string | null>(null);
  const [managedKey, setManagedKey] = useState<ManagedKey | null>(null);
  const [keyBusy, setKeyBusy] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);
  const [issuerDialogType, setIssuerDialogType] = useState<IssuerTypeConfig | null>(null);
  const [issuerBusy, setIssuerBusy] = useState(false);
  const [issuerError, setIssuerError] = useState<string | null>(null);
  const [probe, setProbe] = useState<ProbeState | null>(null);
  const [offlineRootForm, setOfflineRootForm] = useState<OfflineCAForm>(offlineRootDefaults);
  const [offlineIntermediateForm, setOfflineIntermediateForm] = useState<OfflineIntermediateForm>(offlineIntermediateDefaults);
  const [offlineRootCeremonyID, setOfflineRootCeremonyID] = useState("");
  const [offlineIntermediateCeremonyID, setOfflineIntermediateCeremonyID] = useState("");
  const [offlineRoot, setOfflineRoot] = useState<CAAuthority | null>(null);
  const [offlineCSR, setOfflineCSR] = useState<CAIntermediateCSR | null>(null);
  const [offlineIntermediate, setOfflineIntermediate] = useState<CAAuthority | null>(null);
  const [offlineBusy, setOfflineBusy] = useState(false);
  const [offlineError, setOfflineError] = useState<string | null>(null);
  const [existingCAForm, setExistingCAForm] = useState<ExistingCAForm>(existingCADefaults);
  const [existingCACeremonyID, setExistingCACeremonyID] = useState("");
  const [existingCA, setExistingCA] = useState<CAAuthority | null>(null);
  const [existingCABusy, setExistingCABusy] = useState(false);
  const [existingCAError, setExistingCAError] = useState<string | null>(null);
  const [rotationPredecessorID, setRotationPredecessorID] = useState("");
  const [rotationSuccessorID, setRotationSuccessorID] = useState("");
  const [rotationReason, setRotationReason] = useState("planned CA rotation");
  const [rotationResult, setRotationResult] = useState<CAAuthorityRotation | null>(null);
  const [rotationBusy, setRotationBusy] = useState(false);
  const [rotationError, setRotationError] = useState<string | null>(null);
  const [rotationReview, setRotationReview] = useState<RotationReviewState | null>(null);
  const [rotationReviewError, setRotationReviewError] = useState<string | null>(null);
  const [rekeyAuthorityID, setRekeyAuthorityID] = useState("");
  const [rekeyCeremonyID, setRekeyCeremonyID] = useState("");
  const [rekeyTTLDays, setRekeyTTLDays] = useState("825");
  const [rekeyReason, setRekeyReason] = useState("planned CA renewal");
  const [rekeyResult, setRekeyResult] = useState<CAAuthorityRotation | null>(null);
  const [rekeyBusy, setRekeyBusy] = useState(false);
  const [rekeyError, setRekeyError] = useState<string | null>(null);
  const [externalIssueForm, setExternalIssueForm] = useState<ExternalCAIssueForm>(externalCAIssueDefaults);
  const [externalIssueBusy, setExternalIssueBusy] = useState(false);
  const [externalIssueError, setExternalIssueError] = useState<string | null>(null);
  const [externalIssueResult, setExternalIssueResult] = useState<ExternalCAIssueResult | null>(null);
  const { toast } = useToast();
  const [authorities, setAuthorities] = useState<CAAuthority[]>([]);
  const [authoritiesError, setAuthoritiesError] = useState<string | null>(null);
  const [authorityDetail, setAuthorityDetail] = useState<CAAuthority | null>(null);
  const [createAuthorityKind, setCreateAuthorityKind] = useState<"root" | "intermediate" | null>(null);
  const [leafTarget, setLeafTarget] = useState<CAAuthority | null>(null);
  const [signTarget, setSignTarget] = useState<CAAuthority | null>(null);
  const [ceremonyDetail, setCeremonyDetail] = useState<CAKeyCeremony | null>(null);
  const [ceremonyReview, setCeremonyReview] = useState<CeremonyReviewState | null>(null);
  const [ceremonyReviewBusy, setCeremonyReviewBusy] = useState(false);
  const [ceremonyReviewError, setCeremonyReviewError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setNotice(null);
    // R2: the capability matrix is read defensively. A control plane that does
    // not serve the route — an older one, or one where it is unavailable — must
    // leave the column reading "unknown" rather than taking the page down. The
    // console already treats an absent matrix as a different fact from a
    // negative one, so this degrades to the honest answer.
    const capabilityRead = typeof api.issuerCapabilities === "function" ? api.issuerCapabilities() : Promise.reject(new Error("unavailable"));
    const externalCARead =
      externalCAList.runnable && typeof api.externalCAs === "function"
        ? api.externalCAs()
        : Promise.reject(
            new Error(
              externalCAList.unavailable?.detail ??
                (externalCAList.state === "denied" ? translateNow("capabilities.reason.permissionBlocked") : translateNow("capabilities.reason.unknown")),
            ),
          );
    const [issuerResult, discoveryResult, authoritiesResult, capabilityResult, externalCAResult] = await Promise.allSettled([
      api.issuers(),
      api.caDiscoveryInventory(),
      api.caAuthorities(),
      capabilityRead,
      externalCARead,
    ]);
    setCapabilities(capabilityResult.status === "fulfilled" ? capabilityResult.value : null);
    if (externalCAResult.status === "fulfilled") {
      setExternalCARegistry(externalCAResult.value);
      setExternalCAError(null);
    } else {
      setExternalCARegistry([]);
      setExternalCAError(apiProblemMessage(externalCAResult.reason, "Could not load the external CA registry"));
    }
    if (issuerResult.status === "fulfilled") {
      setIssuers(issuerResult.value);
    } else {
      setIssuers([]);
      setNotice(noticeForError(issuerResult.reason, "Could not load issuers"));
    }
    setCADiscovery(discoveryResult.status === "fulfilled" ? discoveryResult.value : null);
    if (authoritiesResult.status === "fulfilled") {
      setAuthorities(authoritiesResult.value.items ?? []);
      setAuthoritiesError(null);
    } else {
      setAuthorities([]);
      setAuthoritiesError(errorText(authoritiesResult.reason, "Could not load served authorities"));
    }
    setLoading(false);
  }, [externalCAList.runnable, externalCAList.state, externalCAList.unavailable?.detail]);

  useEffect(() => {
    if (externalCAList.checking) return;
    void load();
  }, [externalCAList.checking, load]);

  useEffect(() => {
    let cancelled = false;
    Promise.resolve()
      .then(() => api.profiles())
      .then((list) => {
        if (!cancelled) setProfiles(list);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  const sortedIssuers = useMemo(() => [...issuers].sort((a, b) => a.name.localeCompare(b.name)), [issuers]);
  const authorityParents = useMemo(() => authorities.filter((authority) => authority.kind === "root" || authority.kind === "intermediate"), [authorities]);
  const retirementCandidates = useMemo(
    () => authorities.filter((authority) => authority.signer_handle && (authority.status === "superseded" || authority.status === "revoked")),
    [authorities],
  );

  async function refreshAuthorities() {
    try {
      const next = await api.caAuthorities();
      setAuthorities(next.items ?? []);
      setAuthoritiesError(null);
    } catch (err) {
      setAuthoritiesError(errorText(err, "Could not load served authorities"));
    }
  }

  function handleAuthorityCreated(authority: CAAuthority) {
    setCreateAuthorityKind(null);
    toast({
      kind: "success",
      title: authority.kind === "root" ? "Root CA created" : "Intermediate CA created",
      description: `${authority.common_name} (serial ${shortSerial(authority.serial)})`,
    });
    void refreshAuthorities();
  }

  async function viewCeremony(id: string) {
    setCeremonyBusy(true);
    setCeremonyError(null);
    try {
      setCeremonyDetail(await api.caCeremony(id));
    } catch (err) {
      setCeremonyError(errorText(err, "Could not load ceremony detail"));
    } finally {
      setCeremonyBusy(false);
    }
  }

  async function openCeremonyReview(
    request: CACeremonyStartRequest,
    onCreated: (ceremony: CAKeyCeremony) => void,
    onError: (message: string) => void,
    setBusy: (busy: boolean) => void,
  ) {
    setBusy(true);
    onError("");
    setCeremonyReviewError(null);
    try {
      const preview = await api.previewCACeremony(request);
      if (!preview.ready || preview.preview_writes.length > 0 || preview.preview_external_effects.length > 0) {
        throw new Error(t("caHierarchy.preview.unsafe"));
      }
      setCeremonyReview({ onCreated, onError, preview, request });
    } catch (err) {
      onError(errorText(err, t("caHierarchy.preview.failed")));
    } finally {
      setBusy(false);
    }
  }

  async function confirmCeremonyReview() {
    if (!ceremonyReview) return;
    setCeremonyReviewBusy(true);
    setCeremonyReviewError(null);
    try {
      const next = await api.createCACeremony(ceremonyReview.request);
      ceremonyReview.onCreated(next);
      setCeremonyReview(null);
    } catch (err) {
      const message = errorText(err, t("caHierarchy.preview.startFailed"));
      ceremonyReview.onError(message);
      setCeremonyReviewError(message);
    } finally {
      setCeremonyReviewBusy(false);
    }
  }

  async function startRootCeremony() {
    await openCeremonyReview(rootCeremonyRequest, setCeremony, (message) => setCeremonyError(message || null), setCeremonyBusy);
  }

  async function approveCeremony(id: string) {
    setCeremonyBusy(true);
    setCeremonyError(null);
    try {
      setCeremony(await api.approveCACeremony(id));
    } catch (err) {
      setCeremonyError(errorText(err, "Could not approve ceremony"));
    } finally {
      setCeremonyBusy(false);
    }
  }

  async function generateManagedKey() {
    setKeyBusy(true);
    setKeyError(null);
    try {
      setManagedKey(await api.generateManagedKey(managedKeyRequest));
    } catch (err) {
      setKeyError(errorText(err, "Could not generate managed key"));
    } finally {
      setKeyBusy(false);
    }
  }

  async function runManagedKeyAction(action: "rotate" | "revoke" | "zeroize", keyId: string) {
    setKeyBusy(true);
    setKeyError(null);
    try {
      const next =
        action === "rotate" ? await api.rotateManagedKey(keyId) : action === "revoke" ? await api.revokeManagedKey(keyId) : await api.zeroizeManagedKey(keyId);
      setManagedKey(next);
    } catch (err) {
      setKeyError(errorText(err, `Could not ${action} managed key`));
    } finally {
      setKeyBusy(false);
    }
  }

  async function createIssuerFromCatalog(type: IssuerTypeConfig, name: string, chainPEM: string) {
    setIssuerBusy(true);
    setIssuerError(null);
    try {
      const req: IssuerRequest = {
        name,
        kind: "x509_ca",
        internal: type.internal,
        chain: splitPEMChain(chainPEM),
      };
      await api.createIssuer(req);
      setIssuerDialogType(null);
      await load();
    } catch (err) {
      setIssuerError(errorText(err, "Could not create issuer"));
    } finally {
      setIssuerBusy(false);
    }
  }

  async function testIssuerConnection(issuer: Issuer) {
    setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "pending", message: translateNow("source.connection.pending.31378595b4") });
    if (issuer.internal) {
      setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "passed", message: translateNow("source.connection.passed.49369abdb8") });
      return;
    }
    if (!externalCAList.runnable) {
      setProbe({
        issuerID: issuer.id,
        issuerName: issuer.name,
        status: "failed",
        message: externalCAList.unavailable?.detail ?? translateNow("capabilities.reason.notAttached"),
      });
      return;
    }
    try {
      const externalCAs = await api.externalCAs();
      const upstream = findExternalCAForIssuer(issuer, externalCAs);
      if (upstream && externalCAAvailable(upstream)) {
        setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "passed", message: translateNow("source.connection.passed.49369abdb8") });
        return;
      }
      setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "failed", message: translateNow("source.connection.failed.1c43266b45") });
    } catch (err) {
      setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "failed", message: errorText(err, "connection failed") });
    }
  }

  async function startOfflineRootCeremony() {
    const request: CACeremonyStartRequest = {
      operation: "import_offline_root",
      threshold: 2,
      certificate_pem: offlineRootForm.certificatePEM.trim(),
      spec: offlineFormSpec(offlineRootForm),
    };
    await openCeremonyReview(
      request,
      (next) => {
        setOfflineRootCeremonyID(next.id);
        setCeremony(next);
      },
      (message) => setOfflineError(message || null),
      setOfflineBusy,
    );
  }

  async function importOfflineRoot() {
    setOfflineBusy(true);
    setOfflineError(null);
    try {
      const next = await api.importOfflineRootCA({
        ceremony_id: offlineRootCeremonyID.trim(),
        certificate_pem: offlineRootForm.certificatePEM.trim(),
        spec: offlineFormSpec(offlineRootForm),
      });
      setOfflineRoot(next);
      setOfflineIntermediateForm((current) => ({ ...current, parentID: next.id }));
    } catch (err) {
      setOfflineError(errorText(err, "Could not import offline root"));
    } finally {
      setOfflineBusy(false);
    }
  }

  async function startOfflineIntermediateCeremony() {
    const request: CACeremonyStartRequest = {
      operation: "create_offline_intermediate",
      threshold: 2,
      parent_id: offlineIntermediateForm.parentID.trim(),
      spec: offlineFormSpec(offlineIntermediateForm),
    };
    await openCeremonyReview(
      request,
      (next) => {
        setOfflineIntermediateCeremonyID(next.id);
        setCeremony(next);
      },
      (message) => setOfflineError(message || null),
      setOfflineBusy,
    );
  }

  async function createOfflineIntermediateCSR() {
    setOfflineBusy(true);
    setOfflineError(null);
    try {
      setOfflineCSR(
        await api.createOfflineIntermediateCSR(offlineIntermediateForm.parentID.trim(), {
          ceremony_id: offlineIntermediateCeremonyID.trim(),
          spec: offlineFormSpec(offlineIntermediateForm),
        }),
      );
    } catch (err) {
      setOfflineError(errorText(err, "Could not create offline-intermediate CSR"));
    } finally {
      setOfflineBusy(false);
    }
  }

  async function importOfflineIntermediate() {
    setOfflineBusy(true);
    setOfflineError(null);
    try {
      setOfflineIntermediate(
        await api.importOfflineIntermediateCA(offlineIntermediateForm.parentID.trim(), {
          ceremony_id: offlineIntermediateCeremonyID.trim(),
          certificate_pem: offlineIntermediateForm.certificatePEM.trim(),
          spec: offlineFormSpec(offlineIntermediateForm),
        }),
      );
    } catch (err) {
      setOfflineError(errorText(err, "Could not import offline-signed intermediate"));
    } finally {
      setOfflineBusy(false);
    }
  }

  async function startExistingCACeremony() {
    const request: CACeremonyStartRequest = {
      operation: "import_existing_ca",
      threshold: 2,
      certificate_pem: existingCAForm.certificatePEM.trim(),
      signer_handle: existingCAForm.signerHandle.trim(),
      spec: offlineFormSpec(existingCAForm),
    };
    await openCeremonyReview(
      request,
      (next) => {
        setExistingCACeremonyID(next.id);
        setCeremony(next);
      },
      (message) => setExistingCAError(message || null),
      setExistingCABusy,
    );
  }

  async function importExistingCA() {
    setExistingCABusy(true);
    setExistingCAError(null);
    try {
      setExistingCA(
        await api.importExistingCA({
          ceremony_id: existingCACeremonyID.trim(),
          certificate_pem: existingCAForm.certificatePEM.trim(),
          signer_handle: existingCAForm.signerHandle.trim(),
          spec: offlineFormSpec(existingCAForm),
        }),
      );
    } catch (err) {
      setExistingCAError(errorText(err, "Could not import existing CA"));
    } finally {
      setExistingCABusy(false);
    }
  }

  async function activateCARotation() {
    setRotationBusy(true);
    setRotationError(null);
    setRotationReviewError(null);
    try {
      const predecessorID = rotationPredecessorID.trim();
      const request: CAAuthorityRotationRequest = {
        successor_id: rotationSuccessorID.trim(),
        reason: rotationReason.trim() || undefined,
      };
      const preview = await api.previewCAAuthorityRotation(predecessorID, request);
      if (!preview.ready || preview.preview_writes.length > 0 || preview.preview_external_effects.length > 0) {
        throw new Error(t("caHierarchy.preview.unsafe"));
      }
      setRotationReview({ predecessorID, preview, request });
    } catch (err) {
      setRotationError(errorText(err, t("caHierarchy.rotationPreview.failed")));
    } finally {
      setRotationBusy(false);
    }
  }

  async function confirmCARotation() {
    if (!rotationReview) return;
    setRotationBusy(true);
    setRotationReviewError(null);
    try {
      const next = await api.rotateCAAuthority(rotationReview.predecessorID, rotationReview.request);
      setRotationResult(next);
      setRotationReview(null);
      await load();
    } catch (err) {
      setRotationReviewError(errorText(err, t("caHierarchy.rotationPreview.activateFailed")));
    } finally {
      setRotationBusy(false);
    }
  }

  async function startCARekeyCeremony() {
    const authorityID = rekeyAuthorityID.trim();
    const selected = (caDiscovery?.items ?? []).find((item) => item.source_id === authorityID);
    const request: CACeremonyStartRequest = {
      operation: "rekey_ca",
      authority_id: authorityID,
      threshold: 2,
      spec: {
        common_name: selected?.name ?? "Re-key existing CA",
      },
    };
    await openCeremonyReview(
      request,
      (next) => {
        setRekeyCeremonyID(next.id);
        setCeremony(next);
      },
      (message) => setRekeyError(message || null),
      setRekeyBusy,
    );
  }

  async function activateCARekey() {
    setRekeyBusy(true);
    setRekeyError(null);
    try {
      const days = Number.parseInt(rekeyTTLDays.trim(), 10);
      const ttlSeconds = Number.isFinite(days) && days > 0 ? days * 24 * 60 * 60 : undefined;
      const next = await api.rekeyCAAuthority(rekeyAuthorityID.trim(), {
        ceremony_id: rekeyCeremonyID.trim(),
        ttl_seconds: ttlSeconds,
        reason: rekeyReason.trim() || undefined,
      });
      setRekeyResult(next);
      await load();
    } catch (err) {
      setRekeyError(errorText(err, "Could not re-key CA authority"));
    } finally {
      setRekeyBusy(false);
    }
  }

  async function issueExternalCA() {
    const caID = externalIssueForm.caID.trim();
    const path = externalCAIssuePath(caDiscovery, caID);
    setExternalIssueError(null);
    if (!externalCAIssue.runnable) {
      setExternalIssueResult(null);
      setExternalIssueError(
        externalCAIssue.unavailable?.detail ??
          (externalCAIssue.state === "denied" ? translateNow("capabilities.reason.permissionBlocked") : translateNow("capabilities.reason.unknown")),
      );
      return;
    }
    setExternalIssueBusy(true);
    setExternalIssueResult({ state: "outbox-pending", caID, path });
    try {
      const certificate = await api.issueExternalCA(caID, externalCAIssueRequest(externalIssueForm));
      setExternalIssueResult({ state: "external-ca-issued", caID, path, certificate });
    } catch (err) {
      setExternalIssueResult(null);
      setExternalIssueError(errorText(err, "Could not issue through external CA"));
    } finally {
      setExternalIssueBusy(false);
    }
  }

  function selectTab(next: string) {
    const value = caWorkspaceTabFromSearchParam(next);
    setSearchParams(
      (current) => {
        const nextParams = new URLSearchParams(current);
        if (value === "overview") {
          nextParams.delete("tab");
        } else {
          nextParams.set("tab", value);
        }
        return nextParams;
      },
      { replace: true },
    );
  }

  const hasOverviewInventory = authorities.length > 0 || sortedIssuers.length > 0 || (caDiscovery?.items?.length ?? 0) > 0;
  const showOverviewInventory = hasOverviewInventory || loading || Boolean(authoritiesError);
  const externalRegistryExpectedAbsent = Boolean(externalCAError && /not enabled|not configured|disabled/i.test(externalCAError));

  return (
    <section aria-labelledby="ca-heading" className="grid gap-6">
      <PageHeader
        titleId="ca-heading"
        title={t("nav.item.caHierarchy")}
        description="See who signs each certificate and whether every link in the trust chain is healthy. Sensitive key actions require multiple people, so one admin cannot change trust alone."
        technicalDetails="Exact evidence includes root and intermediate lineage, fingerprints and serial numbers, signer custody, ceremony quorum, authority state, retirement and rollover, trust distribution, and immutable audit events."
        actions={
          <Button type="button" onClick={() => selectTab("authorities")}>
            <Plus className="h-4 w-4" aria-hidden="true" />
            {t("caHierarchy.action.addAuthority")}
          </Button>
        }
      />

      <PageTabs
        tabs={[
          { id: "overview", label: t("caHierarchy.workspace.tabs.overview") },
          { id: "authorities", label: t("caHierarchy.workspace.tabs.authorities") },
          { id: "lifecycle", label: t("caHierarchy.workspace.tabs.lifecycle") },
          { id: "imports", label: t("caHierarchy.workspace.tabs.imports") },
          { id: "custody", label: t("caHierarchy.workspace.tabs.custody") },
        ]}
        active={tab}
        onChange={selectTab}
        ariaLabel={t("caHierarchy.workspace.label")}
        idPrefix="ca"
      />

      <div {...tabPanelProps("ca", "overview")} className={tab === "overview" ? "grid gap-6" : "hidden"}>
        <CAWorkspaceOverview
          authorities={authorities}
          authoritiesError={authoritiesError}
          ceremony={ceremony}
          discovery={caDiscovery}
          loading={loading}
          managedKey={managedKey}
          onRefresh={() => void load()}
        />
        {externalCAError &&
          (externalRegistryExpectedAbsent ? (
            <p className="text-sm text-muted-foreground">
              {t("caHierarchy.workspace.externalExpected")} <span className="font-mono text-xs">{externalCAError}</span>
            </p>
          ) : (
            <UnavailableState title={t("caHierarchy.externalRegistryUnavailableTitle")}>{externalCAError}</UnavailableState>
          ))}

        {!showOverviewInventory ? (
          <EmptyState title={t("caHierarchy.discovery.emptyTitle")}>{t("caHierarchy.discovery.emptyBody")}</EmptyState>
        ) : (
          <>
            <ServedAuthoritiesPanel authorities={authorities} error={authoritiesError} loading={loading} onShowDetail={setAuthorityDetail} />
            <details id="ca-discovery-details" className="group border-y border-border py-4">
              <summary className="cursor-pointer font-medium text-foreground">{t("caHierarchy.workspace.discoveryDetails")}</summary>
              <div className="mt-4">
                <CADiscoveryInventoryPanel inventory={caDiscovery} />
              </div>
            </details>
            <details id="ca-issuance-details" className="group border-y border-border py-4">
              <summary className="cursor-pointer font-medium text-foreground">{t("caHierarchy.workspace.issuanceDetails")}</summary>
              <div className="mt-4">
                <CAOverview issuers={sortedIssuers} profiles={profiles} />
              </div>
            </details>
          </>
        )}
      </div>

      <div {...tabPanelProps("ca", "authorities")} className={tab === "authorities" ? "grid gap-6" : "hidden"}>
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" onClick={() => setCreateAuthorityKind("root")}>
            <Plus className="h-4 w-4" aria-hidden="true" />
            {t("parity.createRootCa_94fb33")}
          </Button>
          <Button type="button" variant="outline" onClick={() => setCreateAuthorityKind("intermediate")}>
            <Plus className="h-4 w-4" aria-hidden="true" />
            {t("parity.createIntermediateCa_829ab7")}
          </Button>
        </div>
        <IssuerCatalog onConfigure={(type) => setIssuerDialogType(type)} />
      </div>

      <div className={tab === "authorities" ? undefined : "hidden"}>
        {/* B6: the delegated edge sub-CA lives beside the authorities it hangs
            from — the one bounded exception to in-signer signing, shown with
            its bounds. */}
        <EdgeDelegationsPanel />
      </div>

      <div className={tab === "authorities" ? undefined : "hidden"}>
        <ExternalCAIssuancePanel
          busy={externalIssueBusy}
          error={externalIssueError}
          form={externalIssueForm}
          inventory={caDiscovery}
          result={externalIssueResult}
          onChange={(patch) => setExternalIssueForm((current) => ({ ...current, ...patch }))}
          onIssue={() => void issueExternalCA()}
        />
      </div>

      <div {...tabPanelProps("ca", "lifecycle")} className={tab === "lifecycle" ? undefined : "hidden"}>
        {/* H4: retirement is the end of the lifecycle, so it lives on the
            lifecycle tab beside rotation. Only signer-backed authorities which
            are already superseded or revoked can be selected; the backend
            independently enforces the same terminal precondition. */}
        <RetirementWorkspace candidates={retirementCandidates} />
        <CARotationPanel
          busy={rotationBusy}
          error={rotationError}
          inventory={caDiscovery}
          predecessorID={rotationPredecessorID}
          reason={rotationReason}
          result={rotationResult}
          successorID={rotationSuccessorID}
          onActivate={() => void activateCARotation()}
          onPredecessorChange={setRotationPredecessorID}
          onReasonChange={setRotationReason}
          onSuccessorChange={setRotationSuccessorID}
        />
      </div>

      <div className={tab === "lifecycle" ? undefined : "hidden"}>
        <CARekeyPanel
          authorityID={rekeyAuthorityID}
          busy={rekeyBusy}
          ceremonyID={rekeyCeremonyID}
          error={rekeyError}
          inventory={caDiscovery}
          reason={rekeyReason}
          result={rekeyResult}
          ttlDays={rekeyTTLDays}
          onActivate={() => void activateCARekey()}
          onAuthorityChange={setRekeyAuthorityID}
          onCeremonyChange={setRekeyCeremonyID}
          onReasonChange={setRekeyReason}
          onStartCeremony={() => void startCARekeyCeremony()}
          onTTLChange={setRekeyTTLDays}
        />
      </div>

      {probe && (
        <div className={tab === "authorities" ? undefined : "hidden"}>
          <ProbeBanner probe={probe} onDismiss={() => setProbe(null)} />
        </div>
      )}

      <section aria-labelledby="issuer-heading" className={tab === "authorities" ? "grid gap-3 border-y border-border py-4" : "hidden"}>
        <div className="flex items-start gap-3">
          <ShieldCheck className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="issuer-heading" className="text-title font-semibold">
              {translateNow("source.issuer.visibility.859e72db07")}
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.this.view.shows.issuer.name.kind.public.ke.5166a2828e")}</p>
          </div>
        </div>
        {loading && <LoadingState>{translateNow("source.loading.issuers.98644f83a7")}</LoadingState>}
        {renderNotice(notice)}
        {!loading && !notice && sortedIssuers.length === 0 && (
          <EmptyState
            icon={<Server className="h-5 w-5" aria-hidden="true" />}
            title={translateNow("source.no.issuers.yet.fc838bfd4a")}
            primaryAction={{
              label: translateNow("source.connect.first.issuer.ba893ce98c"),
              onClick: () => {
                const firstIssuerType = issuerTypes.find((type) => !type.internal) ?? issuerTypes[0];
                if (firstIssuerType) setIssuerDialogType(firstIssuerType);
              },
              icon: <Plus className="h-4 w-4" />,
            }}
            secondaryAction={{ label: translateNow("source.create.a.profile.6d7beeefb5"), to: "/profiles", icon: <ShieldCheck className="h-4 w-4" /> }}
          >
            {translateNow("source.add.a.local.authority.or.upstream.ca.befor.ef39bb7995")}
          </EmptyState>
        )}
        {!loading && !notice && sortedIssuers.length > 0 && (
          <IssuerTable
            issuers={sortedIssuers}
            capabilities={capabilities}
            externalCAs={externalCARegistry}
            probe={probe}
            onTestConnection={(issuer) => void testIssuerConnection(issuer)}
          />
        )}
      </section>

      <section aria-labelledby="ceremony-heading" className={tab === "lifecycle" ? "grid gap-3 border-y border-border py-4" : "hidden"}>
        <div className="flex items-start gap-3">
          <FileKey2 className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="ceremony-heading" className="text-title font-semibold">
              {translateNow("source.ca.key.ceremony.244faa4ab3")}
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.start.a.root.ca.ceremony.then.record.a.sec.da658d7848")}</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" onClick={() => void startRootCeremony()} disabled={ceremonyBusy}>
            {translateNow("source.start.root.ceremony.01836ae713")}
          </Button>
          <span className="text-sm text-muted-foreground">{translateNow("source.default.request.trust.root.ca.2.approvals.246b100b12")}</span>
        </div>
        {ceremonyError && <ErrorState title={translateNow("source.ceremony.action.failed.974d5f2180")}>{ceremonyError}</ErrorState>}
        {ceremony ? (
          <CeremonyPanel ceremony={ceremony} busy={ceremonyBusy} onApprove={(id) => void approveCeremony(id)} onView={(id) => void viewCeremony(id)} />
        ) : (
          <EmptyState title={translateNow("source.no.ceremony.loaded.3e9d28986c")}>
            {translateNow("source.start.a.ceremony.to.see.its.purpose.approv.9f9d9ee9fd")}
          </EmptyState>
        )}
      </section>

      <div {...tabPanelProps("ca", "imports")} className={tab === "imports" ? undefined : "hidden"}>
        <OfflineRootWorkflow
          busy={offlineBusy}
          error={offlineError}
          intermediate={offlineIntermediate}
          intermediateCeremonyID={offlineIntermediateCeremonyID}
          intermediateForm={offlineIntermediateForm}
          offlineCSR={offlineCSR}
          root={offlineRoot}
          rootCeremonyID={offlineRootCeremonyID}
          rootForm={offlineRootForm}
          onCreateCSR={() => void createOfflineIntermediateCSR()}
          onImportIntermediate={() => void importOfflineIntermediate()}
          onImportRoot={() => void importOfflineRoot()}
          onIntermediateCeremonyIDChange={setOfflineIntermediateCeremonyID}
          onIntermediateFormChange={(patch) => setOfflineIntermediateForm((current) => ({ ...current, ...patch }))}
          onRootCeremonyIDChange={setOfflineRootCeremonyID}
          onRootFormChange={(patch) => setOfflineRootForm((current) => ({ ...current, ...patch }))}
          onStartIntermediateCeremony={() => void startOfflineIntermediateCeremony()}
          onStartRootCeremony={() => void startOfflineRootCeremony()}
        />
      </div>

      <div className={tab === "imports" ? undefined : "hidden"}>
        <ExistingCAImportWorkflow
          busy={existingCABusy}
          ceremonyID={existingCACeremonyID}
          error={existingCAError}
          form={existingCAForm}
          imported={existingCA}
          onCeremonyIDChange={setExistingCACeremonyID}
          onFormChange={(patch) => setExistingCAForm((current) => ({ ...current, ...patch }))}
          onImport={() => void importExistingCA()}
          onStartCeremony={() => void startExistingCACeremony()}
        />
      </div>

      <section {...tabPanelProps("ca", "custody")} className={tab === "custody" ? "grid gap-3 border-y border-border py-4" : "hidden"}>
        <div className="flex items-start gap-3">
          <KeyRound className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="custody-heading" className="text-title font-semibold">
              {translateNow("source.managed.key.custody.ba98c44d9c")}
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.aws.kms.azure.key.vault.hsm.gcp.cloud.kms.957ee3c57b")}</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" onClick={() => void generateManagedKey()} disabled={keyBusy}>
            {translateNow("source.generate.managed.key.9ff7b150a0")}
          </Button>
          <span className="text-sm text-muted-foreground">{translateNow("source.default.algorithm.ecdsa.p256.e268f7deba")}</span>
        </div>
        {keyError && <ErrorState title={translateNow("source.managed.key.action.failed.934f359a98")}>{keyError}</ErrorState>}
        {managedKey ? (
          <ManagedKeyPanel managedKey={managedKey} busy={keyBusy} onAction={(action, keyId) => void runManagedKeyAction(action, keyId)} />
        ) : (
          <EmptyState title={translateNow("source.no.managed.key.loaded.c921eb07f2")}>
            {translateNow("source.generate.a.managed.key.to.inspect.its.publ.0756dcae94")}
          </EmptyState>
        )}
      </section>

      {issuerDialogType && (
        <CreateIssuerDialog
          type={issuerDialogType}
          busy={issuerBusy}
          error={issuerError}
          onClose={() => {
            setIssuerDialogType(null);
            setIssuerError(null);
          }}
          onSubmit={(name, chainPEM) => void createIssuerFromCatalog(issuerDialogType, name, chainPEM)}
        />
      )}

      {createAuthorityKind && (
        <CreateAuthorityDialog
          kind={createAuthorityKind}
          parents={authorityParents}
          onClose={() => setCreateAuthorityKind(null)}
          onCreated={handleAuthorityCreated}
        />
      )}
      {leafTarget && <IssueLeafDialog authority={leafTarget} onClose={() => setLeafTarget(null)} />}
      {signTarget && <SignIntermediateCSRDialog authority={signTarget} onClose={() => setSignTarget(null)} />}
      {authorityDetail && (
        <AuthorityDetailDialog
          authority={authorityDetail}
          onClose={() => setAuthorityDetail(null)}
          onIssueLeaf={() => {
            setAuthorityDetail(null);
            setLeafTarget(authorityDetail);
          }}
          onSignCSR={() => {
            setAuthorityDetail(null);
            setSignTarget(authorityDetail);
          }}
        />
      )}
      {ceremonyReview && (
        <CACeremonyReviewDialog
          busy={ceremonyReviewBusy}
          error={ceremonyReviewError}
          preview={ceremonyReview.preview}
          onClose={() => {
            if (ceremonyReviewBusy) return;
            setCeremonyReview(null);
            setCeremonyReviewError(null);
          }}
          onConfirm={() => void confirmCeremonyReview()}
        />
      )}
      {rotationReview && (
        <CARotationReviewDialog
          busy={rotationBusy}
          error={rotationReviewError}
          preview={rotationReview.preview}
          onClose={() => {
            if (rotationBusy) return;
            setRotationReview(null);
            setRotationReviewError(null);
          }}
          onConfirm={() => void confirmCARotation()}
        />
      )}
      {ceremonyDetail && <CeremonyDetailDialog ceremony={ceremonyDetail} onClose={() => setCeremonyDetail(null)} />}
    </section>
  );
}

function CAWorkspaceOverview({
  authorities,
  authoritiesError,
  ceremony,
  discovery,
  loading,
  managedKey,
  onRefresh,
}: {
  authorities: CAAuthority[];
  authoritiesError: string | null;
  ceremony: CAKeyCeremony | null;
  discovery: CADiscovery | null;
  loading: boolean;
  managedKey: ManagedKey | null;
  onRefresh: () => void;
}) {
  const { t } = useTranslation();
  const roots = authorities.filter((authority) => !authority.parent_id).length;
  const intermediates = Math.max(authorities.length - roots, 0);
  const health = loading
    ? t("caHierarchy.workspace.healthLoading")
    : authoritiesError
      ? t("caHierarchy.workspace.healthUnavailable")
      : t("caHierarchy.workspace.healthReady", { count: authorities.length });
  const lineage = t("caHierarchy.workspace.lineageSummary", {
    roots,
    intermediates,
    discovered: discovery?.summary.authority_count ?? authorities.length,
  });
  const custody = managedKey
    ? t("caHierarchy.workspace.custodyLoaded", { algorithm: managedKey.algorithm, version: managedKey.version, state: managedKey.state })
    : t("caHierarchy.workspace.custodyEmpty");
  const pending = ceremony
    ? t("caHierarchy.workspace.pendingCeremony", { status: ceremony.status, approvals: ceremony.approvals, threshold: ceremony.threshold })
    : t("caHierarchy.workspace.pendingEmpty");

  return (
    <section aria-label={t("caHierarchy.workspace.overviewLabel")} className="grid gap-4 border-y border-border py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-title font-semibold">{t("caHierarchy.workspace.authorityHealth")}</h2>
          <p className="mt-1 text-sm text-muted-foreground">{health}</p>
        </div>
        <Button type="button" variant="ghost" size="sm" onClick={onRefresh} disabled={loading}>
          <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
          {t("caHierarchy.workspace.refresh")}
        </Button>
      </div>
      <dl className="grid gap-4 text-sm md:grid-cols-3">
        <div>
          <dt className="font-medium text-foreground">{t("caHierarchy.workspace.lineage")}</dt>
          <dd className="mt-1 text-muted-foreground">{lineage}</dd>
        </div>
        <div>
          <dt className="font-medium text-foreground">{t("caHierarchy.workspace.custody")}</dt>
          <dd className="mt-1 text-muted-foreground">{custody}</dd>
        </div>
        <div>
          <dt className="font-medium text-foreground">{t("caHierarchy.workspace.pendingActions")}</dt>
          <dd className="mt-1 text-muted-foreground">{pending}</dd>
        </div>
      </dl>
    </section>
  );
}

function CADiscoveryInventoryPanel({ inventory }: { inventory: CADiscovery | null }) {
  const { t } = useTranslation();
  if (!inventory) return null;
  const items = inventory.items ?? [];
  return (
    <section aria-labelledby="ca-discovery-heading" className="grid gap-3 border-y border-border py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <Globe2 className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="ca-discovery-heading" className="text-title font-semibold">
              {t("caHierarchy.discovery.heading")}
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("caHierarchy.discovery.description")}</p>
          </div>
        </div>
        <dl className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
          <SummaryPill label={t("caHierarchy.discovery.summaryPublic")} value={inventory.summary.public_count} />
          <SummaryPill label={t("caHierarchy.discovery.summaryPrivate")} value={inventory.summary.private_count} />
          <SummaryPill label={t("caHierarchy.discovery.summaryUpstream")} value={inventory.summary.external_registry_count} />
          <SummaryPill label={t("caHierarchy.discovery.summaryAuthorities")} value={inventory.summary.authority_count} />
        </dl>
      </div>
      {items.length === 0 ? (
        <EmptyState title={t("caHierarchy.discovery.emptyTitle")}>{t("caHierarchy.discovery.emptyBody")}</EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-control border border-border">
          <table className="min-w-full divide-y divide-border text-sm">
            <thead className="bg-muted/40 text-left text-xs text-muted-foreground">
              <tr>
                <th className="px-3 py-2 font-medium">{t("caHierarchy.discovery.columnName")}</th>
                <th className="px-3 py-2 font-medium">{t("caHierarchy.discovery.columnScope")}</th>
                <th className="px-3 py-2 font-medium">{t("caHierarchy.discovery.columnSource")}</th>
                <th className="px-3 py-2 font-medium">{t("caHierarchy.discovery.columnStatus")}</th>
                <th className="px-3 py-2 font-medium">{t("caHierarchy.discovery.columnServedPath")}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border bg-background">
              {items.map((item) => (
                <tr key={item.id}>
                  <td className="px-3 py-2 align-top">
                    <div className="font-medium">{item.name}</div>
                    <div className="font-mono text-xs text-muted-foreground">{item.source_id}</div>
                  </td>
                  <td className="px-3 py-2 align-top">
                    {item.scope === "public" ? t("caHierarchy.discovery.scopePublic") : t("caHierarchy.discovery.scopePrivate")}
                  </td>
                  <td className="px-3 py-2 align-top">{caDiscoverySourceLabel(item.source, t)}</td>
                  <td className="px-3 py-2 align-top">
                    {item.status}
                    {item.managed && <span className="ml-2 text-xs text-muted-foreground">{t("caHierarchy.discovery.signerBacked")}</span>}
                  </td>
                  <td className="px-3 py-2 align-top font-mono text-xs text-muted-foreground break-all">
                    {item.issuance_path || item.import_path || item.inventory_path}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ExternalCAIssuancePanel({
  busy,
  error,
  form,
  inventory,
  onChange,
  onIssue,
  result,
}: {
  busy: boolean;
  error: string | null;
  form: ExternalCAIssueForm;
  inventory: CADiscovery | null;
  result: ExternalCAIssueResult | null;
  onChange: (patch: Partial<ExternalCAIssueForm>) => void;
  onIssue: () => void;
}) {
  const { t } = useTranslation();
  if (!inventory) return null;
  const externalCAs = (inventory.items ?? []).filter((item) => item.source === "external_ca_registry" && item.issuance_path);
  const selected = externalCAs.find((item) => item.source_id === form.caID);
  const ready = form.caID.trim() !== "" && form.commonName.trim() !== "" && form.csrPEM.trim() !== "" && externalCAIssueDNSNames(form).length > 0;

  return (
    <section aria-labelledby="external-ca-issue-heading" className="grid gap-3 border-y border-border py-4">
      <div className="flex items-start gap-3">
        <Cloud className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="external-ca-issue-heading" className="text-title font-semibold">
            {t("caHierarchy.externalIssue.heading")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("caHierarchy.externalIssue.description")}</p>
        </div>
      </div>
      {error && <ErrorState title={t("caHierarchy.externalIssue.errorTitle")}>{error}</ErrorState>}
      {externalCAs.length === 0 ? (
        <EmptyState title={t("caHierarchy.externalIssue.emptyTitle")}>{t("caHierarchy.externalIssue.emptyBody")}</EmptyState>
      ) : (
        <section aria-labelledby="external-ca-issue-form-heading" className="ui-panel p-comfortable text-sm">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 id="external-ca-issue-form-heading" className="text-title font-semibold">
                {t("caHierarchy.externalIssue.formHeading")}
              </h3>
              {selected?.issuance_path && <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{selected.issuance_path}</p>}
            </div>
            <Button type="button" size="sm" onClick={onIssue} disabled={busy || !ready}>
              <FileKey2 className={busy ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
              {t("caHierarchy.externalIssue.submit")}
            </Button>
          </div>
          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <LabeledSelect
              id="external-ca-issue-ca"
              label={t("caHierarchy.externalIssue.caLabel")}
              value={form.caID}
              onChange={(value) => onChange({ caID: value })}
            >
              <option value="">{t("caHierarchy.externalIssue.caPlaceholder")}</option>
              {externalCAs.map((item) => (
                <option key={item.id} value={item.source_id}>
                  {item.name} ({item.type}, {item.status})
                </option>
              ))}
            </LabeledSelect>
            <LabeledInput
              id="external-ca-common-name"
              label={t("caHierarchy.externalIssue.commonNameLabel")}
              value={form.commonName}
              required
              onChange={(value) => onChange({ commonName: value })}
            />
            <LabeledInput
              id="external-ca-dns-names"
              label={t("caHierarchy.externalIssue.dnsNamesLabel")}
              value={form.dnsNames}
              required
              onChange={(value) => onChange({ dnsNames: value })}
              placeholder={t("caHierarchy.externalIssue.dnsNamesPlaceholder")}
            />
            <LabeledInput
              id="external-ca-profile-name"
              label={t("caHierarchy.externalIssue.profileLabel")}
              value={form.profileName}
              onChange={(value) => onChange({ profileName: value })}
              placeholder={t("caHierarchy.externalIssue.profilePlaceholder")}
            />
            <LabeledInput
              id="external-ca-ttl-days"
              label={t("caHierarchy.externalIssue.ttlLabel")}
              value={form.ttlDays}
              type="number"
              onChange={(value) => onChange({ ttlDays: value })}
            />
            <LabeledTextarea
              id="external-ca-csr-pem"
              label={t("caHierarchy.externalIssue.csrLabel")}
              value={form.csrPEM}
              required
              rows={5}
              onChange={(value) => onChange({ csrPEM: value })}
              placeholder={t("caHierarchy.externalIssue.csrPlaceholder")}
            />
          </div>
          {result && (
            <section aria-labelledby="external-ca-issue-status-heading" className="mt-4 rounded-control border border-border p-3" role="status">
              <h4 id="external-ca-issue-status-heading" className="text-sm font-semibold">
                {t("caHierarchy.externalIssue.statusHeading")}
              </h4>
              <dl className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <KeyValue
                  label={t("caHierarchy.externalIssue.stateLabel")}
                  value={
                    result.state === "outbox-pending"
                      ? t("caHierarchy.externalIssue.state.outboxPending")
                      : t("caHierarchy.externalIssue.state.externalCAIssued")
                  }
                />
                <KeyValue label={t("caHierarchy.externalIssue.caLabel")} value={result.caID} mono />
                <KeyValue label={t("caHierarchy.externalIssue.pathLabel")} value={result.path} mono />
                {result.certificate && <KeyValue label={t("caHierarchy.externalIssue.serialLabel")} value={result.certificate.serial || "-"} mono />}
                {result.certificate && <KeyValue label={t("caHierarchy.externalIssue.issuerLabel")} value={result.certificate.issuer || "-"} />}
                {result.certificate && <KeyValue label={t("caHierarchy.externalIssue.notAfterLabel")} value={result.certificate.not_after || "-"} />}
              </dl>
            </section>
          )}
        </section>
      )}
    </section>
  );
}

function CARotationPanel({
  busy,
  error,
  inventory,
  predecessorID,
  reason,
  result,
  successorID,
  onActivate,
  onPredecessorChange,
  onReasonChange,
  onSuccessorChange,
}: {
  busy: boolean;
  error: string | null;
  inventory: CADiscovery | null;
  predecessorID: string;
  reason: string;
  result: CAAuthorityRotation | null;
  successorID: string;
  onActivate: () => void;
  onPredecessorChange: (value: string) => void;
  onReasonChange: (value: string) => void;
  onSuccessorChange: (value: string) => void;
}) {
  const authorities = (inventory?.items ?? []).filter((item) => item.source === "ca_hierarchy" && item.managed && item.issuance_path);
  const ready = predecessorID.trim() !== "" && successorID.trim() !== "" && predecessorID.trim() !== successorID.trim();

  return (
    <section aria-labelledby="ca-rotation-heading" className="grid gap-3 border-y border-border py-4">
      <div className="flex items-start gap-3">
        <RefreshCw className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="ca-rotation-heading" className="text-title font-semibold">
            {translateNow("source.ca.rotation.27b00eaa0b")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.activate.an.existing.signer.backed.success.ba9399274b")}</p>
        </div>
      </div>
      {error && <ErrorState title={translateNow("source.ca.rotation.failed.e781fb6f5f")}>{error}</ErrorState>}
      <section aria-labelledby="ca-rotation-form-heading" className="ui-panel p-comfortable text-sm">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 id="ca-rotation-form-heading" className="text-title font-semibold">
              {translateNow("source.successor.activation.2c89a6285d")}
            </h3>
            {result && <p className="mt-1 font-mono text-xs">{result.issue_path}</p>}
          </div>
          <Button type="button" size="sm" onClick={onActivate} disabled={busy || !ready}>
            <RefreshCw className={busy ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
            {translateNow("source.activate.ca.rotation.a7d096d68f")}
          </Button>
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-3">
          <LabeledSelect id="ca-rotation-predecessor" label="Predecessor CA" value={predecessorID} onChange={onPredecessorChange}>
            <option value="">{translateNow("source.select.predecessor.ec02008346")}</option>
            {authorities.map((item) => (
              <option key={item.id} value={item.source_id}>
                {item.name} ({item.status})
              </option>
            ))}
          </LabeledSelect>
          <LabeledSelect id="ca-rotation-successor" label="Successor CA" value={successorID} onChange={onSuccessorChange}>
            <option value="">{translateNow("source.select.successor.ea343d0bff")}</option>
            {authorities.map((item) => (
              <option key={item.id} value={item.source_id}>
                {item.name} ({item.status})
              </option>
            ))}
          </LabeledSelect>
          <LabeledInput id="ca-rotation-reason" label="Rotation reason" value={reason} onChange={onReasonChange} />
        </div>
        {authorities.length < 2 && (
          <p className="mt-3 text-sm text-muted-foreground">{translateNow("source.create.a.signer.backed.successor.before.ac.c0163adb05")}</p>
        )}
        {result && (
          <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <KeyValue label="Predecessor" value={`${result.predecessor.common_name} (${result.predecessor.status})`} />
            <KeyValue label="Successor" value={`${result.successor.common_name} (${result.successor.status})`} />
            <KeyValue label="Stable issue URL" value={result.issue_path} mono />
            <KeyValue label="Active issue URL" value={result.active_issue_path} mono />
          </dl>
        )}
      </section>
    </section>
  );
}

function CARekeyPanel({
  authorityID,
  busy,
  ceremonyID,
  error,
  inventory,
  reason,
  result,
  ttlDays,
  onActivate,
  onAuthorityChange,
  onCeremonyChange,
  onReasonChange,
  onStartCeremony,
  onTTLChange,
}: {
  authorityID: string;
  busy: boolean;
  ceremonyID: string;
  error: string | null;
  inventory: CADiscovery | null;
  reason: string;
  result: CAAuthorityRotation | null;
  ttlDays: string;
  onActivate: () => void;
  onAuthorityChange: (value: string) => void;
  onCeremonyChange: (value: string) => void;
  onReasonChange: (value: string) => void;
  onStartCeremony: () => void;
  onTTLChange: (value: string) => void;
}) {
  const { t } = useTranslation();
  const authorities = (inventory?.items ?? []).filter(
    (item) => item.source === "ca_hierarchy" && item.managed && item.issuance_path && item.status === "active",
  );
  const readyToStart = authorityID.trim() !== "";
  const readyToRekey = readyToStart && ceremonyID.trim() !== "";

  return (
    <section aria-labelledby="ca-rekey-heading" className="grid gap-3 border-b border-border py-4">
      <div className="flex items-start gap-3">
        <KeyRound className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="ca-rekey-heading" className="text-title font-semibold">
            {translateNow("source.ca.renewal.and.re.key.fb27d9e180")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.mint.a.fresh.signer.backed.ca.key.and.cert.4f35946ce6")}</p>
        </div>
      </div>
      {error && <ErrorState title={translateNow("source.ca.re.key.failed.c94515c43b")}>{error}</ErrorState>}
      <section aria-labelledby="ca-rekey-form-heading" className="ui-panel p-comfortable text-sm">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 id="ca-rekey-form-heading" className="text-title font-semibold">
              {translateNow("source.fresh.ca.material.d1a53a627a")}
            </h3>
            {result && <p className="mt-1 font-mono text-xs">{result.active_issue_path}</p>}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" variant="outline" onClick={onStartCeremony} disabled={busy || !readyToStart}>
              <FileKey2 className={busy ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
              {translateNow("source.start.re.key.ceremony.c2e02a1a0c")}
            </Button>
            <Button type="button" size="sm" onClick={onActivate} disabled={busy || !readyToRekey}>
              <KeyRound className={busy ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
              {translateNow("source.re.key.ca.4aadf37c7a")}
            </Button>
          </div>
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-4">
          <LabeledSelect id="ca-rekey-authority" label="CA authority" value={authorityID} onChange={onAuthorityChange}>
            <option value="">{translateNow("source.select.authority.b2858bf4f3")}</option>
            {authorities.map((item) => (
              <option key={item.id} value={item.source_id}>
                {item.name} ({item.status})
              </option>
            ))}
          </LabeledSelect>
          <LabeledInput id="ca-rekey-ceremony" label={t("parity.ceremonyId_6f8ee6")} value={ceremonyID} onChange={onCeremonyChange} />
          <LabeledInput id="ca-rekey-ttl" label="Validity days" value={ttlDays} type="number" onChange={onTTLChange} />
          <LabeledInput id="ca-rekey-reason" label="Re-key reason" value={reason} onChange={onReasonChange} />
        </div>
        {authorities.length === 0 && (
          <p className="mt-3 text-sm text-muted-foreground">{translateNow("source.create.or.import.a.signer.backed.authority.938d8e0658")}</p>
        )}
        {result && (
          <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <KeyValue label="Predecessor" value={`${result.predecessor.common_name} (${result.predecessor.status})`} />
            <KeyValue label="Fresh successor" value={`${result.successor.common_name} (${result.successor.status})`} />
            <KeyValue label="Stable issue URL" value={result.issue_path} mono />
            <KeyValue label="Active issue URL" value={result.active_issue_path} mono />
          </dl>
        )}
      </section>
    </section>
  );
}

function LabeledSelect({
  children,
  id,
  label,
  onChange,
  value,
}: {
  children: ReactNode;
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="grid gap-2">
      <label className="text-sm font-medium" htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-control border border-border bg-background px-3 py-2 outline-none transition-colors focus:border-focus focus:ring-2 focus:ring-focus/20"
      >
        {children}
      </select>
    </div>
  );
}

function SummaryPill({ label, value }: { label: string; value: number }) {
  return (
    <div className="border-s border-border ps-3">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="text-base font-semibold">{value}</dd>
    </div>
  );
}

function caDiscoverySourceLabel(source: string, t: ReturnType<typeof useTranslation>["t"]) {
  switch (source) {
    case "external_ca_registry":
      return t("caHierarchy.discovery.sourceExternal");
    case "ca_hierarchy":
      return t("caHierarchy.discovery.sourceHierarchy");
    default:
      return source;
  }
}

function ExistingCAImportWorkflow({
  busy,
  ceremonyID,
  error,
  form,
  imported,
  onCeremonyIDChange,
  onFormChange,
  onImport,
  onStartCeremony,
}: {
  busy: boolean;
  ceremonyID: string;
  error: string | null;
  form: ExistingCAForm;
  imported: CAAuthority | null;
  onCeremonyIDChange: (value: string) => void;
  onFormChange: (patch: Partial<ExistingCAForm>) => void;
  onImport: () => void;
  onStartCeremony: () => void;
}) {
  const { t } = useTranslation();
  const ready = form.certificatePEM.trim() !== "" && form.commonName.trim() !== "" && form.signerHandle.trim() !== "";
  const importReady = ready && ceremonyID.trim() !== "";

  return (
    <section aria-labelledby="existing-ca-import-heading" className="grid gap-3 border-y border-border py-4">
      <div className="flex items-start gap-3">
        <ShieldCheck className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="existing-ca-import-heading" className="text-title font-semibold">
            {t("caHierarchy.existing.heading")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("caHierarchy.existing.description")}</p>
        </div>
      </div>
      {error && <ErrorState title={t("caHierarchy.existing.errorTitle")}>{error}</ErrorState>}
      <section aria-labelledby="existing-ca-form-heading" className="ui-panel p-comfortable text-sm">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 id="existing-ca-form-heading" className="text-title font-semibold">
              {t("caHierarchy.existing.formHeading")}
            </h3>
            {imported && <p className="mt-1 font-mono text-xs">{imported.id}</p>}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" variant="outline" onClick={onStartCeremony} disabled={busy || !ready}>
              {t("caHierarchy.existing.startCeremony")}
            </Button>
            <Button type="button" size="sm" onClick={onImport} disabled={busy || !importReady}>
              {t("caHierarchy.existing.import")}
            </Button>
          </div>
        </div>
        <div className="mt-4 grid gap-4">
          <OfflineSpecFields
            commonNameId="existing-ca-common-name"
            dnsDomainsId="existing-ca-dns-domains"
            form={form}
            maxPathLenId="existing-ca-max-path-len"
            onChange={onFormChange}
            ttlDaysId="existing-ca-ttl-days"
          />
          <LabeledInput
            id="existing-ca-signer-handle"
            label={t("caHierarchy.offline.signerHandle")}
            value={form.signerHandle}
            required
            onChange={(value) => onFormChange({ signerHandle: value })}
            placeholder={t("caHierarchy.existing.placeholderSignerHandle")}
          />
          <div className="grid gap-2">
            <label className="text-sm font-medium" htmlFor="existing-ca-chain">
              {t("caHierarchy.existing.chainPEM")}
            </label>
            <textarea
              id="existing-ca-chain"
              rows={6}
              value={form.certificatePEM}
              onChange={(event) => onFormChange({ certificatePEM: event.target.value })}
              className="min-h-36 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs outline-none transition-colors placeholder:text-muted-foreground focus:border-focus focus:ring-2 focus:ring-focus/20"
              placeholder={t("caHierarchy.offline.placeholderCertificate")}
            />
          </div>
          <LabeledInput
            id="existing-ca-ceremony-id"
            label={t("caHierarchy.existing.ceremonyID")}
            value={ceremonyID}
            onChange={onCeremonyIDChange}
            placeholder={t("caHierarchy.existing.placeholderCeremonyID")}
          />
          {imported && (
            <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <KeyValue label={t("caHierarchy.offline.commonName")} value={imported.common_name} />
              <KeyValue label={t("caHierarchy.existing.kind")} value={imported.kind} />
              <KeyValue label={t("caHierarchy.offline.signerHandle")} value={imported.signer_handle || "-"} mono />
              <KeyValue label={t("caHierarchy.existing.serial")} value={imported.serial || "-"} mono />
            </dl>
          )}
        </div>
      </section>
    </section>
  );
}

function OfflineRootWorkflow({
  busy,
  error,
  intermediate,
  intermediateCeremonyID,
  intermediateForm,
  offlineCSR,
  onCreateCSR,
  onImportIntermediate,
  onImportRoot,
  onIntermediateCeremonyIDChange,
  onIntermediateFormChange,
  onRootCeremonyIDChange,
  onRootFormChange,
  onStartIntermediateCeremony,
  onStartRootCeremony,
  root,
  rootCeremonyID,
  rootForm,
}: {
  busy: boolean;
  error: string | null;
  intermediate: CAAuthority | null;
  intermediateCeremonyID: string;
  intermediateForm: OfflineIntermediateForm;
  offlineCSR: CAIntermediateCSR | null;
  root: CAAuthority | null;
  rootCeremonyID: string;
  rootForm: OfflineCAForm;
  onCreateCSR: () => void;
  onImportIntermediate: () => void;
  onImportRoot: () => void;
  onIntermediateCeremonyIDChange: (value: string) => void;
  onIntermediateFormChange: (patch: Partial<OfflineIntermediateForm>) => void;
  onRootCeremonyIDChange: (value: string) => void;
  onRootFormChange: (patch: Partial<OfflineCAForm>) => void;
  onStartIntermediateCeremony: () => void;
  onStartRootCeremony: () => void;
}) {
  const { t } = useTranslation();
  const rootReady = rootForm.certificatePEM.trim() !== "" && rootForm.commonName.trim() !== "";
  const rootImportReady = rootReady && rootCeremonyID.trim() !== "";
  const parentID = intermediateForm.parentID.trim();
  const intermediateReady = parentID !== "" && intermediateForm.commonName.trim() !== "";
  const csrReady = intermediateReady && intermediateCeremonyID.trim() !== "";
  const importIntermediateReady = csrReady && intermediateForm.certificatePEM.trim() !== "";

  return (
    <section aria-labelledby="offline-root-heading" className="grid gap-3 border-y border-border py-4">
      <div className="flex items-start gap-3">
        <FileKey2 className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="offline-root-heading" className="text-title font-semibold">
            {t("caHierarchy.offline.heading")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("caHierarchy.offline.description")}</p>
        </div>
      </div>
      {error && <ErrorState title={t("caHierarchy.offline.errorTitle")}>{error}</ErrorState>}
      <div className="grid gap-4 xl:grid-cols-2">
        <section aria-labelledby="offline-root-import-heading" className="ui-panel p-comfortable text-sm">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 id="offline-root-import-heading" className="text-title font-semibold">
                {t("caHierarchy.offline.rootImport")}
              </h3>
              {root && <p className="mt-1 font-mono text-xs">{root.id}</p>}
            </div>
            <div className="flex flex-wrap gap-2">
              <Button type="button" size="sm" variant="outline" onClick={onStartRootCeremony} disabled={busy || !rootReady}>
                {t("caHierarchy.offline.startRootCeremony")}
              </Button>
              <Button type="button" size="sm" onClick={onImportRoot} disabled={busy || !rootImportReady}>
                {t("caHierarchy.offline.importRoot")}
              </Button>
            </div>
          </div>
          <div className="mt-4 grid gap-4">
            <OfflineSpecFields
              commonNameId="offline-root-common-name"
              dnsDomainsId="offline-root-dns-domains"
              maxPathLenId="offline-root-max-path-len"
              ttlDaysId="offline-root-ttl-days"
              form={rootForm}
              onChange={onRootFormChange}
            />
            <div className="grid gap-2">
              <label className="text-sm font-medium" htmlFor="offline-root-cert">
                {t("caHierarchy.offline.rootCertPEM")}
              </label>
              <textarea
                id="offline-root-cert"
                rows={5}
                value={rootForm.certificatePEM}
                onChange={(event) => onRootFormChange({ certificatePEM: event.target.value })}
                className="min-h-32 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs outline-none transition-colors placeholder:text-muted-foreground focus:border-focus focus:ring-2 focus:ring-focus/20"
                placeholder={t("caHierarchy.offline.placeholderCertificate")}
              />
            </div>
            <LabeledInput
              id="offline-root-ceremony-id"
              label={t("caHierarchy.offline.rootCeremonyID")}
              value={rootCeremonyID}
              onChange={onRootCeremonyIDChange}
              placeholder={t("caHierarchy.offline.placeholderCeremonyID")}
            />
            {root && (
              <dl className="grid gap-3 sm:grid-cols-2">
                <KeyValue label={t("caHierarchy.offline.commonName")} value={root.common_name} />
                <KeyValue label={t("caHierarchy.offline.signerHandle")} value={root.signer_handle || t("caHierarchy.offline.signerOffline")} mono />
              </dl>
            )}
          </div>
        </section>

        <section aria-labelledby="offline-intermediate-heading" className="ui-panel p-comfortable text-sm">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 id="offline-intermediate-heading" className="text-title font-semibold">
                {t("caHierarchy.offline.intermediate")}
              </h3>
              {intermediate && <p className="mt-1 font-mono text-xs">{intermediate.id}</p>}
            </div>
            <div className="flex flex-wrap gap-2">
              <Button type="button" size="sm" variant="outline" onClick={onStartIntermediateCeremony} disabled={busy || !intermediateReady}>
                {t("caHierarchy.offline.startIntermediateCeremony")}
              </Button>
              <Button type="button" size="sm" variant="outline" onClick={onCreateCSR} disabled={busy || !csrReady}>
                {t("caHierarchy.offline.generateCSR")}
              </Button>
              <Button type="button" size="sm" onClick={onImportIntermediate} disabled={busy || !importIntermediateReady}>
                {t("caHierarchy.offline.importIntermediate")}
              </Button>
            </div>
          </div>
          <div className="mt-4 grid gap-4">
            <LabeledInput
              id="offline-parent-authority-id"
              label={t("caHierarchy.offline.parentAuthorityID")}
              value={intermediateForm.parentID}
              onChange={(value) => onIntermediateFormChange({ parentID: value })}
              placeholder={t("caHierarchy.offline.placeholderAuthorityID")}
            />
            <OfflineSpecFields
              commonNameId="offline-intermediate-common-name"
              dnsDomainsId="offline-intermediate-dns-domains"
              maxPathLenId="offline-intermediate-max-path-len"
              ttlDaysId="offline-intermediate-ttl-days"
              form={intermediateForm}
              onChange={onIntermediateFormChange}
            />
            <LabeledInput
              id="offline-intermediate-ceremony-id"
              label={t("caHierarchy.offline.intermediateCeremonyID")}
              value={intermediateCeremonyID}
              onChange={onIntermediateCeremonyIDChange}
              placeholder={t("caHierarchy.offline.placeholderCeremonyID")}
            />
            {offlineCSR && (
              <div className="grid gap-2">
                <label className="text-sm font-medium" htmlFor="offline-intermediate-csr">
                  {t("caHierarchy.offline.signerCSRPEM")}
                </label>
                <textarea
                  id="offline-intermediate-csr"
                  readOnly
                  rows={5}
                  value={offlineCSR.csr_pem}
                  className="min-h-32 rounded-control border border-border bg-muted/40 px-3 py-2 font-mono text-xs outline-none"
                />
              </div>
            )}
            <div className="grid gap-2">
              <label className="text-sm font-medium" htmlFor="offline-intermediate-cert">
                {t("caHierarchy.offline.signedIntermediatePEM")}
              </label>
              <textarea
                id="offline-intermediate-cert"
                rows={5}
                value={intermediateForm.certificatePEM}
                onChange={(event) => onIntermediateFormChange({ certificatePEM: event.target.value })}
                className="min-h-32 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs outline-none transition-colors placeholder:text-muted-foreground focus:border-focus focus:ring-2 focus:ring-focus/20"
                placeholder={t("caHierarchy.offline.placeholderCertificate")}
              />
            </div>
            {intermediate && (
              <dl className="grid gap-3 sm:grid-cols-2">
                <KeyValue label={t("caHierarchy.offline.commonName")} value={intermediate.common_name} />
                <KeyValue label={t("caHierarchy.offline.signerHandle")} value={intermediate.signer_handle || "-"} mono />
              </dl>
            )}
          </div>
        </section>
      </div>
    </section>
  );
}

function OfflineSpecFields({
  commonNameId,
  dnsDomainsId,
  form,
  maxPathLenId,
  onChange,
  ttlDaysId,
}: {
  commonNameId: string;
  dnsDomainsId: string;
  form: OfflineCAForm;
  maxPathLenId: string;
  onChange: (patch: Partial<OfflineCAForm>) => void;
  ttlDaysId: string;
}) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-4 md:grid-cols-2">
      <LabeledInput
        id={commonNameId}
        label={t("caHierarchy.offline.commonName")}
        value={form.commonName}
        required
        onChange={(value) => onChange({ commonName: value })}
      />
      <LabeledInput
        id={dnsDomainsId}
        label={t("caHierarchy.offline.permittedDNSDomains")}
        value={form.dnsDomains}
        onChange={(value) => onChange({ dnsDomains: value })}
        placeholder={t("caHierarchy.offline.placeholderDNSDomain")}
      />
      <LabeledInput
        id={maxPathLenId}
        label={t("caHierarchy.offline.maxPathLen")}
        value={form.maxPathLen}
        required
        type="number"
        onChange={(value) => onChange({ maxPathLen: value })}
      />
      <LabeledInput
        id={ttlDaysId}
        label={t("caHierarchy.offline.ttlDays")}
        value={form.ttlDays}
        required
        type="number"
        onChange={(value) => onChange({ ttlDays: value })}
      />
    </div>
  );
}

function ServedAuthoritiesPanel({
  authorities,
  error,
  loading,
  onShowDetail,
}: {
  authorities: CAAuthority[];
  error: string | null;
  loading: boolean;
  onShowDetail: (authority: CAAuthority) => void;
}) {
  const columns = useMemo<Array<DataGridColumn<CAAuthority>>>(
    () => [
      {
        id: "common_name",
        header: "Common name",
        sortable: true,
        cell: (authority) => <span className="font-medium">{authority.common_name}</span>,
      },
      { id: "kind", header: "Kind", cell: (authority) => authority.kind },
      { id: "status", header: "Status", cell: (authority) => <StatusBadge vocabulary="certificate" value={authority.status} /> },
      // H5: the band, not the raw date. A root 30 months out reads as fine
      // against a leaf yardstick and is already late against its own.
      { id: "horizon", header: translateNow("source.expiry.horizon.191bec0761"), cell: (authority) => <CAHorizonBadge authority={authority} /> },
      { id: "renew_by", header: translateNow("source.renew.or.re.key.by.00be37d4f2"), cell: (authority) => <CAHorizonRenewBy authority={authority} /> },
    ],
    [],
  );

  const { t } = useTranslation();

  return (
    <section aria-labelledby="served-authorities-heading" className="grid gap-3 border-y border-border py-4">
      <div className="flex items-start gap-3">
        <ShieldCheck className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="served-authorities-heading" className="text-title font-semibold">
            {t("parity.servedAuthorities_52df47")}
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("parity.signerBackedRootsAndIntermediatesThis_957f38")}</p>
        </div>
      </div>
      <DataGrid
        ariaLabel="Served CA authorities"
        rows={authorities}
        columns={columns}
        getRowId={(authority) => authority.id}
        state={loading ? "loading" : error ? "error" : authorities.length === 0 ? "empty" : "ready"}
        stateTitle={error ? "Served authorities unavailable" : "No served authorities yet"}
        stateMessage={error ?? "Create a root CA from a quorum-approved ceremony to serve issuance from this control plane."}
        onRowOpen={onShowDetail}
        rowActionLabel={() => "Details"}
      />
      {/* S-C12: parent_id was an opaque uuid in a detail field, so "what signs
          what" had to be reconstructed by eye. The served list already
          carries the whole tree — render it as one. */}
      {!loading && !error && authorities.length > 0 ? (
        <div className="grid gap-2">
          <h3 className="text-sm font-medium text-muted-foreground">{translateNow("ca.lineage.heading")}</h3>
          <CALineageTree authorities={authorities} />
        </div>
      ) : null}
    </section>
  );
}

function CreateAuthorityDialog({
  kind,
  onClose,
  onCreated,
  parents,
}: {
  kind: "root" | "intermediate";
  parents: CAAuthority[];
  onClose: () => void;
  onCreated: (authority: CAAuthority) => void;
}) {
  const { t } = useTranslation();
  const isRoot = kind === "root";
  const [ceremonyID, setCeremonyID] = useState("");
  const [parentID, setParentID] = useState(parents[0]?.id ?? "");
  const [specJSON, setSpecJSON] = useState(() =>
    JSON.stringify(
      isRoot
        ? { common_name: "Trust Root CA", max_path_len: 1, signature_algorithm: "ECDSA-P256", ttl_seconds: 315_360_000 }
        : { common_name: "Issuing Intermediate CA", max_path_len: 0, signature_algorithm: "ECDSA-P256", ttl_seconds: 71_280_000 },
      null,
      2,
    ),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ceremonyInputRef = useRef<HTMLInputElement>(null);
  const titleId = "create-authority-heading";

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const spec = parseSpecJSON(specJSON);
    if (typeof spec === "string") {
      setError(spec);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = isRoot
        ? await api.createRootCA({ ceremony_id: ceremonyID.trim(), spec })
        : await api.createIntermediateCA({ ceremony_id: ceremonyID.trim(), parent_id: parentID, spec });
      onCreated(created);
    } catch (err) {
      setError(errorText(err, isRoot ? "Could not create root CA" : "Could not create intermediate CA"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      initialFocusRef={ceremonyInputRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 id={titleId} className="text-title font-semibold">
            {isRoot ? t("parity.createRootCa_94fb33") : t("parity.createIntermediateCa_829ab7")}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            {isRoot
              ? translateNow("source.mints.a.signer.backed.root.from.a.quorum.a.592ee04526")
              : translateNow("source.mints.a.signer.backed.intermediate.chained.5b33f94914")}
          </p>
        </div>
        <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label={t("parity.closeCreateCaForm_e01a8e")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>
      <form className="grid gap-4 p-5" onSubmit={(event) => void submit(event)}>
        {error && (
          <ErrorState
            title={isRoot ? translateNow("source.root.ca.create.failed.6cab086b1e") : translateNow("source.intermediate.ca.create.failed.508df7468d")}
          >
            {error}
          </ErrorState>
        )}
        <label className="grid gap-1 text-body font-medium">
          {t("parity.ceremonyId_6f8ee6")}
          <input
            ref={ceremonyInputRef}
            required
            value={ceremonyID}
            onChange={(event) => setCeremonyID(event.target.value)}
            className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
          />
          <span className="text-caption font-normal text-muted-foreground">{t("parity.quorumApprovedCeremonyId_df8e12")}</span>
        </label>
        {!isRoot && (
          <label className="grid gap-1 text-body font-medium">
            {t("parity.parentAuthority_d9bb89")}
            <select
              required
              value={parentID}
              onChange={(event) => setParentID(event.target.value)}
              className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
            >
              <option value="">{t("parity.selectParentAuthority_76a0a6")}</option>
              {parents.map((parent) => (
                <option key={parent.id} value={parent.id}>
                  {parent.common_name} ({parent.kind}, {parent.status})
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="grid gap-1 text-body font-medium">
          {t("parity.specJson_e57c5c")}
          <textarea
            required
            rows={7}
            value={specJSON}
            onChange={(event) => setSpecJSON(event.target.value)}
            className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
          />
          <span className="text-caption font-normal text-muted-foreground">{t("parity.commonNameMaxPathLenSignature_0d8b25")}</span>
        </label>
        <footer className="flex justify-end gap-2 border-t border-border pt-4">
          <Button type="button" variant="outline" onClick={onClose}>
            {translateNow("source.cancel.19766ed6cc")}
          </Button>
          <Button type="submit" disabled={busy || ceremonyID.trim() === "" || (!isRoot && parentID === "")}>
            {isRoot ? t("parity.createRootCa_94fb33") : t("parity.createIntermediateCa_829ab7")}
          </Button>
        </footer>
      </form>
    </Dialog>
  );
}

function IssueLeafDialog({ authority, onClose }: { authority: CAAuthority; onClose: () => void }) {
  const { t } = useTranslation();
  const [csrPEM, setCSRPEM] = useState("");
  const [ttlSeconds, setTTLSeconds] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CAIssuedLeaf | null>(null);
  const csrRef = useRef<HTMLTextAreaElement>(null);
  const titleId = "issue-leaf-heading";

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const csr = csrPEM.trim();
    if (!csr.includes("BEGIN CERTIFICATE REQUEST")) {
      setError("CSR PEM must contain a BEGIN CERTIFICATE REQUEST block.");
      return;
    }
    const ttl = Number.parseInt(ttlSeconds.trim(), 10);
    setBusy(true);
    setError(null);
    try {
      setResult(
        await api.issueLeafFromCA(authority.id, {
          csr_pem: csr,
          ttl_seconds: Number.isFinite(ttl) && ttl > 0 ? ttl : undefined,
        }),
      );
    } catch (err) {
      setError(errorText(err, "Could not issue leaf certificate"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      initialFocusRef={csrRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 id={titleId} className="truncate text-title font-semibold">
            {translateNow("source.issue.leaf.from.47e7b2541d")} {authority.common_name}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">The CA key never leaves the signer; the CSR public key is certified as a leaf.</p>
        </div>
        <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label={t("parity.closeIssueLeafForm_2c9eeb")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>
      {result ? (
        <div className="grid gap-4 p-5">
          <IssuedCertificateResult certificatePEM={result.certificate_pem} notAfter={result.not_after} serial={result.serial} />
          <footer className="flex justify-end border-t border-border pt-4">
            <Button type="button" onClick={onClose}>
              {translateNow("source.close.7d9eb7acb1")}
            </Button>
          </footer>
        </div>
      ) : (
        <form className="grid gap-4 p-5" onSubmit={(event) => void submit(event)}>
          {error && <ErrorState title={t("parity.leafIssuanceFailed_235d03")}>{error}</ErrorState>}
          <label className="grid gap-1 text-body font-medium">
            {t("parity.csrPem_c5931f")}
            <textarea
              ref={csrRef}
              required
              rows={6}
              value={csrPEM}
              onChange={(event) => setCSRPEM(event.target.value)}
              placeholder={translateNow("source.begin.certificate.request.929bb0afef")}
              className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
            />
          </label>
          <label className="grid gap-1 text-body font-medium">
            {t("parity.ttlSecondsOptional_68f1c5")}
            <input
              type="number"
              min={1}
              value={ttlSeconds}
              onChange={(event) => setTTLSeconds(event.target.value)}
              placeholder="2592000"
              className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
            />
          </label>
          <footer className="flex justify-end gap-2 border-t border-border pt-4">
            <Button type="button" variant="outline" onClick={onClose}>
              {translateNow("source.cancel.19766ed6cc")}
            </Button>
            <Button type="submit" disabled={busy || csrPEM.trim() === ""}>
              {t("parity.issueLeafCertificate_bddf5d")}
            </Button>
          </footer>
        </form>
      )}
    </Dialog>
  );
}

function SignIntermediateCSRDialog({ authority, onClose }: { authority: CAAuthority; onClose: () => void }) {
  const { t } = useTranslation();
  const [ceremonyID, setCeremonyID] = useState("");
  const [csrPEM, setCSRPEM] = useState("");
  const [specJSON, setSpecJSON] = useState(() => JSON.stringify({ common_name: "Issuing Intermediate CA", max_path_len: 0 }, null, 2));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<CAIssuedIntermediate | null>(null);
  const ceremonyInputRef = useRef<HTMLInputElement>(null);
  const titleId = "sign-intermediate-csr-heading";

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const csr = csrPEM.trim();
    if (!csr.includes("BEGIN CERTIFICATE REQUEST")) {
      setError("CSR PEM must contain a BEGIN CERTIFICATE REQUEST block.");
      return;
    }
    const spec = parseSpecJSON(specJSON);
    if (typeof spec === "string") {
      setError(spec);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setResult(await api.signIntermediateCSR(authority.id, { ceremony_id: ceremonyID.trim(), csr_pem: csr, spec }));
    } catch (err) {
      setError(errorText(err, "Could not sign intermediate CSR"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      initialFocusRef={ceremonyInputRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 id={titleId} className="truncate text-title font-semibold">
            {translateNow("source.sign.intermediate.csr.with.64b849b64d")} {authority.common_name}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">{t("parity.certifiesAnExternallyHeldIntermediateKey_d95cc4")}</p>
        </div>
        <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label={t("parity.closeSignIntermediateCsrForm_162507")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>
      {result ? (
        <div className="grid gap-4 p-5">
          <IssuedCertificateResult certificatePEM={result.certificate_pem} notAfter={result.not_after} serial={result.serial} />
          <footer className="flex justify-end border-t border-border pt-4">
            <Button type="button" onClick={onClose}>
              {translateNow("source.close.7d9eb7acb1")}
            </Button>
          </footer>
        </div>
      ) : (
        <form className="grid gap-4 p-5" onSubmit={(event) => void submit(event)}>
          {error && <ErrorState title={t("parity.intermediateCsrSigningFailed_636cae")}>{error}</ErrorState>}
          <label className="grid gap-1 text-body font-medium">
            {t("parity.ceremonyId_6f8ee6")}
            <input
              ref={ceremonyInputRef}
              required
              value={ceremonyID}
              onChange={(event) => setCeremonyID(event.target.value)}
              className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
            />
            <span className="text-caption font-normal text-muted-foreground">{t("parity.quorumApprovedCeremonyId_df8e12")}</span>
          </label>
          <label className="grid gap-1 text-body font-medium">
            {t("parity.csrPem_c5931f")}
            <textarea
              required
              rows={6}
              value={csrPEM}
              onChange={(event) => setCSRPEM(event.target.value)}
              placeholder={translateNow("source.begin.certificate.request.929bb0afef")}
              className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
            />
          </label>
          <label className="grid gap-1 text-body font-medium">
            {t("parity.specJson_e57c5c")}
            <textarea
              required
              rows={5}
              value={specJSON}
              onChange={(event) => setSpecJSON(event.target.value)}
              className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
            />
            <span className="text-caption font-normal text-muted-foreground">{t("parity.theServedContractRequiresASpec_bf854f")}</span>
          </label>
          <footer className="flex justify-end gap-2 border-t border-border pt-4">
            <Button type="button" variant="outline" onClick={onClose}>
              {translateNow("source.cancel.19766ed6cc")}
            </Button>
            <Button type="submit" disabled={busy || ceremonyID.trim() === "" || csrPEM.trim() === ""}>
              {t("parity.signIntermediateCsr_e1f90b")}
            </Button>
          </footer>
        </form>
      )}
    </Dialog>
  );
}

function AuthorityDetailDialog({
  authority,
  onClose,
  onIssueLeaf,
  onSignCSR,
}: {
  authority: CAAuthority;
  onClose: () => void;
  onIssueLeaf: () => void;
  onSignCSR: () => void;
}) {
  const { t } = useTranslation();
  const titleId = "authority-detail-heading";
  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 id={titleId} className="truncate text-title font-semibold">
            {authority.common_name}
          </h2>
          <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{authority.id}</p>
        </div>
        <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label={t("parity.closeAuthorityDetail_9bee0e")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>
      <div className="grid gap-4 p-5 text-sm">
        <dl className="grid gap-3 sm:grid-cols-2">
          <KeyValue label="Kind" value={authority.kind} />
          <KeyValue label="Status" value={authority.status} />
          <KeyValue label="Serial" value={authority.serial} mono />
          <KeyValue label="Not after" value={authority.not_after || "-"} />
          <KeyValue label={translateNow("source.expiry.horizon.191bec0761")} value={<CAHorizonBadge authority={authority} />} />
          <KeyValue label={translateNow("source.renew.or.re.key.by.00be37d4f2")} value={<CAHorizonRenewBy authority={authority} />} />
          <KeyValue label={t("parity.parentAuthority_d9bb89")} value={authority.parent_id || "-"} mono />
          <KeyValue label="Signer handle" value={authority.signer_handle || "-"} mono />
        </dl>
        <CertificatePEMBlock label="Certificate PEM" pem={authority.certificate_pem} />
        <footer className="flex flex-wrap justify-end gap-2 border-t border-border pt-4">
          <Button type="button" variant="outline" onClick={onSignCSR}>
            {t("parity.signIntermediateCsr_cf1361")}
          </Button>
          <Button type="button" onClick={onIssueLeaf}>
            {t("parity.issueLeaf_f1c3ee")}
          </Button>
          <Button type="button" variant="ghost" onClick={onClose}>
            {translateNow("source.close.7d9eb7acb1")}
          </Button>
        </footer>
      </div>
    </Dialog>
  );
}

function IssuedCertificateResult({ certificatePEM, notAfter, serial }: { certificatePEM: string; notAfter: string; serial: string }) {
  return (
    <div role="status" className="grid gap-3 rounded-control border border-border p-3 text-sm">
      <dl className="grid gap-3 sm:grid-cols-2">
        <KeyValue label="Serial" value={serial} mono />
        <KeyValue label="Not after" value={notAfter} />
      </dl>
      <CertificatePEMBlock label="Certificate PEM" pem={certificatePEM} />
    </div>
  );
}

function CertificatePEMBlock({ label, pem }: { label: string; pem: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard?.writeText(pem);
    } finally {
      setCopied(true);
    }
  }

  return (
    <div className="grid gap-1">
      <div className="flex items-center justify-between gap-2">
        <span className="text-body font-medium">{label}</span>
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => void copy()}
          aria-label={translateNow("source.copy.value1.6dd8303613", { value1: label })}
        >
          <Copy className="h-4 w-4" aria-hidden="true" />
          {copied ? translateNow("source.copied.8d525e5f15") : translateNow("source.copy.e21f935f11")}
        </Button>
      </div>
      <pre className="max-h-48 overflow-auto rounded-control border border-border bg-muted/40 p-3 font-mono text-xs">{pem}</pre>
    </div>
  );
}

function IssuerCatalog({ onConfigure }: { onConfigure: (type: IssuerTypeConfig) => void }) {
  return (
    <section aria-labelledby="issuer-catalog-heading" className="grid gap-3 border-y border-border py-4">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-start gap-3">
          <Server className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="issuer-catalog-heading" className="text-title font-semibold">
              {translateNow("source.issuer.catalog.add106b6a5")}
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{translateNow("source.available.ca.integrations.and.local.signin.a7967de86e")}</p>
          </div>
        </div>
      </div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {issuerTypes.map((type) => (
          <IssuerCatalogCard key={type.id} type={type} onConfigure={onConfigure} />
        ))}
      </div>
    </section>
  );
}

function IssuerCatalogCard({ onConfigure, type }: { type: IssuerTypeConfig; onConfigure: (type: IssuerTypeConfig) => void }) {
  return (
    <article className="ui-panel grid min-h-40 gap-3 p-comfortable">
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-control border border-border bg-muted/40">
            <IssuerIcon icon={type.icon} />
          </span>
          <div className="min-w-0">
            <h3 className="truncate text-sm font-semibold">{type.name}</h3>
            <p className="text-xs text-muted-foreground">
              {type.internal ? translateNow("source.internal.3bed2cb3a3") : translateNow("source.external.3c4623849a")}
            </p>
          </div>
        </div>
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => onConfigure(type)}
          aria-label={translateNow("source.configure.value1.852b3f111c", { value1: type.name })}
        >
          <Plus className="h-4 w-4" aria-hidden="true" />
          {translateNow("source.configure.6defafa2ca")}
        </Button>
      </div>
      <p className="text-sm text-muted-foreground">{type.description}</p>
      <div className="flex flex-wrap gap-1.5">
        {type.configFields.slice(0, 3).map((field) => (
          <span key={field.key} className="rounded-control border border-border px-2 py-1 text-xs text-muted-foreground">
            {field.label}
          </span>
        ))}
      </div>
    </article>
  );
}

function CreateIssuerDialog({
  busy,
  error,
  onClose,
  onSubmit,
  type,
}: {
  type: IssuerTypeConfig;
  busy: boolean;
  error: string | null;
  onClose: () => void;
  onSubmit: (name: string, chainPEM: string) => void;
}) {
  const [name, setName] = useState("");
  const [chainPEM, setChainPEM] = useState("");
  const [config, setConfig] = useState<Record<string, string>>(() => defaultIssuerConfigValues(type));
  const nameInputRef = useRef<HTMLInputElement>(null);
  const titleId = "issuer-create-heading";
  const descriptionId = "issuer-create-description";

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onSubmit(name.trim(), chainPEM.trim());
  }

  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      descriptionId={descriptionId}
      initialFocusRef={nameInputRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[min(42rem,calc(100vh-2rem))] w-full max-w-3xl overflow-hidden rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 id={titleId} className="truncate text-title font-semibold">
            {translateNow("source.configure.6defafa2ca")} {type.name} {translateNow("source.issuer.535c6f8eb5")}
          </h2>
          <p id={descriptionId} className="mt-1 text-sm text-muted-foreground">
            {type.internal ? translateNow("source.local.signing.authority.0461c7306a") : translateNow("source.external.ca.integration.c66b92973a")}
          </p>
        </div>
        <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label={translateNow("source.close.issuer.form.b40f6c2037")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>
      <form className="grid max-h-[calc(100vh-8rem)] overflow-y-auto" onSubmit={submit}>
        <div className="grid gap-5 p-5">
          {error && <ErrorState title={translateNow("source.issuer.create.failed.1550974caf")}>{error}</ErrorState>}
          <div className="grid gap-4 md:grid-cols-2">
            <LabeledInput
              inputRef={nameInputRef}
              id="issuer-name"
              label="Issuer name"
              value={name}
              required
              onChange={setName}
              placeholder={translateNow("source.production.acme.c76ba14398")}
            />
            <div className="grid gap-2">
              <label className="text-sm font-medium" htmlFor="issuer-kind">
                {translateNow("source.issuer.kind.9f06073f8d")}
              </label>
              <input
                id="issuer-kind"
                value="x509_ca"
                readOnly
                className="h-10 rounded-control border border-border bg-muted/40 px-3 text-sm text-muted-foreground"
              />
            </div>
          </div>
          <div className="grid gap-2">
            <label className="text-sm font-medium" htmlFor="issuer-chain">
              {translateNow("source.ca.chain.pem.add189510a")}
            </label>
            <textarea
              id="issuer-chain"
              required
              rows={5}
              value={chainPEM}
              onChange={(event) => setChainPEM(event.target.value)}
              className="min-h-32 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs outline-none transition-colors placeholder:text-muted-foreground focus:border-focus focus:ring-2 focus:ring-focus/20"
              placeholder={translateNow("source.begin.certificate.ddddb6cbd3")}
            />
          </div>
          <IssuerConfigForm fields={type.configFields} values={config} onChange={(key, value) => setConfig((current) => ({ ...current, [key]: value }))} />
        </div>
        <footer className="flex flex-wrap justify-end gap-2 border-t border-border px-5 py-4">
          <Button type="button" variant="outline" onClick={onClose}>
            {translateNow("source.cancel.19766ed6cc")}
          </Button>
          <Button type="submit" disabled={busy || name.trim() === "" || chainPEM.trim() === ""}>
            {translateNow("source.create.issuer.83b848cf15")}
          </Button>
        </footer>
      </form>
    </Dialog>
  );
}

function IssuerConfigForm({
  fields,
  onChange,
  values,
}: {
  fields: IssuerConfigField[];
  values: Record<string, string>;
  onChange: (key: string, value: string) => void;
}) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {fields.map((field) => (
        <IssuerConfigFieldControl key={field.key} field={field} value={values[field.key] ?? ""} onChange={(value) => onChange(field.key, value)} />
      ))}
    </div>
  );
}

function IssuerConfigFieldControl({ field, onChange, value }: { field: IssuerConfigField; value: string; onChange: (value: string) => void }) {
  const id = `issuer-config-${field.key}`;
  if (field.type === "select") {
    return (
      <div className="grid gap-2">
        <FieldLabel field={field} id={id} />
        <select
          id={id}
          required={field.required}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none transition-colors focus:border-focus focus:ring-2 focus:ring-focus/20"
        >
          <option value="">{translateNow("source.select.2a78025de6")}</option>
          {field.options?.map((option) => (
            <option key={option} value={option}>
              {option || translateNow("source.default.37a8eec1ce")}
            </option>
          ))}
        </select>
      </div>
    );
  }
  if (field.type === "textarea") {
    return (
      <div className="grid gap-2 md:col-span-2">
        <FieldLabel field={field} id={id} />
        <textarea
          id={id}
          required={field.required}
          value={value}
          rows={4}
          onChange={(event) => onChange(event.target.value)}
          placeholder={field.placeholder}
          className="rounded-control border border-border bg-background px-3 py-2 text-sm outline-none transition-colors placeholder:text-muted-foreground focus:border-focus focus:ring-2 focus:ring-focus/20"
        />
      </div>
    );
  }
  return (
    <LabeledInput
      id={id}
      label={field.label}
      value={value}
      required={field.required}
      type={field.type === "password" ? "password" : field.type === "number" ? "number" : "text"}
      placeholder={field.placeholder}
      onChange={onChange}
    />
  );
}

function LabeledInput({
  id,
  label,
  onChange,
  placeholder,
  required,
  type = "text",
  value,
  inputRef,
}: {
  id: string;
  label: string;
  value: string;
  type?: "text" | "password" | "number";
  required?: boolean;
  placeholder?: string;
  onChange: (value: string) => void;
  inputRef?: RefObject<HTMLInputElement>;
}) {
  return (
    <div className="grid gap-2">
      <label className="text-sm font-medium" htmlFor={id}>
        {label}
      </label>
      <input
        ref={inputRef}
        id={id}
        type={type}
        required={required}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none transition-colors placeholder:text-muted-foreground focus:border-focus focus:ring-2 focus:ring-focus/20"
      />
    </div>
  );
}

function LabeledTextarea({
  id,
  label,
  onChange,
  placeholder,
  required,
  rows = 4,
  value,
}: {
  id: string;
  label: string;
  value: string;
  rows?: number;
  required?: boolean;
  placeholder?: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="grid gap-2 lg:col-span-2">
      <label className="text-sm font-medium" htmlFor={id}>
        {label}
      </label>
      <textarea
        id={id}
        required={required}
        rows={rows}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="min-h-32 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs outline-none transition-colors placeholder:text-muted-foreground focus:border-focus focus:ring-2 focus:ring-focus/20"
      />
    </div>
  );
}

function FieldLabel({ field, id }: { field: IssuerConfigField; id: string }) {
  return (
    <label className="text-sm font-medium" htmlFor={id}>
      {field.label}
    </label>
  );
}

function ProbeBanner({ onDismiss, probe }: { probe: ProbeState; onDismiss: () => void }) {
  const passed = probe.status === "passed";
  const pending = probe.status === "pending";
  const Icon = passed ? CheckCircle2 : pending ? RefreshCw : XCircle;
  return (
    <div className="ui-panel flex items-start justify-between gap-3 p-comfortable text-sm" role="status">
      <div className="flex min-w-0 items-start gap-2">
        <Icon
          className={
            pending
              ? "mt-0.5 h-4 w-4 shrink-0 animate-spin text-muted-foreground"
              : passed
                ? "mt-0.5 h-4 w-4 shrink-0 text-emerald-600"
                : "mt-0.5 h-4 w-4 shrink-0 text-destructive"
          }
          aria-hidden="true"
        />
        <p className="min-w-0 break-words font-medium">
          {translateNow("source.value1.value2.efae3eb968", { value1: probe.issuerName, value2: probe.message })}
        </p>
      </div>
      <Button type="button" variant="ghost" size="sm" onClick={onDismiss}>
        {translateNow("source.dismiss.48845bff33")}
      </Button>
    </div>
  );
}

function ManagedKeyPanel({
  busy,
  managedKey,
  onAction,
}: {
  busy: boolean;
  managedKey: ManagedKey;
  onAction: (action: "rotate" | "revoke" | "zeroize", keyId: string) => void;
}) {
  return (
    <section aria-labelledby="managed-key-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="managed-key-heading" className="text-title font-semibold">
            {translateNow("source.managed.key.f08acca719")}
          </h3>
          <p className="mt-1 font-mono text-xs">{managedKey.key_id}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => onAction("rotate", managedKey.key_id)}
            aria-label={translateNow("source.rotate.key.value1.f9e66701f9", { value1: managedKey.key_id })}
          >
            {translateNow("source.rotate.c3613b1704")}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => onAction("revoke", managedKey.key_id)}
            aria-label={translateNow("source.revoke.key.value1.2e6b1284fb", { value1: managedKey.key_id })}
          >
            {translateNow("source.revoke.87e6d00bbf")}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => onAction("zeroize", managedKey.key_id)}
            aria-label={translateNow("source.zeroize.key.value1.4e92e53f48", { value1: managedKey.key_id })}
          >
            {translateNow("source.zeroize.9fb44dd187")}
          </Button>
        </div>
      </div>
      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <KeyValue label="Algorithm" value={managedKey.algorithm} />
        <KeyValue label="Version" value={`Version ${managedKey.version}`} />
        <KeyValue label="State" value={managedKey.state} />
        <KeyValue label="Public DER" value={managedKey.public_der ? `${managedKey.public_der.length} bytes` : "-"} />
        <KeyValue label="Extractable" value={managedKey.extractable ? "Yes" : "No"} />
      </dl>
    </section>
  );
}

function KeyValue({ label, mono = false, value }: { label: string; mono?: boolean; value: ReactNode }) {
  return (
    <div>
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "font-medium"}>{value}</dd>
    </div>
  );
}

function IssuerTable({
  issuers,
  capabilities,
  externalCAs,
  onTestConnection,
  probe,
}: {
  issuers: Issuer[];
  capabilities: IssuerCapabilityMatrix | null;
  externalCAs: ExternalCA[];
  probe: ProbeState | null;
  onTestConnection: (issuer: Issuer) => void;
}) {
  // Resolve an issuer to its row in the served capability census.
  //
  // Three genuinely different answers, and collapsing any two of them would
  // mislead: an INTERNAL issuer has no upstream authority, so the question does
  // not apply; an external issuer we cannot match to a registry entry is
  // unknown; and a matched one gets its authority kind's row.
  const capabilityFor = (issuer: Issuer) => {
    if (issuer.internal) return "internal" as const;
    const upstream = findExternalCAForIssuer(issuer, externalCAs);
    if (!upstream) return undefined;
    return (capabilities?.issuers ?? []).find((c) => c.issuer === upstream.type);
  };
  return (
    <div className="ui-panel overflow-x-auto">
      <table className="ui-table min-w-[60rem]">
        <caption className="sr-only">{translateNow("source.issuer.list.477db22fd7")}</caption>
        <thead>
          <tr>
            <th scope="col">{translateNow("source.name.dcd1d5223f")}</th>
            <th scope="col">{translateNow("source.kind.f5387f9bb6")}</th>
            <th scope="col">{translateNow("source.internal.2ea1842b44")}</th>
            <th scope="col">{translateNow("source.chain.dae0896cbc")}</th>
            <th scope="col">{translateNow("source.public.key.4ee252fb73")}</th>
            <th scope="col">{translateNow("source.certificates.16f637921e")}</th>
            <th scope="col">{translateNow("source.revocation.r2cap00001")}</th>
            <th scope="col">{translateNow("source.domain.validation.b7dv000001")}</th>
            <th scope="col">{translateNow("source.connection.639a40e82b")}</th>
          </tr>
        </thead>
        <tbody>
          {issuers.map((issuer) => (
            <tr key={issuer.id} className="align-top">
              <td className="font-medium">{issuer.name}</td>
              <td>{issuer.kind}</td>
              <td>{issuer.internal ? translateNow("source.internal.3bed2cb3a3") : translateNow("source.external.3c4623849a")}</td>
              <td>{issuer.chain?.length ? issuer.chain.join(" -> ") : "-"}</td>
              <td className="max-w-sm break-all font-mono text-xs">{issuer.public_key || "-"}</td>
              <td>
                <a className="text-brand-accent underline" href={`/certificates?issuer=${encodeURIComponent(issuer.id)}`}>
                  {translateNow("source.certificates.for.143f183f89")} {issuer.name}
                </a>
              </td>
              {/* R2: whether trstctl can revoke THROUGH this authority, from
                  the served capability matrix. An operator holding a compromised
                  key needs to know before they reach for the button, not after
                  a revocation that went nowhere. */}
              <td className="max-w-[22rem] text-sm">
                {(() => {
                  const cap = capabilityFor(issuer);
                  if (cap === "internal") {
                    return <span className="text-status-success">{translateNow("source.revoke.internal.r2cap00005")}</span>;
                  }
                  if (!cap) return <span className="text-muted-foreground">{translateNow("source.unknown.r2cap00004")}</span>;
                  return cap.revoke ? (
                    <span className="font-medium text-status-success">{translateNow("source.revoke.supported.r2cap00002")}</span>
                  ) : (
                    <>
                      <span className="text-status-warning">{translateNow("source.revoke.elsewhere.r2cap00003")}</span>
                      {cap.revoke_note ? <span className="mt-1 block text-xs text-muted-foreground">{cap.revoke_note}</span> : null}
                    </>
                  );
                })()}
              </td>
              {/* B7: whether trstctl can satisfy this authority's domain
                  validation with nobody in the loop. As the CA/Browser Forum
                  compresses the validation-reuse window, an authority that
                  reads "manual" here needs a person every cycle, and the
                  number of cycles per year is going up. */}
              <td className="max-w-[22rem] text-sm">
                {(() => {
                  const cap = capabilityFor(issuer);
                  if (cap === "internal") {
                    return <span className="text-muted-foreground">{translateNow("source.dv.internal.b7dv000004")}</span>;
                  }
                  if (!cap) return <span className="text-muted-foreground">{translateNow("source.unknown.r2cap00004")}</span>;
                  return cap.unattended_dv ? (
                    <span className="font-medium text-status-success">{translateNow("source.unattended.b7dv000002")}</span>
                  ) : (
                    <>
                      <span className="text-status-warning">{translateNow("source.manual.step.b7dv000003")}</span>
                      {cap.unattended_dv_note ? <span className="mt-1 block text-xs text-muted-foreground">{cap.unattended_dv_note}</span> : null}
                    </>
                  );
                })()}
              </td>
              <td>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={probe?.issuerID === issuer.id && probe.status === "pending"}
                  onClick={() => onTestConnection(issuer)}
                  aria-label={translateNow("source.test.connection.value1.3b3d22ad35", { value1: issuer.name })}
                >
                  {translateNow("source.test.532eaabd95")}
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function IssuerIcon({ icon }: { icon: IssuerTypeConfig["icon"] }) {
  const className = "h-4 w-4 text-brand-accent";
  switch (icon) {
    case "building":
      return <Building2 className={className} aria-hidden="true" />;
    case "cloud":
      return <Cloud className={className} aria-hidden="true" />;
    case "globe":
      return <Globe2 className={className} aria-hidden="true" />;
    case "home":
      return <Home className={className} aria-hidden="true" />;
    case "lock":
      return <LockKeyhole className={className} aria-hidden="true" />;
    case "server":
      return <Server className={className} aria-hidden="true" />;
    case "key":
    default:
      return <KeyRound className={className} aria-hidden="true" />;
  }
}

function externalCAIssueRequest(form: ExternalCAIssueForm): ExternalCAIssueRequest {
  const dnsNames = externalCAIssueDNSNames(form);
  const req: ExternalCAIssueRequest = {
    csr_pem: form.csrPEM.trim(),
    dns_names: dnsNames,
  };
  const ttlDays = positiveInteger(form.ttlDays, 0);
  if (ttlDays > 0) req.ttl_seconds = ttlDays * 86_400;
  const profileName = form.profileName.trim();
  if (profileName) req.profile_name = profileName;
  return req;
}

function externalCAIssueDNSNames(form: ExternalCAIssueForm): string[] {
  const dnsNames = splitTokenList(form.dnsNames);
  if (dnsNames.length > 0) return dnsNames;
  const commonName = form.commonName.trim();
  return commonName ? [commonName] : [];
}

function externalCAIssuePath(inventory: CADiscovery | null, caID: string): string {
  const item = (inventory?.items ?? []).find((entry) => entry.source === "external_ca_registry" && entry.source_id === caID);
  return item?.issuance_path || `/api/v1/external-cas/${encodeURIComponent(caID)}/issue`;
}

function offlineFormSpec(form: OfflineCAForm): CACeremonyStartRequest["spec"] {
  const permitted = splitTokenList(form.dnsDomains);
  return {
    common_name: form.commonName.trim(),
    max_path_len: positiveInteger(form.maxPathLen, 0),
    permitted_dns_domains: permitted.length ? permitted : undefined,
    signature_algorithm: "ECDSA-P256",
    ttl_seconds: positiveInteger(form.ttlDays, 1) * 86_400,
  };
}

function shortSerial(serial: string): string {
  return serial.length > 18 ? `${serial.slice(0, 18)}…` : serial;
}

function parseSpecJSON(value: string): CACeremonyStartRequest["spec"] | string {
  const trimmed = value.trim();
  if (trimmed === "") return "Spec JSON is required.";
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (err) {
    return `Spec must be valid JSON: ${err instanceof Error ? err.message : "parse error"}`;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return "Spec must be a JSON object.";
  }
  return parsed as CACeremonyStartRequest["spec"];
}

function positiveInteger(value: string, fallback: number): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(0, parsed);
}

function splitTokenList(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function findExternalCAForIssuer(issuer: Issuer, externalCAs: ExternalCA[]): ExternalCA | undefined {
  const issuerName = issuer.name.trim().toLowerCase();
  return externalCAs.find((externalCA) => externalCA.id === issuer.id || externalCA.name.trim().toLowerCase() === issuerName);
}

function externalCAAvailable(externalCA: ExternalCA): boolean {
  const status = externalCA.status.trim().toLowerCase();
  return status !== "" && !["disabled", "down", "error", "failed", "unavailable"].some((bad) => status.includes(bad));
}

function renderNotice(notice: Notice | null) {
  if (!notice) return null;
  if (notice.kind === "permission") {
    return <PermissionDeniedState>{notice.message}</PermissionDeniedState>;
  }
  return <ErrorState title={translateNow("source.issuer.metadata.unavailable.5b4cf4fcb5")}>{notice.message}</ErrorState>;
}

function errorText(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || fallback;
    } catch {
      return err.body || fallback;
    }
  }
  return err instanceof Error ? err.message : fallback;
}

function noticeForError(err: unknown, fallback: string): Notice {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return {
        kind: err.status === 403 ? "permission" : "error",
        message: problem.detail || problem.title || fallback,
      };
    } catch {
      return { kind: err.status === 403 ? "permission" : "error", message: err.body || fallback };
    }
  }
  return { kind: "error", message: err instanceof Error ? err.message : fallback };
}

import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode, type RefObject } from "react";
import { Building2, CheckCircle2, Cloud, FileKey2, Globe2, Home, KeyRound, LockKeyhole, Plus, RefreshCw, Server, ShieldCheck, X, XCircle } from "lucide-react";
import { Dialog } from "@/components/Dialog";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { CAOverview } from "@/components/ca";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import {
  api,
  ApiError,
  type CADiscovery,
  type CAAuthority,
  type CAAuthorityRotation,
  type CACeremonyStartRequest,
  type CAIntermediateCSR,
  type CAKeyCeremony,
  type ExternalCA,
  type ExternalCAIssuedCertificate,
  type ExternalCAIssueRequest,
  type Issuer,
  type IssuerRequest,
  type ManagedKey,
  type Profile,
} from "@/lib/api";
import { defaultIssuerConfigValues, issuerTypes, splitPEMChain, type IssuerConfigField, type IssuerTypeConfig } from "@/lib/issuerCatalog";

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

export function CAHierarchy() {
  const [issuers, setIssuers] = useState<Issuer[]>([]);
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

  async function load() {
    setLoading(true);
    setNotice(null);
    const [issuerResult, discoveryResult] = await Promise.allSettled([api.issuers(), api.caDiscoveryInventory()]);
    if (issuerResult.status === "fulfilled") {
      setIssuers(issuerResult.value);
    } else {
      setIssuers([]);
      setNotice(noticeForError(issuerResult.reason, "Could not load issuers"));
    }
    setCADiscovery(discoveryResult.status === "fulfilled" ? discoveryResult.value : null);
    setLoading(false);
  }

  useEffect(() => {
    void load();
  }, []);

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

  async function startRootCeremony() {
    setCeremonyBusy(true);
    setCeremonyError(null);
    try {
      setCeremony(await api.createCACeremony(rootCeremonyRequest));
    } catch (err) {
      setCeremonyError(errorText(err, "Could not start ceremony"));
    } finally {
      setCeremonyBusy(false);
    }
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
        action === "rotate"
          ? await api.rotateManagedKey(keyId)
          : action === "revoke"
            ? await api.revokeManagedKey(keyId)
            : await api.zeroizeManagedKey(keyId);
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
    setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "pending", message: "connection pending" });
    if (issuer.internal) {
      setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "passed", message: "connection passed" });
      return;
    }
    try {
      const externalCAs = await api.externalCAs();
      const upstream = findExternalCAForIssuer(issuer, externalCAs);
      if (upstream && externalCAAvailable(upstream)) {
        setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "passed", message: "connection passed" });
        return;
      }
      setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "failed", message: "connection failed" });
    } catch (err) {
      setProbe({ issuerID: issuer.id, issuerName: issuer.name, status: "failed", message: errorText(err, "connection failed") });
    }
  }

  async function startOfflineRootCeremony() {
    setOfflineBusy(true);
    setOfflineError(null);
    try {
      const certPEM = offlineRootForm.certificatePEM.trim();
      const next = await api.createCACeremony({
        operation: "import_offline_root",
        threshold: 2,
        certificate_pem: certPEM,
        spec: offlineFormSpec(offlineRootForm),
      });
      setOfflineRootCeremonyID(next.id);
      setCeremony(next);
    } catch (err) {
      setOfflineError(errorText(err, "Could not start offline-root ceremony"));
    } finally {
      setOfflineBusy(false);
    }
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
    setOfflineBusy(true);
    setOfflineError(null);
    try {
      const parentID = offlineIntermediateForm.parentID.trim();
      const next = await api.createCACeremony({
        operation: "create_offline_intermediate",
        threshold: 2,
        parent_id: parentID,
        spec: offlineFormSpec(offlineIntermediateForm),
      });
      setOfflineIntermediateCeremonyID(next.id);
      setCeremony(next);
    } catch (err) {
      setOfflineError(errorText(err, "Could not start offline-intermediate ceremony"));
    } finally {
      setOfflineBusy(false);
    }
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
    setExistingCABusy(true);
    setExistingCAError(null);
    try {
      const next = await api.createCACeremony({
        operation: "import_existing_ca",
        threshold: 2,
        certificate_pem: existingCAForm.certificatePEM.trim(),
        signer_handle: existingCAForm.signerHandle.trim(),
        spec: offlineFormSpec(existingCAForm),
      });
      setExistingCACeremonyID(next.id);
      setCeremony(next);
    } catch (err) {
      setExistingCAError(errorText(err, "Could not start existing-CA import ceremony"));
    } finally {
      setExistingCABusy(false);
    }
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
    try {
      const predecessorID = rotationPredecessorID.trim();
      const next = await api.rotateCAAuthority(predecessorID, {
        successor_id: rotationSuccessorID.trim(),
        reason: rotationReason.trim() || undefined,
      });
      setRotationResult(next);
      await load();
    } catch (err) {
      setRotationError(errorText(err, "Could not activate CA rotation"));
    } finally {
      setRotationBusy(false);
    }
  }

  async function startCARekeyCeremony() {
    setRekeyBusy(true);
    setRekeyError(null);
    try {
      const authorityID = rekeyAuthorityID.trim();
      const selected = (caDiscovery?.items ?? []).find((item) => item.source_id === authorityID);
      const next = await api.createCACeremony({
        operation: "rekey_ca",
        authority_id: authorityID,
        threshold: 2,
        spec: {
          common_name: selected?.name ?? "Re-key existing CA",
        },
      });
      setRekeyCeremonyID(next.id);
      setCeremony(next);
    } catch (err) {
      setRekeyError(errorText(err, "Could not start CA re-key ceremony"));
    } finally {
      setRekeyBusy(false);
    }
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
    setExternalIssueBusy(true);
    setExternalIssueError(null);
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

  return (
    <section aria-labelledby="ca-heading" className="grid gap-6">
      <PageHeader
        titleId="ca-heading"
        title="CA hierarchy"
        description="Your certificate authorities — roots and intermediates — and their issuers, with multi-person approval ceremonies (no single admin can act alone) and custody controls for the signing keys."
        actions={
          <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={loading ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      <CAOverview issuers={sortedIssuers} profiles={profiles} />

      <IssuerCatalog onConfigure={(type) => setIssuerDialogType(type)} />

      <CADiscoveryInventoryPanel inventory={caDiscovery} />

      <ExternalCAIssuancePanel
        busy={externalIssueBusy}
        error={externalIssueError}
        form={externalIssueForm}
        inventory={caDiscovery}
        result={externalIssueResult}
        onChange={(patch) => setExternalIssueForm((current) => ({ ...current, ...patch }))}
        onIssue={() => void issueExternalCA()}
      />

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

      {probe && <ProbeBanner probe={probe} onDismiss={() => setProbe(null)} />}

      <section aria-labelledby="issuer-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <ShieldCheck className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="issuer-heading" className="text-title font-semibold">
              Issuer visibility
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              This view shows issuer name, kind, public key, custody boundary, and chain metadata. The ceremony and managed-key panels below drive the
              corresponding protected workflows.
            </p>
          </div>
        </div>
        {loading && <LoadingState>Loading issuers...</LoadingState>}
        {renderNotice(notice)}
        {!loading && !notice && sortedIssuers.length === 0 && (
          <EmptyState
            icon={<Server className="h-5 w-5" aria-hidden="true" />}
            title="No issuers yet"
            primaryAction={{
              label: "Connect first issuer",
              onClick: () => {
                const firstIssuerType = issuerTypes.find((type) => !type.internal) ?? issuerTypes[0];
                if (firstIssuerType) setIssuerDialogType(firstIssuerType);
              },
              icon: <Plus className="h-4 w-4" />,
            }}
            secondaryAction={{ label: "Create a profile", to: "/profiles", icon: <ShieldCheck className="h-4 w-4" /> }}
          >
            Add a local authority or upstream CA before certificates can be issued from constrained profiles.
          </EmptyState>
        )}
        {!loading && !notice && sortedIssuers.length > 0 && <IssuerTable issuers={sortedIssuers} probe={probe} onTestConnection={(issuer) => void testIssuerConnection(issuer)} />}
      </section>

      <section aria-labelledby="ceremony-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <FileKey2 className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="ceremony-heading" className="text-title font-semibold">
              CA key ceremony
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              Start a root CA ceremony, then record a second custodian approval before using the ceremony for a signer-backed authority action.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" onClick={() => void startRootCeremony()} disabled={ceremonyBusy}>
            Start root ceremony
          </Button>
          <span className="text-sm text-muted-foreground">Default request: Trust Root CA, 2 approvals, ECDSA-P256.</span>
        </div>
        {ceremonyError && <ErrorState title="Ceremony action failed">{ceremonyError}</ErrorState>}
        {ceremony ? (
          <CeremonyPanel ceremony={ceremony} busy={ceremonyBusy} onApprove={(id) => void approveCeremony(id)} />
        ) : (
          <EmptyState title="No ceremony loaded">Start a ceremony to see its purpose, approval threshold, and status.</EmptyState>
        )}
      </section>

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

      <section aria-labelledby="custody-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex items-start gap-3">
          <KeyRound className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <h2 id="custody-heading" className="text-title font-semibold">
              Managed key custody
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              AWS KMS, Azure Key Vault HSM, GCP Cloud KMS, and PKCS#11 HSM keys stay inside their provider. This panel shows public metadata and drives custody actions by key id.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button type="button" onClick={() => void generateManagedKey()} disabled={keyBusy}>
            Generate managed key
          </Button>
          <span className="text-sm text-muted-foreground">Default algorithm: ECDSA-P256.</span>
        </div>
        {keyError && <ErrorState title="Managed-key action failed">{keyError}</ErrorState>}
        {managedKey ? (
          <ManagedKeyPanel
            managedKey={managedKey}
            busy={keyBusy}
            onAction={(action, keyId) => void runManagedKeyAction(action, keyId)}
          />
        ) : (
          <EmptyState title="No managed key loaded">Generate a managed key to inspect its public metadata and lifecycle state.</EmptyState>
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
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              {t("caHierarchy.discovery.description")}
            </p>
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
            <thead className="bg-muted/40 text-left text-xs uppercase text-muted-foreground">
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
                  <td className="px-3 py-2 align-top">{item.scope === "public" ? t("caHierarchy.discovery.scopePublic") : t("caHierarchy.discovery.scopePrivate")}</td>
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
            <LabeledSelect id="external-ca-issue-ca" label={t("caHierarchy.externalIssue.caLabel")} value={form.caID} onChange={(value) => onChange({ caID: value })}>
              <option value="">{t("caHierarchy.externalIssue.caPlaceholder")}</option>
              {externalCAs.map((item) => (
                <option key={item.id} value={item.source_id}>
                  {item.name} ({item.type}, {item.status})
                </option>
              ))}
            </LabeledSelect>
            <LabeledInput id="external-ca-common-name" label={t("caHierarchy.externalIssue.commonNameLabel")} value={form.commonName} required onChange={(value) => onChange({ commonName: value })} />
            <LabeledInput id="external-ca-dns-names" label={t("caHierarchy.externalIssue.dnsNamesLabel")} value={form.dnsNames} required onChange={(value) => onChange({ dnsNames: value })} placeholder={t("caHierarchy.externalIssue.dnsNamesPlaceholder")} />
            <LabeledInput id="external-ca-profile-name" label={t("caHierarchy.externalIssue.profileLabel")} value={form.profileName} onChange={(value) => onChange({ profileName: value })} placeholder={t("caHierarchy.externalIssue.profilePlaceholder")} />
            <LabeledInput id="external-ca-ttl-days" label={t("caHierarchy.externalIssue.ttlLabel")} value={form.ttlDays} type="number" onChange={(value) => onChange({ ttlDays: value })} />
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
                  value={result.state === "outbox-pending" ? t("caHierarchy.externalIssue.state.outboxPending") : t("caHierarchy.externalIssue.state.externalCAIssued")}
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
            CA rotation
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Activate an existing signer-backed successor while the predecessor issue URL remains valid for the overlap window.
          </p>
        </div>
      </div>
      {error && <ErrorState title="CA rotation failed">{error}</ErrorState>}
      <section aria-labelledby="ca-rotation-form-heading" className="ui-panel p-comfortable text-sm">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 id="ca-rotation-form-heading" className="text-title font-semibold">
              Successor activation
            </h3>
            {result && <p className="mt-1 font-mono text-xs">{result.issue_path}</p>}
          </div>
          <Button type="button" size="sm" onClick={onActivate} disabled={busy || !ready}>
            <RefreshCw className={busy ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
            Activate CA rotation
          </Button>
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-3">
          <LabeledSelect id="ca-rotation-predecessor" label="Predecessor CA" value={predecessorID} onChange={onPredecessorChange}>
            <option value="">Select predecessor</option>
            {authorities.map((item) => (
              <option key={item.id} value={item.source_id}>
                {item.name} ({item.status})
              </option>
            ))}
          </LabeledSelect>
          <LabeledSelect id="ca-rotation-successor" label="Successor CA" value={successorID} onChange={onSuccessorChange}>
            <option value="">Select successor</option>
            {authorities.map((item) => (
              <option key={item.id} value={item.source_id}>
                {item.name} ({item.status})
              </option>
            ))}
          </LabeledSelect>
          <LabeledInput id="ca-rotation-reason" label="Rotation reason" value={reason} onChange={onReasonChange} />
        </div>
        {authorities.length < 2 && <p className="mt-3 text-sm text-muted-foreground">Create a signer-backed successor before activating rotation.</p>}
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
  const authorities = (inventory?.items ?? []).filter((item) => item.source === "ca_hierarchy" && item.managed && item.issuance_path && item.status === "active");
  const readyToStart = authorityID.trim() !== "";
  const readyToRekey = readyToStart && ceremonyID.trim() !== "";

  return (
    <section aria-labelledby="ca-rekey-heading" className="grid gap-3 border-b border-border py-4">
      <div className="flex items-start gap-3">
        <KeyRound className="mt-1 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        <div>
          <h2 id="ca-rekey-heading" className="text-title font-semibold">
            CA renewal and re-key
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Mint a fresh signer-backed CA key and certificate for the selected authority while the previous issue URL keeps routing to the active successor.
          </p>
        </div>
      </div>
      {error && <ErrorState title="CA re-key failed">{error}</ErrorState>}
      <section aria-labelledby="ca-rekey-form-heading" className="ui-panel p-comfortable text-sm">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 id="ca-rekey-form-heading" className="text-title font-semibold">
              Fresh CA material
            </h3>
            {result && <p className="mt-1 font-mono text-xs">{result.active_issue_path}</p>}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" variant="outline" onClick={onStartCeremony} disabled={busy || !readyToStart}>
              <FileKey2 className={busy ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
              Start re-key ceremony
            </Button>
            <Button type="button" size="sm" onClick={onActivate} disabled={busy || !readyToRekey}>
              <KeyRound className={busy ? "h-4 w-4 animate-spin" : "h-4 w-4"} aria-hidden="true" />
              Re-key CA
            </Button>
          </div>
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-4">
          <LabeledSelect id="ca-rekey-authority" label="CA authority" value={authorityID} onChange={onAuthorityChange}>
            <option value="">Select authority</option>
            {authorities.map((item) => (
              <option key={item.id} value={item.source_id}>
                {item.name} ({item.status})
              </option>
            ))}
          </LabeledSelect>
          <LabeledInput id="ca-rekey-ceremony" label="Ceremony ID" value={ceremonyID} onChange={onCeremonyChange} />
          <LabeledInput id="ca-rekey-ttl" label="Validity days" value={ttlDays} type="number" onChange={onTTLChange} />
          <LabeledInput id="ca-rekey-reason" label="Re-key reason" value={reason} onChange={onReasonChange} />
        </div>
        {authorities.length === 0 && <p className="mt-3 text-sm text-muted-foreground">Create or import a signer-backed authority before re-key.</p>}
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
        className="rounded-control border border-border bg-background px-3 py-2 outline-none transition-colors focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
      >
        {children}
      </select>
    </div>
  );
}

function SummaryPill({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-control border border-border px-3 py-2">
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
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            {t("caHierarchy.existing.description")}
          </p>
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
              className="min-h-36 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs outline-none transition-colors placeholder:text-muted-foreground focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
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
                className="min-h-32 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs outline-none transition-colors placeholder:text-muted-foreground focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
                placeholder={t("caHierarchy.offline.placeholderCertificate")}
              />
            </div>
            <LabeledInput id="offline-root-ceremony-id" label={t("caHierarchy.offline.rootCeremonyID")} value={rootCeremonyID} onChange={onRootCeremonyIDChange} placeholder={t("caHierarchy.offline.placeholderCeremonyID")} />
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
            <LabeledInput id="offline-intermediate-ceremony-id" label={t("caHierarchy.offline.intermediateCeremonyID")} value={intermediateCeremonyID} onChange={onIntermediateCeremonyIDChange} placeholder={t("caHierarchy.offline.placeholderCeremonyID")} />
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
                className="min-h-32 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs outline-none transition-colors placeholder:text-muted-foreground focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
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
      <LabeledInput id={commonNameId} label={t("caHierarchy.offline.commonName")} value={form.commonName} required onChange={(value) => onChange({ commonName: value })} />
      <LabeledInput id={dnsDomainsId} label={t("caHierarchy.offline.permittedDNSDomains")} value={form.dnsDomains} onChange={(value) => onChange({ dnsDomains: value })} placeholder={t("caHierarchy.offline.placeholderDNSDomain")} />
      <LabeledInput id={maxPathLenId} label={t("caHierarchy.offline.maxPathLen")} value={form.maxPathLen} required type="number" onChange={(value) => onChange({ maxPathLen: value })} />
      <LabeledInput id={ttlDaysId} label={t("caHierarchy.offline.ttlDays")} value={form.ttlDays} required type="number" onChange={(value) => onChange({ ttlDays: value })} />
    </div>
  );
}

function CeremonyPanel({ busy, ceremony, onApprove }: { busy: boolean; ceremony: CAKeyCeremony; onApprove: (id: string) => void }) {
  const complete = ceremony.approvals >= ceremony.threshold || ceremony.status === "approved";
  return (
    <section aria-labelledby="active-ceremony-heading" className="ui-panel p-comfortable text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="active-ceremony-heading" className="text-title font-semibold">
            Active ceremony
          </h3>
          <p className="mt-1 font-mono text-xs">{ceremony.id}</p>
        </div>
        <Button type="button" variant="outline" disabled={busy || complete} onClick={() => onApprove(ceremony.id)} aria-label={`Approve ceremony ${ceremony.id}`}>
          Approve
        </Button>
      </div>
      <dl className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <KeyValue label="Purpose" value={ceremony.purpose} mono />
        <KeyValue label="Approvals" value={`${ceremony.approvals} / ${ceremony.threshold} approvals`} />
        <KeyValue label="Status" value={ceremony.status} />
        <KeyValue label="Opened by" value={ceremony.opener || "-"} />
      </dl>
    </section>
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
              Issuer catalog
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">Available CA integrations and local signing authority templates.</p>
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
            <p className="text-xs text-muted-foreground">{type.internal ? "internal" : "external"}</p>
          </div>
        </div>
        <Button type="button" size="sm" variant="outline" onClick={() => onConfigure(type)} aria-label={`Configure ${type.name}`}>
          <Plus className="h-4 w-4" aria-hidden="true" />
          Configure
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
              Configure {type.name} issuer
            </h2>
            <p id={descriptionId} className="mt-1 text-sm text-muted-foreground">
              {type.internal ? "Local signing authority" : "External CA integration"}
            </p>
          </div>
          <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label="Close issuer form">
            <X className="h-4 w-4" aria-hidden="true" />
          </Button>
        </header>
        <form className="grid max-h-[calc(100vh-8rem)] overflow-y-auto" onSubmit={submit}>
          <div className="grid gap-5 p-5">
            {error && <ErrorState title="Issuer create failed">{error}</ErrorState>}
            <div className="grid gap-4 md:grid-cols-2">
              <LabeledInput inputRef={nameInputRef} id="issuer-name" label="Issuer name" value={name} required onChange={setName} placeholder="Production ACME" />
              <div className="grid gap-2">
                <label className="text-sm font-medium" htmlFor="issuer-kind">
                  Issuer kind
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
                CA chain PEM
              </label>
              <textarea
                id="issuer-chain"
                required
                rows={5}
                value={chainPEM}
                onChange={(event) => setChainPEM(event.target.value)}
                className="min-h-32 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs outline-none transition-colors placeholder:text-muted-foreground focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
                placeholder="-----BEGIN CERTIFICATE-----"
              />
            </div>
            <IssuerConfigForm fields={type.configFields} values={config} onChange={(key, value) => setConfig((current) => ({ ...current, [key]: value }))} />
          </div>
          <footer className="flex flex-wrap justify-end gap-2 border-t border-border px-5 py-4">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy || name.trim() === "" || chainPEM.trim() === ""}>
              Create issuer
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
          className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none transition-colors focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
        >
          <option value="">Select</option>
          {field.options?.map((option) => (
            <option key={option} value={option}>
              {option || "default"}
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
          className="rounded-control border border-border bg-background px-3 py-2 text-sm outline-none transition-colors placeholder:text-muted-foreground focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
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
        className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none transition-colors placeholder:text-muted-foreground focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
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
        className="min-h-32 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs outline-none transition-colors placeholder:text-muted-foreground focus:border-brand-accent focus:ring-2 focus:ring-brand-accent/20"
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
        <Icon className={pending ? "mt-0.5 h-4 w-4 shrink-0 animate-spin text-muted-foreground" : passed ? "mt-0.5 h-4 w-4 shrink-0 text-emerald-600" : "mt-0.5 h-4 w-4 shrink-0 text-destructive"} aria-hidden="true" />
        <p className="min-w-0 break-words font-medium">{`${probe.issuerName}: ${probe.message}`}</p>
      </div>
      <Button type="button" variant="ghost" size="sm" onClick={onDismiss}>
        Dismiss
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
            Managed key
          </h3>
          <p className="mt-1 font-mono text-xs">{managedKey.key_id}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onAction("rotate", managedKey.key_id)} aria-label={`Rotate key ${managedKey.key_id}`}>
            Rotate
          </Button>
          <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onAction("revoke", managedKey.key_id)} aria-label={`Revoke key ${managedKey.key_id}`}>
            Revoke
          </Button>
          <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => onAction("zeroize", managedKey.key_id)} aria-label={`Zeroize key ${managedKey.key_id}`}>
            Zeroize
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

function KeyValue({ label, mono = false, value }: { label: string; mono?: boolean; value: string }) {
  return (
    <div>
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "font-medium"}>{value}</dd>
    </div>
  );
}

function IssuerTable({
  issuers,
  onTestConnection,
  probe,
}: {
  issuers: Issuer[];
  probe: ProbeState | null;
  onTestConnection: (issuer: Issuer) => void;
}) {
  return (
    <div className="ui-panel overflow-x-auto">
      <table className="ui-table min-w-[60rem]">
        <caption className="sr-only">Issuer list</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Kind</th>
            <th scope="col">Internal</th>
            <th scope="col">Chain</th>
            <th scope="col">Public key</th>
            <th scope="col">Certificates</th>
            <th scope="col">Connection</th>
          </tr>
        </thead>
        <tbody>
          {issuers.map((issuer) => (
            <tr key={issuer.id} className="align-top">
              <td className="font-medium">{issuer.name}</td>
              <td>{issuer.kind}</td>
              <td>{issuer.internal ? "internal" : "external"}</td>
              <td>{issuer.chain?.length ? issuer.chain.join(" -> ") : "-"}</td>
              <td className="max-w-sm break-all font-mono text-xs">{issuer.public_key || "-"}</td>
              <td>
                <a className="text-brand-accent underline" href={`/certificates?issuer=${encodeURIComponent(issuer.id)}`}>
                  Certificates for {issuer.name}
                </a>
              </td>
              <td>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={probe?.issuerID === issuer.id && probe.status === "pending"}
                  onClick={() => onTestConnection(issuer)}
                  aria-label={`Test connection ${issuer.name}`}
                >
                  Test
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
  return <ErrorState title="Issuer metadata unavailable">{notice.message}</ErrorState>;
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

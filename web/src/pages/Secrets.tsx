import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Copy, Eye, KeyRound, Loader2, LogIn, RefreshCw, RotateCw, Share2, Trash2, X } from "lucide-react";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { DataGridToolbar } from "@/components/DataGridToolbar";
import { DetailDrawer } from "@/components/DetailDrawer";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { SecretTree, ReferenceResolver, EnvDiffPanel, VersionHistory, SecretImport } from "@/components/secrets";
import {
  api,
  ApiError,
  type DynamicLease,
  type EphemeralAPIKey,
  type MachineLoginResponse,
  type PKISecret,
  type SecretMeta,
  type SecretScan,
  type SecretSync,
  type SecretValue,
  type ShareToken,
  type ShareValue,
  type TransitCiphertext,
  type TransitHMAC,
  type TransitSignature,
} from "@/lib/api";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";

export function Secrets() {
  const [items, setItems] = useState<SecretMeta[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [secretSearch, setSecretSearch] = useState("");
  const [detailSecretName, setDetailSecretName] = useState<string | null>(null);

  const [createName, setCreateName] = useState("");
  const [createValue, setCreateValue] = useState("");
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const [revealed, setRevealed] = useState<SecretValue | null>(null);
  const [revealBusy, setRevealBusy] = useState<string | null>(null);
  const [revealError, setRevealError] = useState<string | null>(null);

  const [rotateName, setRotateName] = useState("");
  const [rotateValue, setRotateValue] = useState("");
  const [rotateBusy, setRotateBusy] = useState(false);
  const [rotateError, setRotateError] = useState<string | null>(null);

  const [deleteName, setDeleteName] = useState("");
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const [accessName, setAccessName] = useState("");
  const [accessResult, setAccessResult] = useState<{ name: string; version?: number } | null>(null);
  const [accessBusy, setAccessBusy] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);

  const [pkiName, setPkiName] = useState("");
  const [pkiTTL, setPkiTTL] = useState("900");
  const [pkiBusy, setPkiBusy] = useState(false);
  const [pkiError, setPkiError] = useState<string | null>(null);
  const [pkiBundle, setPkiBundle] = useState<PKISecret | null>(null);

  const [loginMethod, setLoginMethod] = useState("token");
  const [loginCredential, setLoginCredential] = useState("");
  const [loginBusy, setLoginBusy] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [session, setSession] = useState<MachineLoginResponse | null>(null);

  const [shareValueInput, setShareValueInput] = useState("");
  const [shareTTL, setShareTTL] = useState("300");
  const [shareBusy, setShareBusy] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [shareToken, setShareToken] = useState<ShareToken | null>(null);
  const [redeemToken, setRedeemToken] = useState("");
  const [redeemBusy, setRedeemBusy] = useState(false);
  const [redeemError, setRedeemError] = useState<string | null>(null);
  const [redeemed, setRedeemed] = useState<ShareValue | null>(null);

  const [ephemeralSubject, setEphemeralSubject] = useState("");
  const [ephemeralScopes, setEphemeralScopes] = useState("");
  const [ephemeralTTL, setEphemeralTTL] = useState("900");
  const [ephemeralBusy, setEphemeralBusy] = useState(false);
  const [ephemeralError, setEphemeralError] = useState<string | null>(null);
  const [ephemeralKey, setEphemeralKey] = useState<EphemeralAPIKey | null>(null);

  const [leaseProvider, setLeaseProvider] = useState("postgresql");
  const [leaseRole, setLeaseRole] = useState("");
  const [leaseTTL, setLeaseTTL] = useState("1200");
  const [leaseExtendSeconds, setLeaseExtendSeconds] = useState("300");
  const [leaseBusy, setLeaseBusy] = useState<"issue" | "renew" | "revoke" | null>(null);
  const [leaseError, setLeaseError] = useState<string | null>(null);
  const [lease, setLease] = useState<DynamicLease | null>(null);
  const [leaseCredential, setLeaseCredential] = useState<{ id: string; credential: string } | null>(null);

  const [transitKey, setTransitKey] = useState("");
  const [transitPlaintext, setTransitPlaintext] = useState("");
  const [transitAAD, setTransitAAD] = useState("");
  const [transitCiphertextInput, setTransitCiphertextInput] = useState("");
  const [transitMessage, setTransitMessage] = useState("");
  const [transitBusy, setTransitBusy] = useState<"encrypt" | "decrypt" | "hmac" | "rewrap" | "sign" | null>(null);
  const [transitError, setTransitError] = useState<string | null>(null);
  const [transitCiphertext, setTransitCiphertext] = useState<TransitCiphertext | null>(null);
  const [transitPlaintextResult, setTransitPlaintextResult] = useState<string | null>(null);
  const [transitHMACResult, setTransitHMACResult] = useState<TransitHMAC | null>(null);
  const [transitSignature, setTransitSignature] = useState<TransitSignature | null>(null);

  const [scanPath, setScanPath] = useState("");
  const [scanBusy, setScanBusy] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<SecretScan | null>(null);

  const [syncName, setSyncName] = useState("");
  const [syncTarget, setSyncTarget] = useState("");
  const [syncRemoteKey, setSyncRemoteKey] = useState("");
  const [syncBusy, setSyncBusy] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [syncResult, setSyncResult] = useState<SecretSync | null>(null);

  async function load(cursor?: string) {
    setLoadError(null);
    setLoading(true);
    try {
      const page = await api.secretPage({ limit: 20, cursor });
      setItems((current) => (cursor ? mergeMeta(current, page.items) : page.items));
      setNextCursor(page.next_cursor);
      setAccessName((current) => current || page.items[0]?.name || "");
      setSyncName((current) => current || page.items[0]?.name || "");
    } catch (err) {
      setLoadError(apiProblemMessage(err, "Secrets API unavailable or disabled"));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  const selectedMeta = useMemo(() => items.find((item) => item.name === accessName) ?? items[0] ?? null, [items, accessName]);
  const filteredItems = useMemo(() => {
    const needle = secretSearch.trim().toLowerCase();
    if (!needle) return items;
    return items.filter((item) =>
      [item.name, String(item.version ?? ""), item.created_at ?? "", item.updated_at ?? "", "native store"].join(" ").toLowerCase().includes(needle),
    );
  }, [items, secretSearch]);
  const detailSecret = useMemo(() => items.find((item) => item.name === detailSecretName) ?? null, [detailSecretName, items]);

  const secretColumns = useMemo<Array<DataGridColumn<SecretMeta>>>(
    () => [
      { id: "name", header: "Name", sortable: true, cell: (item) => <span className="font-medium">{item.name}</span> },
      { id: "engine", header: "Engine", cell: () => "native store" },
      { id: "version", header: "Version", cell: (item) => <span className="font-mono text-xs">v{item.version}</span> },
      { id: "updated", header: "Updated", cell: (item) => formatDate(item.updated_at) },
      { id: "created", header: "Created", cell: (item) => formatDate(item.created_at) },
      {
        id: "actions",
        header: "Actions",
        cell: (item) => (
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" variant="outline" onClick={() => void revealSecret(item.name)} disabled={revealBusy === item.name}>
              {revealBusy === item.name ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
              Reveal once
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={() => setRotateName(item.name)}>
              <RotateCw className="h-4 w-4" aria-hidden="true" />
              Prepare rotate
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={() => setDeleteName(item.name)}>
              <Trash2 className="h-4 w-4" aria-hidden="true" />
              Prepare delete
            </Button>
          </div>
        ),
      },
    ],
    [revealBusy],
  );

  async function submitCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setCreateError(null);
    setNotice(null);
    setCreateBusy(true);
    try {
      const meta = await api.createSecret({ name: createName, value: createValue });
      setItems((current) => mergeMeta(current, [meta]));
      setCreateName("");
      setCreateValue("");
      setNotice(`Secret ${meta.name} stored as version ${meta.version}. The value was sealed and is not shown after submit.`);
    } catch (err) {
      setCreateError(apiProblemMessage(err, "Could not create secret"));
    } finally {
      setCreateBusy(false);
    }
  }

  async function revealSecret(name: string) {
    setRevealError(null);
    setRevealed(null);
    setRevealBusy(name);
    try {
      setRevealed(await api.getSecret(name));
    } catch (err) {
      setRevealError(apiProblemMessage(err, "Could not reveal secret"));
    } finally {
      setRevealBusy(null);
    }
  }

  async function submitRotate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRotateError(null);
    setNotice(null);
    setRotateBusy(true);
    try {
      const meta = await api.rotateSecret(rotateName, { name: rotateName, value: rotateValue });
      setItems((current) => mergeMeta(current, [meta]));
      setRotateName("");
      setRotateValue("");
      setNotice(`Secret ${meta.name} rotated to version ${meta.version}. The replacement value was not rendered.`);
    } catch (err) {
      setRotateError(apiProblemMessage(err, "Could not rotate secret"));
    } finally {
      setRotateBusy(false);
    }
  }

  async function submitDelete(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setDeleteError(null);
    setNotice(null);
    setDeleteBusy(true);
    try {
      await api.deleteSecret(deleteName);
      setItems((current) => current.filter((item) => item.name !== deleteName));
      setNotice(`Secret ${deleteName} deleted from the native store.`);
      setDeleteName("");
      setDeleteConfirm("");
    } catch (err) {
      setDeleteError(apiProblemMessage(err, "Could not delete secret"));
    } finally {
      setDeleteBusy(false);
    }
  }

  async function runAccessTest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAccessError(null);
    setAccessResult(null);
    setAccessBusy(true);
    try {
      const value = await api.getSecret(accessName);
      setAccessResult({ name: value.name, version: value.version });
    } catch (err) {
      setAccessError(apiProblemMessage(err, "Access test failed"));
    } finally {
      setAccessBusy(false);
    }
  }

  async function submitPKI(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPkiError(null);
    setPkiBundle(null);
    setPkiBusy(true);
    try {
      const ttl = Number(pkiTTL);
      setPkiBundle(await api.issuePKISecret({ common_name: pkiName, ttl_seconds: Number.isFinite(ttl) ? ttl : undefined }));
      setPkiName("");
    } catch (err) {
      setPkiError(apiProblemMessage(err, "Could not issue PKI secret"));
    } finally {
      setPkiBusy(false);
    }
  }

  async function submitLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoginError(null);
    setSession(null);
    setLoginBusy(true);
    try {
      setSession(await api.machineLogin({ method: loginMethod, credential: loginCredential }));
      setLoginCredential("");
    } catch (err) {
      setLoginError(apiProblemMessage(err, "Machine login failed"));
    } finally {
      setLoginBusy(false);
    }
  }

  async function submitShare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setShareError(null);
    setShareToken(null);
    setShareBusy(true);
    try {
      const ttl = Number(shareTTL);
      setShareToken(await api.createShare({ value: shareValueInput, ttl_seconds: Number.isFinite(ttl) ? ttl : undefined }));
      setShareValueInput("");
    } catch (err) {
      setShareError(apiProblemMessage(err, "Could not create one-time share"));
    } finally {
      setShareBusy(false);
    }
  }

  async function submitRedeem(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRedeemError(null);
    setRedeemed(null);
    setRedeemBusy(true);
    try {
      setRedeemed(await api.redeemShare({ token: redeemToken }));
    } catch (err) {
      setRedeemError(apiProblemMessage(err, "Could not redeem one-time share"));
    } finally {
      setRedeemBusy(false);
    }
  }

  async function submitEphemeralAPIKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setEphemeralError(null);
    setEphemeralKey(null);
    setEphemeralBusy(true);
    try {
      const subject = ephemeralSubject.trim();
      const scopes = parseScopeList(ephemeralScopes);
      const ttl = Number(ephemeralTTL);
      if (!subject) throw new Error("Subject is required");
      if (scopes.length === 0) throw new Error("At least one scope is required");
      if (!Number.isFinite(ttl) || ttl <= 0) throw new Error("TTL seconds must be a positive number");
      setEphemeralKey(await api.issueEphemeralAPIKey({ subject, scopes, ttl_seconds: Math.round(ttl) }));
      setEphemeralSubject("");
      setEphemeralScopes("");
    } catch (err) {
      setEphemeralError(apiProblemMessage(err, "Could not issue ephemeral API key"));
    } finally {
      setEphemeralBusy(false);
    }
  }

  async function submitDynamicLease(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLeaseError(null);
    setLeaseCredential(null);
    setLeaseBusy("issue");
    try {
      const role = leaseRole.trim();
      const ttl = Number(leaseTTL);
      if (!role) throw new Error("Role is required");
      if (!Number.isFinite(ttl) || ttl <= 0) throw new Error("TTL seconds must be a positive number");
      const issued = await api.issueDynamicLease({ provider: leaseProvider, role, ttl_seconds: Math.round(ttl) });
      setLease(leaseMetadataOnly(issued));
      if (issued.credential) setLeaseCredential({ id: issued.id, credential: issued.credential });
      setLeaseRole("");
    } catch (err) {
      setLeaseError(apiProblemMessage(err, "Could not issue dynamic lease"));
    } finally {
      setLeaseBusy(null);
    }
  }

  async function renewDynamicLease() {
    if (!lease) return;
    setLeaseError(null);
    setLeaseBusy("renew");
    try {
      const extendSeconds = Number(leaseExtendSeconds);
      if (!Number.isFinite(extendSeconds) || extendSeconds <= 0) throw new Error("Extend seconds must be a positive number");
      setLease(leaseMetadataOnly(await api.renewDynamicLease(lease.id, { extend_seconds: Math.round(extendSeconds) })));
    } catch (err) {
      setLeaseError(apiProblemMessage(err, "Could not renew dynamic lease"));
    } finally {
      setLeaseBusy(null);
    }
  }

  async function revokeDynamicLease() {
    if (!lease) return;
    setLeaseError(null);
    setLeaseCredential(null);
    setLeaseBusy("revoke");
    try {
      setLease(leaseMetadataOnly(await api.revokeDynamicLease(lease.id)));
    } catch (err) {
      setLeaseError(apiProblemMessage(err, "Could not revoke dynamic lease"));
    } finally {
      setLeaseBusy(null);
    }
  }

  async function encryptTransit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setTransitError(null);
    setTransitPlaintextResult(null);
    setTransitBusy("encrypt");
    try {
      const ciphertext = await api.encryptTransit({
        key: transitKey.trim(),
        plaintext: encodeTransitBytes(transitPlaintext),
        ...(transitAAD.trim() ? { aad: encodeTransitBytes(transitAAD.trim()) } : {}),
      });
      setTransitCiphertext(ciphertext);
      setTransitCiphertextInput(ciphertext.ciphertext);
      setTransitPlaintext("");
    } catch (err) {
      setTransitError(apiProblemMessage(err, "Could not encrypt plaintext"));
    } finally {
      setTransitBusy(null);
    }
  }

  async function decryptTransit() {
    setTransitError(null);
    setTransitPlaintextResult(null);
    setTransitBusy("decrypt");
    try {
      const result = await api.decryptTransit({
        key: transitKey.trim(),
        ciphertext: transitCiphertextInput.trim(),
        ...(transitAAD.trim() ? { aad: encodeTransitBytes(transitAAD.trim()) } : {}),
      });
      setTransitPlaintextResult(decodeTransitBytes(result.plaintext));
    } catch (err) {
      setTransitError(apiProblemMessage(err, "Could not decrypt ciphertext"));
    } finally {
      setTransitBusy(null);
    }
  }

  async function hmacTransit() {
    setTransitError(null);
    setTransitHMACResult(null);
    setTransitBusy("hmac");
    try {
      setTransitHMACResult(await api.hmacTransit({ key: transitKey.trim(), data: encodeTransitBytes(transitMessage) }));
    } catch (err) {
      setTransitError(apiProblemMessage(err, "Could not compute HMAC"));
    } finally {
      setTransitBusy(null);
    }
  }

  async function rewrapTransit() {
    setTransitError(null);
    setTransitBusy("rewrap");
    try {
      const result = await api.rewrapTransit({
        key: transitKey.trim(),
        ciphertext: transitCiphertextInput.trim(),
        ...(transitAAD.trim() ? { aad: encodeTransitBytes(transitAAD.trim()) } : {}),
      });
      setTransitCiphertext(result);
      setTransitCiphertextInput(result.ciphertext);
    } catch (err) {
      setTransitError(apiProblemMessage(err, "Could not rewrap ciphertext"));
    } finally {
      setTransitBusy(null);
    }
  }

  async function signTransit() {
    setTransitError(null);
    setTransitSignature(null);
    setTransitBusy("sign");
    try {
      setTransitSignature(await api.signTransit({ key: transitKey.trim(), message: encodeTransitBytes(transitMessage) }));
    } catch (err) {
      setTransitError(apiProblemMessage(err, "Could not sign message"));
    } finally {
      setTransitBusy(null);
    }
  }

  async function submitSecretScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setScanError(null);
    setScanBusy(true);
    try {
      const path = scanPath.trim();
      if (!path) throw new Error("Path is required");
      setScanResult(await api.scanSecrets({ path }));
    } catch (err) {
      setScanError(apiProblemMessage(err, "Could not run secret scan"));
    } finally {
      setScanBusy(false);
    }
  }

  async function submitSecretSync(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSyncError(null);
    setSyncBusy(true);
    try {
      const name = syncName.trim();
      const target = syncTarget.trim();
      const remoteKey = syncRemoteKey.trim();
      if (!name) throw new Error("Secret name is required");
      if (!target) throw new Error("Target is required");
      setSyncResult(await api.syncSecret({ name, target, ...(remoteKey ? { remote_key: remoteKey } : {}) }));
    } catch (err) {
      setSyncError(apiProblemMessage(err, "Could not sync secret"));
    } finally {
      setSyncBusy(false);
    }
  }

  return (
    <section aria-labelledby="secrets-heading" className="grid gap-6">
      <PageHeader
        titleId="secrets-heading"
        title="Secrets"
        description="Secret-store, machine-login, PKI-secret, and one-time-share workflows. Metadata is durable; returned values, keys, and tokens are explicit reveal-once material."
        actions={
          <Button type="button" variant="outline" onClick={() => void load()} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
            Refresh
          </Button>
        }
      />

      {notice && (
        <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
          {notice}
        </p>
      )}

      {loadError && (
        <UnavailableState title="Secrets API unavailable or disabled">
          {loadError}. Secret operations are fail-closed until the feature is enabled and a key-encryption key is configured.
        </UnavailableState>
      )}

      <SecretTree secrets={items} />

      <div className="grid gap-4 lg:grid-cols-2">
        <ReferenceResolver />
        <EnvDiffPanel secrets={items} />
      </div>

      <SecretImport onImported={() => void load()} />

      <section aria-labelledby="store-heading" className="grid gap-4 border-y border-border py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="store-heading" className="text-title font-semibold">
              Native secret store
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              The native store returns names and versions only. Create and rotate send a value once, then this page drops the input and shows metadata.
            </p>
          </div>
        </div>

        <form aria-label="Create secret" onSubmit={(event) => void submitCreate(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Secret name</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={createName}
              onChange={(event) => setCreateName(event.target.value)}
              placeholder="app/db/password"
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Secret value</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              type="password"
              value={createValue}
              onChange={(event) => setCreateValue(event.target.value)}
              required
            />
          </label>
          <Button type="submit" className="self-end" disabled={createBusy || Boolean(loadError)}>
            {createBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            Create secret
          </Button>
        </form>
        {createError && <ErrorState title="Secret create failed">{createError}</ErrorState>}

        {!loadError && (
          <DataGrid
            ariaLabel="Native secret metadata"
            rows={filteredItems}
            columns={secretColumns}
            getRowId={(item) => item.name}
            state={loading ? "loading" : filteredItems.length === 0 ? "empty" : "ready"}
            stateTitle={items.length === 0 ? "No secrets stored yet" : "No matching secret metadata"}
            stateMessage={
              items.length === 0
                ? "Create a tenant-scoped native-store secret. Only the name and version return to the metadata table."
                : "No secret metadata matches the current search."
            }
            showColumnChooser
            toolbar={({ columnChooser }) => (
              <DataGridToolbar
                searchLabel="Search native secret metadata"
                searchPlaceholder="Search names or metadata"
                searchValue={secretSearch}
                onSearchChange={setSecretSearch}
                filters={<span className="rounded-control border border-border px-2.5 py-2 text-sm text-muted-foreground">Engine: native store</span>}
                columnChooser={columnChooser}
              />
            )}
            onRowOpen={(item) => setDetailSecretName(item.name)}
            rowActionLabel={() => "View metadata"}
          />
        )}
        {nextCursor && (
          <Button type="button" variant="outline" onClick={() => void load(nextCursor)} disabled={loading}>
            Load next metadata page
          </Button>
        )}
        {revealError && <ErrorState title="Reveal failed">{revealError}</ErrorState>}
        {revealed && (
          <RevealPanel title={`Reveal-once value for ${revealed.name}`} onDismiss={() => setRevealed(null)} value={revealed.value}>
            Version {revealed.version ?? "latest"} was returned for this secret. Dismiss clears it from the page.
          </RevealPanel>
        )}
        <DetailDrawer
          open={!!detailSecret}
          title="Secret metadata"
          description="Native-store metadata only; secret values are never shown here."
          onClose={() => setDetailSecretName(null)}
        >
          {detailSecret && (
            <dl className="grid gap-3 text-sm md:grid-cols-2">
              <div>
                <dt className="font-medium text-muted-foreground">Name</dt>
                <dd className="break-all">{detailSecret.name}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Engine</dt>
                <dd>native store</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Version</dt>
                <dd className="font-mono text-xs">v{detailSecret.version}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Updated</dt>
                <dd>{formatDate(detailSecret.updated_at)}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Created</dt>
                <dd>{formatDate(detailSecret.created_at)}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Value handling</dt>
                <dd>Reveal-once only; no value is stored in this drawer, browser storage, or the URL.</dd>
              </div>
            </dl>
          )}
          {detailSecret && <VersionHistory name={detailSecret.name} latestVersion={detailSecret.version} />}
        </DetailDrawer>
      </section>

      <section aria-labelledby="rotate-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="rotate-heading" className="text-title font-semibold">
            Manual rotation and delete
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Manual native-store rotation replaces one stored value at a time. Scheduled rotation and downstream sync controls aren't in the console yet.
          </p>
        </div>
        <UnavailableState title="Scheduled rotation and downstream sync aren't in the console yet">
          Rollback-safe static rotation is available for configured backends. Scheduled rotation, downstream sync, and delivery receipts are not yet exposed in
          this console, so this page offers only per-secret rotate/delete controls.
        </UnavailableState>
        <form aria-label="Rotate secret" onSubmit={(event) => void submitRotate(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Secret to rotate</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={rotateName}
              onChange={(event) => setRotateName(event.target.value)}
              placeholder={selectedMeta?.name ?? "app/db/password"}
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Replacement value</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              type="password"
              value={rotateValue}
              onChange={(event) => setRotateValue(event.target.value)}
              required
            />
          </label>
          <Button type="submit" className="self-end" disabled={rotateBusy || Boolean(loadError)}>
            {rotateBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            Rotate secret
          </Button>
        </form>
        {rotateError && <ErrorState title="Rotation failed">{rotateError}</ErrorState>}

        <form aria-label="Delete secret" onSubmit={(event) => void submitDelete(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Secret to delete</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={deleteName}
              onChange={(event) => setDeleteName(event.target.value)}
              placeholder={selectedMeta?.name ?? "app/db/password"}
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Type the exact secret name</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={deleteConfirm}
              onChange={(event) => setDeleteConfirm(event.target.value)}
              required
            />
          </label>
          <Button type="submit" className="self-end" disabled={deleteBusy || !deleteName || deleteConfirm !== deleteName || Boolean(loadError)}>
            {deleteBusy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            Delete secret
          </Button>
        </form>
        {deleteError && <ErrorState title="Delete failed">{deleteError}</ErrorState>}
      </section>

      <section aria-labelledby="developer-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="developer-heading" className="text-title font-semibold">
            Developer access
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            SDK and CLI examples contain only names, tenants, and versions. The access test performs a read without rendering the value.
          </p>
        </div>
        <div className="grid gap-3 lg:grid-cols-2">
          <Snippet
            title="CLI injector"
            text={`trstctl secrets get ${selectedMeta?.name ?? "app/db/password"} --tenant current --format env --exec ./service`}
          />
          <Snippet
            title="TypeScript SDK"
            text={`const secret = await client.secrets.get("${selectedMeta?.name ?? "app/db/password"}");\nprocess.env.DB_PASSWORD = secret.value; // keep in process memory only`}
          />
        </div>
        <form aria-label="Secret access test" onSubmit={(event) => void runAccessTest(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Secret name</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={accessName}
              onChange={(event) => setAccessName(event.target.value)}
              placeholder="app/db/password"
              required
            />
          </label>
          <Button type="submit" className="self-end" variant="outline" disabled={accessBusy || Boolean(loadError)}>
            {accessBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
            Run access test
          </Button>
        </form>
        {accessError && <ErrorState title="Access test failed">{accessError}</ErrorState>}
        {accessResult && (
          <p role="status" className="rounded-control border border-status-success/30 bg-status-success/10 px-3 py-2 text-sm text-status-success">
            Access test passed for {accessResult.name}; version {accessResult.version ?? "latest"} was reachable, and the value was not rendered.
          </p>
        )}
      </section>

      <section aria-labelledby="pki-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="pki-heading" className="text-title font-semibold">
            PKI as a secret
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Issue a short-lived certificate bundle and reveal the private key only in the explicit result panel.
          </p>
        </div>
        <form aria-label="Issue PKI secret" onSubmit={(event) => void submitPKI(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_10rem_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Common name</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={pkiName}
              onChange={(event) => setPkiName(event.target.value)}
              placeholder="svc.internal"
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">TTL seconds</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              type="number"
              min="60"
              value={pkiTTL}
              onChange={(event) => setPkiTTL(event.target.value)}
            />
          </label>
          <Button type="submit" className="self-end" disabled={pkiBusy || Boolean(loadError)}>
            {pkiBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
            Issue PKI secret
          </Button>
        </form>
        {pkiError && <ErrorState title="PKI issue failed">{pkiError}</ErrorState>}
        {pkiBundle && (
          <RevealPanel
            title={`PKI bundle ${pkiBundle.serial}`}
            onDismiss={() => setPkiBundle(null)}
            value={`${pkiBundle.certificate}\n${pkiBundle.private_key}`}
          >
            Copy or download now. The serial, certificate, and private key are cleared when dismissed.
          </RevealPanel>
        )}
      </section>

      <section aria-labelledby="machine-login-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="machine-login-heading" className="text-title font-semibold">
            Machine login
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Exchange a machine credential for a scoped workload session. The submitted credential is cleared after submit and never echoed.
          </p>
        </div>
        <form aria-label="Machine login test" onSubmit={(event) => void submitLogin(event)} className="grid gap-3 md:grid-cols-[12rem_minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Method</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={loginMethod}
              onChange={(event) => setLoginMethod(event.target.value)}
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Credential</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              type="password"
              value={loginCredential}
              onChange={(event) => setLoginCredential(event.target.value)}
              required
            />
          </label>
          <Button type="submit" className="self-end" disabled={loginBusy || Boolean(loadError)}>
            {loginBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <LogIn className="h-4 w-4" aria-hidden="true" />}
            Test login
          </Button>
        </form>
        {loginError && <ErrorState title="Machine login failed">{loginError}</ErrorState>}
        {session && <MachineSession session={session} />}
        <UnavailableState title="Auth-method administration isn't in the console yet">
          Configured token methods, audience rules, issued-session ledger, and revoked methods are not available in the console yet. This page exposes only the
          login exchange.
        </UnavailableState>
      </section>

      <section aria-labelledby="share-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="share-heading" className="text-title font-semibold">
            One-time sharing
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Create returns a bearer token once. Redeem returns the value once; a later redeem is expected to fail closed.
          </p>
        </div>
        <UnavailableState title="Secret-change approvals aren't in the console yet">
          Request/approve state for sensitive secret mutations is not available in the console yet. This page exposes the one-time share path and no fake
          approval queue.
        </UnavailableState>
        <div className="grid gap-4 xl:grid-cols-2">
          <form aria-label="Create one-time share" onSubmit={(event) => void submitShare(event)} className="grid content-start gap-3">
            <label className="grid gap-1 text-sm">
              <span className="font-medium">Value to share</span>
              <input
                className="rounded-md border border-input bg-background px-3 py-2"
                type="password"
                value={shareValueInput}
                onChange={(event) => setShareValueInput(event.target.value)}
                required
              />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium">TTL seconds</span>
              <input
                className="rounded-md border border-input bg-background px-3 py-2"
                type="number"
                min="60"
                value={shareTTL}
                onChange={(event) => setShareTTL(event.target.value)}
              />
            </label>
            <Button type="submit" disabled={shareBusy || Boolean(loadError)}>
              {shareBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Share2 className="h-4 w-4" aria-hidden="true" />}
              Create share
            </Button>
            {shareError && <ErrorState title="Share create failed">{shareError}</ErrorState>}
          </form>
          <form aria-label="Redeem one-time share" onSubmit={(event) => void submitRedeem(event)} className="grid content-start gap-3">
            <label className="grid gap-1 text-sm">
              <span className="font-medium">Share token</span>
              <input
                className="rounded-md border border-input bg-background px-3 py-2"
                value={redeemToken}
                onChange={(event) => setRedeemToken(event.target.value)}
                required
              />
            </label>
            <Button type="submit" variant="outline" disabled={redeemBusy || Boolean(loadError)}>
              {redeemBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
              Redeem share
            </Button>
            {redeemError && <ErrorState title="Share redeem failed">{redeemError}</ErrorState>}
          </form>
        </div>
        {shareToken && (
          <RevealPanel title="One-time share token" onDismiss={() => setShareToken(null)} value={shareToken.token}>
            Expires {formatDate(shareToken.expires_at)}. The token is bearer material; copy it now, then dismiss.
          </RevealPanel>
        )}
        {redeemed && (
          <RevealPanel title="Redeemed share value" onDismiss={() => setRedeemed(null)} value={redeemed.value}>
            This value is the exact-once redeem result. A second redeem should fail.
          </RevealPanel>
        )}
      </section>

      <section aria-labelledby="ephemeral-api-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="ephemeral-api-heading" className="text-title font-semibold">
            Ephemeral API keys
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Issue a scoped, short-lived key for a machine task. The server returns the raw token once; after dismissal this page keeps no copy.
          </p>
          {/* TRACE-005 source anchor: ephemeral API-key issuance is served; POST /api/v1/ephemeral/api-keys; trstctl-cli ephemeral api-keys issue; api_token.revoked */}
        </div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(18rem,0.7fr)]">
          <form aria-label="Issue ephemeral API key" onSubmit={(event) => void submitEphemeralAPIKey(event)} className="grid content-start gap-3">
            <label className="grid gap-1 text-sm">
              <span className="font-medium">Subject</span>
              <input
                className="rounded-md border border-input bg-background px-3 py-2"
                value={ephemeralSubject}
                onChange={(event) => setEphemeralSubject(event.target.value)}
                placeholder="ci/deploy-preview"
                required
              />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium">Scopes</span>
              <textarea
                className="min-h-24 rounded-md border border-input bg-background px-3 py-2"
                value={ephemeralScopes}
                onChange={(event) => setEphemeralScopes(event.target.value)}
                placeholder="repo:payments:read, deploy:staging:write"
                required
              />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium">TTL seconds</span>
              <input
                className="rounded-md border border-input bg-background px-3 py-2"
                type="number"
                min="60"
                value={ephemeralTTL}
                onChange={(event) => setEphemeralTTL(event.target.value)}
                required
              />
            </label>
            <Button type="submit" disabled={ephemeralBusy || Boolean(loadError)}>
              {ephemeralBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
              Issue API key
            </Button>
            {ephemeralError && <ErrorState title="Ephemeral API-key issue failed">{ephemeralError}</ErrorState>}
          </form>
          <div className="ui-panel grid content-start gap-2 p-comfortable text-sm">
            <h3 className="text-title font-semibold">Reveal-once key issuance</h3>
            <p className="text-muted-foreground">
              Send the subject, scopes, and TTL to issue a short-lived token. Copy the returned token from the reveal panel, then dismiss it so browser memory
              drops the raw key.
            </p>
          </div>
        </div>
        {ephemeralKey && (
          <RevealPanel title="Ephemeral API key" onDismiss={() => setEphemeralKey(null)} value={ephemeralKey.token}>
            Key <span className="font-mono text-xs">{ephemeralKey.id}</span> for {ephemeralKey.subject} expires {formatDate(ephemeralKey.expires_at)}. Scopes:{" "}
            {ephemeralKey.scopes.join(", ")}.
          </RevealPanel>
        )}
      </section>

      <section aria-labelledby="secret-scanning-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="secret-scanning-heading" className="text-title font-semibold">
            Code and CI secret scanning bridge
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Run a scan for a repository or build workspace. Findings show rule, file, line, and the redacted credential reference only.
          </p>
          {/* TRACE-005 source anchor: secret-scanning triage is library-only */}
        </div>
        <form aria-label="Run secret scan" onSubmit={(event) => void submitSecretScan(event)} className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Path</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={scanPath}
              onChange={(event) => setScanPath(event.target.value)}
              placeholder="github.com/example/payments"
              required
            />
          </label>
          <Button type="submit" className="self-end" disabled={scanBusy || Boolean(loadError)}>
            {scanBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
            Run scan
          </Button>
        </form>
        {scanError && <ErrorState title="Secret scan failed">{scanError}</ErrorState>}
        {scanResult && (
          <div className="ui-panel grid gap-3 p-comfortable text-sm">
            <dl className="grid gap-2 md:grid-cols-4">
              <div>
                <dt className="font-medium text-muted-foreground">Run ID</dt>
                <dd className="break-all font-mono text-xs">{scanResult.run_id}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Scanner</dt>
                <dd>{scanResult.scanner}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Rules</dt>
                <dd>{scanResult.rules_active}</dd>
              </div>
              <div>
                <dt className="font-medium text-muted-foreground">Findings</dt>
                <dd>{scanResult.findings_count}</dd>
              </div>
            </dl>
            <div className="overflow-x-auto">
              <table className="ui-table min-w-[48rem]">
                <caption className="sr-only">Secret scan findings</caption>
                <thead>
                  <tr>
                    <th scope="col">Rule</th>
                    <th scope="col">File</th>
                    <th scope="col">Line</th>
                    <th scope="col">Redacted reference</th>
                  </tr>
                </thead>
                <tbody>
                  {scanResult.findings.map((finding) => (
                    <tr key={`${finding.rule_id}-${finding.file}-${finding.line}`} className="align-top">
                      <td>{finding.rule_id}</td>
                      <td>{finding.file}</td>
                      <td className="font-mono text-xs">{finding.line}</td>
                      <td className="font-mono text-xs">{finding.credential_ref}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>

      <section aria-labelledby="dynamic-secrets-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="dynamic-secrets-heading" className="text-title font-semibold">
            Dynamic secrets
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Issue a lease-scoped credential from a configured provider, renew its expiry when needed, or revoke it immediately. Generated credentials are shown
            once and then cleared from the page.
          </p>
          {/* TRACE-005 source anchor: dynamic secret leases are served; POST /api/v1/secrets/leases; secrets:read */}
        </div>
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(22rem,0.8fr)]">
          <form aria-label="Issue dynamic secret lease" onSubmit={(event) => void submitDynamicLease(event)} className="grid content-start gap-3">
            <label className="grid gap-1 text-sm">
              <span className="font-medium">Provider</span>
              <select
                className="rounded-md border border-input bg-background px-3 py-2"
                value={leaseProvider}
                onChange={(event) => setLeaseProvider(event.target.value)}
              >
                <option value="postgresql">PostgreSQL</option>
                <option value="aws-iam">AWS IAM</option>
                <option value="kubernetes">Kubernetes</option>
                <option value="redis">Redis</option>
              </select>
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium">Role</span>
              <input
                className="rounded-md border border-input bg-background px-3 py-2"
                value={leaseRole}
                onChange={(event) => setLeaseRole(event.target.value)}
                placeholder="readonly-reporting"
                required
              />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="font-medium">TTL seconds</span>
              <input
                className="rounded-md border border-input bg-background px-3 py-2"
                type="number"
                min="60"
                value={leaseTTL}
                onChange={(event) => setLeaseTTL(event.target.value)}
                required
              />
            </label>
            <Button type="submit" disabled={leaseBusy === "issue" || Boolean(loadError)}>
              {leaseBusy === "issue" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
              Issue lease
            </Button>
          </form>
          <div className="ui-panel grid content-start gap-3 p-comfortable text-sm">
            <h3 className="text-title font-semibold">Lease state</h3>
            {lease ? (
              <>
                <DynamicLeaseMetadata lease={lease} />
                <label className="grid gap-1">
                  <span className="font-medium">Extend seconds</span>
                  <input
                    className="rounded-md border border-input bg-background px-3 py-2"
                    type="number"
                    min="60"
                    value={leaseExtendSeconds}
                    onChange={(event) => setLeaseExtendSeconds(event.target.value)}
                  />
                </label>
                <div className="flex flex-wrap gap-2">
                  <Button type="button" variant="outline" onClick={() => void renewDynamicLease()} disabled={leaseBusy === "renew" || lease.state === "revoked"}>
                    {leaseBusy === "renew" ? (
                      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                    ) : (
                      <RotateCw className="h-4 w-4" aria-hidden="true" />
                    )}
                    Renew lease
                  </Button>
                  <Button type="button" variant="outline" onClick={() => void revokeDynamicLease()} disabled={leaseBusy === "revoke" || lease.state === "revoked"}>
                    {leaseBusy === "revoke" ? (
                      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                    ) : (
                      <Trash2 className="h-4 w-4" aria-hidden="true" />
                    )}
                    Revoke lease
                  </Button>
                </div>
              </>
            ) : (
              <p className="text-muted-foreground">No dynamic lease issued yet.</p>
            )}
          </div>
        </div>
        {leaseError && <ErrorState title="Dynamic lease operation failed">{leaseError}</ErrorState>}
        {leaseCredential && (
          <RevealPanel title={`Generated credential for lease ${leaseCredential.id}`} onDismiss={() => setLeaseCredential(null)} value={leaseCredential.credential}>
            Copy this generated credential now. Renew and revoke actions keep only lease metadata.
          </RevealPanel>
        )}
      </section>

      <section aria-labelledby="transit-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="transit-heading" className="text-title font-semibold">
            Transit and KMIP
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Transit operations keep key material server-side. This page base64-encodes local plaintext for the API, clears plaintext inputs after encrypt, and
            shows decrypted values only in a reveal panel.
          </p>
        </div>
        <form aria-label="Transit encrypt and decrypt" onSubmit={(event) => void encryptTransit(event)} className="grid gap-3 xl:grid-cols-[14rem_minmax(0,1fr)]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Key name</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={transitKey}
              onChange={(event) => setTransitKey(event.target.value)}
              placeholder="payments-pii"
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">AAD</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={transitAAD}
              onChange={(event) => setTransitAAD(event.target.value)}
              placeholder="optional associated data"
            />
          </label>
          <label className="grid gap-1 text-sm xl:col-span-2">
            <span className="font-medium">Plaintext</span>
            <textarea
              className="min-h-24 rounded-md border border-input bg-background px-3 py-2"
              value={transitPlaintext}
              onChange={(event) => setTransitPlaintext(event.target.value)}
              placeholder="local plaintext to encrypt"
            />
          </label>
          <label className="grid gap-1 text-sm xl:col-span-2">
            <span className="font-medium">Ciphertext</span>
            <textarea
              className="min-h-24 rounded-md border border-input bg-background px-3 py-2 font-mono text-xs"
              value={transitCiphertextInput}
              onChange={(event) => setTransitCiphertextInput(event.target.value)}
              placeholder="encrypted result or ciphertext to decrypt"
            />
          </label>
          <div className="flex flex-wrap gap-2 xl:col-span-2">
            <Button type="submit" disabled={transitBusy === "encrypt" || !transitPlaintext.trim() || Boolean(loadError)}>
              {transitBusy === "encrypt" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
              Encrypt
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => void decryptTransit()}
              disabled={transitBusy === "decrypt" || !transitCiphertextInput.trim() || Boolean(loadError)}
            >
              {transitBusy === "decrypt" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
              Decrypt
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => void rewrapTransit()}
              disabled={transitBusy === "rewrap" || !transitCiphertextInput.trim() || Boolean(loadError)}
            >
              {transitBusy === "rewrap" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RotateCw className="h-4 w-4" aria-hidden="true" />}
              Rewrap
            </Button>
          </div>
        </form>
        <div className="grid gap-4 xl:grid-cols-2">
          <div className="ui-panel grid gap-3 p-comfortable text-sm">
            <h3 className="text-title font-semibold">Transit result</h3>
            {transitCiphertext ? (
              <dl className="grid gap-2">
                <div>
                  <dt className="font-medium text-muted-foreground">Ciphertext</dt>
                  <dd className="break-all font-mono text-xs">{transitCiphertext.ciphertext}</dd>
                </div>
                <div>
                  <dt className="font-medium text-muted-foreground">Key version</dt>
                  <dd className="font-mono text-xs">v{transitCiphertext.version}</dd>
                </div>
              </dl>
            ) : (
              <p className="text-muted-foreground">No transit ciphertext yet.</p>
            )}
          </div>
          <div className="ui-panel grid gap-3 p-comfortable text-sm">
            <h3 className="text-title font-semibold">HMAC and signing</h3>
            <label className="grid gap-1">
              <span className="font-medium">Message</span>
              <textarea
                className="min-h-20 rounded-md border border-input bg-background px-3 py-2"
                value={transitMessage}
                onChange={(event) => setTransitMessage(event.target.value)}
                placeholder="message bytes to MAC or sign"
              />
            </label>
            <div className="flex flex-wrap gap-2">
              <Button type="button" variant="outline" onClick={() => void hmacTransit()} disabled={transitBusy === "hmac" || !transitMessage.trim() || Boolean(loadError)}>
                {transitBusy === "hmac" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                Compute HMAC
              </Button>
              <Button type="button" variant="outline" onClick={() => void signTransit()} disabled={transitBusy === "sign" || !transitMessage.trim() || Boolean(loadError)}>
                {transitBusy === "sign" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <KeyRound className="h-4 w-4" aria-hidden="true" />}
                Sign message
              </Button>
            </div>
            {transitHMACResult && <Snippet title="HMAC" text={transitHMACResult.hmac} />}
            {transitSignature && <Snippet title="Signature" text={`${transitSignature.signature}\npublic_der: ${transitSignature.public_der}`} />}
          </div>
        </div>
        {transitError && <ErrorState title="Transit operation failed">{transitError}</ErrorState>}
        {transitPlaintextResult && (
          <RevealPanel title="Decrypted plaintext" onDismiss={() => setTransitPlaintextResult(null)} value={transitPlaintextResult}>
            This plaintext was decoded locally from the transit response. Dismiss clears it from the page.
          </RevealPanel>
        )}
      </section>

      <section aria-labelledby="secret-sync-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="secret-sync-heading" className="text-title font-semibold">
            Secret sync and platform integrations
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Push a stored secret to a configured target. The browser sends the secret name and remote key only; the stored value is never rendered here.
          </p>
        </div>
        <form aria-label="Sync stored secret" onSubmit={(event) => void submitSecretSync(event)} className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_14rem_minmax(0,1fr)_auto]">
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Secret name</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={syncName}
              onChange={(event) => setSyncName(event.target.value)}
              placeholder={selectedMeta?.name ?? "app/db/password"}
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Target</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={syncTarget}
              onChange={(event) => setSyncTarget(event.target.value)}
              placeholder="kubernetes/prod"
              required
            />
          </label>
          <label className="grid gap-1 text-sm">
            <span className="font-medium">Remote key</span>
            <input
              className="rounded-md border border-input bg-background px-3 py-2"
              value={syncRemoteKey}
              onChange={(event) => setSyncRemoteKey(event.target.value)}
              placeholder="Secret/payments-db/password"
            />
          </label>
          <Button type="submit" className="self-end" disabled={syncBusy || Boolean(loadError)}>
            {syncBusy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Share2 className="h-4 w-4" aria-hidden="true" />}
            Sync secret
          </Button>
        </form>
        {syncError && <ErrorState title="Secret sync failed">{syncError}</ErrorState>}
        {syncResult && (
          <dl className="ui-panel grid gap-3 p-comfortable text-sm md:grid-cols-2 xl:grid-cols-5">
            <div>
              <dt className="font-medium text-muted-foreground">Secret</dt>
              <dd>{syncResult.name}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Target</dt>
              <dd>{syncResult.target}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Remote key</dt>
              <dd className="break-all font-mono text-xs">{syncResult.remote_key}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Queue</dt>
              <dd>{syncResult.enqueued ? "Queued" : "Not queued"}</dd>
            </div>
            <div>
              <dt className="font-medium text-muted-foreground">Delivery</dt>
              <dd>{syncResult.delivered ? "Delivered" : "Not delivered"}</dd>
            </div>
          </dl>
        )}
      </section>
    </section>
  );
}

function RevealPanel({ title, value, children, onDismiss }: { title: string; value: string; children: ReactNode; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);
  async function copyValue() {
    try {
      await navigator.clipboard?.writeText(value);
      setCopied(true);
    } catch {
      setCopied(true);
    }
  }
  return (
    <div className="ui-panel grid gap-3 p-3 text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-medium">{title}</p>
          <p className="mt-1 text-muted-foreground">{children}</p>
        </div>
        <Button type="button" variant="ghost" size="sm" onClick={onDismiss}>
          <X className="h-4 w-4" aria-hidden="true" />
          Dismiss
        </Button>
      </div>
      <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded bg-muted px-3 py-2 font-mono text-xs">{value}</pre>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" size="sm" variant="outline" onClick={() => void copyValue()}>
          <Copy className="h-4 w-4" aria-hidden="true" />
          Copy once
        </Button>
        {copied && <span className="text-xs text-muted-foreground">Copied from this reveal panel.</span>}
      </div>
    </div>
  );
}

function Snippet({ title, text }: { title: string; text: string }) {
  return (
    <div className="ui-panel grid gap-2 p-3 text-sm">
      <p className="font-medium">{title}</p>
      <pre className="overflow-x-auto whitespace-pre-wrap rounded bg-muted px-3 py-2 font-mono text-xs">{text}</pre>
    </div>
  );
}

function MachineSession({ session }: { session: MachineLoginResponse }) {
  return (
    <dl className="ui-panel grid gap-2 p-3 text-sm md:grid-cols-2">
      <div>
        <dt className="font-medium text-muted-foreground">Session ID</dt>
        <dd className="break-all font-mono text-xs">{session.session_id}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Principal</dt>
        <dd>{session.principal}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Method</dt>
        <dd>{session.method}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Expires</dt>
        <dd>{formatDate(session.expires_at)}</dd>
      </div>
      <div className="md:col-span-2">
        <dt className="font-medium text-muted-foreground">Scopes</dt>
        <dd>{session.scopes.join(", ") || "No scopes"}</dd>
      </div>
    </dl>
  );
}

function DynamicLeaseMetadata({ lease }: { lease: DynamicLease }) {
  return (
    <dl className="grid gap-2 md:grid-cols-2">
      <div>
        <dt className="font-medium text-muted-foreground">Lease ID</dt>
        <dd className="break-all font-mono text-xs">{lease.id}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">State</dt>
        <dd>{lease.state}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Provider</dt>
        <dd>{lease.provider}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Role</dt>
        <dd>{lease.role}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Issued</dt>
        <dd>{formatDate(lease.issued_at)}</dd>
      </div>
      <div>
        <dt className="font-medium text-muted-foreground">Expires</dt>
        <dd>{formatDate(lease.expires_at)}</dd>
      </div>
    </dl>
  );
}

function mergeMeta(current: SecretMeta[], incoming: SecretMeta[]): SecretMeta[] {
  const byName = new Map(current.map((item) => [item.name, item]));
  for (const item of incoming) byName.set(item.name, item);
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function leaseMetadataOnly(lease: DynamicLease): DynamicLease {
  const metadata = { ...lease };
  delete metadata.credential;
  return metadata;
}

function formatDate(value?: string): string {
  if (!value) return "-";
  return formatDateTimePolicy(value);
}

function parseScopeList(value: string): string[] {
  return value
    .split(/[\n,]+/)
    .map((scope) => scope.trim())
    .filter(Boolean);
}

function encodeTransitBytes(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeTransitBytes(value: string): string {
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function apiProblemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.retryAfterSeconds != null) return `${fallback}: retry in ${err.retryAfterSeconds}s`;
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || err.message;
    } catch {
      return err.body || err.message;
    }
  }
  return err instanceof Error ? err.message : fallback;
}

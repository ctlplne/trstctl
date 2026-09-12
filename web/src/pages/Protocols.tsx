import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { MDMDevicesPanel } from "@/components/MDMDevicesPanel";
import { Copy, X } from "lucide-react";
import { Dialog } from "@/components/Dialog";
import { PageHeader } from "@/components/PageHeader";
import { ScrollableRegion, ScrollableTableRegion } from "@/components/ScrollableTableRegion";
import { useCan } from "@/components/rbac";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { useToast } from "@/components/ToastProvider";
import { Checkbox } from "@/components/ui/checkbox";
import { Button } from "@/components/ui/button";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";
import { useTranslation, translateNow } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import { ARIPosturePanel } from "@/pages/protocols/ARIPosturePanel";
import { EABCredentialsPanel } from "@/pages/protocols/EABCredentialsPanel";
import { ACMEOperatorPanel } from "@/pages/protocols/ACMEOperatorPanel";
import { ESTOperatorPanel } from "@/pages/protocols/ESTOperatorPanel";
import { SCEPOperatorPanel } from "@/pages/protocols/SCEPOperatorPanel";
import { CMPOperatorPanel } from "@/pages/protocols/CMPOperatorPanel";
import { SPIFFEOperatorPanel } from "@/pages/protocols/SPIFFEOperatorPanel";
import { TSAOperatorPanel } from "@/pages/protocols/TSAOperatorPanel";
import { RevocationCachePanel } from "@/pages/protocols/RevocationCachePanel";
import { DNS01PreflightDialog } from "@/pages/protocols/DNS01PreflightDialog";
import { DNS01QualificationDialog } from "@/pages/protocols/DNS01QualificationDialog";
import { DNS01ProviderTrustPanel } from "@/pages/protocols/DNS01ProviderTrustPanel";
import { MDMSCEPPolicyDialog } from "@/pages/protocols/MDMSCEPPolicyDialog";
import { enrollmentRelaySegments } from "@/pages/protocols/enrollmentRelaySegments";
import {
  api,
  ApiError,
  type ACMEDNS01ProviderCatalogItem,
  type ACMEDNS01ProviderConfig,
  type ACMEUpstreamAuthorizationList,
  type Agent,
  type ACMEDNS01ProviderConfigRequest,
  type EnrollmentDiagnosticList,
  type EnrollmentDiagnostic,
  type MDMSCEPPolicy,
  type MDMSCEPChallengeRotationPreview,
  type MDMSCEPStatus,
  type ProtocolRuntimeStatus,
  type SPIFFEQualification,
} from "@/lib/api";

interface ProtocolSnippet {
  label: string;
  command: string;
}

interface ProtocolSurface {
  id: string;
  name: string;
  capability: string;
  auth: string;
  requirements: string[];
  profile: string;
  snippets: ProtocolSnippet[];
}

interface ProtocolGuideCopy {
  nameKey: MessageKey;
  audienceKey: MessageKey;
  outcomeKey: MessageKey;
}

const protocolGuideCopy: Record<string, ProtocolGuideCopy> = {
  acme: {
    nameKey: "protocols.guide.acme.name",
    audienceKey: "protocols.guide.acme.audience",
    outcomeKey: "protocols.guide.acme.outcome",
  },
  est: {
    nameKey: "protocols.guide.est.name",
    audienceKey: "protocols.guide.est.audience",
    outcomeKey: "protocols.guide.est.outcome",
  },
  scep: {
    nameKey: "protocols.guide.scep.name",
    audienceKey: "protocols.guide.scep.audience",
    outcomeKey: "protocols.guide.scep.outcome",
  },
  cmp: {
    nameKey: "protocols.guide.cmp.name",
    audienceKey: "protocols.guide.cmp.audience",
    outcomeKey: "protocols.guide.cmp.outcome",
  },
  spiffe: {
    nameKey: "protocols.guide.spiffe.name",
    audienceKey: "protocols.guide.spiffe.audience",
    outcomeKey: "protocols.guide.spiffe.outcome",
  },
  ssh: {
    nameKey: "protocols.guide.ssh.name",
    audienceKey: "protocols.guide.ssh.audience",
    outcomeKey: "protocols.guide.ssh.outcome",
  },
  tsa: {
    nameKey: "protocols.guide.tsa.name",
    audienceKey: "protocols.guide.tsa.audience",
    outcomeKey: "protocols.guide.tsa.outcome",
  },
};

const protocolSurfaces: ProtocolSurface[] = [
  {
    id: "acme",
    name: "ACME",
    capability: "ACME directory, account, order, challenge, and certificate issuance flow",
    auth: "ACME account key, challenge validation, profile gate",
    requirements: ["Protocol enabled", "Tenant binding"],
    profile: "Use a profile that allows the acme protocol and serverAuth EKU.",
    snippets: [
      {
        label: translateNow("source.certbot.2fdd3b0f47"),
        command:
          "certbot certonly --server https://trstctl.example.test/directory --dns-rfc2136 --dns-rfc2136-credentials /etc/letsencrypt/rfc2136.ini --preferred-challenges dns -d api.example.test",
      },
      {
        label: translateNow("source.x.crypto.acme.e3bd443082"),
        command: 'client := &acme.Client{DirectoryURL: "https://trstctl.example.test/directory"}',
      },
    ],
  },
  {
    id: "est",
    name: "EST",
    capability: "CA certificate download and simple enrollment flow",
    auth: "Bearer-token or TLS client auth, profile gate",
    requirements: ["Protocol enabled", "Tenant binding"],
    profile: "Use a profile that allows the est protocol and the requested certificate shape.",
    snippets: [
      {
        label: translateNow("source.cacerts.d757429cef"),
        command: "curl -s https://trstctl.example.test/.well-known/est/cacerts -o cacerts.p7",
      },
      {
        label: translateNow("source.simpleenroll.4ea6ad8043"),
        command: "curl -s -H 'Authorization: Bearer <bootstrap-token>' --data-binary @device.csr https://trstctl.example.test/.well-known/est/simpleenroll",
      },
    ],
  },
  {
    id: "scep",
    name: "SCEP",
    capability: "SCEP CA discovery and PKI operation flow",
    auth: "CMS transport, challenge-password gate, profile gate",
    requirements: ["Protocol enabled", "Tenant binding", "RA key file"],
    profile: "Use a profile that allows the scep protocol; keep the RA transport key on shared storage in HA.",
    snippets: [
      {
        label: translateNow("source.getcacert.26e72db504"),
        command: "sscep getca -u https://trstctl.example.test/scep -c trstctl-ca.pem",
      },
      {
        label: translateNow("source.pkioperation.f57e1d9c16"),
        command: "sscep enroll -u https://trstctl.example.test/scep -c trstctl-ca.pem -k device.key -r device.csr -l device.pem",
      },
    ],
  },
  {
    id: "cmp",
    name: "CMP",
    capability: "CMP enrollment request flow",
    auth: "CMP protection key, profile gate",
    requirements: ["Protocol enabled", "Tenant binding", "RA key file"],
    profile: "Use a profile that allows the cmp protocol; keep the RA transport key on shared storage in HA.",
    snippets: [
      {
        label: translateNow("source.openssl.p10cr.ac3c5c9967"),
        command:
          'openssl cmp -config "" -cmd p10cr -server https://trstctl.example.test -path /cmp -csr device.csr -cert cmp-client.pem -key cmp-client.key -extracerts cmp-client.pem -srvcert cmp-ra.pem -ignore_keyusage -disable_confirm -certout device.pem -reqout request.der -rspout response.der -batch -verbosity 7',
      },
    ],
  },
  {
    id: "spiffe",
    name: "SPIFFE",
    capability: "Workload API socket issuing X.509-SVID and JWT-SVID credentials",
    auth: "Workload API metadata, selector match, X.509-SVID and JWT-SVID support",
    requirements: ["Protocol enabled", "Tenant binding", "Socket path", "Trust domain"],
    profile: "Selectors map a workload to an allowed SPIFFE ID; no SVID private key is exposed through the console.",
    snippets: [
      {
        label: translateNow("source.spiffe.helper.7ba7061b6b"),
        command: "SPIFFE_ENDPOINT_SOCKET=unix:///tmp/trstctl-spiffe-workload.sock spiffe-helper -config ./spiffe-helper.conf",
      },
      {
        label: translateNow("source.go.spiffe.7ccff8bcaf"),
        command:
          'source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix:///tmp/trstctl-spiffe-workload.sock")))',
      },
    ],
  },
  {
    id: "ssh",
    name: "SSH CA",
    capability: "SSH CA public key, user/host certificate issuance, and revocation list flow",
    auth: "Tenant-scoped JSON issuance, signer-held SSH CA key, OpenSSH binary KRL",
    requirements: ["Protocol enabled", "Tenant binding"],
    profile: "Principals, extensions, and TTL policy are enforced by the SSH CA path; the CA private key stays in the signer.",
    snippets: [
      {
        label: translateNow("source.authority.key.cfdd3eeb4b"),
        command: "curl -s https://trstctl.example.test/ssh/ca -o /etc/ssh/trusted_user_ca_keys",
      },
      {
        label: translateNow("source.krl.1192cd9855"),
        command: "curl -s https://trstctl.example.test/ssh/krl -o /etc/ssh/revoked_keys.krl",
      },
    ],
  },
  {
    id: "tsa",
    name: "TSA",
    capability: "RFC 3161 timestamp request flow",
    auth: "RFC 3161 TimeStampReq, stable TSA certificate, signer-held TSA key",
    requirements: ["Protocol enabled", "Tenant binding", "TSA certificate file"],
    profile: "The TSA certificate is persisted for stable verification; the timestamp signing key stays in the signer.",
    snippets: [
      {
        label: translateNow("source.openssl.query.5ae6b22e8f"),
        command: "openssl ts -query -data artifact.bin -sha256 -cert -out request.tsq",
      },
      {
        label: translateNow("source.http.post.482b52eb11"),
        command: "curl -s -H 'Content-Type: application/timestamp-query' --data-binary @request.tsq https://trstctl.example.test/tsa -o response.tsr",
      },
      {
        label: translateNow("source.openssl.verify.64d6554ef1"),
        command: "openssl ts -verify -in response.tsr -queryfile request.tsq -CAfile tsa-ca.pem",
      },
    ],
  },
];

export function Protocols() {
  const { t } = useTranslation();
  const [copied, setCopied] = useState<string | null>(null);
  const [protocolStatuses, setProtocolStatuses] = useState<ProtocolRuntimeStatus[]>([]);
  const [relayAgents, setRelayAgents] = useState<Agent[]>([]);
  const [relayTopologyError, setRelayTopologyError] = useState<string | null>(null);
  // I4: recent enrolment refusals, classified. Loaded separately so a
  // deployment without the surface still renders the rest of the page.
  const [diagnostics, setDiagnostics] = useState<EnrollmentDiagnosticList | null>(null);
  const [verifyingDiagnostic, setVerifyingDiagnostic] = useState<string | null>(null);
  const [diagnosticVerificationError, setDiagnosticVerificationError] = useState<string | null>(null);
  const [statusCheckedAt, setStatusCheckedAt] = useState<string | null>(null);
  const [dnsProviders, setDNSProviders] = useState<ACMEDNS01ProviderCatalogItem[]>([]);
  const [dnsProviderConfigs, setDNSProviderConfigs] = useState<ACMEDNS01ProviderConfig[]>([]);
  const [upstreamAuthorizations, setUpstreamAuthorizations] = useState<ACMEUpstreamAuthorizationList | null>(null);
  // A failed read is a THIRD state, not the empty one. Hiding the panel when
  // the request errors would make a broken surface look like a deployment with
  // nothing stale — the same false reassurance the panel exists to prevent,
  // one level up.
  const [upstreamAuthorizationsError, setUpstreamAuthorizationsError] = useState<string | null>(null);
  const [mdmSCEPStatus, setMDMSCEPStatus] = useState<MDMSCEPStatus | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [statusError, setStatusError] = useState<string | null>(null);
  const { toast } = useToast();
  const canProveEnrollmentFixed = useCan("certs:issue");
  const [scepPolicyEditor, setSCEPPolicyEditor] = useState<{ policy?: MDMSCEPPolicy } | null>(null);
  const [scepDeletePolicy, setSCEPDeletePolicy] = useState<MDMSCEPPolicy | null>(null);
  const [scepRotatePolicy, setSCEPRotatePolicy] = useState<MDMSCEPPolicy | null>(null);
  const [dnsEditConfig, setDNSEditConfig] = useState<ACMEDNS01ProviderConfig | null>(null);
  const [dnsCreateOpen, setDNSCreateOpen] = useState(false);
  const [dnsDeleteConfig, setDNSDeleteConfig] = useState<ACMEDNS01ProviderConfig | null>(null);
  const [dnsPreflightConfig, setDNSPreflightConfig] = useState<ACMEDNS01ProviderConfig | null>(null);
  const [dnsQualificationConfig, setDNSQualificationConfig] = useState<ACMEDNS01ProviderConfig | null>(null);
  const [operationsOpen, setOperationsOpen] = useState(false);

  // B7: upstream authorization staleness, fetched on its own so a deployment
  // without the surface still renders every other protocol panel.
  useEffect(() => {
    let active = true;
    if (typeof api.acmeUpstreamAuthorizations !== "function") return;
    api
      .acmeUpstreamAuthorizations()
      .then((list) => {
        if (!active) return;
        setUpstreamAuthorizations(list);
        setUpstreamAuthorizationsError(null);
      })
      .catch((err: unknown) => {
        if (!active) return;
        setUpstreamAuthorizations(null);
        setUpstreamAuthorizationsError(protocolStatusError(err));
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    void (async () => {
      const rows: Agent[] = [];
      const seen = new Set<string>();
      let cursor = "";
      do {
        const page = await api.agentPage({ limit: 100, ...(cursor ? { cursor } : {}) });
        rows.push(...(page.agents ?? []));
        const next = page.next_cursor ?? "";
        if (next && seen.has(next)) throw new Error("agent topology returned a repeated cursor");
        if (next) seen.add(next);
        cursor = next;
      } while (cursor);
      return rows;
    })()
      .then((rows) => {
        if (!active) return;
        setRelayAgents(rows);
        setRelayTopologyError(null);
      })
      .catch((err: unknown) => {
        if (!active) return;
        setRelayAgents([]);
        setRelayTopologyError(protocolStatusError(err));
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    setStatusLoading(true);
    setStatusError(null);
    Promise.all([api.protocolStatuses(), api.acmeDNS01Providers(), api.acmeDNS01ProviderConfigs(), api.mdmSCEPStatus()])
      .then(([page, providerCatalog, providerConfigs, mdmStatus]) => {
        if (!active) return;
        setProtocolStatuses(page.items);
        setStatusCheckedAt(page.checked_at);
        setDNSProviders(providerCatalog.items ?? []);
        setDNSProviderConfigs(providerConfigs.items ?? []);
        setMDMSCEPStatus(mdmStatus);
      })
      .catch((err: unknown) => {
        if (!active) return;
        setStatusError(protocolStatusError(err));
      })
      .finally(() => {
        if (active) setStatusLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const statusByProtocol = new Map(protocolStatuses.map((status) => [status.protocol, status]));
  const relaySegments = enrollmentRelaySegments(relayAgents);
  const readyMethodCount = protocolSurfaces.filter((protocol) => {
    const status = statusByProtocol.get(protocol.id);
    return status?.enabled && status.served;
  }).length;
  const nextUnreadyMethod = protocolSurfaces.find((protocol) => {
    const status = statusByProtocol.get(protocol.id);
    return !status?.enabled || !status.served;
  });

  const recordSPIFFEQualification = useCallback((result: SPIFFEQualification) => {
    setProtocolStatuses((current) => [
      ...current.filter((status) => status.protocol !== "spiffe"),
      {
        protocol: "spiffe",
        endpoint: result.socket_uri,
        enabled: result.checks.find((check) => check.id === "configured")?.passed ?? false,
        served: result.ready,
        status_code: 0,
        detail: result.ready ? translateNow("protocols.spiffeCheck.ready") : translateNow("protocols.spiffeCheck.blocked"),
      },
    ]);
    setStatusCheckedAt(result.checked_at);
  }, []);

  function openProtocolOperations(protocolId: string) {
    setOperationsOpen(true);
    window.setTimeout(() => {
      // ACME, EST, SCEP, and CMP have purpose-built operator workspaces. Land
      // on the requested method instead of making the operator hunt through
      // every earlier protocol panel. Methods without a workspace still fall
      // back to their exact register row.
      const target = document.getElementById(`${protocolId}-operator-panel`) ?? document.getElementById(`protocol-row-${protocolId}`);
      target?.scrollIntoView({ block: "start" });
    }, 0);
  }

  async function copySnippet(protocol: ProtocolSurface, snippet: ProtocolSnippet) {
    try {
      await navigator.clipboard?.writeText(snippet.command);
    } finally {
      setCopied(`${protocol.id}:${snippet.label}`);
    }
  }

  function replaceSCEPPolicy(updated: MDMSCEPPolicy) {
    setMDMSCEPStatus((current) =>
      current
        ? {
            ...current,
            policies: current.policies.some((policy) => policy.id === updated.id)
              ? current.policies.map((policy) => (policy.id === updated.id ? updated : policy))
              : [...current.policies, updated],
          }
        : current,
    );
  }

  function handleSCEPPolicySaved(updated: MDMSCEPPolicy) {
    replaceSCEPPolicy(updated);
    setSCEPPolicyEditor(null);
    toast({ kind: "success", title: t("parity.scepPolicyUpdated_3a2953"), description: updated.name });
  }

  function handleSCEPPolicyDeleted(policy: MDMSCEPPolicy) {
    setMDMSCEPStatus((current) => (current ? { ...current, policies: current.policies.filter((candidate) => candidate.id !== policy.id) } : current));
    setSCEPDeletePolicy(null);
    toast({ kind: "success", title: t("parity.scepPolicyDeleted_45064c"), description: policy.name });
  }

  function handleSCEPChallengeRotated(policy: MDMSCEPPolicy) {
    replaceSCEPPolicy(policy);
    setSCEPRotatePolicy(null);
    toast({ kind: "success", title: t("parity.scepChallengeRotated_77c4f1"), description: `${policy.name} rotation version ${policy.rotation_version}` });
  }

  function handleDNSConfigSaved(updated: ACMEDNS01ProviderConfig) {
    setDNSProviderConfigs((current) =>
      current.some((config) => config.id === updated.id) ? current.map((config) => (config.id === updated.id ? updated : config)) : [updated, ...current],
    );
    setDNSEditConfig(null);
    setDNSCreateOpen(false);
    toast({ kind: "success", title: t("parity.dns01ProviderConfigUpdated_5a6d3d"), description: updated.name });
  }

  function handleDNSConfigDeleted(config: ACMEDNS01ProviderConfig) {
    setDNSProviderConfigs((current) => current.filter((candidate) => candidate.id !== config.id));
    setDNSDeleteConfig(null);
    toast({ kind: "success", title: t("parity.dns01ProviderConfigDeleted_9ead6a"), description: config.name });
  }

  async function proveEnrollmentDiagnosticFixed(row: EnrollmentDiagnostic) {
    if (!row.id || verifyingDiagnostic) return;
    setVerifyingDiagnostic(row.id);
    setDiagnosticVerificationError(null);
    try {
      const queued = await api.proveEnrollmentDiagnosticFixed(row.id);
      setDiagnostics((current) =>
        current
          ? {
              ...current,
              items: current.items.map((item) =>
                item.id === row.id
                  ? {
                      ...item,
                      verification_endpoint_id: queued.verification_endpoint_id,
                      verification_queued_at: queued.queued_at,
                      verification_status: queued.status,
                      verification_result_path: queued.result_path,
                    }
                  : item,
              ),
            }
          : current,
      );
      toast({
        kind: "success",
        title: translateNow("source.verification.queued.i4diag0023"),
        description: row.endpoint_ref,
      });
    } catch (err: unknown) {
      setDiagnosticVerificationError(protocolStatusError(err));
    } finally {
      setVerifyingDiagnostic(null);
    }
  }

  const hasQueuedEnrollmentVerification = Boolean((diagnostics?.items ?? []).some((item) => item.verification_status === "queued"));

  useEffect(() => {
    if (!hasQueuedEnrollmentVerification || typeof api.enrollmentDiagnostics !== "function") return;
    let active = true;
    let attempts = 0;
    let timer: number | undefined;
    const refresh = async () => {
      attempts += 1;
      try {
        const list = await api.enrollmentDiagnostics();
        if (active) setDiagnostics(list);
      } catch {
        // Keep the explicit queued state and retry within the fixed budget. A
        // transient read failure is not proof that the verification failed.
      } finally {
        if (active && attempts < 30) {
          timer = window.setTimeout(() => void refresh(), 2_000);
        }
      }
    };
    void refresh();
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [hasQueuedEnrollmentVerification]);

  useEffect(() => {
    let active = true;
    if (typeof api.enrollmentDiagnostics !== "function") return;
    api
      .enrollmentDiagnostics()
      .then((list) => {
        if (active) setDiagnostics(list);
      })
      .catch(() => {
        if (active) setDiagnostics(null);
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <section aria-labelledby="protocols-heading" className="grid min-w-0 gap-6 [&>*]:min-w-0">
      <PageHeader
        titleId="protocols-heading"
        title={t("nav.item.protocols")}
        description="Choose the safe doorway a machine uses to request and renew a certificate: ACME for servers, EST or SCEP for managed devices, and CMP for established PKI systems."
        technicalDetails="Exact evidence includes public endpoints, responder health, tenant and profile binding, authentication challenges, copy-paste client commands, enrollment diagnostics, signed relay health, and CRL or OCSP cache freshness."
        actions={
          <Button type="button" onClick={() => openProtocolOperations(nextUnreadyMethod?.id ?? protocolSurfaces[0].id)}>
            {nextUnreadyMethod ? t("protocols.action.setUpMethod", { method: nextUnreadyMethod.name }) : t("protocols.action.viewMethods")}
          </Button>
        }
      />

      <section aria-labelledby="method-readiness-heading" className="ui-panel grid gap-1 p-comfortable">
        <h2 id="method-readiness-heading" className="text-title font-semibold">
          {statusLoading
            ? t("protocols.readiness.checking")
            : statusError
              ? t("protocols.readiness.unavailable")
              : t("protocols.readiness.summary", { ready: readyMethodCount, total: protocolSurfaces.length })}
        </h2>
        <p className="text-body text-muted-foreground">
          {statusLoading
            ? t("protocols.readiness.checkingBody")
            : statusError
              ? t("protocols.readiness.unavailableBody")
              : nextUnreadyMethod
                ? t("protocols.readiness.next", { method: nextUnreadyMethod.name })
                : t("protocols.readiness.allReady")}
        </p>
      </section>

      <section aria-labelledby="protocol-guide-heading" className="border-y border-border">
        <div className="py-4">
          <h2 id="protocol-guide-heading" className="text-title font-semibold">
            {t("protocols.guide.heading")}
          </h2>
          <p className="mt-1 max-w-3xl text-body text-muted-foreground">{t("protocols.guide.description")}</p>
        </div>
        <ul className="divide-y divide-border" aria-label={t("protocols.guide.listLabel")}>
          {protocolSurfaces.map((protocol) => {
            const copy = protocolGuideCopy[protocol.id];
            const status = statusByProtocol.get(protocol.id);
            const ready = Boolean(status?.enabled && status.served);
            const needsAttention = Boolean(status?.enabled && !status.served);
            const statusLabel = statusLoading
              ? t("protocols.guide.status.checking")
              : statusError
                ? t("protocols.guide.status.unavailable")
                : ready
                  ? t("protocols.guide.status.ready")
                  : needsAttention
                    ? t("protocols.guide.status.needsAttention")
                    : t("protocols.guide.status.notSetUp");
            const statusClass = ready ? "text-status-success" : needsAttention ? "text-status-warning" : "text-muted-foreground";
            return (
              <li key={protocol.id} className="grid gap-3 py-4 md:grid-cols-[minmax(0,1fr)_10rem_auto] md:items-center">
                <div className="min-w-0">
                  <h3 className="text-body font-semibold">
                    {t(copy.nameKey)} <span className="font-normal text-muted-foreground">({protocol.name})</span>
                  </h3>
                  <p className="mt-1 text-caption font-medium text-muted-foreground">{t(copy.audienceKey)}</p>
                  <p className="mt-1 text-body text-muted-foreground">{t(copy.outcomeKey)}</p>
                </div>
                <p className={`text-sm font-medium ${statusClass}`}>{statusLabel}</p>
                <Button type="button" size="sm" variant="ghost" onClick={() => openProtocolOperations(protocol.id)}>
                  {t("protocols.guide.action")}
                </Button>
              </li>
            );
          })}
        </ul>
      </section>

      {/* I4: what enrolments are failing and what to do about it. Rendered only
          when something has failed — an empty panel on a healthy estate is
          noise, and this surface earns attention by appearing. */}
      {(diagnostics?.items ?? []).length > 0 ? (
        <section aria-labelledby="enrollment-diagnostics-heading" className="grid gap-3 border-y border-border py-4">
          <div>
            <h2 id="enrollment-diagnostics-heading" className="text-title font-semibold">
              {translateNow("source.enrollment.diagnostics.i4diag0001")}
            </h2>
            <p className="mt-1 max-w-4xl text-caption text-muted-foreground">{diagnostics?.guidance}</p>
            {diagnosticVerificationError ? (
              <p role="alert" className="mt-2 text-xs text-danger">
                {diagnosticVerificationError}
              </p>
            ) : null}
          </div>
          <div className="ui-panel overflow-x-auto">
            <table className="ui-table min-w-[60rem]">
              <caption className="sr-only">{translateNow("source.enrollment.diagnostics.caption.i4diag0002")}</caption>
              <thead>
                <tr>
                  <th scope="col">{translateNow("source.protocol.i4diag0003")}</th>
                  <th scope="col">{translateNow("source.failing.step.i4diag0004")}</th>
                  <th scope="col">{translateNow("source.what.happened.i4diag0005")}</th>
                  <th scope="col">{translateNow("source.what.to.do.i4diag0006")}</th>
                  <th scope="col">{translateNow("source.exact.evidence.i4diag0010")}</th>
                  <th scope="col">{translateNow("source.verification.i4diag0011")}</th>
                  <th scope="col">{translateNow("source.seen.i4diag0007")}</th>
                </tr>
              </thead>
              <tbody>
                {(diagnostics?.items ?? []).map((row) => (
                  <tr key={row.id || `${row.protocol}:${row.step}:${row.cause}`} className="align-top">
                    <td className="font-mono text-xs">{row.protocol}</td>
                    <td className="font-mono text-xs">{row.step}</td>
                    <td className="max-w-[24rem] text-xs">{row.summary}</td>
                    {/* An unclassified failure shows what it is rather than an
                        empty cell: "we could not place this" is a real answer
                        and a blank looks like a rendering bug. */}
                    <td className="max-w-[26rem] text-xs">
                      {row.actionable ? (
                        row.remediation
                      ) : (
                        <span className="text-muted-foreground">{translateNow("source.cause.not.established.i4diag0008")}</span>
                      )}
                    </td>
                    <td className="max-w-[24rem] text-xs">
                      <dl className="grid gap-1">
                        {row.operation_ref ? (
                          <div>
                            <dt className="inline text-muted-foreground">{translateNow("source.operation.i4diag0012")}: </dt>
                            <dd className="inline break-all font-mono">{row.operation_ref}</dd>
                          </div>
                        ) : null}
                        {row.identity_ref ? (
                          <div>
                            <dt className="inline text-muted-foreground">{translateNow("source.identity.i4diag0013")}: </dt>
                            <dd className="inline break-all font-mono">{row.identity_ref}</dd>
                          </div>
                        ) : null}
                        {row.endpoint_ref ? (
                          <div>
                            <dt className="inline text-muted-foreground">{translateNow("source.endpoint.i4diag0014")}: </dt>
                            <dd className="inline break-all font-mono">{row.endpoint_ref}</dd>
                          </div>
                        ) : null}
                      </dl>
                    </td>
                    <td className="max-w-[22rem] text-xs">
                      {row.verification_status === "verified" ? (
                        <div className="grid gap-1">
                          <span className="font-semibold text-success">{translateNow("source.verified.fixed.i4diag0015")}</span>
                          {row.verification_agent ? <span className="font-mono">{row.verification_agent}</span> : null}
                          {row.verification_evidence_digest ? <span className="break-all font-mono">{row.verification_evidence_digest}</span> : null}
                          {row.verification_result_path ? (
                            <a className="font-medium text-brand-accent underline" href={row.verification_result_path}>
                              {translateNow("source.signed.verification.evidence.i4diag0016")}
                            </a>
                          ) : null}
                        </div>
                      ) : row.verification_status === "queued" ? (
                        <span>{translateNow("source.queued.network.verification.i4diag0017")}</span>
                      ) : row.verification_status === "diverged" ? (
                        <span className="text-danger">{translateNow("source.verification.diverged.i4diag0018")}</span>
                      ) : row.verification_status === "unreachable" ? (
                        <span className="text-danger">{translateNow("source.verification.unreachable.i4diag0019")}</span>
                      ) : canProveEnrollmentFixed && row.verification_kind === "endpoint.verify" ? (
                        <Button size="sm" variant="outline" disabled={verifyingDiagnostic !== null} onClick={() => void proveEnrollmentDiagnosticFixed(row)}>
                          {verifyingDiagnostic === row.id
                            ? translateNow("source.queueing.verification.i4diag0020")
                            : translateNow("source.prove.fixed.i4diag0021")}
                        </Button>
                      ) : (
                        <span className="text-muted-foreground">{translateNow("source.no.network.proof.queued.i4diag0022")}</span>
                      )}
                    </td>
                    <td className="text-xs text-muted-foreground">
                      {translateNow("source.times.since.i4diag0009", {
                        value1: String(row.count),
                        value2: formatDateTimePolicy(row.observed_at),
                      })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      <details
        data-testid="protocol-operational-details"
        className="group border-y border-border py-3"
        open={operationsOpen}
        onToggle={(event) => setOperationsOpen(event.currentTarget.open)}
      >
        <summary className="cursor-pointer list-none marker:hidden">
          <span className="font-medium">{t("protocols.operations.summary")}</span>
          <span className="ms-2 text-caption text-muted-foreground">{t("protocols.operations.description")}</span>
        </summary>
        <div className="mt-5 grid min-w-0 gap-6 [&>*]:min-w-0">
          <MDMDevicesPanel />

          <details data-testid="protocol-network-evidence" className="group border-y border-border py-3">
            <summary className="cursor-pointer list-none marker:hidden">
              <span className="font-medium">{t("protocols.networkEvidence.summary")}</span>
              <span className="ms-2 text-caption text-muted-foreground">
                {relayTopologyError
                  ? t("protocols.networkEvidence.unavailable")
                  : relaySegments.length > 0
                    ? relaySegments.length === 1
                      ? t("protocols.networkEvidence.countOne")
                      : t("protocols.networkEvidence.countMany", { count: relaySegments.length })
                    : t("protocols.networkEvidence.empty")}
              </span>
            </summary>
            <div className="mt-4 grid gap-6">
              <section aria-labelledby="enrollment-relay-topology-heading" aria-label={t("protocols.relays.heading")}>
                <h2 id="enrollment-relay-topology-heading" className="text-title font-semibold">
                  {t("protocols.relays.heading")}
                </h2>
                <p className="mt-1 max-w-4xl text-caption text-muted-foreground">{t("protocols.relays.description")}</p>
                {relayTopologyError ? (
                  <div className="mt-3">
                    <ErrorState title={t("protocols.relays.loadFailed")}>{relayTopologyError}</ErrorState>
                  </div>
                ) : relaySegments.length === 0 ? (
                  <div role="status" className="mt-3 rounded-panel border border-border bg-muted/20 p-4">
                    <p className="text-body font-semibold">{t("protocols.relays.emptyTitle")}</p>
                    <p className="mt-1 text-caption text-muted-foreground">{t("protocols.relays.emptyBody")}</p>
                  </div>
                ) : (
                  <div className="ui-panel mt-3 overflow-x-auto">
                    <table className="ui-table min-w-[76rem]">
                      <caption className="sr-only">{t("protocols.relays.caption")}</caption>
                      <thead>
                        <tr>
                          <th scope="col">{t("protocols.relays.segment")}</th>
                          <th scope="col">{t("protocols.relays.redundancy")}</th>
                          <th scope="col">{t("protocols.relays.relay")}</th>
                          <th scope="col">{t("protocols.relays.publicURL")}</th>
                          <th scope="col">{t("protocols.relays.state")}</th>
                          <th scope="col">{t("protocols.relays.upstreams")}</th>
                          <th scope="col">{t("protocols.relays.evidence")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {relaySegments.flatMap((segment) =>
                          segment.relays.map((relay, index) => {
                            const proxy = relay.enrollment_proxy;
                            return (
                              <tr key={relay.id} className="align-top">
                                {index === 0 ? (
                                  <td rowSpan={segment.relays.length} className="font-medium">
                                    {segment.name}
                                  </td>
                                ) : null}
                                {index === 0 ? (
                                  <td rowSpan={segment.relays.length}>
                                    {segment.relays.length === 1
                                      ? t("protocols.relays.oneRelay")
                                      : t("protocols.relays.manyRelays", { count: segment.relays.length })}
                                  </td>
                                ) : null}
                                <td>
                                  <p className="font-medium">{relay.name}</p>
                                  <p className="mt-1 font-mono text-xs text-muted-foreground">{relay.id}</p>
                                </td>
                                <td className="font-mono text-xs">{proxy.public_url}</td>
                                <td>
                                  <StatusBadge value={proxy.state} />
                                  <p className="mt-1 max-w-[18rem] text-caption text-muted-foreground">{proxy.detail}</p>
                                </td>
                                <td className="text-xs">
                                  <p>
                                    {t("protocols.relays.upstreamHealth", {
                                      healthy: proxy.healthy_upstreams,
                                      unhealthy: proxy.unhealthy_upstreams,
                                      unknown: proxy.unknown_upstreams,
                                    })}
                                  </p>
                                  <p className="mt-1 text-muted-foreground">{t("protocols.relays.upstreamFailures", { count: proxy.upstream_failures })}</p>
                                </td>
                                <td className="text-xs">
                                  <p>{t("protocols.relays.forwarded", { count: proxy.forwarded_requests })}</p>
                                  <p>{t("protocols.relays.refused", { count: proxy.refused_requests })}</p>
                                  <p className="mt-1 text-muted-foreground">
                                    {proxy.last_forwarded_at
                                      ? t("protocols.relays.lastForwarded", { at: formatDateTimePolicy(proxy.last_forwarded_at) })
                                      : t("protocols.relays.lastForwarded", { at: t("protocols.relays.never") })}
                                  </p>
                                  <p className="text-muted-foreground">
                                    {proxy.last_failover_at
                                      ? t("protocols.relays.lastFailover", { at: formatDateTimePolicy(proxy.last_failover_at) })
                                      : t("protocols.relays.lastFailover", { at: t("protocols.relays.never") })}
                                  </p>
                                  {proxy.reported_at ? (
                                    <p className="text-muted-foreground">{t("protocols.relays.reported", { at: formatDateTimePolicy(proxy.reported_at) })}</p>
                                  ) : null}
                                </td>
                              </tr>
                            );
                          }),
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              <RevocationCachePanel />
            </div>
          </details>

          <ACMEOperatorPanel />
          <ESTOperatorPanel />
          <SCEPOperatorPanel />
          <CMPOperatorPanel diagnostics={diagnostics?.items ?? []} />
          <TSAOperatorPanel />
          <SPIFFEOperatorPanel onResult={recordSPIFFEQualification} />

          <section aria-labelledby="protocol-status-heading" className="border-y border-border py-4">
            <h2 id="protocol-status-heading" className="text-title font-semibold">
              {translateNow("source.protocol.responder.status.e57eff8ebc")}
            </h2>
            <div className="mt-3 grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <div className="ui-panel p-3 text-sm">
                <p className="font-medium">{translateNow("source.read.only.responder.probe.23655af063")}</p>
                <p className="mt-1 text-muted-foreground">{translateNow("source.the.register.checks.the.same.origin.protoc.851c152de8")}</p>
                {statusCheckedAt && (
                  <p className="mt-2 text-caption text-muted-foreground">
                    {translateNow("source.checked.0efd92a335")} {formatDate(statusCheckedAt)}
                  </p>
                )}
              </div>
              <div className="ui-panel p-3 text-sm">
                <p className="font-medium">{translateNow("source.fail.closed.startup.and.issuance.posture.661fcb680a")}</p>
                <p className="mt-1 text-muted-foreground">{translateNow("source.each.protocol.requires.an.enabled.flag.plu.a66867a87e")}</p>
              </div>
            </div>
          </section>

          <section aria-labelledby="protocol-table-heading">
            <h2 id="protocol-table-heading" className="mb-3 text-title font-semibold">
              {translateNow("source.protocol.register.6109f4cf46")}
            </h2>
            <ScrollableTableRegion className="ui-panel" label={translateNow("source.enrollment.protocol.surfaces.de695f7aa5")}>
              <table className="ui-table min-w-[56rem]">
                <caption className="sr-only">{translateNow("source.enrollment.protocol.surfaces.de695f7aa5")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{translateNow("source.protocol.cf0883343f")}</th>
                    <th scope="col">{translateNow("source.capability.5faf58a69d")}</th>
                    <th scope="col">{translateNow("source.tenant.binding.73a4b393b8")}</th>
                    <th scope="col">{translateNow("source.auth.and.profile.gate.220561196c")}</th>
                    <th scope="col">{translateNow("source.responder.status.85b7b015dc")}</th>
                  </tr>
                </thead>
                <tbody>
                  {protocolSurfaces.map((protocol) => {
                    const status = statusByProtocol.get(protocol.id);
                    return (
                      <tr id={`protocol-row-${protocol.id}`} key={protocol.id} className="align-top scroll-mt-24">
                        <td>
                          <p className="font-medium">{protocol.name}</p>
                        </td>
                        <td>{protocol.capability}</td>
                        <td>
                          <ul className="grid gap-1">
                            {protocol.requirements.map((requirement) => (
                              <li key={requirement}>{requirement}</li>
                            ))}
                          </ul>
                        </td>
                        <td>
                          <p>{protocol.auth}</p>
                          <p className="mt-1 text-muted-foreground">{protocol.profile}</p>
                        </td>
                        <td>
                          <ProtocolStatusBadge status={status} />
                          <p className="mt-2 font-mono text-xs text-muted-foreground">{status?.endpoint ?? protocolEndpointFallback(protocol.id)}</p>
                          {status?.status_code != null && (
                            <p className="mt-1 text-caption text-muted-foreground">
                              {translateNow("source.http.56d6f32151")} {status.status_code}
                            </p>
                          )}
                          {status?.detail && <p className="mt-1 text-caption text-muted-foreground">{status.detail}</p>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </ScrollableTableRegion>
            <div className="mt-3">
              {statusLoading && <LoadingState>{translateNow("source.checking.protocol.responders.b300fe1dfa")}</LoadingState>}
              {statusError && <ErrorState title={translateNow("source.protocol.status.check.failed.d6b8e1268d")}>{statusError}</ErrorState>}
            </div>
          </section>

          <ARIPosturePanel />
          <EABCredentialsPanel />

          <section aria-labelledby="dns-provider-heading">
            <h2 id="dns-provider-heading" className="mb-3 text-title font-semibold">
              {t("protocols.dns01.heading")}
            </h2>
            <ScrollableTableRegion className="ui-panel" label={t("protocols.dns01.caption")}>
              <table className="ui-table min-w-[62rem]">
                <caption className="sr-only">{t("protocols.dns01.caption")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("protocols.dns01.provider")}</th>
                    <th scope="col">{t("protocols.dns01.kind")}</th>
                    <th scope="col">{t("protocols.dns01.conformance")}</th>
                    <th scope="col">{t("protocols.dns01.secretReferences")}</th>
                    <th scope="col">{t("protocols.dns01.capabilityGrant")}</th>
                  </tr>
                </thead>
                <tbody>
                  {dnsProviders.map((provider) => (
                    <tr key={provider.name} className="align-top">
                      <td>
                        <p className="font-medium">{provider.display_name}</p>
                        <p className="mt-1 font-mono text-xs text-muted-foreground">{provider.name}</p>
                        <p className="mt-1 font-mono text-xs text-muted-foreground">{provider.provider_package}</p>
                        <ProtocolServedBadge served={provider.served} servedLabel={t("protocols.dns01.served")} offLabel={t("protocols.dns01.off")} />
                      </td>
                      <td>{provider.kind}</td>
                      <td>
                        <p>{provider.conformance}</p>
                        {provider.admission_state && (
                          <p className="mt-1 text-caption text-muted-foreground">
                            {t("protocols.dns01.admission")}: {provider.admission_state}
                          </p>
                        )}
                        {provider.provenance && (
                          <p className="mt-1 text-caption text-muted-foreground">
                            {t("protocols.dns01.provenance")}: {provider.provenance}
                          </p>
                        )}
                        {provider.propagation_preflight && (
                          <p className="mt-1 text-caption text-muted-foreground">{t("protocols.dns01.propagationPreflight")}</p>
                        )}
                      </td>
                      <td>
                        <ul className="grid gap-1">
                          {(provider.credential_reference_fields ?? []).map((field) => (
                            <li key={field} className="font-mono text-xs">
                              {field}
                            </li>
                          ))}
                        </ul>
                        {(provider.secret_fields ?? []).length === 0 && (
                          <p className="mt-2 text-caption text-muted-foreground">{t("protocols.dns01.noRawSecretFields")}</p>
                        )}
                      </td>
                      <td>
                        <ul className="grid gap-1">
                          {(provider.capabilities ?? []).map((capability) => (
                            <li key={capability} className="font-mono text-xs">
                              {capability}
                            </li>
                          ))}
                        </ul>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </ScrollableTableRegion>
            {statusLoading && <LoadingState>{t("protocols.dns01.loading")}</LoadingState>}
            {!statusLoading && !statusError && dnsProviders.length === 0 && (
              <ErrorState title={t("protocols.dns01.unavailableTitle")}>{t("protocols.dns01.empty")}</ErrorState>
            )}
          </section>

          {/* B7: automating DNS-01 upstream removes the human from the validation
          cycle, and with them the human who used to notice when validation
          stopped working. An authority holding a valid authorization issues
          without a challenge, so a broken publish path stays invisible until
          the reuse window closes — and then every identifier authorized in the
          same original burst fails on the same day. This panel leads with the
          date each identifier last actually proved control, not the date it
          last issued, because those two diverge silently. */}
          {upstreamAuthorizationsError && (
            <section aria-labelledby="dns-upstream-error-heading">
              <h2 id="dns-upstream-error-heading" className="mb-3 text-title font-semibold">
                {t("protocols.dns01.upstreamHeading")}
              </h2>
              <ErrorState title={t("protocols.dns01.upstreamUnavailableTitle")}>{t("protocols.dns01.upstreamUnavailable")}</ErrorState>
            </section>
          )}
          {(upstreamAuthorizations?.items ?? []).length > 0 && (
            <section aria-labelledby="dns-upstream-heading">
              <h2 id="dns-upstream-heading" className="mb-3 text-title font-semibold">
                {t("protocols.dns01.upstreamHeading")}
              </h2>
              <p className="mb-3 max-w-4xl text-caption text-muted-foreground">{upstreamAuthorizations?.guidance}</p>
              {(upstreamAuthorizations?.never_validated_count ?? 0) > 0 && (
                <p className="mb-3 text-sm font-medium text-status-warning">
                  {t(
                    upstreamAuthorizations?.never_validated_count === 1
                      ? "protocols.dns01.upstreamNeverValidatedOne"
                      : "protocols.dns01.upstreamNeverValidatedMany",
                    { count: upstreamAuthorizations?.never_validated_count ?? 0 },
                  )}
                </p>
              )}
              <div className="ui-panel overflow-x-auto">
                <table className="ui-table min-w-[64rem]">
                  <caption className="sr-only">{t("protocols.dns01.upstreamCaption")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("protocols.dns01.upstreamIdentifier")}</th>
                      <th scope="col">{t("protocols.dns01.upstreamIssuer")}</th>
                      <th scope="col">{t("protocols.dns01.upstreamLastValidated")}</th>
                      <th scope="col">{t("protocols.dns01.upstreamLastReused")}</th>
                      <th scope="col">{t("protocols.dns01.upstreamExpires")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(upstreamAuthorizations?.items ?? []).map((row) => (
                      <tr key={`${row.issuer}:${row.identifier}`} className="align-top">
                        <td className="font-mono text-xs">{row.identifier}</td>
                        <td>{row.issuer}</td>
                        <td>
                          {row.never_validated ? (
                            <span className="font-medium text-status-warning">{t("protocols.dns01.upstreamNeverValidated")}</span>
                          ) : (
                            <span>{formatDate(row.last_validated_at)}</span>
                          )}
                        </td>
                        <td className="text-muted-foreground">{row.last_reused_at ? formatDate(row.last_reused_at) : "-"}</td>
                        <td>{row.expires_at ? formatDate(row.expires_at) : t("protocols.dns01.upstreamNoStatedExpiry")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          <section aria-labelledby="dns-config-heading">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 id="dns-config-heading" className="text-title font-semibold">
                  {t("protocols.dns01.configHeading")}
                </h2>
                <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("protocols.dns01.configHelp")}</p>
              </div>
              <Button type="button" size="sm" onClick={() => setDNSCreateOpen(true)}>
                {t("protocols.dns01.addProvider")}
              </Button>
            </div>
            <ScrollableTableRegion className="ui-panel" label={t("protocols.dns01.configCaption")}>
              <table className="ui-table min-w-[76rem]">
                <caption className="sr-only">{t("protocols.dns01.configCaption")}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t("protocols.dns01.config")}</th>
                    <th scope="col">{t("protocols.dns01.provider")}</th>
                    <th scope="col">{t("protocols.dns01.zone")}</th>
                    <th scope="col">{t("protocols.dns01.policy")}</th>
                    <th scope="col">{t("protocols.dns01.secretReferences")}</th>
                    <th scope="col">{translateNow("source.actions.ff8059dc67")}</th>
                  </tr>
                </thead>
                <tbody>
                  {dnsProviderConfigs.map((config) => {
                    const refs = credentialReferenceNames(config);
                    return (
                      <tr key={config.id} className="align-top">
                        <td>
                          <p className="font-medium">{config.name}</p>
                          <p className="mt-1 font-mono text-xs text-muted-foreground">{config.id}</p>
                          <p className="mt-2 text-caption text-muted-foreground">{config.secret_handling}</p>
                        </td>
                        <td className="font-mono text-xs">{config.provider}</td>
                        <td>
                          <p>{config.zone || t("protocols.dns01.zoneUnbound")}</p>
                          {config.challenge_domain && <p className="mt-1 font-mono text-xs text-muted-foreground">{config.challenge_domain}</p>}
                          {config.delegation_target && <p className="mt-1 font-mono text-xs text-muted-foreground">{config.delegation_target}</p>}
                        </td>
                        <td>
                          <ul className="grid gap-1">
                            <li>{(config.allowed_methods ?? []).join(", ") || t("protocols.dns01.noMethodPolicy")}</li>
                            <li>{config.allow_wildcards ? t("protocols.dns01.wildcardsAllowed") : t("protocols.dns01.wildcardsDenied")}</li>
                            <li>{config.allow_upstream_dv ? t("protocols.dns01.upstreamDVAllowed") : t("protocols.dns01.upstreamDVDenied")}</li>
                            {config.caa_issuer_domain && (
                              <li>
                                {translateNow("source.caa.084696b5b2")} {config.caa_issuer_domain}
                              </li>
                            )}
                          </ul>
                        </td>
                        <td>
                          <ul className="grid gap-1">
                            {refs.map((field) => (
                              <li key={field} className="font-mono text-xs">
                                {field}
                              </li>
                            ))}
                          </ul>
                        </td>
                        <td>
                          <div className="flex flex-wrap gap-2">
                            <Button
                              type="button"
                              size="sm"
                              onClick={() => setDNSQualificationConfig(config)}
                              aria-label={t("protocols.dns01.qualification.open", { name: config.name })}
                            >
                              {t("protocols.dns01.qualification.testAction")}
                            </Button>
                            <Button
                              type="button"
                              size="sm"
                              variant="outline"
                              onClick={() => setDNSPreflightConfig(config)}
                              aria-label={translateNow("source.preflight.check.value1.dd32be6184", { value1: config.name })}
                            >
                              {t("parity.preflightCheck_4a464a")}
                            </Button>
                            <Button
                              type="button"
                              size="sm"
                              variant="outline"
                              onClick={() => setDNSEditConfig(config)}
                              aria-label={translateNow("source.edit.dns.01.config.value1.58a4415e35", { value1: config.name })}
                            >
                              {t("parity.edit_530164")}
                            </Button>
                            <Button
                              type="button"
                              size="sm"
                              variant="destructive-outline"
                              onClick={() => setDNSDeleteConfig(config)}
                              aria-label={translateNow("source.delete.dns.01.config.value1.c275f568a2", { value1: config.name })}
                            >
                              {t("parity.delete_f6fdbe")}
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </ScrollableTableRegion>
            {statusLoading && <LoadingState>{t("protocols.dns01.configLoading")}</LoadingState>}
            {!statusLoading && !statusError && dnsProviderConfigs.length === 0 && (
              <NeutralEmptyState title={t("protocols.dns01.configEmptyTitle")} body={t("protocols.dns01.configEmpty")} />
            )}
          </section>

          <section aria-labelledby="mdm-scep-heading">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 id="mdm-scep-heading" className="text-title font-semibold">
                  {t("protocols.mdm.heading")}
                </h2>
                <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{t("protocols.mdm.sectionHelp")}</p>
              </div>
              <Button type="button" size="sm" onClick={() => setSCEPPolicyEditor({})}>
                {t("protocols.mdm.addPolicy")}
              </Button>
            </div>
            <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_18rem]">
              <ScrollableTableRegion className="ui-panel" label={t("protocols.mdm.caption")}>
                <table className="ui-table min-w-[72rem]">
                  <caption className="sr-only">{t("protocols.mdm.caption")}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{t("protocols.mdm.policy")}</th>
                      <th scope="col">{t("protocols.mdm.provider")}</th>
                      <th scope="col">{t("protocols.mdm.profile")}</th>
                      <th scope="col">{t("protocols.mdm.challenge")}</th>
                      <th scope="col">{t("protocols.mdm.references")}</th>
                      <th scope="col">{translateNow("source.actions.ff8059dc67")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(mdmSCEPStatus?.policies ?? []).map((policy) => {
                      const refs = mdmReferenceNames(policy);
                      return (
                        <tr key={policy.id} className="align-top">
                          <td>
                            <p className="font-medium">{policy.name}</p>
                            <p className="mt-1 font-mono text-xs text-muted-foreground">{policy.id}</p>
                            <ProtocolServedBadge served={policy.enabled} servedLabel={t("protocols.mdm.enabled")} offLabel={t("protocols.mdm.disabled")} />
                          </td>
                          <td className="font-mono text-xs">{policy.provider}</td>
                          <td>
                            <p>{policy.scep_profile}</p>
                            <p className="mt-1 font-mono text-xs text-muted-foreground">{policy.scep_endpoint}</p>
                            {policy.expected_audience && <p className="mt-1 font-mono text-xs text-muted-foreground">{policy.expected_audience}</p>}
                          </td>
                          <td>
                            <p>{policy.challenge_mode}</p>
                            <p className="mt-1 text-caption text-muted-foreground">
                              {t("protocols.mdm.rotationVersion")} {policy.rotation_version}
                            </p>
                            {policy.last_rotated_at && <p className="mt-1 text-caption text-muted-foreground">{formatDate(policy.last_rotated_at)}</p>}
                          </td>
                          <td>
                            <ul className="grid gap-1">
                              {refs.map((field) => (
                                <li key={field} className="font-mono text-xs">
                                  {field}
                                </li>
                              ))}
                            </ul>
                          </td>
                          <td>
                            <div className="flex flex-wrap gap-2">
                              <Button
                                type="button"
                                size="sm"
                                variant="outline"
                                onClick={() => setSCEPPolicyEditor({ policy })}
                                aria-label={translateNow("source.edit.scep.policy.value1.883c2507e1", { value1: policy.name })}
                              >
                                {t("parity.edit_530164")}
                              </Button>
                              <Button
                                type="button"
                                size="sm"
                                variant="outline"
                                onClick={() => setSCEPRotatePolicy(policy)}
                                aria-label={translateNow("source.rotate.challenge.for.value1.c7c084eaeb", { value1: policy.name })}
                              >
                                {t("parity.rotateChallenge_99fc02")}
                              </Button>
                              <Button
                                type="button"
                                size="sm"
                                variant="destructive-outline"
                                onClick={() => setSCEPDeletePolicy(policy)}
                                aria-label={translateNow("source.delete.scep.policy.value1.62934aa247", { value1: policy.name })}
                              >
                                {t("parity.delete_f6fdbe")}
                              </Button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </ScrollableTableRegion>
              <div className="ui-panel p-3 text-sm">
                <p className="font-medium">{t("protocols.mdm.telemetry")}</p>
                <dl className="mt-3 grid grid-cols-2 gap-2 text-caption">
                  <div>
                    <dt className="text-muted-foreground">{t("protocols.mdm.allowed")}</dt>
                    <dd className="font-semibold tabular-nums">{mdmSCEPStatus?.telemetry.allowed ?? 0}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">{t("protocols.mdm.denied")}</dt>
                    <dd className="font-semibold tabular-nums">{mdmSCEPStatus?.telemetry.denied ?? 0}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">{t("protocols.mdm.replay")}</dt>
                    <dd className="font-semibold tabular-nums">{mdmSCEPStatus?.telemetry.replay_rejected ?? 0}</dd>
                  </div>
                  <div>
                    <dt className="text-muted-foreground">{t("protocols.mdm.runtime")}</dt>
                    <dd className="font-semibold">{mdmSCEPStatus?.runtime_gate ? t("protocols.mdm.runtimeConfigured") : t("protocols.mdm.runtimeUnknown")}</dd>
                  </div>
                </dl>
                {mdmSCEPStatus?.telemetry.last_failure_reason && (
                  <p className="mt-3 text-caption text-muted-foreground">{mdmSCEPStatus.telemetry.last_failure_reason}</p>
                )}
                {mdmSCEPStatus?.runtime_note && <p className="mt-3 text-caption text-muted-foreground">{mdmSCEPStatus.runtime_note}</p>}
              </div>
            </div>
            {statusLoading && <LoadingState>{t("protocols.mdm.loading")}</LoadingState>}
            {!statusLoading && !statusError && (mdmSCEPStatus?.policies ?? []).length === 0 && (
              <NeutralEmptyState title={t("protocols.mdm.emptyTitle")} body={t("protocols.mdm.empty")} />
            )}
          </section>

          <section aria-labelledby="client-setup-heading" className="grid min-w-0 gap-4 [&>*]:min-w-0">
            <h2 id="client-setup-heading" className="text-title font-semibold">
              {translateNow("source.client.setup.4ba2b51d20")}
            </h2>
            {protocolSurfaces.map((protocol) => (
              <section key={protocol.id} aria-labelledby={`${protocol.id}-heading`} className="min-w-0 border-y border-border py-4">
                <div className="grid min-w-0 gap-4 lg:grid-cols-[14rem_minmax(0,1fr)] [&>*]:min-w-0">
                  <div>
                    <h3 id={`${protocol.id}-heading`} className="text-base font-semibold">
                      {protocol.name}
                    </h3>
                    <p className="mt-1 text-sm text-muted-foreground">{protocol.capability}</p>
                  </div>
                  <div className="grid min-w-0 gap-3 [&>*]:min-w-0">
                    {protocol.snippets.map((snippet) => {
                      const copiedKey = `${protocol.id}:${snippet.label}`;
                      return (
                        <div key={snippet.label} className="ui-panel p-3">
                          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                            <p className="text-sm font-medium">{snippet.label}</p>
                            <Button
                              type="button"
                              size="sm"
                              variant="outline"
                              aria-label={translateNow("source.copy.value1.value2.command.fbc14f63f6", { value1: protocol.name, value2: snippet.label })}
                              onClick={() => void copySnippet(protocol, snippet)}
                            >
                              <Copy className="h-4 w-4" aria-hidden="true" />
                              {translateNow("source.copy.e21f935f11")}
                            </Button>
                          </div>
                          <ScrollableRegion
                            className="bg-muted px-3 py-2"
                            label={translateNow("source.copy.value1.value2.command.fbc14f63f6", { value1: protocol.name, value2: snippet.label })}
                          >
                            <code className="block min-w-max text-xs">{snippet.command}</code>
                          </ScrollableRegion>
                          {copied === copiedKey && (
                            <p className="mt-2 text-xs text-muted-foreground">{translateNow("source.copied.command.without.token.material.6c656e4f88")}</p>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </section>
            ))}
          </section>
        </div>
      </details>

      {scepPolicyEditor && <MDMSCEPPolicyDialog policy={scepPolicyEditor.policy} onClose={() => setSCEPPolicyEditor(null)} onSaved={handleSCEPPolicySaved} />}
      {scepRotatePolicy && (
        <MDMSCEPRotateChallengeDialog policy={scepRotatePolicy} onClose={() => setSCEPRotatePolicy(null)} onRotated={handleSCEPChallengeRotated} />
      )}
      {scepDeletePolicy && (
        <MDMSCEPPolicyDeleteDialog policy={scepDeletePolicy} onClose={() => setSCEPDeletePolicy(null)} onDeleted={handleSCEPPolicyDeleted} />
      )}
      {dnsEditConfig && (
        <DNS01ConfigDialog config={dnsEditConfig} providers={dnsProviders} onClose={() => setDNSEditConfig(null)} onSaved={handleDNSConfigSaved} />
      )}
      {dnsCreateOpen && <DNS01ConfigDialog providers={dnsProviders} onClose={() => setDNSCreateOpen(false)} onSaved={handleDNSConfigSaved} />}
      {dnsDeleteConfig && <DNS01ConfigDeleteDialog config={dnsDeleteConfig} onClose={() => setDNSDeleteConfig(null)} onDeleted={handleDNSConfigDeleted} />}
      {dnsPreflightConfig && <DNS01PreflightDialog config={dnsPreflightConfig} onClose={() => setDNSPreflightConfig(null)} />}
      {dnsQualificationConfig && (
        <DNS01QualificationDialog
          config={dnsQualificationConfig}
          provider={dnsProviders.find((candidate) => candidate.name === dnsQualificationConfig.provider)}
          onClose={() => setDNSQualificationConfig(null)}
        />
      )}
    </section>
  );
}

function NeutralEmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div role="status" className="min-w-0 max-w-full rounded-control border border-border bg-muted/20 px-3 py-2 text-sm [overflow-wrap:anywhere]">
      <p className="font-medium">{title}</p>
      <p className="mt-1 text-muted-foreground">{body}</p>
    </div>
  );
}

function credentialReferenceNames(config: ACMEDNS01ProviderConfig) {
  return Object.keys(config.credential_refs ?? {}).sort();
}

function mdmReferenceNames(policy: MDMSCEPStatus["policies"][number]) {
  return Object.keys(policy.trust_anchor_refs ?? {}).sort();
}

function ProtocolServedBadge({ served, servedLabel, offLabel }: { served: boolean; servedLabel: string; offLabel: string }) {
  const cls = served
    ? "border-status-success/30 bg-status-success/10 text-status-success"
    : "border-status-warning/30 bg-status-warning/10 text-status-warning";
  return <span className={`mt-2 inline-flex rounded-control border px-2 py-1 text-caption font-medium ${cls}`}>{served ? servedLabel : offLabel}</span>;
}

function ProtocolStatusBadge({ status }: { status: ProtocolRuntimeStatus | undefined }) {
  if (!status) {
    return (
      <span className="inline-flex rounded-control border border-border bg-muted px-2 py-1 text-caption font-medium text-muted-foreground">
        {translateNow("source.not.browser.readable.cc2ff0b76e")}
      </span>
    );
  }
  const routeServedOnly = status.served && status.status_code === 405;
  const label = status.enabled ? (routeServedOnly ? "Served" : "Enabled") : "Off";
  const cls = status.enabled
    ? "border-status-success/30 bg-status-success/10 text-status-success"
    : "border-status-warning/30 bg-status-warning/10 text-status-warning";
  return <span className={`inline-flex rounded-control border px-2 py-1 text-caption font-medium ${cls}`}>{label}</span>;
}

function protocolEndpointFallback(protocol: string): string {
  if (protocol === "spiffe") return "unix:///tmp/trstctl-spiffe-workload.sock";
  return "No browser-readable route";
}

function protocolStatusError(err: unknown): string {
  if (err instanceof ApiError) return err.body || err.message;
  if (err instanceof Error) return err.message;
  return "The responder status check failed.";
}

function formatDate(value?: string): string {
  if (!value) return "Not recorded";
  return formatDateTimePolicy(value);
}

const acmeMethodOptions = ["http-01", "dns-01", "tls-alpn-01"] as const;
type ACMEChallengeMethod = (typeof acmeMethodOptions)[number];

function isACMEChallengeMethod(value: string): value is ACMEChallengeMethod {
  return (acmeMethodOptions as readonly string[]).includes(value);
}

function stringifyRecord(value: Record<string, unknown> | undefined): string {
  if (!value || Object.keys(value).length === 0) return "";
  return JSON.stringify(value, null, 2);
}

function parseOptionalJSONRecord(value: string, label: string): Record<string, unknown> | null | string {
  const trimmed = value.trim();
  if (trimmed === "") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (err) {
    return `${label} must be valid JSON: ${err instanceof Error ? err.message : "parse error"}`;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return `${label} must be a JSON object.`;
  return parsed as Record<string, unknown>;
}

function MDMSCEPRotateChallengeDialog({
  onClose,
  onRotated,
  policy,
}: {
  policy: MDMSCEPPolicy;
  onClose: () => void;
  onRotated: (policy: MDMSCEPPolicy) => void;
}) {
  const { t } = useTranslation();
  const [preview, setPreview] = useState<MDMSCEPChallengeRotationPreview | null>(null);
  const [previewing, setPreviewing] = useState(true);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);

  async function loadPreview() {
    setPreviewing(true);
    setPreviewError(null);
    try {
      setPreview(await api.previewMDMSCEPChallengeRotation(policy.id));
    } catch (err) {
      setPreview(null);
      setPreviewError(protocolStatusError(err));
    } finally {
      setPreviewing(false);
    }
  }

  useEffect(() => {
    void loadPreview();
    // The policy id is the stable server object whose rotation plan is being reviewed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policy.id]);

  async function confirmRotate() {
    setBusy(true);
    setError(null);
    try {
      const rotated = await api.rotateMDMSCEPChallenge(policy.id);
      onRotated(rotated.policy);
    } catch (err) {
      setError(protocolStatusError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      titleId="scep-rotate-title"
      descriptionId="scep-rotate-desc"
      initialFocusRef={confirmRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative w-full max-w-xl rounded-panel border border-border bg-card p-4 text-sm shadow-elevation2"
    >
      <h2 id="scep-rotate-title" className="text-title font-semibold">
        {translateNow("source.rotate.scep.challenge.for.3553645d3e")} {policy.name}?
      </h2>
      <p id="scep-rotate-desc" className="mt-1 text-muted-foreground">
        {t("parity.rotationMintsFreshChallengeMaterialAnd_0aec47")}
      </p>
      <p className="mt-2 text-caption text-muted-foreground">
        {translateNow("source.current.rotation.version.ede128c23f")} {policy.rotation_version}
      </p>
      {previewing && <LoadingState>{t("protocols.mdm.rotation.previewing")}</LoadingState>}
      {previewError && (
        <ErrorState title={t("protocols.mdm.rotation.previewFailed")}>
          <p>{previewError}</p>
          <Button className="mt-3" type="button" size="sm" variant="outline" onClick={() => void loadPreview()}>
            {t("protocols.mdm.form.retryPreview")}
          </Button>
        </ErrorState>
      )}
      {preview && (
        <section aria-label={t("protocols.mdm.rotation.previewLabel")} className="mt-3 grid gap-3 rounded-control border border-border bg-muted/25 p-3">
          <p className="font-medium">{t("protocols.mdm.rotation.versionPlan", { current: preview.current_version, next: preview.next_version })}</p>
          <p className="text-caption text-muted-foreground">
            {preview.effect_free ? t("protocols.mdm.form.effectFree") : t("protocols.mdm.form.effectWarning")} · {preview.outside_calls.length}{" "}
            {t("protocols.mdm.form.outsideCalls")} · {preview.signer_calls} {t("protocols.mdm.form.signerCalls")}
          </p>
          {preview.blockers.length > 0 && (
            <ul className="list-disc space-y-1 ps-5 text-sm text-risk-warning">
              {preview.blockers.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          )}
          <div>
            <p className="text-sm font-semibold">{t("protocols.mdm.form.recovery")}</p>
            <ol className="mt-1 list-decimal space-y-1 ps-5 text-sm text-muted-foreground">
              {preview.recovery_steps.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ol>
          </div>
          <p className="text-caption text-muted-foreground">{preview.secret_data_handling}</p>
        </section>
      )}
      {error && <ErrorState title={t("parity.challengeRotationFailed_c4b11e")}>{error}</ErrorState>}
      <div className="mt-3 flex gap-2">
        <Button
          ref={confirmRef}
          type="button"
          size="sm"
          disabled={busy || previewing || !preview?.ready || !preview.effect_free}
          onClick={() => void confirmRotate()}
        >
          {t("parity.rotateChallenge_99fc02")}
        </Button>
        <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={onClose}>
          {translateNow("source.cancel.19766ed6cc")}
        </Button>
      </div>
    </Dialog>
  );
}

function MDMSCEPPolicyDeleteDialog({ onClose, onDeleted, policy }: { policy: MDMSCEPPolicy; onClose: () => void; onDeleted: (policy: MDMSCEPPolicy) => void }) {
  const { t } = useTranslation();
  const [confirmName, setConfirmName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const confirmRef = useRef<HTMLInputElement>(null);

  async function confirmDelete() {
    setBusy(true);
    setError(null);
    try {
      await api.deleteMDMSCEPPolicy(policy.id);
      onDeleted(policy);
    } catch (err) {
      setError(protocolStatusError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open
      role="alertdialog"
      onClose={onClose}
      titleId="scep-policy-delete-title"
      descriptionId="scep-policy-delete-desc"
      initialFocusRef={confirmRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative w-full max-w-xl rounded-panel border border-destructive/40 bg-card p-4 text-sm shadow-elevation2"
    >
      <h2 id="scep-policy-delete-title" className="text-title font-semibold text-destructive">
        {translateNow("source.delete.scep.policy.1a5e5ddeb3")}
        {policy.name}”?
      </h2>
      <p id="scep-policy-delete-desc" className="mt-1 text-destructive">
        Deleting this policy stops MDM SCEP challenge validation for its endpoint; devices enrolling through it will be denied. This cannot be undone.
      </p>
      {error && (
        <p role="alert" className="mt-2 text-destructive">
          {error}
        </p>
      )}
      <label className="mt-3 block text-sm font-medium text-destructive" htmlFor="scep-policy-delete-confirm">
        {t("parity.typePolicyNameToConfirm_fc5738")}
      </label>
      <input
        ref={confirmRef}
        id="scep-policy-delete-confirm"
        value={confirmName}
        onChange={(event) => setConfirmName(event.target.value)}
        className="mt-1 w-full rounded-control border border-destructive/40 bg-background px-3 py-2 text-sm text-foreground"
        placeholder={policy.name}
      />
      <div className="mt-3 flex gap-2">
        <Button type="button" size="sm" variant="destructive" loading={busy} disabled={confirmName.trim() !== policy.name} onClick={() => void confirmDelete()}>
          {t("parity.yesDeletePolicy_30ce34")}
        </Button>
        <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={onClose}>
          {translateNow("source.cancel.19766ed6cc")}
        </Button>
      </div>
    </Dialog>
  );
}

function DNS01ConfigDialog({
  config,
  onClose,
  onSaved,
  providers,
}: {
  config?: ACMEDNS01ProviderConfig;
  providers: ACMEDNS01ProviderCatalogItem[];
  onClose: () => void;
  onSaved: (updated: ACMEDNS01ProviderConfig) => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState(config?.name ?? "");
  const [provider, setProvider] = useState(config?.provider ?? providers[0]?.name ?? "");
  const [zone, setZone] = useState(config?.zone ?? "");
  const [challengeDomain, setChallengeDomain] = useState(config?.challenge_domain ?? "");
  const [delegationTarget, setDelegationTarget] = useState(config?.delegation_target ?? "");
  const [caaIssuerDomain, setCAAIssuerDomain] = useState(config?.caa_issuer_domain ?? "");
  const [allowWildcards, setAllowWildcards] = useState(config?.allow_wildcards ?? false);
  // B7 consent. Seeded from the saved config because this dialog does a PUT
  // (replace): a field the form does not send comes back false, so omitting it
  // here silently revoked upstream-DV consent every time an operator edited
  // anything else on the config — and the next renewal cycle would then need a
  // human nobody knew to expect.
  const [allowUpstreamDV, setAllowUpstreamDV] = useState(config?.allow_upstream_dv ?? false);
  const [allowedMethods, setAllowedMethods] = useState<ACMEChallengeMethod[]>(() => (config?.allowed_methods ?? []).filter(isACMEChallengeMethod));
  const [configJSON, setConfigJSON] = useState(() => stringifyRecord(config?.config));
  const [credentialRefsJSON, setCredentialRefsJSON] = useState(() => stringifyRecord(config?.credential_refs));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const nameRef = useRef<HTMLInputElement>(null);
  const titleId = "dns01-config-editor-heading";
  const providerOptions =
    config && !providers.some((candidate) => candidate.name === config.provider)
      ? [config.provider, ...providers.map((candidate) => candidate.name)]
      : providers.map((candidate) => candidate.name);
  const selectedProvider = providers.find((candidate) => candidate.name === provider);

  function toggleMethod(method: ACMEChallengeMethod, checked: boolean) {
    setAllowedMethods((current) => {
      const next = new Set(current);
      if (checked) next.add(method);
      else next.delete(method);
      return acmeMethodOptions.filter((candidate) => next.has(candidate));
    });
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const parsedConfig = parseOptionalJSONRecord(configJSON, "Provider config");
    if (typeof parsedConfig === "string") {
      setError(parsedConfig);
      return;
    }
    const parsedRefs = parseOptionalJSONRecord(credentialRefsJSON, "Credential references");
    if (typeof parsedRefs === "string") {
      setError(parsedRefs);
      return;
    }
    const input: ACMEDNS01ProviderConfigRequest = {
      name: name.trim(),
      provider: provider.trim(),
      allow_wildcards: allowWildcards,
      allow_upstream_dv: allowUpstreamDV,
    };
    if (zone.trim()) input.zone = zone.trim();
    if (challengeDomain.trim()) input.challenge_domain = challengeDomain.trim();
    if (delegationTarget.trim()) input.delegation_target = delegationTarget.trim();
    if (caaIssuerDomain.trim()) input.caa_issuer_domain = caaIssuerDomain.trim();
    if (allowedMethods.length > 0) input.allowed_methods = allowedMethods;
    if (parsedConfig) input.config = parsedConfig;
    if (parsedRefs) input.credential_refs = parsedRefs;
    setBusy(true);
    setError(null);
    try {
      onSaved(config ? await api.updateACMEDNS01ProviderConfig(config.id, input) : await api.createACMEDNS01ProviderConfig(input));
    } catch (err) {
      setError(protocolStatusError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      titleId={titleId}
      initialFocusRef={nameRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative max-h-[calc(100vh-2rem)] w-full max-w-2xl overflow-y-auto rounded-panel border border-border bg-card shadow-elevation2"
    >
      <header className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 id={titleId} className="truncate text-title font-semibold">
            {config ? t("protocols.dns01.editDialogTitle", { name: config.name }) : t("protocols.dns01.addDialogTitle")}
          </h2>
          {config && <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{config.id}</p>}
        </div>
        <Button type="button" variant="ghost" size="icon" onClick={onClose} aria-label={t("parity.closeDns01ConfigForm_00c6cb")}>
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </header>
      <form className="grid gap-4 p-5" onSubmit={(event) => void submit(event)}>
        {error && <ErrorState title={config ? t("parity.dns01ConfigUpdateFailed_86ad97") : t("protocols.dns01.addFailed")}>{error}</ErrorState>}
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="grid gap-1 text-body font-medium">
            {t("parity.configName_11f179")}
            <input
              ref={nameRef}
              required
              value={name}
              onChange={(event) => setName(event.target.value)}
              className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
            />
          </label>
          <label className="grid gap-1 text-body font-medium">
            {translateNow("source.provider.472590ae97")}
            <select
              required
              value={provider}
              onChange={(event) => setProvider(event.target.value)}
              className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
            >
              {providerOptions.map((candidate) => (
                <option key={candidate} value={candidate}>
                  {providers.find((item) => item.name === candidate)?.display_name ?? candidate} — {candidate}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1 text-body font-medium">
            {t("parity.zoneOptional_0f915d")}
            <input
              value={zone}
              onChange={(event) => setZone(event.target.value)}
              className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
            />
          </label>
          <label className="grid gap-1 text-body font-medium">
            {t("parity.challengeDomainOptional_d7bed2")}
            <input
              value={challengeDomain}
              onChange={(event) => setChallengeDomain(event.target.value)}
              className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
            />
          </label>
          <label className="grid gap-1 text-body font-medium">
            {t("parity.delegationTargetOptional_8439dd")}
            <input
              value={delegationTarget}
              onChange={(event) => setDelegationTarget(event.target.value)}
              className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
            />
          </label>
          <label className="grid gap-1 text-body font-medium">
            {t("parity.caaIssuerDomainOptional_8c2f53")}
            <input
              value={caaIssuerDomain}
              onChange={(event) => setCAAIssuerDomain(event.target.value)}
              className="min-h-9 rounded-control border border-border bg-background px-3 py-2 text-body"
            />
          </label>
        </div>
        {provider && <DNS01ProviderTrustPanel provider={selectedProvider} />}
        <fieldset className="grid gap-2">
          <legend className="text-body font-medium">{t("parity.allowedMethods_ac5c6c")}</legend>
          <div className="flex flex-wrap gap-4">
            {acmeMethodOptions.map((method) => (
              <label key={method} className="flex items-center gap-2 text-body">
                <input type="checkbox" checked={allowedMethods.includes(method)} onChange={(event) => toggleMethod(method, event.target.checked)} />
                {method}
              </label>
            ))}
          </div>
        </fieldset>
        <label className="flex items-center gap-2 text-body font-medium">
          <input type="checkbox" checked={allowWildcards} onChange={(event) => setAllowWildcards(event.target.checked)} />
          {t("parity.allowWildcardIssuance_0fe53c")}
        </label>
        {/* B7: this is a permission, not a preference. It lets trstctl publish
            into this zone on an EXTERNAL CA's behalf, unattended, every
            validation cycle — which is not what credentials given for the
            server direction were granted for. */}
        <label className="flex items-start gap-2 text-body font-medium">
          <Checkbox className="mt-1" checked={allowUpstreamDV} onChange={(event) => setAllowUpstreamDV(event.target.checked)} />
          <span>
            {t("protocols.dns01.allowUpstreamDV")}
            <span className="mt-1 block text-caption font-normal text-muted-foreground">{t("protocols.dns01.allowUpstreamDVHelp")}</span>
          </span>
        </label>
        <label className="grid gap-1 text-body font-medium">
          {t("parity.providerConfigJsonOptional_02753c")}
          <textarea
            rows={4}
            value={configJSON}
            onChange={(event) => setConfigJSON(event.target.value)}
            className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
          />
        </label>
        <label className="grid gap-1 text-body font-medium">
          {t("parity.credentialReferencesJsonOptional_faddae")}
          <textarea
            rows={4}
            value={credentialRefsJSON}
            onChange={(event) => setCredentialRefsJSON(event.target.value)}
            className="min-h-24 rounded-control border border-border bg-background px-3 py-2 font-mono text-xs"
          />
          <span className="text-caption font-normal text-muted-foreground">{t("parity.secretReferencesOnlyRawCredentialsAre_f74f29")}</span>
        </label>
        <footer className="flex justify-end gap-2 border-t border-border pt-4">
          <Button type="button" variant="outline" onClick={onClose}>
            {translateNow("source.cancel.19766ed6cc")}
          </Button>
          <Button type="submit" disabled={busy || name.trim() === "" || provider.trim() === ""}>
            {config ? t("parity.saveConfig_64e1de") : t("protocols.dns01.addAction")}
          </Button>
        </footer>
      </form>
    </Dialog>
  );
}

function DNS01ConfigDeleteDialog({
  config,
  onClose,
  onDeleted,
}: {
  config: ACMEDNS01ProviderConfig;
  onClose: () => void;
  onDeleted: (config: ACMEDNS01ProviderConfig) => void;
}) {
  const { t } = useTranslation();
  const [confirmName, setConfirmName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const confirmRef = useRef<HTMLInputElement>(null);

  async function confirmDelete() {
    setBusy(true);
    setError(null);
    try {
      await api.deleteACMEDNS01ProviderConfig(config.id);
      onDeleted(config);
    } catch (err) {
      setError(protocolStatusError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open
      role="alertdialog"
      onClose={onClose}
      titleId="dns01-config-delete-title"
      descriptionId="dns01-config-delete-desc"
      initialFocusRef={confirmRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      overlayClassName="absolute inset-0 bg-black/55"
      panelClassName="relative w-full max-w-xl rounded-panel border border-destructive/40 bg-card p-4 text-sm shadow-elevation2"
    >
      <h2 id="dns01-config-delete-title" className="text-title font-semibold text-destructive">
        {translateNow("source.delete.dns.01.provider.config.d870732e81")}
        {config.name}”?
      </h2>
      <p id="dns01-config-delete-desc" className="mt-1 text-destructive">
        Deleting this config removes its challenge policy and credential references; ACME DNS-01 orders that rely on it will fail preflight. This cannot be
        undone.
      </p>
      {error && (
        <p role="alert" className="mt-2 text-destructive">
          {error}
        </p>
      )}
      <label className="mt-3 block text-sm font-medium text-destructive" htmlFor="dns01-config-delete-confirm">
        {t("parity.typeConfigNameToConfirm_f46ed6")}
      </label>
      <input
        ref={confirmRef}
        id="dns01-config-delete-confirm"
        value={confirmName}
        onChange={(event) => setConfirmName(event.target.value)}
        className="mt-1 w-full rounded-control border border-destructive/40 bg-background px-3 py-2 text-sm text-foreground"
        placeholder={config.name}
      />
      <div className="mt-3 flex gap-2">
        <Button type="button" size="sm" variant="destructive" loading={busy} disabled={confirmName.trim() !== config.name} onClick={() => void confirmDelete()}>
          {t("parity.yesDeleteConfig_bd6fac")}
        </Button>
        <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={onClose}>
          {translateNow("source.cancel.19766ed6cc")}
        </Button>
      </div>
    </Dialog>
  );
}

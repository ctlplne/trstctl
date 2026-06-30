import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Braces, Copy, Signature } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { formatDateTime as formatDateTimePolicy } from "@/i18n/format";
import { useTranslation } from "@/i18n/I18nProvider";
import { api, ApiError, type ACMEDNS01ProviderCatalogItem, type ACMEDNS01ProviderConfig, type ProtocolRuntimeStatus } from "@/lib/api";

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
        label: "certbot",
        command: "certbot certonly --server https://trstctl.example.test/directory --manual --preferred-challenges dns -d api.example.test",
      },
      {
        label: "x/crypto/acme",
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
        label: "cacerts",
        command: "curl -s https://trstctl.example.test/.well-known/est/cacerts -o cacerts.p7",
      },
      {
        label: "simpleenroll",
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
        label: "GetCACert",
        command: "sscep getca -u https://trstctl.example.test/scep -c trstctl-ca.pem",
      },
      {
        label: "PKIOperation",
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
        label: "OpenSSL p10cr",
        command: "openssl cmp -server https://trstctl.example.test -path /cmp -cmd p10cr -csr device.csr -certout device.pem",
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
        label: "spiffe-helper",
        command: "SPIFFE_ENDPOINT_SOCKET=unix:///tmp/trstctl-spiffe-workload.sock spiffe-helper -config ./spiffe-helper.conf",
      },
      {
        label: "go-spiffe",
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
        label: "authority key",
        command: "curl -s https://trstctl.example.test/ssh/ca -o /etc/ssh/trusted_user_ca_keys",
      },
      {
        label: "KRL",
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
        label: "OpenSSL query",
        command: "openssl ts -query -data artifact.bin -sha256 -cert -out request.tsq",
      },
      {
        label: "HTTP POST",
        command: "curl -s -H 'Content-Type: application/timestamp-query' --data-binary @request.tsq https://trstctl.example.test/tsa -o response.tsr",
      },
      {
        label: "OpenSSL verify",
        command: "openssl ts -verify -in response.tsr -queryfile request.tsq -CAfile tsa-ca.pem",
      },
    ],
  },
];

export function Protocols() {
  const { t } = useTranslation();
  const [copied, setCopied] = useState<string | null>(null);
  const [protocolStatuses, setProtocolStatuses] = useState<ProtocolRuntimeStatus[]>([]);
  const [statusCheckedAt, setStatusCheckedAt] = useState<string | null>(null);
  const [dnsProviders, setDNSProviders] = useState<ACMEDNS01ProviderCatalogItem[]>([]);
  const [dnsProviderConfigs, setDNSProviderConfigs] = useState<ACMEDNS01ProviderConfig[]>([]);
  const [statusLoading, setStatusLoading] = useState(true);
  const [statusError, setStatusError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setStatusLoading(true);
    setStatusError(null);
    Promise.all([api.protocolStatuses(), api.acmeDNS01Providers(), api.acmeDNS01ProviderConfigs()])
      .then(([page, providerCatalog, providerConfigs]) => {
        if (!active) return;
        setProtocolStatuses(page.items);
        setStatusCheckedAt(page.checked_at);
        setDNSProviders(providerCatalog.items ?? []);
        setDNSProviderConfigs(providerConfigs.items ?? []);
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

  async function copySnippet(protocol: ProtocolSurface, snippet: ProtocolSnippet) {
    try {
      await navigator.clipboard?.writeText(snippet.command);
    } finally {
      setCopied(`${protocol.id}:${snippet.label}`);
    }
  }

  return (
    <section aria-labelledby="protocols-heading" className="grid gap-6">
      <PageHeader
        titleId="protocols-heading"
        title="Protocols"
        description="The enrollment endpoints clients use to obtain certificates automatically — ACME, EST, SCEP, and CMP — with responder status and copy-paste client setup."
        actions={
          <>
            <Link
              to="/ssh"
              className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
            >
              <Braces className="h-4 w-4" aria-hidden="true" />
              {t("nav.item.sshTrust")}
            </Link>
            <Link
              to="/codesign"
              className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
            >
              <Signature className="h-4 w-4" aria-hidden="true" />
              {t("nav.item.codeSigning")}
            </Link>
          </>
        }
      />

      <section aria-labelledby="protocol-status-heading" className="border-y border-border py-4">
        <h2 id="protocol-status-heading" className="text-title font-semibold">
          Protocol responder status
        </h2>
        <div className="mt-3 grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <div className="ui-panel p-3 text-sm">
            <p className="font-medium">Read-only responder probe</p>
            <p className="mt-1 text-muted-foreground">
              The register checks the same-origin protocol responder paths the control plane mounts. A protocol is shown as off only when its responder path is
              missing or unavailable.
            </p>
            {statusCheckedAt && <p className="mt-2 text-caption text-muted-foreground">Checked {formatDate(statusCheckedAt)}</p>}
          </div>
          <div className="ui-panel p-3 text-sm">
            <p className="font-medium">Fail-closed startup and issuance posture</p>
            <p className="mt-1 text-muted-foreground">
              Each protocol requires an enabled flag plus a tenant ID. Startup rejects an enabled protocol with no tenant binding, and issuance refuses requests
              when no issuing CA/profile can satisfy the protocol request.
            </p>
          </div>
        </div>
      </section>

      <section aria-labelledby="protocol-table-heading">
        <h2 id="protocol-table-heading" className="mb-3 text-title font-semibold">
          Protocol register
        </h2>
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[56rem]">
            <caption className="sr-only">Enrollment protocol surfaces</caption>
            <thead>
              <tr>
                <th scope="col">Protocol</th>
                <th scope="col">Capability</th>
                <th scope="col">Tenant binding</th>
                <th scope="col">Auth and profile gate</th>
                <th scope="col">Responder status</th>
              </tr>
            </thead>
            <tbody>
              {protocolSurfaces.map((protocol) => {
                const status = statusByProtocol.get(protocol.id);
                return (
                  <tr key={protocol.id} className="align-top">
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
                      {status?.status_code != null && <p className="mt-1 text-caption text-muted-foreground">HTTP {status.status_code}</p>}
                      {status?.detail && <p className="mt-1 text-caption text-muted-foreground">{status.detail}</p>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="mt-3">
          {statusLoading && <LoadingState>Checking protocol responders.</LoadingState>}
          {statusError && <ErrorState title="Protocol status check failed">{statusError}</ErrorState>}
        </div>
      </section>

      <section aria-labelledby="dns-provider-heading">
        <h2 id="dns-provider-heading" className="mb-3 text-title font-semibold">
          {t("protocols.dns01.heading")}
        </h2>
        <div className="ui-panel overflow-x-auto">
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
                    <ProtocolServedBadge served={provider.served} servedLabel={t("protocols.dns01.served")} offLabel={t("protocols.dns01.off")} />
                  </td>
                  <td>{provider.kind}</td>
                  <td>
                    <p>{provider.conformance}</p>
                    {provider.propagation_preflight && <p className="mt-1 text-caption text-muted-foreground">{t("protocols.dns01.propagationPreflight")}</p>}
                  </td>
                  <td>
                    <ul className="grid gap-1">
                      {(provider.credential_reference_fields ?? []).map((field) => (
                        <li key={field} className="font-mono text-xs">
                          {field}
                        </li>
                      ))}
                    </ul>
                    {(provider.secret_fields ?? []).length === 0 && <p className="mt-2 text-caption text-muted-foreground">{t("protocols.dns01.noRawSecretFields")}</p>}
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
        </div>
        {statusLoading && <LoadingState>{t("protocols.dns01.loading")}</LoadingState>}
        {!statusLoading && !statusError && dnsProviders.length === 0 && (
          <ErrorState title={t("protocols.dns01.unavailableTitle")}>{t("protocols.dns01.empty")}</ErrorState>
        )}
      </section>

      <section aria-labelledby="dns-config-heading">
        <h2 id="dns-config-heading" className="mb-3 text-title font-semibold">
          {t("protocols.dns01.configHeading")}
        </h2>
        <div className="ui-panel overflow-x-auto">
          <table className="ui-table min-w-[68rem]">
            <caption className="sr-only">{t("protocols.dns01.configCaption")}</caption>
            <thead>
              <tr>
                <th scope="col">{t("protocols.dns01.config")}</th>
                <th scope="col">{t("protocols.dns01.provider")}</th>
                <th scope="col">{t("protocols.dns01.zone")}</th>
                <th scope="col">{t("protocols.dns01.policy")}</th>
                <th scope="col">{t("protocols.dns01.secretReferences")}</th>
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
                        {config.caa_issuer_domain && <li>CAA {config.caa_issuer_domain}</li>}
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
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {statusLoading && <LoadingState>{t("protocols.dns01.configLoading")}</LoadingState>}
        {!statusLoading && !statusError && dnsProviderConfigs.length === 0 && (
          <ErrorState title={t("protocols.dns01.configEmptyTitle")}>{t("protocols.dns01.configEmpty")}</ErrorState>
        )}
      </section>

      <section aria-labelledby="client-setup-heading" className="grid gap-4">
        <h2 id="client-setup-heading" className="text-title font-semibold">
          Client setup
        </h2>
        {protocolSurfaces.map((protocol) => (
          <section key={protocol.id} aria-labelledby={`${protocol.id}-heading`} className="border-y border-border py-4">
            <div className="grid gap-4 lg:grid-cols-[14rem_minmax(0,1fr)]">
              <div>
                <h3 id={`${protocol.id}-heading`} className="text-base font-semibold">
                  {protocol.name}
                </h3>
                <p className="mt-1 text-sm text-muted-foreground">{protocol.capability}</p>
              </div>
              <div className="grid gap-3">
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
                          aria-label={`Copy ${protocol.name} ${snippet.label} command`}
                          onClick={() => void copySnippet(protocol, snippet)}
                        >
                          <Copy className="h-4 w-4" aria-hidden="true" />
                          Copy
                        </Button>
                      </div>
                      <code className="block overflow-x-auto rounded bg-muted px-3 py-2 text-xs">{snippet.command}</code>
                      {copied === copiedKey && <p className="mt-2 text-xs text-muted-foreground">Copied command without token material.</p>}
                    </div>
                  );
                })}
              </div>
            </div>
          </section>
        ))}
      </section>
    </section>
  );
}

function credentialReferenceNames(config: ACMEDNS01ProviderConfig) {
  return Object.keys(config.credential_refs ?? {}).sort();
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
        Not browser-readable
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

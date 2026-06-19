import { useState } from "react";
import { Copy } from "lucide-react";
import { UnavailableState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";

interface ProtocolSnippet {
  label: string;
  command: string;
}

interface ProtocolSurface {
  id: string;
  name: string;
  feature: string;
  route: string;
  auth: string;
  env: string[];
  profile: string;
  snippets: ProtocolSnippet[];
  deferredRead: string;
  diagnostics: string;
}

interface AriSignal {
  signal: string;
  current: string;
  gate: string;
}

interface DnsProviderDisclosure {
  label: string;
  feature: string;
  reference: string;
  posture: string;
  status: string;
}

interface ValidationFixture {
  scenario: string;
  record: string;
  result: string;
}

const protocolSurfaces: ProtocolSurface[] = [
  {
    id: "acme",
    name: "ACME",
    feature: "F5",
    route: "GET /directory + POST /acme/...",
    auth: "ACME account key, challenge validation, profile gate",
    env: ["TRSTCTL_PROTOCOLS_ACME_ENABLED", "TRSTCTL_PROTOCOLS_ACME_TENANT_ID"],
    profile: "Use a profile that allows the acme protocol and serverAuth EKU.",
    snippets: [
      {
        label: "certbot",
        command:
          "certbot certonly --server https://trstctl.example.test/directory --manual --preferred-challenges dns -d api.example.test",
      },
      {
        label: "x/crypto/acme",
        command:
          'client := &acme.Client{DirectoryURL: "https://trstctl.example.test/directory"}',
      },
    ],
    deferredRead: "ACME accounts, orders, challenges, ARI state, and revocations",
    diagnostics: "No served ACME admin read lists orders or challenge outcomes yet.",
  },
  {
    id: "est",
    name: "EST",
    feature: "F22",
    route: "GET /.well-known/est/cacerts + POST /.well-known/est/simpleenroll",
    auth: "Bearer-token or TLS client auth, profile gate",
    env: ["TRSTCTL_PROTOCOLS_EST_ENABLED", "TRSTCTL_PROTOCOLS_EST_TENANT_ID"],
    profile: "Use a profile that allows the est protocol and the requested certificate shape.",
    snippets: [
      {
        label: "cacerts",
        command:
          "curl -s https://trstctl.example.test/.well-known/est/cacerts -o cacerts.p7",
      },
      {
        label: "simpleenroll",
        command:
          "curl -s -H 'Authorization: Bearer <bootstrap-token>' --data-binary @device.csr https://trstctl.example.test/.well-known/est/simpleenroll",
      },
    ],
    deferredRead: "EST enrollment transcript",
    diagnostics: "No served EST admin read exposes recent enrollments or protocol diagnostics yet.",
  },
  {
    id: "scep",
    name: "SCEP",
    feature: "F23",
    route: "GET/POST /scep",
    auth: "CMS transport, challenge-password gate, profile gate",
    env: ["TRSTCTL_PROTOCOLS_SCEP_ENABLED", "TRSTCTL_PROTOCOLS_SCEP_TENANT_ID", "TRSTCTL_PROTOCOLS_RA_KEY_FILE"],
    profile: "Use a profile that allows the scep protocol; keep the RA transport key on shared storage in HA.",
    snippets: [
      {
        label: "GetCACert",
        command:
          "sscep getca -u https://trstctl.example.test/scep -c trstctl-ca.pem",
      },
      {
        label: "PKIOperation",
        command:
          "sscep enroll -u https://trstctl.example.test/scep -c trstctl-ca.pem -k device.key -r device.csr -l device.pem",
      },
    ],
    deferredRead: "SCEP enrollment transcript",
    diagnostics: "No served SCEP admin read exposes recent PKIOperation outcomes or challenge failures yet.",
  },
  {
    id: "cmp",
    name: "CMP",
    feature: "F55",
    route: "POST /cmp",
    auth: "CMP protection key, profile gate",
    env: ["TRSTCTL_PROTOCOLS_CMP_ENABLED", "TRSTCTL_PROTOCOLS_CMP_TENANT_ID", "TRSTCTL_PROTOCOLS_RA_KEY_FILE"],
    profile: "Use a profile that allows the cmp protocol; keep the RA transport key on shared storage in HA.",
    snippets: [
      {
        label: "OpenSSL p10cr",
        command:
          "openssl cmp -server https://trstctl.example.test -path /cmp -cmd p10cr -csr device.csr -certout device.pem",
      },
    ],
    deferredRead: "CMP enrollment transcript",
    diagnostics: "No served CMP admin read exposes recent enrollment outcomes or response diagnostics yet.",
  },
  {
    id: "spiffe",
    name: "SPIFFE",
    feature: "F24",
    route: "gRPC UDS /tmp/trstctl-spiffe-workload.sock",
    auth: "Workload API metadata, selector match, X.509-SVID and JWT-SVID support",
    env: [
      "TRSTCTL_PROTOCOLS_SPIFFE_ENABLED",
      "TRSTCTL_PROTOCOLS_SPIFFE_TENANT_ID",
      "TRSTCTL_PROTOCOLS_SPIFFE_SOCKET_PATH",
      "TRSTCTL_PROTOCOLS_SPIFFE_TRUST_DOMAIN",
    ],
    profile: "Selectors map a workload to an allowed SPIFFE ID; no SVID private key is exposed through the console.",
    snippets: [
      {
        label: "spiffe-helper",
        command:
          "SPIFFE_ENDPOINT_SOCKET=unix:///tmp/trstctl-spiffe-workload.sock spiffe-helper -config ./spiffe-helper.conf",
      },
      {
        label: "go-spiffe",
        command:
          'source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix:///tmp/trstctl-spiffe-workload.sock")))',
      },
    ],
    deferredRead: "SPIFFE live workload status",
    diagnostics: "No served console read exposes trust domain, socket path, enabled state, or SVID issuance health yet.",
  },
  {
    id: "ssh",
    name: "SSH CA",
    feature: "F43",
    route: "GET /ssh/ca + POST /ssh/issue/user|host + GET /ssh/krl",
    auth: "Tenant-scoped JSON issuance, signer-held SSH CA key, OpenSSH binary KRL",
    env: ["TRSTCTL_PROTOCOLS_SSH_ENABLED", "TRSTCTL_PROTOCOLS_SSH_TENANT_ID"],
    profile: "Principals, extensions, and TTL policy are enforced by the SSH CA path; the CA private key stays in the signer.",
    snippets: [
      {
        label: "authority key",
        command:
          "curl -s https://trstctl.example.test/ssh/ca -o /etc/ssh/trusted_user_ca_keys",
      },
      {
        label: "KRL",
        command:
          "curl -s https://trstctl.example.test/ssh/krl -o /etc/ssh/revoked_keys.krl",
      },
    ],
    deferredRead: "SSH issue/revoke log",
    diagnostics: "No served SSH-CA admin read exposes issued user/host certificates or KRL revocation rows yet.",
  },
  {
    id: "tsa",
    name: "TSA",
    feature: "F51",
    route: "POST /tsa",
    auth: "RFC 3161 TimeStampReq, stable TSA certificate, signer-held TSA key",
    env: ["TRSTCTL_PROTOCOLS_TSA_ENABLED", "TRSTCTL_PROTOCOLS_TSA_TENANT_ID", "TRSTCTL_PROTOCOLS_TSA_CERT_FILE"],
    profile: "The TSA certificate is persisted for stable verification; the timestamp signing key stays in the signer.",
    snippets: [
      {
        label: "OpenSSL query",
        command:
          "openssl ts -query -data artifact.bin -sha256 -cert -out request.tsq",
      },
      {
        label: "HTTP POST",
        command:
          "curl -s -H 'Content-Type: application/timestamp-query' --data-binary @request.tsq https://trstctl.example.test/tsa -o response.tsr",
      },
      {
        label: "OpenSSL verify",
        command:
          "openssl ts -verify -in response.tsr -queryfile request.tsq -CAfile tsa-ca.pem",
      },
    ],
    deferredRead: "TSA issuance health",
    diagnostics: "No served TSA admin read exposes the active TSA certificate, tenant binding, enabled state, or timestamp issuance health yet.",
  },
];

const ariSignals: AriSignal[] = [
  {
    signal: "Renewal window",
    current: "Client renewal windows and Retry-After guidance are protocol concepts only; no live ARI window is read by this console.",
    gate: "ACME enabled flag plus durable ARI state",
  },
  {
    signal: "Client recommendation",
    current: "Clients should jitter inside the suggested window and keep using their existing certificate until replacement succeeds.",
    gate: "Served ARI recommendation read",
  },
  {
    signal: "Durable-state caveat",
    current: "ARI recommendations must survive process restart; in-memory hints would make retry storms and duplicate issuance more likely.",
    gate: "Persistent ACME order/account state",
  },
];

const dnsProviderDisclosures: DnsProviderDisclosure[] = [
  {
    label: "DNS-01 provider config",
    feature: "F69",
    reference: "secret://dns/cloudflare/prod",
    posture: "Scoped secret reference for _acme-challenge writes only. Raw DNS provider tokens are never typed into this console.",
    status: "Disabled in console until BACKEND-PROTOCOL-STATUS reports ACME enabled and a served DNS preflight read exists.",
  },
  {
    label: "Built-in provider",
    feature: "F70",
    reference: "route53",
    posture: "Bundled provider capability summary: create TXT, wait authoritative, clean up challenge TXT.",
    status: "Activation is blocked until served provider health and tenant binding are observable.",
  },
  {
    label: "Plugin provider",
    feature: "F70",
    reference: "wasm:dns/externaldns",
    posture: "Plugin providers need conformance results, provenance, and explicit DNS capability grants before activation.",
    status: "Plugin activation is blocked until verified conformance, provenance, and capability grants are served.",
  },
];

const cnameFixtures: ValidationFixture[] = [
  {
    scenario: "Delegated validation zone",
    record: "_acme-challenge.example.test CNAME _acme-challenge.acme-validation.example.net",
    result: "Preview would pass validation isolation because ACME writes stay in the delegated zone.",
  },
  {
    scenario: "Inline production zone",
    record: "_acme-challenge.inline.example.test TXT in primary zone",
    result: "Preview fails validation isolation policy because challenge writes touch the production zone.",
  },
];

const caaFixtures: ValidationFixture[] = [
  {
    scenario: "No CAA record",
    record: "example.test has no CAA",
    result: "Preview allows issuance only when profile and tenant policy allow missing CAA.",
  },
  {
    scenario: "CAA allowed issuer",
    record: '0 issue "trstctl.example.test"',
    result: "Preview allows issuance for this CA.",
  },
  {
    scenario: "CAA denied issuer",
    record: '0 issue "letsencrypt.org"',
    result: "Preview denies issuance for this CA.",
  },
  {
    scenario: "CAA DNS failure",
    record: "SERVFAIL while resolving CAA",
    result: "Preview fails closed until DNS lookup succeeds.",
  },
  {
    scenario: "Wildcard CAA",
    record: '0 issuewild "trstctl.example.test"',
    result: "Preview permits wildcard only with DNS-01 and wildcard acknowledgement.",
  },
];

const validationMethodFixtures: ValidationFixture[] = [
  {
    scenario: "HTTP-01",
    record: "http://example.test/.well-known/acme-challenge/{token}",
    result: "Allowed only for single-host issuance when edge HTTP reachability is policy-approved.",
  },
  {
    scenario: "DNS-01",
    record: "_acme-challenge.example.test TXT",
    result: "Required for wildcard issuance and compatible with CNAME delegation.",
  },
  {
    scenario: "TLS-ALPN-01",
    record: "acme-tls/1 on port 443",
    result: "Blocked when edge termination cannot serve the challenge certificate.",
  },
  {
    scenario: "Policy denied",
    record: "profile denies requested validation method",
    result: "Challenge selection fails before any external DNS or HTTP write.",
  },
];

export function Protocols() {
  const [copied, setCopied] = useState<string | null>(null);

  async function copySnippet(protocol: ProtocolSurface, snippet: ProtocolSnippet) {
    try {
      await navigator.clipboard?.writeText(snippet.command);
    } finally {
      setCopied(`${protocol.id}:${snippet.label}`);
    }
  }

  return (
    <section aria-labelledby="protocols-heading" className="grid gap-6">
      <div>
        <h1 id="protocols-heading" className="text-2xl font-semibold">
          Protocols
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Served-gated enrollment endpoints with exact paths, tenant-binding configuration, client setup commands, and honest gaps for live status reads.
        </p>
      </div>

      <section aria-labelledby="protocol-status-heading" className="border-y border-border py-4">
        <h2 id="protocol-status-heading" className="text-lg font-semibold">
          Protocol status source
        </h2>
        <div className="mt-3 grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <UnavailableState title="Live enabled-state is not served yet">
            `BACKEND-PROTOCOL-STATUS` must expose enabled/disabled state, tenant binding, public endpoint, and responder health before this console can claim a protocol is active. The protocol servers themselves are served-gated and default off.
          </UnavailableState>
          <div className="rounded-md border border-border p-3 text-sm">
            <p className="font-medium">Fail-closed startup and issuance posture</p>
            <p className="mt-1 text-muted-foreground">
              Each protocol requires an enabled flag plus a tenant ID. Startup rejects an enabled protocol with no tenant binding, and issuance refuses requests when no issuing CA/profile can satisfy the protocol request.
            </p>
          </div>
        </div>
      </section>

      <section aria-labelledby="ari-heading" className="grid gap-3 border-y border-border py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="ari-heading" className="text-lg font-semibold">
              ACME Renewal Information (ARI)
            </h2>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              ARI tells ACME clients when to renew and how to pace retries. This console only renders the safe model until ACME enabled-state and durable ARI state are served.
            </p>
          </div>
          <span className="inline-flex rounded-md border border-amber-200 bg-amber-50 px-2 py-1 text-xs font-medium text-amber-800">
            ACME enabled state unknown to console
          </span>
        </div>
        <UnavailableState title="ARI live renewal windows are not served yet">
          Disabled in console until `BACKEND-PROTOCOL-STATUS` reports ACME enabled and a served ARI read exposes durable renewal guidance.
        </UnavailableState>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[48rem] text-left text-sm">
            <caption className="sr-only">ACME ARI disclosure model</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Signal</th>
                <th scope="col" className="py-2 pr-4 font-medium">Console posture</th>
                <th scope="col" className="py-2 pr-3 font-medium">Backend gate</th>
              </tr>
            </thead>
            <tbody>
              {ariSignals.map((row) => (
                <tr key={row.signal} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4 font-medium">{row.signal}</td>
                  <td className="py-2 pr-4">{row.current}</td>
                  <td className="py-2 pr-3">{row.gate}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="dns-validation-heading" className="grid gap-4 border-y border-border py-4">
        <div>
          <h2 id="dns-validation-heading" className="text-lg font-semibold">
            ACME DNS validation
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            DNS-01 automation, provider plugins, CNAME isolation, CAA enforcement, validation-method policy, and wildcard issuance are shown as non-interactive previews until protocol status and DNS preflight reads are served.
          </p>
        </div>

        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[58rem] text-left text-sm">
            <caption className="sr-only">DNS provider and plugin disclosure</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Surface</th>
                <th scope="col" className="py-2 pr-4 font-medium">Reference</th>
                <th scope="col" className="py-2 pr-4 font-medium">Guardrail</th>
                <th scope="col" className="py-2 pr-3 font-medium">Console status</th>
              </tr>
            </thead>
            <tbody>
              {dnsProviderDisclosures.map((row) => (
                <tr key={row.label} className="border-b border-border align-top">
                  <td className="py-2 pl-3 pr-4">
                    <p className="font-medium">{row.label}</p>
                    <p className="text-xs text-muted-foreground">{row.feature}</p>
                  </td>
                  <td className="py-2 pr-4 font-mono text-xs">{row.reference}</td>
                  <td className="py-2 pr-4">{row.posture}</td>
                  <td className="py-2 pr-3">{row.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="grid gap-4 xl:grid-cols-3">
          <FixtureTable
            title="CNAME validation isolation"
            caption="CNAME validation isolation fixtures"
            rows={cnameFixtures}
          />
          <FixtureTable
            title="CAA policy preview"
            caption="CAA policy fixtures"
            rows={caaFixtures}
          />
          <FixtureTable
            title="Validation method policy"
            caption="Validation method fixtures"
            rows={validationMethodFixtures}
          />
        </div>

        <UnavailableState title="DNS validation controls are protocol-status gated">
          `BACKEND-PROTOCOL-STATUS` must serve ACME enabled-state, DNS provider health, challenge history, and preflight results before this console can run DNS checks. Wildcard issuance requires explicit operator acknowledgement, DNS-01 only, profile opt-in, and blast-radius review.
        </UnavailableState>
      </section>

      <section aria-labelledby="protocol-table-heading">
        <h2 id="protocol-table-heading" className="mb-3 text-lg font-semibold">
          Endpoint register
        </h2>
        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full min-w-[56rem] text-left text-sm">
            <caption className="sr-only">Served-gated enrollment protocol endpoints</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pl-3 pr-4 font-medium">Protocol</th>
                <th scope="col" className="py-2 pr-4 font-medium">Public route</th>
                <th scope="col" className="py-2 pr-4 font-medium">Tenant binding</th>
                <th scope="col" className="py-2 pr-4 font-medium">Auth and profile gate</th>
                <th scope="col" className="py-2 pr-3 font-medium">Console status</th>
              </tr>
            </thead>
            <tbody>
              {protocolSurfaces.map((protocol) => (
                <tr key={protocol.id} className="border-b border-border align-top">
                  <td className="py-3 pl-3 pr-4">
                    <p className="font-medium">{protocol.name}</p>
                    <p className="text-xs text-muted-foreground">{protocol.feature}</p>
                  </td>
                  <td className="py-3 pr-4 font-mono text-xs">{protocol.route}</td>
                  <td className="py-3 pr-4">
                    <ul className="grid gap-1">
                      {protocol.env.map((env) => (
                        <li key={env} className="font-mono text-xs">{env}</li>
                      ))}
                    </ul>
                  </td>
                  <td className="py-3 pr-4">
                    <p>{protocol.auth}</p>
                    <p className="mt-1 text-muted-foreground">{protocol.profile}</p>
                  </td>
                  <td className="py-3 pr-3">
                    <span className="inline-flex rounded-md border border-amber-200 bg-amber-50 px-2 py-1 text-xs font-medium text-amber-800">
                      Status unknown to console
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="client-setup-heading" className="grid gap-4">
        <h2 id="client-setup-heading" className="text-lg font-semibold">
          Client setup
        </h2>
        {protocolSurfaces.map((protocol) => (
          <section key={protocol.id} aria-labelledby={`${protocol.id}-heading`} className="border-y border-border py-4">
            <div className="grid gap-4 lg:grid-cols-[14rem_minmax(0,1fr)_minmax(18rem,0.8fr)]">
              <div>
                <h3 id={`${protocol.id}-heading`} className="text-base font-semibold">
                  {protocol.name}
                </h3>
                <p className="mt-1 text-sm text-muted-foreground">{protocol.route}</p>
              </div>
              <div className="grid gap-3">
                {protocol.snippets.map((snippet) => {
                  const copiedKey = `${protocol.id}:${snippet.label}`;
                  return (
                    <div key={snippet.label} className="rounded-md border border-border p-3">
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
              <div className="grid content-start gap-3">
                <UnavailableState title={`${protocol.deferredRead} not served yet`}>
                  {protocol.diagnostics} This remains blocked until a served admin/status read exists; the page does not invent order, challenge, or transcript data.
                </UnavailableState>
                <p className="rounded-md border border-border p-3 text-sm text-muted-foreground">
                  Live tenant binding and endpoint health also need `BACKEND-PROTOCOL-STATUS`.
                </p>
              </div>
            </div>
          </section>
        ))}
      </section>
    </section>
  );
}

function FixtureTable({
  title,
  caption,
  rows,
}: {
  title: string;
  caption: string;
  rows: ValidationFixture[];
}) {
  return (
    <section aria-labelledby={`${title.replace(/\W+/g, "-").toLowerCase()}-heading`} className="grid gap-2">
      <h3 id={`${title.replace(/\W+/g, "-").toLowerCase()}-heading`} className="text-base font-semibold">
        {title}
      </h3>
      <div className="overflow-x-auto rounded-md border border-border">
        <table className="w-full min-w-[24rem] text-left text-sm">
          <caption className="sr-only">{caption}</caption>
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th scope="col" className="py-2 pl-3 pr-4 font-medium">Scenario</th>
              <th scope="col" className="py-2 pr-4 font-medium">Record</th>
              <th scope="col" className="py-2 pr-3 font-medium">Preview result</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.scenario} className="border-b border-border align-top">
                <td className="py-2 pl-3 pr-4 font-medium">{row.scenario}</td>
                <td className="py-2 pr-4 font-mono text-xs">{row.record}</td>
                <td className="py-2 pr-3">{row.result}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

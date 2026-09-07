import type { MessageKey } from "@/i18n/messages";
import type { JourneyCensusId } from "@/lib/journeyCensus.gen";

/** Journeys turn the documented operator walkthroughs (docs/journeys/*.md)
 * into live, click-through checklists: steps with a `to` deep-link straight to
 * the exact page and workspace tab; steps with a `command` show the verbatim,
 * copy-ready command for the parts the console does not serve (YAML, DNS,
 * external tooling); steps with a `detect` check themselves off from served
 * data. Definitions are data-only so the runner stays generic. */

export type JourneyDetector =
  | "issuers"
  | "requests"
  | "certificates"
  | "sources"
  | "runs"
  | "findings"
  | "profiles"
  | "incidents"
  | "agents"
  | "secrets"
  | "members"
  | "audit";

export interface JourneyStep {
  id: string;
  titleKey: MessageKey;
  bodyKey: MessageKey;
  /** Deep link straight to the page (and `?tab=` workspace) for this step. */
  to?: string;
  /** Copy-ready command/config snippet for console-less steps (verbatim from the reference doc). */
  command?: string;
  /** When present, the step auto-completes once served data shows progress. */
  detect?: JourneyDetector;
}

export interface Journey {
  /** Also keys the generated shipped-binary census evidence for this path. */
  id: JourneyCensusId;
  titleKey: MessageKey;
  descriptionKey: MessageKey;
  /** The long-form reference walkthrough this journey mirrors. */
  doc: string;
  steps: JourneyStep[];
}

export const journeys: Journey[] = [
  {
    id: "first-certificate",
    titleKey: "journeys.fc.title",
    descriptionKey: "journeys.fc.description",
    doc: "docs/journeys/first-certificate.md",
    steps: [
      // The wizard's proof is a real certificate, not merely an issuer catalog
      // row. Fresh eval installs use the built-in signer-backed setup issuer,
      // so checking the catalog left a completed wizard stuck at 3/4.
      { id: "wizard", titleKey: "journeys.fc.wizard.title", bodyKey: "journeys.fc.wizard.body", to: "/wizard", detect: "certificates" },
      { id: "request", titleKey: "journeys.fc.request.title", bodyKey: "journeys.fc.request.body", to: "/request", detect: "requests" },
      { id: "approve", titleKey: "journeys.fc.approve.title", bodyKey: "journeys.fc.approve.body", to: "/approvals?status=pending", detect: "certificates" },
      { id: "inventory", titleKey: "journeys.fc.inventory.title", bodyKey: "journeys.fc.inventory.body", to: "/certificates", detect: "certificates" },
    ],
  },
  {
    id: "migrate-from-existing-ca",
    titleKey: "journeys.mig.title",
    descriptionKey: "journeys.mig.description",
    doc: "docs/journeys/migrate-from-existing-ca.md",
    steps: [
      { id: "source", titleKey: "journeys.mig.source.title", bodyKey: "journeys.mig.source.body", to: "/discovery?tab=sources", detect: "sources" },
      { id: "scan", titleKey: "journeys.mig.scan.title", bodyKey: "journeys.mig.scan.body", to: "/discovery?tab=sources", detect: "runs" },
      { id: "findings", titleKey: "journeys.mig.findings.title", bodyKey: "journeys.mig.findings.body", to: "/discovery", detect: "findings" },
      { id: "profile", titleKey: "journeys.mig.profile.title", bodyKey: "journeys.mig.profile.body", to: "/profiles", detect: "profiles" },
      { id: "request", titleKey: "journeys.mig.request.title", bodyKey: "journeys.mig.request.body", to: "/request", detect: "requests" },
      { id: "health", titleKey: "journeys.mig.health.title", bodyKey: "journeys.mig.health.body", to: "/certificates?tab=health" },
    ],
  },
  {
    id: "preserve-existing-ca",
    titleKey: "journeys.pec.title",
    descriptionKey: "journeys.pec.description",
    doc: "docs/journeys/preserve-existing-ca.md",
    steps: [
      {
        id: "baseline",
        titleKey: "journeys.pec.baseline.title",
        bodyKey: "journeys.pec.baseline.body",
        command:
          "openssl s_client -connect web-canary.example.test:443 \\\n  -servername web-canary.example.test -showcerts </dev/null 2>/dev/null \\\n  | openssl x509 -noout -fingerprint -sha256 -issuer -subject -dates",
      },
      { id: "discover", titleKey: "journeys.pec.discover.title", bodyKey: "journeys.pec.discover.body", to: "/discovery?tab=sources", detect: "sources" },
      { id: "authority", titleKey: "journeys.pec.authority.title", bodyKey: "journeys.pec.authority.body", to: "/ca-hierarchy", detect: "issuers" },
      { id: "preview", titleKey: "journeys.pec.preview.title", bodyKey: "journeys.pec.preview.body", to: "/connectors" },
      { id: "authorize", titleKey: "journeys.pec.authorize.title", bodyKey: "journeys.pec.authorize.body", to: "/connectors" },
      { id: "inspect", titleKey: "journeys.pec.inspect.title", bodyKey: "journeys.pec.inspect.body", to: "/certificates?tab=health", detect: "certificates" },
      { id: "routing", titleKey: "journeys.pec.routing.title", bodyKey: "journeys.pec.routing.body", to: "/notifications" },
    ],
  },
  {
    id: "respond-to-compromise",
    titleKey: "journeys.ir.title",
    descriptionKey: "journeys.ir.description",
    doc: "docs/journeys/respond-to-compromise.md",
    steps: [
      { id: "blast", titleKey: "journeys.ir.blast.title", bodyKey: "journeys.ir.blast.body", to: "/graph" },
      { id: "contain", titleKey: "journeys.ir.contain.title", bodyKey: "journeys.ir.contain.body", to: "/incidents", detect: "incidents" },
      { id: "verify", titleKey: "journeys.ir.verify.title", bodyKey: "journeys.ir.verify.body", to: "/certificates?tab=crlct" },
      { id: "evidence", titleKey: "journeys.ir.evidence.title", bodyKey: "journeys.ir.evidence.body", to: "/audit" },
    ],
  },
  {
    id: "automate-fleet-tls",
    titleKey: "journeys.fleet.title",
    descriptionKey: "journeys.fleet.description",
    doc: "docs/journeys/automate-fleet-tls.md",
    steps: [
      { id: "protocols", titleKey: "journeys.fleet.protocols.title", bodyKey: "journeys.fleet.protocols.body", to: "/protocols" },
      { id: "dns", titleKey: "journeys.fleet.dns.title", bodyKey: "journeys.fleet.dns.body", to: "/protocols" },
      {
        id: "certbot",
        titleKey: "journeys.fleet.certbot.title",
        bodyKey: "journeys.fleet.certbot.body",
        command:
          "certbot certonly \\\n  --server https://trstctl.example.com/directory \\\n  --preferred-challenges dns \\\n  -d 'example.com' -d '*.example.com'",
      },
      {
        id: "bindings",
        titleKey: "journeys.fleet.bindings.title",
        bodyKey: "journeys.fleet.bindings.body",
        to: "/certificates?tab=renewal",
        command:
          'curl -sS -X POST "$TRSTCTL_URL/api/v1/lifecycle/endpoint-bindings/preview" \\\n  -H "Authorization: Bearer $TRSTCTL_TOKEN" \\\n  -H "Content-Type: application/json" \\\n  -d @endpoint-binding-plan.json',
      },
    ],
  },
  {
    id: "kubernetes-workload-identity",
    titleKey: "journeys.k8s.title",
    descriptionKey: "journeys.k8s.description",
    doc: "docs/journeys/kubernetes-workload-identity.md",
    steps: [
      { id: "trust", titleKey: "journeys.k8s.trust.title", bodyKey: "journeys.k8s.trust.body", to: "/workloads" },
      { id: "spiffe", titleKey: "journeys.k8s.spiffe.title", bodyKey: "journeys.k8s.spiffe.body", to: "/protocols" },
      {
        id: "register",
        titleKey: "journeys.k8s.register.title",
        bodyKey: "journeys.k8s.register.body",
        to: "/identities",
        command: "trstctl-cli identities create -f service-account.json",
        detect: "requests",
      },
      {
        id: "integrate",
        titleKey: "journeys.k8s.integrate.title",
        bodyKey: "journeys.k8s.integrate.body",
        command:
          "apiVersion: trstctl.com/v1alpha1\nkind: ClusterIssuer\nmetadata:\n  name: trstctl\nspec:\n  signerURL: https://trstctl:8443/api/v1/ca/authorities/<ca-authority-id>/issue",
      },
      {
        id: "verify",
        titleKey: "journeys.k8s.verify.title",
        bodyKey: "journeys.k8s.verify.body",
        to: "/certificates",
        command: "trstctl-cli certificates list --limit 50",
        detect: "certificates",
      },
    ],
  },
  {
    id: "enroll-devices",
    titleKey: "journeys.devices.title",
    descriptionKey: "journeys.devices.description",
    doc: "docs/journeys/enroll-devices.md",
    steps: [
      { id: "protocols", titleKey: "journeys.devices.protocols.title", bodyKey: "journeys.devices.protocols.body", to: "/protocols" },
      {
        id: "cacerts",
        titleKey: "journeys.devices.cacerts.title",
        bodyKey: "journeys.devices.cacerts.body",
        command: "curl -s https://trstctl.example.com/.well-known/est/cacerts -o cacerts.p7",
      },
      {
        id: "enroll",
        titleKey: "journeys.devices.enroll.title",
        bodyKey: "journeys.devices.enroll.body",
        command:
          'curl -s -H "Content-Type: application/pkcs10" \\\n  -H "Idempotency-Key: $(uuidgen)" \\\n  --data-binary @request.b64 \\\n  https://trstctl.example.com/.well-known/est/simpleenroll',
      },
      {
        id: "bootstrap",
        titleKey: "journeys.devices.bootstrap.title",
        bodyKey: "journeys.devices.bootstrap.body",
        to: "/protocols",
        // Placeholders avoid angle brackets: the i18n extractor's JSX-text
        // heuristic reads a bracket pair inside one string as markup.
        command: 'curl -s -X POST https://trstctl.example.com/enroll/bootstrap \\\n  -d \'{"token":"ONE-TIME-TOKEN","csr":"BASE64-DER-CSR"}\'',
      },
    ],
  },
  {
    id: "manage-secrets",
    titleKey: "journeys.sec.title",
    descriptionKey: "journeys.sec.description",
    doc: "docs/journeys/manage-secrets.md",
    steps: [
      {
        id: "enable",
        titleKey: "journeys.sec.enable.title",
        bodyKey: "journeys.sec.enable.body",
        command: "export TRSTCTL_SECRETS_KEK_FILE=/etc/trstctl/secrets-kek",
      },
      { id: "store", titleKey: "journeys.sec.store.title", bodyKey: "journeys.sec.store.body", to: "/secrets", detect: "secrets" },
      { id: "engines", titleKey: "journeys.sec.engines.title", bodyKey: "journeys.sec.engines.body", to: "/secrets/engines" },
      { id: "share", titleKey: "journeys.sec.share.title", bodyKey: "journeys.sec.share.body", to: "/secrets/sharing" },
      { id: "scan", titleKey: "journeys.sec.scan.title", bodyKey: "journeys.sec.scan.body", to: "/secrets/scanning" },
      { id: "sync", titleKey: "journeys.sec.sync.title", bodyKey: "journeys.sec.sync.body", to: "/secrets/sync" },
    ],
  },
  {
    id: "ssh-at-scale",
    titleKey: "journeys.ssh.title",
    descriptionKey: "journeys.ssh.description",
    doc: "docs/journeys/ssh-at-scale.md",
    steps: [
      {
        id: "source",
        titleKey: "journeys.ssh.source.title",
        bodyKey: "journeys.ssh.source.body",
        to: "/discovery?tab=sources",
        command: "trstctl-cli discovery sources create -f ssh-source.json",
        detect: "sources",
      },
      { id: "findings", titleKey: "journeys.ssh.findings.title", bodyKey: "journeys.ssh.findings.body", to: "/discovery", detect: "findings" },
      {
        id: "trust",
        titleKey: "journeys.ssh.trust.title",
        bodyKey: "journeys.ssh.trust.body",
        to: "/ssh",
        command:
          "trstctl ssh trust-rollout \\\n  --source <source-id> \\\n  --hosts edge-1.internal \\\n  --ca-fingerprint SHA256:... \\\n  --reload-cmd 'systemctl reload sshd' \\\n  --health-cmd 'ssh -o BatchMode=yes localhost true' \\\n  --rollback-plan 'restore trusted_user_ca_keys backup and reload sshd' \\\n  --status health_passed \\\n  --confirm",
      },
      {
        id: "issue",
        titleKey: "journeys.ssh.issue.title",
        bodyKey: "journeys.ssh.issue.body",
        to: "/ssh",
        command: "trstctl ssh issue-attested-user -f ssh-attested-user.json",
      },
      {
        id: "revoke",
        titleKey: "journeys.ssh.revoke.title",
        bodyKey: "journeys.ssh.revoke.body",
        to: "/ssh",
        command: "trstctl ssh revoke --serial <serial> --reason 'operator requested revocation'",
      },
      { id: "retire", titleKey: "journeys.ssh.retire.title", bodyKey: "journeys.ssh.retire.body", to: "/ssh", command: "trstctl ssh status" },
    ],
  },
  {
    id: "operate-as-a-provider",
    titleKey: "journeys.provider.title",
    descriptionKey: "journeys.provider.description",
    doc: "docs/journeys/operate-as-a-provider.md",
    steps: [
      {
        id: "entitlement",
        titleKey: "journeys.provider.entitlement.title",
        bodyKey: "journeys.provider.entitlement.body",
        to: "/admin/editions",
        command: "trstctl-cli managed-offering status",
      },
      { id: "signin", titleKey: "journeys.provider.signin.title", bodyKey: "journeys.provider.signin.body", command: "trstctl-cli managed-offering status" },
      {
        id: "delegate",
        titleKey: "journeys.provider.delegate.title",
        bodyKey: "journeys.provider.delegate.body",
        command:
          "trstctl provider-grant -operator op-1 -customer acme-robotics -operations read,provision,suspend,resume -granted-by platform-admin -idempotency-key acme-robotics-op-1-v1",
      },
      {
        id: "customers",
        titleKey: "journeys.provider.customers.title",
        bodyKey: "journeys.provider.customers.body",
        command: "trstctl-cli managed-offering tenants provision -f hosted-tenant.json",
      },
      { id: "lifecycle", titleKey: "journeys.provider.lifecycle.title", bodyKey: "journeys.provider.lifecycle.body", to: "/connectors" },
    ],
  },
  {
    id: "onboard-a-team",
    titleKey: "journeys.team.title",
    descriptionKey: "journeys.team.description",
    doc: "docs/journeys/onboard-a-team.md",
    steps: [
      {
        id: "token",
        titleKey: "journeys.team.token.title",
        bodyKey: "journeys.team.token.body",
        command: "trstctl token create --tenant 22222222-2222-2222-2222-222222222222 --subject payments-team",
      },
      {
        id: "sso",
        titleKey: "journeys.team.sso.title",
        bodyKey: "journeys.team.sso.body",
        command:
          "export TRSTCTL_AUTH_OIDC_ISSUER=https://login.example.com/\nexport TRSTCTL_AUTH_OIDC_CLIENT_ID=trstctl-web\nexport TRSTCTL_AUTH_OIDC_REDIRECT_URI=https://trstctl.example.com/auth/callback",
      },
      { id: "roles", titleKey: "journeys.team.roles.title", bodyKey: "journeys.team.roles.body", to: "/admin/access", detect: "members" },
      { id: "policy", titleKey: "journeys.team.policy.title", bodyKey: "journeys.team.policy.body", to: "/policy" },
      {
        id: "audit",
        titleKey: "journeys.team.audit.title",
        bodyKey: "journeys.team.audit.body",
        to: "/audit",
        command: "trstctl-cli audit export --since 2026-01-01T00:00:00Z --until 2026-06-01T00:00:00Z",
        detect: "audit",
      },
    ],
  },
  {
    id: "crypto-agility-pqc",
    titleKey: "journeys.pqc.title",
    descriptionKey: "journeys.pqc.description",
    doc: "docs/journeys/crypto-agility-pqc.md",
    steps: [
      {
        id: "scan",
        titleKey: "journeys.pqc.scan.title",
        bodyKey: "journeys.pqc.scan.body",
        to: "/posture",
        command:
          'curl -sS -H "Idempotency-Key: cbom-pqc-001" \\\n  -X POST https://trstctl.example.com/api/v1/cbom/scans \\\n  -d \'{"tls_endpoints": ["payments.internal.example:443"],\n       "host_configs": ["/etc/nginx/sites-enabled/payments.conf"]}\'',
      },
      { id: "inventory", titleKey: "journeys.pqc.inventory.title", bodyKey: "journeys.pqc.inventory.body", to: "/posture" },
      { id: "graph", titleKey: "journeys.pqc.graph.title", bodyKey: "journeys.pqc.graph.body", to: "/graph", command: "trstctl-cli graph nodes" },
      {
        id: "profile",
        titleKey: "journeys.pqc.profile.title",
        bodyKey: "journeys.pqc.profile.body",
        to: "/profiles",
        command: "trstctl-cli profiles create -f hybrid-web-30d.json",
        detect: "profiles",
      },
      {
        id: "migrate",
        titleKey: "journeys.pqc.migrate.title",
        bodyKey: "journeys.pqc.migrate.body",
        command:
          'curl -sS -H "Idempotency-Key: pqc-migration-001" \\\n  -X POST https://trstctl.example.com/api/v1/pqc/migrations \\\n  -d @pqc-migration.json',
      },
    ],
  },
  {
    id: "run-in-production",
    titleKey: "journeys.prod.title",
    descriptionKey: "journeys.prod.description",
    doc: "docs/journeys/run-in-production.md",
    steps: [
      {
        id: "tls",
        titleKey: "journeys.prod.tls.title",
        bodyKey: "journeys.prod.tls.body",
        command: "export TRSTCTL_SERVER_TLS_CERT_FILE=/etc/trstctl/tls.crt\nexport TRSTCTL_SERVER_TLS_KEY_FILE=/etc/trstctl/tls.key",
      },
      {
        id: "health",
        titleKey: "journeys.prod.health.title",
        bodyKey: "journeys.prod.health.body",
        to: "/admin/system",
        command: "curl -fksS https://localhost:8443/readyz",
      },
      {
        id: "backup",
        titleKey: "journeys.prod.backup.title",
        bodyKey: "journeys.prod.backup.body",
        command: "trstctl --full-backup-dir=/backups/trstctl-$(date +%F)",
      },
      {
        id: "audit",
        titleKey: "journeys.prod.audit.title",
        bodyKey: "journeys.prod.audit.body",
        to: "/audit",
        command: "trstctl-cli audit events --type policy.decision --since 2026-01-01T00:00:00Z --limit 100",
        detect: "audit",
      },
      { id: "resilience", titleKey: "journeys.prod.resilience.title", bodyKey: "journeys.prod.resilience.body", to: "/admin/system" },
    ],
  },
  {
    id: "build-on-the-api",
    titleKey: "journeys.api.title",
    descriptionKey: "journeys.api.description",
    doc: "docs/journeys/build-on-the-api.md",
    steps: [
      {
        id: "contract",
        titleKey: "journeys.api.contract.title",
        bodyKey: "journeys.api.contract.body",
        to: "/integrate/api",
        command: "curl -fksS https://localhost:8443/api/v1/openapi.json",
      },
      {
        id: "cli",
        titleKey: "journeys.api.cli.title",
        bodyKey: "journeys.api.cli.body",
        command: "export TRSTCTL_SERVER=https://localhost:8443\nexport TRSTCTL_TOKEN=trst_...\ntrstctl-cli certificates list --limit 50",
      },
      {
        id: "idempotency",
        titleKey: "journeys.api.idempotency.title",
        bodyKey: "journeys.api.idempotency.body",
        command: 'echo \'{"kind":"workload","name":"payments"}\' \\\n  | trstctl-cli owners create -f - --idempotency-key my-stable-key',
      },
      { id: "graph", titleKey: "journeys.api.graph.title", bodyKey: "journeys.api.graph.body", to: "/graph", command: "trstctl-cli graph nodes" },
    ],
  },
];

export function journeyById(id: string | null): Journey {
  return journeys.find((journey) => journey.id === id) ?? journeys[0];
}

/** Journey ids are the doc slugs (docs/journeys/<id>.md), so the published
 * walkthrough for every journey lives at the same slug on the docs site. */
export const journeyDocsBaseUrl = "https://docs.trstctl.com/journeys";

export function journeyDocUrl(journey: Journey): string {
  return `${journeyDocsBaseUrl}/${journey.id}/`;
}

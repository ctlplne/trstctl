import { useState } from "react";
import { Link } from "react-router-dom";
import { BookOpen } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { SectionCard } from "@/components/dashboard";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";

const protocols = [
  { name: "ACME", reference: "/acme/{profile}/directory", note: "RFC 8555 — cert-manager, Caddy, certbot, Traefik." },
  { name: "EST", reference: "/.well-known/est/{profile}/cacerts", note: "RFC 7030 — routers, switches, and embedded fleets." },
  { name: "SCEP", reference: "/scep/{profile}", note: "MDM enrollment for laptops and mobile devices." },
];

const sdks = [
  { name: "Python SDK", reference: "pip install trstctl" },
  { name: "Go SDK", reference: "go get github.com/trstctl/trstctl/clients/sdk/go" },
  { name: "TypeScript SDK", reference: "npm install @trstctl/sdk" },
  { name: "Java SDK", reference: "com.trstctl:sdk" },
];

const iac = [
  { name: "Terraform provider", reference: "terraform { required_providers { trstctl = { source = \"trstctl/trstctl\" } } }" },
  { name: "cert-manager issuer", reference: "kind: ClusterIssuer  # external-issuer: trstctl-acme" },
  { name: "SPIRE upstream authority", reference: "UpstreamAuthority \"trstctl\" { ... }" },
];

function CopyRef({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="flex items-center gap-2">
      <code className="flex-1 truncate rounded bg-muted px-2 py-1 font-mono text-xs">{value}</code>
      <Button
        type="button"
        size="sm"
        variant="outline"
        aria-label={`Copy ${value}`}
        onClick={() => {
          void globalThis.navigator?.clipboard?.writeText(value);
          setCopied(true);
        }}
      >
        {copied ? "Copied" : "Copy"}
      </Button>
    </span>
  );
}

/** Integrate is the one place to wire trstctl into a stack: copy the served
 * ACME/EST/SCEP enrollment URLs, grab an SDK, or drop in the Terraform / cert-
 * manager / SPIRE integration. Every reference points at a served surface; no
 * internal-only endpoint is exposed here. */
export function Integrate() {
  const { t } = useTranslation();
  return (
    <section aria-labelledby="integrate-heading" className="grid gap-6">
      <PageHeader
        titleId="integrate-heading"
        title="Integrate"
        description="Wire trstctl into your stack: enrollment protocols, language SDKs, and infrastructure-as-code, each with a copyable reference."
        actions={
          <Link
            to="/integrate/api"
            className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium hover:border-brand-accent/40 hover:bg-muted/60"
          >
            <BookOpen className="h-4 w-4" aria-hidden="true" />
            {t("nav.item.apiExplorer")}
          </Link>
        }
      />

      <SectionCard title="Enrollment protocols" description="Standards-based certificate enrollment endpoints (per issuance profile).">
        <ul className="grid gap-3">
          {protocols.map((protocol) => (
            <li key={protocol.name} className="grid gap-1">
              <span className="text-sm font-medium">{protocol.name}</span>
              <CopyRef value={protocol.reference} />
              <span className="text-caption text-muted-foreground">{protocol.note}</span>
            </li>
          ))}
        </ul>
      </SectionCard>

      <SectionCard title="SDKs" description="Generated client libraries for the trstctl API.">
        <ul className="grid gap-3 md:grid-cols-2">
          {sdks.map((sdk) => (
            <li key={sdk.name} className="grid gap-1">
              <span className="text-sm font-medium">{sdk.name}</span>
              <CopyRef value={sdk.reference} />
            </li>
          ))}
        </ul>
      </SectionCard>

      <SectionCard title="Infrastructure as code" description="Declare trstctl trust the same way you declare the rest of your platform.">
        <ul className="grid gap-3">
          {iac.map((entry) => (
            <li key={entry.name} className="grid gap-1">
              <span className="text-sm font-medium">{entry.name}</span>
              <CopyRef value={entry.reference} />
            </li>
          ))}
        </ul>
      </SectionCard>
    </section>
  );
}

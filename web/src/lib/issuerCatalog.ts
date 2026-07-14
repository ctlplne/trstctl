import { translateNow } from "@/i18n/I18nProvider";
export type IssuerFieldType = "text" | "password" | "number" | "select" | "textarea";

export interface IssuerConfigField {
  key: string;
  label: string;
  type?: IssuerFieldType;
  placeholder?: string;
  required?: boolean;
  options?: string[];
  defaultValue?: string;
  sensitive?: boolean;
}

export interface IssuerTypeConfig {
  id: string;
  name: string;
  description: string;
  icon: "building" | "cloud" | "globe" | "home" | "key" | "lock" | "server";
  internal: boolean;
  configFields: IssuerConfigField[];
}

export const issuerTypes: IssuerTypeConfig[] = [
  {
    id: "ACME",
    name: "ACME",
    get description() {
      return translateNow("source.let.s.encrypt.zerossl.or.another.acme.comp.1c98036428");
    },
    icon: "globe",
    internal: false,
    configFields: [
      { key: "directory_url", get label() {
      return translateNow("source.directory.url.2029b746ff");
    }, placeholder: "https://acme.example/directory", required: true },
      { key: "email", get label() {
      return translateNow("source.email.969ccbd3cf");
    }, placeholder: "ops@example.test", required: true },
      { key: "challenge_type", get label() {
      return translateNow("source.challenge.type.28e80b8fc5");
    }, type: "select", options: ["http-01", "dns-01", "dns-persist-01"], defaultValue: "http-01" },
      { key: "profile", get label() {
      return translateNow("source.certificate.profile.529fcbe3c7");
    }, type: "select", options: ["", "tlsserver", "shortlived"], defaultValue: "" },
      { key: "eab_kid", get label() {
      return translateNow("source.eab.key.id.ae214f3c91");
    }, placeholder: "External account binding key id" },
      { key: "eab_hmac", get label() {
      return translateNow("source.eab.hmac.key.66e42cab64");
    }, placeholder: "External account binding HMAC", type: "password", sensitive: true },
    ],
  },
  {
    id: "GenericCA",
    name: "Local CA",
    get description() {
      return translateNow("source.signer.backed.internal.authority.managed.b.19410d893d");
    },
    icon: "home",
    internal: true,
    configFields: [
      { key: "key_policy", get label() {
      return translateNow("source.key.policy.11836d31c5");
    }, type: "select", options: ["managed-key", "ceremony-backed"], defaultValue: "managed-key" },
      { key: "max_path_len", get label() {
      return translateNow("source.max.path.length.bd7da36364");
    }, type: "number", placeholder: "1" },
    ],
  },
  {
    id: "StepCA",
    name: "step-ca",
    get description() {
      return translateNow("source.smallstep.private.ca.with.provisioner.back.5405e244dd");
    },
    icon: "key",
    internal: false,
    configFields: [
      { key: "ca_url", get label() {
      return translateNow("source.ca.url.e1a07aa107");
    }, placeholder: "https://ca.example.com", required: true },
      { key: "provisioner_name", get label() {
      return translateNow("source.provisioner.name.5f64622a37");
    }, placeholder: "ops-provisioner", required: true },
      { key: "provisioner_password", get label() {
      return translateNow("source.provisioner.password.1b221f0592");
    }, type: "password", sensitive: true },
    ],
  },
  {
    id: "VaultPKI",
    name: "Vault PKI",
    get description() {
      return translateNow("source.hashicorp.vault.pki.secrets.engine.f550e2a57a");
    },
    icon: "lock",
    internal: false,
    configFields: [
      { key: "addr", get label() {
      return translateNow("source.vault.address.dad7f7adc2");
    }, placeholder: "https://vault.internal:8200", required: true },
      { key: "token", get label() {
      return translateNow("source.vault.token.5a3be032b1");
    }, type: "password", sensitive: true, required: true },
      { key: "mount", get label() {
      return translateNow("source.pki.mount.path.a9700c999e");
    }, placeholder: "pki", defaultValue: "pki" },
      { key: "role", get label() {
      return translateNow("source.pki.role.name.ab27cf1159");
    }, placeholder: "web-certs", required: true },
    ],
  },
  {
    id: "DigiCert",
    name: "DigiCert CertCentral",
    get description() {
      return translateNow("source.digicert.certcentral.for.public.tls.certif.4231041928");
    },
    icon: "building",
    internal: false,
    configFields: [
      { key: "api_key", get label() {
      return translateNow("source.digicert.api.key.c19aab13d5");
    }, type: "password", sensitive: true, required: true },
      { key: "org_id", get label() {
      return translateNow("source.organization.id.1f46632263");
    }, placeholder: "12345", required: true },
      {
        key: "product_type",
        get label() {
      return translateNow("source.product.type.f123dc0e0e");
    },
        type: "select",
        options: ["ssl_basic", "ssl_plus", "ssl_wildcard", "ssl_ev_basic"],
        defaultValue: "ssl_basic",
      },
    ],
  },
  {
    id: "Sectigo",
    name: "Sectigo SCM",
    get description() {
      return translateNow("source.sectigo.certificate.manager.for.dv.ov.and.99478bb1bf");
    },
    icon: "lock",
    internal: false,
    configFields: [
      { key: "customer_uri", get label() {
      return translateNow("source.customer.uri.8360e5ff63");
    }, placeholder: "your-org-uri", required: true },
      { key: "login", get label() {
      return translateNow("source.api.login.05362c2cd2");
    }, placeholder: "api-account-name", required: true },
      { key: "password", get label() {
      return translateNow("source.api.password.32d247edf2");
    }, type: "password", sensitive: true, required: true },
    ],
  },
  {
    id: "GoogleCAS",
    name: "Google CAS",
    get description() {
      return translateNow("source.google.cloud.certificate.authority.service.a4a6180427");
    },
    icon: "cloud",
    internal: false,
    configFields: [
      { key: "project", get label() {
      return translateNow("source.gcp.project.id.11dc9b119c");
    }, placeholder: "platform-prod", required: true },
      { key: "location", get label() {
      return translateNow("source.location.15b61974b2");
    }, placeholder: "us-central1", required: true },
      { key: "ca_pool", get label() {
      return translateNow("source.ca.pool.4b4ad58567");
    }, placeholder: "prod-pool", required: true },
      { key: "credentials", get label() {
      return translateNow("source.service.account.json.b9f92e30b9");
    }, type: "password", sensitive: true, required: true },
    ],
  },
  {
    id: "AWSACMPCA",
    name: "AWS ACM Private CA",
    get description() {
      return translateNow("source.aws.certificate.manager.private.certificat.bc4fcbdf3e");
    },
    icon: "cloud",
    internal: false,
    configFields: [
      { key: "region", get label() {
      return translateNow("source.aws.region.7e489ee639");
    }, placeholder: "us-east-1", required: true },
      { key: "ca_arn", get label() {
      return translateNow("source.ca.arn.1017e7970e");
    }, placeholder: "arn:aws:acm-pca:...", required: true },
      {
        key: "signing_algorithm",
        get label() {
      return translateNow("source.signing.algorithm.fcb60f7f35");
    },
        type: "select",
        options: ["SHA256WITHRSA", "SHA384WITHRSA", "SHA256WITHECDSA"],
        defaultValue: "SHA256WITHRSA",
      },
    ],
  },
  {
    id: "Entrust",
    name: "Entrust",
    get description() {
      return translateNow("source.entrust.certificate.services.with.client.c.7b1583ae36");
    },
    icon: "server",
    internal: false,
    configFields: [
      { key: "api_url", get label() {
      return translateNow("source.api.url.ed650c75c5");
    }, placeholder: "https://api.managed.entrust.com/v1", required: true },
      { key: "client_cert_path", get label() {
      return translateNow("source.client.certificate.path.b28a72f649");
    }, placeholder: "/etc/trstctl/entrust.crt", required: true },
      { key: "client_key_path", get label() {
      return translateNow("source.client.key.path.c0fc7c99e3");
    }, type: "password", sensitive: true, required: true },
    ],
  },
  {
    id: "GlobalSign",
    name: "GlobalSign",
    get description() {
      return translateNow("source.globalsign.atlas.hvca.with.api.key.and.mtl.769ac13254");
    },
    icon: "globe",
    internal: false,
    configFields: [
      { key: "api_url", get label() {
      return translateNow("source.api.url.ed650c75c5");
    }, placeholder: "https://api.hvca.globalsign.com", required: true },
      { key: "api_key", get label() {
      return translateNow("source.api.key.23189d55f6");
    }, type: "password", sensitive: true, required: true },
      { key: "api_secret", get label() {
      return translateNow("source.api.secret.e2453eca0e");
    }, type: "password", sensitive: true, required: true },
    ],
  },
  {
    id: "EJBCA",
    name: "EJBCA",
    get description() {
      return translateNow("source.keyfactor.ejbca.with.mtls.or.oauth2.auth.c5b980825e");
    },
    icon: "key",
    internal: false,
    configFields: [
      { key: "api_url", get label() {
      return translateNow("source.api.url.ed650c75c5");
    }, placeholder: "https://ejbca.example.com/ejbca/ejbca-rest-api/v1", required: true },
      { key: "auth_mode", get label() {
      return translateNow("source.auth.mode.82aaf8d568");
    }, type: "select", options: ["mtls", "oauth2"], defaultValue: "mtls" },
      { key: "token", get label() {
      return translateNow("source.oauth2.token.23027fafb1");
    }, type: "password", sensitive: true },
      { key: "ca_name", get label() {
      return translateNow("source.ca.name.7f0892c4ef");
    }, placeholder: "Issuing CA", required: true },
    ],
  },
];

const sensitiveKeyParts = ["password", "secret", "token", "key", "hmac", "private"];

export function defaultIssuerConfigValues(type: IssuerTypeConfig): Record<string, string> {
  return Object.fromEntries(type.configFields.filter((field) => field.defaultValue !== undefined).map((field) => [field.key, field.defaultValue ?? ""]));
}

export function isSensitiveIssuerField(field: Pick<IssuerConfigField, "key" | "sensitive">): boolean {
  if (field.sensitive) return true;
  const key = field.key.toLowerCase();
  return sensitiveKeyParts.some((part) => key.includes(part));
}

export function splitPEMChain(value: string): string[] {
  return value
    .split(/(?=-----BEGIN CERTIFICATE-----)/)
    .map((part) => part.trim())
    .filter(Boolean);
}

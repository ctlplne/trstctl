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
    description: "Let's Encrypt, ZeroSSL, or another ACME-compatible CA.",
    icon: "globe",
    internal: false,
    configFields: [
      { key: "directory_url", label: "Directory URL", placeholder: "https://acme.example/directory", required: true },
      { key: "email", label: "Email", placeholder: "ops@example.test", required: true },
      { key: "challenge_type", label: "Challenge Type", type: "select", options: ["http-01", "dns-01", "dns-persist-01"], defaultValue: "http-01" },
      { key: "profile", label: "Certificate Profile", type: "select", options: ["", "tlsserver", "shortlived"], defaultValue: "" },
      { key: "eab_kid", label: "EAB Key ID", placeholder: "External account binding key id" },
      { key: "eab_hmac", label: "EAB HMAC Key", placeholder: "External account binding HMAC", type: "password", sensitive: true },
    ],
  },
  {
    id: "GenericCA",
    name: "Local CA",
    description: "Signer-backed internal authority managed by this control plane.",
    icon: "home",
    internal: true,
    configFields: [
      { key: "key_policy", label: "Key Policy", type: "select", options: ["managed-key", "ceremony-backed"], defaultValue: "managed-key" },
      { key: "max_path_len", label: "Max Path Length", type: "number", placeholder: "1" },
    ],
  },
  {
    id: "StepCA",
    name: "step-ca",
    description: "Smallstep private CA with provisioner-backed issuance.",
    icon: "key",
    internal: false,
    configFields: [
      { key: "ca_url", label: "CA URL", placeholder: "https://ca.example.com", required: true },
      { key: "provisioner_name", label: "Provisioner Name", placeholder: "ops-provisioner", required: true },
      { key: "provisioner_password", label: "Provisioner Password", type: "password", sensitive: true },
    ],
  },
  {
    id: "VaultPKI",
    name: "Vault PKI",
    description: "HashiCorp Vault PKI secrets engine.",
    icon: "lock",
    internal: false,
    configFields: [
      { key: "addr", label: "Vault Address", placeholder: "https://vault.internal:8200", required: true },
      { key: "token", label: "Vault Token", type: "password", sensitive: true, required: true },
      { key: "mount", label: "PKI Mount Path", placeholder: "pki", defaultValue: "pki" },
      { key: "role", label: "PKI Role Name", placeholder: "web-certs", required: true },
    ],
  },
  {
    id: "DigiCert",
    name: "DigiCert CertCentral",
    description: "DigiCert CertCentral for public TLS certificates.",
    icon: "building",
    internal: false,
    configFields: [
      { key: "api_key", label: "DigiCert API Key", type: "password", sensitive: true, required: true },
      { key: "org_id", label: "Organization ID", placeholder: "12345", required: true },
      {
        key: "product_type",
        label: "Product Type",
        type: "select",
        options: ["ssl_basic", "ssl_plus", "ssl_wildcard", "ssl_ev_basic"],
        defaultValue: "ssl_basic",
      },
    ],
  },
  {
    id: "Sectigo",
    name: "Sectigo SCM",
    description: "Sectigo Certificate Manager for DV, OV, and EV issuance.",
    icon: "lock",
    internal: false,
    configFields: [
      { key: "customer_uri", label: "Customer URI", placeholder: "your-org-uri", required: true },
      { key: "login", label: "API Login", placeholder: "api-account-name", required: true },
      { key: "password", label: "API Password", type: "password", sensitive: true, required: true },
    ],
  },
  {
    id: "GoogleCAS",
    name: "Google CAS",
    description: "Google Cloud Certificate Authority Service.",
    icon: "cloud",
    internal: false,
    configFields: [
      { key: "project", label: "GCP Project ID", placeholder: "platform-prod", required: true },
      { key: "location", label: "Location", placeholder: "us-central1", required: true },
      { key: "ca_pool", label: "CA Pool", placeholder: "prod-pool", required: true },
      { key: "credentials", label: "Service Account JSON", type: "password", sensitive: true, required: true },
    ],
  },
  {
    id: "AWSACMPCA",
    name: "AWS ACM Private CA",
    description: "AWS Certificate Manager Private Certificate Authority.",
    icon: "cloud",
    internal: false,
    configFields: [
      { key: "region", label: "AWS Region", placeholder: "us-east-1", required: true },
      { key: "ca_arn", label: "CA ARN", placeholder: "arn:aws:acm-pca:...", required: true },
      {
        key: "signing_algorithm",
        label: "Signing Algorithm",
        type: "select",
        options: ["SHA256WITHRSA", "SHA384WITHRSA", "SHA256WITHECDSA"],
        defaultValue: "SHA256WITHRSA",
      },
    ],
  },
  {
    id: "Entrust",
    name: "Entrust",
    description: "Entrust Certificate Services with client certificate auth.",
    icon: "server",
    internal: false,
    configFields: [
      { key: "api_url", label: "API URL", placeholder: "https://api.managed.entrust.com/v1", required: true },
      { key: "client_cert_path", label: "Client Certificate Path", placeholder: "/etc/trstctl/entrust.crt", required: true },
      { key: "client_key_path", label: "Client Key Path", type: "password", sensitive: true, required: true },
    ],
  },
  {
    id: "GlobalSign",
    name: "GlobalSign",
    description: "GlobalSign Atlas HVCA with API key and mTLS auth.",
    icon: "globe",
    internal: false,
    configFields: [
      { key: "api_url", label: "API URL", placeholder: "https://api.hvca.globalsign.com", required: true },
      { key: "api_key", label: "API Key", type: "password", sensitive: true, required: true },
      { key: "api_secret", label: "API Secret", type: "password", sensitive: true, required: true },
    ],
  },
  {
    id: "EJBCA",
    name: "EJBCA",
    description: "Keyfactor EJBCA with mTLS or OAuth2 auth.",
    icon: "key",
    internal: false,
    configFields: [
      { key: "api_url", label: "API URL", placeholder: "https://ejbca.example.com/ejbca/ejbca-rest-api/v1", required: true },
      { key: "auth_mode", label: "Auth Mode", type: "select", options: ["mtls", "oauth2"], defaultValue: "mtls" },
      { key: "token", label: "OAuth2 Token", type: "password", sensitive: true },
      { key: "ca_name", label: "CA Name", placeholder: "Issuing CA", required: true },
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

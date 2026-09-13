// Connector-aware starting points for the "Add destination" configuration.
//
// The dialog used to seed every connector with the same two-field example
// ({credential_ref, host}), which matches no served connector schema. A cold
// operator then had to discover the real keys from the docs table and, for an
// external CA, the host-custody keys the endpoint preview requires. Each
// template below mirrors the required target config fields the control plane
// validates (see docs/features/deployment-connectors.md) and, for host-executed
// families, the custody and verification keys the enrolled host agent honours.
// Values are placeholders an operator replaces; secret fields are references,
// never values.

const HOST_FILE_PATHS: Record<string, string> = {
  nginx: "/etc/nginx/tls",
  apache: "/etc/apache2/tls",
  caddy: "/etc/caddy/tls",
  traefik: "/etc/traefik/tls",
  postgresql: "/var/lib/postgresql/tls",
  mysql: "/etc/mysql/tls",
  rabbitmq: "/etc/rabbitmq/tls",
  elasticsearch: "/etc/elasticsearch/tls",
  tomcat: "/etc/tomcat/tls",
};

const hostVerification = {
  verify_address: "service.example.com:443",
  verify_server_name: "service.example.com",
};

const hostCustody = { executor: "agent", required_agent_role: "host" };

export function defaultTargetConfigObject(connector: string): Record<string, string> {
  const name = connector.trim().toLowerCase();
  const filePath = HOST_FILE_PATHS[name];
  if (filePath) {
    return {
      ...hostCustody,
      cert_path: `${filePath}/server.crt`,
      key_path: `${filePath}/server.key`,
      ...(name === "traefik" ? { config_path: "/etc/traefik/dynamic.yml" } : {}),
      ...hostVerification,
    };
  }
  switch (name) {
    case "haproxy":
      return { ...hostCustody, crt_path: "/etc/haproxy/tls/server.pem", config_path: "/etc/haproxy/haproxy.cfg", ...hostVerification };
    case "iis":
      return { ...hostCustody, binding: "*:443:service.example.com", import_dir: "C:/trstctl/import", store: "My", ...hostVerification };
    case "postfix":
      return {
        ...hostCustody,
        postfix_cert_path: "/etc/postfix/tls/server.crt",
        postfix_key_path: "/etc/postfix/tls/server.key",
        dovecot_cert_path: "/etc/dovecot/tls/server.crt",
        dovecot_key_path: "/etc/dovecot/tls/server.key",
      };
    case "java-keystore":
      return {
        ...hostCustody,
        keystore_path: "/etc/app/tls/keystore.p12",
        keystore_password_ref: "secret://connectors/keystore-password",
        alias: "server",
        format: "pkcs12",
        reload_action: "java-tls-reload",
        ...hostVerification,
      };
    case "envoy":
      return { endpoint: "http://127.0.0.1:9901", secret_name: "server_cert" };
    case "f5":
      return {
        endpoint: "https://bigip.example.com",
        client_ssl_profile: "clientssl-service",
        username: "trstctl",
        password_ref: "secret://connectors/f5-password",
      };
    case "netscaler":
    case "a10":
    case "cisco":
      return { endpoint: `https://${name}.example.com`, username: "trstctl", password_ref: `secret://connectors/${name}-password` };
    case "kemp":
    case "fortigate":
      return { endpoint: `https://${name}.example.com`, token_ref: `secret://connectors/${name}-token` };
    case "paloalto":
      return { endpoint: "https://panorama.example.com", api_key_ref: "secret://connectors/paloalto-api-key" };
    case "aws-acm":
      return {
        endpoint: "https://acm.us-east-1.amazonaws.com",
        region: "us-east-1",
        access_key_id: "AKIA...",
        secret_access_key_ref: "secret://connectors/aws-secret-access-key",
      };
    case "azure-keyvault":
      return { endpoint: "https://vault.vault.azure.net", bearer_token_ref: "secret://connectors/azure-bearer-token" };
    case "gcp-certificate-manager":
      return {
        endpoint: "https://certificatemanager.googleapis.com",
        project: "my-project",
        location: "global",
        bearer_token_ref: "secret://connectors/gcp-bearer-token",
      };
    default:
      return { credential_ref: `secret://connectors/${name || "connector"}`, host: "edge-1.internal" };
  }
}

export function defaultTargetConfig(connector: string): string {
  return JSON.stringify(defaultTargetConfigObject(connector), null, 2);
}

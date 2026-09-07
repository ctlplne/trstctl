import { describe, expect, it } from "vitest";

import { defaultTargetConfig, defaultTargetConfigObject } from "@/lib/connectorTargetTemplates";

const HOST_FAMILIES = [
  "nginx",
  "apache",
  "caddy",
  "traefik",
  "postgresql",
  "mysql",
  "rabbitmq",
  "elasticsearch",
  "tomcat",
  "haproxy",
  "iis",
  "postfix",
  "java-keystore",
];
const ALL = [
  ...HOST_FAMILIES,
  "envoy",
  "f5",
  "netscaler",
  "a10",
  "cisco",
  "kemp",
  "fortigate",
  "paloalto",
  "aws-acm",
  "azure-keyvault",
  "gcp-certificate-manager",
  "unknown-plugin",
];

describe("connector target templates", () => {
  it("emits valid JSON for every connector family", () => {
    for (const name of ALL) {
      const parsed = JSON.parse(defaultTargetConfig(name)) as Record<string, string>;
      expect(Object.keys(parsed).length).toBeGreaterThan(0);
      for (const value of Object.values(parsed)) expect(typeof value).toBe("string");
    }
  });

  it("seeds host-executed families with host key custody so an external CA can be used", () => {
    for (const name of HOST_FAMILIES) {
      const cfg = defaultTargetConfigObject(name);
      expect(cfg.executor).toBe("agent");
      expect(cfg.required_agent_role).toBe("host");
    }
    expect(defaultTargetConfigObject("apache")).toMatchObject({
      cert_path: "/etc/apache2/tls/server.crt",
      key_path: "/etc/apache2/tls/server.key",
      verify_server_name: "service.example.com",
    });
    expect(defaultTargetConfigObject("haproxy")).toMatchObject({ crt_path: "/etc/haproxy/tls/server.pem", config_path: "/etc/haproxy/haproxy.cfg" });
    expect(defaultTargetConfigObject("iis")).toMatchObject({ binding: "*:443:service.example.com", import_dir: "C:/trstctl/import" });
  });

  it("never seeds a secret value, only references", () => {
    for (const name of ALL) {
      for (const [key, value] of Object.entries(defaultTargetConfigObject(name))) {
        if (key.endsWith("_ref")) expect(value.startsWith("secret://")).toBe(true);
        expect(["password", "token", "api_key", "secret_access_key"]).not.toContain(key);
      }
    }
  });

  it("keeps control-plane-executed families on their documented fields", () => {
    expect(defaultTargetConfigObject("f5")).toMatchObject({ client_ssl_profile: "clientssl-service", password_ref: "secret://connectors/f5-password" });
    expect(defaultTargetConfigObject("aws-acm")).toMatchObject({ region: "us-east-1", secret_access_key_ref: "secret://connectors/aws-secret-access-key" });
    expect(defaultTargetConfigObject("f5").executor).toBeUndefined();
  });
});

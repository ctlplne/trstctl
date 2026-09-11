import * as fs from "node:fs";
import * as pulumi from "@pulumi/pulumi";

type ResourcePlan = {
  profileName: string;
  certificateCommonName: string;
  secretName: string;
};

const cfg = new pulumi.Config();
const endpoint = cfg.require("endpoint").replace(/\/+$/, "");
const plan: ResourcePlan = JSON.parse(fs.readFileSync(new URL("./trstctl.resources.json", import.meta.url), "utf8"));

async function trstctlPost(path: string, bearer: string, idempotencyKey: string, body: unknown): Promise<Record<string, unknown>> {
  const res = await fetch(endpoint + path, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${bearer}`,
      "Content-Type": "application/json",
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`trstctl ${path}: ${res.status} ${await res.text()}`);
  return (await res.json()) as Record<string, unknown>;
}

class ProfileResource extends pulumi.dynamic.Resource {
  constructor(name: string, args: { profileName: string }, opts?: pulumi.CustomResourceOptions) {
    super(new TrstctlProvider("/api/v1/profiles", (bearer) => ({
      name: args.profileName,
      version: 1,
      created_by: "pulumi",
      spec: { allowed_key_algorithms: ["ECDSA-P256"], max_validity: "1h" },
      bearer,
    })), name, args, opts);
  }
}

class PkiCertificateResource extends pulumi.dynamic.Resource {
  constructor(name: string, args: { commonName: string }, opts?: pulumi.CustomResourceOptions) {
    super(new TrstctlProvider("/api/v1/secrets/pki", (bearer) => ({
      common_name: args.commonName,
      ttl_seconds: 900,
      bearer,
    })), name, args, opts);
  }
}

class SecretResource extends pulumi.dynamic.Resource {
  constructor(name: string, args: { secretName: string }, opts?: pulumi.CustomResourceOptions) {
    super(new TrstctlProvider("/api/v1/secrets/store", (bearer) => ({
      name: args.secretName,
      plaintext: "replace-me-from-ci-secret",
      bearer,
    })), name, args, opts);
  }
}

class TrstctlProvider implements pulumi.dynamic.ResourceProvider {
  private bearer?: string;

  constructor(
    private readonly path: string,
    private readonly body: (bearer: string) => Record<string, unknown>,
  ) {}

  async configure(request: pulumi.dynamic.ConfigureRequest): Promise<void> {
    // Resolve provider configuration in the provider process. Capturing an
    // Output and calling its private promise API cannot resolve it here.
    this.bearer = request.config.require("token");
  }

  async create(inputs: pulumi.Inputs): Promise<pulumi.dynamic.CreateResult> {
    const bearer = this.bearer;
    if (!bearer) throw new Error("trstctl provider requires configured token");
    const idempotencyKey = `pulumi-${this.path.replaceAll("/", "-")}-${inputs.name ?? "resource"}`;
    const body = this.body(String(bearer));
    delete body.bearer;
    const out = await trstctlPost(this.path, String(bearer), idempotencyKey, body);
    return { id: String(out.id ?? idempotencyKey), outs: { ...inputs, result: out } };
  }
}

const profile = new ProfileResource("web-server-profile", { profileName: plan.profileName });
const cert = new PkiCertificateResource("deploy-hook-certificate", { commonName: plan.certificateCommonName }, { dependsOn: profile });
const secret = new SecretResource("deploy-hook-secret", { secretName: plan.secretName }, { dependsOn: profile });

export const profileName = plan.profileName;
export const certificateCommonName = plan.certificateCommonName;
export const secretName = plan.secretName;
export const resourceIds = [profile.id, cert.id, secret.id];

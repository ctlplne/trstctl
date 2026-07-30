import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { AppQueryProvider } from "@/lib/query";
import { SecretSyncWorkloadIdentityPanel } from "@/pages/secrets/SecretSyncWorkloadIdentityPanel";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    secretSyncWorkloadIdentitySources: vi.fn(),
    workloadAttesterTrustSources: vi.fn(),
    secretSyncTargets: vi.fn(),
    createSecretSyncWorkloadIdentitySource: vi.fn(),
    updateSecretSyncWorkloadIdentitySource: vi.fn(),
    deleteSecretSyncWorkloadIdentitySource: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const source = {
  id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  tenant_id: "11111111-1111-4111-8111-111111111111",
  name: "Payments delivery",
  provider: "aws" as const,
  role_arn: "arn:aws:iam::123456789012:role/payments-sync",
  service_account: "",
  azure_tenant_id: "",
  client_id: "",
  target_scope: "",
  audience: "trstctl-secrets",
  subject: "system:serviceaccount:security:trstctl",
  target_id: "aws-secretsmanager-primary",
  allowed_remote_key_prefixes: ["payments/"],
  workload_proof_ref: "secret://sync/aws-proof",
  trust_source_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  enabled: true,
  status: "active" as const,
  status_reason: "credential exchanged by outbox worker",
  token_expires_at: "2026-07-28T12:00:00Z",
  created_at: "2026-07-28T10:00:00Z",
  updated_at: "2026-07-28T10:01:00Z",
};

function renderPanel() {
  return render(
    <AppQueryProvider>
      <SecretSyncWorkloadIdentityPanel />
    </AppQueryProvider>,
  );
}

async function completeWizard(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Source name"), "Edge delivery");
  await user.type(screen.getByLabelText("AWS role ARN"), "arn:aws:iam::123456789012:role/edge-sync");
  await user.type(screen.getByLabelText("Token audience"), "trstctl-secrets");
  await user.type(screen.getByLabelText("Token subject"), "system:serviceaccount:security:edge");
  await user.click(screen.getByRole("button", { name: "Next" }));
  await user.selectOptions(screen.getByLabelText("Cloud sync target"), "aws-secretsmanager-primary");
  await user.type(screen.getByLabelText("Allowed remote-key prefixes"), "edge/\nshared/");
  await user.click(screen.getByRole("button", { name: "Next" }));
  await user.type(screen.getByLabelText("Workload proof reference"), "secret://sync/edge-proof");
  await user.selectOptions(screen.getByLabelText("JWT trust source"), "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
}

describe("AWS workload identity secret sync", () => {
  beforeEach(() => {
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.secretSyncWorkloadIdentitySources.mockResolvedValue({ items: [source], next_cursor: "" });
    apiMock.workloadAttesterTrustSources.mockResolvedValue({
      items: [
        {
          id: source.trust_source_id,
          tenant_id: source.tenant_id,
          name: "Cluster OIDC",
          method: "k8s_sat",
          issuer: "https://issuer.example.test",
          audience: source.audience,
          jwks: { keys: [] },
          root_certs_pem: [],
          enabled: true,
          rotation_version: 1,
          created_at: source.created_at,
          updated_at: source.updated_at,
        },
      ],
      next_cursor: "",
    });
    apiMock.secretSyncTargets.mockResolvedValue({
      capability: "secret_sync",
      configured_targets: [source.target_id],
      evidence_refs: [],
      generated_at: source.updated_at,
      outbox_mode: "durable",
      residuals: [],
      served: true,
      targets: [
        {
          id: source.target_id,
          name: "AWS Secrets Manager primary",
          platform: "AWS Secrets Manager",
          configured: true,
          capabilities: ["write"],
          auth_mode: "workload_identity",
          delivery_mode: "outbox",
          secret_handling: "byte-native",
          wire_format: "aws-json",
        },
        {
          id: "gcp-secretmanager-primary",
          name: "GCP Secret Manager primary",
          platform: "GCP Secret Manager",
          configured: true,
          capabilities: ["write"],
          auth_mode: "workload_identity",
          delivery_mode: "outbox",
          secret_handling: "byte-native",
          wire_format: "gcp-json",
        },
        {
          id: "azure-keyvault-primary",
          name: "Azure Key Vault primary",
          platform: "Azure Key Vault",
          configured: true,
          capabilities: ["write"],
          auth_mode: "workload_identity",
          delivery_mode: "outbox",
          secret_handling: "byte-native",
          wire_format: "azure-json",
        },
      ],
    });
    apiMock.createSecretSyncWorkloadIdentitySource.mockResolvedValue(source);
    apiMock.updateSecretSyncWorkloadIdentitySource.mockResolvedValue(source);
    apiMock.deleteSecretSyncWorkloadIdentitySource.mockResolvedValue(undefined);
  });

  it("renders the served source status and has no automated accessibility violations", async () => {
    const { container } = renderPanel();
    expect(await screen.findByText("Payments delivery")).toBeInTheDocument();
    expect(screen.getByText("credential exchanged by outbox worker")).toBeInTheDocument();
    expect(screen.getByText(/bounded outbox worker delivers a secret/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("keeps the empty list and create form below the workload-identity panel heading", async () => {
    apiMock.secretSyncWorkloadIdentitySources.mockResolvedValue({ items: [], next_cursor: "" });
    const { container } = renderPanel();

    expect(await screen.findByRole("heading", { level: 3, name: "Cloud workload identity federation" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { level: 4, name: "No workload identities configured" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 4, name: "Add cloud workload identity" })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("creates an explicitly configured source through the three-step workflow", async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByText("Payments delivery");
    await completeWizard(user);
    await user.click(screen.getByRole("button", { name: "Save source" }));
    await waitFor(() =>
      expect(apiMock.createSecretSyncWorkloadIdentitySource).toHaveBeenCalledWith({
        name: "Edge delivery",
        provider: "aws",
        role_arn: "arn:aws:iam::123456789012:role/edge-sync",
        audience: "trstctl-secrets",
        subject: "system:serviceaccount:security:edge",
        target_id: "aws-secretsmanager-primary",
        allowed_remote_key_prefixes: ["edge/", "shared/"],
        workload_proof_ref: "secret://sync/edge-proof",
        trust_source_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        enabled: true,
      }),
    );
  });

  it("shows a mutation failure instead of pretending the source was saved", async () => {
    apiMock.createSecretSyncWorkloadIdentitySource.mockRejectedValue(new Error("AWS workload identity exchange policy rejected the source"));
    const user = userEvent.setup();
    renderPanel();
    await screen.findByText("Payments delivery");
    await completeWizard(user);
    await user.click(screen.getByRole("button", { name: "Save source" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("AWS workload identity exchange policy rejected the source");
  });

  it("creates a GCP RFC 8693 source with optional service-account impersonation", async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByText("Payments delivery");
    await user.type(screen.getByLabelText("Source name"), "GCP delivery");
    await user.selectOptions(screen.getByLabelText("Cloud provider"), "gcp");
    await user.type(screen.getByLabelText("GCP service account (optional)"), "sync@example.iam.gserviceaccount.com");
    await user.type(screen.getByLabelText("Token audience"), "trstctl-secrets");
    await user.type(screen.getByLabelText("Token subject"), "system:serviceaccount:security:gcp");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.selectOptions(screen.getByLabelText("Cloud sync target"), "gcp-secretmanager-primary");
    await user.type(screen.getByLabelText("Allowed remote-key prefixes"), "gcp/");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.type(screen.getByLabelText("Workload proof reference"), "secret://sync/gcp-proof");
    await user.selectOptions(screen.getByLabelText("JWT trust source"), "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    await user.click(screen.getByRole("button", { name: "Save source" }));
    await waitFor(() =>
      expect(apiMock.createSecretSyncWorkloadIdentitySource).toHaveBeenCalledWith({
        name: "GCP delivery",
        provider: "gcp",
        role_arn: "",
        service_account: "sync@example.iam.gserviceaccount.com",
        audience: "trstctl-secrets",
        subject: "system:serviceaccount:security:gcp",
        target_id: "gcp-secretmanager-primary",
        allowed_remote_key_prefixes: ["gcp/"],
        workload_proof_ref: "secret://sync/gcp-proof",
        trust_source_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        enabled: true,
      }),
    );
  });

  it("creates an Azure federated-credential source without certificate custody", async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByText("Payments delivery");
    await user.type(screen.getByLabelText("Source name"), "Azure delivery");
    await user.selectOptions(screen.getByLabelText("Cloud provider"), "azure");
    await user.type(screen.getByLabelText("Entra tenant ID"), "33333333-3333-4333-8333-333333333333");
    await user.type(screen.getByLabelText("Entra application client ID"), "44444444-4444-4444-8444-444444444444");
    expect(screen.getByLabelText("Azure Key Vault scope")).toHaveValue("https://vault.azure.net/.default");
    await user.type(screen.getByLabelText("Token audience"), "trstctl-secrets");
    await user.type(screen.getByLabelText("Token subject"), "system:serviceaccount:security:azure");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.selectOptions(screen.getByLabelText("Cloud sync target"), "azure-keyvault-primary");
    await user.type(screen.getByLabelText("Allowed remote-key prefixes"), "azure/");
    await user.click(screen.getByRole("button", { name: "Next" }));
    await user.type(screen.getByLabelText("Workload proof reference"), "secret://sync/azure-proof");
    await user.selectOptions(screen.getByLabelText("JWT trust source"), "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    await user.click(screen.getByRole("button", { name: "Save source" }));
    await waitFor(() =>
      expect(apiMock.createSecretSyncWorkloadIdentitySource).toHaveBeenCalledWith({
        name: "Azure delivery",
        provider: "azure",
        role_arn: "",
        azure_tenant_id: "33333333-3333-4333-8333-333333333333",
        client_id: "44444444-4444-4444-8444-444444444444",
        target_scope: "https://vault.azure.net/.default",
        audience: "trstctl-secrets",
        subject: "system:serviceaccount:security:azure",
        target_id: "azure-keyvault-primary",
        allowed_remote_key_prefixes: ["azure/"],
        workload_proof_ref: "secret://sync/azure-proof",
        trust_source_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        enabled: true,
      }),
    );
  });
});

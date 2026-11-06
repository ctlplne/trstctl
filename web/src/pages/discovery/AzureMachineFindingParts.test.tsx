import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { DiscoveryFinding } from "@/lib/api";
import { AzureMachineFindingParts } from "./AzureMachineFindingParts";
describe("Azure captured workload evidence", () => {
  it("shows public credential dates, conditional policy and explicit unknown use", () => {
    const finding = {
      kind: "azure_machine_identity",
      metadata: {
        version: 1,
        provider: "azure-entra",
        azure_tenant_id: "owned-tenant",
        subscription_id: "owned-subscription",
        collected_at: "2026-11-06T00:00:00Z",
        identity: {
          id: "owned-principal",
          appId: "owned-app",
          displayName: "Orders worker",
          servicePrincipalType: "Application",
          accountEnabled: true,
          keyCredentials: null,
          passwordCredentials: [
            {
              keyId: "owned-key",
              startDateTime: "2026-01-01T00:00:00Z",
              endDateTime: "2027-01-01T00:00:00Z",
              kind: "client_secret",
              long_lived: true,
              last_use_coverage: "unavailable",
            },
          ],
        },
        app_role_coverage: "selected_principal_assignments_only",
        federation_coverage: "unavailable",
        rbac_coverage: "subscription_principal_filter_only",
        managed_identity_coverage: "not_applicable",
        activity_coverage: "unavailable",
        app_roles: [
          { id: "binding", resourceId: "owned-resource", appRoleId: "owned-role", value: "Orders.Read", definition_coverage: "resource_app_role_definition" },
        ],
        rbac: [
          {
            id: "assignment",
            properties: { scope: "owned-scope", roleDefinitionId: "reader-role", condition: "orders-condition", conditionVersion: "2.0" },
            permissions: [{ actions: ["read"], notActions: ["listKeys"], dataActions: ["blobs/read"], notDataActions: [] }],
            definition_coverage: "role_definition_only",
          },
        ],
        federation: [{ id: "federation", issuer: "https://issuer.example.test", subject: "orders-worker", audiences: ["api://AzureADTokenExchange"] }],
        limitations: ["Effective access is unknown."],
      },
    } as unknown as DiscoveryFinding;
    render(<AzureMachineFindingParts finding={finding} />);
    expect(screen.getByText("Orders.Read")).toBeInTheDocument();
    expect(screen.getByText(/Credential last use is unknown/)).toBeInTheDocument();
    expect(screen.getByText(/orders-condition/)).toBeInTheDocument();
    expect(screen.getByText(/listKeys/)).toBeInTheDocument();
    expect(screen.getByText("Effective access is unknown.")).toBeInTheDocument();
  });
  it("refuses unsupported evidence versions", () => {
    render(<AzureMachineFindingParts finding={{ kind: "azure_machine_identity", metadata: { version: 99 } } as unknown as DiscoveryFinding} />);
    expect(screen.getByText("Captured Azure evidence unavailable")).toBeInTheDocument();
  });
});

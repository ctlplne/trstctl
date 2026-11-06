import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import type { DiscoveryFinding } from "@/lib/api";
import { GCPMachineFindingParts } from "./GCPMachineFindingParts";
describe("captured GCP evidence", () => {
  it("keeps unobserved use unknown and conditional bindings separate from effective access", () => {
    const finding = {
      kind: "gcp_machine_identity",
      metadata: {
        version: 1,
        provider: "gcp-iam",
        collected_at: "2026-11-06T00:00:00Z",
        identity: { email: "orders@owned-project.iam.gserviceaccount.com", uniqueId: "123456789012345678901", projectId: "owned-project", disabled: false },
        keys_coverage: "complete_selected_account_user_managed",
        trust_coverage: "complete_account_policy_only",
        policy_coverage: "project_policy_only",
        activity_coverage: "observed_only",
        keys: [
          {
            name: "projects/owned-project/serviceAccounts/orders/keys/owned",
            validAfterTime: "2020-01-01T00:00:00Z",
            validBeforeTime: "2030-01-01T00:00:00Z",
            disabled: false,
            long_lived: true,
            last_use_coverage: "observed_only",
          },
        ],
        policy_bindings: [
          {
            role: "roles/storage.objectViewer",
            scope: "projects/owned-project",
            condition: { expression: "resource.name.startsWith('projects/_/buckets/owned/')" },
            permissions: ["storage.objects.get"],
            permission_coverage: "role_definition_only",
          },
        ],
        trust_policy: { bindings: [] },
        limitations: ["Inherited policies are not evaluated."],
      },
    } as unknown as DiscoveryFinding;
    render(<GCPMachineFindingParts finding={finding} />);
    expect(screen.getByText(/actual last use remains unknown/)).toBeInTheDocument();
    expect(screen.getByText(/effective access is not evaluated/)).toBeInTheDocument();
    expect(screen.getByText(/resource.name.startsWith/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Revoke|Replace/ })).not.toBeInTheDocument();
  });
  it("requests fresh evidence when the typed capture cannot be read", () => {
    render(<GCPMachineFindingParts finding={{ kind: "gcp_machine_identity", metadata: { version: 99 } } as unknown as DiscoveryFinding} />);
    expect(screen.getByText(/Capture this native source again/)).toBeInTheDocument();
  });
});

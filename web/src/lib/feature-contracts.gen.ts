// Code generated from internal/featureparity/feature-map-backlog.json by
// web/scripts/gen-feature-contracts.mjs. DO NOT EDIT by hand.
// Regenerate with: npm run gen:feature-contracts

export const canonicalTools = ["discover","certificates","workloads_machines","secrets","software_trust","operations","platform_integrations"] as const;
export const capabilityMaturities = ["absent","api_cli_only","observe_only","partial_workflow","complete_vertical_slice"] as const;
export const capabilityStageNames = ["discover","understand","configure","preview","execute","observe","recover","verify","automate"] as const;
export const capabilityStageStatuses = ["complete","not_applicable","intentional_api_only","blocked","missing"] as const;
export const canonicalCapabilityIDs = ["F1","F2","F3","F42","F49","F35","F36","F17","F18","F19","F52","F4","F48","F53","F46","F47","F26","F5","F69","F70","F71","F72","F73","F74","F22","F23","F55","F54","F56","F24","F25","F30","F59","F61","F43","F44","F45","F6","F16","F57","F7","F27","F50","F51","F31","F32","F33","F34","F37","F38","F39","F63","F64","F65","F66","F67","F68","F58","F60","F28","F29","F62","F8","F9","F10","F11","F12","F13","F14","F15","F40","F41","F20","F21","F75","F76","F77","F78","F79"] as const;

export type CanonicalTool = (typeof canonicalTools)[number];
export type CapabilityMaturity = (typeof capabilityMaturities)[number];
export type CapabilityStageName = (typeof capabilityStageNames)[number];
export type CapabilityStageStatus = (typeof capabilityStageStatuses)[number];
export type CanonicalCapabilityID = (typeof canonicalCapabilityIDs)[number];

export interface CapabilityStage {
  readonly status: CapabilityStageStatus;
  readonly reason?: string;
  readonly evidence?: readonly string[];
}

export interface CanonicalCapability {
  readonly featureId: CanonicalCapabilityID;
  readonly feature: string;
  readonly domain: string;
  readonly phase: string;
  readonly priority: number;
  readonly contract: {
    readonly purpose: string;
    readonly tool: CanonicalTool;
    readonly classification: "primary" | "supporting";
    readonly releaseBlocking: boolean;
    readonly consoleRoute: string;
    readonly navigationEntrypoints: readonly string[];
    readonly permissionAuthority: string;
    readonly edition: string;
    readonly dependencies: readonly string[];
    readonly sideEffects: "read_only" | "mutating" | "mixed";
    readonly secretDataHandling: string;
    readonly maturity: CapabilityMaturity;
    readonly stages: Readonly<Record<CapabilityStageName, CapabilityStage>>;
    readonly owner: string;
    readonly targetCheckpoint: string;
    readonly candidateSHA: string;
    readonly freshness: string;
  };
}

export const canonicalCapabilities = [
  {
    "featureId": "F1",
    "feature": "Certificate inventory",
    "domain": "Discovery and inventory",
    "phase": "P0",
    "priority": 1,
    "contract": {
      "purpose": "Lets an operator understand and safely use certificate inventory while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/certificates",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/certificates"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "read_only",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "not_applicable",
          "reason": "This is an evidence or inventory workflow; configuration is owned by the originating capability."
        },
        "preview": {
          "status": "not_applicable",
          "reason": "This read-only workflow has no external effect to preview."
        },
        "execute": {
          "status": "not_applicable",
          "reason": "This workflow reads tenant-scoped state and performs no product mutation."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "not_applicable",
          "reason": "A read-only view cannot leave an external effect that requires rollback."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/discovery_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: ingestCertificate",
            "OpenAPI operationId: listCertificates",
            "OpenAPI operationId: getCertificateHealth",
            "OpenAPI operationId: getCertificate",
            "CLI command: certificates ingest",
            "CLI command: certificates list",
            "CLI command: certificates health",
            "CLI command: certificates get"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "maintain",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F2",
    "feature": "Network discovery",
    "domain": "Discovery and inventory",
    "phase": "P2",
    "priority": 44,
    "contract": {
      "purpose": "Lets an operator understand and safely use network discovery while tenant, policy, and security authority remain on the server.",
      "tool": "discover",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/discovery",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/discovery"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx",
            "internal/server/discovery_served_test.go"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx",
            "internal/server/discovery_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: retryDiscoveryRun",
            "CLI command: discovery runs retry",
            "internal/server/discovery_recovery_served_test.go",
            "web/src/pages/Discovery.tsx",
            "web/src/__tests__/discovery.test.tsx"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/discovery_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: claimDiscoveryFinding",
            "OpenAPI operationId: createDiscoverySchedule",
            "OpenAPI operationId: createDiscoverySegment",
            "OpenAPI operationId: createDiscoverySource",
            "OpenAPI operationId: dismissDiscoveryFinding",
            "OpenAPI operationId: getADCSPosture",
            "OpenAPI operationId: getADCSTemplateDrift",
            "OpenAPI operationId: getDiscoveryCoverage",
            "OpenAPI operationId: getDiscoveryMonitoring",
            "OpenAPI operationId: getDiscoveryRun",
            "OpenAPI operationId: ingestADCSDatabase",
            "OpenAPI operationId: listADCSDatabases",
            "OpenAPI operationId: listCertificates",
            "OpenAPI operationId: listDiscoveryFindings",
            "OpenAPI operationId: listDiscoveryCapabilities",
            "OpenAPI operationId: previewDiscoveryPlan",
            "OpenAPI operationId: preflightDiscoverySource",
            "OpenAPI operationId: listDiscoveryRuns",
            "OpenAPI operationId: listDiscoverySchedules",
            "OpenAPI operationId: listDiscoverySources",
            "OpenAPI operationId: retryDiscoveryRun",
            "OpenAPI operationId: startDiscoveryRun",
            "CLI command: discovery segments create",
            "CLI command: discovery capabilities",
            "CLI command: discovery plans preview",
            "CLI command: discovery sources create",
            "CLI command: discovery sources list",
            "CLI command: discovery sources preflight",
            "CLI command: discovery schedules create",
            "CLI command: discovery schedules list",
            "CLI command: discovery runs start",
            "CLI command: discovery runs list",
            "CLI command: discovery runs get",
            "CLI command: discovery runs retry",
            "CLI command: discovery monitoring",
            "CLI command: discovery coverage",
            "CLI command: discovery findings list",
            "CLI command: certificates list",
            "CLI command: discovery findings claim",
            "CLI command: discovery findings dismiss",
            "CLI command: adcs ca-database ingest",
            "CLI command: adcs ca-database list"
          ]
        }
      },
      "owner": "discovery",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F3",
    "feature": "Agent-based discovery",
    "domain": "Discovery and inventory",
    "phase": "P1",
    "priority": 20,
    "contract": {
      "purpose": "Lets an operator understand and safely use agent-based discovery while tenant, policy, and security authority remain on the server.",
      "tool": "discover",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/agents",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/agents"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Wizard.tsx",
            "web/src/pages/Agents.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: previewEnrollmentToken",
            "internal/projections/agents_api_test.go",
            "web/src/pages/Agents.tsx",
            "web/src/__tests__/agents.test.tsx"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createEnrollmentToken",
            "web/src/pages/Agents.tsx",
            "web/src/__tests__/agents.test.tsx",
            "internal/server/agentchannel_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: revokeAgentCertificate",
            "OpenAPI operationId: offboardAgent",
            "web/src/pages/Agents.tsx",
            "web/src/__tests__/agents.test.tsx"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/agentchannel_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listAgents",
            "OpenAPI operationId: previewEnrollmentToken",
            "OpenAPI operationId: createEnrollmentToken",
            "OpenAPI operationId: revokeAgentCertificate",
            "OpenAPI operationId: offboardAgent",
            "OpenAPI operationId: listDiscoveryFindings",
            "OpenAPI operationId: getGraph",
            "OpenAPI operationId: getAgentJobPosture",
            "CLI command: agents list",
            "CLI command: agents enroll-token-preview",
            "CLI command: agents enroll-token",
            "CLI command: agents revoke-cert",
            "CLI command: agents offboard",
            "CLI command: discovery findings list",
            "CLI command: graph nodes"
          ]
        }
      },
      "owner": "discovery",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "e3fc8229ecfcf4ba2fe7e0e0727d5f17682669b8",
      "freshness": "2026-08-27"
    }
  },
  {
    "featureId": "F42",
    "feature": "SSH credential discovery and inventory",
    "domain": "Discovery and inventory",
    "phase": "P2",
    "priority": 45,
    "contract": {
      "purpose": "Lets an operator understand and safely use ssh credential discovery and inventory while tenant, policy, and security authority remain on the server.",
      "tool": "discover",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/discovery",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/discovery"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/discovery/SourceSetup.tsx",
            "internal/server/discovery_recovery_served_test.go"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx",
            "internal/server/discovery_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: retryDiscoveryRun",
            "CLI command: discovery runs retry",
            "internal/server/discovery_recovery_served_test.go",
            "web/src/pages/Discovery.tsx",
            "web/src/__tests__/discovery.test.tsx"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/discovery_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createDiscoverySchedule",
            "OpenAPI operationId: createDiscoverySource",
            "OpenAPI operationId: getDiscoveryRun",
            "OpenAPI operationId: getSSHFleet",
            "OpenAPI operationId: listDiscoveryFindings",
            "OpenAPI operationId: listDiscoveryRuns",
            "OpenAPI operationId: listDiscoverySchedules",
            "OpenAPI operationId: listDiscoverySources",
            "OpenAPI operationId: startDiscoveryRun",
            "CLI command: discovery findings list",
            "CLI command: discovery runs get",
            "CLI command: discovery runs list",
            "CLI command: discovery runs start",
            "CLI command: discovery schedules create",
            "CLI command: discovery schedules list",
            "CLI command: discovery sources create",
            "CLI command: discovery sources list",
            "CLI command: ssh fleet"
          ]
        }
      },
      "owner": "discovery",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F49",
    "feature": "Agentless cloud certificate discovery",
    "domain": "Discovery and inventory",
    "phase": "P2",
    "priority": 46,
    "contract": {
      "purpose": "Lets an operator understand and safely use agentless cloud certificate discovery while tenant, policy, and security authority remain on the server.",
      "tool": "discover",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/discovery",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/discovery"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx",
            "internal/server/discovery_served_test.go"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx",
            "internal/server/discovery_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: retryDiscoveryRun",
            "CLI command: discovery runs retry",
            "internal/server/discovery_recovery_served_test.go",
            "web/src/pages/Discovery.tsx",
            "web/src/__tests__/discovery.test.tsx"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/discovery_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createDiscoverySource",
            "OpenAPI operationId: listDiscoverySources",
            "OpenAPI operationId: createDiscoverySchedule",
            "OpenAPI operationId: listDiscoverySchedules",
            "OpenAPI operationId: startDiscoveryRun",
            "OpenAPI operationId: listDiscoveryRuns",
            "OpenAPI operationId: getDiscoveryRun",
            "OpenAPI operationId: listDiscoveryFindings",
            "CLI command: discovery sources create",
            "CLI command: discovery sources list",
            "CLI command: discovery schedules create",
            "CLI command: discovery schedules list",
            "CLI command: discovery runs start",
            "CLI command: discovery runs list",
            "CLI command: discovery runs get",
            "CLI command: discovery findings list"
          ]
        }
      },
      "owner": "discovery",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F35",
    "feature": "Secret store discovery",
    "domain": "Discovery and inventory",
    "phase": "P2",
    "priority": 47,
    "contract": {
      "purpose": "Lets an operator understand and safely use secret store discovery while tenant, policy, and security authority remain on the server.",
      "tool": "discover",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/discovery",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/discovery"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/discovery/SourceSetup.tsx",
            "web/src/__tests__/discovery.test.tsx",
            "internal/server/discovery_recovery_served_test.go"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx",
            "internal/discovery/cloudsecret/vaultkv/vaultkv_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: retryDiscoveryRun",
            "CLI command: discovery runs retry",
            "internal/server/discovery_recovery_served_test.go",
            "web/src/pages/Discovery.tsx",
            "web/src/__tests__/discovery.test.tsx"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/discovery_served_test.go",
            "internal/server/secrets_sync_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createDiscoverySource",
            "OpenAPI operationId: listDiscoverySources",
            "OpenAPI operationId: createDiscoverySchedule",
            "OpenAPI operationId: listDiscoverySchedules",
            "OpenAPI operationId: startDiscoveryRun",
            "OpenAPI operationId: listDiscoveryRuns",
            "OpenAPI operationId: getDiscoveryRun",
            "OpenAPI operationId: listDiscoveryFindings",
            "CLI command: discovery sources create",
            "CLI command: discovery sources list",
            "CLI command: discovery schedules create",
            "CLI command: discovery schedules list",
            "CLI command: discovery runs start",
            "CLI command: discovery runs list",
            "CLI command: discovery runs get",
            "CLI command: discovery findings list"
          ]
        }
      },
      "owner": "discovery",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F36",
    "feature": "API key / token inventory",
    "domain": "Discovery and inventory",
    "phase": "P2",
    "priority": 48,
    "contract": {
      "purpose": "Lets an operator understand and safely use api key / token inventory while tenant, policy, and security authority remain on the server.",
      "tool": "discover",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/discovery",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/discovery"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx",
            "web/src/__tests__/discovery.test.tsx",
            "internal/server/discovery_recovery_served_test.go"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx",
            "internal/api/discovery_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: retryDiscoveryRun",
            "CLI command: discovery runs retry",
            "internal/server/discovery_recovery_served_test.go",
            "web/src/pages/Discovery.tsx",
            "web/src/__tests__/discovery.test.tsx"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/discovery_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createDiscoverySource",
            "OpenAPI operationId: listDiscoverySources",
            "OpenAPI operationId: createDiscoverySchedule",
            "OpenAPI operationId: listDiscoverySchedules",
            "OpenAPI operationId: startDiscoveryRun",
            "OpenAPI operationId: listDiscoveryRuns",
            "OpenAPI operationId: getDiscoveryRun",
            "OpenAPI operationId: listDiscoveryFindings",
            "OpenAPI operationId: listAPITokens",
            "OpenAPI operationId: createAPIToken",
            "OpenAPI operationId: revokeAPIToken",
            "CLI command: discovery sources create",
            "CLI command: discovery sources list",
            "CLI command: discovery schedules create",
            "CLI command: discovery schedules list",
            "CLI command: discovery runs start",
            "CLI command: discovery runs list",
            "CLI command: discovery runs get",
            "CLI command: discovery findings list",
            "CLI command: access tokens list",
            "CLI command: access tokens create",
            "CLI command: access tokens revoke"
          ]
        }
      },
      "owner": "discovery",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F17",
    "feature": "Certificate Transparency monitoring",
    "domain": "Observability and risk",
    "phase": "P2",
    "priority": 49,
    "contract": {
      "purpose": "Lets an operator understand and safely use certificate transparency monitoring while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/posture",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/posture"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx",
            "web/src/pages/Posture.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/ct_drift_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/ct_drift_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createDiscoverySource",
            "OpenAPI operationId: listDiscoverySources",
            "OpenAPI operationId: createDiscoverySchedule",
            "OpenAPI operationId: listDiscoverySchedules",
            "OpenAPI operationId: startDiscoveryRun",
            "OpenAPI operationId: listDiscoveryRuns",
            "OpenAPI operationId: getDiscoveryRun",
            "OpenAPI operationId: listDiscoveryFindings",
            "OpenAPI operationId: getCTMonitoring",
            "OpenAPI operationId: updateCTMonitoring",
            "CLI command: discovery sources create",
            "CLI command: discovery sources list",
            "CLI command: discovery schedules create",
            "CLI command: discovery schedules list",
            "CLI command: discovery runs start",
            "CLI command: discovery runs list",
            "CLI command: discovery runs get",
            "CLI command: discovery findings list",
            "CLI command: discovery ct-monitoring get",
            "CLI command: discovery ct-monitoring update"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F18",
    "feature": "Drift detection",
    "domain": "Observability and risk",
    "phase": "P2",
    "priority": 50,
    "contract": {
      "purpose": "Lets an operator understand and safely use drift detection while tenant, policy, and security authority remain on the server.",
      "tool": "discover",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/posture",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/posture"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Discovery.tsx",
            "web/src/pages/Posture.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: previewDiscoveryPlan",
            "OpenAPI operationId: preflightDiscoverySource",
            "internal/discovery/driftplan/plan.go",
            "internal/server/ct_drift_served_test.go",
            "web/src/pages/posture/DriftRecoveryWorkflow.tsx"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/ct_drift_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: retryDiscoveryRun",
            "CLI command: discovery runs retry",
            "internal/server/discovery_recovery_served_test.go",
            "web/src/pages/posture/DriftRecoveryWorkflow.tsx",
            "web/src/__tests__/posture.test.tsx"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/ct_drift_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createDiscoverySource",
            "OpenAPI operationId: listDiscoverySources",
            "OpenAPI operationId: createDiscoverySchedule",
            "OpenAPI operationId: listDiscoverySchedules",
            "OpenAPI operationId: startDiscoveryRun",
            "OpenAPI operationId: listDiscoveryRuns",
            "OpenAPI operationId: getDiscoveryRun",
            "OpenAPI operationId: listDiscoveryFindings",
            "OpenAPI operationId: previewDiscoveryPlan",
            "OpenAPI operationId: preflightDiscoverySource",
            "OpenAPI operationId: retryDiscoveryRun",
            "OpenAPI operationId: getDriftRemediation",
            "OpenAPI operationId: decideDriftRemediation",
            "CLI command: discovery sources create",
            "CLI command: discovery sources list",
            "CLI command: discovery schedules create",
            "CLI command: discovery schedules list",
            "CLI command: discovery runs start",
            "CLI command: discovery runs list",
            "CLI command: discovery runs get",
            "CLI command: discovery findings list",
            "CLI command: discovery plans preview",
            "CLI command: discovery sources preflight",
            "CLI command: discovery runs retry",
            "CLI command: discovery drift-remediation",
            "CLI command: discovery drift-remediation decide"
          ]
        }
      },
      "owner": "discovery",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "4c710ece1ab63de9ac6ce3c2ab72ee993ff6c2db",
      "freshness": "2026-08-27"
    }
  },
  {
    "featureId": "F19",
    "feature": "Credential risk scoring",
    "domain": "Observability and risk",
    "phase": "P0",
    "priority": 8,
    "contract": {
      "purpose": "Lets an operator understand and safely use credential risk scoring while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/risk",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/risk"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "read_only",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "not_applicable",
          "reason": "This is an evidence or inventory workflow; configuration is owned by the originating capability."
        },
        "preview": {
          "status": "not_applicable",
          "reason": "This read-only workflow has no external effect to preview."
        },
        "execute": {
          "status": "not_applicable",
          "reason": "This workflow reads tenant-scoped state and performs no product mutation."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "not_applicable",
          "reason": "A read-only view cannot leave an external effect that requires rollback."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/nhi_posture_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listRiskScores",
            "OpenAPI operationId: listContextualRiskPriorities",
            "OpenAPI operationId: listNHIOverPrivilegePosture",
            "OpenAPI operationId: listNHIStalePosture",
            "OpenAPI operationId: listNHIStaticPosture",
            "OpenAPI operationId: listNHIExposurePosture",
            "CLI command: risk credentials",
            "CLI command: risk contextual-priorities",
            "CLI command: nhi posture overprivilege",
            "CLI command: nhi posture stale",
            "CLI command: nhi posture static-credentials",
            "CLI command: nhi posture exposure"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "maintain",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F52",
    "feature": "CBOM and cryptographic observability",
    "domain": "Observability and risk",
    "phase": "P2",
    "priority": 51,
    "contract": {
      "purpose": "Lets an operator understand and safely use cbom and cryptographic observability while tenant, policy, and security authority remain on the server.",
      "tool": "software_trust",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/posture",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/posture"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core_with_licensed_extensions",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Posture.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Posture.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Posture.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Posture.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/cbom_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: startCBOMScan",
            "OpenAPI operationId: listCBOMAssets",
            "OpenAPI operationId: startPQCMigrationCampaign",
            "OpenAPI operationId: listPQCMigrationCampaigns",
            "OpenAPI operationId: getPQCMigrationCampaign",
            "OpenAPI operationId: updatePQCMigrationCampaign",
            "OpenAPI operationId: setPQCMigrationCampaignReadiness",
            "OpenAPI operationId: dispositionPQCMigrationFinding",
            "OpenAPI operationId: closePQCMigrationCampaign",
            "OpenAPI operationId: getPQCMigrationCampaignEvidence",
            "CLI command: cbom scan",
            "CLI command: cbom assets",
            "CLI command: pqc campaigns create",
            "CLI command: pqc campaigns list",
            "CLI command: pqc campaigns get",
            "CLI command: pqc campaigns update",
            "CLI command: pqc campaigns readiness",
            "CLI command: pqc campaigns disposition",
            "CLI command: pqc campaigns close",
            "CLI command: pqc campaigns evidence"
          ]
        }
      },
      "owner": "software-trust",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F4",
    "feature": "CA-agnostic outbound issuance",
    "domain": "Issuance and CAs",
    "phase": "P0",
    "priority": 4,
    "contract": {
      "purpose": "Lets an operator understand and safely use ca-agnostic outbound issuance while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/request",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/request"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/RequestCredential.tsx",
            "web/src/__tests__/self_service.test.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: previewIssuanceRequest",
            "CLI command: issuance-requests preview",
            "internal/server/issuance_request_served_test.go",
            "web/src/pages/RequestCredential.tsx",
            "web/src/__tests__/self_service.test.tsx"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/self_service_issuance_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/components/IssuanceRequestsPanel.tsx",
            "web/src/__tests__/issuance_requests_panel.test.tsx",
            "internal/server/issuance_request_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/self_service_issuance_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createIssuer",
            "OpenAPI operationId: listIssuerCapabilities",
            "OpenAPI operationId: listIssuers",
            "OpenAPI operationId: getIssuer",
            "OpenAPI operationId: createIdentity",
            "OpenAPI operationId: transitionIdentity",
            "OpenAPI operationId: approveIdentityAction",
            "OpenAPI operationId: listExternalCAs",
            "OpenAPI operationId: issueExternalCA",
            "OpenAPI operationId: previewIssuanceRequest",
            "OpenAPI operationId: getKubernetesCSRSupport",
            "OpenAPI operationId: getKubernetesTrustBundleDistribution",
            "CLI command: issuers create",
            "CLI command: issuers capabilities",
            "CLI command: issuers list",
            "CLI command: issuers get",
            "CLI command: identities create",
            "CLI command: identities transition",
            "CLI command: identities approve",
            "CLI command: external-cas list",
            "CLI command: external-cas issue",
            "CLI command: issuance-requests preview",
            "CLI command: kubernetes csr",
            "CLI command: kubernetes trust-bundles"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "7171340342f0f04d3c42a7faa9b3552d9930a7bf",
      "freshness": "2026-08-27"
    }
  },
  {
    "featureId": "F48",
    "feature": "Private/enterprise CA hierarchy management",
    "domain": "Issuance and CAs",
    "phase": "P2",
    "priority": 52,
    "contract": {
      "purpose": "Lets an operator understand and safely use private/enterprise ca hierarchy management while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/ca-hierarchy",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/ca-hierarchy"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/CAHierarchy.tsx",
            "web/src/pages/Migration.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/ca_hierarchy_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/ca_hierarchy_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/ca_hierarchy_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createCACeremony",
            "OpenAPI operationId: getCACeremony",
            "OpenAPI operationId: approveCACeremony",
            "OpenAPI operationId: listCADiscoveryInventory",
            "OpenAPI operationId: listCAAuthorities",
            "OpenAPI operationId: createRootCA",
            "OpenAPI operationId: importOfflineRootCA",
            "OpenAPI operationId: importExistingCA",
            "OpenAPI operationId: createIntermediateCA",
            "OpenAPI operationId: createOfflineIntermediateCSR",
            "OpenAPI operationId: importOfflineIntermediateCA",
            "OpenAPI operationId: issueIntermediateCAFromCSR",
            "OpenAPI operationId: issueHierarchyLeaf",
            "OpenAPI operationId: rotateCAAuthority",
            "OpenAPI operationId: rekeyCAAuthority",
            "OpenAPI operationId: crossSignCAAuthority",
            "OpenAPI operationId: rekeyOfflineRoot",
            "OpenAPI operationId: importOfflineRootCrossSign",
            "OpenAPI operationId: listEdgeSegmentPolicies",
            "OpenAPI operationId: putEdgeSegmentPolicy",
            "OpenAPI operationId: mintEdgeDelegation",
            "OpenAPI operationId: listEdgeDelegations",
            "OpenAPI operationId: getEdgeDelegation",
            "OpenAPI operationId: revokeEdgeDelegation",
            "OpenAPI operationId: reconcileEdgeDelegation",
            "OpenAPI operationId: startMigrationRun",
            "OpenAPI operationId: listMigrationRuns",
            "OpenAPI operationId: getMigrationRun",
            "OpenAPI operationId: pauseMigrationRun",
            "OpenAPI operationId: resumeMigrationRun",
            "OpenAPI operationId: rollbackMigrationRun",
            "CLI command: ca ceremonies start",
            "CLI command: ca ceremonies get",
            "CLI command: ca ceremonies approve",
            "CLI command: ca discovery list",
            "CLI command: ca authorities list",
            "CLI command: ca authorities create-root",
            "CLI command: ca authorities import-offline-root",
            "CLI command: ca authorities import-existing",
            "CLI command: ca authorities create-intermediate",
            "CLI command: ca authorities offline-intermediate-csr",
            "CLI command: ca authorities import-offline-intermediate",
            "CLI command: ca authorities issue-intermediate-csr",
            "CLI command: ca authorities rotate",
            "CLI command: ca authorities rekey",
            "CLI command: ca authorities issue",
            "CLI command: ca authorities cross-sign",
            "CLI command: ca authorities rekey-offline-root",
            "CLI command: ca authorities import-offline-cross-sign",
            "CLI command: edge segments list",
            "CLI command: edge segments set",
            "CLI command: edge delegations mint",
            "CLI command: edge delegations list",
            "CLI command: edge delegations show",
            "CLI command: edge delegations revoke",
            "CLI command: edge delegations reconcile",
            "CLI command: migrations start",
            "CLI command: migrations list",
            "CLI command: migrations show",
            "CLI command: migrations pause",
            "CLI command: migrations resume",
            "CLI command: migrations rollback"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F53",
    "feature": "Certificate profiles and registration-authority model",
    "domain": "Issuance and CAs",
    "phase": "P0",
    "priority": 5,
    "contract": {
      "purpose": "Lets an operator understand and safely use certificate profiles and registration-authority model while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/profiles",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/profiles"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Profiles.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/projections/profile_e2e_test.go"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/projections/profile_e2e_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/projections/profile_e2e_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createProfile",
            "OpenAPI operationId: listProfiles",
            "OpenAPI operationId: getProfileVersion",
            "CLI command: profiles create",
            "CLI command: profiles list",
            "CLI command: profiles get-version"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F46",
    "feature": "ACME Renewal Information (ARI)",
    "domain": "Issuance and CAs",
    "phase": "P2",
    "priority": 53,
    "contract": {
      "purpose": "Lets an operator understand and safely use acme renewal information (ari) while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/protocols"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "read_only",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/protocols/ARIPosturePanel.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/protocols/ARIPosturePanel.tsx"
          ]
        },
        "configure": {
          "status": "not_applicable",
          "reason": "This is an evidence or inventory workflow; configuration is owned by the originating capability."
        },
        "preview": {
          "status": "not_applicable",
          "reason": "This read-only workflow has no external effect to preview."
        },
        "execute": {
          "status": "not_applicable",
          "reason": "This workflow reads tenant-scoped state and performs no product mutation."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/protocols/ARIPosturePanel.tsx"
          ]
        },
        "recover": {
          "status": "not_applicable",
          "reason": "A read-only view cannot leave an external effect that requires rollback."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/journey_delivery_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: getACMEARIPosture",
            "CLI command: acme ari posture"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "maintain",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F47",
    "feature": "X.509 revocation infrastructure",
    "domain": "Issuance and CAs",
    "phase": "P1",
    "priority": 21,
    "contract": {
      "purpose": "Lets an operator understand and safely use x.509 revocation infrastructure while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/identities",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/certificates"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "No structured evidence proves an operator can configure every required prerequisite from this console journey."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/revocation_public_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/revocation_public_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/revocation_public_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: transitionIdentity",
            "OpenAPI operationId: searchAudit",
            "OpenAPI operationId: bulkRevokeIdentities",
            "OpenAPI operationId: bulkRevokeCertificates",
            "OpenAPI operationId: listCRLDistributions",
            "OpenAPI operationId: submitCertificateTransparency",
            "OpenAPI operationId: listRogueCertificates",
            "OpenAPI operationId: listRevocationHealth",
            "OpenAPI operationId: listRevocationCaches",
            "CLI command: identities transition",
            "CLI command: audit events",
            "CLI command: identities bulk-revoke",
            "CLI command: certificates bulk-revoke",
            "CLI command: revocation crls",
            "CLI command: revocation caches",
            "CLI command: revocation health",
            "CLI command: revocation ct-submit",
            "CLI command: revocation rogue-certificates"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F26",
    "feature": "HSM integration",
    "domain": "Issuance and CAs",
    "phase": "P2",
    "priority": 54,
    "contract": {
      "purpose": "Lets an operator understand and safely use hsm integration while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/ca-hierarchy",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/ca-hierarchy"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core_with_licensed_extensions",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "No structured evidence proves an operator can configure every required prerequisite from this console journey."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "ee/managedkeys/managedkeys_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "ee/managedkeys/managedkeys_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "ee/managedkeys/managedkeys_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: generateManagedKey",
            "OpenAPI operationId: approveManagedKeyAction",
            "OpenAPI operationId: rotateManagedKey",
            "OpenAPI operationId: revokeManagedKey",
            "OpenAPI operationId: zeroizeManagedKey",
            "OpenAPI operationId: getEditions",
            "CLI command: managed-keys generate",
            "CLI command: managed-keys approve",
            "CLI command: managed-keys rotate",
            "CLI command: managed-keys revoke",
            "CLI command: managed-keys zeroize"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F5",
    "feature": "Built-in ACME server",
    "domain": "ACME and DNS validation",
    "phase": "P1",
    "priority": 22,
    "contract": {
      "purpose": "Lets an operator understand and safely use built-in acme server while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/protocols"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/protocols_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listACMEEABCredentials",
            "OpenAPI operationId: disableACMEEABCredential",
            "OpenAPI operationId: enableACMEEABCredential"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F69",
    "feature": "DNS-01 challenge automation",
    "domain": "ACME and DNS validation",
    "phase": "P2",
    "priority": 55,
    "contract": {
      "purpose": "Lets an operator understand and safely use dns-01 challenge automation while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/protocols"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx",
            "internal/server/protocols_served_test.go"
          ]
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/protocols_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listACMEDNS01Providers",
            "OpenAPI operationId: createACMEDNS01ProviderConfig",
            "OpenAPI operationId: listACMEDNS01ProviderConfigs",
            "OpenAPI operationId: getACMEDNS01ProviderConfig",
            "OpenAPI operationId: updateACMEDNS01ProviderConfig",
            "OpenAPI operationId: deleteACMEDNS01ProviderConfig",
            "OpenAPI operationId: preflightACMEDNS01",
            "OpenAPI operationId: listACMEUpstreamAuthorizations",
            "CLI command: acme dns-01 providers",
            "CLI command: acme dns-01 provider-configs create",
            "CLI command: acme dns-01 upstream-authorizations",
            "CLI command: acme dns-01 provider-configs list",
            "CLI command: acme dns-01 provider-configs get",
            "CLI command: acme dns-01 provider-configs update",
            "CLI command: acme dns-01 provider-configs delete",
            "CLI command: acme dns-01 preflight"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F70",
    "feature": "DNS-provider plugin framework",
    "domain": "ACME and DNS validation",
    "phase": "P2",
    "priority": 56,
    "contract": {
      "purpose": "Lets an operator understand and safely use dns-provider plugin framework while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/protocols"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/protocols_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listACMEDNS01Providers",
            "OpenAPI operationId: createACMEDNS01ProviderConfig",
            "OpenAPI operationId: listACMEDNS01ProviderConfigs",
            "OpenAPI operationId: getACMEDNS01ProviderConfig",
            "OpenAPI operationId: updateACMEDNS01ProviderConfig",
            "OpenAPI operationId: deleteACMEDNS01ProviderConfig",
            "OpenAPI operationId: preflightACMEDNS01",
            "CLI command: acme dns-01 providers",
            "CLI command: acme dns-01 provider-configs create",
            "CLI command: acme dns-01 provider-configs list",
            "CLI command: acme dns-01 provider-configs get",
            "CLI command: acme dns-01 provider-configs update",
            "CLI command: acme dns-01 provider-configs delete",
            "CLI command: acme dns-01 preflight"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F71",
    "feature": "CNAME delegation for validation isolation",
    "domain": "ACME and DNS validation",
    "phase": "P2",
    "priority": 57,
    "contract": {
      "purpose": "Lets an operator understand and safely use cname delegation for validation isolation while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/protocols"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx",
            "internal/server/protocols_served_test.go"
          ]
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/protocols_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: preflightACMEDNS01",
            "CLI command: acme dns-01 preflight"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F72",
    "feature": "CAA policy enforcement and management",
    "domain": "ACME and DNS validation",
    "phase": "P2",
    "priority": 58,
    "contract": {
      "purpose": "Lets an operator understand and safely use caa policy enforcement and management while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/protocols"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx",
            "internal/server/protocols_served_test.go"
          ]
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "missing",
          "reason": "Durable or external-effect verification is not yet proved from this console journey."
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: preflightACMEDNS01",
            "CLI command: acme dns-01 preflight"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F73",
    "feature": "Multi-method domain-validation policy",
    "domain": "ACME and DNS validation",
    "phase": "P2",
    "priority": 59,
    "contract": {
      "purpose": "Lets an operator understand and safely use multi-method domain-validation policy while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/protocols"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx",
            "internal/server/protocols_served_test.go"
          ]
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "missing",
          "reason": "Durable or external-effect verification is not yet proved from this console journey."
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createACMEDNS01ProviderConfig",
            "OpenAPI operationId: updateACMEDNS01ProviderConfig",
            "OpenAPI operationId: preflightACMEDNS01",
            "CLI command: acme dns-01 provider-configs create",
            "CLI command: acme dns-01 provider-configs update",
            "CLI command: acme dns-01 preflight"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F74",
    "feature": "Automated wildcard issuance and renewal",
    "domain": "ACME and DNS validation",
    "phase": "P2",
    "priority": 60,
    "contract": {
      "purpose": "Lets an operator understand and safely use automated wildcard issuance and renewal while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/identities"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Identities.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Identities.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Identities.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Identities.tsx",
            "internal/server/journey_delivery_served_test.go"
          ]
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Identities.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "missing",
          "reason": "Durable or external-effect verification is not yet proved from this console journey."
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createIdentity",
            "OpenAPI operationId: transitionIdentity",
            "OpenAPI operationId: preflightACMEDNS01",
            "CLI command: acme dns-01 preflight"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F22",
    "feature": "EST server",
    "domain": "Enrollment protocols",
    "phase": "P1",
    "priority": 23,
    "contract": {
      "purpose": "Lets an operator understand and safely use est server while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/protocols"
      ],
      "permissionAuthority": "feature-specific served authorization boundary",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/protocols_served_enroll_test.go"
          ]
        },
        "automate": {
          "status": "not_applicable",
          "reason": "The catalog declares no supported API or CLI automation surface for this capability."
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F23",
    "feature": "SCEP server",
    "domain": "Enrollment protocols",
    "phase": "P1",
    "priority": 24,
    "contract": {
      "purpose": "Lets an operator understand and safely use scep server while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/protocols"
      ],
      "permissionAuthority": "feature-specific served authorization boundary",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/protocols_served_enroll_test.go"
          ]
        },
        "automate": {
          "status": "not_applicable",
          "reason": "The catalog declares no supported API or CLI automation surface for this capability."
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F55",
    "feature": "CMP server",
    "domain": "Enrollment protocols",
    "phase": "P1",
    "priority": 25,
    "contract": {
      "purpose": "Lets an operator understand and safely use cmp server while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/protocols"
      ],
      "permissionAuthority": "feature-specific served authorization boundary",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/protocols_served_enroll_test.go"
          ]
        },
        "automate": {
          "status": "not_applicable",
          "reason": "The catalog declares no supported API or CLI automation surface for this capability."
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F54",
    "feature": "Embedded / IoT enrollment agent",
    "domain": "Enrollment protocols",
    "phase": "P1",
    "priority": 26,
    "contract": {
      "purpose": "Lets an operator understand and safely use embedded / iot enrollment agent while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/agents",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/agents"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "No structured evidence proves an operator can configure every required prerequisite from this console journey."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/api/enroll_routes_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/api/enroll_routes_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listAgents",
            "OpenAPI operationId: createEnrollmentToken",
            "OpenAPI operationId: revokeAgentCertificate",
            "OpenAPI operationId: offboardAgent",
            "CLI command: agents list",
            "CLI command: agents enroll-token",
            "CLI command: agents revoke-cert",
            "CLI command: agents offboard"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F56",
    "feature": "Intune / MDM enrollment integration",
    "domain": "Enrollment protocols",
    "phase": "P2",
    "priority": 61,
    "contract": {
      "purpose": "Lets an operator understand and safely use intune / mdm enrollment integration while tenant, policy, and security authority remain on the server.",
      "tool": "certificates",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/protocols"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx",
            "internal/server/protocols_served_enroll_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/protocols_served_enroll_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: getMDMSCEPStatus",
            "OpenAPI operationId: createMDMSCEPPolicy",
            "OpenAPI operationId: listMDMSCEPPolicies",
            "OpenAPI operationId: getMDMSCEPPolicy",
            "OpenAPI operationId: updateMDMSCEPPolicy",
            "OpenAPI operationId: deleteMDMSCEPPolicy",
            "OpenAPI operationId: rotateMDMSCEPChallenge",
            "OpenAPI operationId: listMDMDevices",
            "OpenAPI operationId: getMDMDeviceTrace",
            "OpenAPI operationId: putMDMPollSchedule",
            "OpenAPI operationId: listMDMPollSchedules",
            "CLI command: mdm scep status",
            "CLI command: mdm scep policies create",
            "CLI command: mdm scep policies list",
            "CLI command: mdm scep policies get",
            "CLI command: mdm scep policies update",
            "CLI command: mdm scep policies delete",
            "CLI command: mdm scep policies rotate-challenge",
            "CLI command: mdm devices",
            "CLI command: mdm trace",
            "CLI command: mdm poll-schedule set",
            "CLI command: mdm poll-schedule show"
          ]
        }
      },
      "owner": "pki",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F24",
    "feature": "SPIFFE Workload API",
    "domain": "Workload identity",
    "phase": "P1",
    "priority": 27,
    "contract": {
      "purpose": "Lets an operator understand and safely use spiffe workload api while tenant, policy, and security authority remain on the server.",
      "tool": "workloads_machines",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/protocols"
      ],
      "permissionAuthority": "feature-specific served authorization boundary",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/protocols_served_spiffe_ssh_test.go"
          ]
        },
        "automate": {
          "status": "not_applicable",
          "reason": "The catalog declares no supported API or CLI automation surface for this capability."
        }
      },
      "owner": "identity",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F25",
    "feature": "Ephemeral credential issuance",
    "domain": "Workload identity",
    "phase": "P2",
    "priority": 62,
    "contract": {
      "purpose": "Lets an operator understand and safely use ephemeral credential issuance while tenant, policy, and security authority remain on the server.",
      "tool": "workloads_machines",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/workloads",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/workloads"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx",
            "internal/server/ephemeral_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx",
            "internal/server/ephemeral_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/ephemeral_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: issueEphemeralCredential",
            "OpenAPI operationId: approveEphemeralCredential",
            "CLI command: ephemeral issue",
            "CLI command: ephemeral approve"
          ]
        }
      },
      "owner": "identity",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F30",
    "feature": "Workload attestation chain",
    "domain": "Workload identity",
    "phase": "P2",
    "priority": 63,
    "contract": {
      "purpose": "Lets an operator understand and safely use workload attestation chain while tenant, policy, and security authority remain on the server.",
      "tool": "workloads_machines",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/workloads",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/workloads"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx",
            "internal/server/attested_issuance_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx",
            "internal/server/attested_issuance_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/attested_issuance_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createWorkloadAttesterTrustSource",
            "OpenAPI operationId: listWorkloadAttesterTrustSources",
            "OpenAPI operationId: getWorkloadAttesterTrustSource",
            "OpenAPI operationId: updateWorkloadAttesterTrustSource",
            "OpenAPI operationId: rotateWorkloadAttesterTrustSource",
            "OpenAPI operationId: revokeWorkloadAttesterTrustSource",
            "OpenAPI operationId: deleteWorkloadAttesterTrustSource",
            "OpenAPI operationId: issueAttestedSVID",
            "CLI command: workloads attester-trust-sources create",
            "CLI command: workloads attester-trust-sources list",
            "CLI command: workloads attester-trust-sources get",
            "CLI command: workloads attester-trust-sources update",
            "CLI command: workloads attester-trust-sources rotate",
            "CLI command: workloads attester-trust-sources revoke",
            "CLI command: workloads attester-trust-sources delete",
            "CLI command: workloads attested-issuance"
          ]
        }
      },
      "owner": "identity",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F59",
    "feature": "Non-human identity lifecycle management",
    "domain": "Workload identity",
    "phase": "P0",
    "priority": 6,
    "contract": {
      "purpose": "Lets an operator understand and safely use non-human identity lifecycle management while tenant, policy, and security authority remain on the server.",
      "tool": "workloads_machines",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/identities",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/workloads"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "No structured evidence proves an operator can configure every required prerequisite from this console journey."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/discovery_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/discovery_served_test.go"
          ]
        },
        "verify": {
          "status": "missing",
          "reason": "Durable or external-effect verification is not yet proved from this console journey."
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createIdentity",
            "OpenAPI operationId: listIdentities",
            "OpenAPI operationId: getIdentity",
            "OpenAPI operationId: transitionIdentity",
            "OpenAPI operationId: approveIdentityAction",
            "OpenAPI operationId: listNHIInventory",
            "OpenAPI operationId: listNHIShadowPosture",
            "OpenAPI operationId: decommissionNHI",
            "CLI command: identities create",
            "CLI command: identities list",
            "CLI command: identities get",
            "CLI command: identities transition",
            "CLI command: identities approve",
            "CLI command: nhi inventory",
            "CLI command: nhi posture shadow",
            "CLI command: nhi decommission"
          ]
        }
      },
      "owner": "identity",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F61",
    "feature": "AI-agent / NHI identity broker",
    "domain": "Workload identity",
    "phase": "P2",
    "priority": 64,
    "contract": {
      "purpose": "Lets an operator understand and safely use ai-agent / nhi identity broker while tenant, policy, and security authority remain on the server.",
      "tool": "workloads_machines",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/workloads",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/workloads"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Workloads.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/broker_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: issueBrokerAgentIdentity",
            "CLI command: broker agent-identities issue"
          ]
        }
      },
      "owner": "identity",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F43",
    "feature": "SSH certificate authority",
    "domain": "SSH",
    "phase": "P1",
    "priority": 28,
    "contract": {
      "purpose": "Lets an operator understand and safely use ssh certificate authority while tenant, policy, and security authority remain on the server.",
      "tool": "workloads_machines",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/ssh",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/ssh"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx",
            "internal/server/protocols_served_spiffe_ssh_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx",
            "internal/server/protocols_served_spiffe_ssh_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/protocols_served_spiffe_ssh_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: getSSHStatus",
            "OpenAPI operationId: revokeSSHCertificate",
            "OpenAPI operationId: getProtocolProfile",
            "OpenAPI operationId: activateProtocolProfile",
            "CLI command: ssh status",
            "CLI command: ssh revoke",
            "CLI command: setup protocols status",
            "CLI command: setup protocols activate"
          ]
        }
      },
      "owner": "identity",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F44",
    "feature": "SSH deployment and trust configuration agent",
    "domain": "SSH",
    "phase": "P2",
    "priority": 65,
    "contract": {
      "purpose": "Lets an operator understand and safely use ssh deployment and trust configuration agent while tenant, policy, and security authority remain on the server.",
      "tool": "workloads_machines",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/ssh",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/ssh"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx",
            "internal/server/ssh_journey_served_test.go"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx",
            "internal/server/ssh_journey_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx",
            "internal/server/ssh_journey_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/ssh_journey_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: recordSSHTrustRollout",
            "OpenAPI operationId: retireSSHHost",
            "CLI command: ssh trust-rollout",
            "CLI command: ssh retire-host"
          ]
        }
      },
      "owner": "identity",
      "targetCheckpoint": "maintain",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F45",
    "feature": "Attestation-gated short-lived SSH user certs",
    "domain": "SSH",
    "phase": "P2",
    "priority": 66,
    "contract": {
      "purpose": "Lets an operator understand and safely use attestation-gated short-lived ssh user certs while tenant, policy, and security authority remain on the server.",
      "tool": "workloads_machines",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/ssh",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/ssh"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx",
            "internal/server/ssh_journey_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/SSHTrust.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/ssh_journey_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: issueAttestedSSHUserCert",
            "CLI command: ssh issue-attested-user"
          ]
        }
      },
      "owner": "identity",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F6",
    "feature": "Lifecycle automation",
    "domain": "Lifecycle and PQC",
    "phase": "P1",
    "priority": 29,
    "contract": {
      "purpose": "Lets an operator understand and safely use lifecycle automation while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/identities",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/identities"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Identities.tsx",
            "web/src/pages/Connectors.tsx",
            "web/src/pages/Notifications.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Identities.tsx",
            "web/src/pages/Connectors.tsx",
            "web/src/pages/Notifications.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Connectors.tsx",
            "internal/server/journey_delivery_served_test.go"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "The console does not yet show the exact renewal window, affected credentials, connector effects, policy decisions, and outbox work before a lifecycle run starts."
        },
        "execute": {
          "status": "missing",
          "reason": "Endpoint-binding setup is available, but the console does not yet provide the complete start, pause, resume, retry, and cancel workflow for lifecycle automation runs."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Identities.tsx",
            "web/src/pages/Notifications.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "The backend records rotation and delivery recovery evidence, but the console does not yet give the operator a complete retry, resume, or rollback workflow."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/journey_delivery_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listIdentities",
            "OpenAPI operationId: transitionIdentity",
            "OpenAPI operationId: createEndpointBinding",
            "OpenAPI operationId: listNotifications",
            "OpenAPI operationId: getNotification",
            "OpenAPI operationId: searchAudit",
            "OpenAPI operationId: listRotationRuns",
            "OpenAPI operationId: getRotationRun",
            "OpenAPI operationId: getRenewalSLO",
            "CLI command: identities list",
            "CLI command: identities transition",
            "CLI command: audit events",
            "CLI command: lifecycle endpoint-bindings create",
            "CLI command: notifications list",
            "CLI command: notifications get",
            "CLI command: lifecycle rotation-runs list",
            "CLI command: lifecycle rotation-runs get",
            "CLI command: operations renewal-slo"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F16",
    "feature": "Crypto-agility and PQC readiness",
    "domain": "Lifecycle and PQC",
    "phase": "P2",
    "priority": 67,
    "contract": {
      "purpose": "Lets an operator understand and safely use crypto-agility and pqc readiness while tenant, policy, and security authority remain on the server.",
      "tool": "software_trust",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/posture",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/posture"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core_with_licensed_extensions",
      "dependencies": [
        "One or more lifecycle or console stages remain incomplete and are shown in the stage ledger."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Profiles.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Profiles.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Profiles.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Profiles.tsx",
            "internal/server/crypto_agility_served_test.go"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Profiles.tsx",
            "internal/server/crypto_agility_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Profiles.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Profiles.tsx",
            "internal/server/crypto_agility_served_test.go"
          ]
        },
        "verify": {
          "status": "missing",
          "reason": "Durable or external-effect verification is not yet proved from this console journey."
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createProfile",
            "OpenAPI operationId: listProfiles",
            "OpenAPI operationId: getProfileVersion",
            "OpenAPI operationId: startCBOMScan",
            "OpenAPI operationId: listCBOMAssets",
            "CLI command: cbom assets",
            "CLI command: cbom scan",
            "CLI command: migration plan",
            "CLI command: migration rollback",
            "CLI command: migration start",
            "CLI command: migration status",
            "CLI command: profiles create",
            "CLI command: profiles get-version",
            "CLI command: profiles list"
          ]
        }
      },
      "owner": "software-trust",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F57",
    "feature": "PQC migration orchestration",
    "domain": "Lifecycle and PQC",
    "phase": "P2",
    "priority": 68,
    "contract": {
      "purpose": "Lets an operator understand and safely use pqc migration orchestration while tenant, policy, and security authority remain on the server.",
      "tool": "software_trust",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/posture",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/posture"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core_with_licensed_extensions",
      "dependencies": [
        "One or more lifecycle or console stages remain incomplete and are shown in the stage ledger."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Posture.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Posture.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Posture.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Posture.tsx",
            "internal/server/pqc_migration_campaign_served_test.go"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Posture.tsx",
            "internal/server/pqc_migration_campaign_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Posture.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Posture.tsx",
            "internal/server/pqc_migration_campaign_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/pqc_migration_campaign_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: startPQCMigrationCampaign",
            "OpenAPI operationId: listPQCMigrationCampaigns",
            "OpenAPI operationId: getPQCMigrationCampaign",
            "OpenAPI operationId: updatePQCMigrationCampaign",
            "OpenAPI operationId: setPQCMigrationCampaignReadiness",
            "OpenAPI operationId: dispositionPQCMigrationFinding",
            "OpenAPI operationId: closePQCMigrationCampaign",
            "OpenAPI operationId: getPQCMigrationCampaignEvidence",
            "CLI command: pqc campaigns create",
            "CLI command: pqc campaigns list",
            "CLI command: pqc campaigns get",
            "CLI command: pqc campaigns update",
            "CLI command: pqc campaigns readiness",
            "CLI command: pqc campaigns disposition",
            "CLI command: pqc campaigns close",
            "CLI command: pqc campaigns evidence"
          ]
        }
      },
      "owner": "software-trust",
      "targetCheckpoint": "maintain",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F7",
    "feature": "Deployment connectors initial set",
    "domain": "Deployment connectors",
    "phase": "P2",
    "priority": 69,
    "contract": {
      "purpose": "Lets an operator understand and safely use deployment connectors initial set while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/connectors",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/connectors"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Connectors.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Connectors.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Connectors.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Connectors.tsx",
            "internal/server/journey_delivery_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Connectors.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/journey_delivery_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listConnectorCatalog",
            "OpenAPI operationId: createConnectorTarget",
            "OpenAPI operationId: listConnectorTargets",
            "OpenAPI operationId: getConnectorTarget",
            "OpenAPI operationId: updateConnectorTarget",
            "OpenAPI operationId: deleteConnectorTarget",
            "OpenAPI operationId: testConnectorTarget",
            "OpenAPI operationId: deployConnectorTarget",
            "OpenAPI operationId: rollbackConnectorTarget",
            "OpenAPI operationId: bindIdentityConnectorTarget",
            "OpenAPI operationId: listConnectorDeliveries",
            "OpenAPI operationId: getConnectorDelivery",
            "OpenAPI operationId: listOutboxCircuits",
            "OpenAPI operationId: listEndpointVerifications",
            "OpenAPI operationId: getEndpointVerification",
            "OpenAPI operationId: listEndpointKeyCustody",
            "OpenAPI operationId: listEnrollmentDiagnostics",
            "OpenAPI operationId: getEnrollmentDiagnosticsSupportAddendum",
            "OpenAPI operationId: proveEnrollmentDiagnosticFixed",
            "OpenAPI operationId: getDRPosture",
            "CLI command: connectors catalog",
            "CLI command: connector target list",
            "CLI command: connector target get",
            "CLI command: connector target create",
            "CLI command: connector target update",
            "CLI command: connector target delete",
            "CLI command: connector target bind",
            "CLI command: connector target test",
            "CLI command: connector target deploy",
            "CLI command: connector target rollback",
            "CLI command: connectors deliveries list",
            "CLI command: connectors deliveries get",
            "CLI command: connectors outbox-circuits",
            "CLI command: endpoints verifications",
            "CLI command: endpoints verifications get",
            "CLI command: endpoints key-custody",
            "CLI command: enrollment diagnostics",
            "CLI command: enrollment diagnostics support-addendum",
            "CLI command: enrollment diagnostics prove-fixed",
            "CLI command: platform dr-posture"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F27",
    "feature": "Additional deployment connectors",
    "domain": "Deployment connectors",
    "phase": "P2",
    "priority": 70,
    "contract": {
      "purpose": "Lets an operator understand and safely use additional deployment connectors while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/connectors",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/connectors"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Connectors.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Connectors.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Connectors.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Connectors.tsx",
            "internal/server/journey_delivery_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Connectors.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Connectors.tsx",
            "internal/server/journey_delivery_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/journey_delivery_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listConnectorCatalog",
            "OpenAPI operationId: createConnectorTarget",
            "OpenAPI operationId: listConnectorTargets",
            "OpenAPI operationId: getConnectorTarget",
            "OpenAPI operationId: updateConnectorTarget",
            "OpenAPI operationId: deleteConnectorTarget",
            "OpenAPI operationId: testConnectorTarget",
            "OpenAPI operationId: deployConnectorTarget",
            "OpenAPI operationId: rollbackConnectorTarget",
            "OpenAPI operationId: bindIdentityConnectorTarget",
            "OpenAPI operationId: listConnectorDeliveries",
            "OpenAPI operationId: getConnectorDelivery",
            "OpenAPI operationId: listOutboxCircuits",
            "CLI command: connector target list",
            "CLI command: connector target get",
            "CLI command: connector target create",
            "CLI command: connector target update",
            "CLI command: connector target delete",
            "CLI command: connector target bind",
            "CLI command: connector target test",
            "CLI command: connector target deploy",
            "CLI command: connector target rollback"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F50",
    "feature": "Code-signing service",
    "domain": "Code signing and timestamping",
    "phase": "P2",
    "priority": 71,
    "contract": {
      "purpose": "Lets an operator understand and safely use code-signing service while tenant, policy, and security authority remain on the server.",
      "tool": "software_trust",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/codesign",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/codesign"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/CodeSigning.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/codesign/codesign_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listCodeSigningIdentities",
            "OpenAPI operationId: signCodeArtifact",
            "OpenAPI operationId: signCodeArtifactKeyless",
            "CLI command: code-signing identities",
            "CLI command: code-signing keyless",
            "CLI command: code-signing sign"
          ]
        }
      },
      "owner": "software-trust",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F51",
    "feature": "Timestamping authority",
    "domain": "Code signing and timestamping",
    "phase": "P1",
    "priority": 30,
    "contract": {
      "purpose": "Lets an operator understand and safely use timestamping authority while tenant, policy, and security authority remain on the server.",
      "tool": "software_trust",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/protocols",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/protocols"
      ],
      "permissionAuthority": "feature-specific served authorization boundary",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Protocols.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/protocols_served_tsa_test.go"
          ]
        },
        "automate": {
          "status": "not_applicable",
          "reason": "The catalog declares no supported API or CLI automation surface for this capability."
        }
      },
      "owner": "software-trust",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F31",
    "feature": "Credential compromise workflow",
    "domain": "Incident and JIT",
    "phase": "P2",
    "priority": 72,
    "contract": {
      "purpose": "Lets an operator understand and safely use credential compromise workflow while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/incidents",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/incidents"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core_with_licensed_extensions",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Incidents.tsx",
            "web/src/pages/incidents/OutboxRecoveryPanel.tsx",
            "web/src/pages/Discovery.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/incident_execution_served_test.go"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/incident_execution_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/incident_execution_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/incident_execution_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: executeIncident",
            "OpenAPI operationId: dispatchResponseIntegrations",
            "OpenAPI operationId: createServiceNowTicket",
            "OpenAPI operationId: listIncidentExecutions",
            "OpenAPI operationId: getIncidentExecution",
            "OpenAPI operationId: listOwnerRemediationActions",
            "OpenAPI operationId: acceptOwnerRemediationAction",
            "OpenAPI operationId: listRemediationPlaybooks",
            "OpenAPI operationId: runRemediationPlaybook",
            "OpenAPI operationId: listRemediationPlaybookRuns",
            "OpenAPI operationId: getRemediationPlaybookRun",
            "OpenAPI operationId: listOutboxReconciliationConflicts",
            "OpenAPI operationId: createDiscoverySource",
            "OpenAPI operationId: startDiscoveryRun",
            "OpenAPI operationId: getDiscoveryRun",
            "OpenAPI operationId: listDiscoveryFindings",
            "CLI command: incidents executions execute",
            "CLI command: incidents response-integrations dispatch",
            "CLI command: itsm servicenow tickets create",
            "CLI command: incidents executions list",
            "CLI command: incidents executions get",
            "CLI command: incidents outbox-reconciliation-conflicts list",
            "CLI command: remediation owner-actions list",
            "CLI command: remediation owner-actions accept",
            "CLI command: remediation playbooks",
            "CLI command: remediation playbooks run",
            "CLI command: remediation playbook-runs list",
            "CLI command: remediation playbook-runs get",
            "CLI command: discovery sources create",
            "CLI command: discovery runs start",
            "CLI command: discovery runs get",
            "CLI command: discovery findings list"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "maintain",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F32",
    "feature": "Fleet re-issuance for CA compromise",
    "domain": "Incident and JIT",
    "phase": "P2",
    "priority": 73,
    "contract": {
      "purpose": "Lets an operator understand and safely use fleet re-issuance for ca compromise while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/incidents",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/incidents"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "No structured evidence proves an operator can configure every required prerequisite from this console journey."
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/incident_fleet_reissuance_served_test.go"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/incident_fleet_reissuance_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/incident_fleet_reissuance_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/incident_fleet_reissuance_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: startFleetReissuance",
            "OpenAPI operationId: listFleetReissuanceRuns",
            "OpenAPI operationId: getFleetReissuanceRun",
            "OpenAPI operationId: pauseFleetReissuance",
            "OpenAPI operationId: resumeFleetReissuance",
            "OpenAPI operationId: rollbackFleetReissuance",
            "OpenAPI operationId: exportFleetReissuanceEvidence",
            "CLI command: incidents fleet-reissuance start",
            "CLI command: incidents fleet-reissuance list",
            "CLI command: incidents fleet-reissuance get",
            "CLI command: incidents fleet-reissuance pause",
            "CLI command: incidents fleet-reissuance resume",
            "CLI command: incidents fleet-reissuance rollback",
            "CLI command: incidents fleet-reissuance evidence"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F33",
    "feature": "Just-in-time issuance with approval flows",
    "domain": "Incident and JIT",
    "phase": "P1",
    "priority": 31,
    "contract": {
      "purpose": "Lets an operator understand and safely use just-in-time issuance with approval flows while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/request",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/request"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/RequestCredential.tsx",
            "web/src/pages/Approvals.tsx",
            "web/src/pages/Identities.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/self_service_issuance_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/self_service_issuance_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listProfiles",
            "OpenAPI operationId: listIdentities",
            "OpenAPI operationId: createIdentity",
            "OpenAPI operationId: listApprovalRequests",
            "OpenAPI operationId: approveApprovalRequest",
            "OpenAPI operationId: denyApprovalRequest",
            "OpenAPI operationId: approveIdentityAction",
            "OpenAPI operationId: transitionIdentity",
            "OpenAPI operationId: issueEphemeralCredential",
            "OpenAPI operationId: approveEphemeralCredential",
            "OpenAPI operationId: openPAMSession",
            "OpenAPI operationId: listPAMSessions",
            "OpenAPI operationId: getPAMSession",
            "CLI command: profiles list",
            "CLI command: identities list",
            "CLI command: identities create",
            "CLI command: approval-requests list",
            "CLI command: approval-requests approve",
            "CLI command: approval-requests deny",
            "CLI command: identities approve",
            "CLI command: identities approve issue",
            "CLI command: identities approve rotate",
            "CLI command: identities approve revoke",
            "CLI command: identities transition",
            "CLI command: ephemeral issue",
            "CLI command: ephemeral approve",
            "CLI command: access sessions open",
            "CLI command: access sessions list",
            "CLI command: access sessions get"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F34",
    "feature": "Break-glass procedures",
    "domain": "Incident and JIT",
    "phase": "P2",
    "priority": 74,
    "contract": {
      "purpose": "Lets an operator understand and safely use break-glass procedures while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/incidents",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/incidents"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "No structured evidence proves an operator can configure every required prerequisite from this console journey."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/breakglass_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/breakglass_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/breakglass_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: startBreakglassIssueCeremony",
            "OpenAPI operationId: issueBreakglass",
            "OpenAPI operationId: startBreakglassRotationCeremony",
            "OpenAPI operationId: rotateBreakglass",
            "OpenAPI operationId: startBreakglassCrossSignCeremony",
            "OpenAPI operationId: crossSignBreakglass",
            "OpenAPI operationId: reconcileBreakglass",
            "CLI command: breakglass issue-ceremony",
            "CLI command: breakglass issue",
            "CLI command: breakglass rotation-ceremony",
            "CLI command: breakglass rotate",
            "CLI command: breakglass cross-sign-ceremony",
            "CLI command: breakglass cross-sign",
            "CLI command: breakglass reconcile"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F37",
    "feature": "Secret rotation engine",
    "domain": "Secrets",
    "phase": "P1",
    "priority": 32,
    "contract": {
      "purpose": "Lets an operator understand and safely use secret rotation engine while tenant, policy, and security authority remain on the server.",
      "tool": "secrets",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/secrets",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/secrets"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "The parity contract contains metadata only. Product workflows may reveal a value once, but reports and evidence never contain the value.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx",
            "internal/server/secrets_rotation_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx",
            "internal/server/secrets_rotation_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/secrets_rotation_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: rotateSecret",
            "OpenAPI operationId: rotateStaticSecret",
            "OpenAPI operationId: createSecretRotationSchedule",
            "OpenAPI operationId: listSecretRotationSchedules",
            "OpenAPI operationId: runDueSecretRotationSchedules",
            "CLI command: secrets store update",
            "CLI command: secrets rotations run",
            "CLI command: secrets rotation-schedules create",
            "CLI command: secrets rotation-schedules list",
            "CLI command: secrets rotation-schedules run-due"
          ]
        }
      },
      "owner": "secrets",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F38",
    "feature": "Ephemeral API key issuance",
    "domain": "Secrets",
    "phase": "P2",
    "priority": 75,
    "contract": {
      "purpose": "Lets an operator understand and safely use ephemeral api key issuance while tenant, policy, and security authority remain on the server.",
      "tool": "secrets",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/secrets/sharing",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/secrets/sharing"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "The parity contract contains metadata only. Product workflows may reveal a value once, but reports and evidence never contain the value.",
      "maturity": "observe_only",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "No structured evidence proves an operator can configure every required prerequisite from this console journey."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "missing",
          "reason": "Durable or external-effect verification is not yet proved from this console journey."
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: issueEphemeralAPIKey",
            "CLI command: ephemeral api-keys issue"
          ]
        }
      },
      "owner": "secrets",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F39",
    "feature": "Code/CI secret scanning bridge",
    "domain": "Secrets",
    "phase": "P2",
    "priority": 76,
    "contract": {
      "purpose": "Lets an operator understand and safely use code/ci secret scanning bridge while tenant, policy, and security authority remain on the server.",
      "tool": "secrets",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/secrets/scanning",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/secrets/scanning"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "The parity contract contains metadata only. Product workflows may reveal a value once, but reports and evidence never contain the value.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx",
            "internal/server/secret_repository_scan_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/secret_repository_scan_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: getSecretRepositoryScanning",
            "OpenAPI operationId: receiveSecretRepositoryWebhook",
            "OpenAPI operationId: getThirdPartySecretScanning",
            "OpenAPI operationId: ingestThirdPartySecretScan",
            "OpenAPI operationId: scanSecrets",
            "CLI command: secrets scans pre-commit install",
            "CLI command: secrets scans repositories",
            "CLI command: secrets scans repositories webhook",
            "CLI command: secrets scans third-party",
            "CLI command: secrets scans third-party ingest",
            "CLI command: secrets scans run",
            "CLI command: secrets scans staged-diff"
          ]
        }
      },
      "owner": "secrets",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F63",
    "feature": "Native secret store",
    "domain": "Secrets",
    "phase": "P1",
    "priority": 33,
    "contract": {
      "purpose": "Lets an operator understand and safely use native secret store while tenant, policy, and security authority remain on the server.",
      "tool": "secrets",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/secrets",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/secrets"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "The parity contract contains metadata only. Product workflows may reveal a value once, but reports and evidence never contain the value.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx",
            "internal/server/secrets_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx",
            "internal/server/secrets_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/secrets_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createSecret",
            "OpenAPI operationId: listSecrets",
            "OpenAPI operationId: getSecret",
            "OpenAPI operationId: getSecretVersion",
            "OpenAPI operationId: recoverSecretAt",
            "OpenAPI operationId: rotateSecret",
            "OpenAPI operationId: deleteSecret",
            "CLI command: secrets store put",
            "CLI command: secrets store list",
            "CLI command: secrets store get",
            "CLI command: secrets store history",
            "CLI command: secrets store recover",
            "CLI command: secrets store update",
            "CLI command: secrets store delete"
          ]
        }
      },
      "owner": "secrets",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F64",
    "feature": "Developer secrets experience",
    "domain": "Secrets",
    "phase": "P1",
    "priority": 34,
    "contract": {
      "purpose": "Lets an operator understand and safely use developer secrets experience while tenant, policy, and security authority remain on the server.",
      "tool": "secrets",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/secrets/access",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/secrets"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "One or more lifecycle or console stages remain incomplete and are shown in the stage ledger."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "The parity contract contains metadata only. Product workflows may reveal a value once, but reports and evidence never contain the value.",
      "maturity": "observe_only",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "The route registry alone does not prove the configure workflow, and this capability row cites no concrete console implementation evidence."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "missing",
          "reason": "Durable or external-effect verification is not yet proved from this console journey."
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createSecret",
            "OpenAPI operationId: listSecrets",
            "OpenAPI operationId: importSecrets",
            "OpenAPI operationId: getSecret",
            "OpenAPI operationId: rotateSecret",
            "OpenAPI operationId: deleteSecret",
            "CLI command: secrets store put",
            "CLI command: secrets store list",
            "CLI command: secrets store get",
            "CLI command: secrets store update",
            "CLI command: secrets store delete",
            "CLI command: run"
          ]
        }
      },
      "owner": "secrets",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F65",
    "feature": "Dynamic secrets",
    "domain": "Secrets",
    "phase": "P2",
    "priority": 77,
    "contract": {
      "purpose": "Lets an operator understand and safely use dynamic secrets while tenant, policy, and security authority remain on the server.",
      "tool": "secrets",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/secrets/engines",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/secrets/engines"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "The parity contract contains metadata only. Product workflows may reveal a value once, but reports and evidence never contain the value.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "No structured evidence proves an operator can configure every required prerequisite from this console journey."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx",
            "internal/server/dod_secret_integrations_runtime_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx",
            "internal/server/dod_secret_integrations_runtime_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/dod_secret_integrations_runtime_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: issueDynamicSecretLease",
            "OpenAPI operationId: getDynamicSecretLease",
            "OpenAPI operationId: renewDynamicSecretLease",
            "OpenAPI operationId: revokeDynamicSecretLease",
            "CLI command: secrets leases issue",
            "CLI command: secrets leases get",
            "CLI command: secrets leases renew",
            "CLI command: secrets leases revoke"
          ]
        }
      },
      "owner": "secrets",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F66",
    "feature": "Encryption-as-a-service and KMIP",
    "domain": "Secrets",
    "phase": "P2",
    "priority": 78,
    "contract": {
      "purpose": "Lets an operator understand and safely use encryption-as-a-service and kmip while tenant, policy, and security authority remain on the server.",
      "tool": "secrets",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/secrets/engines",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/secrets/engines"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "One or more lifecycle or console stages remain incomplete and are shown in the stage ledger."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "The parity contract contains metadata only. Product workflows may reveal a value once, but reports and evidence never contain the value.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/secrets/TransitOperations.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/secrets/TransitOperations.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/secrets/TransitOperations.tsx",
            "internal/server/transit_served_test.go"
          ]
        },
        "preview": {
          "status": "not_applicable",
          "reason": "Transit operations are explicit bounded requests; incompatible keys are prevented before submission rather than simulated."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/__tests__/secrets.test.tsx",
            "internal/server/transit_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/secrets/TransitOperations.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Key restore and an explicit failed-operation recovery journey are not yet present in the console."
        },
        "verify": {
          "status": "missing",
          "reason": "Signature verification, full version history, filtered audit receipts, and KMIP status remain parity debt."
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listTransitKeys",
            "CLI command: transit keys list"
          ]
        }
      },
      "owner": "secrets",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F67",
    "feature": "PKI as a secrets engine",
    "domain": "Secrets",
    "phase": "P1",
    "priority": 35,
    "contract": {
      "purpose": "Lets an operator understand and safely use pki as a secrets engine while tenant, policy, and security authority remain on the server.",
      "tool": "secrets",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/secrets/engines",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/secrets/engines"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "The parity contract contains metadata only. Product workflows may reveal a value once, but reports and evidence never contain the value.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "No structured evidence proves an operator can configure every required prerequisite from this console journey."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx",
            "internal/server/pki_secret_csr_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx",
            "internal/server/pki_secret_csr_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/pki_secret_csr_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: issuePKISecret",
            "CLI command: secrets pki"
          ]
        }
      },
      "owner": "secrets",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F68",
    "feature": "Secret sync / platform integrations",
    "domain": "Secrets",
    "phase": "P2",
    "priority": 79,
    "contract": {
      "purpose": "Lets an operator understand and safely use secret sync / platform integrations while tenant, policy, and security authority remain on the server.",
      "tool": "secrets",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/secrets/sync",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/secrets/sync"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "The parity contract contains metadata only. Product workflows may reveal a value once, but reports and evidence never contain the value.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx",
            "internal/server/dod_secret_integrations_runtime_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Secrets.tsx",
            "internal/server/dod_secret_integrations_runtime_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/dod_secret_integrations_runtime_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: getCloudSecretManagerIntegration",
            "OpenAPI operationId: listSecretSyncTargets",
            "OpenAPI operationId: createSecretSyncWorkloadIdentitySource",
            "OpenAPI operationId: listSecretSyncWorkloadIdentitySources",
            "OpenAPI operationId: getSecretSyncWorkloadIdentitySource",
            "OpenAPI operationId: updateSecretSyncWorkloadIdentitySource",
            "OpenAPI operationId: deleteSecretSyncWorkloadIdentitySource",
            "OpenAPI operationId: syncSecret",
            "OpenAPI operationId: getKubernetesSecretOperator",
            "OpenAPI operationId: getSecretWorkloadInjection",
            "OpenAPI operationId: getUnvaultedSecretPosture",
            "CLI command: secrets cloud-secret-managers",
            "CLI command: secrets syncs run",
            "CLI command: secrets syncs targets",
            "CLI command: secrets syncs workload-identities create",
            "CLI command: secrets syncs workload-identities list",
            "CLI command: secrets syncs workload-identities get",
            "CLI command: secrets syncs workload-identities update",
            "CLI command: secrets syncs workload-identities delete",
            "CLI command: secrets kubernetes-operator",
            "CLI command: secrets workload-injection",
            "CLI command: secrets unvaulted"
          ]
        }
      },
      "owner": "secrets",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F58",
    "feature": "Platform auth-method framework",
    "domain": "Secrets",
    "phase": "P1",
    "priority": 36,
    "contract": {
      "purpose": "Lets an operator understand and safely use platform auth-method framework while tenant, policy, and security authority remain on the server.",
      "tool": "secrets",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/secrets/access",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/secrets/access"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "The parity contract contains metadata only. Product workflows may reveal a value once, but reports and evidence never contain the value.",
      "maturity": "observe_only",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "The route registry alone does not prove the configure workflow, and this capability row cites no concrete console implementation evidence."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "missing",
          "reason": "Durable or external-effect verification is not yet proved from this console journey."
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: machineLogin",
            "OpenAPI operationId: listMachineAuthMethods",
            "OpenAPI operationId: listMachineSessions",
            "OpenAPI operationId: revokeMachineSession",
            "OpenAPI operationId: disableMachineAuthMethod",
            "OpenAPI operationId: enableMachineAuthMethod",
            "CLI command: secrets login",
            "CLI command: secrets auth-methods list",
            "CLI command: secrets auth-methods disable",
            "CLI command: secrets auth-methods enable",
            "CLI command: secrets sessions list",
            "CLI command: secrets sessions revoke"
          ]
        }
      },
      "owner": "secrets",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F60",
    "feature": "Secret sharing and secret-change approvals",
    "domain": "Secrets",
    "phase": "P1",
    "priority": 37,
    "contract": {
      "purpose": "Lets an operator understand and safely use secret sharing and secret-change approvals while tenant, policy, and security authority remain on the server.",
      "tool": "secrets",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/secrets/sharing",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/secrets/sharing"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "The parity contract contains metadata only. Product workflows may reveal a value once, but reports and evidence never contain the value.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "The route registry alone does not prove the configure workflow, and this capability row cites no concrete console implementation evidence."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "web/src/__tests__/route_parity.test.ts"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "web/src/__tests__/route_parity.test.ts"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createShare",
            "OpenAPI operationId: redeemShare",
            "OpenAPI operationId: approveSecretChange",
            "CLI command: secrets shares create",
            "CLI command: secrets shares redeem",
            "CLI command: secrets approvals approve"
          ]
        }
      },
      "owner": "secrets",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F28",
    "feature": "Policy engine",
    "domain": "Policy and governance",
    "phase": "P1",
    "priority": 38,
    "contract": {
      "purpose": "Lets an operator understand and safely use policy engine while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": false,
      "consoleRoute": "/policy",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/policy"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Policy.tsx",
            "web/src/pages/Identities.tsx",
            "web/src/pages/Risk.tsx",
            "web/src/lib/api.ts"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "web/src/__tests__/route_parity.test.ts"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "web/src/__tests__/route_parity.test.ts"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "web/src/__tests__/route_parity.test.ts"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "web/src/__tests__/route_parity.test.ts"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createOwner",
            "OpenAPI operationId: createIssuer",
            "OpenAPI operationId: createIdentity",
            "OpenAPI operationId: transitionIdentity",
            "OpenAPI operationId: approveIdentityAction",
            "OpenAPI operationId: ingestCertificate",
            "OpenAPI operationId: createProfile",
            "OpenAPI operationId: createEnrollmentToken",
            "OpenAPI operationId: createSecret",
            "OpenAPI operationId: rotateSecret",
            "OpenAPI operationId: createShare",
            "OpenAPI operationId: issuePKISecret",
            "OpenAPI operationId: listOwnershipAttribution",
            "OpenAPI operationId: assignOwnership",
            "OpenAPI operationId: attestOwner",
            "OpenAPI operationId: listOwnershipExceptions",
            "OpenAPI operationId: grantOwnershipException",
            "OpenAPI operationId: revokeOwnershipException",
            "OpenAPI operationId: dryRunPolicy",
            "OpenAPI operationId: createPolicyVersion",
            "OpenAPI operationId: listPolicyVersions",
            "OpenAPI operationId: activatePolicyVersion",
            "OpenAPI operationId: rollbackPolicyVersion",
            "OpenAPI operationId: listNHIPolicyCompliance",
            "OpenAPI operationId: createAccessChangeRequest",
            "OpenAPI operationId: listAccessChangeRequests",
            "OpenAPI operationId: getAccessChangeRequest",
            "OpenAPI operationId: decideAccessChangeRequest",
            "CLI command: owners create",
            "CLI command: issuers create",
            "CLI command: identities create",
            "CLI command: identities transition",
            "CLI command: identities approve",
            "CLI command: certificates ingest",
            "CLI command: profiles create",
            "CLI command: agents enroll-token",
            "CLI command: secrets store put",
            "CLI command: secrets store update",
            "CLI command: secrets shares create",
            "CLI command: secrets pki",
            "CLI command: owners attribution",
            "CLI command: owners assign",
            "CLI command: owners attest",
            "CLI command: owners exceptions list",
            "CLI command: owners exceptions grant",
            "CLI command: owners exceptions revoke",
            "CLI command: policy dry-run",
            "CLI command: policy versions create",
            "CLI command: policy versions list",
            "CLI command: policy versions activate",
            "CLI command: policy versions rollback",
            "CLI command: nhi policy compliance",
            "CLI command: access requests create",
            "CLI command: access requests list",
            "CLI command: access requests get",
            "CLI command: access requests decide"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "maintain",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F29",
    "feature": "Notification integrations",
    "domain": "Policy and governance",
    "phase": "P2",
    "priority": 80,
    "contract": {
      "purpose": "Lets an operator understand and safely use notification integrations while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/policy",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/notifications"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Notifications.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Notifications.tsx"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "No structured evidence proves an operator can configure every required prerequisite from this console journey."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Notifications.tsx",
            "internal/server/notifications_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Notifications.tsx"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/notifications_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: createNotificationChannel",
            "OpenAPI operationId: listNotificationChannels",
            "OpenAPI operationId: getNotificationChannel",
            "OpenAPI operationId: updateNotificationChannel",
            "OpenAPI operationId: deleteNotificationChannel",
            "OpenAPI operationId: testNotificationChannel",
            "OpenAPI operationId: createNotificationRoutingPolicy",
            "OpenAPI operationId: listNotificationRoutingPolicies",
            "OpenAPI operationId: getNotificationRoutingPolicy",
            "OpenAPI operationId: updateNotificationRoutingPolicy",
            "OpenAPI operationId: deleteNotificationRoutingPolicy",
            "OpenAPI operationId: listNotifications",
            "OpenAPI operationId: getNotification",
            "OpenAPI operationId: markNotificationRead",
            "OpenAPI operationId: requeueNotification",
            "OpenAPI operationId: previewNotificationRouting",
            "CLI command: notifications channels",
            "CLI command: notifications channels create",
            "CLI command: notifications channels get",
            "CLI command: notifications channels update",
            "CLI command: notifications channels delete",
            "CLI command: notifications channels test",
            "CLI command: notifications routing-policies create",
            "CLI command: notifications routing-policies list",
            "CLI command: notifications routing-policies get",
            "CLI command: notifications routing-policies update",
            "CLI command: notifications routing-policies delete",
            "CLI command: notifications list",
            "CLI command: notifications get",
            "CLI command: notifications read",
            "CLI command: notifications requeue",
            "CLI command: notifications routing-preview"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F62",
    "feature": "Cryptographic compliance reporting & posture dashboards",
    "domain": "Policy and governance",
    "phase": "P2",
    "priority": 81,
    "contract": {
      "purpose": "Lets an operator understand and safely use cryptographic compliance reporting & posture dashboards while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/policy",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/policy"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Policy.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/governance_seam_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/governance_seam_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: getComplianceEvidencePack",
            "OpenAPI operationId: getComplianceInventoryReport",
            "OpenAPI operationId: getNHIComplianceReport",
            "OpenAPI operationId: createComplianceReportSchedule",
            "OpenAPI operationId: listComplianceReportSchedules",
            "OpenAPI operationId: startNHIReviewCampaign",
            "OpenAPI operationId: listNHIReviewCampaigns",
            "OpenAPI operationId: getNHIReviewCampaign",
            "OpenAPI operationId: decideNHIReviewItem",
            "OpenAPI operationId: erasePrivacySubject",
            "OpenAPI operationId: listPrivacySubjectErasures",
            "OpenAPI operationId: exportPrivacySubject",
            "OpenAPI operationId: getPrivacyCatalog",
            "CLI command: compliance evidence-pack",
            "CLI command: compliance inventory-report",
            "CLI command: compliance nhi-report",
            "CLI command: compliance report-schedules create",
            "CLI command: compliance report-schedules list",
            "CLI command: access reviews start",
            "CLI command: access reviews list",
            "CLI command: access reviews get",
            "CLI command: access reviews decide",
            "CLI command: privacy erasures erase",
            "CLI command: privacy erasures list",
            "CLI command: privacy export",
            "CLI command: privacy catalog"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F8",
    "feature": "RBAC",
    "domain": "Policy and governance",
    "phase": "P0",
    "priority": 7,
    "contract": {
      "purpose": "Lets an operator understand and safely use rbac while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/admin/access",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/admin/access"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/auth/AuthProvider.tsx",
            "web/src/components/AppShell.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "missing",
          "reason": "Durable or external-effect verification is not yet proved from this console journey."
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listOwners",
            "OpenAPI operationId: createOwner",
            "OpenAPI operationId: listCertificates",
            "OpenAPI operationId: createSecret",
            "OpenAPI operationId: aiQuery",
            "OpenAPI operationId: listAccessRoles",
            "OpenAPI operationId: getOIDCMappingStatus",
            "OpenAPI operationId: listMembers",
            "OpenAPI operationId: upsertMember",
            "OpenAPI operationId: offboardMember",
            "OpenAPI operationId: listCapabilities",
            "CLI command: owners list",
            "CLI command: owners create",
            "CLI command: owners import",
            "CLI command: owners ownership-conflicts",
            "CLI command: owners resolve-conflict",
            "CLI command: owners cmdb-schedule set",
            "CLI command: owners cmdb-schedule show",
            "CLI command: issuance-requests open",
            "CLI command: issuance-requests list",
            "CLI command: issuance-requests approve",
            "CLI command: issuance-requests deny",
            "CLI command: issuance-requests cancel",
            "CLI command: issuance-requests prepare",
            "CLI command: issuance-requests complete",
            "CLI command: issuance-requests intake-schedule set",
            "CLI command: issuance-requests intake-schedule show",
            "CLI command: mdm devices",
            "CLI command: mdm trace",
            "CLI command: mdm poll-schedule set",
            "CLI command: mdm poll-schedule show",
            "CLI command: agents upgrade-campaign show",
            "CLI command: agents upgrade-campaign start",
            "CLI command: agents upgrade-campaign pause",
            "CLI command: agents upgrade-campaign resume",
            "CLI command: agents upgrade-ring",
            "CLI command: brand show",
            "CLI command: certificates list",
            "CLI command: secrets store put",
            "CLI command: ai query",
            "CLI command: access roles",
            "CLI command: access oidc-mapping",
            "CLI command: access members list",
            "CLI command: access members upsert",
            "CLI command: access members offboard",
            "CLI command: capabilities list"
          ]
        }
      },
      "owner": "platform",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F9",
    "feature": "Audit log surfaces",
    "domain": "Policy and governance",
    "phase": "P0",
    "priority": 9,
    "contract": {
      "purpose": "Lets an operator understand and safely use audit log surfaces while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/audit",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/audit"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "No structured evidence proves an operator can configure every required prerequisite from this console journey."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/projections/audit_e2e_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/projections/audit_e2e_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: searchAudit",
            "OpenAPI operationId: exportAudit",
            "OpenAPI operationId: getAuditVerificationKeys",
            "OpenAPI operationId: putAuditFeed",
            "OpenAPI operationId: listAuditFeeds",
            "CLI command: audit events",
            "CLI command: audit export",
            "CLI command: audit verification-keys",
            "CLI command: audit verify",
            "CLI command: audit feeds set",
            "CLI command: audit feeds list"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F10",
    "feature": "REST API",
    "domain": "Platform and API",
    "phase": "P0",
    "priority": 10,
    "contract": {
      "purpose": "Lets an operator understand and safely use rest api while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/integrate/api",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/integrate/api"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/ApiExplorer.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/ApiExplorer.tsx"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/ApiExplorer.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/pages/ApiExplorer.tsx"
          ]
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/pages/ApiExplorer.tsx"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/ApiExplorer.tsx"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/__tests__/route_parity.test.ts"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "web/src/__tests__/route_parity.test.ts"
          ]
        },
        "automate": {
          "status": "not_applicable",
          "reason": "The API playground exposes automation; it is not itself a headless automation target."
        }
      },
      "owner": "platform",
      "targetCheckpoint": "maintain",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F11",
    "feature": "CLI",
    "domain": "Platform and API",
    "phase": "P3",
    "priority": 82,
    "contract": {
      "purpose": "Lets an operator understand and safely use cli while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/integrate",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/integrate"
      ],
      "permissionAuthority": "feature-specific served authorization boundary",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "read_only",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Platform.tsx"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Platform.tsx"
          ]
        },
        "configure": {
          "status": "not_applicable",
          "reason": "This is an evidence or inventory workflow; configuration is owned by the originating capability."
        },
        "preview": {
          "status": "not_applicable",
          "reason": "This read-only workflow has no external effect to preview."
        },
        "execute": {
          "status": "not_applicable",
          "reason": "This workflow reads tenant-scoped state and performs no product mutation."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Platform.tsx"
          ]
        },
        "recover": {
          "status": "not_applicable",
          "reason": "A read-only view cannot leave an external effect that requires rollback."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/cli/cli_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "CLI command: acme eab disable",
            "CLI command: acme eab enable",
            "CLI command: acme eab list",
            "CLI command: agents enroll-token",
            "CLI command: agents list",
            "CLI command: ai query",
            "CLI command: ai rca",
            "CLI command: audit events",
            "CLI command: audit export",
            "CLI command: certificates get",
            "CLI command: certificates ingest",
            "CLI command: certificates list",
            "CLI command: graph blast-radius",
            "CLI command: graph trust-stores",
            "CLI command: migrations assess",
            "CLI command: ca keys retirement",
            "CLI command: ca keys retire",
            "CLI command: owners unowned",
            "CLI command: graph nodes",
            "CLI command: graph query",
            "CLI command: graph reachable",
            "CLI command: identities approve",
            "CLI command: identities approve issue",
            "CLI command: identities approve revoke",
            "CLI command: identities approve rotate",
            "CLI command: identities create",
            "CLI command: identities get",
            "CLI command: identities list",
            "CLI command: identities transition",
            "CLI command: issuers create",
            "CLI command: issuers get",
            "CLI command: issuers capabilities",
            "CLI command: issuers list",
            "CLI command: mcp call",
            "CLI command: mcp tools",
            "CLI command: operations bulkheads",
            "CLI command: operations jobs",
            "CLI command: owners create",
            "CLI command: owners delete",
            "CLI command: owners get",
            "CLI command: owners list",
            "CLI command: owners update",
            "CLI command: platform system",
            "CLI command: posture adcs",
            "CLI command: posture adcs drift",
            "CLI command: privacy export",
            "CLI command: privacy retention list",
            "CLI command: privacy retention run",
            "CLI command: profiles create",
            "CLI command: profiles get-version",
            "CLI command: profiles list",
            "CLI command: risk credentials",
            "CLI command: scale ha-issuance",
            "CLI command: scale orchestration",
            "CLI command: secrets login",
            "CLI command: secrets pki",
            "CLI command: secrets shares create",
            "CLI command: secrets shares redeem",
            "CLI command: secrets store delete",
            "CLI command: secrets store get",
            "CLI command: secrets store list",
            "CLI command: secrets store put",
            "CLI command: secrets store update"
          ]
        }
      },
      "owner": "platform",
      "targetCheckpoint": "maintain",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F12",
    "feature": "Web UI",
    "domain": "Platform and API",
    "phase": "P0",
    "priority": 2,
    "contract": {
      "purpose": "Lets an operator understand and safely use web ui while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/"
      ],
      "permissionAuthority": "feature-specific served authorization boundary",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "read_only",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/components/AppShell.tsx",
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/components/AppShell.tsx",
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "not_applicable",
          "reason": "This foundation row describes the served web console itself; feature-specific configuration belongs to each product capability."
        },
        "preview": {
          "status": "not_applicable",
          "reason": "This read-only foundation row has no external effect to preview."
        },
        "execute": {
          "status": "not_applicable",
          "reason": "Feature-specific console mutations are evaluated on their own capability rows."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/components/AppShell.tsx",
            "internal/webui/served_console_test.go"
          ]
        },
        "recover": {
          "status": "not_applicable",
          "reason": "Feature-specific recovery is evaluated on each mutating capability row."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/webui/served_console_test.go"
          ]
        },
        "automate": {
          "status": "not_applicable",
          "reason": "No separate automation surface is required for this read-only product view."
        }
      },
      "owner": "platform",
      "targetCheckpoint": "maintain",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F13",
    "feature": "SSO/OIDC",
    "domain": "Platform and API",
    "phase": "P0",
    "priority": 11,
    "contract": {
      "purpose": "Lets an operator understand and safely use sso/oidc while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/login",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/login"
      ],
      "permissionAuthority": "feature-specific served authorization boundary",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Login.tsx",
            "web/src/auth/AuthProvider.tsx",
            "web/src/components/AppShell.tsx",
            "web/src/pages/Platform.tsx",
            "web/src/lib/api.ts"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/api/auth_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/api/auth_test.go"
          ]
        },
        "automate": {
          "status": "not_applicable",
          "reason": "The catalog declares no supported API or CLI automation surface for this capability."
        }
      },
      "owner": "platform",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F14",
    "feature": "Single-binary distribution",
    "domain": "Platform and API",
    "phase": "P3",
    "priority": 83,
    "contract": {
      "purpose": "Lets an operator understand and safely use single-binary distribution while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/admin/system",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/admin/system"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "read_only",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "complete_vertical_slice",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "not_applicable",
          "reason": "This is an evidence or inventory workflow; configuration is owned by the originating capability."
        },
        "preview": {
          "status": "not_applicable",
          "reason": "This read-only workflow has no external effect to preview."
        },
        "execute": {
          "status": "not_applicable",
          "reason": "This workflow reads tenant-scoped state and performs no product mutation."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "not_applicable",
          "reason": "A read-only view cannot leave an external effect that requires rollback."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/api/platform_distribution_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: getEditions",
            "OpenAPI operationId: getPlatformDistribution",
            "OpenAPI operationId: getPlatformSystem",
            "CLI command: editions status",
            "CLI command: platform distribution"
          ]
        }
      },
      "owner": "platform",
      "targetCheckpoint": "maintain",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F15",
    "feature": "Encrypted control-plane transport",
    "domain": "Platform and API",
    "phase": "P0",
    "priority": 12,
    "contract": {
      "purpose": "Lets an operator understand and safely use encrypted control-plane transport while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/admin/system",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/admin/system"
      ],
      "permissionAuthority": "feature-specific served authorization boundary",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "read_only",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "not_applicable",
          "reason": "This is an evidence or inventory workflow; configuration is owned by the originating capability."
        },
        "preview": {
          "status": "not_applicable",
          "reason": "This read-only workflow has no external effect to preview."
        },
        "execute": {
          "status": "not_applicable",
          "reason": "This workflow reads tenant-scoped state and performs no product mutation."
        },
        "observe": {
          "status": "missing",
          "reason": "The console still has a platform-status gap and does not prove the active HTTPS, agent mTLS, signer transport, issuer, and expiry posture from served runtime data."
        },
        "recover": {
          "status": "not_applicable",
          "reason": "A read-only view cannot leave an external effect that requires rollback."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/config/tls_test.go"
          ]
        },
        "automate": {
          "status": "not_applicable",
          "reason": "No separate automation surface is required for this read-only product view."
        }
      },
      "owner": "platform",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F40",
    "feature": "Multi-tenant deployment topology",
    "domain": "Platform and API",
    "phase": "P0",
    "priority": 13,
    "contract": {
      "purpose": "Lets an operator understand and safely use multi-tenant deployment topology while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/admin/system",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/admin/system"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core_with_licensed_extensions",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/components/AppShell.tsx",
            "web/src/pages/Platform.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/managed_offering_served_test.go"
          ]
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/managed_offering_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listOwners",
            "OpenAPI operationId: listCertificates",
            "OpenAPI operationId: listSecrets",
            "OpenAPI operationId: searchAudit",
            "OpenAPI operationId: getEnterpriseSupportStatus",
            "OpenAPI operationId: getManagedOfferingStatus",
            "OpenAPI operationId: provisionManagedTenant",
            "OpenAPI operationId: getTenantKeyDomain",
            "OpenAPI operationId: migrateTenantKeyDomain",
            "OpenAPI operationId: sealTenantKeyDomain",
            "OpenAPI operationId: unsealTenantKeyDomain",
            "CLI command: owners list",
            "CLI command: certificates list",
            "CLI command: secrets store list",
            "CLI command: audit events",
            "CLI command: support enterprise",
            "CLI command: managed-offering status",
            "CLI command: managed-offering tenants provision",
            "CLI command: platform tenant-key-domain status",
            "CLI command: platform tenant-key-domain migrate",
            "CLI command: platform tenant-key-domain seal",
            "CLI command: platform tenant-key-domain unseal",
            "CLI command: usage evidence"
          ]
        }
      },
      "owner": "platform",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F41",
    "feature": "Cross-cluster / multi-region federation",
    "domain": "Platform and API",
    "phase": "P3",
    "priority": 84,
    "contract": {
      "purpose": "Lets an operator understand and safely use cross-cluster / multi-region federation while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/admin/system",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/admin/system"
      ],
      "permissionAuthority": "feature-specific served authorization boundary",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "observe_only",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "No structured evidence proves an operator can configure every required prerequisite from this console journey."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "ee/federation/federation_served_test.go"
          ]
        },
        "verify": {
          "status": "missing",
          "reason": "Durable or external-effect verification is not yet proved from this console journey."
        },
        "automate": {
          "status": "not_applicable",
          "reason": "The catalog declares no supported API or CLI automation surface for this capability."
        }
      },
      "owner": "platform",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F20",
    "feature": "Plugin SDK with capability sandboxing",
    "domain": "Extensibility and plugins",
    "phase": "P2",
    "priority": 85,
    "contract": {
      "purpose": "Lets an operator understand and safely use plugin sdk with capability sandboxing while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/admin/system",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/admin/system"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "read_only",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "observe_only",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "The console describes grants and provenance but does not yet provide a complete plugin load, admission, or capability-grant configuration workflow."
        },
        "preview": {
          "status": "missing",
          "reason": "The console does not yet preview the exact signature, digest, capability, conformance, and runtime admission decision before activation."
        },
        "execute": {
          "status": "missing",
          "reason": "Plugin activation remains a disclosure instead of a guarded operator action."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "The console does not yet provide disable, quarantine, rollback, or recovery controls for a failed admitted plugin."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/plugins_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listExternalCAs",
            "OpenAPI operationId: issueExternalCA",
            "CLI command: external-cas list",
            "CLI command: external-cas issue"
          ]
        }
      },
      "owner": "platform",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F21",
    "feature": "Credential graph",
    "domain": "Graph, query, and AI",
    "phase": "P0",
    "priority": 14,
    "contract": {
      "purpose": "Lets an operator understand and safely use credential graph while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/graph",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/graph"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "read_only",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Graph.tsx"
          ]
        },
        "understand": {
          "status": "missing",
          "reason": "The basic graph and blast-radius view does not yet prove edge explanations, complete path context, filters, export, or links back to lifecycle, audit, and risk evidence."
        },
        "configure": {
          "status": "not_applicable",
          "reason": "This is an evidence or inventory workflow; configuration is owned by the originating capability."
        },
        "preview": {
          "status": "not_applicable",
          "reason": "This read-only workflow has no external effect to preview."
        },
        "execute": {
          "status": "not_applicable",
          "reason": "This workflow reads tenant-scoped state and performs no product mutation."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Graph.tsx"
          ]
        },
        "recover": {
          "status": "not_applicable",
          "reason": "A read-only view cannot leave an external effect that requires rollback."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/projections/graph_api_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: getGraph",
            "OpenAPI operationId: graphReachable",
            "OpenAPI operationId: graphBlastRadius",
            "OpenAPI operationId: graphQuery",
            "CLI command: graph nodes",
            "CLI command: graph reachable",
            "CLI command: graph blast-radius",
            "CLI command: graph crypto-readiness",
            "CLI command: graph crypto-readiness actions create",
            "CLI command: graph crypto-readiness export",
            "CLI command: graph query"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F75",
    "feature": "Unified semantic query layer",
    "domain": "Graph, query, and AI",
    "phase": "P1",
    "priority": 39,
    "contract": {
      "purpose": "Lets an operator understand and safely use unified semantic query layer while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/assistant",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/assistant"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Assistant.tsx"
          ]
        },
        "preview": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/aisurface_served_test.go"
          ]
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/aisurface_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: aiQuery",
            "OpenAPI operationId: aiRCA",
            "OpenAPI operationId: graphQuery",
            "CLI command: ai query",
            "CLI command: ai rca",
            "CLI command: graph query"
          ]
        }
      },
      "owner": "platform",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F76",
    "feature": "Pluggable AI model adapter",
    "domain": "Graph, query, and AI",
    "phase": "P1",
    "priority": 40,
    "contract": {
      "purpose": "Lets an operator understand and safely use pluggable ai model adapter while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/assistant",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/assistant"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Assistant.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "missing",
          "reason": "No complete console execution path is proved for this capability."
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/aisurface_model_config_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: aiStatus",
            "OpenAPI operationId: aiQuery",
            "OpenAPI operationId: aiRCA",
            "CLI command: ai status",
            "CLI command: ai query",
            "CLI command: ai rca"
          ]
        }
      },
      "owner": "platform",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F77",
    "feature": "Grounded RCA and natural-language query",
    "domain": "Graph, query, and AI",
    "phase": "P1",
    "priority": 41,
    "contract": {
      "purpose": "Lets an operator understand and safely use grounded rca and natural-language query while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/assistant",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/assistant"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Assistant.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/server/aisurface_served_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/server/aisurface_served_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: aiRCA",
            "CLI command: ai rca"
          ]
        }
      },
      "owner": "platform",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F78",
    "feature": "trstctl MCP server",
    "domain": "Graph, query, and AI",
    "phase": "P1",
    "priority": 42,
    "contract": {
      "purpose": "Lets an operator understand and safely use trstctl mcp server while tenant, policy, and security authority remain on the server.",
      "tool": "platform_integrations",
      "classification": "supporting",
      "releaseBlocking": false,
      "consoleRoute": "/assistant",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/assistant"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [
        "Configuration, deployment, or edition prerequisite is named by the served capability evidence."
      ],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "complete",
          "evidence": [
            "web/src/pages/Assistant.tsx"
          ]
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "internal/api/aisurface_contract_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "internal/api/aisurface_contract_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: listMCPTools",
            "OpenAPI operationId: callMCPTool",
            "CLI command: mcp tools",
            "CLI command: mcp call"
          ]
        }
      },
      "owner": "platform",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  },
  {
    "featureId": "F79",
    "feature": "Privacy and data-subject controls",
    "domain": "Policy and governance",
    "phase": "P0",
    "priority": 83,
    "contract": {
      "purpose": "Lets an operator understand and safely use privacy and data-subject controls while tenant, policy, and security authority remain on the server.",
      "tool": "operations",
      "classification": "primary",
      "releaseBlocking": true,
      "consoleRoute": "/privacy",
      "navigationEntrypoints": [
        "tool navigation",
        "task search",
        "/privacy"
      ],
      "permissionAuthority": "internal/api route registry and feature authorization manifest",
      "edition": "core",
      "dependencies": [],
      "sideEffects": "mixed",
      "secretDataHandling": "Tenant-scoped operational metadata only; secret values and private-key bytes never enter this contract or its reports.",
      "maturity": "partial_workflow",
      "stages": {
        "discover": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "understand": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "configure": {
          "status": "missing",
          "reason": "No structured evidence proves an operator can configure every required prerequisite from this console journey."
        },
        "preview": {
          "status": "missing",
          "reason": "No exact, effect-free server preview is linked from this workflow."
        },
        "execute": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts",
            "docs/coverage_test.go"
          ]
        },
        "observe": {
          "status": "complete",
          "evidence": [
            "web/src/lib/navigation.ts"
          ]
        },
        "recover": {
          "status": "missing",
          "reason": "Failure recovery, retry, or rollback is not yet proved from this console journey."
        },
        "verify": {
          "status": "complete",
          "evidence": [
            "docs/coverage_test.go"
          ]
        },
        "automate": {
          "status": "complete",
          "evidence": [
            "OpenAPI operationId: erasePrivacySubject",
            "OpenAPI operationId: listPrivacySubjectErasures",
            "OpenAPI operationId: enforcePrivacyRetention",
            "OpenAPI operationId: listPrivacyRetentionRuns",
            "OpenAPI operationId: attestPrivacyArchiveErasure",
            "OpenAPI operationId: listPrivacyArchiveErasureAttestations",
            "OpenAPI operationId: exportPrivacySubject",
            "OpenAPI operationId: getPrivacyCatalog",
            "CLI command: privacy erasures erase",
            "CLI command: privacy erasures list",
            "CLI command: privacy retention run",
            "CLI command: privacy retention list",
            "CLI command: privacy archives attest",
            "CLI command: privacy archives list",
            "CLI command: privacy export",
            "CLI command: privacy catalog"
          ]
        }
      },
      "owner": "operations",
      "targetCheckpoint": "frontend-convergence",
      "candidateSHA": "73b871089f46e4cc9e95ca10473b9ae5872a53cd",
      "freshness": "2026-08-25"
    }
  }
] as const satisfies readonly CanonicalCapability[];

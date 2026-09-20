// SPDX-License-Identifier: BUSL-1.1

package perf

import "trstctl.com/trstctl/internal/perfcontract"

type HotPathSLO = perfcontract.HotPathSLO
type CapacityTier = perfcontract.CapacityTier
type ScaleOrchestrationPlan = perfcontract.ScaleOrchestrationPlan
type ScaleBand = perfcontract.ScaleBand
type ExecutionLane = perfcontract.ExecutionLane
type ShardPlan = perfcontract.ShardPlan
type BackpressureRule = perfcontract.BackpressureRule
type ScaleReleaseGate = perfcontract.ScaleReleaseGate
type ScaleUnitEconomics = perfcontract.ScaleUnitEconomics
type ScaleTenantIsolation = perfcontract.ScaleTenantIsolation
type ScaleDatastorePosture = perfcontract.ScaleDatastorePosture
type ScaleSignerPosture = perfcontract.ScaleSignerPosture
type ScaleProjectionPosture = perfcontract.ScaleProjectionPosture
type ActiveActiveIssuancePlan = perfcontract.ActiveActiveIssuancePlan
type IssuanceRegion = perfcontract.IssuanceRegion
type TenantWriteFence = perfcontract.TenantWriteFence
type RegionalIssuanceLane = perfcontract.RegionalIssuanceLane
type RegionalFailoverStep = perfcontract.RegionalFailoverStep

const (
	MeasurementArtifact     = perfcontract.MeasurementArtifact
	LiveMeasurementArtifact = perfcontract.LiveMeasurementArtifact
	SpineBurstArtifact      = perfcontract.SpineBurstArtifact
)

func HotPaths() []HotPathSLO {
	return perfcontract.HotPaths()
}

func CapacityTiers() []CapacityTier {
	return perfcontract.CapacityTiers()
}

func ScaleOrchestration(generatedAt string) ScaleOrchestrationPlan {
	return perfcontract.ScaleOrchestration(generatedAt)
}

func ActiveActiveIssuance(generatedAt string) ActiveActiveIssuancePlan {
	return perfcontract.ActiveActiveIssuance(generatedAt)
}

// SPDX-License-Identifier: BUSL-1.1

//go:build !trstctl_core

package main

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// AUD-1: the XREC rounds worker registered, hit a len(Schedules)==0 guard on its
// first tick, and blocked for the life of the process. Zero rounds ever ran, no
// witness was ever raised, and the served agreement report answered "0 open
// witnesses" forever — while a licensed operator watched a healthy worker sit in
// the runtime roster. There was no config key to populate schedules at all.

func TestReconcileSchedulesComeFromOperatorConfig(t *testing.T) {
	t.Parallel()
	got := reconcileSchedulesFromConfig(config.Reconcile{Schedules: []config.ReconcileSchedule{{
		TenantID: "t1", Cadence: "30m", Jitter: "2m", Liveness: "12h",
		Authorities: []config.ReconcileAuthority{{AuthorityID: "adcs"}, {AuthorityID: "vault"}},
	}}})
	if len(got) != 1 {
		t.Fatalf("schedules = %d, want 1.\n\n"+
			"Without this the rounds worker hits its empty-schedules guard on the first tick and "+
			"blocks forever: a registered, healthy-looking worker that compares nothing.", len(got))
	}
	if got[0].Cadence != 30*time.Minute || got[0].Jitter != 2*time.Minute {
		t.Fatalf("cadence/jitter = %v/%v, want the operator's values", got[0].Cadence, got[0].Jitter)
	}
	if len(got[0].Planes) != 2 {
		t.Fatalf("planes = %d, want both authorities", len(got[0].Planes))
	}
}

// A round with fewer than two authorities compares an authority to nothing. It
// must be DROPPED, not scheduled: it produces no witness and would make the
// served report claim collecting=true on a deployment that still compares
// nothing — which is the exact illusion AUD-1 is about.
func TestARoundWithNothingToCompareIsNotScheduled(t *testing.T) {
	t.Parallel()
	for _, s := range []config.ReconcileSchedule{
		{TenantID: "t1", Authorities: []config.ReconcileAuthority{{AuthorityID: "adcs"}}},
		{TenantID: "t1"},
		{Authorities: []config.ReconcileAuthority{{AuthorityID: "a"}, {AuthorityID: "b"}}},
		{TenantID: "t1", Authorities: []config.ReconcileAuthority{{AuthorityID: "adcs"}, {AuthorityID: "  "}}},
	} {
		if got := reconcileSchedulesFromConfig(config.Reconcile{Schedules: []config.ReconcileSchedule{s}}); len(got) != 0 {
			t.Fatalf("%+v was scheduled. Comparing an authority to itself is not reconciliation, "+
				"and scheduling it would make the agreement report say it is collecting while "+
				"nothing is compared", s)
		}
	}
}

// A zero cadence would busy-loop the scheduler and a zero liveness would make
// every authority instantly stale. Unparseable values take a sane default
// rather than zero.
func TestAnUnparseableCadenceDoesNotBusyLoopTheScheduler(t *testing.T) {
	t.Parallel()
	got := reconcileSchedulesFromConfig(config.Reconcile{Schedules: []config.ReconcileSchedule{{
		TenantID: "t1", Cadence: "not-a-duration", Liveness: "0s",
		Authorities: []config.ReconcileAuthority{{AuthorityID: "a"}, {AuthorityID: "b"}},
	}}})
	if len(got) != 1 {
		t.Fatal("the schedule was dropped for a bad duration; the authorities are still valid")
	}
	if got[0].Cadence <= 0 {
		t.Fatalf("cadence = %v; a zero cadence busy-loops the scheduler against a customer's "+
			"authorities", got[0].Cadence)
	}
	if got[0].Liveness <= 0 {
		t.Fatalf("liveness = %v; a zero liveness marks every authority instantly stale, so every "+
			"round would raise staleness witnesses that mean nothing", got[0].Liveness)
	}
}

// An absent config schedules nothing rather than panicking.
func TestNoReconcileConfigSchedulesNothing(t *testing.T) {
	t.Parallel()
	if got := reconcileSchedulesFromConfig(reconcileConfigOf(nil)); len(got) != 0 {
		t.Fatalf("a nil config produced %d schedules", len(got))
	}
}

// A124: a kmip source block becomes one KMIP source per authority id, with
// its TLS material, cap and opt-ins carried over; a vault block does not.
func TestReconcileKMIPSourcesFromConfig(t *testing.T) {
	kmipSource := &config.ReconcileAuthoritySource{Kind: config.ReconcileSourceKindKMIP, Address: " kmip.internal:5696 ",
		ServerName: "kmip.internal", CAFile: "/run/ca.pem", ClientCertFile: "/run/client.pem", ClientKeyFile: "/run/client-key.pem",
		MaxObjects: 250, AllowTLS12: true, AllowInsecureLoopback: true, PrivateEndpointCIDRs: []string{"10.20.0.0/16"}}
	got := reconcileKMIPSourcesFromConfig(config.Reconcile{Schedules: []config.ReconcileSchedule{
		{TenantID: "t1", Authorities: []config.ReconcileAuthority{{AuthorityID: "trstctl-ca"}, {AuthorityID: "kmip-hsm", Source: kmipSource}}},
		{TenantID: "t2", Authorities: []config.ReconcileAuthority{{AuthorityID: "trstctl-ca"}, {AuthorityID: "kmip-hsm", Source: kmipSource},
			{AuthorityID: "vault", Source: &config.ReconcileAuthoritySource{Kind: config.ReconcileSourceKindVault, Address: "https://vault.internal"}}}},
	}})
	if len(got) != 1 {
		t.Fatalf("kmip sources = %+v, want one for kmip-hsm", got)
	}
	ks := got[0]
	if ks.AuthorityID != "kmip-hsm" || ks.Address != "kmip.internal:5696" || ks.ServerName != "kmip.internal" ||
		ks.CAFile != "/run/ca.pem" || ks.ClientCertFile != "/run/client.pem" || ks.ClientKeyFile != "/run/client-key.pem" ||
		ks.MaxObjects != 250 || !ks.AllowTLS12 || !ks.AllowLoopback || len(ks.PrivateEndpointCIDRs) != 1 {
		t.Fatalf("kmip source = %+v", ks)
	}
}

// A218: ejbca, stepca and inventory source blocks become one source each per
// authority id, with their files, CA names, caps and egress carried over.
func TestReconcileCALedgerSourcesFromConfig(t *testing.T) {
	ejbca := &config.ReconcileAuthoritySource{Kind: config.ReconcileSourceKindEJBCA, Address: " https://ejbca.internal:8443 ",
		ServerName: "ejbca.internal", CAFile: "/run/ca.pem", ClientCertFile: "/run/client.pem", ClientKeyFile: "/run/client-key.pem",
		IssuerCertificatesFile: "/etc/ejbca-ca.pem", CANames: []string{"IssuingCA"}, PageSize: 250, MaxObjects: 900,
		AllowTLS12: true, PrivateEndpointCIDRs: []string{"10.20.0.0/16"}}
	stepca := &config.ReconcileAuthoritySource{Kind: config.ReconcileSourceKindStepCA, DSNFile: "/run/stepca.dsn",
		IssuerCertificatesFile: "/etc/stepca.pem", AllowInsecureLoopback: true}
	inventory := &config.ReconcileAuthoritySource{Kind: config.ReconcileSourceKindInventory, IssuerCertificatesFile: "/etc/ejbca-ca.pem"}
	c := config.Reconcile{Schedules: []config.ReconcileSchedule{
		{TenantID: "t1", Authorities: []config.ReconcileAuthority{{AuthorityID: "inventory-ejbca", Source: inventory}, {AuthorityID: "ejbca-prod", Source: ejbca}}},
		{TenantID: "t2", Authorities: []config.ReconcileAuthority{{AuthorityID: "inventory-ejbca", Source: inventory}, {AuthorityID: "ejbca-prod", Source: ejbca},
			{AuthorityID: "stepca-prod", Source: stepca}}},
	}}
	ejbcaSources := reconcileEJBCASourcesFromConfig(c)
	if len(ejbcaSources) != 1 {
		t.Fatalf("ejbca sources = %+v", ejbcaSources)
	}
	if es := ejbcaSources[0]; es.AuthorityID != "ejbca-prod" || es.Address != "https://ejbca.internal:8443" || es.ServerName != "ejbca.internal" ||
		es.CAFile != "/run/ca.pem" || es.ClientCertFile != "/run/client.pem" || es.ClientKeyFile != "/run/client-key.pem" ||
		es.IssuerCertificatesFile != "/etc/ejbca-ca.pem" || len(es.CANames) != 1 || es.PageSize != 250 || es.MaxCertificates != 900 ||
		!es.AllowTLS12 || es.AllowLoopback || len(es.PrivateEndpointCIDRs) != 1 {
		t.Fatalf("ejbca source = %+v", es)
	}
	stepcaSources := reconcileStepCASourcesFromConfig(c)
	if len(stepcaSources) != 1 || stepcaSources[0].DSNFile != "/run/stepca.dsn" || stepcaSources[0].IssuerCertificatesFile != "/etc/stepca.pem" ||
		!stepcaSources[0].AllowLoopback {
		t.Fatalf("stepca sources = %+v", stepcaSources)
	}
	inventories := reconcileInventoryAuthoritiesFromConfig(c)
	if len(inventories) != 1 || inventories[0].AuthorityID != "inventory-ejbca" || inventories[0].IssuerCertificatesFile != "/etc/ejbca-ca.pem" {
		t.Fatalf("inventory authorities = %+v", inventories)
	}
}

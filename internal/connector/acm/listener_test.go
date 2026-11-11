// SPDX-License-Identifier: BUSL-1.1

package acm_test

import (
	"context"
	"encoding/pem"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/acm/acmtest"
	"trstctl.com/trstctl/internal/pluginhost"
)

const listenerARN = "arn:aws:elasticloadbalancing:us-east-1:000000000000:listener/app/web/0123456789abcdef/fedcba9876543210"

func listenerPEM(label string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("acm-listener-leaf-" + label)})
}

func listenerKey(label string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("acm-listener-key-" + label)})
}

// A166-L2: a target that names its load balancer listener imports every deploy
// as a new ACM certificate tagged with its fingerprint and points the
// listener at it, so the predecessor stays in the account. A rollback points
// the listener back at the predecessor, found by its tag across pages and
// confirmed by reading it back, uploading nothing; a readback reports what the
// listener serves.
func TestListenerTargetRollsBackByRepointingTheListenerA166L2(t *testing.T) {
	srv := acmtest.New(accessKey, secretKey)
	defer srv.Close()
	elb := acmtest.NewELB(accessKey, secretKey, listenerARN)
	defer elb.Close()
	c := acm.New("us-east-1", acm.Credentials{AccessKeyID: accessKey, SecretAccessKey: []byte(secretKey)},
		acm.WithEndpoint(srv.URL()), acm.WithListener(listenerARN), acm.WithELBEndpoint(elb.URL()))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	labels := []string{"a", "b", "c", "d"}
	for _, label := range labels {
		if _, err := connector.Run(ctx, c, ops, connector.NewDeployment("web-listener", listenerPEM(label), listenerKey(label))); err != nil {
			t.Fatalf("deploy %s: %v", label, err)
		}
	}
	arns := srv.ARNs()
	if len(arns) != 4 || elb.Serving() != arns[3] || elb.Modifies() != 4 {
		t.Fatalf("after four deploys: %d certificates, listener on %q after %d changes; want four, the newest served", len(arns), elb.Serving(), elb.Modifies())
	}
	for i, arn := range arns {
		imported, _ := srv.Imported(arn)
		if imported.Tags[acm.FingerprintTag] != connector.CertificateFingerprint(listenerPEM(labels[i])) {
			t.Fatalf("certificate %s carries tags %v; want its fingerprint", arn, imported.Tags)
		}
	}
	installed, err := connector.RunReadback(ctx, c, ops, "web-listener")
	if err != nil || installed.Fingerprint != connector.CertificateFingerprint(listenerPEM("d")) || installed.ObjectName != arns[3] || !installed.Bound {
		t.Fatalf("readback before the rollback = %+v %v; want the newest", installed, err)
	}
	imports := srv.Calls()
	// The predecessor sits on the second page of ListCertificates.
	if _, err := connector.RunRollback(ctx, c, ops, connector.Rollback{Target: "web-listener", PredecessorFingerprint: connector.CertificateFingerprint(listenerPEM("c"))}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if elb.Serving() != arns[2] || srv.Calls() != imports {
		t.Fatalf("after the rollback the listener serves %q with %d imports (was %d); want %q and nothing uploaded", elb.Serving(), srv.Calls(), imports, arns[2])
	}
	installed, err = connector.RunReadback(ctx, c, ops, "web-listener")
	if err != nil || installed.Fingerprint != connector.CertificateFingerprint(listenerPEM("c")) {
		t.Fatalf("readback after the rollback = %+v %v; want the predecessor", installed, err)
	}

	// Tags are mutable: a certificate whose tag claims a predecessor it is not
	// is never pointed at.
	srv.SetTag(arns[0], acm.FingerprintTag, "0000")
	srv.SetTag(arns[1], acm.FingerprintTag, connector.CertificateFingerprint(listenerPEM("a")))
	_, err = connector.RunRollback(ctx, c, ops, connector.Rollback{Target: "web-listener", PredecessorFingerprint: connector.CertificateFingerprint(listenerPEM("a"))})
	if !errors.Is(err, connector.ErrNoPredecessorInstalled) || elb.Serving() != arns[2] {
		t.Fatalf("a rollback that only a lying tag could satisfy = %v, listener on %q; want ErrNoPredecessorInstalled and no change", err, elb.Serving())
	}
}

// An in-place target (no listener) re-imports under one ARN and keeps no
// predecessor, so it neither rolls back nor reads back, and only a listener
// target may reach the load balancer endpoint.
func TestInPlaceTargetHasNoRollbackOrReadbackA166L2(t *testing.T) {
	srv := acmtest.New(accessKey, secretKey)
	defer srv.Close()
	inPlace := acm.New("us-east-1", acm.Credentials{AccessKeyID: accessKey, SecretAccessKey: []byte(secretKey)}, acm.WithEndpoint(srv.URL()))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	if _, err := connector.RunRollback(ctx, inPlace, ops, connector.Rollback{Target: "arn:aws:acm:us-east-1:000000000000:certificate/x", PredecessorFingerprint: "aa"}); !errors.Is(err, connector.ErrRollbackNotConfigured) {
		t.Fatalf("in-place rollback = %v; want ErrRollbackNotConfigured", err)
	}
	if _, err := connector.RunReadback(ctx, inPlace, ops, "arn:aws:acm:us-east-1:000000000000:certificate/x"); !errors.Is(err, connector.ErrReadbackNotConfigured) {
		t.Fatalf("in-place readback = %v; want ErrReadbackNotConfigured", err)
	}
	if got := inPlace.Capabilities().PathPrefixes(pluginhost.CapNetDial); len(got) != 1 {
		t.Fatalf("an in-place target may dial %v; want the ACM endpoint alone", got)
	}
	listener := acm.New("us-east-1", acm.Credentials{AccessKeyID: accessKey, SecretAccessKey: []byte(secretKey)},
		acm.WithEndpoint(srv.URL()), acm.WithListener(listenerARN), acm.WithELBEndpoint("https://elb.example.test"))
	if got := listener.Capabilities().PathPrefixes(pluginhost.CapNetDial); len(got) != 2 || got[1] != "elb.example.test" {
		t.Fatalf("a listener target may dial %v; want the ACM and load balancer endpoints", got)
	}
}

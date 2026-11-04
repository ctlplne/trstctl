// SPDX-License-Identifier: BUSL-1.1

package awskms

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/reconcile/awskmstest"
)

// X4: every key in the Region comes back across ListKeys pages with its type,
// size and rotation status. Only a symmetric key KMS generated is asked for
// its rotation status; asymmetric and HMAC keys are not_supported without a
// call, a key pending deletion is unknown without a call, an AWS-managed key
// reports what KMS says, and nothing is ever changed.
func TestKeysReportTypeSizeAndRotationX4(t *testing.T) {
	stand := awskmstest.New("eu-west-1", "AKIAX4READER", "x4-unit-secret", 2)
	t.Cleanup(stand.Close)
	stand.Put(
		awskmstest.Key{ID: "k1-rotating", Spec: "SYMMETRIC_DEFAULT", State: "Enabled", Rotation: true},
		awskmstest.Key{ID: "k2-unrotated", Spec: "SYMMETRIC_DEFAULT", State: "Enabled"},
		awskmstest.Key{ID: "k3-rsa", Spec: "RSA_3072", State: "Enabled"},
		awskmstest.Key{ID: "k4-ec", Spec: "ECC_NIST_P384", State: "Disabled"},
		awskmstest.Key{ID: "k5-hmac", Spec: "HMAC_256", State: "Enabled"},
		awskmstest.Key{ID: "k6-aws-managed", Spec: "SYMMETRIC_DEFAULT", State: "Enabled", Manager: "AWS", Rotation: true},
		awskmstest.Key{ID: "k7-deleting", Spec: "SYMMETRIC_DEFAULT", State: "PendingDeletion"},
	)
	r, err := New(Config{Region: "eu-west-1", Endpoint: stand.URL(), AccessKeyID: "AKIAX4READER", SecretAccessKey: "x4-unit-secret", HTTPClient: stand.Client()})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 7 {
		t.Fatalf("keys = %+v", keys)
	}
	want := map[string]struct {
		alg      string
		bits     int
		rotation string
	}{
		"k1-rotating": {"AES", 256, RotationEnabled}, "k2-unrotated": {"AES", 256, RotationDisabled},
		"k3-rsa": {"RSA", 3072, RotationNotSupported}, "k4-ec": {"ECDSA", 384, RotationNotSupported},
		"k5-hmac": {"HMAC", 256, RotationNotSupported}, "k6-aws-managed": {"AES", 256, RotationEnabled},
		"k7-deleting": {"AES", 256, RotationUnknown},
	}
	for _, k := range keys {
		w, ok := want[k.KeyID]
		if !ok || k.Algorithm != w.alg || k.Bits != w.bits || k.Rotation.Status != w.rotation ||
			!strings.HasPrefix(k.ARN, "arn:aws:kms:eu-west-1:") || k.Created.IsZero() {
			t.Fatalf("key %s = %+v, want %+v", k.KeyID, k, w)
		}
		if k.Unrotated() != (k.KeyID == "k2-unrotated") {
			t.Fatalf("key %s unrotated = %v", k.KeyID, k.Unrotated())
		}
	}
	if stand.Calls("ListKeys") != 4 || stand.Calls("DescribeKey") != 7 || stand.Calls("GetKeyRotationStatus") != 3 {
		t.Fatalf("calls ListKeys=%d DescribeKey=%d GetKeyRotationStatus=%d", stand.Calls("ListKeys"), stand.Calls("DescribeKey"), stand.Calls("GetKeyRotationStatus"))
	}
	if stand.Mutations() != 0 || stand.Refused() != 0 {
		t.Fatalf("mutations=%d refused signatures=%d", stand.Mutations(), stand.Refused())
	}
}

// A refused rotation read leaves that key unknown with KMS's error code and
// the rest of the inventory intact; a refused list fails without echoing the
// response body.
func TestRotationRefusalIsUnknownAndListRefusalFailsX4(t *testing.T) {
	refuseList := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService."); {
		case op == "ListKeys" && refuseList:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"__type":"com.amazonaws.kms#AccessDeniedException","message":"User: arn:aws:iam::123456789012:user/x is not authorized"}`)
		case op == "ListKeys":
			_ = json.NewEncoder(w).Encode(map[string]any{"Keys": []map[string]string{{"KeyId": "k-sym"}}, "Truncated": false})
		case op == "DescribeKey":
			_ = json.NewEncoder(w).Encode(map[string]any{"KeyMetadata": map[string]any{"KeyId": "k-sym", "Arn": "arn:aws:kms:us-east-1:123456789012:key/k-sym",
				"KeySpec": "SYMMETRIC_DEFAULT", "KeyState": "Enabled", "KeyManager": "CUSTOMER", "Origin": "AWS_KMS", "CreationDate": 1.7e9, "Enabled": true}})
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"__type":"com.amazonaws.kms#AccessDeniedException"}`)
		}
	}))
	t.Cleanup(srv.Close)
	r, err := New(Config{Region: "us-east-1", Endpoint: srv.URL, AccessKeyID: "AKIAX4", SecretAccessKey: "s", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(t.Context())
	if err != nil || len(keys) != 1 || keys[0].Rotation.Status != RotationUnknown || keys[0].Rotation.Error != "AccessDeniedException" || keys[0].Unrotated() {
		t.Fatalf("keys = %+v err = %v", keys, err)
	}
	refuseList = true
	_, err = r.Keys(t.Context())
	if err == nil || !strings.Contains(err.Error(), "ListKeys: status 400 AccessDeniedException") || strings.Contains(err.Error(), "arn:aws") {
		t.Fatalf("err = %v", err)
	}
	if _, err := New(Config{Endpoint: srv.URL, AccessKeyID: "a", SecretAccessKey: "s"}); err == nil {
		t.Fatal("a reader without a region was built")
	}
}

func TestKeySpecAlgorithmX4(t *testing.T) {
	for spec, want := range map[string]struct {
		alg  string
		bits int
	}{
		"SYMMETRIC_DEFAULT": {"AES", 256}, "RSA_2048": {"RSA", 2048}, "RSA_4096": {"RSA", 4096}, "ECC_NIST_P256": {"ECDSA", 256},
		"ECC_NIST_P521": {"ECDSA", 521}, "ECC_SECG_P256K1": {"ECDSA", 256}, "HMAC_512": {"HMAC", 512}, "SM2": {"SM2", 256},
		"ML_DSA_65": {"ML-DSA", 0}, "SOMETHING_NEW": {"", 0},
	} {
		if alg, bits := KeySpecAlgorithm(spec); alg != want.alg || bits != want.bits {
			t.Fatalf("%s = %s %d", spec, alg, bits)
		}
	}
}

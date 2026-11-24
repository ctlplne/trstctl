// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"trstctl.com/trstctl/internal/cloudhttp"
)

type cr259MongoAdmin struct{ dropErr error }

func (a cr259MongoAdmin) CreateUser(context.Context, string, string, []byte, []MongoRole) error {
	return nil
}
func (a cr259MongoAdmin) SetUserPassword(context.Context, string, string, []byte) error {
	return nil
}
func (a cr259MongoAdmin) DropUser(context.Context, string, string) error { return a.dropErr }

func TestCR259MongoRevokeOnlyAcceptsTypedUserNotFound(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		missing bool
	}{
		{"dns failure", errors.New("lookup db.example.test: no such host"), false},
		{"unrelated server code", mongo.CommandError{Code: 13, Message: "not found in proxy"}, false},
		{"typed user absence", mongo.CommandError{Code: 11, Message: "UserNotFound"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &MongoBackend{admin: cr259MongoAdmin{dropErr: tc.err}, database: "app", usernamePrefix: "trstctl"}
			err := b.Revoke(context.Background(), "trstctl_reader_0123456789abcdef")
			if (err == nil) != tc.missing {
				t.Fatalf("Revoke returned %v; typed missing=%v", err, tc.missing)
			}
		})
	}
}

type cr259HTTPDoer func(*http.Request) (*http.Response, error)

func (f cr259HTTPDoer) Do(req *http.Request) (*http.Response, error) { return f(req) }

func TestCR259IAMRevokeOnlyAcceptsExactProviderErrorCode(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		missing    bool
	}{
		{"proxy 404", `proxy not found`, false},
		{"proxy XML", `<ProxyError><Code>NoSuchEntity</Code></ProxyError>`, false},
		{"message text", `<ErrorResponse><Error><Code>AccessDenied</Code><Message>NoSuchEntity</Message></Error></ErrorResponse>`, false},
		{"other code", `<ErrorResponse><Error><Code>XNotFound</Code></Error></ErrorResponse>`, false},
		{"exact code", `<ErrorResponse><Error><Code>NoSuchEntity</Code></Error></ErrorResponse>`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doer := cr259HTTPDoer(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			b, err := NewAWSIAMBackend(AWSIAMConfig{Region: "us-east-1", AccessKeyID: "fake-id", SecretAccessKey: []byte("fake-secret"), Endpoint: "https://iam.example.test", HTTPClient: doer})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			_, err = b.callService(context.Background(), map[string]string{"Action": "DeleteUser", "UserName": "trstctl_reader_0123456789abcdef"}, awsIAMService)
			if errors.Is(err, errAWSIAMMissing) != tc.missing {
				t.Fatalf("IAM error classified as missing=%v, want %v", errors.Is(err, errAWSIAMMissing), tc.missing)
			}
		})
	}
	if looksMissing(&cloudhttp.StatusError{StatusCode: http.StatusNotFound}) {
		t.Fatal("a bare proxy HTTP 404 was treated as proof of provider absence")
	}
}

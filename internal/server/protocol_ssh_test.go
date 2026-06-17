package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSSHIssueRejectsOverLimitJSONBody(t *testing.T) {
	p := &sshProtocol{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ssh/issue/user", bytes.NewReader(bytes.Repeat([]byte("x"), (1<<16)+1)))

	p.issue(true)(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit SSH issue status = %d, want 413", rec.Code)
	}
}

func TestSSHRevokeRejectsOverLimitJSONBody(t *testing.T) {
	p := &sshProtocol{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ssh/revoke", bytes.NewReader(bytes.Repeat([]byte("x"), (1<<16)+1)))

	p.revoke(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit SSH revoke status = %d, want 413", rec.Code)
	}
}

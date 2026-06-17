package bodylimit

import (
	"errors"
	"strings"
	"testing"
)

func TestReadAllRejectsOverLimitSuffix(t *testing.T) {
	body, err := ReadAll(strings.NewReader("abcde"), 4)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ReadAll error = %v, want ErrTooLarge", err)
	}
	if body != nil {
		t.Fatalf("ReadAll returned body %q for an over-limit input", body)
	}
}

func TestReadAllAcceptsExactLimit(t *testing.T) {
	body, err := ReadAll(strings.NewReader("abcd"), 4)
	if err != nil {
		t.Fatalf("ReadAll exact limit: %v", err)
	}
	if string(body) != "abcd" {
		t.Fatalf("ReadAll body = %q, want abcd", body)
	}
}

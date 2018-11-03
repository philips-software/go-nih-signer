package signer

import (
	"net/http"
	"testing"
	"time"
)

func fixedTime() time.Time {
	return time.Date(2018, 10, 1, 0, 0, 0, 0, time.UTC)
}

func expiredTime() time.Time {
	return fixedTime().Add(-time.Duration(3 * time.Hour))
}

func TestSigner(t *testing.T) {
	signer, _ := NewWithPrefixAndNowFunc("foo", "bar", "", fixedTime)
	req, _ := http.NewRequest("GET", "https://example.com/path", nil)

	signer.SignRequest(req)

	signedDate := req.Header.Get(SIGNED_DATE_HEADER)
	signature := req.Header.Get(AUTHORIZATION_HEADER)

	nowFormatted := fixedTime().UTC().Format(TIME_FORMAT)

	if signedDate != nowFormatted {
		t.Errorf("Signature mismatch: %s != %s", signedDate, nowFormatted)
	}
	if signature != "HmacSHA256;Credential:foo;SignedHeaders:SignedDate;Signature:mws6Zf5yd8e2dhiCR0fMVyaisvLliNNqnCWpyy1am08=" {
		t.Errorf("Invalid signture: %s", signature)
	}
}

func TestValidator(t *testing.T) {
	signer, _ := NewWithPrefixAndNowFunc("foo", "bar", "", fixedTime)
	req, _ := http.NewRequest("GET", "https://example.com/path", nil)

	signer.SignRequest(req)

	valid, err := signer.ValidateRequest(req)
	if !valid {
		t.Errorf("Validation failed: %s", err)
	}

	badSigner, _ := New("fooz", "baz")
	badSigner.SignRequest(req)
	valid, err = signer.ValidateRequest(req)
	if valid {
		t.Errorf("Expected validation to fail: %s", err)
	}

	expiredSigner, _ := NewWithPrefixAndNowFunc("foo", "bar", "", expiredTime)
	expiredSigner.SignRequest(req)
	valid, err = signer.ValidateRequest(req)
	if valid {
		t.Errorf("Expected validation to fail: %s", err)
	}
	if err != ErrSignatureExpired {
		t.Errorf("Expected ErrSignatureExpired")
	}
}

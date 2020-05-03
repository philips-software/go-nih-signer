package signer

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"strings"
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

	signedDate := req.Header.Get(HeaderSignedDate)
	signature := req.Header.Get(HeaderAuthorization)

	nowFormatted := fixedTime().UTC().Format(TimeFormat)

	if signedDate != nowFormatted {
		t.Errorf("Signature mismatch: %s != %s", signedDate, nowFormatted)
	}
	if signature != "HmacSHA256;Credential:foo;SignedHeaders:SignedDate;Signature:mws6Zf5yd8e2dhiCR0fMVyaisvLliNNqnCWpyy1am08=" {
		t.Errorf("Invalid signture: %s", signature)
	}
}

func TestMissingKeys(t *testing.T) {
	signer, err := NewWithPrefixAndNowFunc("foo", "", "", fixedTime)
	assert.Nil(t, signer)
	assert.Equal(t, ErrMissingShareSecret, err)
	signer, err = NewWithPrefixAndNowFunc("", "bar", "", fixedTime)
	assert.Nil(t, signer)
	assert.Equal(t, ErrMissingSharedKey, err)
}

func TestValidator(t *testing.T) {
	signer, _ := NewWithPrefixAndNowFunc("foo", "bar", "", fixedTime)
	req, _ := http.NewRequest("GET", "https://example.com/path", nil)

	signer.SignRequest(req)

	valid, err := signer.ValidateRequest(req)
	if !valid {
		t.Errorf("Validation failed: %s", err)
	}

	badSigner, _ := New("foo", "baz")
	badSigner.SignRequest(req)
	valid, err = signer.ValidateRequest(req)
	if err != ErrInvalidSignature {
		t.Errorf("Expected validation to fail: %s", err)
	}
	badCreds, _ := New("fooz", "bar")
	badCreds.SignRequest(req)
	valid, err = signer.ValidateRequest(req)
	if err != ErrInvalidCredential {
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

	signer.SignRequest(req)
	authSig := req.Header.Get(HeaderAuthorization)
	req.Header.Set(HeaderAuthorization, strings.Replace(authSig, AlgorithmName, "BogusAlg", 1))
	valid, err = signer.ValidateRequest(req)
	if valid {
		t.Errorf("Expected validation to fail")
	}
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature: %v", err)
	}
	req.Header.Set(HeaderAuthorization, authSig)
}

func TestMultiHeaders(t *testing.T) {
	signer, _ := New("foo", "bar",
		WithNowFunc(fixedTime),
		SignMethod(),
		SignParam(),
		SignHeaders("Api-Version"))
	req, _ := http.NewRequest("GET", "https://example.com/some/path", nil)
	req.Header.Add("Api-Version", "1")

	signer.SignRequest(req)

	valid, err := signer.ValidateRequest(req)
	assert.Nil(t, err)
	assert.True(t, valid)
	sig := req.Header.Get(HeaderAuthorization)
	parts := strings.Split(sig, ";")
	if !assert.Equal(t, 4, len(parts)) {
		return
	}
	assert.Equal(t, "SignedHeaders:SignedDate,Api-Version,param,method", parts[2])
}

func TestWithBody(t *testing.T) {
	signer, _ := New("foo", "bar",
		WithNowFunc(fixedTime),
		SignMethod(),
		SignParam(),
		SignBody())
	body := strings.NewReader("{}")
	req, _ := http.NewRequest("GET", "https://example.com/some/path", body)

	signer.SignRequest(req)

	valid, err := signer.ValidateRequest(req)
	if !valid {
		t.Errorf("Validation failed: %s", err)
	}
}

func TestGetSharedKey(t *testing.T) {
	signer, _ := New("someSharedKey", "bar",
		WithNowFunc(fixedTime),
		SignMethod(),
		SignParam(),
		SignBody())
	body := strings.NewReader("{}")
	req, _ := http.NewRequest("GET", "https://example.com/some/path", body)
	signer.SignRequest(req)

	sharedKey, err := GetSharedKey(req)
	assert.Nil(t, err)
	assert.Equal(t, "someSharedKey", sharedKey)
}

func TestWithExtraHeader(t *testing.T) {
	extraHeader := "X-Extra-Header"
	extraValue := "RonSwanson"

	signer, _ := New("someSharedKey", "bar",
		WithNowFunc(fixedTime))

	body := strings.NewReader("{}")
	req, _ := http.NewRequest("GET", "https://example.com/some/path", body)
	req.Header.Set(extraHeader, extraValue)

	signer.SignRequest(req, extraHeader)

	valid, err := signer.ValidateRequest(req)
	if !valid {
		t.Errorf("Validation failed: %s", err)
	}
}
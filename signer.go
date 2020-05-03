//Package signer provides an implementation of the HSDP API signing
//algorithm. It can sign standard Go http.Request
package signer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// Constants
const (
	LogTimeFormat       = "2006-01-02T15:04:05.000Z07:00"
	TimeFormat          = time.RFC3339
	HeaderAuthorization = "hsdp-api-signature"
	HeaderSignedDate    = "SignedDate"
	DefaultPrefix64     = "REhQV1M="
	AlgorithmName       = "HmacSHA256"
)

// Errors
var (
	ErrMissingSharedKey  = errors.New("missing shared key")
	ErrMissingShareSecret = errors.New("missing shared secret")
	ErrSignatureExpired  = errors.New("signature expired")
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrInvalidCredential = errors.New("invalid credential")
	ErrNotSupportedYet   = errors.New("missing implementation, please contact the author(s)")
	ErrInvalidNowFunc    = errors.New("invalid now function")
)

// Signer holds the configuration of a signer instance
type Signer struct {
	sharedKey    string
	sharedSecret string
	prefix       string
	nowFunc      NowFunc
	signBody     bool
	signMethod   bool
	signURI      bool
	signParam    bool
	signHeaders  []string
}

// SignBody includes body in the signature
func SignBody() func (*Signer) error {
	return func (s *Signer) error {
		s.signBody = true
		return nil
	}
}

// SignMethod includes body in the signature
func SignMethod() func (*Signer) error {
	return func (s *Signer) error {
		s.signMethod = true
		return nil
	}
}

// SignURI includes body in the signature
func SignURI() func (*Signer) error {
	return func (s *Signer) error {
		s.signURI = true
		return nil
	}
}

// SignParam includes body in the signature
func SignParam() func (*Signer) error {
	return func (s *Signer) error {
		s.signParam = true
		return nil
	}
}

// SignHeaders includes the headers if present
func SignHeaders(headers... string) func(*Signer) error {
	return func (s *Signer) error {
		s.signHeaders = headers
		return nil
	}
}

// WithNowFunc uses the nowFunc as the source of time
func WithNowFunc(nowFunc NowFunc) func(*Signer) error {
	return func(s *Signer) error {
		if nowFunc == nil {
			return ErrInvalidNowFunc
		}
		s.nowFunc = nowFunc
		return nil
	}
}

// Prefix sets the signing prefix
func Prefix(prefix string) func(*Signer) error {
	return func(s *Signer) error {
		s.prefix = prefix
		return nil
	}
}

// NowFunc is a time source
type NowFunc func() time.Time


// NewWithPrefixAndNowFunc create na instance of Signer, taking prefix and nowFunc as additional parameters
func NewWithPrefixAndNowFunc(sharedKey, sharedSecret, prefix string, nowFunc NowFunc) (*Signer, error) {
	return New(sharedKey, sharedSecret,
		Prefix(prefix),
		WithNowFunc(nowFunc))
}

// New creates an instance of Signer
func New(sharedKey, sharedSecret string, options ...func(*Signer)error) (*Signer, error) {
	if sharedKey == "" {
		return nil, ErrMissingSharedKey
	}
	if sharedSecret == "" {
		return nil, ErrMissingShareSecret
	}
	signer := &Signer{
		sharedKey:    sharedKey,
		sharedSecret: sharedSecret,
	}
	for _, o := range options {
		err := o(signer)
		if err != nil {
			return nil, err
		}
	}
	if signer.nowFunc == nil {
		signer.nowFunc = func() time.Time {
			return time.Now()
		}
	}
	if signer.prefix == "" {
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(DefaultPrefix64)))
		l, _ := base64.StdEncoding.Decode(decoded, []byte(DefaultPrefix64))
		signer.prefix = string(decoded[:l])
	}
	return signer, nil
}

// SignRequest signs a http.Request by
// adding an Authorization and SignedDate header
func (s *Signer) SignRequest(request *http.Request, withHeaders ...string) error {
	signTime := s.nowFunc().UTC().Format(TimeFormat)

	signParts := []string{HeaderSignedDate}
	signHeaders := append(withHeaders, s.signHeaders...)
	for _, header := range signHeaders {
		if request.Header.Get(header) != "" {
			signParts = append(signParts, header)
		}
	}
	if s.signParam {
		signParts = append(signParts, "param")
	}
	if s.signMethod {
		signParts = append(signParts, "method")
	}
	if s.signURI {
		signParts = append(signParts, "uri")
	}
	if s.signBody {
		signParts = append(signParts, "body")
	}
	signature, err := s.generateSignature(signTime, signParts, request)
	if err != nil {
		return err
	}

	signedHeaders := strings.Join(signParts, ",")
	authorization := AlgorithmName + ";" +
		"Credential:" + s.sharedKey + ";" +
		"SignedHeaders:" + signedHeaders + ";" +
		"Signature:" + signature

	request.Header.Set(HeaderSignedDate, signTime)
	request.Header.Set(HeaderAuthorization, authorization)
	return nil
}

func (s *Signer)generateSignature(signTime string, signParts []string, request *http.Request) (string, error){
	currentSeed := []byte("")
	currentKey := []byte(signTime)
	for _, h := range signParts {
		switch h {
		case HeaderSignedDate:
			continue
		case "method":
			currentSeed = []byte(request.Method)
		case "uri":
			currentSeed = []byte(request.RequestURI)
		case "param":
			currentSeed = []byte(request.Form.Encode())
		case "body":
			if request.Body != nil {
				data, err := ioutil.ReadAll(request.Body)
				if err != nil {
					return "", err
				}
				reader := ioutil.NopCloser(bytes.NewReader(data))
				request.Body = reader
				currentSeed = data
			} else {
				currentSeed = []byte("")
			}
		default:
			currentSeed = []byte(request.Header.Get(h))
		}
		currentKey = hash(currentSeed, currentKey)
	}
	seed1 := base64.StdEncoding.EncodeToString([]byte(currentKey))
	hashedSeed := hash([]byte(seed1), []byte(s.prefix+s.sharedSecret))

	signature := base64.StdEncoding.EncodeToString(hashedSeed)
	return signature, nil
}

// ValidateRequest validates a previously signed request
func (s *Signer) ValidateRequest(request *http.Request) (bool, error) {
	signature := request.Header.Get(HeaderAuthorization)
	signedDate := request.Header.Get(HeaderSignedDate)

	comps := strings.Split(signature, ";")
	if len(comps) < 4 || comps[0] != AlgorithmName {
		return false, ErrInvalidSignature
	}
	credential := strings.TrimPrefix(comps[1], "Credential:")
	if credential != s.sharedKey {
		return false, ErrInvalidCredential
	}
	signParts := strings.Split(strings.TrimPrefix(comps[2], "SignedHeaders:"), ",")

	signature, err := s.generateSignature(signedDate, signParts, request)
	if err != nil {
		return false, ErrInvalidSignature
	}
	receivedSignature := strings.TrimPrefix(comps[3], "Signature:")

	if signature != receivedSignature {
		return false, ErrInvalidSignature
	}

	now := s.nowFunc()
	signed, err := time.Parse(TimeFormat, signedDate)
	if err != nil || now.Sub(signed).Seconds() > 900 {
		return false, ErrSignatureExpired
	}
	return true, nil
}

func hash(data []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// GetSharedKey extracts the shared key from request
func GetSharedKey(request *http.Request) (string, error) {
	signature := request.Header.Get(HeaderAuthorization)

	comps := strings.Split(signature, ";")
	if len(comps) < 4 {
		return "", ErrInvalidSignature
	}
	credential := strings.TrimPrefix(comps[1], "Credential:")
	return credential, nil
}
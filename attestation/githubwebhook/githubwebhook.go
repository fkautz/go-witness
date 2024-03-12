package githubwebhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/in-toto/go-witness/attestation"
	"github.com/in-toto/go-witness/cryptoutil"
)

const (
	Name    = "github-webhook"
	Type    = "https://witness.dev/attestations/github-webhook/v0.1"
	RunType = attestation.PostProductRunType
)

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

type Attestor struct {
	Data json.RawMessage `json:"data"`

	webhookSecret     []byte
	webhookSecretFile string
	request           *http.Request
}

type Option func(*Attestor)

func WithWebhookSecret(secret []byte) Option {
	return func(a *Attestor) {
		a.webhookSecret = secret
	}
}

func WithWebhookSecretFile(secretFile string) Option {
	return func(a *Attestor) {
		a.webhookSecretFile = secretFile
	}
}

func WithRequest(r *http.Request) Option {
	return func(a *Attestor) {
		a.request = r
	}
}

func New(opts ...Option) *Attestor {
	a := &Attestor{}
	for _, opt := range opts {
		opt(a)
	}

	return a
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if a.request == nil {
		return errors.New("must provide a request")
	}

	secret, err := loadWebhookSecret(a.webhookSecretFile, a.webhookSecret)
	if err != nil {
		return err
	}

	webhookData, err := io.ReadAll(a.request.Body)
	if err != nil {
		return fmt.Errorf("could not read request body: %v", err)
	}

	expectedHmac := a.request.Header.Get("X-Hub-Signature-256")
	if len(expectedHmac) == 0 {
		return fmt.Errorf("did not find hmac signature from github")
	}

	if err := verifyWebhook(secret, webhookData, expectedHmac); err != nil {
		return fmt.Errorf("could not validate webhook: %v", err)
	}

	a.Data = webhookData
	return nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	// TODO
	return map[string]cryptoutil.DigestSet{}
}

func loadWebhookSecret(webhookSecretFile string, webhookSecret []byte) ([]byte, error) {
	if len(webhookSecretFile) > 0 {
		secret, err := os.ReadFile(webhookSecretFile)
		if err != nil {
			return nil, fmt.Errorf("could not read secret file: %v", err)
		}

		return secret, nil
	}

	if len(webhookSecret) > 0 {
		return []byte(webhookSecret), nil
	}

	return nil, errors.New("must provide a webhook secret or webhook secret file")
}

func verifyWebhook(secret []byte, data []byte, expected string) error {
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return err
	}

	mac := hmac.New(sha256.New, secret)
	_, err = mac.Write(data)
	if err != nil {
		return err
	}

	dataMac := mac.Sum(nil)
	if !hmac.Equal(dataMac, expectedBytes) {
		return errors.New("webhook mac did not match recieved mac")
	}

	return nil
}

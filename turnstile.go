package turnstile

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

// Verifier verifies Cloudflare issued Turnstile tokens with the siteverify endpoint
// as described here https://developers.cloudflare.com/turnstile/get-started/server-side-validation/.
//
// A verifier is safe for concurrent use by multiple goroutines.
type Verifier struct {
	secret   string
	client   *http.Client
	endpoint string
}

// NewVerifier returns an initialized Verifier. `secret` is the key obtained from cloudflare when creating the turnstile site.
// `httpClient` is used to post verification requests to the cloudflare endpoint, if nil, `http.DefaultClient` is used.
func NewVerifier(secret string, httpClient *http.Client) *Verifier {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	endpointURL := "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	return &Verifier{secret: secret, client: httpClient, endpoint: endpointURL}
}

type request struct {
	SecretKey      string `json:"secret"`
	Token          string `json:"response"`
	RemoteIP       string `json:"remoteip,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// Response is the response received from cloudflare siteverify endpoint.
type Response struct {
	Success     bool      `json:"success"`
	ErrorCodes  []string  `json:"error-codes"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	Action      string    `json:"action"`
	ClientData  string    `json:"cdata"`
}

// Verify verifies token with cloudflare. `remoteIP` and `idempotencyKey` are optional and omitted if empty.
func (v *Verifier) Verify(token, remoteIP, idempotencyKey string) (*Response, error) {
	var b bytes.Buffer
	p := request{v.secret, token, remoteIP, idempotencyKey}
	if err := json.NewEncoder(&b).Encode(p); err != nil {
		return nil, err
	}
	res, err := v.client.Post(v.endpoint, "application/json", &b)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	r := &Response{}
	if err := json.NewDecoder(res.Body).Decode(r); err != nil {
		return nil, err
	}
	return r, nil
}

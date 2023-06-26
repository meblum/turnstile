package turnstile

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestNewVerifier(t *testing.T) {
	customClient := &http.Client{}
	type args struct {
		secret     string
		httpClient *http.Client
	}
	tests := []struct {
		name string
		args args
		want *Verifier
	}{
		{"default client", args{"mySecret1", nil}, &Verifier{secret: "mySecret1", client: http.DefaultClient}},
		{"custom client", args{"mySecret2", customClient}, &Verifier{secret: "mySecret2", client: customClient}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewVerifier(tt.args.secret, tt.args.httpClient)
			if got.client != tt.want.client {
				t.Error("httpClientMismatch")
			}
			if got.secret != tt.want.secret {
				t.Errorf("NewVerifier() secret = %v, want %v", got.secret, tt.want.secret)
			}
		})
	}
}

func TestVerifier_Verify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.Token == "" {
			fmt.Fprint(w, `{ "success": false, "error-codes": [ "invalid-input-response" ], "messages": [] }`)
			return
		}
		fmt.Fprint(w, `{ "success": true,  "error-codes": [],  "challenge_ts": "2023-06-25T23:56:14.476Z",  "hostname": "example.com" }`)
	}))
	defer srv.Close()
	veri := &Verifier{endpoint: srv.URL, client: http.DefaultClient}

	tp, err := time.Parse(time.RFC3339, "2023-06-25T23:56:14.476Z")
	if err != nil {
		t.Error(err)
	}
	tests := []struct {
		name  string
		token string
		want  *Response
	}{
		{"valid token", "a", &Response{true, []string{}, tp, "example.com", "", ""}},
		{"invalid token", "", &Response{false, []string{"invalid-input-response"}, time.Time{}, "", "", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := veri.Verify(tt.token, "", "")
			if err != nil {
				t.Errorf("Verifier.Verify() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Verifier.Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

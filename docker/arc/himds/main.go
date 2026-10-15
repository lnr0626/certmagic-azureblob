// Command himds is a minimal emulator of the Azure Arc Connected Machine
// agent's Hybrid Instance Metadata Service, for testing managed identity auth.
//
// It implements the Arc challenge flow: a first request gets a 401 whose
// WWW-Authenticate header names a key file; the client reads the file and
// retries with "Authorization: Basic <contents>" to receive a token.
// Tokens are unsigned JWTs, which Azurite accepts with --oauth basic.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func jwt(aud string) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	now := time.Now()
	return enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." + enc(map[string]any{
		"aud": aud,
		"iss": "https://sts.windows.net/00000000-0000-0000-0000-000000000001/",
		"iat": now.Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"oid": "00000000-0000-0000-0000-000000000002",
		"sub": "00000000-0000-0000-0000-000000000002",
		"tid": "00000000-0000-0000-0000-000000000001",
	}) + "."
}

func main() {
	dir := os.Getenv("TOKEN_DIR")
	if dir == "" {
		dir = "/var/opt/azcmagent/tokens"
	}
	keyPath := filepath.Join(dir, "challenge.key")
	key := fmt.Sprintf("arc-test-key-%d", time.Now().UnixNano())

	http.HandleFunc("/metadata/identity/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s auth=%v", r.Method, r.URL.RequestURI(), r.Header.Get("Authorization") != "")
		if r.Header.Get("Metadata") != "true" || r.URL.Query().Get("api-version") != "2020-06-01" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resource := r.URL.Query().Get("resource")
		if r.Header.Get("Authorization") != "Basic "+key {
			w.Header().Set("WWW-Authenticate", "Basic realm="+keyPath)
			http.Error(w, "challenge", http.StatusUnauthorized)
			return
		}
		exp := time.Now().Add(time.Hour).Unix()
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": jwt(resource),
			"expires_on":   strconv.FormatInt(exp, 10),
			"resource":     resource,
			"token_type":   "Bearer",
		})
	})

	ln, err := net.Listen("tcp", ":40342")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(key), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("himds emulator listening on :40342, key file %s", keyPath)
	log.Fatal(http.Serve(ln, nil))
}

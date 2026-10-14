package certmagicazureblob

import (
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestLoggingStorageDoesNotExposeSecrets(t *testing.T) {
	secrets := []string{
		"super-secret-client-secret",
		"Endpoint=sb://conn-string-secret",
		"https://acct.blob.core.windows.net/c?sig=sas-secret",
		"encryption-key-secret",
	}
	s := &AzureBlobStorage{
		TenantID:         "tenant",
		ClientID:         "client",
		ClientSecret:     secrets[0],
		ConnectionString: secrets[1],
		ContainerSASURL:  secrets[2],
		EncryptionKey:    secrets[3],
		AccountURL:       "https://acct.blob.core.windows.net",
		Container:        "certs",
		Prefix:           "caddy",
	}

	core, logs := observer.New(zapcore.InfoLevel)
	zap.New(core).Info("cleaning storage unit", zap.Any("storage", s))

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("expected one log entry, got %d", len(entries))
	}
	fields := entries[0].ContextMap()["storage"]
	rendered := strings.Join(flatten(fields), " ")
	for _, secret := range secrets {
		if strings.Contains(rendered, secret) {
			t.Errorf("log output contains secret %q: %s", secret, rendered)
		}
	}
	for _, want := range []string{"certs", "caddy", "client", "acct.blob.core.windows.net"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("log output is missing %q: %s", want, rendered)
		}
	}
}

func flatten(v any) []string {
	m, ok := v.(map[string]any)
	if !ok {
		return []string{fmt.Sprint(v)}
	}
	var out []string
	for k, val := range m {
		out = append(out, k)
		out = append(out, flatten(val)...)
	}
	return out
}

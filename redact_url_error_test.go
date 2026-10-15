package certmagicazureblob

import (
	"context"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

const testSASSecret = "sig=SUPERSECRETSIGNATURE"

func TestInvalidSASURLErrorsDoNotLeakSignature(t *testing.T) {
	bad := "https://acct.blob.core.windows.net/c%zz?sv=2022&" + testSASSecret

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	s := &AzureBlobStorage{ContainerSASURL: bad}
	err := s.Provision(ctx)
	if err == nil {
		t.Fatal("expected error for malformed SAS URL")
	}
	if strings.Contains(err.Error(), "SUPERSECRET") {
		t.Fatalf("Provision error leaks SAS signature: %v", err)
	}
}

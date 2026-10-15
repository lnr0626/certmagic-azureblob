//go:build arc

package certmagicazureblob

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
)

// These tests run inside docker/arc/docker-compose.yml, which emulates an
// Azure Arc-enabled machine (see README "Azure Arc test").
func TestArcManagedIdentity(t *testing.T) {
	accountURL := os.Getenv("ARC_ACCOUNT_URL")
	if accountURL == "" || os.Getenv("IDENTITY_ENDPOINT") == "" || os.Getenv("IMDS_ENDPOINT") == "" {
		t.Skip("not running in the Arc emulation environment")
	}

	s := &AzureBlobStorage{
		Container:       fmt.Sprintf("arc-%d", time.Now().UnixNano()),
		ManagedIdentity: true,
		AccountURL:      accountURL,
		logger:          zap.NewNop(),
	}
	mode, err := s.detectAuthMode()
	if err != nil || mode != authManagedIdentity {
		t.Fatalf("detectAuthMode = %v, %v", mode, err)
	}
	s.client = NewManagedIdentityProvider(s.AccountURL, s.ClientID, false)
	t.Cleanup(s.releaseLocks)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.Store(ctx, "certs/example.com/cert.pem", []byte("arc")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := s.Load(ctx, "certs/example.com/cert.pem")
	if err != nil || string(got) != "arc" {
		t.Fatalf("Load = %q, %v", got, err)
	}
	if err := s.Lock(ctx, "arc-lock"); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := s.Unlock(ctx, "arc-lock"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

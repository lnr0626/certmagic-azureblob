package certmagicazureblob

import (
	"context"
	"strings"
	"testing"
)

func TestSASClientProvider_WrongContainer(t *testing.T) {
	p := &SASClientProvider{
		ContainerSASURL:   "https://sgcerts.blob.core.windows.net/staging-caddy-certs?sp=rwdl&sig=abc",
		ExpectedContainer: "staging-caddy-certs",
	}

	_, err := p.ContainerClient(context.Background(), "other-container")
	if err == nil {
		t.Fatal("expected error for wrong container name")
	}
	if !strings.Contains(err.Error(), "scoped to") {
		t.Errorf("error = %q, want to contain 'scoped to'", err.Error())
	}
}

func TestSASClientProvider_CorrectContainer(t *testing.T) {
	// Use a valid-looking SAS URL. The client won't connect, but it should
	// successfully create the client object.
	p := &SASClientProvider{
		ContainerSASURL:   "https://sgcerts.blob.core.windows.net/staging-caddy-certs?sp=rwdl&sv=2021-06-08&sig=fakesig",
		ExpectedContainer: "staging-caddy-certs",
	}

	client, err := p.ContainerClient(context.Background(), "staging-caddy-certs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}

	// Second call should return the cached client
	client2, err := p.ContainerClient(context.Background(), "staging-caddy-certs")
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if client != client2 {
		t.Error("expected cached client to be returned")
	}
}

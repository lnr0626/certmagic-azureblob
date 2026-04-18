// Package certmagicazureblob provides an Azure Blob Storage backend for CertMagic,
// enabling distributed TLS certificate management across a Caddy cluster.
package certmagicazureblob

import (
	"context"
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
)

// ClientProvider abstracts Azure Blob Storage client creation.
// Implement this interface to support different authentication methods
// (connection string, managed identity, SAS tokens, etc.).
type ClientProvider interface {
	// ContainerClient returns an Azure Blob container client for the given container name.
	// Implementations should cache or reuse clients where appropriate.
	ContainerClient(ctx context.Context, containerName string) (*container.Client, error)
}

// serviceClientBase provides shared ContainerClient logic for providers
// that authenticate via a service.Client. It handles lazy client creation,
// caching, and optional container auto-creation. Auth-method-specific
// providers embed this and supply an initServiceClient function.
type serviceClientBase struct {
	initServiceClient func() (*service.Client, error)
	skipEnsure        bool

	mu      sync.Mutex
	svc     *service.Client
	ensured map[string]bool
}

func (b *serviceClientBase) ContainerClient(ctx context.Context, containerName string) (*container.Client, error) {
	svc, err := b.getServiceClient()
	if err != nil {
		return nil, err
	}
	client := svc.NewContainerClient(containerName)

	if b.skipEnsure {
		return client, nil
	}

	// Only attempt container creation once per container name.
	b.mu.Lock()
	alreadyEnsured := b.ensured[containerName]
	if alreadyEnsured {
		b.mu.Unlock()
		return client, nil
	}

	// Drop lock during the network call to avoid holding a mutex across I/O.
	b.mu.Unlock()
	if err := ensureContainer(ctx, client); err != nil {
		return nil, err
	}
	b.mu.Lock()
	if b.ensured == nil {
		b.ensured = make(map[string]bool)
	}
	b.ensured[containerName] = true
	b.mu.Unlock()

	return client, nil
}

func (b *serviceClientBase) getServiceClient() (*service.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.svc != nil {
		return b.svc, nil
	}

	svc, err := b.initServiceClient()
	if err != nil {
		return nil, err
	}
	b.svc = svc
	return svc, nil
}

// ensureContainer creates the container if it doesn't already exist.
func ensureContainer(ctx context.Context, client *container.Client) error {
	_, err := client.Create(ctx, nil)
	if err != nil {
		// If the container already exists, that's fine.
		if isStorageError(err, "ContainerAlreadyExists") {
			return nil
		}
		return fmt.Errorf("creating container: %w", err)
	}
	return nil
}

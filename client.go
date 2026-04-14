// Package certmagicazureblob provides an Azure Blob Storage backend for CertMagic,
// enabling distributed TLS certificate management across a Caddy cluster.
package certmagicazureblob

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
)

// ClientProvider abstracts Azure Blob Storage client creation.
// Implement this interface to support different authentication methods
// (connection string, managed identity, SAS tokens, etc.).
type ClientProvider interface {
	// ContainerClient returns an Azure Blob container client for the given container name.
	// Implementations should cache or reuse clients where appropriate.
	ContainerClient(ctx context.Context, containerName string) (*container.Client, error)
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

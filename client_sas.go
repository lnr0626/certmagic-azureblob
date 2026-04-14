package certmagicazureblob

import (
	"context"
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
)

// SASClientProvider implements ClientProvider using a container-scoped SAS URL.
// This restricts access to a single container with only the permissions
// granted by the SAS token — no account-level access, no other containers.
type SASClientProvider struct {
	// ContainerSASURL is the full SAS URL for the container, e.g.:
	// https://<account>.blob.core.windows.net/<container>?<sas-params>
	ContainerSASURL string

	// ContainerName is the container name extracted from the SAS URL during provisioning.
	ContainerName string

	mu     sync.Mutex
	client *container.Client
}

func (p *SASClientProvider) ContainerClient(ctx context.Context, containerName string) (*container.Client, error) {
	if containerName != p.ContainerName {
		return nil, fmt.Errorf("container_sas_url is scoped to %q but plugin requested %q — SAS auth only supports a single container", p.ContainerName, containerName)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client != nil {
		return p.client, nil
	}

	client, err := container.NewClientWithNoCredential(p.ContainerSASURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating container client from SAS URL: %w", err)
	}
	p.client = client
	return client, nil
}

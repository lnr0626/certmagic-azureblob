package certmagicazureblob

import (
	"context"
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
)

// ServicePrincipalProvider implements ClientProvider using Azure AD service
// principal credentials (client ID, client secret, tenant ID). This is the
// recommended auth method for production deployments where managed identity
// is not available and you want to avoid long-lived connection strings.
type ServicePrincipalProvider struct {
	// AccountURL is the Azure Blob Storage service URL, e.g.:
	// https://<account>.blob.core.windows.net
	// Supports sovereign clouds, private endpoints, and Azurite.
	AccountURL string

	TenantID     string
	ClientID     string
	ClientSecret string

	SkipEnsure bool

	mu      sync.Mutex
	svc     *service.Client
	ensured map[string]bool
}

func (p *ServicePrincipalProvider) ContainerClient(ctx context.Context, containerName string) (*container.Client, error) {
	svc, err := p.getServiceClient()
	if err != nil {
		return nil, err
	}
	client := svc.NewContainerClient(containerName)

	if p.SkipEnsure {
		return client, nil
	}

	p.mu.Lock()
	alreadyEnsured := p.ensured[containerName]
	if alreadyEnsured {
		p.mu.Unlock()
		return client, nil
	}

	p.mu.Unlock()
	if err := ensureContainer(ctx, client); err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.ensured == nil {
		p.ensured = make(map[string]bool)
	}
	p.ensured[containerName] = true
	p.mu.Unlock()

	return client, nil
}

func (p *ServicePrincipalProvider) getServiceClient() (*service.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.svc != nil {
		return p.svc, nil
	}

	cred, err := azidentity.NewClientSecretCredential(p.TenantID, p.ClientID, p.ClientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("creating service principal credential: %w", err)
	}

	svc, err := service.NewClient(p.AccountURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating service client with service principal: %w", err)
	}
	p.svc = svc
	return svc, nil
}

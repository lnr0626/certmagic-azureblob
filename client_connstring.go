package certmagicazureblob

import (
	"context"
	"fmt"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
)

// ConnStringProvider implements ClientProvider using an Azure Storage connection string.
type ConnStringProvider struct {
	ConnectionString string
	SkipEnsure       bool

	mu        sync.Mutex
	service   *service.Client
	ensured   map[string]bool
}

func (p *ConnStringProvider) ContainerClient(ctx context.Context, containerName string) (*container.Client, error) {
	svc, err := p.getServiceClient()
	if err != nil {
		return nil, err
	}
	client := svc.NewContainerClient(containerName)

	if p.SkipEnsure {
		return client, nil
	}

	// Only attempt container creation once per container name.
	p.mu.Lock()
	alreadyEnsured := p.ensured[containerName]
	if alreadyEnsured {
		p.mu.Unlock()
		return client, nil
	}

	// Still under lock — serialize first-time container creation.
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

func (p *ConnStringProvider) getServiceClient() (*service.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.service != nil {
		return p.service, nil
	}

	svc, err := service.NewClientFromConnectionString(p.ConnectionString, nil)
	if err != nil {
		return nil, fmt.Errorf("creating service client from connection string: %w", err)
	}
	p.service = svc
	return svc, nil
}

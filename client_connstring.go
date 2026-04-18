package certmagicazureblob

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
)

// ConnStringProvider implements ClientProvider using an Azure Storage connection string.
type ConnStringProvider struct {
	serviceClientBase
	ConnectionString string
}

// NewConnStringProvider creates a ConnStringProvider with the given connection string.
func NewConnStringProvider(connectionString string, skipEnsure bool) *ConnStringProvider {
	p := &ConnStringProvider{ConnectionString: connectionString}
	p.skipEnsure = skipEnsure
	p.initServiceClient = func() (*service.Client, error) {
		svc, err := service.NewClientFromConnectionString(p.ConnectionString, nil)
		if err != nil {
			return nil, fmt.Errorf("creating service client from connection string: %w", err)
		}
		return svc, nil
	}
	return p
}

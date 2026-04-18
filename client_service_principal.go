package certmagicazureblob

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
)

// ServicePrincipalProvider implements ClientProvider using Azure AD service
// principal credentials (client ID, client secret, tenant ID). This is the
// recommended auth method for production deployments where managed identity
// is not available and you want to avoid long-lived connection strings.
type ServicePrincipalProvider struct {
	serviceClientBase

	// AccountURL is the Azure Blob Storage service URL, e.g.:
	// https://<account>.blob.core.windows.net
	// Supports sovereign clouds, private endpoints, and Azurite.
	AccountURL string

	TenantID     string
	ClientID     string
	ClientSecret string
}

// NewServicePrincipalProvider creates a ServicePrincipalProvider with the given credentials.
func NewServicePrincipalProvider(accountURL, tenantID, clientID, clientSecret string, skipEnsure bool) *ServicePrincipalProvider {
	p := &ServicePrincipalProvider{
		AccountURL:   accountURL,
		TenantID:     tenantID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	p.skipEnsure = skipEnsure
	p.initServiceClient = func() (*service.Client, error) {
		cred, err := azidentity.NewClientSecretCredential(p.TenantID, p.ClientID, p.ClientSecret, nil)
		if err != nil {
			return nil, fmt.Errorf("creating service principal credential: %w", err)
		}
		svc, err := service.NewClient(p.AccountURL, cred, nil)
		if err != nil {
			return nil, fmt.Errorf("creating service client with service principal: %w", err)
		}
		return svc, nil
	}
	return p
}

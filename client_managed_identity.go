package certmagicazureblob

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
)

// ManagedIdentityProvider implements ClientProvider using an Azure managed
// identity. This covers Azure VMs, App Service, AKS and Azure Arc-enabled
// servers (azidentity detects the Arc Connected Machine agent endpoint via
// IDENTITY_ENDPOINT and IMDS_ENDPOINT).
type ManagedIdentityProvider struct {
	serviceClientBase

	// AccountURL is the Azure Blob Storage service URL, e.g.:
	// https://<account>.blob.core.windows.net
	AccountURL string

	// ClientID optionally selects a user-assigned identity. Empty means the
	// system-assigned identity.
	ClientID string
}

// NewManagedIdentityProvider creates a ManagedIdentityProvider. clientID may be
// empty to use the system-assigned identity.
func NewManagedIdentityProvider(accountURL, clientID string, skipEnsure bool) *ManagedIdentityProvider {
	p := &ManagedIdentityProvider{AccountURL: accountURL, ClientID: clientID}
	p.skipEnsure = skipEnsure
	p.initServiceClient = func() (*service.Client, error) {
		var opts *azidentity.ManagedIdentityCredentialOptions
		if p.ClientID != "" {
			opts = &azidentity.ManagedIdentityCredentialOptions{ID: azidentity.ClientID(p.ClientID)}
		}
		cred, err := azidentity.NewManagedIdentityCredential(opts)
		if err != nil {
			return nil, fmt.Errorf("creating managed identity credential: %w", err)
		}
		svc, err := service.NewClient(p.AccountURL, cred, nil)
		if err != nil {
			return nil, fmt.Errorf("creating service client with managed identity: %w", err)
		}
		return svc, nil
	}
	return p
}

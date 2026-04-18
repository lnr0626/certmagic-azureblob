package certmagicazureblob

import (
	"context"
	"strings"
	"testing"
)

func TestServicePrincipalProvider_CreatesClient(t *testing.T) {
	p := &ServicePrincipalProvider{
		AccountURL:   "https://sgcerts.blob.core.windows.net",
		TenantID:     "fake-tenant-id",
		ClientID:     "fake-client-id",
		ClientSecret: "fake-client-secret",
		SkipEnsure:   true,
	}

	// The provider creates a client eagerly on first call.
	// With fake credentials, the client is still constructed — auth
	// only fails on the first real HTTP request (azidentity is lazy).
	client, err := p.ContainerClient(context.Background(), "my-container")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}

	// Second call should return the cached service client.
	client2, err := p.ContainerClient(context.Background(), "my-container")
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if client2 == nil {
		t.Fatal("expected non-nil cached client")
	}
}

func TestDetectAuthMode(t *testing.T) {
	tests := []struct {
		name     string
		storage  AzureBlobStorage
		wantMode authMode
		wantErr  string
	}{
		{
			name:    "no auth",
			storage: AzureBlobStorage{},
			wantErr: "auth method is required",
		},
		{
			name:     "connection string only",
			storage:  AzureBlobStorage{ConnectionString: "cs"},
			wantMode: authConnectionString,
		},
		{
			name:     "container SAS URL only",
			storage:  AzureBlobStorage{ContainerSASURL: "https://a.blob.core.windows.net/c?sig=x"},
			wantMode: authContainerSAS,
		},
		{
			name: "service principal complete",
			storage: AzureBlobStorage{
				TenantID:     "t",
				ClientID:     "c",
				ClientSecret: "s",
				AccountURL:   "https://a.blob.core.windows.net",
			},
			wantMode: authServicePrincipal,
		},
		{
			name: "service principal missing client_secret",
			storage: AzureBlobStorage{
				TenantID:   "t",
				ClientID:   "c",
				AccountURL: "https://a.blob.core.windows.net",
			},
			wantErr: "missing: client_secret",
		},
		{
			name: "service principal missing multiple fields",
			storage: AzureBlobStorage{
				TenantID: "t",
			},
			wantErr: "missing: client_id, client_secret, account_url",
		},
		{
			name: "connection string and SAS URL conflict",
			storage: AzureBlobStorage{
				ConnectionString: "cs",
				ContainerSASURL:  "https://a.blob.core.windows.net/c?sig=x",
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "connection string and service principal conflict",
			storage: AzureBlobStorage{
				ConnectionString: "cs",
				TenantID:         "t",
				ClientID:         "c",
				ClientSecret:     "s",
				AccountURL:       "https://a.blob.core.windows.net",
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "SAS URL and service principal conflict",
			storage: AzureBlobStorage{
				ContainerSASURL: "https://a.blob.core.windows.net/c?sig=x",
				TenantID:        "t",
				ClientID:        "c",
				ClientSecret:    "s",
				AccountURL:      "https://a.blob.core.windows.net",
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "all three auth methods conflict",
			storage: AzureBlobStorage{
				ConnectionString: "cs",
				ContainerSASURL:  "https://a.blob.core.windows.net/c?sig=x",
				TenantID:         "t",
				ClientID:         "c",
				ClientSecret:     "s",
				AccountURL:       "https://a.blob.core.windows.net",
			},
			wantErr: "mutually exclusive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, err := tt.storage.detectAuthMode()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mode != tt.wantMode {
				t.Errorf("mode = %d, want %d", mode, tt.wantMode)
			}
		})
	}
}

package certmagicazureblob

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(*testing.T, *AzureBlobStorage)
	}{
		{
			name: "full config",
			input: `azure_blob {
				connection_string "DefaultEndpointsProtocol=https;AccountName=test"
				encryption_key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
				container my-certs
				prefix staging
				lease_duration 45
				clean_lock_blobs
				create_container false
			}`,
			check: func(t *testing.T, s *AzureBlobStorage) {
				if s.ConnectionString != "DefaultEndpointsProtocol=https;AccountName=test" {
					t.Errorf("ConnectionString = %q", s.ConnectionString)
				}
				if s.Container != "my-certs" {
					t.Errorf("Container = %q", s.Container)
				}
				if s.EncryptionKey != "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" {
					t.Errorf("EncryptionKey = %q", s.EncryptionKey)
				}
				if s.Prefix != "staging" {
					t.Errorf("Prefix = %q", s.Prefix)
				}
				if s.LeaseDuration != 45 {
					t.Errorf("LeaseDuration = %d", s.LeaseDuration)
				}
				if !s.CleanLockBlobs {
					t.Error("CleanLockBlobs should be true")
				}
				if s.createContainer() {
					t.Error("createContainer() should be false")
				}
			},
		},
		{
			name: "minimal config",
			input: `azure_blob {
				connection_string "connstr"
			}`,
			check: func(t *testing.T, s *AzureBlobStorage) {
				if s.ConnectionString != "connstr" {
					t.Errorf("ConnectionString = %q", s.ConnectionString)
				}
				if s.Container != "" {
					t.Errorf("Container should be empty (default applied at provision), got %q", s.Container)
				}
				if s.CleanLockBlobs {
					t.Error("CleanLockBlobs should default to false")
				}
				if !s.createContainer() {
					t.Error("createContainer() should default to true")
				}
			},
		},
		{
			name: "missing auth method",
			input: `azure_blob {
				container my-certs
			}`,
			wantErr: true,
		},
		{
			name: "container_sas_url config",
			input: `azure_blob {
				container_sas_url "https://sgcerts.blob.core.windows.net/staging-caddy-certs?sp=rwdl&sig=abc"
			}`,
			check: func(t *testing.T, s *AzureBlobStorage) {
				if s.ContainerSASURL != "https://sgcerts.blob.core.windows.net/staging-caddy-certs?sp=rwdl&sig=abc" {
					t.Errorf("ContainerSASURL = %q", s.ContainerSASURL)
				}
				if s.ConnectionString != "" {
					t.Errorf("ConnectionString should be empty, got %q", s.ConnectionString)
				}
			},
		},
		{
			name:    "container_sas_url missing value",
			input:   "azure_blob {\n\tcontainer_sas_url\n}",
			wantErr: true,
		},
		{
			name: "both auth methods",
			input: `azure_blob {
				connection_string "connstr"
				container_sas_url "https://test.blob.core.windows.net/c?sig=x"
			}`,
			wantErr: true,
		},
		{
			name: "invalid lease duration low",
			input: `azure_blob {
				connection_string "connstr"
				lease_duration 10
			}`,
			wantErr: true,
		},
		{
			name: "invalid lease duration high",
			input: `azure_blob {
				connection_string "connstr"
				lease_duration 120
			}`,
			wantErr: true,
		},
		{
			name: "invalid lease duration non-integer",
			input: `azure_blob {
				connection_string "connstr"
				lease_duration 30x
			}`,
			wantErr: true,
		},
		{
			name: "invalid create_container value",
			input: `azure_blob {
				connection_string "connstr"
				create_container maybe
			}`,
			wantErr: true,
		},
		{
			name: "unknown option",
			input: `azure_blob {
				connection_string "connstr"
				unknown_option value
			}`,
			wantErr: true,
		},
		{
			name:    "connection_string missing value",
			input:   "azure_blob {\n\tconnection_string\n}",
			wantErr: true,
		},
		{
			name:    "container missing value",
			input:   "azure_blob {\n\tconnection_string \"cs\"\n\tcontainer\n}",
			wantErr: true,
		},
		{
			name:    "encryption_key missing value",
			input:   "azure_blob {\n\tconnection_string \"cs\"\n\tencryption_key\n}",
			wantErr: true,
		},
		{
			name:    "prefix missing value",
			input:   "azure_blob {\n\tconnection_string \"cs\"\n\tprefix\n}",
			wantErr: true,
		},
		{
			name:    "lease_duration missing value",
			input:   "azure_blob {\n\tconnection_string \"cs\"\n\tlease_duration\n}",
			wantErr: true,
		},
		{
			name:    "create_container missing value",
			input:   "azure_blob {\n\tconnection_string \"cs\"\n\tcreate_container\n}",
			wantErr: true,
		},
		{
			name: "service principal config",
			input: `azure_blob {
				tenant_id "my-tenant"
				client_id "my-client"
				client_secret "my-secret"
				account_url "https://myaccount.blob.core.windows.net"
				container my-certs
			}`,
			check: func(t *testing.T, s *AzureBlobStorage) {
				if s.TenantID != "my-tenant" {
					t.Errorf("TenantID = %q", s.TenantID)
				}
				if s.ClientID != "my-client" {
					t.Errorf("ClientID = %q", s.ClientID)
				}
				if s.ClientSecret != "my-secret" {
					t.Errorf("ClientSecret = %q", s.ClientSecret)
				}
				if s.AccountURL != "https://myaccount.blob.core.windows.net" {
					t.Errorf("AccountURL = %q", s.AccountURL)
				}
				if s.Container != "my-certs" {
					t.Errorf("Container = %q", s.Container)
				}
			},
		},
		{
			name: "service principal missing account_url",
			input: `azure_blob {
				tenant_id "t"
				client_id "c"
				client_secret "s"
			}`,
			wantErr: true,
		},
		{
			name: "service principal missing client_secret",
			input: `azure_blob {
				tenant_id "t"
				client_id "c"
				account_url "https://a.blob.core.windows.net"
			}`,
			wantErr: true,
		},
		{
			name: "service principal mixed with connection_string",
			input: `azure_blob {
				connection_string "connstr"
				tenant_id "t"
				client_id "c"
				client_secret "s"
				account_url "https://a.blob.core.windows.net"
			}`,
			wantErr: true,
		},
		{
			name: "service principal mixed with container_sas_url",
			input: `azure_blob {
				container_sas_url "https://a.blob.core.windows.net/c?sig=x"
				tenant_id "t"
				client_id "c"
				client_secret "s"
				account_url "https://a.blob.core.windows.net"
			}`,
			wantErr: true,
		},
		{
			name:    "tenant_id missing value",
			input:   "azure_blob {\n\ttenant_id\n}",
			wantErr: true,
		},
		{
			name:    "client_id missing value",
			input:   "azure_blob {\n\tclient_id\n}",
			wantErr: true,
		},
		{
			name:    "client_secret missing value",
			input:   "azure_blob {\n\tclient_secret\n}",
			wantErr: true,
		},
		{
			name:    "account_url missing value",
			input:   "azure_blob {\n\taccount_url\n}",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			s := new(AzureBlobStorage)
			err := s.UnmarshalCaddyfile(d)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, s)
			}
		})
	}
}

func TestLeaseDurationDefaults(t *testing.T) {
	s := &AzureBlobStorage{}
	if d := s.leaseDuration(); d != 30 {
		t.Errorf("default leaseDuration = %d, want 30", d)
	}

	s.LeaseDuration = 15
	if d := s.leaseDuration(); d != 15 {
		t.Errorf("leaseDuration(15) = %d, want 15", d)
	}

	s.LeaseDuration = 60
	if d := s.leaseDuration(); d != 60 {
		t.Errorf("leaseDuration(60) = %d, want 60", d)
	}

	// Out of range falls back to default.
	s.LeaseDuration = 5
	if d := s.leaseDuration(); d != 30 {
		t.Errorf("leaseDuration(5) = %d, want 30 (default)", d)
	}
}

func TestBlobNameWithPrefix(t *testing.T) {
	s := &AzureBlobStorage{}

	if got := s.blobName("foo/bar"); got != "foo/bar" {
		t.Errorf("blobName without prefix = %q", got)
	}

	s.Prefix = "pfx"
	if got := s.blobName("foo/bar"); got != "pfx/foo/bar" {
		t.Errorf("blobName with prefix = %q", got)
	}

	if got := s.stripPrefix("pfx/foo/bar"); got != "foo/bar" {
		t.Errorf("stripPrefix = %q", got)
	}
}

func TestLockBlobName(t *testing.T) {
	s := &AzureBlobStorage{}
	if got := s.lockBlobName("mylock"); got != "locks/mylock" {
		t.Errorf("lockBlobName = %q", got)
	}

	s.Prefix = "pfx"
	if got := s.lockBlobName("mylock"); got != "pfx/locks/mylock" {
		t.Errorf("lockBlobName with prefix = %q", got)
	}
}

func TestValidateMissingAuth(t *testing.T) {
	s := &AzureBlobStorage{}
	err := s.Validate()
	if err == nil {
		t.Fatal("expected error for empty auth")
	}
	if !strings.Contains(err.Error(), "auth method is required") {
		t.Errorf("error = %q, want to contain 'auth method is required'", err.Error())
	}
}

func TestValidateMutuallyExclusiveAuth(t *testing.T) {
	s := &AzureBlobStorage{
		ConnectionString: "connstr",
		ContainerSASURL:  "https://test.blob.core.windows.net/c?sig=x",
	}
	err := s.Validate()
	if err == nil {
		t.Fatal("expected error for both auth methods")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error = %q, want to contain 'mutually exclusive'", err.Error())
	}
}

func TestValidateBadEncryptionKey(t *testing.T) {
	s := &AzureBlobStorage{
		ConnectionString: "DefaultEndpointsProtocol=http;AccountName=fake",
		EncryptionKey:    "not-valid-hex",
	}
	err := s.Validate()
	if err == nil {
		t.Fatal("expected error for bad encryption key")
	}
	if !strings.Contains(err.Error(), "invalid encryption_key") {
		t.Errorf("error = %q, want to contain 'invalid encryption_key'", err.Error())
	}
}

func TestCertMagicStorage(t *testing.T) {
	s := &AzureBlobStorage{}
	storage, err := s.CertMagicStorage()
	if err != nil {
		t.Fatalf("CertMagicStorage: %v", err)
	}
	if storage != s {
		t.Error("CertMagicStorage should return self")
	}
}

func TestCleanupWithNoLocks(t *testing.T) {
	s := &AzureBlobStorage{}
	if err := s.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}

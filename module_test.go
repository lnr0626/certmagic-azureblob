package certmagicazureblob

import (
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
				container my-certs
				prefix staging
				lease_duration 45
			}`,
			check: func(t *testing.T, s *AzureBlobStorage) {
				if s.ConnectionString != "DefaultEndpointsProtocol=https;AccountName=test" {
					t.Errorf("ConnectionString = %q", s.ConnectionString)
				}
				if s.Container != "my-certs" {
					t.Errorf("Container = %q", s.Container)
				}
				if s.Prefix != "staging" {
					t.Errorf("Prefix = %q", s.Prefix)
				}
				if s.LeaseDuration != 45 {
					t.Errorf("LeaseDuration = %d", s.LeaseDuration)
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
			},
		},
		{
			name: "missing connection string",
			input: `azure_blob {
				container my-certs
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
			name: "unknown option",
			input: `azure_blob {
				connection_string "connstr"
				unknown_option value
			}`,
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

package certmagicazureblob

import (
	"fmt"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(new(AzureBlobStorage))
}

// AzureBlobStorage implements certmagic.Storage using Azure Blob Storage.
// It supports distributed locking via Azure Blob Leases, making it suitable
// for Caddy clusters that share TLS certificates.
type AzureBlobStorage struct {
	// ConnectionString is the Azure Storage connection string.
	ConnectionString string `json:"connection_string,omitempty"`

	// Container is the blob container name. Default: "caddy-certs".
	Container string `json:"container,omitempty"`

	// Prefix is an optional path prefix for all blob names within the container.
	Prefix string `json:"prefix,omitempty"`

	// LeaseDuration is the blob lease duration in seconds (15-60). Default: 30.
	LeaseDuration int32 `json:"lease_duration,omitempty"`

	client ClientProvider
	locks  sync.Map
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*AzureBlobStorage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.storage.azure_blob",
		New: func() caddy.Module { return new(AzureBlobStorage) },
	}
}

// Provision sets up the storage module. Called by Caddy after configuration is loaded.
func (s *AzureBlobStorage) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger()

	if s.Container == "" {
		s.Container = "caddy-certs"
	}

	s.client = &ConnStringProvider{
		ConnectionString: s.ConnectionString,
	}

	s.logger.Info("azure blob storage provisioned",
		zap.String("container", s.Container),
		zap.String("prefix", s.Prefix),
		zap.Int32("lease_duration", s.leaseDuration()),
	)

	return nil
}

// Cleanup releases all held locks and cleans up resources.
// Called by Caddy during shutdown.
func (s *AzureBlobStorage) Cleanup() error {
	s.releaseLocks()
	return nil
}

// CertMagicStorage returns the storage implementation. Required by Caddy's
// storage module interface.
func (s *AzureBlobStorage) CertMagicStorage() (certmagic.Storage, error) {
	return s, nil
}

// UnmarshalCaddyfile parses the Caddyfile configuration for this module.
//
//	storage azure_blob {
//	    connection_string {env.AZURE_STORAGE_CONNECTION_STRING}
//	    container          caddy-certs
//	    prefix             ""
//	    lease_duration     30
//	}
func (s *AzureBlobStorage) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the directive name

	for d.NextBlock(0) {
		switch d.Val() {
		case "connection_string":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.ConnectionString = d.Val()

		case "container":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.Container = d.Val()

		case "prefix":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.Prefix = d.Val()

		case "lease_duration":
			if !d.NextArg() {
				return d.ArgErr()
			}
			var dur int
			if _, err := fmt.Sscanf(d.Val(), "%d", &dur); err != nil {
				return d.Errf("invalid lease_duration: %v", err)
			}
			if dur < 15 || dur > 60 {
				return d.Errf("lease_duration must be between 15 and 60 seconds, got %d", dur)
			}
			s.LeaseDuration = int32(dur)

		default:
			return d.Errf("unrecognized option: %s", d.Val())
		}
	}

	if s.ConnectionString == "" {
		return d.Err("connection_string is required")
	}

	return nil
}

// Interface guards ensure compile-time compliance.
var (
	_ caddy.Module          = (*AzureBlobStorage)(nil)
	_ caddy.Provisioner     = (*AzureBlobStorage)(nil)
	_ caddy.CleanerUpper    = (*AzureBlobStorage)(nil)
	_ caddyfile.Unmarshaler = (*AzureBlobStorage)(nil)
	_ certmagic.Storage     = (*AzureBlobStorage)(nil)
)

package certmagicazureblob

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

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
	// --- Auth method 1: connection string (account-level access) ---

	// ConnectionString is the Azure Storage account connection string.
	// Provides account-level access. Mutually exclusive with other auth methods.
	ConnectionString string `json:"connection_string,omitempty"`

	// --- Auth method 2: container SAS URL (least-privilege) ---

	// ContainerSASURL is a container-scoped SAS URL for least-privilege access.
	// Restricts the plugin to a single container with only the permissions
	// granted by the SAS token. Mutually exclusive with other auth methods.
	// Example: https://<account>.blob.core.windows.net/<container>?<sas-params>
	ContainerSASURL string `json:"container_sas_url,omitempty"`

	// --- Auth method 3: service principal (Azure AD) ---

	// TenantID is the Azure AD tenant ID for service principal auth.
	TenantID string `json:"tenant_id,omitempty"`

	// ClientID is the Azure AD application (client) ID for service principal auth.
	ClientID string `json:"client_id,omitempty"`

	// ClientSecret is the Azure AD client secret for service principal auth.
	ClientSecret string `json:"client_secret,omitempty"`

	// AccountURL is the Azure Blob Storage service URL for service principal auth.
	// Example: https://<account>.blob.core.windows.net
	// Supports sovereign clouds, private endpoints, and Azurite.
	AccountURL string `json:"account_url,omitempty"`

	// --- Common options ---

	// EncryptionKey is an optional hex-encoded 32-byte AES-256-GCM key.
	EncryptionKey string `json:"encryption_key,omitempty"`

	// Container is the blob container name. Default: "caddy-certs".
	Container string `json:"container,omitempty"`

	// Prefix is an optional path prefix for all blob names within the container.
	Prefix string `json:"prefix,omitempty"`

	// LeaseDuration is the blob lease duration in seconds (15-60). Default: 30.
	LeaseDuration int32 `json:"lease_duration,omitempty"`

	// CleanLockBlobs deletes lock blobs after releasing the lease. Default: false.
	// When false, empty lock blobs accumulate in the locks/ prefix over time.
	// For most deployments, an Azure Blob lifecycle management policy is the
	// better cleanup approach — see README for details.
	CleanLockBlobs bool `json:"clean_lock_blobs,omitempty"`

	// CreateContainer controls whether the plugin auto-creates the blob container
	// on startup. Default: true. Set to false when the container is pre-provisioned
	// by infrastructure tooling, which allows tighter RBAC (no container-create
	// permission needed).
	CreateContainer *bool `json:"create_container,omitempty"`

	client ClientProvider
	locks  sync.Map
	logger *zap.Logger
}

// authMode identifies which authentication method is configured.
type authMode int

const (
	authNone             authMode = iota
	authConnectionString          // connection_string
	authContainerSAS              // container_sas_url
	authServicePrincipal          // tenant_id + client_id + client_secret + account_url
)

// detectAuthMode determines the configured auth method and returns an error
// if the configuration is invalid (no auth, multiple auth methods, or
// incomplete service principal fields). This is the single source of truth
// for auth validation — called from UnmarshalCaddyfile, Provision, and Validate.
func (s *AzureBlobStorage) detectAuthMode() (authMode, error) {
	hasConnStr := s.ConnectionString != ""
	hasSASURL := s.ContainerSASURL != ""
	hasSP := s.TenantID != "" || s.ClientID != "" || s.ClientSecret != "" || s.AccountURL != ""

	count := 0
	if hasConnStr {
		count++
	}
	if hasSASURL {
		count++
	}
	if hasSP {
		count++
	}

	if count == 0 {
		return authNone, fmt.Errorf("an auth method is required: use connection_string, container_sas_url, or service principal (tenant_id + client_id + client_secret + account_url)")
	}
	if count > 1 {
		return authNone, fmt.Errorf("connection_string, container_sas_url, and service principal auth are mutually exclusive — use exactly one")
	}

	if hasConnStr {
		return authConnectionString, nil
	}
	if hasSASURL {
		return authContainerSAS, nil
	}

	// Service principal — verify all required fields are present.
	var missing []string
	if s.TenantID == "" {
		missing = append(missing, "tenant_id")
	}
	if s.ClientID == "" {
		missing = append(missing, "client_id")
	}
	if s.ClientSecret == "" {
		missing = append(missing, "client_secret")
	}
	if s.AccountURL == "" {
		missing = append(missing, "account_url")
	}
	if len(missing) > 0 {
		return authNone, fmt.Errorf("service principal auth requires all of: tenant_id, client_id, client_secret, account_url (missing: %s)", strings.Join(missing, ", "))
	}
	return authServicePrincipal, nil
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

	// Resolve any Caddy placeholders (e.g. {env.VAR}) in config values.
	// This is a safety net — {$VAR} parse-time substitution is preferred
	// in Caddyfiles, but {env.VAR} should also work.
	repl := caddy.NewReplacer()
	s.ConnectionString = repl.ReplaceAll(s.ConnectionString, "")
	s.ContainerSASURL = repl.ReplaceAll(s.ContainerSASURL, "")
	s.TenantID = repl.ReplaceAll(s.TenantID, "")
	s.ClientID = repl.ReplaceAll(s.ClientID, "")
	s.ClientSecret = repl.ReplaceAll(s.ClientSecret, "")
	s.AccountURL = repl.ReplaceAll(s.AccountURL, "")
	s.EncryptionKey = repl.ReplaceAll(s.EncryptionKey, "")
	s.Container = repl.ReplaceAll(s.Container, "")
	s.Prefix = repl.ReplaceAll(s.Prefix, "")

	if s.Container == "" {
		s.Container = "caddy-certs"
	}

	// Re-validate after placeholder resolution (values may differ from parse-time).
	mode, err := s.detectAuthMode()
	if err != nil {
		return err
	}

	// When using SAS URL, extract the container name from the URL path
	// and validate it against any explicitly configured container name.
	if mode == authContainerSAS {
		parsed, err := url.Parse(s.ContainerSASURL)
		if err != nil {
			return fmt.Errorf("invalid container_sas_url: %w", err)
		}
		sasContainer := strings.TrimPrefix(parsed.Path, "/")
		if sasContainer == "" {
			return fmt.Errorf("container_sas_url must include a container path (e.g. https://account.blob.core.windows.net/container?sas)")
		}
		if s.Container != "caddy-certs" && s.Container != sasContainer {
			return fmt.Errorf("container %q does not match container in SAS URL %q — omit the container directive when using container_sas_url", s.Container, sasContainer)
		}
		s.Container = sasContainer
	}

	// Choose client provider based on auth method.
	switch mode {
	case authContainerSAS:
		s.client = &SASClientProvider{
			ContainerSASURL: s.ContainerSASURL,
			ContainerName:   s.Container,
		}
	case authServicePrincipal:
		s.client = &ServicePrincipalProvider{
			AccountURL:   s.AccountURL,
			TenantID:     s.TenantID,
			ClientID:     s.ClientID,
			ClientSecret: s.ClientSecret,
			SkipEnsure:   !s.createContainer(),
		}
	default:
		s.client = &ConnStringProvider{
			ConnectionString: s.ConnectionString,
			SkipEnsure:       !s.createContainer(),
		}
	}

	authMethodName := [...]string{"none", "connection_string", "container_sas_url", "service_principal"}
	s.logger.Info("azure blob storage provisioned",
		zap.String("container", s.Container),
		zap.String("prefix", s.Prefix),
		zap.String("auth_method", authMethodName[mode]),
		zap.Int32("lease_duration", s.leaseDuration()),
	)
	if s.encryptionEnabled() {
		s.logger.Info("azure blob storage client-side encryption enabled")
	}

	return nil
}

// Validate checks that the configuration is valid and Azure is reachable.
// Called by Caddy after Provision, before the module is used.
func (s *AzureBlobStorage) Validate() error {
	if _, err := s.detectAuthMode(); err != nil {
		return err
	}
	if _, err := s.parseEncryptionKey(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := s.containerClient(ctx)
	if err != nil {
		return fmt.Errorf("azure blob storage validation failed: %w", err)
	}
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
//	    connection_string  "{$AZURE_STORAGE_CONNECTION_STRING}"
//	    container_sas_url  "{$CADDY_CERTS_SAS_URL}"
//	    tenant_id          "{$AZURE_TENANT_ID}"
//	    client_id          "{$AZURE_CLIENT_ID}"
//	    client_secret      "{$AZURE_CLIENT_SECRET}"
//	    account_url        "https://myaccount.blob.core.windows.net"
//	    encryption_key     "{env.CADDY_CERT_ENCRYPTION_KEY}"
//	    container          caddy-certs
//	    prefix             ""
//	    lease_duration     30
//	    clean_lock_blobs
//	    create_container   false
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

		case "container_sas_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.ContainerSASURL = d.Val()

		case "tenant_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.TenantID = d.Val()

		case "client_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.ClientID = d.Val()

		case "client_secret":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.ClientSecret = d.Val()

		case "account_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.AccountURL = d.Val()

		case "container":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.Container = d.Val()

		case "encryption_key":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.EncryptionKey = d.Val()

		case "prefix":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.Prefix = d.Val()

		case "lease_duration":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid lease_duration %q: %v", d.Val(), err)
			}
			if dur < 15 || dur > 60 {
				return d.Errf("lease_duration must be between 15 and 60 seconds, got %d", dur)
			}
			s.LeaseDuration = int32(dur)

		case "clean_lock_blobs":
			s.CleanLockBlobs = true

		case "create_container":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val, err := strconv.ParseBool(d.Val())
			if err != nil {
				return d.Errf("invalid create_container %q: must be true or false", d.Val())
			}
			s.CreateContainer = &val

		default:
			return d.Errf("unrecognized option: %s", d.Val())
		}
	}

	if _, err := s.detectAuthMode(); err != nil {
		return d.Err(err.Error())
	}

	return nil
}

// Interface guards ensure compile-time compliance.
var (
	_ caddy.Module          = (*AzureBlobStorage)(nil)
	_ caddy.Provisioner     = (*AzureBlobStorage)(nil)
	_ caddy.Validator       = (*AzureBlobStorage)(nil)
	_ caddy.CleanerUpper    = (*AzureBlobStorage)(nil)
	_ caddyfile.Unmarshaler = (*AzureBlobStorage)(nil)
	_ certmagic.Storage     = (*AzureBlobStorage)(nil)
)

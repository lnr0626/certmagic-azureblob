# certmagic-azureblob

Azure Blob Storage backend for [CertMagic](https://github.com/caddyserver/certmagic) / [Caddy](https://caddyserver.com). Enables distributed TLS certificate management across a Caddy cluster using Azure Blob Storage for persistence and Azure Blob Leases for distributed locking.

## Features

- **Distributed storage** — certificates, keys, and ACME account data stored in Azure Blob Storage
- **Distributed locking** — Azure Blob Leases coordinate certificate renewals across cluster nodes
- **Crash recovery** — leases auto-expire (default 30s), so crashed nodes don't hold locks indefinitely
- **Directory semantics** — `Exists`, `Stat`, `Delete`, and `List` correctly handle both individual keys and directory prefixes
- **Caddy module** — registers as `caddy.storage.azure_blob` with full Caddyfile support

## Installation

Build a custom Caddy binary with this plugin using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/lnr0626/certmagic-azureblob
```

## Configuration

### Caddyfile

#### Using a connection string (account-level access)

```caddyfile
{
    storage azure_blob {
        connection_string {env.AZURE_STORAGE_CONNECTION_STRING}
        encryption_key    {env.CADDY_CERT_ENCRYPTION_KEY}
        container          caddy-certs
        prefix             production
        lease_duration     30
        clean_lock_blobs
        create_container   false
    }
}
```

#### Using a container SAS URL (least-privilege, recommended)

```caddyfile
{
    storage azure_blob {
        container_sas_url {env.CADDY_CERTS_SAS_URL}
        encryption_key    {env.CADDY_CERT_ENCRYPTION_KEY}
        container          staging-caddy-certs
        prefix             production
        lease_duration     30
    }
}
```

The `container_sas_url` option restricts access to a single container with only the
permissions granted by the SAS token. This is the recommended auth method when you
pre-provision the container via infrastructure tooling.

### JSON config

```json
{
  "storage": {
    "module": "azure_blob",
    "container_sas_url": "{env.CADDY_CERTS_SAS_URL}",
    "encryption_key": "{env.CADDY_CERT_ENCRYPTION_KEY}",
    "container": "staging-caddy-certs",
    "prefix": "production",
    "lease_duration": 30
  }
}
```

### Options

| Option | Default | Description |
|---|---|---|
| `connection_string` | *(none)* | Azure Storage account connection string. Mutually exclusive with `container_sas_url` |
| `container_sas_url` | *(none)* | Container-scoped SAS URL for least-privilege access. Mutually exclusive with `connection_string`. Recommended for production |
| `encryption_key` | *(none)* | Optional hex-encoded 32-byte AES-256-GCM key for client-side encryption |
| `container` | `caddy-certs` | Blob container name |
| `prefix` | *(none)* | Optional path prefix for all blob names within the container |
| `lease_duration` | `30` | Blob lease duration in seconds (15–60). Controls crash recovery time |
| `clean_lock_blobs` | `false` | Delete lock blobs after releasing the lease. See [Lock blob cleanup](#lock-blob-cleanup) |
| `create_container` | `true` | Auto-create the container on startup. Set to `false` when pre-provisioned by infra tooling (allows tighter RBAC) |

## How it works

### Storage

CertMagic keys (e.g., `certificates/acme-v02.api.letsencrypt.org-directory/example.com/example.com.crt`) are mapped directly to Azure blob names within the configured container. An optional prefix namespaces all blobs.

### Distributed locking

When CertMagic needs to acquire a lock (e.g., for certificate renewal), the plugin:

1. Creates a lock blob at `locks/{name}` (idempotent — skips if it already exists)
2. Acquires an Azure Blob Lease on the lock blob
3. Starts a background goroutine that renews the lease at 2/3 of the lease duration
4. On unlock, cancels the renewal goroutine and releases the lease

If a Caddy instance crashes, the lease expires automatically after `lease_duration` seconds, allowing another instance to acquire the lock.

### Lease duration tradeoffs

| Duration | Crash recovery time | Renewal safety margin |
|---|---|---|
| 15s | Fast (15s) | Tight (5s between renewals) |
| 30s (default) | Moderate (30s) | Comfortable (10s margin) |
| 60s | Slow (60s) | Very safe (20s margin) |

### Lock blob cleanup

The plugin creates empty blobs at `locks/{name}` to serve as lease targets. By default, these blobs are **not deleted** after the lease is released, which means they accumulate over time.

Two cleanup strategies are available:

#### Option 1: `clean_lock_blobs` (simple)

Set `clean_lock_blobs` in your Caddyfile or JSON config. The plugin will delete each lock blob immediately after releasing the lease. This adds one extra API call per unlock but keeps the container tidy.

> **Note:** If a Caddy instance crashes before unlocking, the lock blob will remain. This is harmless — the lease expires automatically and the blob will be cleaned up on the next successful lock/unlock cycle for that name.

#### Option 2: Azure Blob lifecycle management policy (recommended for production)

Use an Azure lifecycle management policy to automatically delete old lock blobs. This handles crash-orphaned blobs without any plugin-side logic:

```bash
az storage account management-policy create \
  --account-name caddycerts \
  --resource-group mygroup \
  --policy '{
    "rules": [{
      "enabled": true,
      "name": "cleanup-lock-blobs",
      "type": "Lifecycle",
      "definition": {
        "filters": {
          "blobTypes": ["blockBlob"],
          "prefixMatch": ["caddy-certs/locks/"]
        },
        "actions": {
          "baseBlob": {
            "delete": {
              "daysAfterModificationGreaterThan": 30
            }
          }
        }
      }
    }]
  }'
```

Adjust `prefixMatch` to include your container name and any configured `prefix` (e.g., `caddy-certs/production/locks/`).

## Azure setup

### Create a storage account

```bash
az storage account create \
  --name caddycerts \
  --resource-group mygroup \
  --location eastus \
  --sku Standard_LRS

# Get the connection string
az storage account show-connection-string \
  --name caddycerts \
  --resource-group mygroup \
  --output tsv
```

### Permissions

#### Connection string

The connection string provides account-level access. If `create_container` is `true` (the default), the identity also needs permission to create containers. For tighter RBAC, pre-create the container and set `create_container false`.

#### Container SAS URL (recommended)

A container SAS URL restricts access to a single container. Required SAS permissions:

- **Read** (`r`) — load certificates, keys, and lock blobs
- **Write** (`w`) — store certificates/keys, acquire/renew blob leases
- **Delete** (`d`) — delete certificates/keys, break blob leases
- **List** (`l`) — list blobs for directory semantics

Generate a SAS with a stored access policy for revocability:

```bash
# Create a stored access policy
az storage container policy create \
  --container-name caddy-certs \
  --account-name caddycerts \
  --name caddy-rw \
  --permissions rwdl \
  --expiry "$(date -u -v+2y '+%Y-%m-%dT%H:%M:%SZ')"

# Generate a SAS URL from the policy
ACCOUNT="caddycerts"
CONTAINER="caddy-certs"
SAS=$(az storage container generate-sas \
  --account-name "$ACCOUNT" \
  --name "$CONTAINER" \
  --policy-name caddy-rw \
  --https-only \
  -o tsv)
echo "https://${ACCOUNT}.blob.core.windows.net/${CONTAINER}?${SAS}"
```

Pre-create the container since SAS tokens can't create containers:

```bash
az storage container create \
  --name caddy-certs \
  --account-name caddycerts \
  --auth-mode login
```

## Testing

### Unit tests

```bash
go test -v ./...
```

### Integration tests (requires Azurite)

```bash
# Start Azurite
docker run -d -p 10000:10000 mcr.microsoft.com/azure-storage/azurite azurite-blob --blobHost 0.0.0.0

# Run integration tests
go test -tags integration -v ./...
```

Or with a real Azure Storage account:

```bash
AZURE_STORAGE_CONNECTION_STRING="..." go test -tags integration -v ./...
```

## License

MIT

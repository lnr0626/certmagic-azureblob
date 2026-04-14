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

```caddyfile
{
    storage azure_blob {
        connection_string {env.AZURE_STORAGE_CONNECTION_STRING}
        container          caddy-certs
        prefix             production
        lease_duration     30
    }
}

example.com {
    respond "Hello, TLS!"
}
```

### JSON config

```json
{
  "storage": {
    "module": "azure_blob",
    "connection_string": "{env.AZURE_STORAGE_CONNECTION_STRING}",
    "container": "caddy-certs",
    "prefix": "production",
    "lease_duration": 30
  }
}
```

### Options

| Option | Default | Description |
|---|---|---|
| `connection_string` | *(required)* | Azure Storage connection string |
| `container` | `caddy-certs` | Blob container name (created automatically if it doesn't exist) |
| `prefix` | *(none)* | Optional path prefix for all blob names within the container |
| `lease_duration` | `30` | Blob lease duration in seconds (15–60). Controls crash recovery time |

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

The connection string (or future auth method) needs:
- **Blob Data Contributor** role on the storage account or container
- Container create permissions (if auto-create is desired)

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

package certmagicazureblob

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func (s *AzureBlobStorage) blobName(key string) string {
	if s.Prefix != "" {
		return s.Prefix + "/" + key
	}
	return key
}

func (s *AzureBlobStorage) stripPrefix(name string) string {
	if s.Prefix != "" {
		return strings.TrimPrefix(name, s.Prefix+"/")
	}
	return name
}

func (s *AzureBlobStorage) containerClient(ctx context.Context) (*container.Client, error) {
	return s.client.ContainerClient(ctx, s.Container)
}

// Store puts value at key. It creates or overwrites the blob.
func (s *AzureBlobStorage) Store(ctx context.Context, key string, value []byte) error {
	cc, err := s.containerClient(ctx)
	if err != nil {
		return fmt.Errorf("getting container client: %w", err)
	}
	payload, err := s.encrypt(value)
	if err != nil {
		return fmt.Errorf("encrypting key %q: %w", key, err)
	}

	blobClient := cc.NewBlockBlobClient(s.blobName(key))
	_, err = blobClient.Upload(ctx, streaming.NopCloser(bytes.NewReader(payload)), &blockblob.UploadOptions{
		HTTPHeaders: &blob.HTTPHeaders{
			BlobContentType: ptr("application/octet-stream"),
		},
	})
	if err != nil {
		return fmt.Errorf("storing key %q: %w", key, err)
	}
	return nil
}

// Load retrieves the value at key.
func (s *AzureBlobStorage) Load(ctx context.Context, key string) ([]byte, error) {
	cc, err := s.containerClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting container client: %w", err)
	}

	blobClient := cc.NewBlobClient(s.blobName(key))
	resp, err := blobClient.DownloadStream(ctx, nil)
	if err != nil {
		if isBlobNotFound(err) {
			return nil, fs.ErrNotExist
		}
		return nil, fmt.Errorf("loading key %q: %w", key, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading key %q: %w", key, err)
	}
	return s.decryptLoadedValue(key, data)
}

func (s *AzureBlobStorage) decryptLoadedValue(key string, data []byte) ([]byte, error) {
	if !s.encryptionEnabled() {
		return data, nil
	}

	plaintext, err := s.decrypt(data)
	if err == nil {
		return plaintext, nil
	}

	if len(data) < minEncryptedBlobSize {
		if s.logger != nil {
			s.logger.Warn("encryption enabled but blob appears unencrypted; returning raw bytes",
				zap.String("key", key),
				zap.Int("size", len(data)),
			)
		}
		return data, nil
	}

	return nil, fmt.Errorf("decrypting key %q: %w", key, err)
}

// Delete removes the value at key. If the key is a prefix (directory),
// all keys under it are deleted. Delete is idempotent — deleting a
// non-existent key is not an error.
func (s *AzureBlobStorage) Delete(ctx context.Context, key string) error {
	cc, err := s.containerClient(ctx)
	if err != nil {
		return fmt.Errorf("getting container client: %w", err)
	}

	// First try to delete the exact blob.
	blobClient := cc.NewBlobClient(s.blobName(key))
	_, err = blobClient.Delete(ctx, nil)
	if err != nil && !isBlobNotFound(err) {
		return fmt.Errorf("deleting key %q: %w", key, err)
	}

	// Also delete all blobs under this prefix (directory semantics).
	prefix := s.blobName(key)
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	pager := cc.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{
		Prefix: &prefix,
	})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("listing keys for delete at %q: %w", key, err)
		}
		for _, item := range page.Segment.BlobItems {
			if item.Name != nil {
				child := cc.NewBlobClient(*item.Name)
				if _, err := child.Delete(ctx, nil); err != nil && !isBlobNotFound(err) {
					return fmt.Errorf("deleting child key %q: %w", *item.Name, err)
				}
			}
		}
	}

	return nil
}

// Exists returns true if the key exists as either a blob or a prefix (directory).
func (s *AzureBlobStorage) Exists(ctx context.Context, key string) bool {
	cc, err := s.containerClient(ctx)
	if err != nil {
		return false
	}

	// Check exact blob.
	blobClient := cc.NewBlobClient(s.blobName(key))
	_, err = blobClient.GetProperties(ctx, nil)
	if err == nil {
		return true
	}

	// Check if it's a prefix with children.
	prefix := s.blobName(key)
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	maxResults := int32(1)
	pager := cc.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{
		Prefix:     &prefix,
		MaxResults: &maxResults,
	})
	if pager.More() {
		page, listErr := pager.NextPage(ctx)
		if listErr != nil {
			// Log but don't fail — Exists should not error, best-effort false.
			return false
		}
		if len(page.Segment.BlobItems) > 0 {
			return true
		}
	}

	return false
}

// List returns all keys matching the given path prefix.
func (s *AzureBlobStorage) List(ctx context.Context, pathPrefix string, recursive bool) ([]string, error) {
	cc, err := s.containerClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting container client: %w", err)
	}

	prefix := s.blobName(pathPrefix)
	// Ensure prefix ends with / for directory-like listing
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	var keys []string

	if recursive {
		pager := cc.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{
			Prefix: &prefix,
		})
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("listing keys at %q: %w", pathPrefix, err)
			}
			for _, item := range page.Segment.BlobItems {
				if item.Name != nil {
					keys = append(keys, s.stripPrefix(*item.Name))
				}
			}
		}
	} else {
		// Non-recursive: use hierarchy listing with "/" delimiter
		delimiter := "/"
		pager := cc.NewListBlobsHierarchyPager(delimiter, &container.ListBlobsHierarchyOptions{
			Prefix: &prefix,
		})
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("listing keys at %q: %w", pathPrefix, err)
			}
			for _, item := range page.Segment.BlobItems {
				if item.Name != nil {
					keys = append(keys, s.stripPrefix(*item.Name))
				}
			}
			for _, pfx := range page.Segment.BlobPrefixes {
				if pfx.Name != nil {
					// Return directory prefixes without trailing slash
					name := strings.TrimSuffix(s.stripPrefix(*pfx.Name), "/")
					keys = append(keys, name)
				}
			}
		}
	}

	return keys, nil
}

// Stat returns information about the key. For prefix (directory) keys,
// it returns a non-terminal KeyInfo.
func (s *AzureBlobStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	cc, err := s.containerClient(ctx)
	if err != nil {
		return certmagic.KeyInfo{}, fmt.Errorf("getting container client: %w", err)
	}

	// Try exact blob first.
	blobClient := cc.NewBlobClient(s.blobName(key))
	props, err := blobClient.GetProperties(ctx, nil)
	if err == nil {
		info := certmagic.KeyInfo{
			Key:        key,
			IsTerminal: true,
		}
		if props.ContentLength != nil {
			info.Size = *props.ContentLength
		}
		if props.LastModified != nil {
			info.Modified = *props.LastModified
		}
		return info, nil
	}

	if !isBlobNotFound(err) {
		return certmagic.KeyInfo{}, fmt.Errorf("stat key %q: %w", key, err)
	}

	// Check if it's a prefix (directory).
	prefix := s.blobName(key)
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	maxResults := int32(1)
	pager := cc.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{
		Prefix:     &prefix,
		MaxResults: &maxResults,
	})
	if pager.More() {
		page, listErr := pager.NextPage(ctx)
		if listErr != nil {
			return certmagic.KeyInfo{}, fmt.Errorf("listing prefix for stat %q: %w", key, listErr)
		}
		if len(page.Segment.BlobItems) > 0 {
			return certmagic.KeyInfo{
				Key:        key,
				IsTerminal: false,
			}, nil
		}
	}

	return certmagic.KeyInfo{}, fs.ErrNotExist
}

// ptr returns a pointer to the given value.
func ptr[T any](v T) *T {
	return &v
}

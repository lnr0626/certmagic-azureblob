package certmagicazureblob

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"go.uber.org/zap"
)

const (
	migrationLockName = "encryption-migration"
	migrationTimeout  = 5 * time.Minute
)

// upgradeBlob returns raw re-encrypted in the current format, or changed=false
// if it already is. Anything that fails authentication is an error, never
// passed through.
func (s *AzureBlobStorage) upgradeBlob(key string, raw []byte) (upgraded []byte, changed bool, err error) {
	if bytes.HasPrefix(raw, encryptedBlobMagic) {
		return raw, false, nil
	}
	plaintext, err := s.decryptLoadedValue(key, raw)
	if err != nil {
		return nil, false, err
	}
	upgraded, err = s.encrypt(key, plaintext)
	if err != nil {
		return nil, false, err
	}
	return upgraded, true, nil
}

// runMigration rewrites every blob that is not in the current encrypted format.
// It holds a lock so only one instance migrates at a time, and each rewrite is
// conditional on the blob's ETag so a concurrent Store is never overwritten.
func (s *AzureBlobStorage) runMigration(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, migrationTimeout)
	defer cancel()

	if err := s.Lock(ctx, migrationLockName); err != nil {
		s.logger.Error("encryption migration: could not acquire lock", zap.Error(err))
		return
	}
	defer func() {
		unlockCtx, unlockCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer unlockCancel()
		if err := s.Unlock(unlockCtx, migrationLockName); err != nil {
			s.logger.Warn("encryption migration: releasing lock", zap.Error(err))
		}
	}()

	upgraded, current, failed, err := s.migrateAll(ctx)
	if err != nil {
		s.logger.Error("encryption migration aborted", zap.Error(err))
		return
	}
	s.logger.Info("encryption migration finished",
		zap.Int("upgraded", upgraded),
		zap.Int("already_current", current),
		zap.Int("failed", failed),
	)
	if failed == 0 {
		s.logger.Info("encryption migration complete: switch encryption_mode to strict")
	}
}

func (s *AzureBlobStorage) migrateAll(ctx context.Context) (upgraded, current, failed int, err error) {
	cc, err := s.containerClient(ctx)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("getting container client: %w", err)
	}

	prefix := s.blobName("")
	lockPrefix := s.lockBlobName("")
	pager := cc.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{Prefix: &prefix})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return upgraded, current, failed, fmt.Errorf("listing blobs: %w", err)
		}
		for _, item := range page.Segment.BlobItems {
			if item.Name == nil || strings.HasPrefix(*item.Name, lockPrefix) {
				continue
			}
			key := s.stripPrefix(*item.Name)
			changed, err := s.migrateBlob(ctx, cc, *item.Name, key)
			switch {
			case err != nil:
				failed++
				s.logger.Error("encryption migration: blob not upgraded", zap.String("key", key), zap.Error(err))
			case changed:
				upgraded++
			default:
				current++
			}
		}
	}
	return upgraded, current, failed, nil
}

func (s *AzureBlobStorage) migrateBlob(ctx context.Context, cc *container.Client, name, key string) (bool, error) {
	blobClient := cc.NewBlockBlobClient(name)
	resp, err := blobClient.DownloadStream(ctx, nil)
	if err != nil {
		if isBlobNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("downloading: %w", err)
	}
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return false, fmt.Errorf("reading: %w", err)
	}

	upgraded, changed, err := s.upgradeBlob(key, raw)
	if err != nil || !changed {
		return false, err
	}

	_, err = blobClient.Upload(ctx, streaming.NopCloser(bytes.NewReader(upgraded)), &blockblob.UploadOptions{
		HTTPHeaders: &blob.HTTPHeaders{BlobContentType: ptr("application/octet-stream")},
		AccessConditions: &blob.AccessConditions{
			ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfMatch: (*azcore.ETag)(resp.ETag)},
		},
	})
	if err != nil {
		if isStorageError(err, "ConditionNotMet") {
			// Changed since we read it: a concurrent Store has already written it.
			return false, nil
		}
		return false, fmt.Errorf("uploading: %w", err)
	}
	return true, nil
}

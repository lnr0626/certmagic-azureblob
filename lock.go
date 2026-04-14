package certmagicazureblob

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/lease"
	"go.uber.org/zap"
)

// lockState tracks an active distributed lock backed by an Azure Blob Lease.
type lockState struct {
	leaseID string
	cancel  context.CancelFunc
	done    chan struct{} // closed when the renewal goroutine exits
}

// Lock acquires a distributed lock for the given name. It blocks until the lock
// is acquired or the context is cancelled. The lock is maintained by a background
// goroutine that renews the underlying blob lease periodically.
func (s *AzureBlobStorage) Lock(ctx context.Context, name string) error {
	cc, err := s.containerClient(ctx)
	if err != nil {
		return fmt.Errorf("getting container client for lock: %w", err)
	}

	lockBlob := s.lockBlobName(name)

	// Ensure the lock blob exists (idempotent).
	blobClient := cc.NewBlockBlobClient(lockBlob)
	_, err = blobClient.Upload(ctx, streaming.NopCloser(bytes.NewReader([]byte{})), &blockblob.UploadOptions{
		AccessConditions: &blob.AccessConditions{
			ModifiedAccessConditions: &blob.ModifiedAccessConditions{
				IfNoneMatch: ptr(azcore.ETagAny),
			},
		},
	})
	if err != nil && !isStorageError(err, "BlobAlreadyExists") {
		// ConditionNotMet means the blob already exists, which is fine.
		if !isStorageError(err, "ConditionNotMet") {
			return fmt.Errorf("creating lock blob %q: %w", name, err)
		}
	}

	// Acquire lease with retry loop.
	leaseClient, err := lease.NewBlobClient(cc.NewBlobClient(lockBlob), nil)
	if err != nil {
		return fmt.Errorf("creating lease client for %q: %w", name, err)
	}

	duration := s.leaseDuration()
	var leaseID string

	backoff := 500 * time.Millisecond
	maxBackoff := 5 * time.Second

	for {
		resp, err := leaseClient.AcquireLease(ctx, duration, nil)
		if err == nil {
			if resp.LeaseID == nil || *resp.LeaseID == "" {
				return fmt.Errorf("acquired lease for %q but received empty lease ID", name)
			}
			leaseID = *resp.LeaseID
			break
		}

		if !isLeaseConflict(err) {
			return fmt.Errorf("acquiring lock %q: %w", name, err)
		}

		// Lease is held by another instance — wait and retry.
		s.logger.Debug("lock contention, retrying",
			zap.String("lock", name),
			zap.Duration("backoff", backoff),
		)

		jitter := time.Duration(rand.Int64N(int64(backoff / 4)))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff + jitter):
		}

		backoff = min(backoff*2, maxBackoff)
	}

	// Start background lease renewal.
	renewCtx, renewCancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	ls := &lockState{
		leaseID: leaseID,
		cancel:  renewCancel,
		done:    done,
	}
	s.locks.Store(name, ls)

	go s.renewLease(renewCtx, leaseClient, name, done)

	s.logger.Debug("lock acquired", zap.String("lock", name), zap.String("lease_id", leaseID))
	return nil
}

// Unlock releases a previously acquired lock.
func (s *AzureBlobStorage) Unlock(ctx context.Context, name string) error {
	val, ok := s.locks.LoadAndDelete(name)
	if !ok {
		return fmt.Errorf("no active lock for %q", name)
	}

	ls := val.(*lockState)

	// Stop the renewal goroutine and wait for it to exit.
	ls.cancel()
	<-ls.done

	// Release the lease. Create a new lease client with the lease ID
	// so the SDK includes it in the release request.
	cc, err := s.containerClient(ctx)
	if err != nil {
		return fmt.Errorf("getting container client for unlock: %w", err)
	}

	leaseClient, err := lease.NewBlobClient(cc.NewBlobClient(s.lockBlobName(name)), &lease.BlobClientOptions{
		LeaseID: &ls.leaseID,
	})
	if err != nil {
		return fmt.Errorf("creating lease client for unlock %q: %w", name, err)
	}

	_, err = leaseClient.ReleaseLease(ctx, nil)
	if err != nil {
		// If the lease already expired or was lost, that's fine — another instance can proceed.
		if isStorageError(err, "LeaseNotPresentWithLeaseOperation") ||
			isStorageError(err, "LeaseLost") ||
			isBlobNotFound(err) {
			s.logger.Debug("lease already gone during release",
				zap.String("lock", name),
				zap.Error(err),
			)
			return nil
		}
		return fmt.Errorf("releasing lease for %q: %w", name, err)
	}

	s.logger.Debug("lock released", zap.String("lock", name))
	return nil
}

// renewLease periodically renews the lease to keep the lock alive.
// It runs until the context is cancelled (via Unlock). If renewals fail
// repeatedly, it logs a warning that the lock may be lost.
func (s *AzureBlobStorage) renewLease(ctx context.Context, leaseClient *lease.BlobClient, name string, done chan struct{}) {
	defer close(done)

	// Renew at ~2/3 of the lease duration to have a comfortable safety margin.
	renewInterval := time.Duration(s.leaseDuration()) * time.Second * 2 / 3

	ticker := time.NewTicker(renewInterval)
	defer ticker.Stop()

	consecutiveFailures := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, err := leaseClient.RenewLease(ctx, nil)
			if err != nil {
				if ctx.Err() != nil {
					return // context cancelled during unlock
				}
				consecutiveFailures++
				if consecutiveFailures >= 2 {
					s.logger.Warn("lease renewal failing, lock may be lost",
						zap.String("lock", name),
						zap.Int("consecutive_failures", consecutiveFailures),
						zap.Error(err),
					)
				} else {
					s.logger.Error("failed to renew lease",
						zap.String("lock", name),
						zap.Error(err),
					)
				}
			} else {
				if consecutiveFailures > 0 {
					s.logger.Info("lease renewal recovered",
						zap.String("lock", name),
						zap.Int("previous_failures", consecutiveFailures),
					)
				}
				consecutiveFailures = 0
			}
		}
	}
}

func (s *AzureBlobStorage) lockBlobName(name string) string {
	return s.blobName("locks/" + name)
}

func (s *AzureBlobStorage) leaseDuration() int32 {
	if s.LeaseDuration >= 15 && s.LeaseDuration <= 60 {
		return s.LeaseDuration
	}
	return 30
}

// releaseLocks releases all held locks. Called during cleanup/shutdown.
func (s *AzureBlobStorage) releaseLocks() {
	var wg sync.WaitGroup
	s.locks.Range(func(key, value any) bool {
		name := key.(string)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := s.Unlock(ctx, name); err != nil {
				s.logger.Warn("failed to release lock during cleanup",
					zap.String("lock", name),
					zap.Error(err),
				)
			}
		}()
		return true
	})
	wg.Wait()
}

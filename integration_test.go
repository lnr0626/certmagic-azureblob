//go:build integration

package certmagicazureblob

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// These tests require Azurite (Azure Storage Emulator) running locally:
//
//	docker run -p 10000:10000 mcr.microsoft.com/azure-storage/azurite azurite-blob --blobHost 0.0.0.0
//
// Run with: go test -tags integration -v ./...

const azuriteConnString = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"

func connString() string {
	if cs := os.Getenv("AZURE_STORAGE_CONNECTION_STRING"); cs != "" {
		return cs
	}
	return azuriteConnString
}

func testStorage(t *testing.T) *AzureBlobStorage {
	t.Helper()
	s := &AzureBlobStorage{
		Container: fmt.Sprintf("test-%d", time.Now().UnixNano()),
		client: &ConnStringProvider{
			ConnectionString: connString(),
		},
		logger: zap.NewNop(),
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.releaseLocks()
		// Best-effort container cleanup.
		cc, err := s.containerClient(ctx)
		if err == nil {
			cc.Delete(ctx, nil)
		}
	})
	return s
}

func TestStoreAndLoad(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	key := "certs/example.com/cert.pem"
	value := []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

	if err := s.Store(ctx, key, value); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, err := s.Load(ctx, key)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != string(value) {
		t.Errorf("Load = %q, want %q", got, value)
	}
}

func TestLoadNotFound(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	_, err := s.Load(ctx, "nonexistent/key")
	if err != fs.ErrNotExist {
		t.Errorf("Load nonexistent = %v, want fs.ErrNotExist", err)
	}
}

func TestExists(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	key := "certs/example.com/cert.pem"
	if s.Exists(ctx, key) {
		t.Error("Exists before Store = true, want false")
	}

	if err := s.Store(ctx, key, []byte("data")); err != nil {
		t.Fatalf("Store: %v", err)
	}

	if !s.Exists(ctx, key) {
		t.Error("Exists after Store = false, want true")
	}

	// Prefix/directory should also "exist".
	if !s.Exists(ctx, "certs/example.com") {
		t.Error("Exists for prefix = false, want true")
	}
	if !s.Exists(ctx, "certs") {
		t.Error("Exists for root prefix = false, want true")
	}
}

func TestDeleteExact(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	key := "certs/example.com/cert.pem"
	if err := s.Store(ctx, key, []byte("data")); err != nil {
		t.Fatalf("Store: %v", err)
	}

	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if s.Exists(ctx, key) {
		t.Error("Exists after Delete = true, want false")
	}
}

func TestDeletePrefix(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	keys := []string{
		"certs/example.com/cert.pem",
		"certs/example.com/key.pem",
		"certs/example.com/meta.json",
		"certs/other.com/cert.pem",
	}
	for _, k := range keys {
		if err := s.Store(ctx, k, []byte("data")); err != nil {
			t.Fatalf("Store %q: %v", k, err)
		}
	}

	// Delete the entire example.com directory.
	if err := s.Delete(ctx, "certs/example.com"); err != nil {
		t.Fatalf("Delete prefix: %v", err)
	}

	for _, k := range keys[:3] {
		if s.Exists(ctx, k) {
			t.Errorf("Exists(%q) after prefix delete = true, want false", k)
		}
	}
	// other.com should be untouched.
	if !s.Exists(ctx, "certs/other.com/cert.pem") {
		t.Error("other.com cert deleted by prefix delete")
	}
}

func TestDeleteIdempotent(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	// Deleting a non-existent key should not error.
	if err := s.Delete(ctx, "nonexistent/key"); err != nil {
		t.Errorf("Delete nonexistent = %v, want nil", err)
	}
}

func TestListFlat(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	keys := []string{
		"certs/example.com/cert.pem",
		"certs/example.com/key.pem",
		"certs/other.com/cert.pem",
	}
	for _, k := range keys {
		if err := s.Store(ctx, k, []byte("data")); err != nil {
			t.Fatalf("Store %q: %v", k, err)
		}
	}

	// Recursive list of all certs.
	all, err := s.List(ctx, "certs", true)
	if err != nil {
		t.Fatalf("List recursive: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("List recursive got %d items, want 3: %v", len(all), all)
	}

	// Non-recursive list at certs/ should return directory prefixes.
	top, err := s.List(ctx, "certs", false)
	if err != nil {
		t.Fatalf("List non-recursive: %v", err)
	}
	if len(top) != 2 {
		t.Errorf("List non-recursive got %d items, want 2 (example.com, other.com): %v", len(top), top)
	}
}

func TestStat(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	key := "certs/example.com/cert.pem"
	data := []byte("certificate data")
	if err := s.Store(ctx, key, data); err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Stat a terminal key.
	info, err := s.Stat(ctx, key)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !info.IsTerminal {
		t.Error("Stat.IsTerminal = false, want true")
	}
	if info.Size != int64(len(data)) {
		t.Errorf("Stat.Size = %d, want %d", info.Size, len(data))
	}

	// Stat a directory prefix.
	info, err = s.Stat(ctx, "certs/example.com")
	if err != nil {
		t.Fatalf("Stat prefix: %v", err)
	}
	if info.IsTerminal {
		t.Error("Stat prefix.IsTerminal = true, want false")
	}

	// Stat a non-existent key.
	_, err = s.Stat(ctx, "nonexistent")
	if err != fs.ErrNotExist {
		t.Errorf("Stat nonexistent = %v, want fs.ErrNotExist", err)
	}
}

func TestStoreOverwrite(t *testing.T) {
	s := testStorage(t)
	ctx := context.Background()

	key := "certs/example.com/cert.pem"
	if err := s.Store(ctx, key, []byte("v1")); err != nil {
		t.Fatalf("Store v1: %v", err)
	}
	if err := s.Store(ctx, key, []byte("v2")); err != nil {
		t.Fatalf("Store v2: %v", err)
	}

	got, err := s.Load(ctx, key)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != "v2" {
		t.Errorf("Load after overwrite = %q, want %q", got, "v2")
	}
}

func TestPrefix(t *testing.T) {
	s := testStorage(t)
	s.Prefix = "myprefix"
	ctx := context.Background()

	key := "certs/example.com/cert.pem"
	if err := s.Store(ctx, key, []byte("data")); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, err := s.Load(ctx, key)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != "data" {
		t.Errorf("Load = %q, want %q", got, "data")
	}

	// Verify the blob is actually stored with prefix.
	if s.blobName(key) != "myprefix/"+key {
		t.Errorf("blobName = %q, want %q", s.blobName(key), "myprefix/"+key)
	}
}

func TestLockUnlock(t *testing.T) {
	s := testStorage(t)
	s.LeaseDuration = 15 // Use minimum for faster tests.
	ctx := context.Background()

	name := "test-lock"
	if err := s.Lock(ctx, name); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	if err := s.Unlock(ctx, name); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

func TestLockContention(t *testing.T) {
	s1 := testStorage(t)
	s1.LeaseDuration = 15
	s2 := &AzureBlobStorage{
		Container: s1.Container,
		client:    s1.client,
		logger:    zap.NewNop(),
		LeaseDuration: 15,
	}

	ctx := context.Background()
	name := "contention-lock"

	// s1 acquires the lock.
	if err := s1.Lock(ctx, name); err != nil {
		t.Fatalf("s1.Lock: %v", err)
	}

	// s2 should block then acquire after s1 releases.
	var wg sync.WaitGroup
	wg.Add(1)
	var s2Err error
	go func() {
		defer wg.Done()
		s2Err = s2.Lock(ctx, name)
	}()

	// Give s2 a moment to start contending, then release s1's lock.
	time.Sleep(1 * time.Second)
	if err := s1.Unlock(ctx, name); err != nil {
		t.Fatalf("s1.Unlock: %v", err)
	}

	wg.Wait()
	if s2Err != nil {
		t.Fatalf("s2.Lock after s1.Unlock: %v", s2Err)
	}

	// Clean up s2's lock.
	if err := s2.Unlock(ctx, name); err != nil {
		t.Fatalf("s2.Unlock: %v", err)
	}
}

func TestLockContextCancellation(t *testing.T) {
	s1 := testStorage(t)
	s1.LeaseDuration = 15
	s2 := &AzureBlobStorage{
		Container: s1.Container,
		client:    s1.client,
		logger:    zap.NewNop(),
		LeaseDuration: 15,
	}

	ctx := context.Background()
	name := "cancel-lock"

	// s1 acquires the lock.
	if err := s1.Lock(ctx, name); err != nil {
		t.Fatalf("s1.Lock: %v", err)
	}
	defer s1.Unlock(ctx, name)

	// s2 tries to acquire with a short timeout — should fail.
	ctx2, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	err := s2.Lock(ctx2, name)
	if err == nil {
		s2.Unlock(ctx, name)
		t.Fatal("s2.Lock should have failed with context deadline")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("s2.Lock error = %v, want context.DeadlineExceeded", err)
	}
}

func TestLockAutoExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test in short mode")
	}

	s1 := testStorage(t)
	s1.LeaseDuration = 15
	s2 := &AzureBlobStorage{
		Container: s1.Container,
		client:    s1.client,
		logger:    zap.NewNop(),
		LeaseDuration: 15,
	}

	ctx := context.Background()
	name := "expiry-lock"

	// s1 acquires the lock then we kill its renewal (simulating a crash).
	if err := s1.Lock(ctx, name); err != nil {
		t.Fatalf("s1.Lock: %v", err)
	}
	val, _ := s1.locks.LoadAndDelete(name)
	ls := val.(*lockState)
	ls.cancel()
	<-ls.done

	// Wait for the lease to expire.
	t.Log("waiting for lease to expire (15s)...")
	time.Sleep(16 * time.Second)

	// s2 should be able to acquire now.
	if err := s2.Lock(ctx, name); err != nil {
		t.Fatalf("s2.Lock after expiry: %v", err)
	}
	if err := s2.Unlock(ctx, name); err != nil {
		t.Fatalf("s2.Unlock: %v", err)
	}
}

func TestUnlockAfterLeaseExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test in short mode")
	}

	s := testStorage(t)
	s.LeaseDuration = 15
	ctx := context.Background()
	name := "unlock-expired-lock"

	// Acquire the lock, then kill renewal to simulate crash.
	if err := s.Lock(ctx, name); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	val, _ := s.locks.Load(name)
	ls := val.(*lockState)
	ls.cancel()
	<-ls.done

	// Wait for the lease to expire.
	t.Log("waiting for lease to expire (15s)...")
	time.Sleep(16 * time.Second)

	// Unlock after expiry should succeed (not return an error).
	if err := s.Unlock(ctx, name); err != nil {
		t.Errorf("Unlock after lease expiry should return nil, got: %v", err)
	}
}

func TestLockRenewalKeepsLockAlive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow test in short mode")
	}

	s1 := testStorage(t)
	s1.LeaseDuration = 15
	s2 := &AzureBlobStorage{
		Container:     s1.Container,
		client:        s1.client,
		logger:        zap.NewNop(),
		LeaseDuration: 15,
	}

	ctx := context.Background()
	name := "renewal-lock"

	// s1 acquires a 15s lease. Hold it for 20s (beyond a single lease duration).
	if err := s1.Lock(ctx, name); err != nil {
		t.Fatalf("s1.Lock: %v", err)
	}

	t.Log("holding lock for 20s (beyond 15s lease duration)...")
	time.Sleep(20 * time.Second)

	// s2 should NOT be able to acquire — renewal should have kept s1's lock alive.
	ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := s2.Lock(ctx2, name)
	if err == nil {
		s2.Unlock(ctx, name)
		t.Fatal("s2 acquired lock while s1 should still hold it — renewal failed")
	}

	// Clean up s1's lock.
	if err := s1.Unlock(ctx, name); err != nil {
		t.Fatalf("s1.Unlock: %v", err)
	}
}

func TestReleaseLocksOnCleanup(t *testing.T) {
	s := testStorage(t)
	s.LeaseDuration = 15
	s2 := &AzureBlobStorage{
		Container:     s.Container,
		client:        s.client,
		logger:        zap.NewNop(),
		LeaseDuration: 15,
	}

	ctx := context.Background()

	// Acquire multiple locks.
	locks := []string{"cleanup-lock-1", "cleanup-lock-2", "cleanup-lock-3"}
	for _, name := range locks {
		if err := s.Lock(ctx, name); err != nil {
			t.Fatalf("Lock %q: %v", name, err)
		}
	}

	// releaseLocks should release all of them.
	s.releaseLocks()

	// s2 should be able to acquire all of them immediately.
	for _, name := range locks {
		ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := s2.Lock(ctx2, name)
		cancel()
		if err != nil {
			t.Errorf("s2.Lock(%q) after releaseLocks: %v", name, err)
		} else {
			s2.Unlock(ctx, name)
		}
	}
}

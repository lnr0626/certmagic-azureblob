package certmagicazureblob

import (
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

func TestLeaseLost(t *testing.T) {
	ttl := 30 * time.Second
	transient := errors.New("connection reset")

	if leaseLost(transient, 10*time.Second, ttl) {
		t.Error("transient failure within the lease duration must not mark the lease lost")
	}
	if !leaseLost(transient, ttl, ttl) {
		t.Error("unrenewed for a full lease duration must mark the lease lost")
	}
	for _, code := range []string{"LeaseIdMismatchWithLeaseOperation", "LeaseLost", "LeaseNotPresentWithLeaseOperation"} {
		err := &azcore.ResponseError{ErrorCode: code}
		if !leaseLost(err, time.Second, ttl) {
			t.Errorf("%s must mark the lease lost", code)
		}
	}
}

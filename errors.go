package certmagicazureblob

import (
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
)

// isStorageError checks if an error is an Azure storage error with the given code.
func isStorageError(err error, code bloberror.Code) bool {
	return bloberror.HasCode(err, code)
}

// isBlobNotFound returns true if the error indicates the blob does not exist.
func isBlobNotFound(err error) bool {
	return isStorageError(err, bloberror.BlobNotFound)
}

// isContainerNotFound returns true if the error indicates the container does not exist.
func isContainerNotFound(err error) bool {
	return isStorageError(err, bloberror.ContainerNotFound)
}

// isLeaseConflict returns true if the error indicates a lease conflict
// (the blob is already leased by another client).
func isLeaseConflict(err error) bool {
	return isStorageError(err, bloberror.LeaseAlreadyPresent) ||
		isStorageError(err, "LeaseIsBreakingAndCannotBeAcquired")
}

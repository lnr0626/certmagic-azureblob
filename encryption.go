package certmagicazureblob

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"go.uber.org/zap"
)

const (
	aes256KeySize = 32
	nonceSize     = 12
	gcmTagSize    = 16
)

// encryptedBlobMagic is a 4-byte header prepended to every encrypted blob.
// It lets Load() tell an encrypted blob from a plaintext one, so a wrong-key
// failure is never mistaken for a legacy blob.
//
// The current format (ENC2) binds the ciphertext to its container and blob
// name through the GCM additional data, so a blob copied to another key or
// container fails authentication.
var encryptedBlobMagic = []byte{0x00, 'E', 'N', '2'}

// legacyEncryptedBlobMagic marks the original format, which used no additional
// data. They are still authenticated by the key, so they remain readable
// (except in strict mode) and are rewritten in the current format on the next
// Store, or at startup in migrate mode.
var legacyEncryptedBlobMagic = []byte{0x00, 'E', 'N', 'C'}

// EncryptionMode values for the encryption_mode option.
type EncryptionMode string

const (
	EncryptionModeCompatible EncryptionMode = "compatible"
	EncryptionModeStrict     EncryptionMode = "strict"
	EncryptionModeMigrate    EncryptionMode = "migrate"
)

func (s *AzureBlobStorage) encryptionMode() EncryptionMode {
	if s.EncryptionMode == "" {
		return EncryptionModeCompatible
	}
	return EncryptionMode(s.EncryptionMode)
}

// validateEncryptionMode rejects unknown modes, and any non-default mode
// when no encryption_key is configured.
func (s *AzureBlobStorage) validateEncryptionMode() (EncryptionMode, error) {
	m := s.encryptionMode()
	switch m {
	case EncryptionModeCompatible, EncryptionModeStrict, EncryptionModeMigrate:
	default:
		return m, fmt.Errorf("invalid encryption_mode %q: must be compatible, strict or migrate", s.EncryptionMode)
	}
	if s.EncryptionMode != "" && !s.encryptionEnabled() {
		return m, fmt.Errorf("encryption_mode requires encryption_key")
	}
	return m, nil
}

func (s *AzureBlobStorage) aad(key string) []byte {
	return []byte(s.Container + "\x00" + s.blobName(key))
}

// minEncryptedBlobSize is magic + nonce + at least one GCM tag (empty plaintext).
var minEncryptedBlobSize = len(encryptedBlobMagic) + nonceSize + gcmTagSize

func (s *AzureBlobStorage) encryptionEnabled() bool {
	return s.EncryptionKey != ""
}

func (s *AzureBlobStorage) encrypt(key string, plaintext []byte) ([]byte, error) {
	if !s.encryptionEnabled() {
		return plaintext, nil
	}

	rawKey, err := s.parseEncryptionKey()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM cipher: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	sealed := aead.Seal(nil, nonce, plaintext, s.aad(key))
	encrypted := make([]byte, 0, len(encryptedBlobMagic)+len(nonce)+len(sealed))
	encrypted = append(encrypted, encryptedBlobMagic...)
	encrypted = append(encrypted, nonce...)
	encrypted = append(encrypted, sealed...)
	return encrypted, nil
}

func (s *AzureBlobStorage) decrypt(key string, ciphertext []byte) ([]byte, error) {
	if !s.encryptionEnabled() {
		return ciphertext, nil
	}

	rawKey, err := s.parseEncryptionKey()
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < minEncryptedBlobSize {
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, need at least %d", len(ciphertext), minEncryptedBlobSize)
	}

	var aad []byte
	switch {
	case bytes.Equal(ciphertext[:len(encryptedBlobMagic)], encryptedBlobMagic):
		aad = s.aad(key)
	case bytes.Equal(ciphertext[:len(legacyEncryptedBlobMagic)], legacyEncryptedBlobMagic):
		if s.encryptionMode() == EncryptionModeStrict {
			return nil, fmt.Errorf("blob uses the legacy encryption format, which encryption_mode strict rejects; run encryption_mode migrate first")
		}
		if s.logger != nil {
			s.logger.Warn("blob uses the legacy encryption format without key binding; it will be upgraded on next store",
				zap.String("key", key))
		}
	default:
		return nil, fmt.Errorf("missing encryption header")
	}

	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM cipher: %w", err)
	}

	headerLen := len(encryptedBlobMagic)
	nonce := ciphertext[headerLen : headerLen+nonceSize]
	payload := ciphertext[headerLen+nonceSize:]
	plaintext, err := aead.Open(nil, nonce, payload, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypting data: %w", err)
	}
	return plaintext, nil
}

func (s *AzureBlobStorage) parseEncryptionKey() ([]byte, error) {
	if !s.encryptionEnabled() {
		return nil, nil
	}

	key, err := hex.DecodeString(s.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption_key: decode hex: %w", err)
	}
	if len(key) != aes256KeySize {
		return nil, fmt.Errorf("invalid encryption_key: expected 32 decoded bytes, got %d", len(key))
	}

	return key, nil
}

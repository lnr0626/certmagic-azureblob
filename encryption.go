package certmagicazureblob

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const (
	aes256KeySize = 32
	nonceSize     = 12
	gcmTagSize    = 16
)

// encryptedBlobMagic is a 4-byte header prepended to every encrypted blob.
// It lets Load() distinguish "encrypted with this plugin" from "legacy
// plaintext written before encryption was enabled" — without that marker the
// fallback path can't tell a wrong-key failure from a legacy blob.
var encryptedBlobMagic = []byte{0x00, 'E', 'N', 'C'}

// minEncryptedBlobSize is magic + nonce + at least one GCM tag (empty plaintext).
var minEncryptedBlobSize = len(encryptedBlobMagic) + nonceSize + gcmTagSize

func (s *AzureBlobStorage) encryptionEnabled() bool {
	return s.EncryptionKey != ""
}

func (s *AzureBlobStorage) encrypt(plaintext []byte) ([]byte, error) {
	if !s.encryptionEnabled() {
		return plaintext, nil
	}

	key, err := s.parseEncryptionKey()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
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

	sealed := aead.Seal(nil, nonce, plaintext, nil)
	encrypted := make([]byte, 0, len(encryptedBlobMagic)+len(nonce)+len(sealed))
	encrypted = append(encrypted, encryptedBlobMagic...)
	encrypted = append(encrypted, nonce...)
	encrypted = append(encrypted, sealed...)
	return encrypted, nil
}

func (s *AzureBlobStorage) decrypt(ciphertext []byte) ([]byte, error) {
	if !s.encryptionEnabled() {
		return ciphertext, nil
	}

	key, err := s.parseEncryptionKey()
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < minEncryptedBlobSize {
		return nil, fmt.Errorf("ciphertext too short: got %d bytes, need at least %d", len(ciphertext), minEncryptedBlobSize)
	}
	if !bytes.Equal(ciphertext[:len(encryptedBlobMagic)], encryptedBlobMagic) {
		return nil, fmt.Errorf("missing encryption header")
	}

	block, err := aes.NewCipher(key)
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
	plaintext, err := aead.Open(nil, nonce, payload, nil)
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

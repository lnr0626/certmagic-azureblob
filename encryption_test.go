package certmagicazureblob

import (
	"bytes"
	"testing"

	"go.uber.org/zap"
)

const testEncryptionKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func TestEncryptDecryptRoundTrip(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}
	plaintext := []byte("certificate-private-key-material")

	encrypted, err := s.encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encrypted output should differ from plaintext")
	}

	decrypted, err := s.decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypt(encrypt(plaintext)) = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptUsesDifferentNonces(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}
	plaintext := []byte("same input")

	first, err := s.encrypt(plaintext)
	if err != nil {
		t.Fatalf("first encrypt: %v", err)
	}
	second, err := s.encrypt(plaintext)
	if err != nil {
		t.Fatalf("second encrypt: %v", err)
	}

	if bytes.Equal(first, second) {
		t.Fatal("ciphertexts should differ for same plaintext due to random nonce")
	}
}

func TestDecryptCorruptedCiphertext(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}
	encrypted, err := s.encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	encrypted[len(encrypted)-1] ^= 0xff

	if _, err := s.decrypt(encrypted); err == nil {
		t.Fatal("expected decrypt error for corrupted ciphertext")
	}
}

func TestDecryptTruncatedCiphertext(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}

	if _, err := s.decrypt([]byte("too-short")); err == nil {
		t.Fatal("expected decrypt error for truncated ciphertext")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	encryptor := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}
	encrypted, err := encryptor.encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decryptor := &AzureBlobStorage{EncryptionKey: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"}
	if _, err := decryptor.decrypt(encrypted); err == nil {
		t.Fatal("expected decrypt error with wrong key")
	}
}

func TestEncryptDecryptNoopWhenKeyNotSet(t *testing.T) {
	s := &AzureBlobStorage{}
	plaintext := []byte("raw data")

	encrypted, err := s.encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal(encrypted, plaintext) {
		t.Fatal("encrypt should be passthrough when key is empty")
	}

	decrypted, err := s.decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypt should be passthrough when key is empty")
	}
}

func TestDecryptLoadedValueFallsBackToPlaintext(t *testing.T) {
	s := &AzureBlobStorage{
		EncryptionKey: testEncryptionKeyHex,
		logger:        zap.NewNop(),
	}

	t.Run("short blob", func(t *testing.T) {
		plaintext := []byte("tiny")

		got, err := s.decryptLoadedValue("legacy/short", plaintext)
		if err != nil {
			t.Fatalf("decryptLoadedValue: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("decryptLoadedValue fallback = %q, want %q", got, plaintext)
		}
	})

	t.Run("large unencrypted blob like a real PEM cert", func(t *testing.T) {
		// Simulate a real unencrypted PEM private key (well above minEncryptedBlobSize).
		plaintext := bytes.Repeat([]byte("-----BEGIN PRIVATE KEY-----\nMIIE...\n"), 50)

		got, err := s.decryptLoadedValue("certs/example.com/privkey.pem", plaintext)
		if err != nil {
			t.Fatalf("decryptLoadedValue should fall back for large unencrypted blob, got: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("decryptLoadedValue fallback = %q, want %q", got, plaintext)
		}
	})
}

package certmagicazureblob

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
)

const testEncryptionKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func TestEncryptDecryptRoundTrip(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}
	plaintext := []byte("certificate-private-key-material")

	encrypted, err := s.encrypt("k", plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encrypted output should differ from plaintext")
	}

	decrypted, err := s.decrypt("k", encrypted)
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

	first, err := s.encrypt("k", plaintext)
	if err != nil {
		t.Fatalf("first encrypt: %v", err)
	}
	second, err := s.encrypt("k", plaintext)
	if err != nil {
		t.Fatalf("second encrypt: %v", err)
	}

	if bytes.Equal(first, second) {
		t.Fatal("ciphertexts should differ for same plaintext due to random nonce")
	}
}

func TestDecryptCorruptedCiphertext(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}
	encrypted, err := s.encrypt("k", []byte("hello"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	encrypted[len(encrypted)-1] ^= 0xff

	if _, err := s.decrypt("k", encrypted); err == nil {
		t.Fatal("expected decrypt error for corrupted ciphertext")
	}
}

func TestDecryptTruncatedCiphertext(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}

	if _, err := s.decrypt("k", []byte("too-short")); err == nil {
		t.Fatal("expected decrypt error for truncated ciphertext")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	encryptor := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}
	encrypted, err := encryptor.encrypt("k", []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decryptor := &AzureBlobStorage{EncryptionKey: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"}
	if _, err := decryptor.decrypt("k", encrypted); err == nil {
		t.Fatal("expected decrypt error with wrong key")
	}
}

func TestEncryptDecryptNoopWhenKeyNotSet(t *testing.T) {
	s := &AzureBlobStorage{}
	plaintext := []byte("raw data")

	encrypted, err := s.encrypt("k", plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal(encrypted, plaintext) {
		t.Fatal("encrypt should be passthrough when key is empty")
	}

	decrypted, err := s.decrypt("k", encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypt should be passthrough when key is empty")
	}
}

func TestDecryptLoadedValueFallsBackToPlaintext(t *testing.T) {
	s := &AzureBlobStorage{
		EncryptionKey:  testEncryptionKeyHex,
		EncryptionMode: "migrate",
		logger:         zap.NewNop(),
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

	t.Run("encrypted blob with wrong key fails hard", func(t *testing.T) {
		// Encrypt with the correct key, then try to load with a different key.
		encrypted, err := s.encrypt("certs/example.com/privkey.pem", []byte("secret-cert-material"))
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}

		wrongKey := &AzureBlobStorage{
			EncryptionKey: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
			logger:        zap.NewNop(),
		}
		_, err = wrongKey.decryptLoadedValue("certs/example.com/privkey.pem", encrypted)
		if err == nil {
			t.Fatal("expected hard error when decrypting with wrong key, got nil")
		}
	})

	t.Run("corrupted encrypted blob fails hard", func(t *testing.T) {
		encrypted, err := s.encrypt("certs/example.com/privkey.pem", []byte("secret-cert-material"))
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		// Corrupt the ciphertext (but keep magic header intact)
		encrypted[len(encrypted)-1] ^= 0xff

		_, err = s.decryptLoadedValue("certs/example.com/privkey.pem", encrypted)
		if err == nil {
			t.Fatal("expected hard error for corrupted encrypted blob, got nil")
		}
	})
}

func TestEncryptDecryptEmptyPlaintext(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}

	encrypted, err := s.encrypt("k", []byte{})
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	// Empty plaintext → magic (4) + nonce (12) + GCM tag (16) = minEncryptedBlobSize.
	if len(encrypted) != minEncryptedBlobSize {
		t.Fatalf("encrypted empty = %d bytes, want %d", len(encrypted), minEncryptedBlobSize)
	}

	decrypted, err := s.decrypt("k", encrypted)
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}
	if len(decrypted) != 0 {
		t.Fatalf("decrypt(encrypt(empty)) = %d bytes, want 0", len(decrypted))
	}
}

func TestEncryptedOutputStructure(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}
	plaintext := []byte("test data")

	encrypted, err := s.encrypt("k", plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Wire format: magic (4) + nonce (12) + ciphertext (len(plaintext) + 16 GCM tag).
	expectedLen := len(encryptedBlobMagic) + nonceSize + len(plaintext) + gcmTagSize
	if len(encrypted) != expectedLen {
		t.Fatalf("encrypted length = %d, want %d", len(encrypted), expectedLen)
	}

	// First 4 bytes must be the magic header.
	if !bytes.Equal(encrypted[:len(encryptedBlobMagic)], encryptedBlobMagic) {
		t.Fatalf("magic header = %x, want %x", encrypted[:len(encryptedBlobMagic)], encryptedBlobMagic)
	}
}

func TestEncryptDecryptLargeData(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}
	plaintext := make([]byte, 1<<20) // 1 MiB
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	encrypted, err := s.encrypt("k", plaintext)
	if err != nil {
		t.Fatalf("encrypt 1MiB: %v", err)
	}

	decrypted, err := s.decrypt("k", encrypted)
	if err != nil {
		t.Fatalf("decrypt 1MiB: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("round-trip mismatch on 1 MiB payload")
	}
}

func TestEncryptDecryptConcurrent(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			plaintext := []byte(fmt.Sprintf("goroutine-%d-data", id))

			encrypted, err := s.encrypt("k", plaintext)
			if err != nil {
				errs <- fmt.Errorf("goroutine %d encrypt: %w", id, err)
				return
			}

			decrypted, err := s.decrypt("k", encrypted)
			if err != nil {
				errs <- fmt.Errorf("goroutine %d decrypt: %w", id, err)
				return
			}

			if !bytes.Equal(decrypted, plaintext) {
				errs <- fmt.Errorf("goroutine %d: round-trip mismatch", id)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

func TestEncryptWithInvalidKey(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: "not-hex"}
	_, err := s.encrypt("k", []byte("data"))
	if err == nil {
		t.Fatal("expected error for invalid encryption key during encrypt")
	}
	if !strings.Contains(err.Error(), "invalid encryption_key") {
		t.Errorf("error = %q, want to contain 'invalid encryption_key'", err.Error())
	}
}

func TestDecryptWithInvalidKeyFormat(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: "not-hex"}
	_, err := s.decrypt("k", make([]byte, minEncryptedBlobSize))
	if err == nil {
		t.Fatal("expected error for invalid encryption key during decrypt")
	}
	if !strings.Contains(err.Error(), "invalid encryption_key") {
		t.Errorf("error = %q, want to contain 'invalid encryption_key'", err.Error())
	}
}

func TestDecryptMissingMagicHeader(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex}
	// Data passes the length check (>= minEncryptedBlobSize) but lacks the magic header.
	data := bytes.Repeat([]byte("x"), minEncryptedBlobSize)
	_, err := s.decrypt("k", data)
	if err == nil {
		t.Fatal("expected error for missing magic header")
	}
	if !strings.Contains(err.Error(), "missing encryption header") {
		t.Errorf("error = %q, want to contain 'missing encryption header'", err.Error())
	}
}

func TestParseEncryptionKeyInvalidHex(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: "zzzz-not-hex!@#$"}
	_, err := s.parseEncryptionKey()
	if err == nil {
		t.Fatal("expected error for non-hex chars")
	}
	if !strings.Contains(err.Error(), "decode hex") {
		t.Errorf("error = %q, want to contain 'decode hex'", err.Error())
	}
}

func TestParseEncryptionKeyWrongLength(t *testing.T) {
	// Valid hex but only 16 bytes (AES-128), not 32 bytes (AES-256).
	s := &AzureBlobStorage{EncryptionKey: "00112233445566778899aabbccddeeff"}
	_, err := s.parseEncryptionKey()
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
	if !strings.Contains(err.Error(), "expected 32 decoded bytes") {
		t.Errorf("error = %q, want to contain 'expected 32 decoded bytes'", err.Error())
	}
}

func TestParseEncryptionKeyDisabled(t *testing.T) {
	s := &AzureBlobStorage{}
	key, err := s.parseEncryptionKey()
	if err != nil {
		t.Fatalf("parseEncryptionKey disabled: %v", err)
	}
	if key != nil {
		t.Fatalf("parseEncryptionKey disabled = %v, want nil", key)
	}
}

func TestDecryptLoadedValueEncryptionDisabled(t *testing.T) {
	s := &AzureBlobStorage{} // no encryption key
	data := []byte("raw blob data")

	got, err := s.decryptLoadedValue("some/key", data)
	if err != nil {
		t.Fatalf("decryptLoadedValue disabled: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("decryptLoadedValue disabled = %q, want passthrough %q", got, data)
	}
}

func TestDecryptLoadedValueSuccessfulDecrypt(t *testing.T) {
	s := &AzureBlobStorage{
		EncryptionKey: testEncryptionKeyHex,
		logger:        zap.NewNop(),
	}

	plaintext := []byte("encrypted-cert-material")
	encrypted, err := s.encrypt("certs/example.com/key.pem", plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	got, err := s.decryptLoadedValue("certs/example.com/key.pem", encrypted)
	if err != nil {
		t.Fatalf("decryptLoadedValue: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decryptLoadedValue = %q, want %q", got, plaintext)
	}
}

func TestDecryptLoadedValueFallbackNilLogger(t *testing.T) {
	s := &AzureBlobStorage{
		EncryptionKey:  testEncryptionKeyHex,
		EncryptionMode: "migrate",
		// logger intentionally nil — verify no panic on fallback path.
	}

	// Data without magic header triggers legacy fallback.
	data := []byte("legacy-plaintext")

	got, err := s.decryptLoadedValue("legacy/key", data)
	if err != nil {
		t.Fatalf("decryptLoadedValue nil logger: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("decryptLoadedValue nil logger = %q, want %q", got, data)
	}
}

func TestDecryptLoadedValueRejectsUnencryptedByDefault(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex, logger: zap.NewNop()}
	for _, data := range [][]byte{[]byte("planted"), {}, bytes.Repeat([]byte("-----BEGIN PRIVATE KEY-----\n"), 40)} {
		if _, err := s.decryptLoadedValue("certs/example.com/privkey.pem", data); err == nil {
			t.Fatalf("expected error for unencrypted blob of %d bytes", len(data))
		}
	}
}

func TestDecryptBoundToKeyAndContainer(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex, Container: "a", logger: zap.NewNop()}
	encrypted, err := s.encrypt("certs/victim.com/victim.com.key", []byte("victim key"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := s.decryptLoadedValue("certs/attacker.com/attacker.com.key", encrypted); err == nil {
		t.Fatal("ciphertext copied to another key must not decrypt")
	}
	other := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex, Container: "b", logger: zap.NewNop()}
	if _, err := other.decryptLoadedValue("certs/victim.com/victim.com.key", encrypted); err == nil {
		t.Fatal("ciphertext copied to another container must not decrypt")
	}
	if _, err := s.decryptLoadedValue("certs/victim.com/victim.com.key", encrypted); err != nil {
		t.Fatalf("original key should decrypt: %v", err)
	}
}

func TestLegacyEncryptedFormat(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex, logger: zap.NewNop()}
	rawKey, _ := s.parseEncryptionKey()
	block, _ := aes.NewCipher(rawKey)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, nonceSize)
	legacy := append(append(append([]byte{}, legacyEncryptedBlobMagic...), nonce...), aead.Seal(nil, nonce, []byte("old"), nil)...)

	got, err := s.decryptLoadedValue("k", legacy)
	if err != nil || string(got) != "old" {
		t.Fatalf("legacy encrypted blob must stay readable in the default mode: %q, %v", got, err)
	}

	legacy[len(legacy)-1] ^= 0xff
	if _, err := s.decryptLoadedValue("k", legacy); err == nil {
		t.Fatal("tampered legacy blob must fail authentication")
	}
}

func legacyBlob(t *testing.T, s *AzureBlobStorage, plaintext string) []byte {
	t.Helper()
	rawKey, _ := s.parseEncryptionKey()
	block, _ := aes.NewCipher(rawKey)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, nonceSize)
	return append(append(append([]byte{}, legacyEncryptedBlobMagic...), nonce...), aead.Seal(nil, nonce, []byte(plaintext), nil)...)
}

func TestEncryptionModes(t *testing.T) {
	base := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex, logger: zap.NewNop()}
	current, err := base.encrypt("k", []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyBlob(t, base, "v")
	plain := []byte("v")

	tests := []struct {
		mode                         string
		currentOK, legacyOK, plainOK bool
	}{
		{"", true, true, false},
		{"compatible", true, true, false},
		{"strict", true, false, false},
		{"migrate", true, true, true},
	}
	for _, tt := range tests {
		t.Run("mode "+tt.mode, func(t *testing.T) {
			s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex, EncryptionMode: tt.mode, logger: zap.NewNop()}
			for name, c := range map[string]struct {
				data []byte
				ok   bool
			}{"current": {current, tt.currentOK}, "legacy": {legacy, tt.legacyOK}, "plain": {plain, tt.plainOK}} {
				got, err := s.decryptLoadedValue("k", c.data)
				if c.ok && (err != nil || string(got) != "v") {
					t.Errorf("%s: got %q, %v; want success", name, got, err)
				}
				if !c.ok && err == nil {
					t.Errorf("%s: want error", name)
				}
			}
		})
	}
}

func TestValidateEncryptionMode(t *testing.T) {
	for _, bad := range []*AzureBlobStorage{
		{EncryptionKey: testEncryptionKeyHex, EncryptionMode: "bogus"},
		{EncryptionMode: "strict"},
	} {
		if _, err := bad.validateEncryptionMode(); err == nil {
			t.Errorf("expected error for %+v", bad)
		}
	}
	if _, err := (&AzureBlobStorage{}).validateEncryptionMode(); err != nil {
		t.Errorf("no key and no mode must be valid: %v", err)
	}
}

func TestUpgradeBlob(t *testing.T) {
	s := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex, EncryptionMode: "migrate", logger: zap.NewNop()}

	for name, raw := range map[string][]byte{"plaintext": []byte("secret"), "legacy": legacyBlob(t, s, "secret")} {
		up, changed, err := s.upgradeBlob("k", raw)
		if err != nil || !changed {
			t.Fatalf("%s: changed=%v err=%v", name, changed, err)
		}
		strict := &AzureBlobStorage{EncryptionKey: testEncryptionKeyHex, EncryptionMode: "strict"}
		if got, err := strict.decrypt("k", up); err != nil || string(got) != "secret" {
			t.Fatalf("%s: upgraded blob not readable in strict mode: %q, %v", name, got, err)
		}
		if _, changed, _ := s.upgradeBlob("k", up); changed {
			t.Fatalf("%s: current-format blob must not be rewritten", name)
		}
	}

	bad := legacyBlob(t, s, "secret")
	bad[len(bad)-1] ^= 0xff
	if _, _, err := s.upgradeBlob("k", bad); err == nil {
		t.Fatal("tampered legacy blob must not be upgraded")
	}
}

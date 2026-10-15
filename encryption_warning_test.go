package certmagicazureblob

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestLogEncryptionStatus(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		wantLevel zapcore.Level
	}{
		{"disabled warns", "", zapcore.WarnLevel},
		{"enabled is info", testEncryptionKeyHex, zapcore.InfoLevel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.InfoLevel)
			s := &AzureBlobStorage{EncryptionKey: tt.key, logger: zap.New(core)}
			s.logEncryptionStatus()
			entries := logs.All()
			if len(entries) != 1 || entries[0].Level != tt.wantLevel {
				t.Fatalf("got %v, want one %s entry", entries, tt.wantLevel)
			}
		})
	}
}

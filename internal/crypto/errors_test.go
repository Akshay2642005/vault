package crypto

// Stage A4: failure branches. The io.ReadFull error paths (salt, nonce,
// random bytes) can only be reached by failing crypto/rand.Reader — the
// whole suite runs serially, so swapping the package-level reader inside a
// single test cannot race with anything else.

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// failingReader fails every read, standing in for entropy-source failure.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("rand unavailable") }

func withFailingRand(t *testing.T) {
	t.Helper()
	orig := rand.Reader
	rand.Reader = failingReader{}
	t.Cleanup(func() { rand.Reader = orig })
}

func TestNewEngineWithConfig(t *testing.T) {
	cfg := &Config{
		Argon2Time:      2,
		Argon2Memory:    64 * 1024,
		Argon2Threads:   1,
		Argon2KeyLength: 64,
	}
	e := NewEngineWithConfig(cfg)

	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() error = %v", err)
	}
	key := e.DeriveKey("password", salt)
	if len(key) != 64 {
		t.Errorf("DeriveKey() len = %d, want the configured 64", len(key))
	}
}

func TestGenerateSaltFailsWhenRandFails(t *testing.T) {
	withFailingRand(t)

	if _, err := GenerateSalt(); err == nil || !strings.Contains(err.Error(), "failed to generate salt") {
		t.Errorf("GenerateSalt() error = %v, want failed to generate salt", err)
	}
}

func TestGenerateRandomFailuresPropagate(t *testing.T) {
	withFailingRand(t)

	if _, err := GenerateRandomBytes(32); err == nil ||
		!strings.Contains(err.Error(), "failed to generate random bytes") {
		t.Errorf("GenerateRandomBytes() error = %v, want failed to generate random bytes", err)
	}
	if _, err := GenerateRandomToken(32); err == nil {
		t.Errorf("GenerateRandomToken() error = nil, want the wrapped rand failure")
	}
}

func TestEncryptRejectsInvalidKeySize(t *testing.T) {
	e := NewEngine()

	if _, err := e.Encrypt([]byte("x"), []byte("short")); err == nil ||
		!strings.Contains(err.Error(), "invalid key size") {
		t.Errorf("Encrypt(short key) error = %v, want invalid key size", err)
	}
	if _, err := e.EncryptWithChecksum([]byte("x"), []byte("short")); err == nil ||
		!strings.Contains(err.Error(), "invalid key size") {
		t.Errorf("EncryptWithChecksum(short key) error = %v, want invalid key size", err)
	}
}

func TestEncryptFailsWhenNonceGenerationFails(t *testing.T) {
	e := NewEngine()
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() error = %v", err)
	}
	key := e.DeriveKey("password", salt)

	withFailingRand(t)

	if _, err := e.Encrypt([]byte("plaintext"), key); err == nil ||
		!strings.Contains(err.Error(), "failed to generate nonce") {
		t.Errorf("Encrypt() error = %v, want failed to generate nonce", err)
	}
}

func TestDecryptRejectsMalformedInput(t *testing.T) {
	e := NewEngine()
	key := make([]byte, KeySize)

	if _, err := e.Decrypt("AAAA", []byte("short")); err == nil ||
		!strings.Contains(err.Error(), "invalid key size") {
		t.Errorf("Decrypt(short key) error = %v, want invalid key size", err)
	}

	if _, err := e.Decrypt("!!not-base64!!", key); err == nil ||
		!strings.Contains(err.Error(), "failed to decode ciphertext") {
		t.Errorf("Decrypt(not base64) error = %v, want failed to decode ciphertext", err)
	}

	// Valid base64 but shorter than the GCM nonce (12 bytes).
	short := base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	if _, err := e.Decrypt(short, key); err == nil ||
		!strings.Contains(err.Error(), "ciphertext too short") {
		t.Errorf("Decrypt(short ciphertext) error = %v, want ciphertext too short", err)
	}
}

func TestDecryptAndVerifyPropagatesDecryptError(t *testing.T) {
	e := NewEngine()

	data := &EncryptedData{Ciphertext: "!!not-base64!!", Checksum: Hash([]byte("x"))}
	if _, err := e.DecryptAndVerify(data, make([]byte, KeySize)); err == nil ||
		!strings.Contains(err.Error(), "failed to decode ciphertext") {
		t.Errorf("DecryptAndVerify() error = %v, want the decrypt failure", err)
	}
}

func TestVerifyAuthHashRejectsMalformedHash(t *testing.T) {
	if _, err := VerifyAuthHash(make([]byte, KeySize), "!!not-base64!!"); err == nil ||
		!strings.Contains(err.Error(), "failed to decode auth hash") {
		t.Errorf("VerifyAuthHash() error = %v, want failed to decode auth hash", err)
	}
}

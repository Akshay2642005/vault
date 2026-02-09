package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	if len(salt1) != SaltSize {
		t.Errorf("Expected salt size %d, got %d", SaltSize, len(salt1))
	}

	// Generate another salt and ensure they're different
	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	if bytes.Equal(salt1, salt2) {
		t.Error("Generated salts should be different")
	}
}

func TestDeriveKey(t *testing.T) {
	engine := NewEngine()
	password := "test-password-123"
	salt, _ := GenerateSalt()

	key1 := engine.DeriveKey(password, salt)
	if len(key1) != KeySize {
		t.Errorf("Expected key size %d, got %d", KeySize, len(key1))
	}

	// Same password and salt should produce same key
	key2 := engine.DeriveKey(password, salt)
	if !bytes.Equal(key1, key2) {
		t.Error("Same password and salt should produce same key")
	}

	// Different password should produce different key
	key3 := engine.DeriveKey("different-password", salt)
	if bytes.Equal(key1, key3) {
		t.Error("Different passwords should produce different keys")
	}

	// Different salt should produce different key
	salt2, _ := GenerateSalt()
	key4 := engine.DeriveKey(password, salt2)
	if bytes.Equal(key1, key4) {
		t.Error("Different salts should produce different keys")
	}
}

func TestAuthHash(t *testing.T) {
	engine := NewEngine()
	password := "test-password"
	salt, _ := GenerateSalt()
	key := engine.DeriveKey(password, salt)

	// Generate auth hash
	authHash := GenerateAuthHash(key)
	if authHash == "" {
		t.Error("Auth hash should not be empty")
	}

	// Verify correct key
	valid, err := VerifyAuthHash(key, authHash)
	if err != nil {
		t.Fatalf("VerifyAuthHash failed: %v", err)
	}
	if !valid {
		t.Error("Auth hash verification should succeed for correct key")
	}

	// Verify incorrect key
	wrongKey := engine.DeriveKey("wrong-password", salt)
	valid, err = VerifyAuthHash(wrongKey, authHash)
	if err != nil {
		t.Fatalf("VerifyAuthHash failed: %v", err)
	}
	if valid {
		t.Error("Auth hash verification should fail for incorrect key")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	engine := NewEngine()
	password := "test-password"
	salt, _ := GenerateSalt()
	key := engine.DeriveKey(password, salt)

	plaintext := []byte("This is a secret message!")

	// Encrypt
	ciphertext, err := engine.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if ciphertext == "" {
		t.Error("Ciphertext should not be empty")
	}

	// Decrypt
	decrypted, err := engine.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestEncryptDecryptWithWrongKey(t *testing.T) {
	engine := NewEngine()
	salt, _ := GenerateSalt()

	key1 := engine.DeriveKey("password1", salt)
	key2 := engine.DeriveKey("password2", salt)

	plaintext := []byte("Secret data")

	// Encrypt with key1
	ciphertext, err := engine.Encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with key2 (should fail)
	_, err = engine.Decrypt(ciphertext, key2)
	if err == nil {
		t.Error("Decrypt should fail with wrong key")
	}
}

func TestEncryptDecryptLargeData(t *testing.T) {
	engine := NewEngine()
	password := "test-password"
	salt, _ := GenerateSalt()
	key := engine.DeriveKey(password, salt)

	// Test with 1MB of data
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := engine.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := engine.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Large data encryption/decryption failed")
	}
}

func TestEncryptWithChecksum(t *testing.T) {
	engine := NewEngine()
	password := "test-password"
	salt, _ := GenerateSalt()
	key := engine.DeriveKey(password, salt)

	plaintext := []byte("Important secret data")

	// Encrypt with checksum
	encrypted, err := engine.EncryptWithChecksum(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptWithChecksum failed: %v", err)
	}

	if encrypted.Ciphertext == "" {
		t.Error("Ciphertext should not be empty")
	}
	if encrypted.Checksum == "" {
		t.Error("Checksum should not be empty")
	}

	// Decrypt and verify
	decrypted, err := engine.DecryptAndVerify(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptAndVerify failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted data doesn't match original")
	}
}

func TestDecryptWithCorruptedChecksum(t *testing.T) {
	engine := NewEngine()
	password := "test-password"
	salt, _ := GenerateSalt()
	key := engine.DeriveKey(password, salt)

	plaintext := []byte("Important secret data")

	encrypted, err := engine.EncryptWithChecksum(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptWithChecksum failed: %v", err)
	}

	// Corrupt the checksum
	encrypted.Checksum = "corrupted-checksum"

	// Should fail verification
	_, err = engine.DecryptAndVerify(encrypted, key)
	if err == nil {
		t.Error("DecryptAndVerify should fail with corrupted checksum")
	}
}

func TestHash(t *testing.T) {
	data := []byte("test data")
	hash1 := Hash(data)

	if hash1 == "" {
		t.Error("Hash should not be empty")
	}

	// Same data should produce same hash
	hash2 := Hash(data)
	if hash1 != hash2 {
		t.Error("Same data should produce same hash")
	}

	// Different data should produce different hash
	hash3 := Hash([]byte("different data"))
	if hash1 == hash3 {
		t.Error("Different data should produce different hash")
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	bytes1, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}

	if len(bytes1) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(bytes1))
	}

	// Should generate different random bytes
	bytes2, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}

	if bytes.Equal(bytes1, bytes2) {
		t.Error("Random bytes should be different")
	}
}

func TestGenerateRandomToken(t *testing.T) {
	token, err := GenerateRandomToken(32)
	if err != nil {
		t.Fatalf("GenerateRandomToken failed: %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}
}

func TestSecureZero(t *testing.T) {
	data := []byte("sensitive data")
	original := make([]byte, len(data))
	copy(original, data)

	SecureZero(data)

	// All bytes should be zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d should be zero, got %d", i, b)
		}
	}

	// Should be different from original
	if bytes.Equal(data, original) {
		t.Error("Data should be zeroed out")
	}
}

func BenchmarkDeriveKey(b *testing.B) {
	engine := NewEngine()
	password := "benchmark-password"
	salt, _ := GenerateSalt()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.DeriveKey(password, salt)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	engine := NewEngine()
	password := "benchmark-password"
	salt, _ := GenerateSalt()
	key := engine.DeriveKey(password, salt)
	plaintext := []byte("This is a benchmark test message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Encrypt(plaintext, key)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	engine := NewEngine()
	password := "benchmark-password"
	salt, _ := GenerateSalt()
	key := engine.DeriveKey(password, salt)
	plaintext := []byte("This is a benchmark test message")
	ciphertext, _ := engine.Encrypt(plaintext, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Decrypt(ciphertext, key)
	}
}

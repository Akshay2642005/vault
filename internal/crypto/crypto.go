package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	SaltSize  = 32
	KeySize   = 32
	NonceSize = 12

	Argon2Time      = 3
	Argon2Memory    = 64 * 1024
	Argon2Threads   = 4
	Argon2KeyLength = KeySize
)

type Config struct {
	Argon2Time      uint32
	Argon2Memory    uint32
	Argon2Threads   uint8
	Argon2KeyLength uint32
}

type Engine struct {
	config *Config
}

type EncryptedData struct {
	Ciphertext string `json:"ciphertext"`
	Checksum   string `json:"checksum"`
}

func DefaultConfig() *Config {
	return &Config{
		Argon2Time:      Argon2Time,
		Argon2Memory:    Argon2Memory,
		Argon2Threads:   Argon2Threads,
		Argon2KeyLength: Argon2KeyLength,
	}
}

func NewEngine() *Engine {
	return &Engine{
		config: DefaultConfig(),
	}
}

func NewEngineWithConfig(config *Config) *Engine {
	return &Engine{
		config: config,
	}
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

func (e *Engine) DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		e.config.Argon2Time,
		e.config.Argon2Memory,
		e.config.Argon2Threads,
		e.config.Argon2KeyLength,
	)
}

func GenerateAuthHash(key []byte) string {
	hash := sha256.Sum256(key)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func VerifyAuthHash(key []byte, authHash string) (bool, error) {
	stored, err := base64.StdEncoding.DecodeString(authHash)
	if err != nil {
		return false, fmt.Errorf("failed to decode auth hash: %w", err)
	}

	hash := sha256.Sum256(key)

	return subtle.ConstantTimeCompare(hash[:], stored) == 1, nil
}

func (e *Engine) Encrypt(plaintext []byte, key []byte) (string, error) {
	if len(key) != KeySize {
		return "", fmt.Errorf("invalid key size: expected %d, got %d", KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	cipherText := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func (e *Engine) Decrypt(encodedCipherText string, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", KeySize, len(key))
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encodedCipherText)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}

func Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func GenerateRandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

func GenerateRandomToken(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (e *Engine) EncryptWithChecksum(plaintext, key []byte) (*EncryptedData, error) {
	ciphertext, err := e.Encrypt(plaintext, key)
	if err != nil {
		return nil, err
	}
	checksum := Hash(plaintext)

	return &EncryptedData{
		Ciphertext: ciphertext,
		Checksum:   checksum,
	}, nil
}

func (e *Engine) DecryptAndVerify(data *EncryptedData, key []byte) ([]byte, error) {
	plaintext, err := e.Decrypt(data.Ciphertext, key)
	if err != nil {
		return nil, err
	}

	checksum := Hash(plaintext)
	if checksum != data.Checksum {
		return nil, fmt.Errorf("checksum mismatch: data may be corrupted or tampered with")
	}

	return plaintext, nil
}

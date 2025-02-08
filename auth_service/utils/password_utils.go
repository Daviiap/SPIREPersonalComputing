package utils

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

func GeneratePasswordHash(password string) (string, error) {
	// Configuration for Argon2id
	const (
		memory     = 64 * 1024 // 64 MB
		time       = 1         // Number of iterations
		threads    = 4         // Number of parallel threads
		keyLength  = 32        // Length of the generated hash
		saltLength = 16        // Length of the random salt
	)

	// Generate a random salt
	salt := make([]byte, saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive the key using Argon2id
	hash := argon2.IDKey([]byte(password), salt, time, memory, uint8(threads), keyLength)

	// Combine the salt and hash into a single string (base64 encoded)
	fullHash := fmt.Sprintf("%s.%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return fullHash, nil
}

func VerifyPassword(password, fullHash string) (bool, error) {
	parts := strings.Split(fullHash, ".")
	if len(parts) != 2 {
		return false, errors.New("invalid hash format")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return false, errors.New("invalid salt encoding")
	}

	storedHash, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, errors.New("invalid hash encoding")
	}

	const (
		memory    = 64 * 1024 // 64 MB
		time      = 1         // Number of iterations
		threads   = 4         // Number of parallel threads
		keyLength = 32        // Length of the hash
	)

	computedHash := argon2.IDKey([]byte(password), salt, time, memory, uint8(threads), keyLength)

	if len(computedHash) != len(storedHash) {
		return false, nil
	}
	for i := 0; i < len(computedHash); i++ {
		if computedHash[i] != storedHash[i] {
			return false, nil
		}
	}

	return true, nil
}

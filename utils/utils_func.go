package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/joy095/identity/logger"
	"golang.org/x/crypto/argon2"
)

// getSecretFromEnv safely retrieves and base64 decodes a secret from an environment variable.
func getSecretFromEnv(envVarName string) ([]byte, error) {
	secretB64 := os.Getenv(envVarName)
	if secretB64 == "" {
		return nil, fmt.Errorf("environment variable %s not set", envVarName)
	}

	secretBytes, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode %s: %w", envVarName, err)
	}
	return secretBytes, nil
}

// GetJWTSecret retrieves the base64-decoded JWT access secret.
func GetJWTSecret() []byte {
	// Cache the secret if performance is critical and it's read frequently
	// For now, let's keep it simple and re-read/decode each time, which is fine for most apps.
	secret, err := getSecretFromEnv("JWT_SECRET") // Use the function to get and decode
	if err != nil {
		errMsg := fmt.Sprintf("SECURITY RISK: %s - using insecure default", err.Error())
		logger.ErrorLogger.Error(errMsg)
		if os.Getenv("GO_ENV") == "production" {
			logger.ErrorLogger.Fatal("Cannot run in production without secure JWT_SECRET")
		}
		// Insecure default for development only
		return []byte("default-insecure-secret-only-for-development-must-be-long-enough-for-jwt")
	}
	return secret
}

// GetJWTRefreshSecret retrieves the base64-decoded JWT refresh secret.
func GetJWTRefreshSecret() []byte {
	secret, err := getSecretFromEnv("JWT_SECRET_REFRESH") // Use the function to get and decode
	if err != nil {
		errMsg := fmt.Sprintf("SECURITY RISK: %s - using insecure default", err.Error())
		logger.ErrorLogger.Error(errMsg)
		if os.Getenv("GO_ENV") == "production" {
			logger.ErrorLogger.Fatal("Cannot run in production without secure JWT_SECRET_REFRESH")
		}
		// Insecure default for development only
		return []byte("default-insecure-refresh-secret-only-for-development-must-be-long-enough-for-jwt")
	}
	return secret
}

// Generate a secure OTP using crypto/rand (no changes needed)
func GenerateSecureOTP() (string, error) {
	const otpChars = "0123456789"
	otp := make([]byte, 6)
	for i := 0; i < 6; i++ {
		for {
			b := make([]byte, 1)
			_, err := rand.Read(b)
			if err != nil {
				logger.ErrorLogger.Errorf("Error generating secure OTP: %v", err)
				return "", fmt.Errorf("failed to generate secure OTP: %w", err)
			}
			// Reject values that would cause modulo bias
			if b[0] < 250 { // 250 = 25 * 10, largest multiple of 10 less than 256
				otp[i] = otpChars[b[0]%10]
				break
			}
		}
	}
	return string(otp), nil
}

// HashOTP hashes an OTP using Argon2id with a secure salt (no changes needed)
func HashOTP(otp string) string {
	saltBase := os.Getenv("OTP_SALT_SECRET")
	if saltBase == "" {
		logger.ErrorLogger.Warn("OTP_SALT_SECRET not set, using fallback")
		saltBase = "change_this_in_production"
	}

	salt := []byte(saltBase + "-otp-verification-salt")

	time := uint32(2)
	memory := uint32(64 * 1024)
	threads := uint8(1)
	keyLen := uint32(32)
	hashed := argon2.IDKey([]byte(otp), salt, time, memory, threads, keyLen)

	return fmt.Sprintf("%x", hashed)
}

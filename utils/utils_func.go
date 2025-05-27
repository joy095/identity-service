package utils

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/joy095/identity/config"
	"github.com/joy095/identity/logger"
	"golang.org/x/crypto/argon2"
)

func init() {
	config.LoadEnv()
}

func GetJWTSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		logger.ErrorLogger.Error("SECURITY RISK: JWT_SECRET environment variable not set - using insecure default")
		if os.Getenv("GO_ENV") == "production" {
			logger.ErrorLogger.Fatal("Cannot run in production without secure JWT_SECRET")
		}
		return []byte("default-insecure-secret-only-for-development")
	}
	return []byte(secret)
}

func GetJWTRefreshSecret() []byte {
	secret := os.Getenv("JWT_SECRET_REFRESH")
	if secret == "" {
		logger.ErrorLogger.Error("SECURITY RISK: JWT_SECRET_REFRESH environment variable not set - using insecure default")
		if os.Getenv("GO_ENV") == "production" {
			logger.ErrorLogger.Fatal("Cannot run in production without secure JWT_SECRET_REFRESH")
		}
		return []byte("default-insecure-refresh-secret-only-for-development")
	}
	return []byte(secret)
}

// Generate a secure OTP using crypto/rand
func GenerateSecureOTP() (string, error) {
	const otpChars = "0123456789"
	bytes := make([]byte, 6)
	_, err := rand.Read(bytes)
	if err != nil {
		logger.ErrorLogger.Errorf("Error generating secure OTP: %v", err)
		return "", fmt.Errorf("failed to generate secure OTP: %w", err)
	}
	for i := range bytes {
		bytes[i] = otpChars[bytes[i]%byte(len(otpChars))]
	}
	return string(bytes), nil
}

// HashOTP hashes an OTP using Argon2id with a secure salt
// Parameters chosen based on OWASP recommendations for balance of security and performance
func HashOTP(otp string) string {
	// In a production system, each OTP should have a unique salt
	// For OTP verification where we need to compare against stored hash, we use a constant salt
	// derived from application secrets
	saltBase := os.Getenv("OTP_SALT_SECRET")
	if saltBase == "" {
		logger.ErrorLogger.Warn("OTP_SALT_SECRET not set, using fallback")
		saltBase = "change_this_in_production"
	}

	// Create a salt that's unique to this application but constant for comparison

	salt := []byte(saltBase + "-otp-verification-salt")

	// Argon2id parameters:
	// - 1 iteration: acceptable for short-lived OTPs
	// - 64MB memory: reasonable resource usage
	// - 1 thread: balanced for OTP verification performance
	// - 32 bytes output: sufficiently secure hash length
	// OWASP recommends t>=2, m>=19456KiB, p>=1 for production
	time := uint32(2)           // number of iterations
	memory := uint32(64 * 1024) // KiB (≥ 19456)
	threads := uint8(1)         // parallelism (kept low for OTP verification performance)
	keyLen := uint32(32)
	hashed := argon2.IDKey([]byte(otp), salt, time, memory, threads, keyLen)

	return fmt.Sprintf("%x", hashed)
}

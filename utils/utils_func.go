package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

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
		errMsg := "SECURITY RISK: JWT access secret configuration error - using insecure default"
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
		errMsg := "SECURITY RISK: JWT refresh secret configuration error - using insecure default"
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
		errMsg := "SECURITY RISK: OTP_SALT_SECRET not set"
		logger.ErrorLogger.Error(errMsg)
		if os.Getenv("GO_ENV") == "production" {
			logger.ErrorLogger.Fatal("Cannot run in production without OTP_SALT_SECRET")
		}
		// Insecure fallback for development only
		saltBase = "change_this_in_production_" + time.Now().Format("20060102")
	}

	salt := []byte(saltBase + "-otp-verification-salt")

	timeIterations := uint32(2)
	memoryKB := uint32(64 * 1024)
	parallelism := uint8(1)
	keyLen := uint32(32)
	hashed := argon2.IDKey([]byte(otp), salt, timeIterations, memoryKB, parallelism, keyLen)

	return fmt.Sprintf("%x", hashed)
}

// ParseTimeToUTC parses a time string (e.g., "03:30:00") and assigns it a date (today UTC) and UTC timezone.
// The `day` parameter is likely intended for context (e.g., timezone lookup based on the day/business) but is not parsed as time.
func ParseTimeToUTC(t string, day string) (time.Time, error) {
	// Trim whitespace from the time string
	t = strings.TrimSpace(t)

	// Define the expected layout for the time string
	layout := "15:04:05" // This matches HH:MM:SS

	// Parse the time string using the specified layout
	parsedTime, err := time.Parse(layout, t)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot parse time '%s': %w", t, err)
	}

	// Get the current UTC date
	now := time.Now().UTC()

	// Combine the parsed time (hours, minutes, seconds) with today's UTC date
	resultTime := time.Date(
		now.Year(), now.Month(), now.Day(), // Date part from today UTC
		parsedTime.Hour(), parsedTime.Minute(), parsedTime.Second(), // Time part from parsed string
		0,        // Nanoseconds
		time.UTC, // Timezone
	)

	return resultTime, nil
}

var (
	// E.164: optional +, 8–15 digits, no leading 0 after +
	reE164 = regexp.MustCompile(`^\+?[1-9]\d{7,14}$`)
	// India: optional +91/91/0, then 10 digits starting 6–9
	reIN = regexp.MustCompile(`^(?:\+91|91|0)?[6-9]\d{9}$`)
)

func IsValidPhone(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	// Accept if it’s valid E.164 or valid Indian format
	return reE164.MatchString(p) || reIN.MatchString(p)
}

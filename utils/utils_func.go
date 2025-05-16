package utils

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/joy095/identity/config"
	"golang.org/x/crypto/argon2"
)

func init() {
	config.LoadEnv()
}

func GetJWTSecret() []byte {

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		fmt.Println("WARNING: JWT_SECRET environment variable not set.")
		return []byte("default-insecure-secret-only-for-development")
	}
	return []byte(secret)
}

func GetJWTRefreshSecret() []byte {

	secret := os.Getenv("JWT_SECRET_REFRESH")
	if secret == "" {
		fmt.Println("WARNING: JWT_SECRET_REFRESH environment variable not set.")
		return []byte("default-insecure--refresh-secret-only-for-development")
	}
	return []byte(secret)
}

// Generate a secure OTP using crypto/rand
func GenerateSecureOTP() string {
	const otpChars = "0123456789"
	bytes := make([]byte, 6)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Println("Error generating secure OTP:", err)
		return "000000"
	}
	for i := range bytes {
		bytes[i] = otpChars[bytes[i]%byte(len(otpChars))]
	}
	return string(bytes)
}

func HashOTP(otp string) string {
	salt := []byte("some_random_salt")
	hashed := argon2.IDKey([]byte(otp), salt, 1, 64*1024, 4, 32)
	return fmt.Sprintf("%x", hashed)
}

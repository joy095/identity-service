package utils

import (
	"fmt"
	"os"

	"github.com/joy095/identity/config"
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

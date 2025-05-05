package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func LoadEnv() {
	env := os.Getenv("GO_ENV")

	var envFile string
	if env == "development" {
		envFile = ".env.local"
	} else {
		envFile = ".env"
	}

	// Attempt to load the environment file
	if err := godotenv.Load(envFile); err != nil {
		if env == "development" { // Only log errors in development
			log.Printf("No %s file found or failed to load: %v", envFile, err)
		}
	} else {
		if env == "development" { // Only log success in development
			log.Printf("Loaded environment variables from %s", envFile)
		}
	}
}

package shared_models

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/utils"
)

// Location represents geographical coordinates
// type Location struct {
// 	// Latitude should be between -90 and +90
// 	Latitude float64 `json:"latitude" binding:"required,min=-90,max=90"`
// 	// Longitude should be between -180 and +180
// 	Longitude float64 `json:"longitude" binding:"required,min=-180,max=180"`
// }

// Define constants for booking status
const (
	BookingStatusPending   = "pending"
	BookingStatusConfirmed = "confirmed"
	BookingStatusCancelled = "cancelled"
	BookingStatusFailed    = "failed"
	BookingStatusRefunded  = "refunded"
)

// GenerateUUIDv7 generates a new UUIDv7
func GenerateUUIDv7() (uuid.UUID, error) {
	return uuid.NewV7()
}

// generateSecureToken creates a long secure token (for refresh tokens)
func GenerateRefreshToken(userID uuid.UUID, duration time.Duration) (string, error) {
	logger.InfoLogger.Info("GenerateRefreshToken called on models")

	now := time.Now()

	// Use MapClaims for maximum compatibility
	claims := jwt.MapClaims{
		"sub":     userID.String(),
		"user_id": userID.String(),
		"iat":     now.Unix(),
		"exp":     now.Add(duration).Unix(),
		"nbf":     now.Unix(),
		"jti":     uuid.NewString(),
		"iss":     "identity_service",
		"type":    "refresh",
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	jwtRefreshSecret := utils.GetJWTRefreshSecret()

	// Sign the token with the secret key
	tokenString, err := token.SignedString(jwtRefreshSecret)
	if err != nil {

		logger.ErrorLogger.Errorf("failed to sign token: %v", err)
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return tokenString, nil
}

package shared_models

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/utils" // Ensure utils package contains GetJWTSecret() and GetJWTRefreshSecret()
)

// Define constants for booking status (no change)
const (
	BookingStatusPending   = "pending"
	BookingStatusConfirmed = "confirmed"
	BookingStatusCancelled = "cancelled"
	BookingStatusFailed    = "failed"
	BookingStatusRefunded  = "refunded"
)

// GenerateUUIDv7 generates a new UUIDv7 (no change)
func GenerateUUIDv7() (uuid.UUID, error) {
	return uuid.NewV7()
}

// Claims represents the JWT claims for your tokens
type Claims struct {
	UserID uuid.UUID `json:"user_id"`
	Type   string    `json:"type"` // <--- IMPORTANT: Add 'Type' field to your custom Claims struct
	jwt.RegisteredClaims
}

// GenerateRefreshToken creates a JWT token for refresh purposes
func GenerateRefreshToken(userID uuid.UUID, duration time.Duration) (string, error) {
	logger.InfoLogger.Info("GenerateRefreshToken called on models")

	now := time.Now()

	claims := jwt.MapClaims{
		"sub":     userID.String(),
		"user_id": userID.String(),
		"iat":     now.Unix(),
		"exp":     now.Add(duration).Unix(),
		"nbf":     now.Unix(),
		"jti":     uuid.NewString(),
		"iss":     "identity_service",
		"type":    "refresh", // Mark this as a refresh token
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	jwtRefreshSecret := utils.GetJWTRefreshSecret() // Use the refresh secret

	tokenString, err := token.SignedString(jwtRefreshSecret)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to sign refresh token: %v", err)
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	// DEBUG: Verify the generated token *before* returning
	// This should show a pure JWT string, no ':unknown' or other suffixes
	logger.WarnLogger.Debugf("DEBUG_SHARED_MODELS: Generated Pure Refresh Token: %s", tokenString)

	return tokenString, nil // Returns pure JWT
}

// GenerateAccessToken creates a JWT token for access purposes
func GenerateAccessToken(userID uuid.UUID, duration time.Duration) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"sub":     userID.String(),
		"user_id": userID.String(),
		"iat":     now.Unix(),
		"exp":     now.Add(duration).Unix(),
		"nbf":     now.Unix(),
		"jti":     uuid.NewString(),
		"iss":     "identity-service",
		"type":    "access", // Mark this as an access token
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	jwtSecret := utils.GetJWTSecret() // Use the access secret

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to sign access token: %v", err)
		return "", fmt.Errorf("failed to sign access token: %v", err)
	}

	return tokenString, nil // Returns pure JWT
}

// ParseToken parses and validates a JWT token string, determining the secret based on token type
func ParseToken(tokenString string) (*Claims, error) {
	// First, parse without validating the signature to get the claims map
	// This allows us to read the 'type' claim to pick the correct secret.
	parser := jwt.NewParser(jwt.WithJSONNumber()) // Use WithJSONNumber if your claims contain numeric values
	var claimsMap jwt.MapClaims
	_, _, err := parser.ParseUnverified(tokenString, &claimsMap) // Parse without verification
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse token (unverified) to read type: %v", err)
		return nil, fmt.Errorf("invalid token format: %w", err)
	}

	tokenType, ok := claimsMap["type"].(string)
	if !ok {
		logger.ErrorLogger.Error("Token 'type' claim is missing or not a string")
		return nil, fmt.Errorf("token 'type' claim is missing or invalid")
	}

	var secretKey []byte
	switch tokenType {
	case "access":
		secretKey = utils.GetJWTSecret()
	case "refresh":
		secretKey = utils.GetJWTRefreshSecret()
	default:
		logger.ErrorLogger.Errorf("Unknown token type: %s", tokenType)
		return nil, fmt.Errorf("unknown token type")
	}

	// Now parse and validate the token with the correct secret key
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil // Use the determined secret key
	})

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse and validate token: %v", err)
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		logger.ErrorLogger.Errorf("Invalid token: %s", tokenString)
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

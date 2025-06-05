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

const (
	MAX_REFRESH_TOKENS   = 5
	REFRESH_TOKEN_EXPIRY = time.Hour * 24 * 30
	ACCESS_TOKEN_EXPIRY  = time.Hour * 1
)

// GenerateUUIDv7 generates a new UUIDv7 (no change)
func GenerateUUIDv7() (uuid.UUID, error) {
	return uuid.NewV7()
}

// Claims represents the JWT claims for your tokens
type Claims struct {
	UserID       uuid.UUID `json:"user_id"`
	Type         string    `json:"type"`
	TokenVersion int       `json:"token_version"`
	jwt.RegisteredClaims
}

// GenerateRefreshToken creates a JWT token for refresh purposes
func GenerateRefreshToken(userID uuid.UUID, tokenVersion int, duration time.Duration) (string, error) {
	logger.InfoLogger.Info("GenerateRefreshToken called on models")

	now := time.Now()

	claims := jwt.MapClaims{
		"sub":           userID.String(),
		"user_id":       userID.String(),
		"iat":           now.Unix(),
		"exp":           now.Add(duration).Unix(),
		"nbf":           now.Unix(),
		"jti":           uuid.NewString(),
		"iss":           "identity-service",
		"type":          "refresh",
		"token_version": tokenVersion,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtRefreshSecret := utils.GetJWTRefreshSecret()

	tokenString, err := token.SignedString(jwtRefreshSecret)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to sign refresh token: %v", err)
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return tokenString, nil
}

// GenerateAccessToken creates a JWT token for access purposes
func GenerateAccessToken(userID uuid.UUID, tokenVersion int, duration time.Duration) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"sub":           userID.String(),
		"user_id":       userID.String(),
		"iat":           now.Unix(),
		"exp":           now.Add(duration).Unix(),
		"nbf":           now.Unix(),
		"jti":           uuid.NewString(),
		"iss":           "identity-service",
		"type":          "access",
		"token_version": tokenVersion,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtSecret := utils.GetJWTSecret()

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to sign access token: %v", err)
		return "", fmt.Errorf("failed to sign access token: %v", err)
	}

	return tokenString, nil
}

// ParseToken parses and validates a JWT token string, determining the secret based on token type
// This function will need a way to fetch the current user's token_version from the database.
// You might need to pass a 'userRepository' or similar dependency.
// For simplicity in this example, I'll simulate fetching it.
func ParseToken(tokenString string, userTokenVersionFetcher func(userID uuid.UUID) (int, error)) (*Claims, error) {
	parser := jwt.NewParser(jwt.WithJSONNumber())
	var claimsMap jwt.MapClaims
	_, _, err := parser.ParseUnverified(tokenString, &claimsMap)
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

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse and validate token: %v", err)
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		logger.ErrorLogger.Errorf("Invalid token: %s", tokenString)
		return nil, fmt.Errorf("invalid token")
	}

	// --- ADD TOKEN VERSION CHECK HERE ---
	if claims.UserID == uuid.Nil {
		logger.ErrorLogger.Error("UserID claim is missing or invalid in token")
		return nil, fmt.Errorf("invalid token: user ID missing")
	}

	// Fetch the current token_version for the user from the database
	// This function `userTokenVersionFetcher` would be implemented in your service layer
	// and passed into ParseToken when called.
	currentUserTokenVersion, err := userTokenVersionFetcher(claims.UserID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch current user token version for user %s: %v", claims.UserID, err)
		// Depending on your error handling, you might return an error or consider it invalid.
		// For security, usually, if you can't verify the version, it's invalid.
		return nil, fmt.Errorf("token validation failed: cannot retrieve user token version")
	}

	if claims.TokenVersion < currentUserTokenVersion {
		logger.WarnLogger.Warnf("Token for user %s with version %d is older than current version %d. Token revoked.", claims.UserID, claims.TokenVersion, currentUserTokenVersion)
		return nil, fmt.Errorf("token has been revoked (password changed)")
	}
	// --- END TOKEN VERSION CHECK ---

	return claims, nil
}

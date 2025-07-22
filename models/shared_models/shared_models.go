package shared_models

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/utils" // Ensure utils package contains GetJWTSecret() and GetJWTRefreshSecret()
	"github.com/joy095/identity/utils/shared_utils"
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
	UserID       uuid.UUID `json:"sub"`
	Type         string    `json:"type"`
	TokenVersion int       `json:"token_version"`
	jwt.RegisteredClaims
}

// GenerateRefreshTokenWithJTI generates a refresh token with embedded jti
func GenerateRefreshTokenWithJTI(userID uuid.UUID, tokenVersion int, duration time.Duration) (string, string, error) {
	logger.InfoLogger.Infof("GenerateRefreshTokenWithJTI called for user %s", userID)

	now := time.Now()

	// Generate a short, URL-safe JTI
	jti, err := shared_utils.GenerateTinyID(12)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate jti: %w", err)
	}

	claims := jwt.MapClaims{
		"sub":           userID.String(),
		"iat":           now.Unix(),
		"exp":           now.Add(duration).Unix(),
		"nbf":           now.Unix(),
		"jti":           jti,
		"iss":           "identity-service",
		"type":          "refresh",
		"token_version": tokenVersion,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtRefreshSecret := utils.GetJWTRefreshSecret()

	tokenString, err := token.SignedString(jwtRefreshSecret)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to sign refresh token: %v", err)
		return "", "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return tokenString, jti, nil
}

// SetJWTCookie sets a JWT cookie with secure attributes
func SetJWTCookie(c *gin.Context, name, value string, expiry time.Duration, path string) error {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		Expires:  time.Now().Add(expiry),
		MaxAge:   int(expiry.Seconds()),
		HttpOnly: true, // Prevent JS access
		Secure:   true, //  Required with SameSite=None
		SameSite: http.SameSiteNoneMode,
	})

	logger.InfoLogger.Infof("Set cookie %s with path %s and expiry %v", name, path, expiry)
	return nil
}

// RemoveJWTCookie removes a JWT cookie by setting it to expire immediately
func RemoveJWTCookie(c *gin.Context, name, path string) error {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    "", // Empty value
		Path:     path,
		Expires:  time.Unix(0, 0), // Immediate expiration (Unix epoch)
		MaxAge:   -1,              // Instruct browser to delete immediately
		HttpOnly: true,            // Match security settings from SetJWTCookie
		Secure:   true,            // Required with SameSite=None
		SameSite: http.SameSiteNoneMode,
	})

	logger.InfoLogger.Infof("Removed cookie %s with path %s", name, path)
	return nil
}

// GenerateAccessToken creates a JWT token for access purposes
func GenerateAccessToken(userID uuid.UUID, tokenVersion int, duration time.Duration) (string, error) {
	now := time.Now()

	// Generate a short, URL-safe JTI
	jti, err := shared_utils.GenerateTinyID(12)
	if err != nil {
		return "", fmt.Errorf("failed to generate jti: %w", err)
	}

	claims := jwt.MapClaims{
		"sub":           userID.String(),
		"iat":           now.Unix(),
		"exp":           now.Add(duration).Unix(),
		"nbf":           now.Unix(),
		"jti":           jti,
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

	if claims.TokenVersion != currentUserTokenVersion {
		logger.WarnLogger.Warnf("Token for user %s with version %d is older than current version %d. Token revoked.", claims.UserID, claims.TokenVersion, currentUserTokenVersion)
		return nil, fmt.Errorf("token version mismatch: token has been revoked")
	}
	// --- END TOKEN VERSION CHECK ---

	return claims, nil
}

package auth

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/user_models"
	"github.com/joy095/identity/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware checks the authentication of the request using JWT token and validates token version.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.InfoLogger.Info("=== AuthMiddleware START ===")

		// Step 1: Read access_token from cookie
		tokenString, err := c.Cookie("access_token")
		if err != nil || tokenString == "" {
			logger.ErrorLogger.Error("Missing or empty access_token cookie - ABORTING")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: No token provided"})
			return
		}

		// Step 2: Parse and validate JWT
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return utils.GetJWTSecret(), nil
		})
		if err != nil || !token.Valid {
			logger.ErrorLogger.Errorf("Invalid JWT: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["sub"] == nil {
			logger.ErrorLogger.Error("Invalid token claims or missing sub")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		// Extract user ID and token version
		userIDClaim, ok := claims["sub"].(string)
		if !ok {
			logger.ErrorLogger.Error("Invalid sub in token")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
			return
		}

		userID, err := uuid.Parse(userIDClaim) // parse the string into a UUID
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to parse sub string '%s' into UUID: %v", userIDClaim, err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format in token"})
			return
		}

		tokenVersion, ok := claims["token_version"].(float64)
		if !ok {
			logger.ErrorLogger.Error("Missing or invalid token_version in JWT")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token version"})
			return
		}

		// Validate token version is a valid integer
		if tokenVersion != float64(int(tokenVersion)) || tokenVersion < 0 {
			logger.ErrorLogger.Error("Token version must be a non-negative integer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token version format"})
			return
		}

		// Step 3: Fetch user and compare token version
		user, err := user_models.GetUserByID(c.Request.Context(), db.DB, userID)
		if err != nil {
			logger.ErrorLogger.Errorf("User not found: %v", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}

		if user.TokenVersion != int(tokenVersion) {
			logger.ErrorLogger.Errorf("Token version mismatch for user %s", user.ID)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Session expired. Please log in again."})
			return
		}

		// Optional: Email verification check
		isVerified, err := user_models.IsEmailVerified(c.Request.Context(), db.DB, user.ID)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to check email verification for user %s: %v", user.ID, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		if !isVerified {
			logger.ErrorLogger.Errorf("Email not verified for user %s", user.ID)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Email not verified"})
		}

		// Success
		c.Set("sub", user.ID.String())
		c.Set("authenticated_user", user)
		logger.InfoLogger.Infof("=== AuthMiddleware SUCCESS - User %s authenticated ===", user.ID)
		c.Next()
	}
}

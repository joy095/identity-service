package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/user_models"
	"github.com/joy095/identity/utils"
	"github.com/joy095/identity/utils/jwt_parse"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware checks the authentication of the request using JWT token and validates token version.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.InfoLogger.Info("=== AuthMiddleware START ===")

		// Parse JWT token and extract claims by calling the JWT parser.
		logger.InfoLogger.Info("Calling JWT parser helper...")
		jwt_parse.ParseJWTToken()(c) // This invokes the handler returned by ParseJWTToken

		// CRITICAL: Check if the request was aborted by the JWT parser helper
		if c.IsAborted() {
			logger.ErrorLogger.Error("JWT parsing/validation failed (aborted by jwt_parse) - stopping AuthMiddleware execution")
			return // Stop further processing in this middleware
		}

		logger.InfoLogger.Info("JWT parsing helper completed, checking essential context values...")

		userIDFromToken, exists := c.Get("user_id")
		if !exists {
			logger.ErrorLogger.Error("User ID not found in context (expected from JWT parser) - ABORTING")
			c.Header("Content-Type", "application/json")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": "UNAUTHORIZED", "error": "Unauthorized: Missing user identification from token."})
			return
		}
		logger.InfoLogger.Infof("Found user_id in context: %v", userIDFromToken)

		tokenVersionFromJWT, tokenVersionExists := c.Get("token_version")
		var tokenVersion int

		if tokenVersionExists {
			logger.InfoLogger.Infof("Token version found in context: %v", tokenVersionFromJWT)
			switch v := tokenVersionFromJWT.(type) {
			case float64:
				tokenVersion = int(v)
			case int:
				tokenVersion = v
			case int64:
				tokenVersion = int(v)
			default:
				logger.ErrorLogger.Errorf("Invalid token version type in JWT (from context): %T - ABORTING", tokenVersionFromJWT)
				c.Header("Content-Type", "application/json")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": "INVALID_TOKEN", "error": "Invalid token version format."})
				return
			}
		} else {
			logger.WarnLogger.Warn("Token version not found in context, attempting to extract from raw token as fallback.")
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" {
				logger.ErrorLogger.Error("No authorization header found (fallback) - ABORTING")
				c.Header("Content-Type", "application/json")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": "NO_TOKEN", "error": "No authorization token provided."})
				return
			}
			var rawToken string
			if len(authHeader) > 7 && strings.ToLower(authHeader[:7]) == "bearer " {
				rawToken = authHeader[7:]
			} else {
				logger.ErrorLogger.Error("Invalid authorization header format (fallback) - ABORTING")
				c.Header("Content-Type", "application/json")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": "INVALID_AUTH_FORMAT", "error": "Invalid authorization format."})
				return
			}
			var errExtract error
			tokenVersion, errExtract = extractTokenVersionFromJWT(rawToken) // Uses your existing helper
			if errExtract != nil {
				logger.ErrorLogger.Errorf("Failed to extract token version via fallback: %v - ABORTING", errExtract)
				c.Header("Content-Type", "application/json")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": "INVALID_TOKEN_FALLBACK", "error": "Invalid token (fallback parsing failed)."})
				return
			}
		}
		logger.InfoLogger.Infof("Effective token version from JWT: %d", tokenVersion)

		// User fetching and validation logic
		usernameParam := c.Param("username")
		rawBody, _ := c.GetRawData()
		c.Request.Body = io.NopCloser(bytes.NewBuffer(rawBody)) // Restore body

		var bodyData struct {
			UserID string `json:"user_id"`
		}
		if len(rawBody) > 0 {
			if err := json.Unmarshal(rawBody, &bodyData); err != nil {
				logger.WarnLogger.Warnf("Could not unmarshal request body: %v. Proceeding without body UserID.", err)
			}
		}

		var user *user_models.User
		var err error

		userIDStr, ok := userIDFromToken.(string)
		if !ok {
			logger.ErrorLogger.Errorf("User ID from token context is not a string: %T - ABORTING", userIDFromToken)
			c.Header("Content-Type", "application/json")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": "INVALID_TOKEN_UID_TYPE", "error": "Invalid user ID type in token."})
			return
		}

		logger.InfoLogger.Infof("Fetching user by ID from token: %s", userIDStr)
		user, err = user_models.GetUserByID(db.DB, userIDStr)
		if err != nil {
			logger.ErrorLogger.Errorf("User (ID: %s) not found based on token: %v - ABORTING", userIDStr, err)
			c.Header("Content-Type", "application/json")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": "USER_TOKEN_INVALID", "error": "User associated with token not found."})
			return
		}

		// Authorization checks
		if usernameParam != "" && user.Username != usernameParam {
			logger.ErrorLogger.Errorf("Path username (%s) does not match token user (%s) - FORBIDDEN", usernameParam, user.Username)
			c.Header("Content-Type", "application/json")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": "ACCESS_DENIED", "error": "Forbidden: Mismatched user."})
			return
		}
		if bodyData.UserID != "" && user.ID.String() != bodyData.UserID {
			logger.ErrorLogger.Errorf("Body UserID (%s) does not match token user (%s) - FORBIDDEN", bodyData.UserID, user.ID.String())
			c.Header("Content-Type", "application/json")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": "ACCESS_DENIED", "error": "Forbidden: Mismatched user ID in body."})
			return
		}

		logger.InfoLogger.Infof("User validated: ID: %s, DBTokenVersion: %d", user.ID, user.TokenVersion)
		logger.InfoLogger.Infof("Comparing token versions - JWT effective: %d vs DB: %d", tokenVersion, user.TokenVersion)

		if tokenVersion != user.TokenVersion {
			logger.ErrorLogger.Errorf("TOKEN VERSION MISMATCH DETECTED - JWT(%d) vs DB(%d) for user %s - ABORTING REQUEST",
				tokenVersion, user.TokenVersion, user.ID)
			c.Header("Content-Type", "application/json")
			// c.Abort() // Explicitly call Abort first
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Session expired. Please log in again.",
			})
			return // CRITICAL
		}

		logger.InfoLogger.Info("Token version match successful. Checking email verification...")
		isVerified, err := user_models.IsEmailVerified(db.DB, user.ID)
		if err != nil {
			logger.ErrorLogger.Errorf("Error checking email verification for user %s: %v - ABORTING", user.ID, err)
			c.Header("Content-Type", "application/json")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": "SERVER_ERROR", "error": "Internal server error during email verification."})
			return
		}
		if !isVerified {
			logger.ErrorLogger.Errorf("Email not verified for user %s - ABORTING", user.ID)
			c.Header("Content-Type", "application/json")
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": "EMAIL_NOT_VERIFIED", "error": "Email not verified."})
			return
		}

		logger.InfoLogger.Info("Email verification successful.")
		c.Set("authenticated_user", user) // user_id should already be in context from jwt_parse

		logger.InfoLogger.Infof("=== AuthMiddleware SUCCESS - User %s authenticated ===", userIDFromToken)
		c.Next() // Proceed to the actual route handler
	}
}

// extractTokenVersionFromJWT remains the same as you provided it.
// It's used as a fallback if token_version is not found in context.
func extractTokenVersionFromJWT(tokenString string) (int, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return utils.GetJWTSecret(), nil
	})

	if err != nil {
		return 0, fmt.Errorf("failed to parse token: %w", err)
	}
	if !token.Valid {
		return 0, fmt.Errorf("token is not valid")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, fmt.Errorf("invalid token claims")
	}
	tokenVersionClaim, exists := claims["token_version"]
	if !exists {
		return 0, fmt.Errorf("token_version not found in token claims")
	}
	switch v := tokenVersionClaim.(type) {
	case float64:
		return int(v), nil
	case int:
		return v, nil
	case int64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("invalid token_version type: %T", v)
	}
}

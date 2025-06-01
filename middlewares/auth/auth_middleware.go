package auth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/user_models"
	"github.com/joy095/identity/utils/jwt_parse"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware checks the authentication of the request using JWT token.
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.InfoLogger.Info("AuthMiddleware called")

		jwt_parse.ParseJWTToken()(c)

		userIDFromToken, exists := c.Get("user_id")
		if !exists {
			logger.ErrorLogger.Error("User ID not found in context")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		usernameParam := c.Param("username")
		rawBody, _ := c.GetRawData()
		c.Request.Body = io.NopCloser(bytes.NewBuffer(rawBody)) // Restore body for subsequent handlers

		var body struct {
			UserID string `json:"user_id"`
		}
		json.Unmarshal(rawBody, &body)

		var user *user_models.User
		var err error

		// Fetch user based on provided param or body
		if usernameParam != "" {
			user, err = user_models.GetUserByUsername(db.DB, usernameParam)
			if err != nil {
				logger.ErrorLogger.Errorf("User not found: %v", err)
				c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
				c.Abort()
				return
			}
			// Important: Compare the UUID string from the token with the UUID string from the fetched user.
			if user.ID.String() != userIDFromToken {
				logger.ErrorLogger.Errorf("User ID mismatch: token(%s) vs db(%s)", userIDFromToken, user.ID)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
				c.Abort()
				return
			}
		} else if body.UserID != "" {
			// Important: Compare the UUID string from the token with the UUID string from the request body.
			if body.UserID != userIDFromToken {
				logger.ErrorLogger.Errorf("User ID mismatch: token(%s) vs body(%s)", userIDFromToken, body.UserID)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized access"})
				c.Abort()
				return
			}
			user, err = user_models.GetUserByID(db.DB, body.UserID)
			if err != nil {
				logger.ErrorLogger.Errorf("User not found: %v", err)
				c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
				c.Abort()
				return
			}
		} else {
			// If neither username param nor user_id in body is provided, try to get user by userIDFromToken directly
			userIDStr, ok := userIDFromToken.(string)
			if !ok {
				logger.ErrorLogger.Error("Invalid user ID type in token")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
				c.Abort()
				return
			}
			user, err = user_models.GetUserByID(db.DB, userIDStr)
			if err != nil {
				logger.ErrorLogger.Errorf("User not found based on token ID: %v", err)
				c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
				c.Abort()
				return
			}
		}

		// Check if email is verified
		isVerified, err := user_models.IsEmailVerified(db.DB, user.ID)
		if err != nil {
			logger.ErrorLogger.Errorf("Error checking email verification: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			c.Abort()
			return
		}
		if !isVerified {
			logger.ErrorLogger.Error("Email not verified")
			c.JSON(http.StatusForbidden, gin.H{"error": "Email not verified"})
			c.Abort()
			return
		}

		// Pass user_id along
		c.Set("user_id", userIDFromToken)
		logger.InfoLogger.Infof("Authenticated & verified user_id: %s", userIDFromToken)
		c.Next()
	}
}

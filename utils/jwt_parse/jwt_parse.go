package jwt_parse

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/utils"
)

// Your JWT secret key - this should come from environment variables
// var jwtSecret = []byte("your-secret-key") // Replace with your actual secret
// var jwtSecret = os.Getenv("JWT_SECRET")

// ParseJWTToken parses and validates JWT token, setting claims in context
func ParseJWTToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logger.ErrorLogger.Error("No authorization header provided")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No authorization token"})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>" format
		var tokenString string
		if len(authHeader) > 7 && strings.ToLower(authHeader[:7]) == "bearer " {
			tokenString = authHeader[7:]
		} else {
			logger.ErrorLogger.Error("Invalid authorization header format")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}

		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return utils.GetJWTSecret(), nil
		})

		if err != nil {
			logger.ErrorLogger.Errorf("Failed to parse JWT token: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Validate token and extract claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Extract and set user_id
			if userID, exists := claims["user_id"]; exists {
				c.Set("user_id", userID)
			} else if sub, exists := claims["sub"]; exists {
				// If user_id doesn't exist, try 'sub' claim
				c.Set("user_id", sub)
			} else {
				logger.ErrorLogger.Error("No user identifier found in token")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
				c.Abort()
				return
			}

			// Extract and set token_version
			if tokenVersion, exists := claims["token_version"]; exists {
				c.Set("token_version", tokenVersion)
			} else {
				logger.WarnLogger.Warn("Token version not found in JWT claims")
				// Don't abort here - let the auth middleware handle it
			}

			// Extract and set other useful claims
			if jti, exists := claims["jti"]; exists {
				c.Set("jti", jti)
			}
			if tokenType, exists := claims["type"]; exists {
				c.Set("token_type", tokenType)
			}

			logger.InfoLogger.Infof("Successfully parsed JWT token for user: %v", claims["user_id"])
			c.Next()
		} else {
			logger.ErrorLogger.Error("Invalid token claims")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
	}
}

// ExtractUserID extracts the user_id from the JWT token in the request context.
// This function remains largely the same, as it only needs the user_id.
func ExtractUserID(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header required")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(utils.GetJWTSecret()), nil
	})
	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	userIDFromToken, ok := claims["user_id"].(string)
	if !ok {
		return "", errors.New("token does not contain user_id")
	}

	return userIDFromToken, nil
}

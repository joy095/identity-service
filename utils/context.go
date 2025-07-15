// identity/utils/context.go
package utils

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joy095/identity/logger"
)

// GetUserIDFromContext extracts the user ID from the Gin context.
// It assumes the user ID is set in the context as a STRING under the key "sub"
// by an authentication middleware and then parses it into a uuid.UUID.
func GetUserIDFromContext(c *gin.Context) (uuid.UUID, error) {
	ownerUserID, exists := c.Get("sub") // Use "sub" as per your code
	if !exists {
		logger.ErrorLogger.Error("User ID not found in context.")
		return uuid.Nil, fmt.Errorf("authentication required: user ID not found")
	}

	// Attempt to cast to string first, as it's a common way user IDs are stored
	userIDStr, ok := ownerUserID.(string)
	if !ok {
		logger.ErrorLogger.Errorf("User ID in context is not a string, actual type: %T", ownerUserID)
		return uuid.Nil, fmt.Errorf("internal server error: invalid user ID format in context")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse user ID string '%s' to UUID: %v", userIDStr, err)
		return uuid.Nil, fmt.Errorf("internal server error: invalid user ID format")
	}
	return userID, nil
}

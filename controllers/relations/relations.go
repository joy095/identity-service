package relations

import (
	"context"
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models"
	"github.com/joy095/identity/utils/jwt_parse"
)

// RelationController handles user relationship operations
type RelationController struct{}

func NewRelationController() *RelationController {
	return &RelationController{}
}

// SendRequest sends a friend request to another user
func (r *RelationController) SendRequest(c *gin.Context) {
	var payload struct {
		ToUserID string `json:"addressee_id"`
	}

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	fromUserID, err := jwt_parse.ExtractUserID(c)
	if err != nil {
		logger.ErrorLogger.Error("Failed to extract user ID: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Check for empty user IDs
	if fromUserID == "" || payload.ToUserID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing user ID(s)"})
		return
	}

	// Validate UUIDs
	if _, err := uuid.Parse(fromUserID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sender UUID format"})
		return
	}
	if _, err := uuid.Parse(payload.ToUserID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid addressee UUID format"})
		return
	}

	if fromUserID == payload.ToUserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot send request to yourself"})
		return
	}

	// Check for existing relationship
	var exists bool
	err = db.DB.QueryRow(context.Background(), `
		SELECT EXISTS(
			SELECT 1 FROM user_connections 
			WHERE (requester_id = $1 AND addressee_id = $2) 
			OR (requester_id = $2 AND addressee_id = $1)
		)
	`, fromUserID, payload.ToUserID).Scan(&exists)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check existing relationship"})
		return
	}

	if exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Relationship already exists"})
		return
	}

	_, err = db.DB.Exec(context.Background(), `
		INSERT INTO user_connections (requester_id, addressee_id, status)
		VALUES ($1, $2, 'pending')
	`, fromUserID, payload.ToUserID)

	if err != nil {
		log.Printf("Error inserting connection request (from: %s, to: %s): %v", fromUserID, payload.ToUserID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send request"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Connection request sent"})
}

// AcceptRequest handles accepting a pending connection request.
func (r *RelationController) AcceptRequest(c *gin.Context) {
	var payload struct {
		FromUserID string `json:"requester_id"`
	}

	// Validate request body
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Extract authenticated user's ID (as addressee)
	toUserID, err := jwt_parse.ExtractUserID(c)
	if err != nil {
		logger.ErrorLogger.Error("Failed to extract user ID: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Validate UUIDs
	if _, err := uuid.Parse(payload.FromUserID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid requester UUID format"})
		return
	}
	if _, err := uuid.Parse(toUserID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid addressee UUID format"})
		return
	}

	// Perform update: accept the request if pending
	result, err := db.DB.Exec(context.Background(), `
		UPDATE user_connections 
		SET status = 'accepted', updated_at = NOW()
		WHERE requester_id = $1 AND addressee_id = $2 AND status = 'pending'
	`, payload.FromUserID, toUserID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to accept request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to accept request"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No pending request found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Connection request accepted"})
}

// RejectRequest reject request from a user
func (r *RelationController) RejectRequest(c *gin.Context) {
	var payload struct {
		FromUserID string `json:"requester_id"`
	}

	// Bind JSON payload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Extract the authenticated user ID (toUserID)
	toUserID, err := jwt_parse.ExtractUserID(c)
	if err != nil {
		logger.ErrorLogger.Error("Failed to extract user ID: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Validate UUIDs
	if _, err := uuid.Parse(payload.FromUserID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid requester UUID format"})
		return
	}
	if _, err := uuid.Parse(toUserID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid addressee UUID format"})
		return
	}

	// Delete the pending request
	result, err := db.DB.Exec(context.Background(), `
		DELETE FROM user_connections
		WHERE requester_id = $1 AND addressee_id = $2 AND status = 'pending'
	`, payload.FromUserID, toUserID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to reject request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reject request"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "No pending request found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Connection request rejected"})
}

func (r *RelationController) ListPendingRequests(c *gin.Context) {
	// Extract the authenticated user ID (toUserID)
	userID, err := jwt_parse.ExtractUserID(c)
	if err != nil {
		logger.ErrorLogger.Error("Failed to extract user ID: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	rows, err := db.DB.Query(context.Background(), `
		SELECT requester_id FROM user_connections WHERE addressee_id = $1 AND status = 'pending'
	`, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch requests"})
		return
	}
	defer rows.Close()

	var pending []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		pending = append(pending, id)
	}
	c.JSON(http.StatusOK, gin.H{"pending_requests": pending})
}

func (r *RelationController) ListConnections(c *gin.Context) {

	// Extract the authenticated user ID (toUserID)
	userID, err := jwt_parse.ExtractUserID(c)
	if err != nil {
		logger.ErrorLogger.Error("Failed to extract user ID: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	rows, err := db.DB.Query(context.Background(), `
		SELECT requester_id, addressee_id FROM user_connections 
		WHERE (requester_id = $1 OR addressee_id = $1) AND status = 'accepted'
	`, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch connections"})
		return
	}
	defer rows.Close()

	connections := []string{}
	for rows.Next() {
		var fromID, toID string
		rows.Scan(&fromID, &toID)
		if fromID == userID {
			connections = append(connections, toID)
		} else {
			connections = append(connections, fromID)
		}
	}
	c.JSON(http.StatusOK, gin.H{"connections": connections})
}

// CheckConnectionStatus Check connection status between two users using JWT and specific user route
func (r *RelationController) CheckConnectionStatus(c *gin.Context) {
	// Extract the authenticated user ID
	userID, err := jwt_parse.ExtractUserID(c)
	if err != nil {
		logger.ErrorLogger.Error("Failed to extract user ID: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	username := c.Param("username")

	log.Print("Username: ", username)

	user, err := models.GetUserByUsername(db.DB, username)
	if err != nil {
		logger.ErrorLogger.Error("User not found")
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	targetID := user.ID.String()

	// Validate UUIDs
	if _, err := uuid.Parse(userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}
	if _, err := uuid.Parse(targetID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid target user ID format"})
		return
	}

	// Query the connection status
	var status string
	query := `
		SELECT status FROM user_connections 
		WHERE (requester_id = $1 AND addressee_id = $2)
		   OR (requester_id = $2 AND addressee_id = $1)
	`
	err = db.DB.QueryRow(context.Background(), query, userID, targetID).Scan(&status)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusOK, gin.H{"status": "none"})
		return
	} else if err != nil {
		logger.ErrorLogger.Errorf("Database error while checking connection status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": status})
}

package video_controller

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	redisclient "github.com/joy095/identity/config/redis"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/video_models"
	"github.com/joy095/identity/utils"
)

type VideoController struct{ db *pgxpool.Pool }

// NewVideoController creates and returns a new instance of VideoController
func NewVideoController(db *pgxpool.Pool) (*VideoController, error) {
	if db == nil {
		return nil, errors.New("database pool cannot be nil")
	}

	return &VideoController{
		db: db,
	}, nil
}

func (vc *VideoController) JoinVideo(c *gin.Context) {
	logger.InfoLogger.Info("JoinVideo controller called")

	orderIdStr := strings.TrimSpace(c.Param("orderId"))
	if orderIdStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "orderId is required"})
		return
	}

	orderId, err := uuid.Parse(orderIdStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid order ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid order ID format"})
		return
	}

	// --- FETCH ORDER DETAILS ---
	videoAccess, err := video_models.GetVideoAccessDetails(c.Request.Context(), vc.db, orderId)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Order not found"})
			return
		}
		logger.ErrorLogger.Errorf("Failed to retrieve video access: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve video access"})
		return
	}

	// --- AUTHORIZATION CHECK ---
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Errorf("Error extracting user: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Only customer or business owner can join the video call
	if userID != videoAccess.CustomerID && userID != *videoAccess.OwnerID {
		logger.WarnLogger.Warnf("Unauthorized access attempt by user %s on order %s", userID, orderId)
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// --- REDIS TTL CALCULATION ---
	// now := time.Now()
	validFrom := videoAccess.StartTime.Add(-30 * time.Minute)
	validUntil := videoAccess.EndTime.Add(30 * time.Minute)

	ttl := time.Until(validUntil)
	if ttl <= 0 {
		logger.WarnLogger.Warnf("Order %s video window already expired", orderId)
		c.JSON(http.StatusForbidden, gin.H{"error": "Video session expired"})
		return
	}

	// Optional: prevent early join
	// if now.Before(validFrom) {
	// 	waitMins := validFrom.Sub(now).Minutes()
	// 	c.JSON(http.StatusForbidden, gin.H{
	// 		"error": fmt.Sprintf("Video call not started yet. Please wait %.0f minutes", waitMins),
	// 	})
	// 	return
	// }

	// --- REDIS ACCESS KEY ---
	rdb, err := redisclient.GetRedisClient(c.Request.Context())
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to init Redis client: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Redis init failed"})
		return
	}

	redisKey := fmt.Sprintf("video:access:%s:%s", orderId, userID) // unique per user
	if err := rdb.Set(c.Request.Context(), redisKey, "granted", ttl).Err(); err != nil {
		logger.ErrorLogger.Errorf("Failed to set Redis key %s: %v", redisKey, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store video access"})
		return
	}

	logger.InfoLogger.Infof("User %s granted video access for order %s with TTL %v", userID, orderId, ttl)

	// --- RESPONSE ---
	c.JSON(http.StatusOK, gin.H{
		"video": gin.H{
			"id":          videoAccess.Id,
			"customer_id": videoAccess.CustomerID,
			"status":      videoAccess.Status,
			"start_time":  videoAccess.StartTime,
			"end_time":    videoAccess.EndTime,
		},
		"service_id":  videoAccess.ServiceID,
		"business_id": videoAccess.BusinessID,
		"owner_id":    videoAccess.OwnerID,
		"ttl_seconds": int(ttl.Seconds()),
		"valid_from":  validFrom,
		"valid_until": validUntil,
	})
}

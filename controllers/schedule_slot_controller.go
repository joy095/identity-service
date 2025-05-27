// controllers/schedule_slot_controller.go
package controllers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time" // For parsing time strings

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	// Adjust import path
	"github.com/joy095/identity/logger" // Adjust import path
	"github.com/joy095/identity/models" // Adjust import path
	"github.com/joy095/identity/utils"
)

// ScheduleSlotController holds dependencies for schedule slot operations.
type ScheduleSlotController struct {
	DB *pgxpool.Pool
}

// NewScheduleSlotController creates a new instance of ScheduleSlotController.
func NewScheduleSlotController(db *pgxpool.Pool) *ScheduleSlotController {
	return &ScheduleSlotController{
		DB: db,
	}
}

// CreateScheduleSlotRequest represents the expected JSON payload for creating a schedule slot.
type CreateScheduleSlotRequest struct {
	BusinessID uuid.UUID `json:"businessId" binding:"required"`
	DayOfWeek  string    `json:"dayOfWeek" binding:"required,oneof=Monday Tuesday Wednesday Thursday Friday Saturday Sunday"`
	OpenTime   string    `json:"openTime" binding:"required,datetime=15:04:05"`  // HH:MM:SS format
	CloseTime  string    `json:"closeTime" binding:"required,datetime=15:04:05"` // HH:MM:SS format
	IsClosed   bool      `json:"isClosed"`
}

// UpdateScheduleSlotRequest represents the expected JSON payload for updating a schedule slot.
type UpdateScheduleSlotRequest struct {
	DayOfWeek *string `json:"dayOfWeek,omitempty" binding:"omitempty,oneof=Monday Tuesday Wednesday Thursday Friday Saturday Sunday"`
	OpenTime  *string `json:"openTime,omitempty" binding:"omitempty,datetime=15:04:05"`
	CloseTime *string `json:"closeTime,omitempty" binding:"omitempty,datetime=15:04:05"`
	IsClosed  *bool   `json:"isClosed,omitempty"`
}

// validateScheduleTimes ensures open_time < close_time if not closed
func validateScheduleTimes(openTimeStr, closeTimeStr string, isClosed bool) error {
	if isClosed {
		return nil // No time validation needed if the slot is closed
	}

	openTime, err := time.Parse("15:04:05", openTimeStr)
	if err != nil {
		return fmt.Errorf("invalid open time format: %w", err)
	}
	closeTime, err := time.Parse("15:04:05", closeTimeStr)
	if err != nil {
		return fmt.Errorf("invalid close time format: %w", err)
	}

	if closeTime.Before(openTime) || closeTime.Equal(openTime) {
		return fmt.Errorf("close time must be after open time")
	}
	return nil
}

// CreateScheduleSlot handles the HTTP request to create a new schedule slot.
func (sc *ScheduleSlotController) CreateScheduleSlot(c *gin.Context) {
	logger.InfoLogger.Info("CreateScheduleSlot controller called")

	var req CreateScheduleSlotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid request payload for CreateScheduleSlot: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request data: %s", err.Error())})
		return
	}

	if err := validateScheduleTimes(req.OpenTime, req.CloseTime, req.IsClosed); err != nil {
		logger.ErrorLogger.Errorf("Schedule time validation failed: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		// More robust error type checking
		if errors.Is(err, utils.ErrUserIDNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: " + err.Error()})
		}
		return
	}

	// Verify that the business exists and belongs to the authenticated user
	business, err := models.GetBusinessByID(sc.DB, req.BusinessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for schedule slot creation: %v", req.BusinessID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Associated business not found"})
		return
	}

	if business.OwnerID != ownerUserID {
		logger.ErrorLogger.Warnf("User %s attempted to create schedule slot for unowned business %s", ownerUserID, req.BusinessID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to set schedule for this business"})
		return
	}

	// Create a models.ScheduleSlot instance
	slot := models.NewScheduleSlot(
		req.BusinessID,
		req.DayOfWeek,
		req.OpenTime,
		req.CloseTime,
		req.IsClosed,
	)

	createdSlot, err := models.CreateScheduleSlot(sc.DB, slot)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create schedule slot in database: %v", err)
		// Check for specific errors, e.g., unique constraint violation
		if strings.Contains(err.Error(), "unique_business_day_slot") {
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Schedule for %s already exists for this business. Use PUT to update.", req.DayOfWeek)})
		} else if strings.Contains(err.Error(), "foreign key constraint") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID provided"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create schedule slot"})
		}
		return
	}

	logger.InfoLogger.Infof("Schedule slot %s created successfully for business %s by user %s", createdSlot.ID, req.BusinessID, ownerUserID)
	c.JSON(http.StatusCreated, gin.H{
		"message":      "Schedule slot created successfully!",
		"scheduleSlot": createdSlot,
	})
}

// GetScheduleSlotByID handles fetching a single schedule slot.
func (sc *ScheduleSlotController) GetScheduleSlotByID(c *gin.Context) {
	logger.InfoLogger.Info("GetScheduleSlotByID controller called")

	slotIDStr := c.Param("id")
	slotID, err := uuid.Parse(slotIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid schedule slot ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid schedule slot ID format"})
		return
	}

	slot, err := models.GetScheduleSlotByID(sc.DB, slotID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch schedule slot %s: %v", slotID, err)
		if strings.Contains(err.Error(), "schedule slot not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Schedule slot not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch schedule slot"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"scheduleSlot": slot})
}

// GetScheduleSlotsByBusinessID handles fetching all schedule slots for a specific business.
func (sc *ScheduleSlotController) GetScheduleSlotsByBusinessID(c *gin.Context) {
	logger.InfoLogger.Info("GetScheduleSlotsByBusinessID controller called")

	businessIDStr := c.Param("business_id")
	businessID, err := uuid.Parse(businessIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid business ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
		return
	}

	slots, err := models.GetScheduleSlotsByBusinessID(sc.DB, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch schedule slots for business %s: %v", businessID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch schedule slots"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"scheduleSlots": slots})
}

// UpdateScheduleSlot handles the HTTP request to update an existing schedule slot.
func (sc *ScheduleSlotController) UpdateScheduleSlot(c *gin.Context) {
	logger.InfoLogger.Info("UpdateScheduleSlot controller called")

	slotIDStr := c.Param("id")
	slotID, err := uuid.Parse(slotIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid schedule slot ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid schedule slot ID format"})
		return
	}

	var req UpdateScheduleSlotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid request payload for UpdateScheduleSlot: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request data: %s", err.Error())})
		return
	}

	// Extract user ID from authenticated context (to ensure business ownership)
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		if err.Error() == "authentication required: user ID not found" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	// Fetch the existing slot to get its business_id and check ownership
	existingSlot, err := models.GetScheduleSlotByID(sc.DB, slotID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch schedule slot %s for update: %v", slotID, err)
		if strings.Contains(err.Error(), "schedule slot not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Schedule slot not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch schedule slot"})
		}
		return
	}

	// Verify that the business associated with this slot belongs to the authenticated user
	business, err := models.GetBusinessByID(sc.DB, existingSlot.BusinessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for schedule slot %s ownership check: %v", existingSlot.BusinessID, slotID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: business lookup failed"})
		return
	}

	if business.OwnerID != ownerUserID {
		logger.ErrorLogger.Warnf("User %s attempted to update schedule slot %s for unowned business %s", ownerUserID, slotID, existingSlot.BusinessID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to update this schedule slot"})
		return
	}

	// Apply updates from the request to the existing slot
	updatedDayOfWeek := existingSlot.DayOfWeek
	updatedOpenTime := existingSlot.OpenTime
	updatedCloseTime := existingSlot.CloseTime
	updatedIsClosed := existingSlot.IsClosed

	if req.DayOfWeek != nil {
		updatedDayOfWeek = *req.DayOfWeek
	}
	if req.OpenTime != nil {
		updatedOpenTime = *req.OpenTime
	}
	if req.CloseTime != nil {
		updatedCloseTime = *req.CloseTime
	}
	if req.IsClosed != nil {
		updatedIsClosed = *req.IsClosed
	}

	// Re-validate times with potentially updated values
	if err := validateScheduleTimes(updatedOpenTime, updatedCloseTime, updatedIsClosed); err != nil {
		logger.ErrorLogger.Errorf("Schedule time validation failed during update: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existingSlot.DayOfWeek = updatedDayOfWeek
	existingSlot.OpenTime = updatedOpenTime
	existingSlot.CloseTime = updatedCloseTime
	existingSlot.IsClosed = updatedIsClosed

	updatedSlot, err := models.UpdateScheduleSlot(sc.DB, existingSlot)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update schedule slot %s in database: %v", slotID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update schedule slot"})
		return
	}

	logger.InfoLogger.Infof("Schedule slot %s updated successfully by user %s", slotID, ownerUserID)
	c.JSON(http.StatusOK, gin.H{
		"message":      "Schedule slot updated successfully!",
		"scheduleSlot": updatedSlot,
	})
}

// DeleteScheduleSlot handles the HTTP request to delete a schedule slot.
func (sc *ScheduleSlotController) DeleteScheduleSlot(c *gin.Context) {
	logger.InfoLogger.Info("DeleteScheduleSlot controller called")

	slotIDStr := c.Param("id")
	slotID, err := uuid.Parse(slotIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid schedule slot ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid schedule slot ID format"})
		return
	}

	// Extract user ID from authenticated context (to ensure business ownership)
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		if err.Error() == "authentication required: user ID not found" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	// Fetch the existing slot to get its business_id and check ownership
	existingSlot, err := models.GetScheduleSlotByID(sc.DB, slotID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch schedule slot %s for deletion: %v", slotID, err)
		if strings.Contains(err.Error(), "schedule slot not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Schedule slot not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch schedule slot"})
		}
		return
	}

	// Verify that the business associated with this slot belongs to the authenticated user
	business, err := models.GetBusinessByID(sc.DB, existingSlot.BusinessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for schedule slot %s ownership check: %v", existingSlot.BusinessID, slotID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: business lookup failed"})
		return
	}

	if business.OwnerID != ownerUserID {
		logger.ErrorLogger.Warnf("User %s attempted to delete schedule slot %s for unowned business %s", ownerUserID, slotID, existingSlot.BusinessID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to delete this schedule slot"})
		return
	}

	if err := models.DeleteScheduleSlot(sc.DB, slotID, existingSlot.BusinessID); err != nil {
		logger.ErrorLogger.Errorf("Failed to delete schedule slot %s from database: %v", slotID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete schedule slot"})
		return
	}

	logger.InfoLogger.Infof("Schedule slot %s deleted successfully by user %s", slotID, ownerUserID)
	c.JSON(http.StatusOK, gin.H{"message": "Schedule slot deleted successfully"})
}

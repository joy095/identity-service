package schedule_slot_controller

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/schedule_slot_models"
	"github.com/joy095/identity/utils"
)

// ScheduleSlotController handles HTTP requests for schedule slots management
type ScheduleSlotController struct{}

// NewScheduleSlotController creates a new schedule slot controller
func NewScheduleSlotController() *ScheduleSlotController {
	return &ScheduleSlotController{}
}

// CreateScheduleSlotRequest represents the request payload for creating a new schedule slot
type CreateScheduleSlotRequest struct {
	BusinessID  uuid.UUID `json:"business_id" binding:"required"`
	OpenTime    time.Time `json:"open_time" binding:"required"`
	CloseTime   time.Time `json:"close_time" binding:"required"`
	IsAvailable bool      `json:"is_available"`
}

// UpdateScheduleSlotRequest represents the request payload for updating a schedule slot
type UpdateScheduleSlotRequest struct {
	OpenTime    *time.Time `json:"open_time,omitempty"`
	CloseTime   *time.Time `json:"close_time,omitempty"`
	IsAvailable *bool      `json:"is_available,omitempty"`
}

// ScheduleSlotResponse represents the standardized schedule slot response
type ScheduleSlotResponse struct {
	Slot    *schedule_slot_models.ScheduleSlot `json:"slot"`
	Message string                            `json:"message,omitempty"`
}

// ScheduleSlotListResponse represents paginated schedule slot list response
type ScheduleSlotListResponse struct {
	Slots      []schedule_slot_models.ScheduleSlot `json:"slots"`
	TotalCount int                                 `json:"total_count"`
	Page       int                                 `json:"page"`
	Limit      int                                 `json:"limit"`
	HasMore    bool                                `json:"has_more"`
}

// CreateScheduleSlot creates a new schedule slot for a business
func (sc *ScheduleSlotController) CreateScheduleSlot(c *gin.Context) {
	var req CreateScheduleSlotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.WarnLogger.Warnf("Invalid create schedule slot request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	// Validate that open time is before close time
	if req.OpenTime.After(req.CloseTime) || req.OpenTime.Equal(req.CloseTime) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Open time must be before close time"})
		return
	}

	// Get authenticated user ID (for business owner validation if needed)
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// TODO: Add business owner validation - check if userID owns businessID
	logger.InfoLogger.Infof("User %s creating schedule slot for business %s", userID, req.BusinessID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create new schedule slot
	newSlot, err := schedule_slot_models.NewScheduleSlot(req.BusinessID, req.OpenTime, req.CloseTime, req.IsAvailable)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create new schedule slot object: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal error creating slot"})
		return
	}

	createdSlot, err := schedule_slot_models.CreateScheduleSlot(ctx, db.DB, newSlot)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to save schedule slot to DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create schedule slot"})
		return
	}

	logger.InfoLogger.Infof("Schedule slot %s created successfully for business %s", createdSlot.ID, req.BusinessID)
	c.JSON(http.StatusCreated, ScheduleSlotResponse{
		Slot:    createdSlot,
		Message: "Schedule slot created successfully",
	})
}

// GetScheduleSlot retrieves a single schedule slot by ID
func (sc *ScheduleSlotController) GetScheduleSlot(c *gin.Context) {
	slotIDStr := c.Param("slot_id")
	slotID, err := uuid.Parse(slotIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid slot ID format"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	slot, err := schedule_slot_models.GetScheduleSlotByID(ctx, db.DB, slotID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch schedule slot %s: %v", slotID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule slot not found"})
		return
	}

	c.JSON(http.StatusOK, ScheduleSlotResponse{Slot: slot})
}

// GetScheduleSlotsByBusiness retrieves all schedule slots for a specific business
func (sc *ScheduleSlotController) GetScheduleSlotsByBusiness(c *gin.Context) {
	businessIDStr := c.Param("business_id")
	businessID, err := uuid.Parse(businessIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
		return
	}

	// Parse query parameters
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if err != nil || limit < 1 || limit > 100 {
		limit = 10
	}
	
	// Optional availability filter
	var availableFilter *bool
	if availableStr := c.Query("available"); availableStr != "" {
		if available, parseErr := strconv.ParseBool(availableStr); parseErr == nil {
			availableFilter = &available
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	slots, totalCount, err := schedule_slot_models.GetScheduleSlotsByBusiness(ctx, db.DB, businessID, availableFilter, page, limit)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch schedule slots for business %s: %v", businessID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch schedule slots"})
		return
	}

	c.JSON(http.StatusOK, ScheduleSlotListResponse{
		Slots:      slots,
		TotalCount: totalCount,
		Page:       page,
		Limit:      limit,
		HasMore:    page*limit < totalCount,
	})
}

// UpdateScheduleSlot updates an existing schedule slot
func (sc *ScheduleSlotController) UpdateScheduleSlot(c *gin.Context) {
	slotIDStr := c.Param("slot_id")
	slotID, err := uuid.Parse(slotIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid slot ID format"})
		return
	}

	var req UpdateScheduleSlotRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.WarnLogger.Warnf("Invalid update schedule slot request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	// Validate times if both are provided
	if req.OpenTime != nil && req.CloseTime != nil {
		if req.OpenTime.After(*req.CloseTime) || req.OpenTime.Equal(*req.CloseTime) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Open time must be before close time"})
			return
		}
	}

	// Get authenticated user ID (for business owner validation if needed)
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// First, fetch the existing slot to validate ownership
	existingSlot, err := schedule_slot_models.GetScheduleSlotByID(ctx, db.DB, slotID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule slot not found"})
		return
	}

	// TODO: Add business owner validation - check if userID owns existingSlot.BusinessID
	logger.InfoLogger.Infof("User %s updating schedule slot %s for business %s", userID, slotID, existingSlot.BusinessID)

	updatedSlot, err := schedule_slot_models.UpdateScheduleSlot(ctx, db.DB, slotID, req.OpenTime, req.CloseTime, req.IsAvailable)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update schedule slot %s: %v", slotID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update schedule slot"})
		return
	}

	logger.InfoLogger.Infof("Schedule slot %s updated successfully", slotID)
	c.JSON(http.StatusOK, ScheduleSlotResponse{
		Slot:    updatedSlot,
		Message: "Schedule slot updated successfully",
	})
}

// DeleteScheduleSlot soft deletes a schedule slot
func (sc *ScheduleSlotController) DeleteScheduleSlot(c *gin.Context) {
	slotIDStr := c.Param("slot_id")
	slotID, err := uuid.Parse(slotIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid slot ID format"})
		return
	}

	// Get authenticated user ID (for business owner validation if needed)
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// First, fetch the existing slot to validate ownership
	existingSlot, err := schedule_slot_models.GetScheduleSlotByID(ctx, db.DB, slotID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule slot not found"})
		return
	}

	// TODO: Add business owner validation - check if userID owns existingSlot.BusinessID
	logger.InfoLogger.Infof("User %s deleting schedule slot %s for business %s", userID, slotID, existingSlot.BusinessID)

	err = schedule_slot_models.DeleteScheduleSlot(ctx, db.DB, slotID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete schedule slot %s: %v", slotID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete schedule slot"})
		return
	}

	logger.InfoLogger.Infof("Schedule slot %s deleted successfully", slotID)
	c.JSON(http.StatusOK, gin.H{"message": "Schedule slot deleted successfully"})
}

// ToggleSlotAvailability toggles the availability status of a schedule slot
func (sc *ScheduleSlotController) ToggleSlotAvailability(c *gin.Context) {
	slotIDStr := c.Param("slot_id")
	slotID, err := uuid.Parse(slotIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid slot ID format"})
		return
	}

	// Get authenticated user ID (for business owner validation if needed)
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// First, fetch the existing slot to validate ownership and get current status
	existingSlot, err := schedule_slot_models.GetScheduleSlotByID(ctx, db.DB, slotID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule slot not found"})
		return
	}

	// TODO: Add business owner validation - check if userID owns existingSlot.BusinessID
	logger.InfoLogger.Infof("User %s toggling availability for schedule slot %s", userID, slotID)

	// Toggle the availability
	newAvailability := !existingSlot.IsAvailable
	err = schedule_slot_models.UpdateScheduleSlotAvailability(ctx, db.DB, slotID, newAvailability)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to toggle availability for schedule slot %s: %v", slotID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to toggle slot availability"})
		return
	}

	logger.InfoLogger.Infof("Schedule slot %s availability toggled to %t", slotID, newAvailability)
	c.JSON(http.StatusOK, gin.H{
		"message":     "Slot availability toggled successfully",
		"slot_id":     slotID,
		"available":   newAvailability,
		"was_available": existingSlot.IsAvailable,
	})
}

// GetAvailableSlots retrieves all available schedule slots for a business
func (sc *ScheduleSlotController) GetAvailableSlots(c *gin.Context) {
	businessIDStr := c.Param("business_id")
	businessID, err := uuid.Parse(businessIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
		return
	}

	// Parse query parameters
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if err != nil || limit < 1 || limit > 100 {
		limit = 20
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Only get available slots
	availableFilter := true
	slots, totalCount, err := schedule_slot_models.GetScheduleSlotsByBusiness(ctx, db.DB, businessID, &availableFilter, page, limit)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch available schedule slots for business %s: %v", businessID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch available slots"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"available_slots": slots,
		"total_count":     totalCount,
		"page":           page,
		"limit":          limit,
		"has_more":       page*limit < totalCount,
	})
}

// BulkUpdateSlotAvailability updates availability for multiple slots
func (sc *ScheduleSlotController) BulkUpdateSlotAvailability(c *gin.Context) {
	var req struct {
		SlotIDs     []uuid.UUID `json:"slot_ids" binding:"required,min=1"`
		IsAvailable bool        `json:"is_available"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.WarnLogger.Warnf("Invalid bulk update request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	// Limit bulk operations to prevent abuse
	if len(req.SlotIDs) > 50 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot update more than 50 slots at once"})
		return
	}

	// Get authenticated user ID (for business owner validation if needed)
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var successCount, failureCount int
	var failedSlots []uuid.UUID

	for _, slotID := range req.SlotIDs {
		// Validate ownership for each slot (simplified - in production you might batch this)
		_, err := schedule_slot_models.GetScheduleSlotByID(ctx, db.DB, slotID)
		if err != nil {
			logger.WarnLogger.Warnf("Slot %s not found during bulk update by user %s", slotID, userID)
			failedSlots = append(failedSlots, slotID)
			failureCount++
			continue
		}

		// TODO: Add business owner validation - check if userID owns existingSlot.BusinessID

		err = schedule_slot_models.UpdateScheduleSlotAvailability(ctx, db.DB, slotID, req.IsAvailable)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to update slot %s availability during bulk update: %v", slotID, err)
			failedSlots = append(failedSlots, slotID)
			failureCount++
		} else {
			successCount++
		}
	}

	logger.InfoLogger.Infof("Bulk availability update completed by user %s: %d success, %d failures", userID, successCount, failureCount)

	response := gin.H{
		"message":       "Bulk update completed",
		"success_count": successCount,
		"failure_count": failureCount,
		"total_count":   len(req.SlotIDs),
		"is_available":  req.IsAvailable,
	}

	if len(failedSlots) > 0 {
		response["failed_slot_ids"] = failedSlots
	}

	c.JSON(http.StatusOK, response)
}

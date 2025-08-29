package schedule_slot_controller

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/schedule_slot_models"
)

// Status constants
const (
	StatusPending   = "pending"
	StatusConfirmed = "confirmed"
	StatusCancelled = "cancelled"
	StatusRefunded  = "refunded"
)

// ValidStatuses for validation
var ValidStatuses = map[string]bool{
	StatusPending:   true,
	StatusConfirmed: true,
	StatusCancelled: true,
	StatusRefunded:  true,
}

// ScheduleSlotController handles HTTP requests for schedule slots management
type ScheduleSlotController struct{}

// NewScheduleSlotController creates a new schedule slot controller
func NewScheduleSlotController() *ScheduleSlotController {
	return &ScheduleSlotController{}
}

type UnavailableTime struct {
	OpenTime  time.Time `json:"open_time"`
	CloseTime time.Time `json:"close_time"`
}

// CreateScheduleSlotRequest represents the request payload for creating a new schedule slot
type CreateScheduleSlotRequest struct {
	ServiceID uuid.UUID `json:"service_id" binding:"required"`
	OpenTime  time.Time `json:"open_time" binding:"required"`
	CloseTime time.Time `json:"close_time" binding:"required"`
	Status    string    `json:"status,omitempty"` // optional; defaults to "pending"
}

// UpdateScheduleSlotRequest represents the request payload for updating a schedule slot
type UpdateScheduleSlotRequest struct {
	OpenTime  *time.Time `json:"open_time,omitempty"`
	CloseTime *time.Time `json:"close_time,omitempty"`
	Status    *string    `json:"status,omitempty"`
}

// ScheduleSlotResponse represents the standardized schedule slot response
type ScheduleSlotResponse struct {
	Slot    *schedule_slot_models.ScheduleSlot `json:"slot"`
	Message string                             `json:"message,omitempty"`
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

	// Validate open time < close time
	if req.OpenTime.After(req.CloseTime) || req.OpenTime.Equal(req.CloseTime) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Open time must be before close time"})
		return
	}

	// Validate slot date/time is not in the past
	now := time.Now().UTC()
	if req.OpenTime.Before(now) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Slot date/time cannot be in the past"})
		return
	}

	// Default status to "pending" if not provided
	if req.Status == "" {
		req.Status = StatusPending
	}

	// Validate status
	if !ValidStatuses[req.Status] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid status",
			"allowed": []string{StatusPending, StatusConfirmed, StatusCancelled, StatusRefunded},
		})
		return
	}

	// Get authenticated user ID
	userIDFromToken, exists := c.Get("sub")
	if !exists {
		logger.ErrorLogger.Error("Unauthorized: User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userIDStr, ok := userIDFromToken.(string)
	if !ok {
		logger.ErrorLogger.Error("User ID from context is not a string")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid user ID from token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	logger.InfoLogger.Infof("User %s creating schedule slot for business %s with status: %s", userID, req.ServiceID, req.Status)

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Create new slot
	newSlot, err := schedule_slot_models.NewScheduleSlot(req.ServiceID, userID, req.OpenTime, req.CloseTime, req.Status)
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

	logger.InfoLogger.Infof("Schedule slot %s created successfully for business %s", createdSlot.ID, req.ServiceID)
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

	// Get authenticated user ID
	userIDFromToken, exists := c.Get("sub")
	if !exists {
		logger.ErrorLogger.Error("Unauthorized: User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userIDStr, ok := userIDFromToken.(string)
	if !ok {
		logger.ErrorLogger.Error("User ID from context is not a string")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	userID, err := uuid.Parse(userIDStr)

	if err != nil {
		logger.ErrorLogger.Errorf("Invalid user ID from token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	slot, err := schedule_slot_models.GetScheduleSlotByID(ctx, db.DB, slotID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch schedule slot %s: %v", slotID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule slot not found"})
		return
	}

	// Only send response if the authenticated user owns the slot
	if slot.UserID != userID {
		logger.WarnLogger.Warnf("User %s tried to access slot %s owned by %s", userID, slotID, slot.UserID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not allowed to access this schedule slot"})
		return
	}

	c.JSON(http.StatusOK, ScheduleSlotResponse{Slot: slot})
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

	// Validate time order if both are provided
	if req.OpenTime != nil && req.CloseTime != nil {
		if req.OpenTime.After(*req.CloseTime) || req.OpenTime.Equal(*req.CloseTime) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Open time must be before close time"})
			return
		}
	}

	// Validate status if provided
	if req.Status != nil && !ValidStatuses[*req.Status] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid status",
			"allowed": []string{StatusPending, StatusConfirmed, StatusCancelled, StatusRefunded},
		})
		return
	}

	userIDFromToken, exists := c.Get("sub")
	if !exists {
		logger.ErrorLogger.Error("Unauthorized: User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userIDStr, ok := userIDFromToken.(string)
	if !ok {
		logger.ErrorLogger.Error("User ID from context is not a string")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	userID, err := uuid.Parse(userIDStr)

	if err != nil {
		logger.ErrorLogger.Errorf("Invalid user ID from token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	existingSlot, err := schedule_slot_models.GetScheduleSlotByID(ctx, db.DB, slotID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule slot not found"})
		return
	}

	// Ownership check
	if existingSlot.UserID != userID {
		logger.WarnLogger.Warnf("User %s attempted to update slot %s owned by %s", userID, slotID, existingSlot.UserID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You do not have permission to modify this slot"})
		return
	}

	logger.InfoLogger.Infof("User %s updating schedule slot %s for business %s", userID, slotID, existingSlot.ServiceID)

	updatedSlot, err := schedule_slot_models.UpdateScheduleSlot(ctx, db.DB, slotID, req.OpenTime, req.CloseTime, req.Status)
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

	userIDFromToken, exists := c.Get("sub")
	if !exists {
		logger.ErrorLogger.Error("Unauthorized: User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userIDStr, ok := userIDFromToken.(string)
	if !ok {
		logger.ErrorLogger.Error("User ID from context is not a string")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid user ID from token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	existingSlot, err := schedule_slot_models.GetScheduleSlotByID(ctx, db.DB, slotID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule slot not found"})
		return
	}

	// Ownership check
	if existingSlot.UserID != userID {
		logger.WarnLogger.Warnf("User %s attempted to delete slot %s owned by %s", userID, slotID, existingSlot.UserID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You do not have permission to delete this slot"})
		return
	}

	logger.InfoLogger.Infof("User %s deleting schedule slot %s for business %s", userID, slotID, existingSlot.ServiceID)

	err = schedule_slot_models.DeleteScheduleSlot(ctx, db.DB, slotID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete schedule slot %s: %v", slotID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete schedule slot"})
		return
	}

	logger.InfoLogger.Infof("Schedule slot %s deleted successfully", slotID)
	c.JSON(http.StatusOK, gin.H{"message": "Schedule slot deleted successfully"})
}

// SetSlotStatus updates the status of a schedule slot
func (sc *ScheduleSlotController) SetSlotStatus(c *gin.Context) {
	slotIDStr := c.Param("slot_id")
	slotID, err := uuid.Parse(slotIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid slot ID format"})
		return
	}

	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	if !ValidStatuses[req.Status] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid status",
			"allowed": []string{StatusPending, StatusConfirmed, StatusCancelled, StatusRefunded},
		})
		return
	}

	userIDFromToken, exists := c.Get("sub")
	if !exists {
		logger.ErrorLogger.Error("Unauthorized: User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userIDStr, ok := userIDFromToken.(string)
	if !ok {
		logger.ErrorLogger.Error("User ID from context is not a string")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	userID, err := uuid.Parse(userIDStr)

	if err != nil {
		logger.ErrorLogger.Errorf("Invalid user ID from token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	existingSlot, err := schedule_slot_models.GetScheduleSlotByID(ctx, db.DB, slotID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule slot not found"})
		return
	}

	// Ownership check
	if existingSlot.UserID != userID {
		logger.WarnLogger.Warnf("User %s attempted to update status of slot %s owned by %s", userID, slotID, existingSlot.UserID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You do not have permission to modify this slot"})
		return
	}

	logger.InfoLogger.Infof("User %s setting status of slot %s to %s", userID, slotID, req.Status)

	err = schedule_slot_models.UpdateScheduleSlotStatus(ctx, db.DB, slotID, req.Status)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update status for schedule slot %s: %v", slotID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update slot status"})
		return
	}

	logger.InfoLogger.Infof("Schedule slot %s status updated to %s", slotID, req.Status)
	c.JSON(http.StatusOK, gin.H{
		"message":         "Slot status updated successfully",
		"slot_id":         slotID,
		"new_status":      req.Status,
		"previous_status": existingSlot.Status,
	})
}

// GetUnavailableTimes retrieves all confirmed (booked) schedule slots for a service on a specific date
func (sc *ScheduleSlotController) GetUnavailableTimes(c *gin.Context) {
	ServiceIDStr := c.Param("service_id")
	ServiceID, err := uuid.Parse(ServiceIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID format"})
		return
	}

	dateStr := c.Query("date")
	if dateStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Query parameter 'date' is required in YYYY-MM-DD format"})
		return
	}

	// Parse date in YYYY-MM-DD format (UTC)
	bookingDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format, use YYYY-MM-DD"})
		return
	}

	// Normalize current date (UTC) to YYYY-MM-DD
	today := time.Now().UTC().Truncate(24 * time.Hour)

	// Check if booking date is in the past or today
	if !bookingDate.After(today) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Booking date must be in the future"})
		return
	}

	// UTC day boundaries
	startOfDay := time.Date(bookingDate.Year(), bookingDate.Month(), bookingDate.Day(), 0, 0, 0, 0, time.UTC)
	endOfDay := startOfDay.Add(24 * time.Hour)

	logger.InfoLogger.Infof("Fetching unavailable times for business=%s, date=%s, UTC range=%s - %s",
		ServiceID, dateStr, startOfDay.Format(time.RFC3339), endOfDay.Format(time.RFC3339))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Overlap-safe query: returns slots that start or end within the day
	rows, err := db.DB.Query(ctx, `
        SELECT open_time, close_time, status, service_id
        FROM schedule_slots
        WHERE service_id = $1
          AND status = 'confirmed'
          AND (open_time < $3 AND close_time > $2)
        ORDER BY open_time ASC
    `, ServiceID, startOfDay, endOfDay)

	if err != nil {
		logger.ErrorLogger.Errorf("Query error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch unavailable times"})
		return
	}
	defer rows.Close()

	times := make([]UnavailableTime, 0)
	for rows.Next() {
		var t UnavailableTime
		var status string
		var dbServiceID uuid.UUID

		if err := rows.Scan(&t.OpenTime, &t.CloseTime, &status, &dbServiceID); err != nil {
			logger.ErrorLogger.Errorf("Scan error: %v", err)
			continue
		}

		logger.InfoLogger.Infof("Row found: service_id=%s, status=%s, open=%s, close=%s",
			dbServiceID, status, t.OpenTime.Format(time.RFC3339), t.CloseTime.Format(time.RFC3339))

		times = append(times, t)
	}

	if err = rows.Err(); err != nil {
		logger.ErrorLogger.Errorf("Row iteration error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading unavailable times"})
		return
	}

	if len(times) == 0 {
		logger.InfoLogger.Infof("No unavailable slots found for business=%s on date=%s", ServiceID, dateStr)
	}

	c.JSON(http.StatusOK, gin.H{"times": times})
}

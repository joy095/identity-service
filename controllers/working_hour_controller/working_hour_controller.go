// working_hour_controller/working_hour_controller.go

package working_hour_controller

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/business_models"
	"github.com/joy095/identity/models/working_hour_models"
	"github.com/joy095/identity/utils"
)

// WorkingHourController holds dependencies for working hour operations.
type WorkingHourController struct {
	DB *pgxpool.Pool
}

// NewWorkingHourController creates a new instance of WorkingHourController.
func NewWorkingHourController(db *pgxpool.Pool) *WorkingHourController {
	return &WorkingHourController{
		DB: db,
	}
}

const (
	DEFAULT_OPEN_TIME  = "09:00:00"
	DEFAULT_CLOSE_TIME = "17:00:00"
)

// CreateWorkingHourRequest represents the expected JSON payload for creating a working hour slot.
type CreateWorkingHourRequest struct {
	BusinessID uuid.UUID `json:"businessId" binding:"required"`
	DayOfWeek  string    `json:"dayOfWeek" binding:"required,oneof=Monday Tuesday Wednesday Thursday Friday Saturday Sunday"`
	OpenTime   string    `json:"openTime" binding:"required"`  // HH:MM:SS format
	CloseTime  string    `json:"closeTime" binding:"required"` // HH:MM:SS format
	IsClosed   bool      `json:"isClosed"`
}

// UpdateWorkingHourRequest represents the expected JSON payload for updating a working hour slot.
type UpdateWorkingHourRequest struct {
	DayOfWeek *string `json:"dayOfWeek,omitempty" binding:"omitempty,oneof=Monday Tuesday Wednesday Thursday Friday Saturday Sunday"`
	OpenTime  *string `json:"openTime,omitempty" binding:"omitempty"`
	CloseTime *string `json:"closeTime,omitempty" binding:"omitempty"`
	IsClosed  *bool   `json:"isClosed,omitempty"`
}

// DayWorkingHourRequest represents a working hour request for a specific day (without BusinessID)
type DayWorkingHourRequest struct {
	DayOfWeek string `json:"dayOfWeek" binding:"required,oneof=Monday Tuesday Wednesday Thursday Friday Saturday Sunday"`
	OpenTime  string `json:"openTime" binding:"required,datetime=15:04:05"`
	CloseTime string `json:"closeTime" binding:"required,datetime=15:04:05"`
	IsClosed  bool   `json:"isClosed"`
}

// BulkUpdateWorkingHoursRequest represents the expected JSON payload for bulk updating/upserting working hour slots.
// BusinessID is now taken from the path parameter.
type BulkUpdateWorkingHoursRequest struct {
	Days []DayWorkingHourRequest `json:"days" binding:"required,min=1"`
}

// InitializeWorkingHoursRequest represents the expected JSON payload for initializing working hours.
// BusinessID is now taken from the path parameter.
type InitializeWorkingHoursRequest struct {
	DefaultOpenTime    string                  `json:"defaultOpenTime" binding:"omitempty,datetime=15:04:05"`
	DefaultCloseTime   string                  `json:"defaultCloseTime" binding:"omitempty,datetime=15:04:05"`
	Overrides          []DayWorkingHourRequest `json:"overrides,omitempty"`
	InitializeWeekends bool                    `json:"initializeWeekends"`
}

// validateWorkingHoursTimes ensures open_time < close_time if not closed
func validateWorkingHoursTimes(openTimeStr, closeTimeStr string, isClosed bool) error {
	if isClosed {
		logger.InfoLogger.Debug("Working hour is closed, skipping time validation.")
		return nil // No time validation needed if the slot is closed
	}
	openTime, err := time.Parse("15:04:05", openTimeStr)
	if err != nil {
		logger.WarnLogger.Warnf("Invalid open time format '%s': %v", openTimeStr, err)
		return fmt.Errorf("invalid open time format: %w", err)
	}
	closeTime, err := time.Parse("15:04:05", closeTimeStr)
	if err != nil {
		logger.WarnLogger.Warnf("Invalid close time format '%s': %v", closeTimeStr, err)
		return fmt.Errorf("invalid close time format: %w", err)
	}
	if closeTime.Before(openTime) || closeTime.Equal(openTime) {
		logger.WarnLogger.Warnf("Close time '%s' is not after open time '%s'", closeTimeStr, openTimeStr)
		return fmt.Errorf("close time must be after open time")
	}
	logger.InfoLogger.Debugf("Working hours time validation passed for open: %s, close: %s", openTimeStr, closeTimeStr)
	return nil
}

// InitializeWorkingHours sets up default working hours.
// BusinessID is taken from the path parameter :businessId.
func (whc *WorkingHourController) InitializeWorkingHours(c *gin.Context) {
	logger.InfoLogger.Info("InitializeWorkingHours controller called")

	publicID := c.Param("businessPublicId") // Extract from path

	businessID, err := business_models.GetBusinessIdOnly(c.Request.Context(), whc.DB, publicID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get business by publicId: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	var req InitializeWorkingHoursRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Failed to bind JSON for InitializeWorkingHours: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request data: %s", err.Error())})
		return
	}
	// Note: req.BusinessID is no longer part of the struct, so we use businessID from path

	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Errorf("Authentication error in InitializeWorkingHours: %v", err)
		if strings.Contains(err.Error(), "authentication required: user ID not found") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}
	logger.InfoLogger.Debugf("Owner User ID '%s' extracted from context for business %s", ownerUserID, businessID)

	business, err := business_models.GetBusinessByID(c.Request.Context(), whc.DB, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for working hour initialization: %v", businessID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Associated business not found"})
		return
	}
	logger.InfoLogger.Debugf("Business '%s' found for initialization, owner is '%s'", business.ID, business.OwnerID)
	if business.OwnerID != ownerUserID {
		logger.WarnLogger.Warnf("User %s attempted to initialize working hour for unowned business %s (owner: %s)", ownerUserID, businessID, business.OwnerID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to set working hours for this business"})
		return
	}

	// Check if working hours already exist for this business
	existingHours, err := working_hour_models.GetWorkingHoursByBusinessID(c.Request.Context(), whc.DB, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to check existing working hours for business %s: %v", businessID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check existing working hours"})
		return
	}
	if len(existingHours) > 0 {
		logger.InfoLogger.Infof("Working hours already exist for business %s; initialization aborted.", businessID)
		c.JSON(http.StatusConflict, gin.H{"error": "Working hours already exist for this business. Use POST /working-hour/bulk/:businessId to update existing entries or add new ones."})
		return
	}

	// Set default open and close times
	defaultOpenTime := DEFAULT_OPEN_TIME
	defaultCloseTime := DEFAULT_CLOSE_TIME
	if req.DefaultOpenTime != "" {
		defaultOpenTime = req.DefaultOpenTime
	}
	if req.DefaultCloseTime != "" {
		defaultCloseTime = req.DefaultCloseTime
	}
	logger.InfoLogger.Debugf("Default working hours set to: Open=%s, Close=%s, InitializeWeekends=%t", defaultOpenTime, defaultCloseTime, req.InitializeWeekends)

	daysOfWeek := []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}
	if req.InitializeWeekends {
		daysOfWeek = append(daysOfWeek, "Saturday", "Sunday")
	}

	hoursToCreate := make(map[string]working_hour_models.WorkingHour)

	// Create default entries
	for _, day := range daysOfWeek {
		isClosedDefault := false
		if day == "Saturday" || day == "Sunday" {
			isClosedDefault = true // Weekends closed by default if initialized
		}
		// Use businessID from path parameter here
		openTime, err := time.Parse("15:04:05", defaultOpenTime)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to parse default open time for %s: %v", day, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse default open time"})
			return
		}
		closeTime, err := time.Parse("15:04:05", defaultCloseTime)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to parse default close time for %s: %v", day, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse default close time"})
			return
		}
		wh, err := working_hour_models.NewWorkingHour(businessID, day, openTime, closeTime, isClosedDefault)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to create working hour for %s: %v", day, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create working hour for %s", day)})
			return
		}
		hoursToCreate[day] = *wh
		logger.InfoLogger.Debugf("Prepared default entry for %s: Open=%s, Close=%s, IsClosed=%t", day, defaultOpenTime, defaultCloseTime, isClosedDefault)
	}

	// Apply overrides
	for _, override := range req.Overrides {
		if err := validateWorkingHoursTimes(override.OpenTime, override.CloseTime, override.IsClosed); err != nil {
			logger.ErrorLogger.Errorf("Validation failed for working hour override %s: %v", override.DayOfWeek, err)
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Validation failed for override %s: %s", override.DayOfWeek, err.Error())})
			return
		}
		// Use businessID from path parameter here
		openTime, err := time.Parse("15:04:05", override.OpenTime)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to parse open time for override %s: %v", override.DayOfWeek, err)
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid open time for override %s", override.DayOfWeek)})
			return
		}
		closeTime, err := time.Parse("15:04:05", override.CloseTime)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to parse close time for override %s: %v", override.DayOfWeek, err)
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid close time for override %s", override.DayOfWeek)})
			return
		}
		wh, err := working_hour_models.NewWorkingHour(businessID, override.DayOfWeek, openTime, closeTime, override.IsClosed)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to create working hour override for %s: %v", override.DayOfWeek, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create working hour override for %s", override.DayOfWeek)})
			return
		}
		hoursToCreate[override.DayOfWeek] = *wh
		logger.InfoLogger.Debugf("Applied override for %s: Open=%s, Close=%s, IsClosed=%t", override.DayOfWeek, override.OpenTime, override.CloseTime, override.IsClosed)
	}

	tx, err := whc.DB.Begin(c.Request.Context())
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to begin transaction for working hour initialization for business %s: %v", businessID, err) // Use businessID
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize working hours"})
		return
	}
	defer tx.Rollback(c.Request.Context()) // Rollback on error
	logger.InfoLogger.Debug("Database transaction started for working hour initialization.")

	var createdHours []working_hour_models.WorkingHour
	for _, wh := range hoursToCreate {
		createdWH, err := working_hour_models.CreateWorkingHourTx(c.Request.Context(), tx, &wh) // Use CreateWorkingHourTx
		if err != nil {
			tx.Rollback(c.Request.Context())
			logger.ErrorLogger.Errorf("Failed to create default working hour for %s (BusinessID: %s) in transaction: %v", wh.DayOfWeek, wh.BusinessID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to set working hours for %s", wh.DayOfWeek)})
			return
		}
		createdHours = append(createdHours, *createdWH)
		logger.InfoLogger.Debugf("Successfully created working hour for %s (ID: %s) in transaction.", wh.DayOfWeek, createdWH.ID)
	}

	if err := tx.Commit(c.Request.Context()); err != nil {
		logger.ErrorLogger.Errorf("Failed to commit transaction for working hour initialization for business %s: %v", businessID, err) // Use businessID
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize working hours"})
		return
	}

	logger.InfoLogger.Infof("Working hours initialized successfully for business %s with %d entries.", businessID, len(createdHours)) // Use businessID
	c.JSON(http.StatusCreated, gin.H{
		"message":      "Working hours initialized successfully!",
		"businessId":   businessID, // Include business ID in response
		"workingHours": createdHours,
	})
}

// BulkUpsertWorkingHours handles the bulk creation or update of working hours for a business.
// BusinessID is taken from the path parameter :businessId.
func (whc *WorkingHourController) BulkUpsertWorkingHours(c *gin.Context) {
	logger.InfoLogger.Info("BulkUpsertWorkingHours controller called")

	publicID := c.Param("businessPublicId") // Extract from path

	businessID, err := business_models.GetBusinessIdOnly(c.Request.Context(), whc.DB, publicID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get business by publicId: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	// Log message corrected to use businessID instead of req.BusinessID (which doesn't exist anymore)
	logger.InfoLogger.Debugf("BulkUpsertWorkingHours request received for BusinessID (from path): %s", businessID)

	var req BulkUpdateWorkingHoursRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Failed to bind JSON for BulkUpsertWorkingHours: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request data: %s", err.Error())})
		return
	}
	// Note: req.BusinessID is no longer part of the struct, so we use businessID from path

	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Errorf("Authentication error in BulkUpsertWorkingHours: %v", err)
		if strings.Contains(err.Error(), "authentication required: user ID not found") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}
	logger.InfoLogger.Debugf("Owner User ID '%s' extracted from context for business %s", ownerUserID, businessID)

	business, err := business_models.GetBusinessByID(c.Request.Context(), whc.DB, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for working hour bulk update: %v", businessID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Associated business not found"})
		return
	}
	logger.InfoLogger.Debugf("Business '%s' found for bulk update, owner is '%s'", business.ID, business.OwnerID)
	if business.OwnerID != ownerUserID {
		logger.WarnLogger.Warnf("User %s attempted to bulk update working hours for unowned business %s (owner: %s)", ownerUserID, businessID, business.OwnerID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to update working hours for this business"})
		return
	}

	tx, err := whc.DB.Begin(c.Request.Context())
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to begin transaction for bulk working hour update for business %s: %v", businessID, err) // Use businessID
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update working hours"})
		return
	}
	defer tx.Rollback(c.Request.Context())
	logger.InfoLogger.Debug("Database transaction started for bulk working hour update.")

	// Fetch existing hours inside the transaction to prevent race conditions
	// Use businessID from path parameter in the query
	query := `SELECT id, business_id, day_of_week, open_time, close_time, is_closed, created_at, updated_at
              FROM working_hours WHERE business_id = $1`
	rows, err := tx.Query(c.Request.Context(), query, businessID) // Use businessID
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch existing working hours in transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve existing working hours"})
		return
	}
	defer rows.Close()

	existingMap := make(map[string]working_hour_models.WorkingHour)
	for rows.Next() {
		var wh working_hour_models.WorkingHour
		if err := rows.Scan(
			&wh.ID,
			&wh.BusinessID,
			&wh.DayOfWeek,
			&wh.OpenTime,
			&wh.CloseTime,
			&wh.IsClosed,
			&wh.CreatedAt,
			&wh.UpdatedAt,
		); err != nil {
			tx.Rollback(c.Request.Context())
			logger.ErrorLogger.Errorf("Failed to scan working hour row: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read existing working hours"})
			return
		}
		existingMap[wh.DayOfWeek] = wh
	}
	// Use businessID in log message
	logger.InfoLogger.Debugf("Found %d existing working hour entries for business %s.", len(existingMap), businessID)

	var results []working_hour_models.WorkingHour
	for _, dayReq := range req.Days {
		// Validate the day request
		if err := validateWorkingHoursTimes(dayReq.OpenTime, dayReq.CloseTime, dayReq.IsClosed); err != nil {
			tx.Rollback(c.Request.Context())
			logger.ErrorLogger.Errorf("Validation failed for working hour %s during bulk update: %v", dayReq.DayOfWeek, err)
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Validation failed for %s: %s", dayReq.DayOfWeek, err.Error())})
			return
		}

		if existing, ok := existingMap[dayReq.DayOfWeek]; ok {
			// Day exists, perform UPDATE
			logger.InfoLogger.Debugf("Updating existing working hour for %s (ID: %s) for business %s.", dayReq.DayOfWeek, existing.ID, businessID)

			var openTime, closeTime time.Time
			if !dayReq.IsClosed {
				openTime, err = utils.ParseTimeToUTC(dayReq.OpenTime, dayReq.DayOfWeek)
				if err != nil {
					tx.Rollback(c.Request.Context())
					logger.ErrorLogger.Errorf("Failed to parse open time '%s' for %s using utils.ParseTimeToUTC: %v", dayReq.OpenTime, dayReq.DayOfWeek, err) // Add this log
					c.JSON(http.StatusBadRequest, gin.H{
						"error": fmt.Sprintf("Invalid openTime for %s: %v", dayReq.DayOfWeek, err), // Include %v to show the underlying error
					})
					return
				}

				closeTime, err = utils.ParseTimeToUTC(dayReq.CloseTime, dayReq.DayOfWeek)
				if err != nil {
					tx.Rollback(c.Request.Context())
					logger.ErrorLogger.Errorf("Failed to parse close time '%s' for %s using utils.ParseTimeToUTC: %v", dayReq.CloseTime, dayReq.DayOfWeek, err) // Add this log
					c.JSON(http.StatusBadRequest, gin.H{
						"error": fmt.Sprintf("Invalid closeTime for %s: %v", dayReq.DayOfWeek, err),
					})
					return
				}
			}

			// Update existing record directly
			existing.DayOfWeek = dayReq.DayOfWeek
			existing.OpenTime = openTime
			existing.CloseTime = closeTime
			existing.IsClosed = dayReq.IsClosed
			existing.UpdatedAt = time.Now()

			updatedHour, err := working_hour_models.UpdateWorkingHourTx(c.Request.Context(), tx, &existing)
			if err != nil {
				tx.Rollback(c.Request.Context())
				logger.ErrorLogger.Errorf("Failed to update working hour for %s (ID: %s) in bulk update transaction: %v", dayReq.DayOfWeek, existing.ID, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to update working hours for %s", dayReq.DayOfWeek)})
				return
			}

			results = append(results, *updatedHour)
			logger.InfoLogger.Debugf("Successfully updated working hour for %s (ID: %s) in transaction.", dayReq.DayOfWeek, updatedHour.ID)
		} else {
			// Day does not exist, perform INSERT
			// Use businessID in log message
			logger.InfoLogger.Debugf("Creating new working hour for %s for business %s.", dayReq.DayOfWeek, businessID)

			// Create new working hour instance, use businessID from path
			openTime, err := utils.ParseTimeToUTC(dayReq.OpenTime, dayReq.DayOfWeek)
			if err != nil {
				tx.Rollback(c.Request.Context())
				logger.ErrorLogger.Errorf("Failed to parse open time for %s: %v", dayReq.DayOfWeek, err)
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid open time for %s", dayReq.DayOfWeek)})
				return
			}

			closeTime, err := utils.ParseTimeToUTC(dayReq.CloseTime, dayReq.DayOfWeek)
			if err != nil {
				tx.Rollback(c.Request.Context())
				logger.ErrorLogger.Errorf("Failed to parse close time for %s: %v", dayReq.DayOfWeek, err)
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid close time for %s", dayReq.DayOfWeek)})
				return
			}
			newHour, err := working_hour_models.NewWorkingHour(businessID, dayReq.DayOfWeek, openTime, closeTime, dayReq.IsClosed)
			if err != nil {
				tx.Rollback(c.Request.Context())
				logger.ErrorLogger.Errorf("Failed to create new working hour instance for %s: %v", dayReq.DayOfWeek, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create working hours for %s", dayReq.DayOfWeek)})
				return
			}

			// Create in transaction context
			createdHour, err := working_hour_models.CreateWorkingHourTx(c.Request.Context(), tx, newHour) // Use CreateWorkingHourTx
			if err != nil {
				tx.Rollback(c.Request.Context())
				logger.ErrorLogger.Errorf("Failed to create working hour for %s in bulk update transaction: %v", dayReq.DayOfWeek, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create working hours for %s", dayReq.DayOfWeek)})
				return
			}
			results = append(results, *createdHour)
			logger.InfoLogger.Debugf("Successfully created new working hour for %s (ID: %s) in transaction.", dayReq.DayOfWeek, createdHour.ID)
		}
	}

	if err := tx.Commit(c.Request.Context()); err != nil {
		logger.ErrorLogger.Errorf("Failed to commit transaction for bulk working hour update for business %s: %v", businessID, err) // Use businessID
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update working hours"})
		return
	}

	// Use businessID in success log message
	logger.InfoLogger.Infof("Bulk working hours update/create completed successfully for business %s. %d entries processed.", businessID, len(results))
	c.JSON(http.StatusOK, gin.H{
		"message":      "Working hours updated successfully",
		"businessId":   businessID, // Include business ID in response
		"workingHours": results,
	})
}

// CreateWorkingHour handles the HTTP request to create a new working hour slot.
// This is for creating a single, specific working hour.
func (whc *WorkingHourController) CreateWorkingHour(c *gin.Context) {
	logger.InfoLogger.Info("CreateWorkingHour controller called")

	var req CreateWorkingHourRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid request payload for CreateWorkingHour: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request data: %s", err.Error())})
		return
	}
	logger.InfoLogger.Debugf("CreateWorkingHour request received for BusinessID: %s, Day: %s", req.BusinessID, req.DayOfWeek)

	// Custom validation for time logic
	if err := validateWorkingHoursTimes(req.OpenTime, req.CloseTime, req.IsClosed); err != nil {
		logger.ErrorLogger.Errorf("Working hour time validation failed for business %s, day %s: %v", req.BusinessID, req.DayOfWeek, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Extract user ID from authenticated context (to ensure business ownership)
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Errorf("Authentication error in CreateWorkingHour: %v", err)
		if strings.Contains(err.Error(), "authentication required: user ID not found") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}
	logger.InfoLogger.Debugf("Owner User ID '%s' extracted for creating working hour for business %s", ownerUserID, req.BusinessID)

	// Verify that the business exists and belongs to the authenticated user
	business, err := business_models.GetBusinessByID(c.Request.Context(), whc.DB, req.BusinessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for working hour creation: %v", req.BusinessID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Associated business not found"})
		return
	}

	// Check authorization
	if business.OwnerID != ownerUserID {
		logger.WarnLogger.Warnf("User %s attempted to create working hour for unowned business %s (owner: %s)", ownerUserID, req.BusinessID, business.OwnerID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to set working hours for this business"})
		return
	}

	openTime, err := time.Parse("15:04:05", req.OpenTime)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse open time: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid open time format"})
		return
	}
	closeTime, err := time.Parse("15:04:05", req.CloseTime)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse close time: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid close time format"})
		return
	}

	// Create a models.WorkingHour instance
	wh, err := working_hour_models.NewWorkingHour(
		req.BusinessID,
		req.DayOfWeek,
		openTime,
		closeTime,
		req.IsClosed,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create working hour model: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid working hour data"})
		return
	}
	logger.InfoLogger.Debugf("New WorkingHour model created for BusinessID: %s, Day: %s", wh.BusinessID, wh.DayOfWeek)

	// Use the non-transactional CreateWorkingHour
	createdWH, err := working_hour_models.CreateWorkingHour(c.Request.Context(), whc.DB, wh)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create working hour in database for business %s, day %s: %v", req.BusinessID, req.DayOfWeek, err)
		// Check for specific errors, e.g., unique constraint violation
		if strings.Contains(err.Error(), "duplicate key value") || strings.Contains(err.Error(), "unique constraint") {
			logger.InfoLogger.Infof("Attempted to create duplicate working hour for business %s, day %s.", req.BusinessID, req.DayOfWeek)
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Working hours for %s already exist for this business. Use PUT to update.", req.DayOfWeek)})
		} else if strings.Contains(err.Error(), "foreign key constraint") {
			logger.WarnLogger.Warnf("Foreign key constraint violation when creating working hour for business %s: %v", req.BusinessID, err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID provided"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create working hour"})
		}
		return
	}
	logger.InfoLogger.Infof("Working hour %s created successfully for business %s by user %s", createdWH.ID, req.BusinessID, ownerUserID)
	c.JSON(http.StatusCreated, gin.H{
		"message":     "Working hour created successfully!",
		"workingHour": createdWH,
	})
}

// GetWorkingHourByID handles fetching a single working hour.
func (whc *WorkingHourController) GetWorkingHourByID(c *gin.Context) {
	logger.InfoLogger.Info("GetWorkingHourByID controller called")

	whIDStr := c.Param("id")
	whID, err := uuid.Parse(whIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid working hour ID format '%s': %v", whIDStr, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid working hour ID format"})
		return
	}
	logger.InfoLogger.Debugf("Attempting to fetch working hour with ID: %s", whID)

	wh, err := working_hour_models.GetWorkingHourByID(c.Request.Context(), whc.DB, whID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch working hour %s: %v", whID, err)
		if strings.Contains(err.Error(), "working hour not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Working hour not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch working hour"})
		}
		return
	}
	logger.InfoLogger.Infof("Working hour %s fetched successfully.", whID)
	c.JSON(http.StatusOK, gin.H{"workingHour": wh})
}

// GetWorkingHoursByBusinessID handles fetching all working hours for a specific business using its public ID.
func (whc *WorkingHourController) GetWorkingHoursByBusinessID(c *gin.Context) {
	logger.InfoLogger.Info("GetWorkingHoursByBusinessID controller called")

	businessPublicID := c.Param("businessPublicId") // Business Public URL
	whs, err := working_hour_models.GetWorkingHoursByBusinessPublicID(c.Request.Context(), whc.DB, businessPublicID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch working hours for business public ID %s: %v", businessPublicID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch working hours"})
		return
	}
	logger.InfoLogger.Infof("Fetched %d working hours for business public ID %s.", len(whs), businessPublicID)
	c.JSON(http.StatusOK, gin.H{"workingHours": whs})
}

// UpdateWorkingHour handles the HTTP request to update an existing working hour.
func (whc *WorkingHourController) UpdateWorkingHour(c *gin.Context) {
	logger.InfoLogger.Info("UpdateWorkingHour controller called")

	whIDStr := c.Param("id")
	whID, err := uuid.Parse(whIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid working hour ID format '%s': %v", whIDStr, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid working hour ID format"})
		return
	}
	logger.InfoLogger.Debugf("UpdateWorkingHour request received for WorkingHour ID: %s", whID)

	var req UpdateWorkingHourRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid request payload for UpdateWorkingHour (ID: %s): %v", whID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request data: %s", err.Error())})
		return
	}

	// Extract user ID from authenticated context (to ensure business ownership)
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Errorf("Authentication error in UpdateWorkingHour (ID: %s): %v", whID, err)
		if strings.Contains(err.Error(), "authentication required: user ID not found") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}
	logger.InfoLogger.Debugf("Owner User ID '%s' extracted for updating working hour %s", ownerUserID, whID)

	// Fetch the existing working hour to get its business_id and check ownership
	existingWH, err := working_hour_models.GetWorkingHourByID(c.Request.Context(), whc.DB, whID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch working hour %s for update: %v", whID, err)
		if strings.Contains(err.Error(), "working hour not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Working hour not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch working hour"})
		}
		return
	}
	logger.InfoLogger.Debugf("Existing working hour %s found for business %s", whID, existingWH.BusinessID)

	// Verify that the business associated with this working hour belongs to the authenticated user
	business, err := business_models.GetBusinessByID(c.Request.Context(), whc.DB, existingWH.BusinessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for working hour %s ownership check: %v", existingWH.BusinessID, whID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: business lookup failed"})
		return
	}
	if business.OwnerID != ownerUserID {
		logger.WarnLogger.Warnf("User %s attempted to update working hour %s for unowned business %s (owner: %s)", ownerUserID, whID, existingWH.BusinessID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to update this working hour"})
		return
	}

	// Apply updates from the request to the existing working hour
	updatedDayOfWeek := existingWH.DayOfWeek
	updatedOpenTime := existingWH.OpenTime
	updatedCloseTime := existingWH.CloseTime
	updatedIsClosed := existingWH.IsClosed

	if req.DayOfWeek != nil {
		updatedDayOfWeek = *req.DayOfWeek
		logger.InfoLogger.Debugf("Updating DayOfWeek for %s from %s to %s", whID, existingWH.DayOfWeek, updatedDayOfWeek)
	}
	if req.OpenTime != nil {
		parsedTime, err := time.Parse("15:04:05", *req.OpenTime)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to parse open time: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid open time format"})
			return
		}
		updatedOpenTime = parsedTime
		logger.InfoLogger.Debugf("Updating OpenTime for %s from %s to %s", whID, existingWH.OpenTime, updatedOpenTime)
	}
	if req.CloseTime != nil {
		parsedTime, err := time.Parse("15:04:05", *req.CloseTime)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to parse close time: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid close time format"})
			return
		}
		updatedCloseTime = parsedTime
		logger.InfoLogger.Debugf("Updating CloseTime for %s from %s to %s", whID, existingWH.CloseTime, updatedCloseTime)
	}
	if req.IsClosed != nil {
		updatedIsClosed = *req.IsClosed
		logger.InfoLogger.Debugf("Updating IsClosed for %s from %t to %t", whID, existingWH.IsClosed, updatedIsClosed)
	}

	// Re-validate times with potentially updated values
	if err := validateWorkingHoursTimes(updatedOpenTime.Format("15:04:05"), updatedCloseTime.Format("15:04:05"), updatedIsClosed); err != nil {
		logger.ErrorLogger.Errorf("Working hour time validation failed during update for ID %s: %v", whID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	existingWH.DayOfWeek = updatedDayOfWeek
	existingWH.OpenTime = updatedOpenTime
	existingWH.CloseTime = updatedCloseTime
	existingWH.IsClosed = updatedIsClosed

	// Use the non-transactional UpdateWorkingHour
	updatedWH, err := working_hour_models.UpdateWorkingHour(c.Request.Context(), whc.DB, existingWH)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update working hour %s in database: %v", whID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update working hour"})
		return
	}
	logger.InfoLogger.Infof("Working hour %s updated successfully by user %s", whID, ownerUserID)
	c.JSON(http.StatusOK, gin.H{
		"message":     "Working hour updated successfully!",
		"workingHour": updatedWH,
	})
}

// DeleteWorkingHour handles the HTTP request to delete a working hour.
func (whc *WorkingHourController) DeleteWorkingHour(c *gin.Context) {
	logger.InfoLogger.Info("DeleteWorkingHour controller called")

	whIDStr := c.Param("id")
	whID, err := uuid.Parse(whIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid working hour ID format '%s': %v", whIDStr, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid working hour ID format"})
		return
	}
	logger.InfoLogger.Debugf("DeleteWorkingHour request received for WorkingHour ID: %s", whID)

	// Extract user ID from authenticated context (to ensure business ownership)
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Errorf("Authentication error in DeleteWorkingHour (ID: %s): %v", whID, err)
		if strings.Contains(err.Error(), "authentication required: user ID not found") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}
	logger.InfoLogger.Debugf("Owner User ID '%s' extracted for deleting working hour %s", ownerUserID, whID)

	// Fetch the existing working hour to get its business_id and check ownership
	existingWH, err := working_hour_models.GetWorkingHourByID(c.Request.Context(), whc.DB, whID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch working hour %s for deletion: %v", whID, err)
		if strings.Contains(err.Error(), "working hour not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Working hour not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch working hour"})
		}
		return
	}
	logger.InfoLogger.Debugf("Existing working hour %s found for business %s", whID, existingWH.BusinessID)

	// Verify that the business associated with this working hour belongs to the authenticated user
	business, err := business_models.GetBusinessByID(c.Request.Context(), whc.DB, existingWH.BusinessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for working hour %s ownership check: %v", existingWH.BusinessID, whID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: business lookup failed"})
		return
	}
	if business.OwnerID != ownerUserID {
		logger.WarnLogger.Warnf("User %s attempted to delete working hour %s for unowned business %s (owner: %s)", ownerUserID, whID, existingWH.BusinessID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to delete this working hour"})
		return
	}

	if err := working_hour_models.DeleteWorkingHour(c.Request.Context(), whc.DB, whID, existingWH.BusinessID); err != nil {
		logger.ErrorLogger.Errorf("Failed to delete working hour %s for business %s from database: %v", whID, existingWH.BusinessID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete working hour"})
		return
	}
	logger.InfoLogger.Infof("Working hour %s deleted successfully by user %s", whID, ownerUserID)
	c.JSON(http.StatusOK, gin.H{"message": "Working hour deleted successfully"})
}

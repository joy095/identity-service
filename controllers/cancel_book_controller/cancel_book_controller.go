package cancel_book_controller

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/cancel_booking_models"
)

var (
	ErrBookingNotFound         = errors.New("booking not found")
	ErrBookingAlreadyCancelled = errors.New("booking already cancelled")
	ErrBookingNotOwnedByUser   = errors.New("booking does not belong to this user")
	ErrInvalidOrderID          = errors.New("invalid order ID")
	ErrInvalidUserID           = errors.New("invalid user ID")
)

type CancelBookController struct {
	db *pgxpool.Pool
}

// NewCancelBookController creates and returns a new instance of CancelBookController
func NewCancelBookController(db *pgxpool.Pool) (*CancelBookController, error) {
	if db == nil {
		return nil, errors.New("database pool cannot be nil")
	}

	return &CancelBookController{
		db: db,
	}, nil
}

// CancelBook handles the booking cancellation request
func (cb *CancelBookController) CancelBook(c *gin.Context) {
	fmt.Printf("DEBUG: CancelBook controller hit...\n")
	logger.InfoLogger.Info("CancelBook controller hit...")

	var req cancel_booking_models.CancelBookingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Printf("DEBUG: Invalid request body: %v\n", err)
		logger.InfoLogger.Errorf("Invalid request body: %v", err)
		c.JSON(http.StatusBadRequest, cancel_booking_models.CancelBookingResponse{
			Success: false,
			Message: "Invalid request body: " + err.Error(),
		})
		return
	}

	fmt.Printf("DEBUG: Received order_id: %s, reason: %s\n", req.OrderId.String(), req.Reason)
	logger.InfoLogger.Infof("Received request to cancel booking with order_id: %s", req.OrderId.String())

	// Get user ID from context (assuming you have authentication middleware)
	userIdContext, exists := c.Get("sub")
	if !exists {
		fmt.Printf("DEBUG: User not authenticated - no 'sub' in context\n")
		logger.InfoLogger.Error("User not authenticated - no 'sub' in context")
		c.JSON(http.StatusUnauthorized, cancel_booking_models.CancelBookingResponse{
			Success: false,
			Message: "User not authenticated",
		})
		return
	}

	fmt.Printf("DEBUG: Raw user ID from context: %v\n", userIdContext)
	logger.InfoLogger.Infof("Raw user ID from context: %v", userIdContext)

	// The JWT "sub" claim is typically stored as a string
	userIDStr, ok := userIdContext.(string)
	if !ok {
		fmt.Printf("DEBUG: Invalid user ID format - expected string, got %T\n", userIdContext)
		logger.InfoLogger.Errorf("Invalid user ID format - expected string, got %T", userIdContext)
		c.JSON(http.StatusInternalServerError, cancel_booking_models.CancelBookingResponse{
			Success: false,
			Message: "Invalid user ID format",
		})
		return
	}

	fmt.Printf("DEBUG: User ID string: %s\n", userIDStr)
	// Parse the string to UUID
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		fmt.Printf("DEBUG: Failed to parse user ID %s: %v\n", userIDStr, err)
		logger.InfoLogger.Errorf("Failed to parse user ID %s: %v", userIDStr, err)
		c.JSON(http.StatusInternalServerError, cancel_booking_models.CancelBookingResponse{
			Success: false,
			Message: "Invalid user ID format",
		})
		return
	}

	fmt.Printf("DEBUG: Parsed user ID: %s\n", userID.String())
	logger.InfoLogger.Infof("Parsed user ID: %s", userID.String())

	// Perform the cancellation
	fmt.Printf("DEBUG: Calling cancelBookingInDB with order_id: %s, user_id: %s, reason: %s\n", req.OrderId.String(), userID.String(), req.Reason)
	booking, err := cb.cancelBookingInDB(c, req.OrderId, userID, req.Reason)
	if err != nil {
		fmt.Printf("DEBUG: Failed to cancel booking: %v\n", err)
		logger.InfoLogger.Errorf("Failed to cancel booking: %v", err)

		// Handle different error types
		if errors.Is(err, ErrBookingNotFound) {
			fmt.Printf("DEBUG: Booking not found for order_id: %s\n", req.OrderId.String())
			logger.InfoLogger.Errorf("Booking not found for order_id: %s", req.OrderId.String())
			c.JSON(http.StatusNotFound, cancel_booking_models.CancelBookingResponse{
				Success: false,
				Message: "Booking not found",
			})
			return
		}

		if errors.Is(err, ErrBookingAlreadyCancelled) {
			fmt.Printf("DEBUG: Booking %s is already cancelled\n", req.OrderId.String())
			logger.InfoLogger.Infof("Booking %s is already cancelled", req.OrderId.String())
			c.JSON(http.StatusBadRequest, cancel_booking_models.CancelBookingResponse{
				Success: false,
				Message: "Booking is already cancelled",
			})
			return
		}

		if errors.Is(err, ErrBookingNotOwnedByUser) {
			fmt.Printf("DEBUG: User %s does not own booking %s\n", userID.String(), req.OrderId.String())
			logger.InfoLogger.Errorf("User %s does not own booking %s", userID.String(), req.OrderId.String())
			c.JSON(http.StatusForbidden, cancel_booking_models.CancelBookingResponse{
				Success: false,
				Message: "Booking does not belong to this user",
			})
			return
		}

		fmt.Printf("DEBUG: Internal error cancelling booking: %v\n", err)
		logger.InfoLogger.Errorf("Internal error cancelling booking: %v", err)
		c.JSON(http.StatusInternalServerError, cancel_booking_models.CancelBookingResponse{
			Success: false,
			Message: "Failed to cancel booking: " + err.Error(),
		})
		return
	}

	fmt.Printf("DEBUG: Booking %s cancelled successfully by user %s\n", req.OrderId.String(), userID.String())
	logger.InfoLogger.Infof("Booking %s cancelled successfully by user %s", req.OrderId.String(), userID.String())
	c.JSON(http.StatusOK, cancel_booking_models.CancelBookingResponse{
		Success: true,
		Message: "Booking cancelled successfully",
		Data:    booking,
	})
}

// cancelBookingInDB performs the actual database operations for booking cancellation
func (cb *CancelBookController) cancelBookingInDB(c *gin.Context, orderID uuid.UUID, userID uuid.UUID, reason string) (*cancel_booking_models.Booking, error) {
	ctx := c.Request.Context()

	fmt.Printf("DEBUG: Looking for order to cancel with order_id: %s\n", orderID.String())
	logger.InfoLogger.Infof("Looking for order to cancel with order_id: %s", orderID.String())

	// First, let's verify the order exists, belongs to the user, and cancellation is within valid time window
	var orderCustomerID uuid.UUID
	var orderStatus string
	var orderStartTime time.Time

	// Check if order exists and get its details
	orderCheckQuery := `
	SELECT customer_id, status, start_time
	FROM orders 
	WHERE id = $1
`
	err := cb.db.QueryRow(ctx, orderCheckQuery, orderID).Scan(&orderCustomerID, &orderStatus, &orderStartTime)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			fmt.Printf("DEBUG: Order not found: %s\n", orderID.String())
			return nil, ErrBookingNotFound
		}
		fmt.Printf("DEBUG: Error checking order: %v\n", err)
		return nil, fmt.Errorf("failed to check order: %w", err)
	}

	// Check if the order belongs to the user
	if orderCustomerID != userID {
		fmt.Printf("DEBUG: Order owner mismatch: expected %s, got %s\n", userID.String(), orderCustomerID.String())
		return nil, ErrBookingNotOwnedByUser
	}

	// Calculate the cancellation deadline (24 hours before start time)
	cancellationDeadline := orderStartTime.Add(-time.Hour * 24) // 24 hours before start time
	currentTime := time.Now()

	// Check if cancellation is still allowed (current time should be before the deadline)
	if currentTime.After(cancellationDeadline) {
		fmt.Printf("DEBUG: Cancellation deadline passed. Order start time: %v, Deadline: %v, Current time: %v\n",
			orderStartTime, cancellationDeadline, currentTime)
		return nil, errors.New("cancellation deadline has passed - too close to start time")
	}

	fmt.Printf("DEBUG: Order %s exists, belongs to user %s, current status: %s, start time: %v\n",
		orderID.String(), userID.String(), orderStatus, orderStartTime)

	// Check if the order is already cancelled by checking the cancel_booking table
	var existingCancellationID uuid.UUID
	cancellationCheckQuery := `
		SELECT id 
		FROM cancel_booking 
		WHERE order_id = $1
	`
	err = cb.db.QueryRow(ctx, cancellationCheckQuery, orderID).Scan(&existingCancellationID)
	if err == nil {
		// A cancellation record already exists
		fmt.Printf("DEBUG: Order %s is already cancelled with cancellation ID: %s\n",
			orderID.String(), existingCancellationID.String())
		return nil, ErrBookingAlreadyCancelled
	} else if !errors.Is(err, pgx.ErrNoRows) {
		// There was an actual database error
		fmt.Printf("DEBUG: Error checking for existing cancellation: %v\n", err)
		return nil, fmt.Errorf("failed to check for existing cancellation: %w", err)
	}

	// If we get here, the order exists, belongs to the user, and hasn't been cancelled yet
	// Now insert a cancellation record into the cancel_booking table
	now := time.Now()
	var cancellationRecord cancel_booking_models.Booking

	insertQuery := `
		INSERT INTO cancel_booking (id, order_id, cancellation_reason, cancelled_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, order_id, cancellation_reason, cancelled_at, created_at, updated_at
	`

	cancellationID := uuid.New()
	err = cb.db.QueryRow(ctx, insertQuery,
		cancellationID,
		orderID,
		reason,
		now,
		now,
		now,
	).Scan(
		&cancellationRecord.ID,
		&cancellationRecord.OrderId,
		&cancellationRecord.CancellationReason,
		&cancellationRecord.CancelledAt,
		&cancellationRecord.CreatedAt,
		&cancellationRecord.UpdatedAt,
	)

	if err != nil {
		fmt.Printf("DEBUG: Error inserting cancellation record: %v\n", err)
		logger.InfoLogger.Errorf("Error inserting cancellation record: %v", err)
		return nil, fmt.Errorf("failed to record cancellation: %w", err)
	}

	// Update the order status to cancelled
	updateOrderStatusQuery := `
		UPDATE orders 
		SET status = 'cancelled', updated_at = $1 
		WHERE id = $2
	`
	_, err = cb.db.Exec(ctx, updateOrderStatusQuery, now, orderID)
	if err != nil {
		fmt.Printf("DEBUG: Warning - failed to update order status: %v\n", err)
		// Don't return error here as the cancellation was recorded
	}

	fmt.Printf("DEBUG: Order %s cancelled successfully, cancellation ID: %s\n",
		orderID.String(), cancellationRecord.ID.String())
	logger.InfoLogger.Infof("Order %s cancelled successfully", orderID.String())

	// Create response with the cancellation record
	responseBooking := &cancel_booking_models.Booking{
		ID:                 cancellationRecord.ID,
		OrderId:            orderID,
		CancellationReason: &reason,
		CancelledAt:        &now,
		CreatedAt:          now,
		UpdatedAt:          now,
		Status:             orderStatus,
	}

	return responseBooking, nil
}

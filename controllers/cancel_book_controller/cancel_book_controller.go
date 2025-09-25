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
	logger.InfoLogger.Info("CancelBook controller hit...")

	var req cancel_booking_models.CancelBookingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.InfoLogger.Errorf("Invalid request body: %v", err)
		c.JSON(http.StatusBadRequest, cancel_booking_models.CancelBookingResponse{
			Success: false,
			Message: "Invalid request body: " + err.Error(),
		})
		return
	}

	// Get user ID from context (assuming you have authentication middleware)
	userIdParam, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, cancel_booking_models.CancelBookingResponse{
			Success: false,
			Message: "User not authenticated",
		})
		return
	}

	// Validate user ID type
	userID, ok := userIdParam.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusInternalServerError, cancel_booking_models.CancelBookingResponse{
			Success: false,
			Message: "Invalid user ID format",
		})
		return
	}

	// Perform the cancellation
	booking, err := cb.cancelBookingInDB(c, req.OrderId, userID, req.Reason)
	if err != nil {
		logger.InfoLogger.Errorf("Failed to cancel booking: %v", err)

		// Handle different error types
		if errors.Is(err, ErrBookingNotFound) {
			c.JSON(http.StatusNotFound, cancel_booking_models.CancelBookingResponse{
				Success: false,
				Message: "Booking not found",
			})
			return
		}

		if errors.Is(err, ErrBookingAlreadyCancelled) {
			c.JSON(http.StatusBadRequest, cancel_booking_models.CancelBookingResponse{
				Success: false,
				Message: "Booking is already cancelled",
			})
			return
		}

		if errors.Is(err, ErrBookingNotOwnedByUser) {
			c.JSON(http.StatusForbidden, cancel_booking_models.CancelBookingResponse{
				Success: false,
				Message: "Booking does not belong to this user",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, cancel_booking_models.CancelBookingResponse{
			Success: false,
			Message: "Failed to cancel booking: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, cancel_booking_models.CancelBookingResponse{
		Success: true,
		Message: "Booking cancelled successfully",
		Data:    booking,
	})
}

// cancelBookingInDB performs the actual database operations for booking cancellation
func (cb *CancelBookController) cancelBookingInDB(c *gin.Context, orderID uuid.UUID, userID uuid.UUID, reason string) (*cancel_booking_models.Booking, error) {
	ctx := c.Request.Context()

	// Check if booking exists and belongs to user using LEFT JOIN with orders table
	var booking cancel_booking_models.Booking
	var customerID uuid.UUID

	query := `
		SELECT b.id, b.order_id, b.status, b.cancelled_at, b.cancellation_reason, b.created_at, b.updated_at, o.customer_id
		FROM bookings b
		LEFT JOIN orders o ON b.order_id = o.id
		WHERE b.order_id = $1
	`

	err := cb.db.QueryRow(ctx, query, orderID).Scan(
		&booking.ID,
		&booking.OrderId,
		&booking.Status,
		&booking.CancelledAt,
		&booking.CancellationReason,
		&booking.CreatedAt,
		&booking.UpdatedAt,
		&customerID,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrBookingNotFound
		}
		return nil, fmt.Errorf("failed to fetch booking: %w", err)
	}

	// Check if booking belongs to user (compare with customer_id from orders table)
	if customerID != userID {
		return nil, ErrBookingNotOwnedByUser
	}

	// Check if booking is already cancelled
	if booking.Status == "cancelled" {
		return nil, ErrBookingAlreadyCancelled
	}

	// Update booking status to cancelled
	updateQuery := `
		UPDATE bookings 
		SET 
			status = 'cancelled',
			cancelled_at = $1,
			cancellation_reason = $2,
			updated_at = $3
		WHERE order_id = $4
		RETURNING id, order_id, status, cancelled_at, cancellation_reason, created_at, updated_at
	`

	now := time.Now()
	var updatedBooking cancel_booking_models.Booking
	err = cb.db.QueryRow(ctx, updateQuery,
		now,
		&reason, // Use &reason to handle NULL for empty string
		now,
		orderID,
	).Scan(
		&updatedBooking.ID,
		&updatedBooking.OrderId,
		&updatedBooking.Status,
		&updatedBooking.CancelledAt,
		&updatedBooking.CancellationReason,
		&updatedBooking.CreatedAt,
		&updatedBooking.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to update booking: %w", err)
	}

	return &updatedBooking, nil
}

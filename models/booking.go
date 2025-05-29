package models

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
)

// Booking represents a customer's reservation for a service at a specific slot.
type Booking struct {
	ID         uuid.UUID `json:"id"`
	BusinessID uuid.UUID `json:"business_id"`
	ServiceID  uuid.UUID `json:"service_id"`
	SlotID     uuid.UUID `json:"slot_id"`
	Status     string    `json:"status"` // e.g., "pending", "confirmed", "cancelled"
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	CustomerID uuid.UUID `json:"customer_id"`
}

// NewBooking creates a new Booking struct.
func NewBooking(businessID, serviceID, slotID, customerID uuid.UUID, status string) (*Booking, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID for booking: %w", err)
	}
	now := time.Now()
	return &Booking{
		ID:         id,
		BusinessID: businessID,
		ServiceID:  serviceID,
		SlotID:     slotID,
		CustomerID: customerID,
		Status:     status,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

// CreateBooking inserts a new booking record into the database.
func CreateBooking(ctx context.Context, db *pgxpool.Pool, booking *Booking) (*Booking, error) {
	logger.InfoLogger.Infof("Attempting to create booking record for slot ID: %s", booking.SlotID)

	if booking.ID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("failed to generate UUID: %w", err)
		}
		booking.ID = id
	}
	now := time.Now()
	booking.CreatedAt = now
	booking.UpdatedAt = now

	query := `
		INSERT INTO bookings (
			id, business_id, service_id, slot_id, status, created_at, updated_at, customer_id
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		) RETURNING id`

	var insertedID uuid.UUID
	err := db.QueryRow(ctx, query,
		booking.ID, booking.BusinessID, booking.ServiceID, booking.SlotID,
		booking.Status, booking.CreatedAt, booking.UpdatedAt, booking.CustomerID,
	).Scan(&insertedID)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to insert booking into database for slot %s: %v", booking.SlotID, err)
		return nil, fmt.Errorf("failed to create booking: %w", err)
	}

	booking.ID = insertedID
	logger.InfoLogger.Infof("Booking with ID %s created successfully for slot %s", booking.ID, booking.SlotID)
	return booking, nil
}

// UpdateBookingStatus updates the status of a booking.
func UpdateBookingStatus(ctx context.Context, db *pgxpool.Pool, bookingID uuid.UUID, status string) error {
	logger.InfoLogger.Infof("Updating status for booking %s to %s", bookingID, status)

	query := `
		UPDATE bookings
		SET status = $2, updated_at = NOW()
		WHERE id = $1`

	cmdTag, err := db.Exec(ctx, query, bookingID, status)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update booking %s status: %v", bookingID, err)
		return fmt.Errorf("failed to update booking status: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("booking with ID %s not found for update", bookingID)
	}

	logger.InfoLogger.Infof("Booking %s status updated to %s", bookingID, status)
	return nil
}

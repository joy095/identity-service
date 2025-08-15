package booking_models

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

// GetBookingByID fetches a booking record by its ID.
func GetBookingByID(ctx context.Context, db *pgxpool.Pool, bookingID uuid.UUID) (*Booking, error) {
	logger.InfoLogger.Infof("Attempting to fetch booking with ID: %s", bookingID)

	booking := &Booking{}
	query := `
		SELECT id, business_id, service_id, slot_id, status, created_at, updated_at, customer_id
		FROM bookings
		WHERE id = $1
	`

	err := db.QueryRow(ctx, query, bookingID).Scan(
		&booking.ID,
		&booking.BusinessID,
		&booking.ServiceID,
		&booking.SlotID,
		&booking.Status,
		&booking.CreatedAt,
		&booking.UpdatedAt,
		&booking.CustomerID,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			logger.WarnLogger.Warnf("Booking with ID %s not found", bookingID)
			return nil, fmt.Errorf("booking not found")
		}
		logger.ErrorLogger.Errorf("Failed to fetch booking %s: %v", bookingID, err)
		return nil, fmt.Errorf("database error fetching booking: %w", err)
	}
	
	// Validate booking data
	if booking.ID == uuid.Nil {
		return nil, fmt.Errorf("invalid booking data: missing ID")
	}

	logger.InfoLogger.Infof("Booking with ID %s fetched successfully", bookingID)
	return booking, nil
}

// CreateBooking inserts a new booking record into the database.
func CreateBooking(ctx context.Context, db *pgxpool.Pool, booking *Booking) (*Booking, error) {
	logger.InfoLogger.Infof("Attempting to create booking record for slot ID: %s", booking.SlotID)

	// Ensure booking has an ID and timestamps
	if booking.ID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("failed to generate UUID: %w", err)
		}
		booking.ID = id
	}
	if booking.CreatedAt.IsZero() {
		now := time.Now()
		booking.CreatedAt = now
		booking.UpdatedAt = now
	}

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
		SET status = $2, updated_at = $3
		WHERE id = $1`

	updatedAt := time.Now()
	cmdTag, err := db.Exec(ctx, query, bookingID, status, updatedAt)
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

// GetBookingsByCustomer retrieves bookings for a specific customer with pagination and optional status filter
func GetBookingsByCustomer(ctx context.Context, db *pgxpool.Pool, customerID uuid.UUID, status string, page, limit int) ([]Booking, int, error) {
	logger.InfoLogger.Infof("Fetching bookings for customer %s with status filter: %s", customerID, status)
	
	offset := (page - 1) * limit
	var bookings []Booking
	var totalCount int
	
	// Build dynamic query based on status filter
	baseQuery := `
		SELECT id, business_id, service_id, slot_id, status, created_at, updated_at, customer_id
		FROM bookings
		WHERE customer_id = $1
	`
	countQuery := `SELECT COUNT(*) FROM bookings WHERE customer_id = $1`
	
	var query, finalCountQuery string
	var args []interface{}
	args = append(args, customerID)
	
	if status != "" {
		baseQuery += " AND status = $2"
		countQuery += " AND status = $2"
		args = append(args, status)
		finalCountQuery = countQuery
		query = baseQuery + " ORDER BY created_at DESC LIMIT $3 OFFSET $4"
		args = append(args, limit, offset)
	} else {
		finalCountQuery = countQuery
		query = baseQuery + " ORDER BY created_at DESC LIMIT $2 OFFSET $3"
		args = append(args, limit, offset)
	}
	
	// Get total count
	err := db.QueryRow(ctx, finalCountQuery, args[:len(args)-2]...).Scan(&totalCount)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get booking count for customer %s: %v", customerID, err)
		return nil, 0, fmt.Errorf("failed to get booking count: %w", err)
	}
	
	// Get bookings
	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch bookings for customer %s: %v", customerID, err)
		return nil, 0, fmt.Errorf("failed to fetch bookings: %w", err)
	}
	defer rows.Close()
	
	for rows.Next() {
		var booking Booking
		err := rows.Scan(
			&booking.ID,
			&booking.BusinessID,
			&booking.ServiceID,
			&booking.SlotID,
			&booking.Status,
			&booking.CreatedAt,
			&booking.UpdatedAt,
			&booking.CustomerID,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan booking row: %v", err)
			return nil, 0, fmt.Errorf("failed to scan booking: %w", err)
		}
		bookings = append(bookings, booking)
	}
	
	logger.InfoLogger.Infof("Fetched %d bookings for customer %s (total: %d)", len(bookings), customerID, totalCount)
	return bookings, totalCount, nil
}

// GetBookingsByBusiness retrieves bookings for a specific business with pagination and optional status filter
func GetBookingsByBusiness(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID, status string, page, limit int) ([]Booking, int, error) {
	logger.InfoLogger.Infof("Fetching bookings for business %s with status filter: %s", businessID, status)
	
	offset := (page - 1) * limit
	var bookings []Booking
	var totalCount int
	
	// Build dynamic query based on status filter
	baseQuery := `
		SELECT id, business_id, service_id, slot_id, status, created_at, updated_at, customer_id
		FROM bookings
		WHERE business_id = $1
	`
	countQuery := `SELECT COUNT(*) FROM bookings WHERE business_id = $1`
	
	var query, finalCountQuery string
	var args []interface{}
	args = append(args, businessID)
	
	if status != "" {
		baseQuery += " AND status = $2"
		countQuery += " AND status = $2"
		args = append(args, status)
		finalCountQuery = countQuery
		query = baseQuery + " ORDER BY created_at DESC LIMIT $3 OFFSET $4"
		args = append(args, limit, offset)
	} else {
		finalCountQuery = countQuery
		query = baseQuery + " ORDER BY created_at DESC LIMIT $2 OFFSET $3"
		args = append(args, limit, offset)
	}
	
	// Get total count
	err := db.QueryRow(ctx, finalCountQuery, args[:len(args)-2]...).Scan(&totalCount)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get booking count for business %s: %v", businessID, err)
		return nil, 0, fmt.Errorf("failed to get booking count: %w", err)
	}
	
	// Get bookings
	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch bookings for business %s: %v", businessID, err)
		return nil, 0, fmt.Errorf("failed to fetch bookings: %w", err)
	}
	defer rows.Close()
	
	for rows.Next() {
		var booking Booking
		err := rows.Scan(
			&booking.ID,
			&booking.BusinessID,
			&booking.ServiceID,
			&booking.SlotID,
			&booking.Status,
			&booking.CreatedAt,
			&booking.UpdatedAt,
			&booking.CustomerID,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan booking row: %v", err)
			return nil, 0, fmt.Errorf("failed to scan booking: %w", err)
		}
		bookings = append(bookings, booking)
	}
	
	logger.InfoLogger.Infof("Fetched %d bookings for business %s (total: %d)", len(bookings), businessID, totalCount)
	return bookings, totalCount, nil
}

// GetAllBookings retrieves all bookings in the system with pagination and optional status filter (admin function)
func GetAllBookings(ctx context.Context, db *pgxpool.Pool, status string, page, limit int) ([]Booking, int, error) {
	logger.InfoLogger.Info("Fetching all bookings in the system")
	
	offset := (page - 1) * limit
	var bookings []Booking
	var totalCount int
	
	// Build dynamic query based on status filter
	baseQuery := `
		SELECT id, business_id, service_id, slot_id, status, created_at, updated_at, customer_id
		FROM bookings
	`
	countQuery := `SELECT COUNT(*) FROM bookings`
	
	var query, finalCountQuery string
	var args []interface{}
	
	if status != "" {
		baseQuery += " WHERE status = $1"
		countQuery += " WHERE status = $1"
		args = append(args, status)
		finalCountQuery = countQuery
		query = baseQuery + " ORDER BY created_at DESC LIMIT $2 OFFSET $3"
		args = append(args, limit, offset)
	} else {
		finalCountQuery = countQuery
		query = baseQuery + " ORDER BY created_at DESC LIMIT $1 OFFSET $2"
		args = append(args, limit, offset)
	}
	
	// Get total count
	if status != "" {
		err := db.QueryRow(ctx, finalCountQuery, status).Scan(&totalCount)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to get total booking count: %v", err)
			return nil, 0, fmt.Errorf("failed to get booking count: %w", err)
		}
	} else {
		err := db.QueryRow(ctx, finalCountQuery).Scan(&totalCount)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to get total booking count: %v", err)
			return nil, 0, fmt.Errorf("failed to get booking count: %w", err)
		}
	}
	
	// Get bookings
	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch all bookings: %v", err)
		return nil, 0, fmt.Errorf("failed to fetch bookings: %w", err)
	}
	defer rows.Close()
	
	for rows.Next() {
		var booking Booking
		err := rows.Scan(
			&booking.ID,
			&booking.BusinessID,
			&booking.ServiceID,
			&booking.SlotID,
			&booking.Status,
			&booking.CreatedAt,
			&booking.UpdatedAt,
			&booking.CustomerID,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan booking row: %v", err)
			return nil, 0, fmt.Errorf("failed to scan booking: %w", err)
		}
		bookings = append(bookings, booking)
	}
	
	logger.InfoLogger.Infof("Fetched %d bookings from system (total: %d)", len(bookings), totalCount)
	return bookings, totalCount, nil
}

package booking_models

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
)

type Booking struct {
	Id           uuid.UUID `json:"id"`
	CustomerID   uuid.UUID `json:"customerId"`
	ServiceID    uuid.UUID `json:"serviceId"`
	Amount       float64   `json:"amount"`
	Status       string    `json:"status"`
	ObjectName   *string   `json:"objectName"`
	ServiceName  *string   `json:"serviceName"`
	BusinessName *string   `json:"businessName"`
}

type Order struct {
	Id          uuid.UUID `json:"id"`
	CustomerID  uuid.UUID `json:"customerId"`
	ServiceID   uuid.UUID `json:"serviceId"`
	Amount      float64   `json:"amount"`
	Status      string    `json:"status"`
	ObjectName  *string   `json:"objectName"`
	ServiceName *string   `json:"serviceName"`
}

// Owners get booking services
type OrderFilter struct {
	Status    string
	DateRange string
	Limit     int
	Offset    int
}

// Owners get booking services with pagination
func GetBookingByOwnerModels(ctx context.Context, db *pgxpool.Pool, ownerID uuid.UUID, filter OrderFilter) ([]*Order, int, error) {
	baseQuery := `
        SELECT 
            o.id,
            o.customer_id, 
            o.service_id, 
            o.amount, 
            o.status,
            i.object_name,
            s.name
        FROM orders AS o
            LEFT JOIN services AS s ON s.id = o.service_id
            LEFT JOIN images AS i ON s.image_id = i.id
        WHERE o.customer_id = $1
    `

	countQuery := `
        SELECT COUNT(*) 
        FROM orders AS o
            LEFT JOIN services AS s ON s.id = o.service_id
            LEFT JOIN images AS i ON s.image_id = i.id
        WHERE o.customer_id = $1
    `

	var args []interface{}
	args = append(args, ownerID)
	argIndex := 2

	// Add status filter
	if filter.Status != "" && filter.Status != "all" {
		baseQuery += fmt.Sprintf(" AND o.status = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND o.status = $%d", argIndex)
		args = append(args, filter.Status)
		argIndex++
	}

	// Add date filter
	if filter.DateRange != "" {
		var dateCondition string
		switch filter.DateRange {
		case "week":
			dateCondition = "o.created_at >= NOW() - INTERVAL '7 days'"
		case "month":
			dateCondition = "o.created_at >= NOW() - INTERVAL '1 month'"
		case "3months":
			dateCondition = "o.created_at >= NOW() - INTERVAL '3 months'"
		case "6months":
			dateCondition = "o.created_at >= NOW() - INTERVAL '6 months'"
		case "year":
			dateCondition = "o.created_at >= NOW() - INTERVAL '1 year'"
		}

		if dateCondition != "" {
			baseQuery += " AND " + dateCondition
			countQuery += " AND " + dateCondition
		}
	}

	// Execute count query FIRST with current args (before adding limit/offset)
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)

	var totalOrders int
	err := db.QueryRow(ctx, countQuery, countArgs...).Scan(&totalOrders)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to count booking orders for customerId: %s: %v", ownerID, err)
		return nil, 0, fmt.Errorf("database error counting booked times: %w", err)
	}

	// Now add ordering and pagination to base query
	baseQuery += " ORDER BY o.created_at DESC LIMIT $%d OFFSET $%d"
	baseQuery = fmt.Sprintf(baseQuery, argIndex, argIndex+1)
	args = append(args, filter.Limit, filter.Offset)

	// Execute data query
	rows, err := db.Query(ctx, baseQuery, args...)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to query booking times orders with customerId: %s: %v", ownerID, err)
		return nil, 0, fmt.Errorf("database error fetching booked times: %w", err)
	}
	defer rows.Close()

	var orders []*Order
	for rows.Next() {
		var o Order
		if err := rows.Scan(&o.Id, &o.CustomerID, &o.ServiceID, &o.Amount, &o.Status, &o.ObjectName, &o.ServiceName); err != nil {
			return nil, 0, fmt.Errorf("failed to scan booking row: %w", err)
		}
		orders = append(orders, &o)
	}

	if rows.Err() != nil {
		return nil, 0, fmt.Errorf("row iteration error: %w", rows.Err())
	}

	return orders, totalOrders, nil
}

func GetBookingByUserModels(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID) ([]*Booking, error) {
	rows, err := db.Query(ctx, `
		SELECT 
			o.id,
			o.customer_id, 
			o.service_id, 
			o.amount, 
			o.status,
			i.object_name,
			s.name,
			b.name AS business_name
		FROM orders AS o
			LEFT JOIN services AS s ON s.id = o.service_id
			LEFT JOIN images AS i ON s.image_id = i.id
			LEFT JOIN businesses AS b ON b.id = s.business_id
		WHERE o.customer_id = $1
		ORDER BY o.created_at DESC
		LIMIT 20;
	`, userID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to query booking times orders with customerId: %s: %v", userID, err)
		return nil, fmt.Errorf("database error fetching booked times: %w", err)
	}
	defer rows.Close()

	var bookings []*Booking
	for rows.Next() {
		var b Booking
		// Fixed: Added scanning of o.id into b.Id
		if err := rows.Scan(&b.Id, &b.CustomerID, &b.ServiceID, &b.Amount, &b.Status, &b.ObjectName, &b.ServiceName, &b.BusinessName); err != nil {
			return nil, fmt.Errorf("failed to scan booking row: %w", err)
		}
		bookings = append(bookings, &b)
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("row iteration error: %w", rows.Err())
	}

	return bookings, nil
}

func GetBookingByIdModels(ctx context.Context, db *pgxpool.Pool, userID, orderID uuid.UUID) ([]*Booking, error) {
	rows, err := db.Query(ctx, `
		SELECT 
			o.id,
			o.customer_id, 
			o.service_id, 
			o.amount, 
			o.status,
			i.object_name,
			s.name AS service_name,
			b.name AS business_name
		FROM orders AS o
			LEFT JOIN services AS s ON s.id = o.service_id
			LEFT JOIN images AS i ON s.image_id = i.id
			LEFT JOIN businesses AS b ON b.id = s.business_id
		WHERE o.customer_id = $1 AND o.id = $2
	`, userID, orderID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to query booking with ID %s for user %s: %v", orderID, userID, err)
		return nil, fmt.Errorf("database error fetching booking: %w", err)
	}
	defer rows.Close()

	var bookings []*Booking
	for rows.Next() {
		var b Booking
		if err := rows.Scan(
			&b.Id,
			&b.CustomerID,
			&b.ServiceID,
			&b.Amount,
			&b.Status,
			&b.ObjectName,
			&b.ServiceName,
			&b.BusinessName,
		); err != nil {
			return nil, fmt.Errorf("failed to scan booking row: %w", err)
		}
		bookings = append(bookings, &b)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return bookings, nil
}

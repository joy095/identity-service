package payment_models

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
)

type UnavailableTime struct {
	OpenTime  time.Time `json:"open_time"`
	CloseTime time.Time `json:"close_time"`
}

const (
	OrderStatusPending  = "pending"
	OrderStatusPaid     = "paid"
	OrderStatusRefunded = "refunded"
)

// HasBookingOverlap checks if there is any overlapping paid booking for the service in the given time range.
func HasBookingOverlap(ctx context.Context, db *pgxpool.Pool, serviceID uuid.UUID, startTime, endTime time.Time) (bool, error) {
	var count int
	err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM orders 
		 WHERE service_id = $1 AND status = $2 
		 AND start_time < $3 AND end_time > $4`,
		serviceID, OrderStatusPaid, endTime, startTime).Scan(&count)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to check booking overlap for service %s: %v", serviceID, err)
		return false, fmt.Errorf("database error checking overlap: %w", err)
	}
	return count > 0, nil
}

// GetBookedTimesForServiceDate retrieves all paid (booked) time ranges for a service that overlap with the given date.
func GetBookedTimesForServiceDate(ctx context.Context, db *pgxpool.Pool, serviceID uuid.UUID, startOfDay, endOfDay time.Time) ([]UnavailableTime, error) {
	rows, err := db.Query(ctx,
		`SELECT start_time, end_time 
		 FROM orders 
		 WHERE service_id = $1 AND status = $2 
		 AND start_time < $3 AND end_time > $4 
		 AND status = 'paid'
		 ORDER BY start_time ASC`,
		serviceID, OrderStatusPaid, endOfDay, startOfDay)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to query booked times for service %s: %v", serviceID, err)
		return nil, fmt.Errorf("database error fetching booked times: %w", err)
	}
	defer rows.Close()

	var times []UnavailableTime
	for rows.Next() {
		var t UnavailableTime
		if err := rows.Scan(&t.OpenTime, &t.CloseTime); err != nil {
			logger.ErrorLogger.Errorf("Failed to scan booked time row: %v", err)
			return nil, fmt.Errorf("error reading booked times: %w", err)
		}
		times = append(times, t)
	}

	if err = rows.Err(); err != nil {
		logger.ErrorLogger.Errorf("Row iteration error for booked times: %v", err)
		return nil, fmt.Errorf("error reading booked times: %w", err)
	}

	return times, nil
}

package video_models

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
)

type Video struct {
	Id         uuid.UUID  `json:"id"`
	CustomerID uuid.UUID  `json:"customerId"`
	Status     string     `json:"status"`
	StartTime  time.Time  `json:"startTime"`
	EndTime    time.Time  `json:"endTime"`
	ServiceID  uuid.UUID  `json:"serviceId"`
	BusinessID *uuid.UUID `json:"businessId,omitempty"`
	OwnerID    *uuid.UUID `json:"ownerId,omitempty"`
}

// GetVideoAccessDetails verifies ownership and paid status of an order for video access.
func GetVideoAccessDetails(ctx context.Context, db *pgxpool.Pool, orderId uuid.UUID) (*Video, error) {
	logger.InfoLogger.Infof("Fetching video access details for order ID: %s", orderId)

	video := &Video{}

	query := `
		SELECT
			o.id,
			o.customer_id,
			o.status,
			o.start_time,
			o.end_time,
			o.service_id,
			s.business_id,
			b.owner_id
		FROM orders AS o
		INNER JOIN services AS s ON s.id = o.service_id
		INNER JOIN businesses AS b ON b.id = s.business_id
		WHERE o.id = $1;
	`

	err := db.QueryRow(ctx, query, orderId).Scan(
		&video.Id,
		&video.CustomerID,
		&video.Status,
		&video.StartTime,
		&video.EndTime,
		&video.ServiceID,
		&video.BusinessID,
		&video.OwnerID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.InfoLogger.Infof("No order found for ID: %s", orderId)
			return nil, fmt.Errorf("order not found")
		}
		logger.ErrorLogger.Errorf("Error fetching order %s: %v", orderId, err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	if strings.ToLower(video.Status) != "paid" {
		logger.WarnLogger.Warnf("Order %s is not paid (status: %s)", orderId, video.Status)
		return nil, fmt.Errorf("order is not paid")
	}

	logger.InfoLogger.Infof("Access details fetched successfully for order %s", orderId)
	return video, nil
}

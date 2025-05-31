package schedule_slot_models

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
)

// ScheduleSlot represents a time slot for a business.
type ScheduleSlot struct {
	ID          uuid.UUID `json:"id"`
	BusinessID  uuid.UUID `json:"business_id"`
	OpenTime    time.Time `json:"open_time"`
	CloseTime   time.Time `json:"close_time"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	IsAvailable bool      `json:"is_available"`
}

// GetScheduleSlotByID fetches a schedule slot by its ID.
func GetScheduleSlotByID(ctx context.Context, db *pgxpool.Pool, slotID uuid.UUID) (*ScheduleSlot, error) {
	logger.InfoLogger.Infof("Attempting to fetch schedule slot with ID: %s", slotID)

	slot := &ScheduleSlot{}
	query := `
		SELECT id, business_id, open_time, close_time, created_at, updated_at, is_available
		FROM schedule_slots
		WHERE id = $1`

	err := db.QueryRow(ctx, query, slotID).Scan(
		&slot.ID, &slot.BusinessID, &slot.OpenTime, &slot.CloseTime,
		&slot.CreatedAt, &slot.UpdatedAt, &slot.IsAvailable,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.WarnLogger.Warnf("Schedule slot with ID %s not found", slotID)
			return nil, fmt.Errorf("schedule slot not found")
		}
		logger.ErrorLogger.Errorf("Failed to fetch schedule slot %s: %v", slotID, err)
		return nil, fmt.Errorf("database error fetching schedule slot: %w", err)
	}

	logger.InfoLogger.Infof("Schedule slot with ID %s fetched successfully", slotID)
	return slot, nil
}

// UpdateScheduleSlotAvailability updates the is_available status of a schedule slot.
func UpdateScheduleSlotAvailability(ctx context.Context, db *pgxpool.Pool, slotID uuid.UUID, isAvailable bool) error {
	logger.InfoLogger.Infof("Updating availability for slot %s to %t", slotID, isAvailable)

	query := `
		UPDATE schedule_slots
		SET is_available = $2, updated_at = NOW()
		WHERE id = $1`

	cmdTag, err := db.Exec(ctx, query, slotID, isAvailable)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update slot %s availability: %v", slotID, err)
		return fmt.Errorf("failed to update slot availability: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("slot with ID %s not found for update", slotID)
	}

	logger.InfoLogger.Infof("Slot %s availability updated to %t", slotID, isAvailable)
	return nil
}

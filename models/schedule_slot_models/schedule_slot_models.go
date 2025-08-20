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

const (
	StatusPending   = "pending"
	StatusConfirmed = "confirmed"
	StatusCancelled = "cancelled"
	StatusRefunded  = "refunded"
)

// validStatuses ensures only allowed values are stored in DB
var validStatuses = map[string]bool{
	StatusPending:   true,
	StatusConfirmed: true,
	StatusCancelled: true,
	StatusRefunded:  true,
}

type UnavailableTime struct {
	OpenTime  time.Time `json:"open_time"`
	CloseTime time.Time `json:"close_time"`
}

// ScheduleSlot represents a time slot for a business.
type ScheduleSlot struct {
	ID         uuid.UUID `json:"id"`
	BusinessID uuid.UUID `json:"business_id"`
	UserID     uuid.UUID `json:"user_id"`
	OpenTime   time.Time `json:"open_time"`
	CloseTime  time.Time `json:"close_time"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Status     string    `json:"status"` // pending, confirmed, cancelled, refunded
}

// GetScheduleSlotByID fetches a schedule slot by its ID.
func GetScheduleSlotByID(ctx context.Context, db *pgxpool.Pool, slotID uuid.UUID) (*ScheduleSlot, error) {
	logger.InfoLogger.Infof("Attempting to fetch schedule slot with ID: %s", slotID)

	slot := &ScheduleSlot{}
	query := `
	SELECT id, business_id, user_id, open_time, close_time, created_at, updated_at, status
	FROM schedule_slots
	WHERE id = $1`

	err := db.QueryRow(ctx, query, slotID).Scan(
		&slot.ID, &slot.BusinessID, &slot.UserID, &slot.OpenTime, &slot.CloseTime,
		&slot.CreatedAt, &slot.UpdatedAt, &slot.Status,
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

// UpdateScheduleSlotStatus updates the status of a schedule slot.
func UpdateScheduleSlotStatus(ctx context.Context, db *pgxpool.Pool, slotID uuid.UUID, status string) error {
	if !validStatuses[status] {
		return fmt.Errorf("invalid status: %s", status)
	}

	query := `
		UPDATE schedule_slots
		SET status = $2, updated_at = NOW()
		WHERE id = $1`

	cmdTag, err := db.Exec(ctx, query, slotID, status)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update slot %s status: %v", slotID, err)
		return fmt.Errorf("failed to update slot status: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("slot with ID %s not found for update", slotID)
	}

	logger.InfoLogger.Infof("Slot %s status updated to %s", slotID, status)
	return nil
}

// NewScheduleSlot creates a new ScheduleSlot instance.
func NewScheduleSlot(businessID, userID uuid.UUID, openTime, closeTime time.Time, status string) (*ScheduleSlot, error) {
	if status == "" {
		status = StatusPending
	}
	if !validStatuses[status] {
		return nil, fmt.Errorf("invalid status: %s", status)
	}

	return &ScheduleSlot{
		ID:         uuid.New(),
		BusinessID: businessID,
		UserID:     userID,
		OpenTime:   openTime,
		CloseTime:  closeTime,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		Status:     status,
	}, nil
}

// CreateScheduleSlot inserts a new schedule slot into the database.
func CreateScheduleSlot(ctx context.Context, db *pgxpool.Pool, slot *ScheduleSlot) (*ScheduleSlot, error) {
	if slot == nil {
		return nil, fmt.Errorf("slot must not be nil")
	}
	// Validate and normalize input before insert
	if slot.BusinessID == uuid.Nil {
		return nil, fmt.Errorf("businessID must be provided")
	}
	if slot.Status == "" {
		slot.Status = StatusPending
	}
	if !validStatuses[slot.Status] {
		return nil, fmt.Errorf("invalid status: %s", slot.Status)
	}
	if slot.OpenTime.IsZero() || slot.CloseTime.IsZero() {
		return nil, fmt.Errorf("openTime and closeTime must be provided")
	}
	if !slot.OpenTime.Before(slot.CloseTime) {
		return nil, fmt.Errorf("closeTime must be after openTime")
	}
	if slot.ID == uuid.Nil {
		slot.ID = uuid.New()
	}
	if slot.CreatedAt.IsZero() {
		slot.CreatedAt = time.Now()
	}
	if slot.UpdatedAt.IsZero() {
		slot.UpdatedAt = time.Now()
	}
	logger.InfoLogger.Infof("Creating new schedule slot for business %s", slot.BusinessID)

	query := `
		INSERT INTO schedule_slots (id, business_id, user_id, open_time, close_time, created_at, updated_at, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, business_id, user_id, open_time, close_time, created_at, updated_at, status`

	var createdSlot ScheduleSlot
	err := db.QueryRow(ctx, query,
		slot.ID, slot.BusinessID, slot.UserID, slot.OpenTime, slot.CloseTime,
		slot.CreatedAt, slot.UpdatedAt, slot.Status,
	).Scan(
		&createdSlot.ID, &createdSlot.BusinessID, &createdSlot.UserID,
		&createdSlot.OpenTime, &createdSlot.CloseTime,
		&createdSlot.CreatedAt, &createdSlot.UpdatedAt, &createdSlot.Status,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create schedule slot: %v", err)
		return nil, fmt.Errorf("failed to create schedule slot: %w", err)
	}

	logger.InfoLogger.Infof("Schedule slot %s created successfully by user %s", createdSlot.ID, createdSlot.UserID)
	return &createdSlot, nil
}

// UpdateScheduleSlot updates an existing schedule slot in the database.
func UpdateScheduleSlot(ctx context.Context, db *pgxpool.Pool, slotID uuid.UUID, openTime, closeTime *time.Time, status *string) (*ScheduleSlot, error) {
	logger.InfoLogger.Infof("Updating schedule slot %s", slotID)

	// If updating either time, validate the final [open, close) window
	if openTime != nil || closeTime != nil {
		existing, err := GetScheduleSlotByID(ctx, db, slotID)
		if err != nil {
			return nil, err
		}
		finalOpen := existing.OpenTime
		finalClose := existing.CloseTime
		if openTime != nil {
			finalOpen = *openTime
		}
		if closeTime != nil {
			finalClose = *closeTime
		}
		if !finalOpen.Before(finalClose) {
			return nil, fmt.Errorf("closeTime must be after openTime")
		}
	}

	if openTime != nil && closeTime != nil && !closeTime.After(*openTime) {
		return nil, fmt.Errorf("close time must be after open time")
	}

	// Use COALESCE to handle optional updates
	query := `
		UPDATE schedule_slots
		SET 
			open_time = COALESCE($2, open_time),
			close_time = COALESCE($3, close_time),
			updated_at = $4
		WHERE id = $1
		RETURNING id, business_id, open_time, close_time, created_at, updated_at`

	var updatedSlot ScheduleSlot
	err := db.QueryRow(ctx, query, slotID, openTime, closeTime, time.Now()).Scan(
		&updatedSlot.ID, &updatedSlot.BusinessID, &updatedSlot.OpenTime, &updatedSlot.CloseTime,
		&updatedSlot.CreatedAt, &updatedSlot.UpdatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.WarnLogger.Warnf("Schedule slot %s not found for update", slotID)
			return nil, fmt.Errorf("schedule slot not found")
		}
		logger.ErrorLogger.Errorf("Failed to update schedule slot %s: %v", slotID, err)
		return nil, fmt.Errorf("failed to update schedule slot: %w", err)
	}

	logger.InfoLogger.Infof("Schedule slot %s updated successfully", slotID)
	return &updatedSlot, nil
}

// DeleteScheduleSlot hard deletes a schedule slot.
func DeleteScheduleSlot(ctx context.Context, db *pgxpool.Pool, slotID uuid.UUID) error {
	logger.InfoLogger.Infof("Deleting schedule slot %s", slotID)

	query := `DELETE FROM schedule_slots WHERE id = $1`

	cmdTag, err := db.Exec(ctx, query, slotID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete schedule slot %s: %v", slotID, err)
		return fmt.Errorf("failed to delete schedule slot: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("schedule slot with ID %s not found for deletion", slotID)
	}

	logger.InfoLogger.Infof("Schedule slot %s deleted successfully", slotID)
	return nil
}

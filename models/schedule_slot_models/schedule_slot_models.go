package schedule_slot_models

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

// NewScheduleSlot creates a new ScheduleSlot instance.
func NewScheduleSlot(businessID uuid.UUID, openTime, closeTime time.Time, isAvailable bool) (*ScheduleSlot, error) {
	return &ScheduleSlot{
		ID:          uuid.New(),
		BusinessID:  businessID,
		OpenTime:    openTime,
		CloseTime:   closeTime,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		IsAvailable: isAvailable,
	}, nil
}

// CreateScheduleSlot inserts a new schedule slot into the database.
func CreateScheduleSlot(ctx context.Context, db *pgxpool.Pool, slot *ScheduleSlot) (*ScheduleSlot, error) {
	logger.InfoLogger.Infof("Creating new schedule slot for business %s", slot.BusinessID)

	query := `
		INSERT INTO schedule_slots (id, business_id, open_time, close_time, created_at, updated_at, is_available)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, business_id, open_time, close_time, created_at, updated_at, is_available`

	row := db.QueryRow(ctx, query,
		slot.ID, slot.BusinessID, slot.OpenTime, slot.CloseTime,
		slot.CreatedAt, slot.UpdatedAt, slot.IsAvailable,
	)

	var createdSlot ScheduleSlot
	err := row.Scan(
		&createdSlot.ID, &createdSlot.BusinessID, &createdSlot.OpenTime, &createdSlot.CloseTime,
		&createdSlot.CreatedAt, &createdSlot.UpdatedAt, &createdSlot.IsAvailable,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create schedule slot: %v", err)
		return nil, fmt.Errorf("failed to create schedule slot: %w", err)
	}

	logger.InfoLogger.Infof("Schedule slot %s created successfully", createdSlot.ID)
	return &createdSlot, nil
}

// GetScheduleSlotsByBusiness retrieves schedule slots for a specific business with pagination and filtering.
func GetScheduleSlotsByBusiness(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID, availableFilter *bool, page, limit int) ([]ScheduleSlot, int, error) {
	logger.InfoLogger.Infof("Fetching schedule slots for business %s, page %d, limit %d", businessID, page, limit)

	// Build base query
	baseQuery := `FROM schedule_slots WHERE business_id = $1`
	params := []interface{}{businessID}
	paramCount := 1

	// Add availability filter if specified
	if availableFilter != nil {
		paramCount++
		baseQuery += fmt.Sprintf(` AND is_available = $%d`, paramCount)
		params = append(params, *availableFilter)
	}

	// Count total records
	countQuery := "SELECT COUNT(*) " + baseQuery
	var totalCount int
	err := db.QueryRow(ctx, countQuery, params...).Scan(&totalCount)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to count schedule slots for business %s: %v", businessID, err)
		return nil, 0, fmt.Errorf("failed to count schedule slots: %w", err)
	}

	// Get paginated data
	offset := (page - 1) * limit
	paramCount++
	limitParam := paramCount
	paramCount++
	offsetParam := paramCount

	dataQuery := `
		SELECT id, business_id, open_time, close_time, created_at, updated_at, is_available
		` + baseQuery + `
		ORDER BY open_time ASC
		LIMIT $` + fmt.Sprintf("%d", limitParam) + ` OFFSET $` + fmt.Sprintf("%d", offsetParam)

	params = append(params, limit, offset)

	rows, err := db.Query(ctx, dataQuery, params...)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch schedule slots for business %s: %v", businessID, err)
		return nil, 0, fmt.Errorf("failed to fetch schedule slots: %w", err)
	}
	defer rows.Close()

	var slots []ScheduleSlot
	for rows.Next() {
		var slot ScheduleSlot
		err := rows.Scan(
			&slot.ID, &slot.BusinessID, &slot.OpenTime, &slot.CloseTime,
			&slot.CreatedAt, &slot.UpdatedAt, &slot.IsAvailable,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan schedule slot: %v", err)
			return nil, 0, fmt.Errorf("failed to scan schedule slot: %w", err)
		}
		slots = append(slots, slot)
	}

	if err = rows.Err(); err != nil {
		logger.ErrorLogger.Errorf("Error iterating schedule slots: %v", err)
		return nil, 0, fmt.Errorf("error iterating schedule slots: %w", err)
	}

	logger.InfoLogger.Infof("Fetched %d schedule slots for business %s", len(slots), businessID)
	return slots, totalCount, nil
}

// UpdateScheduleSlot updates an existing schedule slot in the database.
func UpdateScheduleSlot(ctx context.Context, db *pgxpool.Pool, slotID uuid.UUID, openTime, closeTime *time.Time, isAvailable *bool) (*ScheduleSlot, error) {
	logger.InfoLogger.Infof("Updating schedule slot %s", slotID)

	// Build dynamic update query
	updateFields := []string{}
	params := []interface{}{}
	paramCount := 0

	if openTime != nil {
		paramCount++
		updateFields = append(updateFields, fmt.Sprintf("open_time = $%d", paramCount))
		params = append(params, *openTime)
	}

	if closeTime != nil {
		paramCount++
		updateFields = append(updateFields, fmt.Sprintf("close_time = $%d", paramCount))
		params = append(params, *closeTime)
	}

	if isAvailable != nil {
		paramCount++
		updateFields = append(updateFields, fmt.Sprintf("is_available = $%d", paramCount))
		params = append(params, *isAvailable)
	}

	if len(updateFields) == 0 {
		return GetScheduleSlotByID(ctx, db, slotID) // No updates, return existing slot
	}

	// Always update the updated_at field
	paramCount++
	updateFields = append(updateFields, fmt.Sprintf("updated_at = $%d", paramCount))
	params = append(params, time.Now())

	// Add the WHERE condition
	paramCount++
	params = append(params, slotID)

	query := fmt.Sprintf(`
		UPDATE schedule_slots
		SET %s
		WHERE id = $%d
		RETURNING id, business_id, open_time, close_time, created_at, updated_at, is_available`,
		strings.Join(updateFields, ", "), paramCount)

	var updatedSlot ScheduleSlot
	err := db.QueryRow(ctx, query, params...).Scan(
		&updatedSlot.ID, &updatedSlot.BusinessID, &updatedSlot.OpenTime, &updatedSlot.CloseTime,
		&updatedSlot.CreatedAt, &updatedSlot.UpdatedAt, &updatedSlot.IsAvailable,
	)
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

// DeleteScheduleSlot soft deletes a schedule slot (marks as unavailable and updates timestamp).
// For hard delete, you could implement a separate function.
func DeleteScheduleSlot(ctx context.Context, db *pgxpool.Pool, slotID uuid.UUID) error {
	logger.InfoLogger.Infof("Deleting schedule slot %s", slotID)

	// For now, we'll do a hard delete. You could implement soft delete by setting a deleted_at field
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

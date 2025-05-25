// models/schedule_slot.go
package models

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger" // Adjust import path
)

// ScheduleSlot represents the operating hours for a business on a specific day.
type ScheduleSlot struct {
	ID         uuid.UUID `json:"id"`
	BusinessID uuid.UUID `json:"businessId"`
	DayOfWeek  string    `json:"dayOfWeek"` // e.g., "Monday", "Tuesday"
	OpenTime   string    `json:"openTime"`  // Stored as HH:MM:SS string for TIME WITHOUT TIME ZONE
	CloseTime  string    `json:"closeTime"` // Stored as HH:MM:SS string
	IsClosed   bool      `json:"isClosed"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// NewScheduleSlot creates a new ScheduleSlot instance.
func NewScheduleSlot(
	businessID uuid.UUID,
	dayOfWeek, openTime, closeTime string,
	isClosed bool,
) *ScheduleSlot {
	now := time.Now()
	return &ScheduleSlot{
		ID:         uuid.New(),
		BusinessID: businessID,
		DayOfWeek:  dayOfWeek,
		OpenTime:   openTime,
		CloseTime:  closeTime,
		IsClosed:   isClosed,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
}

// CreateScheduleSlot inserts a new schedule slot into the database.
func CreateScheduleSlot(db *pgxpool.Pool, slot *ScheduleSlot) (*ScheduleSlot, error) {
	logger.InfoLogger.Info("Attempting to create schedule slot record in database")

	query := `
        INSERT INTO schedule_slots (
            id, business_id, day_of_week, open_time, close_time,
            is_closed, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8
        ) RETURNING id`

	_, err := db.Exec(context.Background(), query,
		slot.ID,
		slot.BusinessID,
		slot.DayOfWeek,
		slot.OpenTime,
		slot.CloseTime,
		slot.IsClosed,
		slot.CreatedAt,
		slot.UpdatedAt,
	)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to insert schedule slot into database: %v", err)
		return nil, fmt.Errorf("failed to create schedule slot: %w", err)
	}

	logger.InfoLogger.Infof("Schedule slot with ID %s created successfully", slot.ID)
	return slot, nil
}

// GetScheduleSlotByID fetches a schedule slot record by its ID.
func GetScheduleSlotByID(db *pgxpool.Pool, id uuid.UUID) (*ScheduleSlot, error) {
	logger.InfoLogger.Infof("Attempting to fetch schedule slot with ID: %s", id)

	slot := &ScheduleSlot{}
	query := `
		SELECT
			id, business_id, day_of_week, open_time, close_time,
			is_closed, created_at, updated_at
		FROM
			schedule_slots
		WHERE
			id = $1`

	err := db.QueryRow(context.Background(), query, id).Scan(
		&slot.ID,
		&slot.BusinessID,
		&slot.DayOfWeek,
		&slot.OpenTime,
		&slot.CloseTime,
		&slot.IsClosed,
		&slot.CreatedAt,
		&slot.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			logger.InfoLogger.Infof("Schedule slot with ID %s not found", id)
			return nil, fmt.Errorf("schedule slot not found")
		}
		logger.ErrorLogger.Errorf("Failed to fetch schedule slot %s: %v", id, err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	logger.InfoLogger.Infof("Schedule slot with ID %s fetched successfully", id)
	return slot, nil
}

// GetScheduleSlotsByBusinessID fetches all schedule slots for a given business ID.
func GetScheduleSlotsByBusinessID(db *pgxpool.Pool, businessID uuid.UUID) ([]ScheduleSlot, error) {
	logger.InfoLogger.Infof("Attempting to fetch schedule slots for Business ID: %s", businessID)

	var slots []ScheduleSlot
	query := `
		SELECT
			id, business_id, day_of_week, open_time, close_time,
			is_closed, created_at, updated_at
		FROM
			schedule_slots
		WHERE
			business_id = $1
		ORDER BY
			CASE day_of_week
				WHEN 'Sunday' THEN 1
				WHEN 'Monday' THEN 2
				WHEN 'Tuesday' THEN 3
				WHEN 'Wednesday' THEN 4
				WHEN 'Thursday' THEN 5
				WHEN 'Friday' THEN 6
				WHEN 'Saturday' THEN 7
			END` // Order by day of week

	rows, err := db.Query(context.Background(), query, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to query schedule slots for business %s: %v", businessID, err)
		return nil, fmt.Errorf("failed to fetch schedule slots: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var slot ScheduleSlot
		err := rows.Scan(
			&slot.ID,
			&slot.BusinessID,
			&slot.DayOfWeek,
			&slot.OpenTime,
			&slot.CloseTime,
			&slot.IsClosed,
			&slot.CreatedAt,
			&slot.UpdatedAt,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan schedule slot row for business %s: %v", businessID, err)
			return nil, fmt.Errorf("failed to scan schedule slot data: %w", err)
		}
		slots = append(slots, slot)
	}

	if err := rows.Err(); err != nil {
		logger.ErrorLogger.Errorf("Error after scanning rows for schedule slots for business %s: %v", businessID, err)
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	logger.InfoLogger.Infof("Successfully fetched %d schedule slots for Business ID %s", len(slots), businessID)
	return slots, nil
}

// UpdateScheduleSlot updates an existing schedule slot record in the database.
func UpdateScheduleSlot(db *pgxpool.Pool, slot *ScheduleSlot) (*ScheduleSlot, error) {
	logger.InfoLogger.Infof("Attempting to update schedule slot record with ID: %s", slot.ID)

	slot.UpdatedAt = time.Now() // Update timestamp on modification

	query := `
        UPDATE schedule_slots
        SET
            day_of_week = $2,
            open_time = $3,
            close_time = $4,
            is_closed = $5,
            updated_at = $6
        WHERE
            id = $1 AND business_id = $7
        RETURNING id`

	res, err := db.Exec(context.Background(), query,
		slot.ID,
		slot.DayOfWeek,
		slot.OpenTime,
		slot.CloseTime,
		slot.IsClosed,
		slot.UpdatedAt,
		slot.BusinessID, // Used in WHERE clause for security/ownership
	)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update schedule slot %s in database: %v", slot.ID, err)
		return nil, fmt.Errorf("failed to update schedule slot: %w", err)
	}

	if res.RowsAffected() == 0 {
		return nil, fmt.Errorf("schedule slot with ID %s (for business %s) not found for update", slot.ID, slot.BusinessID)
	}

	logger.InfoLogger.Infof("Schedule slot with ID %s updated successfully", slot.ID)
	return slot, nil
}

// DeleteScheduleSlot deletes a schedule slot record from the database.
func DeleteScheduleSlot(db *pgxpool.Pool, slotID, businessID uuid.UUID) error {
	logger.InfoLogger.Infof("Attempting to delete schedule slot record with ID: %s for Business ID: %s", slotID, businessID)

	query := `DELETE FROM schedule_slots WHERE id = $1 AND business_id = $2` // Include business_id for ownership check

	res, err := db.Exec(context.Background(), query, slotID, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete schedule slot %s for business %s from database: %v", slotID, businessID, err)
		return fmt.Errorf("failed to delete schedule slot: %w", err)
	}

	if res.RowsAffected() == 0 {
		return fmt.Errorf("schedule slot with ID %s (for business %s) not found for deletion", slotID, businessID)
	}

	logger.InfoLogger.Infof("Schedule slot with ID %s deleted successfully", slotID)
	return nil
}

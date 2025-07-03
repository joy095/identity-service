package working_hour_models

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5" // Correct import for pgx.Tx
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger" // Adjust import path
)

// WorkingHour represents the operating hours for a business on a specific day.
type WorkingHour struct {
	ID         uuid.UUID `json:"id"`
	BusinessID uuid.UUID `json:"businessId"`
	DayOfWeek  string    `json:"dayOfWeek"` // e.g., "Monday", "Tuesday"
	OpenTime   string    `json:"openTime"`  // Stored as HH:MM:SS string for TIME WITHOUT TIME ZONE
	CloseTime  string    `json:"closeTime"` // Stored as HH:MM:SS string
	IsClosed   bool      `json:"isClosed"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// NewWorkingHour creates a new WorkingHour instance.
func NewWorkingHour(
	businessID uuid.UUID,
	dayOfWeek, openTime, closeTime string,
	isClosed bool,
) *WorkingHour {
	now := time.Now()
	wh := &WorkingHour{
		ID:         uuid.New(),
		BusinessID: businessID,
		DayOfWeek:  dayOfWeek,
		OpenTime:   openTime,
		CloseTime:  closeTime,
		IsClosed:   isClosed,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	logger.DebugLogger.Debugf("Created new WorkingHour model for BusinessID: %s, Day: %s", businessID, dayOfWeek)
	return wh
}

// CreateWorkingHour inserts a new working hour slot into the database using the pool.
func CreateWorkingHour(db *pgxpool.Pool, wh *WorkingHour) (*WorkingHour, error) {
	logger.InfoLogger.Infof("Attempting to create working hour record for BusinessID: %s, Day: %s (using pool)", wh.BusinessID, wh.DayOfWeek)

	query := `
		INSERT INTO working_hours (
			id, business_id, day_of_week, open_time, close_time,
			is_closed, created_at, updated_at
		)
		VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		) RETURNING id`

	var returnedID uuid.UUID
	if err := db.QueryRow(context.Background(), query,
		wh.ID,
		wh.BusinessID,
		wh.DayOfWeek,
		wh.OpenTime,
		wh.CloseTime,
		wh.IsClosed,
		wh.CreatedAt,
		wh.UpdatedAt,
	).Scan(&returnedID); err != nil {
		logger.ErrorLogger.Errorf("Failed to insert working hour for BusinessID: %s, Day: %s into database: %v", wh.BusinessID, wh.DayOfWeek, err)
		return nil, fmt.Errorf("failed to create working hour: %w", err)
	}

	logger.InfoLogger.Infof("Working hour with ID %s created successfully for BusinessID: %s, Day: %s (using pool)", wh.ID, wh.BusinessID, wh.DayOfWeek)
	return wh, nil
}

// CreateWorkingHourTx inserts a new working hour slot into the database using a transaction.
func CreateWorkingHourTx(ctx context.Context, tx pgx.Tx, wh *WorkingHour) (*WorkingHour, error) {
	logger.InfoLogger.Infof("Attempting to create working hour record for BusinessID: %s, Day: %s (using transaction)", wh.BusinessID, wh.DayOfWeek)

	query := `
		INSERT INTO working_hours (
			id, business_id, day_of_week, open_time, close_time,
			is_closed, created_at, updated_at
		)
		VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		) RETURNING id`

	var returnedID uuid.UUID
	err := tx.QueryRow(ctx, query,
		wh.ID,
		wh.BusinessID,
		wh.DayOfWeek,
		wh.OpenTime,
		wh.CloseTime,
		wh.IsClosed,
		wh.CreatedAt,
		wh.UpdatedAt,
	).Scan(&returnedID)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to insert working hour for BusinessID: %s, Day: %s into database (tx): %v", wh.BusinessID, wh.DayOfWeek, err)
		return nil, fmt.Errorf("failed to create working hour (tx): %w", err)
	}

	logger.InfoLogger.Infof("Working hour with ID %s created successfully for BusinessID: %s, Day: %s (using transaction)", wh.ID, wh.BusinessID, wh.DayOfWeek)
	return wh, nil
}

// GetWorkingHourByID fetches a working hour record by its ID.
func GetWorkingHourByID(db *pgxpool.Pool, id uuid.UUID) (*WorkingHour, error) {
	logger.InfoLogger.Infof("Attempting to fetch working hour with ID: %s", id)

	wh := &WorkingHour{}
	query := `
		SELECT
			id, business_id, day_of_week, open_time, close_time,
			is_closed, created_at, updated_at
		FROM
			working_hours
		WHERE
			id = $1`

	err := db.QueryRow(context.Background(), query, id).Scan(
		&wh.ID,
		&wh.BusinessID,
		&wh.DayOfWeek,
		&wh.OpenTime,
		&wh.CloseTime,
		&wh.IsClosed,
		&wh.CreatedAt,
		&wh.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			logger.InfoLogger.Infof("Working hour with ID %s not found in database.", id)
			return nil, fmt.Errorf("working hour not found")
		}
		logger.ErrorLogger.Errorf("Failed to fetch working hour %s from database: %v", id, err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	logger.InfoLogger.Infof("Working hour with ID %s fetched successfully from database.", id)
	return wh, nil
}

// GetWorkingHoursByBusinessID fetches all working hours for a given business ID.
func GetWorkingHoursByBusinessID(db *pgxpool.Pool, businessID uuid.UUID) ([]WorkingHour, error) {
	logger.InfoLogger.Infof("Attempting to fetch working hours for Business ID: %s", businessID)

	var whs []WorkingHour
	query := `
		SELECT
			id, business_id, day_of_week, open_time, close_time,
			is_closed, created_at, updated_at
		FROM
			working_hours
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
		logger.ErrorLogger.Errorf("Failed to query working hours for business %s: %v", businessID, err)
		return nil, fmt.Errorf("failed to fetch working hours: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var wh WorkingHour
		err := rows.Scan(
			&wh.ID,
			&wh.BusinessID,
			&wh.DayOfWeek,
			&wh.OpenTime,
			&wh.CloseTime,
			&wh.IsClosed,
			&wh.CreatedAt,
			&wh.UpdatedAt,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan row for working hours for business %s: %v", businessID, err)
			return nil, fmt.Errorf("failed to scan working hour row: %w", err)
		}
		whs = append(whs, wh)
	}

	if err = rows.Err(); err != nil {
		logger.ErrorLogger.Errorf("Error encountered during iteration over working hours rows for business %s: %v", businessID, err)
		return nil, fmt.Errorf("error during row iteration: %w", err)
	}

	logger.InfoLogger.Infof("Fetched %d working hours for business %s from database.", len(whs), businessID)
	return whs, nil
}

// GetWorkingHoursByBusinessID fetches all working hours for a given business ID.
func GetWorkingHoursByBusinessPublicID(db *pgxpool.Pool, publicID string) ([]WorkingHour, error) {
	logger.InfoLogger.Infof("Attempting to fetch working hours for Business Public ID: %s", publicID)

	var whs []WorkingHour
	query := `
		SELECT
			w.id,
			w.business_id,
			w.day_of_week,
			w.open_time,
			w.close_time,
			w.is_closed,
			w.created_at,
			w.updated_at
		FROM
			working_hours w
		LEFT JOIN
			businesses b ON w.business_id = b.id
		WHERE
			b.public_id = $1
		ORDER BY
			CASE w.day_of_week
				WHEN 'Sunday' THEN 1
				WHEN 'Monday' THEN 2
				WHEN 'Tuesday' THEN 3
				WHEN 'Wednesday' THEN 4
				WHEN 'Thursday' THEN 5
				WHEN 'Friday' THEN 6
				WHEN 'Saturday' THEN 7
			END
	`

	rows, err := db.Query(context.Background(), query, publicID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to query working hours for business public ID %s: %v", publicID, err)
		return nil, fmt.Errorf("failed to fetch working hours: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var wh WorkingHour
		err := rows.Scan(
			&wh.ID,
			&wh.BusinessID,
			&wh.DayOfWeek,
			&wh.OpenTime,
			&wh.CloseTime,
			&wh.IsClosed,
			&wh.CreatedAt,
			&wh.UpdatedAt,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan row for working hours for business public ID %s: %v", publicID, err)
			return nil, fmt.Errorf("failed to scan working hour row: %w", err)
		}
		whs = append(whs, wh)
	}

	if err = rows.Err(); err != nil {
		logger.ErrorLogger.Errorf("Error during row iteration for business public ID %s: %v", publicID, err)
		return nil, fmt.Errorf("error during row iteration: %w", err)
	}

	logger.InfoLogger.Infof("Fetched %d working hours for business public ID %s from database.", len(whs), publicID)
	return whs, nil
}

// UpdateWorkingHour updates an existing working hour record using the pool.
func UpdateWorkingHour(db *pgxpool.Pool, wh *WorkingHour) (*WorkingHour, error) {
	logger.InfoLogger.Infof("Attempting to update working hour ID: %s for BusinessID: %s, Day: %s (using pool)", wh.ID, wh.BusinessID, wh.DayOfWeek)

	wh.UpdatedAt = time.Now() // Update the UpdatedAt timestamp
	query := `
		UPDATE working_hours
		SET
			day_of_week = $1,
			open_time = $2,
			close_time = $3,
			is_closed = $4,
			updated_at = $5
		WHERE
			id = $6 AND business_id = $7
		RETURNING updated_at` // Return updated_at to confirm

	var updatedTime time.Time
	err := db.QueryRow(context.Background(), query,
		wh.DayOfWeek,
		wh.OpenTime,
		wh.CloseTime,
		wh.IsClosed,
		wh.UpdatedAt,
		wh.ID,
		wh.BusinessID,
	).Scan(&updatedTime)

	if err != nil {
		if err == pgx.ErrNoRows {
			logger.InfoLogger.Warnf("No row found to update for working hour ID %s for business %s.", wh.ID, wh.BusinessID)
			return nil, fmt.Errorf("working hour not found or not associated with business")
		}
		logger.ErrorLogger.Errorf("Failed to update working hour ID %s for BusinessID %s in database: %v", wh.ID, wh.BusinessID, err)
		return nil, fmt.Errorf("failed to update working hour: %w", err)
	}

	wh.UpdatedAt = updatedTime // Ensure the returned updated_at is set
	logger.InfoLogger.Infof("Working hour ID %s updated successfully for BusinessID: %s, Day: %s (using pool)", wh.ID, wh.BusinessID, wh.DayOfWeek)
	return wh, nil
}

// UpdateWorkingHourTx updates an existing working hour record using a transaction.
func UpdateWorkingHourTx(ctx context.Context, tx pgx.Tx, wh *WorkingHour) (*WorkingHour, error) {
	logger.InfoLogger.Infof("Attempting to update working hour ID: %s for BusinessID: %s, Day: %s (using transaction)", wh.ID, wh.BusinessID, wh.DayOfWeek)

	wh.UpdatedAt = time.Now() // Update the UpdatedAt timestamp
	query := `
		UPDATE working_hours
		SET
			day_of_week = $1,
			open_time = $2,
			close_time = $3,
			is_closed = $4,
			updated_at = $5
		WHERE
			id = $6 AND business_id = $7
		RETURNING updated_at`

	var updatedTime time.Time
	err := tx.QueryRow(ctx, query,
		wh.DayOfWeek,
		wh.OpenTime,
		wh.CloseTime,
		wh.IsClosed,
		wh.UpdatedAt,
		wh.ID,
		wh.BusinessID,
	).Scan(&updatedTime)

	if err != nil {
		if err == pgx.ErrNoRows {
			logger.InfoLogger.Warnf("No row found to update for working hour ID %s for business %s in transaction.", wh.ID, wh.BusinessID)
			return nil, fmt.Errorf("working hour not found or not associated with business (tx)")
		}
		logger.ErrorLogger.Errorf("Failed to update working hour ID %s for BusinessID %s in database (tx): %v", wh.ID, wh.BusinessID, err)
		return nil, fmt.Errorf("failed to update working hour (tx): %w", err)
	}

	wh.UpdatedAt = updatedTime
	logger.InfoLogger.Infof("Working hour ID %s updated successfully for BusinessID: %s, Day: %s (using transaction)", wh.ID, wh.BusinessID, wh.DayOfWeek)
	return wh, nil
}

// DeleteWorkingHour deletes a working hour record by its ID and business ID.
func DeleteWorkingHour(db *pgxpool.Pool, id uuid.UUID, businessID uuid.UUID) error {
	logger.InfoLogger.Infof("Attempting to delete working hour ID: %s for BusinessID: %s", id, businessID)

	query := `
		DELETE FROM working_hours
		WHERE id = $1 AND business_id = $2` // Added business_id to ensure ownership before delete

	commandTag, err := db.Exec(context.Background(), query, id, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete working hour ID %s for BusinessID %s from database: %v", id, businessID, err)
		return fmt.Errorf("failed to delete working hour: %w", err)
	}

	if commandTag.RowsAffected() == 0 {
		logger.InfoLogger.Warnf("No working hour found with ID %s and BusinessID %s for deletion.", id, businessID)
		return fmt.Errorf("working hour not found or not associated with business")
	}

	logger.InfoLogger.Infof("Working hour ID %s for BusinessID %s deleted successfully.", id, businessID)
	return nil
}

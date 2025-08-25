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
	OpenTime   time.Time `json:"openTime"`  // Stored as HH:MM:SS string for TIME WITHOUT TIME ZONE
	CloseTime  time.Time `json:"closeTime"` // Stored as HH:MM:SS string
	IsClosed   bool      `json:"isClosed"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// NewWorkingHour creates a new WorkingHour instance.
func NewWorkingHour(
	businessID uuid.UUID,
	dayOfWeek string,
	openTime time.Time,
	closeTime time.Time,
	isClosed bool,
) (*WorkingHour, error) {
	validDays := map[string]bool{
		"Sunday": true, "Monday": true, "Tuesday": true,
		"Wednesday": true, "Thursday": true,
		"Friday": true, "Saturday": true,
	}
	if !validDays[dayOfWeek] {
		return nil, fmt.Errorf("invalid day of week: %s", dayOfWeek)
	}

	now := time.Now()
	return &WorkingHour{
		ID:         uuid.New(),
		BusinessID: businessID,
		DayOfWeek:  dayOfWeek,
		OpenTime:   openTime, // preserve local time
		CloseTime:  closeTime,
		IsClosed:   isClosed,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

func createWorkingHourCore(ctx context.Context, dbConn interface{}, wh *WorkingHour) (*WorkingHour, error) {
	logger.InfoLogger.Infof("Attempting to create working hour record for BusinessID: %s, Day: %s", wh.BusinessID, wh.DayOfWeek)
	query := `
        INSERT INTO working_hours (
            id, business_id, day_of_week, open_time, close_time,
            is_closed, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8
        ) RETURNING id` // Always use RETURNING for consistency if needed, or just rely on success/failure

	var err error
	switch conn := dbConn.(type) {
	case *pgxpool.Pool:
		var returnedID uuid.UUID
		err = conn.QueryRow(ctx, query, wh.BusinessID, wh.DayOfWeek, wh.OpenTime, wh.CloseTime, wh.IsClosed, wh.CreatedAt, wh.UpdatedAt).Scan(&returnedID)

	case pgx.Tx:
		var returnedID uuid.UUID
		err = conn.QueryRow(ctx, query, wh.BusinessID, wh.DayOfWeek, wh.OpenTime, wh.CloseTime, wh.IsClosed, wh.CreatedAt, wh.UpdatedAt).Scan(&returnedID)
		// Optionally assign returnedID if needed locally, but wh.ID is already set
	default:
		return nil, fmt.Errorf("unsupported database connection type")
	}

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to insert working hour for BusinessID: %s, Day: %s into database: %v", wh.BusinessID, wh.DayOfWeek, err)
		return nil, fmt.Errorf("failed to create working hour: %w", err)
	}
	logger.InfoLogger.Infof("Working hour with ID %s created successfully for BusinessID: %s, Day: %s", wh.ID, wh.BusinessID, wh.DayOfWeek)
	return wh, nil
}

// CreateWorkingHour inserts a new working hour slot into the database using the pool.
// It manages its own short transaction.
func CreateWorkingHour(ctx context.Context, db *pgxpool.Pool, wh *WorkingHour) (*WorkingHour, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to begin transaction for CreateWorkingHour (BusinessID: %s): %v", wh.BusinessID, err)
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil {
				logger.ErrorLogger.Errorf("Failed to rollback transaction: %v", rbErr)
			}
		}
	}()

	createdWH, err := createWorkingHourCore(ctx, tx, wh)
	if err != nil {
		// Defer will handle rollback
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("Failed to commit transaction for CreateWorkingHour (BusinessID: %s): %v", wh.BusinessID, err)
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return createdWH, nil
}

// CreateWorkingHourTx inserts a new working hour slot into the database using a transaction.
// This function now calls the core logic.
func CreateWorkingHourTx(ctx context.Context, tx pgx.Tx, wh *WorkingHour) (*WorkingHour, error) {
	return createWorkingHourCore(ctx, tx, wh)
}

// updateWorkingHourCore contains the core logic for updating a working hour.
func updateWorkingHourCore(ctx context.Context, dbConn interface{}, wh *WorkingHour) (*WorkingHour, error) {
	logger.InfoLogger.Infof("Attempting to update working hour ID: %s for BusinessID: %s, Day: %s", wh.ID, wh.BusinessID, wh.DayOfWeek)
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
	var err error

	switch conn := dbConn.(type) {
	case *pgxpool.Pool:
		err = conn.QueryRow(ctx, query,
			wh.DayOfWeek, wh.OpenTime, wh.CloseTime, wh.IsClosed, wh.UpdatedAt,
			wh.ID, wh.BusinessID).Scan(&updatedTime)
	case pgx.Tx:
		err = conn.QueryRow(ctx, query,
			wh.DayOfWeek, wh.OpenTime, wh.CloseTime, wh.IsClosed, wh.UpdatedAt,
			wh.ID, wh.BusinessID).Scan(&updatedTime)
	default:
		return nil, fmt.Errorf("unsupported database connection type")
	}

	if err != nil {
		if err == pgx.ErrNoRows {
			logger.InfoLogger.Warnf("No row found to update for working hour ID %s for business %s.", wh.ID, wh.BusinessID)
			return nil, fmt.Errorf("working hour not found or not associated with business")
		}
		logger.ErrorLogger.Errorf("Failed to update working hour ID %s for BusinessID %s in database: %v", wh.ID, wh.BusinessID, err)
		return nil, fmt.Errorf("failed to update working hour: %w", err)
	}
	wh.UpdatedAt = updatedTime // Ensure the returned updated_at is set
	logger.InfoLogger.Infof("Working hour ID %s updated successfully for BusinessID: %s, Day: %s", wh.ID, wh.BusinessID, wh.DayOfWeek)
	return wh, nil
}

// GetWorkingHourByID fetches a working hour record by its ID.
func GetWorkingHourByID(ctx context.Context, db *pgxpool.Pool, id uuid.UUID) (*WorkingHour, error) {
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

	err := db.QueryRow(ctx, query, id).Scan(
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
func GetWorkingHoursByBusinessID(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID) ([]WorkingHour, error) {
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

	rows, err := db.Query(ctx, query, businessID)
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

// GetWorkingHoursByBusinessPublicID fetches all working hours for a given business ID.
func GetWorkingHoursByBusinessPublicID(ctx context.Context, db *pgxpool.Pool, publicID string) ([]WorkingHour, error) {
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
		INNER JOIN
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

	rows, err := db.Query(ctx, query, publicID)
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
// It manages its own short transaction.
func UpdateWorkingHour(ctx context.Context, db *pgxpool.Pool, wh *WorkingHour) (*WorkingHour, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to begin transaction for UpdateWorkingHour (ID: %s): %v", wh.ID, err)
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback(ctx) // Rollback on any error from this function
		}
	}()

	updatedWH, err := updateWorkingHourCore(ctx, tx, wh)
	if err != nil {
		// Defer will handle rollback
		return nil, err
	}

	if err = tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("Failed to commit transaction for UpdateWorkingHour (ID: %s): %v", wh.ID, err)
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return updatedWH, nil
}

// UpdateWorkingHourTx updates an existing working hour record using a transaction.
// This function now calls the core logic.
func UpdateWorkingHourTx(ctx context.Context, tx pgx.Tx, wh *WorkingHour) (*WorkingHour, error) {
	return updateWorkingHourCore(ctx, tx, wh)
}

// DeleteWorkingHour deletes a working hour record by its ID and business ID.
// (No significant duplication here, logic is straightforward)
func DeleteWorkingHour(ctx context.Context, db *pgxpool.Pool, id uuid.UUID, businessID uuid.UUID) error {
	logger.InfoLogger.Infof("Attempting to delete working hour ID: %s for BusinessID: %s", id, businessID)
	query := `
        DELETE FROM working_hours
        WHERE id = $1 AND business_id = $2` // Added business_id to ensure ownership before delete
	commandTag, err := db.Exec(ctx, query, id, businessID)
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

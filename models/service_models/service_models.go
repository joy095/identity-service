// models/service.go
package service_models

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5" // Use pgx for scanning/rows operations
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger" // Adjust import path for your logger
)

// Service represents a service offered by a business.
type Service struct {
	ID              uuid.UUID `json:"id"`
	BusinessID      uuid.UUID `json:"businessId"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	DurationMinutes int       `json:"durationMinutes"`
	Price           float64   `json:"price"` // Use float64 for price for convenience, or string for exact decimal handling
	IsActive        bool      `json:"isActive"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

// NewService creates a new Service instance with default values and generated ID/timestamps.
func NewService(
	businessID uuid.UUID,
	name, description string,
	durationMinutes int,
	price float64,
) *Service {
	now := time.Now()
	return &Service{
		ID:              uuid.New(),
		BusinessID:      businessID,
		Name:            name,
		Description:     description,
		DurationMinutes: durationMinutes,
		Price:           price,
		IsActive:        true, // Services are active by default
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// CreateService inserts a new service record into the database.
func CreateService(db *pgxpool.Pool, service *Service) (*Service, error) {
	logger.InfoLogger.Info("Attempting to create service record in database")

	query := `
        INSERT INTO services (
            id, business_id, name, description, duration_minutes,
            price, is_active, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9
        )`

	_, err := db.Exec(context.Background(), query,
		service.ID,
		service.BusinessID,
		service.Name,
		service.Description,
		service.DurationMinutes,
		service.Price,
		service.IsActive,
		service.CreatedAt,
		service.UpdatedAt,
	)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to insert service into database: %v", err)
		return nil, fmt.Errorf("failed to create service: %w", err)
	}

	logger.InfoLogger.Infof("Service with ID %s created successfully", service.ID)
	return service, nil
}

// GetServiceByID fetches a service record by its ID.
func GetServiceByID(db *pgxpool.Pool, id uuid.UUID) (*Service, error) {
	logger.InfoLogger.Infof("Attempting to fetch service with ID: %s", id)

	service := &Service{}
	query := `
		SELECT
			id, business_id, name, description, duration_minutes,
			price, is_active, created_at, updated_at
		FROM
			services
		WHERE
			id = $1`

	err := db.QueryRow(context.Background(), query, id).Scan(
		&service.ID,
		&service.BusinessID,
		&service.Name,
		&service.Description,
		&service.DurationMinutes,
		&service.Price,
		&service.IsActive,
		&service.CreatedAt,
		&service.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			logger.InfoLogger.Infof("Service with ID %s not found", id)
			return nil, fmt.Errorf("service not found")
		}
		logger.ErrorLogger.Errorf("Failed to fetch service %s: %v", id, err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	logger.InfoLogger.Infof("Service with ID %s fetched successfully", id)
	return service, nil
}

// GetServicesByBusinessID fetches all services for a given business ID.
func GetServicesByBusinessID(db *pgxpool.Pool, businessID uuid.UUID) ([]Service, error) {
	logger.InfoLogger.Infof("Attempting to fetch services for Business ID: %s", businessID)

	var services []Service
	query := `
		SELECT
			id, business_id, name, description, duration_minutes,
			price, is_active, created_at, updated_at
		FROM
			services
		WHERE
			business_id = $1
		ORDER BY name ASC` // Order alphabetically for consistency

	rows, err := db.Query(context.Background(), query, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to query services for business %s: %v", businessID, err)
		return nil, fmt.Errorf("failed to fetch services: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var service Service
		err := rows.Scan(
			&service.ID,
			&service.BusinessID,
			&service.Name,
			&service.Description,
			&service.DurationMinutes,
			&service.Price,
			&service.IsActive,
			&service.CreatedAt,
			&service.UpdatedAt,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan service row for business %s: %v", businessID, err)
			return nil, fmt.Errorf("failed to scan service data: %w", err)
		}
		services = append(services, service)
	}

	if err := rows.Err(); err != nil {
		logger.ErrorLogger.Errorf("Error after scanning rows for services for business %s: %v", businessID, err)
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	logger.InfoLogger.Infof("Successfully fetched %d services for Business ID %s", len(services), businessID)
	return services, nil
}

// UpdateService updates an existing service record in the database.
func UpdateService(db *pgxpool.Pool, service *Service) (*Service, error) {
	logger.InfoLogger.Infof("Attempting to update service record with ID: %s", service.ID)

	service.UpdatedAt = time.Now() // Update timestamp on modification

	query := `
        UPDATE services
        SET
            name = $2,
            description = $3,
            duration_minutes = $4,
            price = $5,
            is_active = $6,
            updated_at = $7
        WHERE
            id = $1 AND business_id = $8 -- Include business_id for security/ownership check
        `

	res, err := db.Exec(context.Background(), query,
		service.ID,
		service.Name,
		service.Description,
		service.DurationMinutes,
		service.Price,
		service.IsActive,
		service.UpdatedAt,
		service.BusinessID, // Used in WHERE clause
	)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update service %s in database: %v", service.ID, err)
		return nil, fmt.Errorf("failed to update service: %w", err)
	}

	if res.RowsAffected() == 0 {
		return nil, fmt.Errorf("service with ID %s (for business %s) not found for update", service.ID, service.BusinessID)
	}

	logger.InfoLogger.Infof("Service with ID %s updated successfully", service.ID)
	return service, nil
}

// DeleteService deletes a service record from the database.
func DeleteService(db *pgxpool.Pool, serviceID, businessID uuid.UUID) error {
	logger.InfoLogger.Infof("Attempting to delete service record with ID: %s for Business ID: %s", serviceID, businessID)

	query := `DELETE FROM services WHERE id = $1 AND business_id = $2` // Include business_id for ownership check

	res, err := db.Exec(context.Background(), query, serviceID, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete service %s for business %s from database: %v", serviceID, businessID, err)
		return fmt.Errorf("failed to delete service: %w", err)
	}

	if res.RowsAffected() == 0 {
		return fmt.Errorf("service with ID %s (for business %s) not found for deletion", serviceID, businessID)
	}

	logger.InfoLogger.Infof("Service with ID %s deleted successfully", serviceID)
	return nil
}

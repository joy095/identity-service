// models/service_models
package service_models

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5" // Use pgx for scanning/rows operations
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger" // Adjust import path for your logger
)

// Service represents a service offered by a business.
type Service struct {
	ID          uuid.UUID   `json:"id"`
	BusinessID  uuid.UUID   `json:"businessId"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Duration    int         `json:"duration"`
	Price       int64       `json:"price"` // Use int64 for price for convenience, or string for exact decimal handling
	ImageID     pgtype.UUID `json:"imageId"`
	IsActive    bool        `json:"isActive"`
	CreatedAt   time.Time   `json:"createdAt"`
	UpdatedAt   time.Time   `json:"updatedAt"`
	ObjectName  *string     `json:"objectName,omitempty"`
}

// NewService creates a new Service instance with default values and generated ID/timestamps.
func NewService(
	businessID uuid.UUID,
	name, description string,
	duration int,
	price int64,
) *Service {
	now := time.Now()
	return &Service{
		ID:          uuid.New(),
		BusinessID:  businessID,
		Name:        name,
		Description: description,
		Duration:    duration,
		Price:       price,
		ImageID:     pgtype.UUID{Valid: false}, // Explicitly initialize as invalid/NULL
		IsActive:    true,                      // Services are active by default
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// NewServiceWithImage creates a new Service instance with an image ID.
func NewServiceWithImage(
	businessID uuid.UUID,
	name, description string,
	duration int,
	price int64,
	imageID uuid.UUID,
) *Service {
	now := time.Now()
	return &Service{
		ID:          uuid.New(),
		BusinessID:  businessID,
		Name:        name,
		Description: description,
		Duration:    duration,
		Price:       price,
		ImageID:     pgtype.UUID{Bytes: imageID, Valid: true}, // Set valid image ID
		IsActive:    true,                                     // Services are active by default
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// CreateServiceModel inserts a new service record into the database.
func CreateServiceModel(ctx context.Context, db *pgxpool.Pool, service *Service) (*Service, error) {
	logger.InfoLogger.Info("Attempting to create service record in database")

	// Log the ImageID details for debugging
	if service.ImageID.Valid {
		logger.InfoLogger.Infof("Creating service with Image ID: %s", service.ImageID.Bytes)
	} else {
		logger.InfoLogger.Info("Creating service without Image ID (NULL)")
	}

	query := `
        INSERT INTO services (
            id, business_id, name, description, duration_minutes,
            price, image_id, is_active, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
        )`

	_, err := db.Exec(ctx, query,
		service.ID,
		service.BusinessID,
		service.Name,
		service.Description,
		service.Duration,
		service.Price,
		service.ImageID,
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

// GetServiceByIDModel fetches a service record by its ID.
func GetServiceByIDModel(ctx context.Context, db *pgxpool.Pool, id uuid.UUID) (*Service, error) {
	logger.InfoLogger.Infof("Attempting to fetch service with ID: %s", id)

	service := &Service{}
	var imageObjectName pgtype.Text // Declare a variable to hold the object_name

	query := `
		SELECT
			s.id,
			s.business_id,
			s.name,
			s.description,
			s.duration_minutes,
			s.price,
			s.is_active,
			s.image_id,
			s.created_at,
			s.updated_at,
			i.object_name
		FROM
			services AS s
		LEFT JOIN
			images AS i ON s.image_id = i.id
		WHERE
			s.id = $1;
		`

	// Make sure the order of arguments in Scan matches the order of columns in SELECT
	err := db.QueryRow(ctx, query, id).Scan(
		&service.ID,
		&service.BusinessID,
		&service.Name,
		&service.Description,
		&service.Duration,
		&service.Price,
		&service.IsActive,
		&service.ImageID, // Changed to pgtype.UUID to handle NULL
		&service.CreatedAt,
		&service.UpdatedAt,
		&imageObjectName, // Scan the object_name into the new variable
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			logger.InfoLogger.Infof("Service with ID %s not found", id)
			return nil, fmt.Errorf("service not found")
		}
		logger.ErrorLogger.Errorf("Failed to fetch service %s: %v", id, err)
		return nil, fmt.Errorf("database error: %w", err)
	}
	// Assign the object_name to the service if it's valid
	if imageObjectName.Valid {
		service.ObjectName = &imageObjectName.String
	}
	logger.InfoLogger.Infof("Service with ID %s fetched successfully", id)
	return service, nil
}

// IsServiceBusiness checks if a service exists for the given businessId
func IsServiceBusiness(ctx context.Context, db *pgxpool.Pool, businessId uuid.UUID) (bool, error) {
	logger.InfoLogger.Infof("Checking if service exists for businessId: %s", businessId)

	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM services WHERE business_id = $1)`

	err := db.QueryRow(ctx, query, businessId).Scan(&exists)
	if err != nil {
		logger.ErrorLogger.Errorf("Database error while checking service existence for businessId %s: %v", businessId, err)
		return false, fmt.Errorf("database error: %w", err)
	}

	logger.InfoLogger.Infof("Service exists for businessId %s: %t", businessId, exists)
	return exists, nil
}

// GetAllServicesModel fetches all services for a given business ID.
func GetAllServicesModel(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID) ([]Service, error) {
	const operation = "GetAllServicesModel"
	logger.InfoLogger.Printf("%s: Attempting to fetch services for business ID: %s", operation, businessID)

	query := `
		SELECT
			s.id,
			s.business_id,
			s.name,
			s.description,
			s.duration_minutes,
			s.price,
			s.image_id,
			s.is_active,
			s.created_at,
			s.updated_at,
			i.object_name
		FROM
			services AS s
		LEFT JOIN images AS i ON s.image_id = i.id
		WHERE
			s.business_id = $1
		ORDER BY s.name ASC
	`

	rows, err := db.Query(ctx, query, businessID)
	if err != nil {
		logger.ErrorLogger.Printf("%s: Failed to execute query: %v", operation, err)
		return nil, fmt.Errorf("%s: failed to fetch services: %w", operation, err)
	}
	defer rows.Close()

	var services []Service
	for rows.Next() {
		var service Service
		var (
			imageID    pgtype.UUID
			objectName pgtype.Text
		)

		if err := rows.Scan(
			&service.ID,
			&service.BusinessID,
			&service.Name,
			&service.Description,
			&service.Duration,
			&service.Price,
			&imageID,
			&service.IsActive,
			&service.CreatedAt,
			&service.UpdatedAt,
			&objectName,
		); err != nil {
			logger.ErrorLogger.Printf("%s: Failed to scan row: %v", operation, err)
			return nil, fmt.Errorf("%s: failed to scan service row: %w", operation, err)
		}

		service.ImageID = imageID
		if objectName.Valid {
			service.ObjectName = &objectName.String
		}

		services = append(services, service)
	}

	if err := rows.Err(); err != nil {
		logger.ErrorLogger.Printf("%s: Row iteration error: %v", operation, err)
		return nil, fmt.Errorf("%s: error during row iteration: %w", operation, err)
	}

	logger.InfoLogger.Printf("%s: Successfully fetched %d services for business ID: %s",
		operation, len(services), businessID)
	return services, nil
}

// Service represents a service record (you can extend this struct)
type BusinessID struct {
	BusinessID uuid.UUID `json:"business_id"`
}

// GetBusinessIdByService fetches the business_id for a given service ID
func GetBusinessIdByService(ctx context.Context, db *pgxpool.Pool, serviceID uuid.UUID) (*BusinessID, error) {
	logger.InfoLogger.Infof("Attempting to fetch business with service ID: %s", serviceID)

	query := `
		SELECT business_id
		FROM services
		WHERE id = $1
	`

	// Single row query (since you only expect one business_id per service_id)
	row := db.QueryRow(ctx, query, serviceID)

	var bus BusinessID
	if err := row.Scan(&bus.BusinessID); err != nil {
		if err == pgx.ErrNoRows {
			logger.InfoLogger.Infof("No business found for service ID: %s", serviceID)
			return nil, nil // not found
		}
		logger.ErrorLogger.Errorf("Failed to scan business for service %s: %v", serviceID, err)
		return nil, fmt.Errorf("failed to fetch business_id: %w", err)
	}

	logger.InfoLogger.Infof("Successfully fetched business_id %s for service ID: %s", bus.BusinessID, serviceID)
	return &bus, nil
}

// GetServicesByBusinessID fetches all services for a given business ID.
func GetServicesByBusinessID(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID) ([]Service, error) {
	logger.InfoLogger.Infof("Attempting to fetch services for Business ID: %s", businessID)

	var services []Service
	query := `
		SELECT
			id, business_id, name, description, duration_minutes,
			price, image_id, is_active, created_at, updated_at
		FROM
			services
		WHERE
			business_id = $1
		ORDER BY name ASC` // Order alphabetically for consistency

	rows, err := db.Query(ctx, query, businessID)
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
			&service.Duration,
			&service.Price,
			&service.ImageID, // pgtype.UUID handles NULL automatically
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

// UpdateServiceModel updates an existing service record in the database.
func UpdateServiceModel(ctx context.Context, db *pgxpool.Pool, service *Service) (*Service, error) {
	logger.InfoLogger.Infof("Attempting to update service record with ID: %s", service.ID)

	query := `
		UPDATE services
		SET
			name = $2,
			description = $3,
			duration_minutes = $4,
			price = $5,
			image_id = $6,
			is_active = $7,
			updated_at = NOW()
		WHERE
			id = $1 AND business_id = $8
			RETURNING updated_at
		`

	var updatedAt time.Time
	err := db.QueryRow(ctx, query,
		service.ID,
		service.Name,
		service.Description,
		service.Duration,
		service.Price,
		service.ImageID,
		service.IsActive,
		service.BusinessID,
	).Scan(&updatedAt)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update service %s in database: %v", service.ID, err)
		return nil, fmt.Errorf("failed to update service: %w", err)
	}

	// Update the timestamp to reflect the database change
	service.UpdatedAt = updatedAt

	logger.InfoLogger.Infof("Service with ID %s updated successfully", service.ID)
	return service, nil
}

// DeleteServiceByIDModel deletes a service record from the database.
func DeleteServiceByIDModel(ctx context.Context, db *pgxpool.Pool, serviceID, businessID uuid.UUID) error {
	logger.InfoLogger.Infof("Attempting to delete service record with ID: %s for Business ID: %s", serviceID, businessID)

	query := `DELETE FROM services WHERE id = $1 AND business_id = $2` // Include business_id for ownership check

	res, err := db.Exec(ctx, query, serviceID, businessID)
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

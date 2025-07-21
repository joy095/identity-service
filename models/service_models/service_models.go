// models/service_models
package service_models

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5" // Use pgx for scanning/rows operations
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger" // Adjust import path for your logger
)

// Service represents a service offered by a business.
type Service struct {
	ID              uuid.UUID   `json:"id"`
	BusinessID      uuid.UUID   `json:"businessId"`
	Name            string      `json:"name"`
	Description     string      `json:"description,omitempty"`
	DurationMinutes int         `json:"durationMinutes"`
	Price           int64       `json:"price"` // Use int64 for price for convenience, or string for exact decimal handling
	ImageID         pgtype.UUID `json:"imageId"`
	IsActive        bool        `json:"isActive"`
	CreatedAt       time.Time   `json:"createdAt"`
	UpdatedAt       time.Time   `json:"updatedAt"`
	ObjectName      *string     `json:"object_name,omitempty"`
}

// NewService creates a new Service instance with default values and generated ID/timestamps.
func NewService(
	businessID uuid.UUID,
	name, description string,
	durationMinutes int,
	price int64,
) *Service {
	now := time.Now()
	return &Service{
		ID:              uuid.New(),
		BusinessID:      businessID,
		Name:            name,
		Description:     description,
		DurationMinutes: durationMinutes,
		Price:           price,
		ImageID:         pgtype.UUID{Valid: false}, // Explicitly initialize as invalid/NULL
		IsActive:        true,                      // Services are active by default
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// NewServiceWithImage creates a new Service instance with an image ID.
func NewServiceWithImage(
	businessID uuid.UUID,
	name, description string,
	durationMinutes int,
	price int64,
	imageID uuid.UUID,
) *Service {
	now := time.Now()
	return &Service{
		ID:              uuid.New(),
		BusinessID:      businessID,
		Name:            name,
		Description:     description,
		DurationMinutes: durationMinutes,
		Price:           price,
		ImageID:         pgtype.UUID{Bytes: imageID, Valid: true}, // Set valid image ID
		IsActive:        true,                                     // Services are active by default
		CreatedAt:       now,
		UpdatedAt:       now,
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
		service.DurationMinutes,
		service.Price,
		service.ImageID,
		service.IsActive,
		service.CreatedAt,
		service.UpdatedAt,
	)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to insert service into database: %v", err)

		// Check if it's a NOT NULL constraint violation
		if strings.Contains(err.Error(), "null value in column \"image_id\"") {
			return nil, fmt.Errorf("image is required for service creation")
		}

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
		&service.DurationMinutes,
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

func GetAllServicesModel(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID) ([]Service, error) {
	logger.InfoLogger.Info("Attempting to fetch all services for business ID: " + businessID.String())

	cloudflareImageBaseURL := os.Getenv("CLOUDFLARE_IMAGE_URL")

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
			CASE
				WHEN s.image_id IS NOT NULL THEN i.object_name
				ELSE NULL
			END AS object_name
		FROM
			services AS s
		LEFT JOIN
			images AS i ON s.image_id = i.id
		WHERE
			s.business_id = $1
		ORDER BY s.name ASC`

	rows, err := db.Query(context.Background(), query, businessID)
	if err != nil {
		logger.ErrorLogger.Error("Failed to execute query to fetch services: " + err.Error())
		return nil, fmt.Errorf("failed to fetch services from database: %w", err)
	}
	defer rows.Close()

	var services []Service
	for rows.Next() {
		var service Service
		var imageID pgtype.UUID    // For scanning nullable UUID
		var objectName pgtype.Text // For scanning nullable string

		err := rows.Scan(
			&service.ID,
			&service.BusinessID,
			&service.Name,
			&service.Description,
			&service.DurationMinutes,
			&service.Price,
			&imageID,
			&service.IsActive,
			&service.CreatedAt,
			&service.UpdatedAt,
			&objectName, // Scan into pgtype.Text
		)
		if err != nil {
			logger.ErrorLogger.Error("Failed to scan service row: " + err.Error())
			return nil, fmt.Errorf("failed to scan service row: %w", err)
		}

		// Handle nullable ImageID
		if imageID.Valid {
			service.ImageID = pgtype.UUID{Bytes: imageID.Bytes, Valid: true}
		} else {
			service.ImageID = pgtype.UUID{Valid: false}
		}

		// Handle nullable ObjectName and construct full URL
		if objectName.Valid {
			fullPath := cloudflareImageBaseURL + "/" + objectName.String
			service.ObjectName = &fullPath
		} else {
			// If object_name is NULL, set to an empty string pointer or nil, based on your preference
			// Setting to nil is generally cleaner if it represents "no image"
			service.ObjectName = nil
			// Or if you prefer an empty string:
			// emptyStr := ""
			// service.ObjectName = &emptyStr
		}

		services = append(services, service)
	}

	if err = rows.Err(); err != nil {
		logger.ErrorLogger.Error("Error after iterating through service rows: " + err.Error())
		return nil, fmt.Errorf("error during service row iteration: %w", err)
	}

	logger.InfoLogger.Info("Successfully fetched services for business ID: " + businessID.String())
	return services, nil
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

	service.UpdatedAt = time.Now() // Update timestamp on modification

	query := `
		UPDATE services
		SET
			name = $2,
			description = $3,
			duration_minutes = $4,
			price = $5,
			image_id = $6,
			is_active = $7,
			updated_at = $8
		WHERE
			id = $1 AND business_id = $9
		`

	res, err := db.Exec(ctx, query,
		service.ID,
		service.Name,
		service.Description,
		service.DurationMinutes,
		service.Price,
		service.ImageID,
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

// DeleteServiceByIDModel deletes a service record from the database.
func DeleteServiceByIDModel(ctx context.Context, db *pgxpool.Pool, serviceID, businessID uuid.UUID) error {
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

package business_models

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger" // Assuming this logger package is available
)

// User Model (Commented out as it's not directly used in Business model logic here, but good to keep for context)
// type User struct {
// 	// ... user fields
// }

// Location represents geographical coordinates
type Location struct {
	// Latitude should be between -90 and +90
	Latitude float64 `json:"latitude" binding:"required,min=-90,max=90"`
	// Longitude should be between -180 and +180
	Longitude float64 `json:"longitude" binding:"required,min=-180,max=180"`
}

// Business represents a business entity in your system.
type Business struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`     // Business legal name or trading name
	Category   string    `json:"category"` // e.g., "Retail", "Services", "Technology"
	Address    string    `json:"address"`  // Street address
	City       string    `json:"city"`
	State      string    `json:"state"`
	Country    string    `json:"country"`
	PostalCode string    `json:"postalCode"`
	TaxID      string    `json:"taxId,omitempty"` // Tax identification number (e.g., EIN, GSTIN)
	About      string    `json:"about,omitempty"` // Short description of the business
	Location   Location  `json:"location"`        // Embedded Location struct
	CreatedAt  time.Time `json:"createdAt"`       // Timestamp of creation
	UpdatedAt  time.Time `json:"updatedAt"`       // Timestamp of last update
	IsActive   bool      `json:"isActive"`        // Status of the business
	OwnerID    uuid.UUID `json:"ownerId"`         // ID of the user who owns this business
}

// NewBusiness creates a new Business struct with a generated ID and initial timestamps.
// This is a helper to prepare the struct before insertion.
func NewBusiness(
	name, category, address, city, state, country, postalCode, taxID,
	about string, lat, long float64, ownerUserID uuid.UUID) (*Business, error) {

	id, err := uuid.NewV7() // Generate new UUID
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %w", err)
	}
	now := time.Now()
	return &Business{
		ID:         id,
		Name:       name,
		Category:   category,
		Address:    address,
		City:       city,
		State:      state,
		Country:    country,
		PostalCode: postalCode,
		TaxID:      taxID,
		About:      about,
		Location:   Location{Latitude: lat, Longitude: long},
		CreatedAt:  now,
		UpdatedAt:  now,
		IsActive:   true, // Default to active
		OwnerID:    ownerUserID,
	}, nil
}

// CreateBusiness inserts a new business record into the database.
// It returns the created Business object with its ID and any error.
func CreateBusiness(ctx context.Context, db *pgxpool.Pool, business *Business) (*Business, error) {
	logger.InfoLogger.Info("Attempting to create business record in database")

	// Ensure ID is set (if not already set by NewBusiness)
	if business.ID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("failed to generate UUID: %w", err)
		}
		business.ID = id
	}
	// Set creation and update timestamps
	now := time.Now()

	business.CreatedAt = now
	business.UpdatedAt = now
	business.IsActive = true // Ensure active status if not explicitly set

	query := `
		INSERT INTO businesses (
			id, name, category, address, city, state, country,
			postal_code, tax_id, about,
			location_latitude, location_longitude,
			created_at, updated_at, is_active, owner_id
		)
		VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
			$14, $15, $16
		)`

	_, err := db.Exec(ctx, query,
		business.ID,
		business.Name,
		business.Category,
		business.Address,
		business.City,
		business.State,
		business.Country,
		business.PostalCode,
		business.TaxID,
		business.About,
		business.Location.Latitude,  // This will go into location_latitude
		business.Location.Longitude, // This will go into location_longitude
		business.CreatedAt,
		business.UpdatedAt,
		business.IsActive,
		business.OwnerID,
	)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to insert business into database: %v", err)
		return nil, fmt.Errorf("failed to create business: %w", err)
	}

	logger.InfoLogger.Infof("Business with ID %s created successfully", business.ID)
	return business, nil
}

// GetBusinessByID fetches a business record by its ID.
func GetBusinessByID(db *pgxpool.Pool, id uuid.UUID) (*Business, error) {
	logger.InfoLogger.Infof("Attempting to fetch business with ID: %s", id)

	business := &Business{}
	query := `
		SELECT
			id, name, category, address, city, state, country,
			postal_code, tax_id, about, location_latitude, location_longitude,
			created_at, updated_at, is_active, owner_id
		FROM
			businesses
		WHERE
			id = $1`

	err := db.QueryRow(context.Background(), query, id).Scan(
		&business.ID,
		&business.Name,
		&business.Category,
		&business.Address,
		&business.City,
		&business.State,
		&business.Country,
		&business.PostalCode,
		&business.TaxID,
		&business.About,
		&business.Location.Latitude,
		&business.Location.Longitude,
		&business.CreatedAt,
		&business.UpdatedAt,
		&business.IsActive,
		&business.OwnerID,
	)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s: %v", id, err)
		return nil, fmt.Errorf("business not found or database error: %w", err)
	}

	logger.InfoLogger.Infof("Business with ID %s fetched successfully", id)
	return business, nil
}

// UpdateBusiness updates an existing business record in the database.
func UpdateBusiness(db *pgxpool.Pool, business *Business) (*Business, error) {
	logger.InfoLogger.Infof("Attempting to update business record with ID: %s", business.ID)

	business.UpdatedAt = time.Now()

	query := `
		UPDATE businesses
		SET
			name = $2,
			category = $3,
			address = $4,
			city = $5,
			state = $6,
			country = $7,
			postal_code = $8,
			tax_id = $9,
			about = $10,
			location_latitude = $11,
			location_longitude = $12,
			updated_at = $13,
			is_active = $14
		WHERE
			id = $1
		RETURNING id`

	var id uuid.UUID
	err := db.QueryRow(context.Background(), query,
		business.ID,
		business.Name,
		business.Category,
		business.Address,
		business.City,
		business.State,
		business.Country,
		business.PostalCode,
		business.TaxID,
		business.About,
		business.Location.Latitude,
		business.Location.Longitude,
		business.UpdatedAt,
		business.IsActive,
	).Scan(&id)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update business %s in database: %v", business.ID, err)
		return nil, fmt.Errorf("failed to update business: %w", err)
	}

	logger.InfoLogger.Infof("Business with ID %s updated successfully", business.ID)
	return business, nil
}

// DeleteBusiness deletes a business record from the database by its ID.
func DeleteBusiness(ctx context.Context, db *pgxpool.Pool, id uuid.UUID) error {
	logger.InfoLogger.Infof("Attempting to delete business record with ID: %s", id)

	query := `DELETE FROM businesses WHERE id = $1`

	res, err := db.Exec(ctx, query, id)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete business %s from database: %v", id, err)
		return fmt.Errorf("failed to delete business: %w", err)
	}

	if res.RowsAffected() == 0 {
		return fmt.Errorf("business with ID %s not found for deletion", id)
	}

	logger.InfoLogger.Infof("Business with ID %s deleted successfully", id)
	return nil
}

// GetAllBusinesses fetches all business records from the database, with optional pagination.
// If limit is 0, no limit is applied. If offset is 0, no offset is applied.
func GetAllBusinesses(ctx context.Context, db *pgxpool.Pool, limit, offset int) ([]*Business, error) {
	logger.InfoLogger.Info("Attempting to fetch all businesses from database")

	businesses := []*Business{}

	// Build query with placeholders
	queryBuilder := `
		SELECT
			id, name, category, address, city, state, country,
			postal_code, tax_id, about, location_latitude, location_longitude,
			created_at, updated_at, is_active, owner_id
		FROM
			businesses
		ORDER BY
			created_at DESC`

	args := []interface{}{}
	argCount := 0

	if limit > 0 && offset > 0 {
		queryBuilder += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argCount+1, argCount+2)
		args = append(args, limit, offset)
	} else if limit > 0 {
		queryBuilder += fmt.Sprintf(" LIMIT $%d", argCount+1)
		args = append(args, limit)
	} else if offset > 0 {
		queryBuilder += fmt.Sprintf(" OFFSET $%d", argCount+1)
		args = append(args, offset)
	}

	rows, err := db.Query(ctx, queryBuilder, args...)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to query all businesses: %v", err)
		return nil, fmt.Errorf("failed to retrieve all businesses: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		business := &Business{}
		err := rows.Scan(
			&business.ID,
			&business.Name,
			&business.Category,
			&business.Address,
			&business.City,
			&business.State,
			&business.Country,
			&business.PostalCode,
			&business.TaxID,
			&business.About,
			&business.Location.Latitude,
			&business.Location.Longitude,
			&business.CreatedAt,
			&business.UpdatedAt,
			&business.IsActive,
			&business.OwnerID,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan business row: %v", err)
			return nil, fmt.Errorf("failed to scan business data: %w", err)
		}
		businesses = append(businesses, business)
	}

	if err = rows.Err(); err != nil {
		logger.ErrorLogger.Errorf("Error after iterating rows for all businesses: %v", err)
		return nil, fmt.Errorf("error during business row iteration: %w", err)
	}

	logger.InfoLogger.Infof("Fetched %d businesses successfully", len(businesses))
	return businesses, nil
}

// GetBusinessesByOwnerID fetches all business records owned by a specific user ID.
func GetBusinessesByOwnerID(ctx context.Context, db *pgxpool.Pool, ownerID uuid.UUID) ([]*Business, error) {
	logger.InfoLogger.Infof("Attempting to fetch businesses for owner ID: %s", ownerID)

	businesses := []*Business{}
	query := `
		SELECT
			id, name, category, address, city, state, country,
			postal_code, tax_id, about, location_latitude, location_longitude,
			created_at, updated_at, is_active, owner_id
		FROM
			businesses
		WHERE
			owner_id = $1
		ORDER BY
			created_at DESC` // Order by creation time, newest first

	rows, err := db.Query(ctx, query, ownerID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to query businesses for owner %s: %v", ownerID, err)
		return nil, fmt.Errorf("failed to retrieve businesses by owner ID: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		business := &Business{}
		err := rows.Scan(
			&business.ID,
			&business.Name,
			&business.Category,
			&business.Address,
			&business.City,
			&business.State,
			&business.Country,
			&business.PostalCode,
			&business.TaxID,
			&business.About,
			&business.Location.Latitude,
			&business.Location.Longitude,
			&business.CreatedAt,
			&business.UpdatedAt,
			&business.IsActive,
			&business.OwnerID,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan business row for owner %s: %v", ownerID, err)
			return nil, fmt.Errorf("failed to scan business data for owner: %w", err)
		}
		businesses = append(businesses, business)
	}

	if err = rows.Err(); err != nil {
		logger.ErrorLogger.Errorf("Error after iterating rows for businesses by owner %s: %v", ownerID, err)
		return nil, fmt.Errorf("error during business row iteration by owner: %w", err)
	}

	logger.InfoLogger.Infof("Fetched %d businesses for owner ID %s successfully", len(businesses), ownerID)
	return businesses, nil
}

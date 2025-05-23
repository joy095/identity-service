package models

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
)

// User Model
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
	CreatedAt  string    `json:"createdAt"`       // Timestamp of creation
	UpdatedAt  string    `json:"updatedAt"`       // Timestamp of last update
	IsActive   bool      `json:"isActive"`        // Status of the business
	OwnerID    uuid.UUID `json:"ownerId"`         // ID of the user who owns this business
}

// NewBusiness creates a new Business struct with a generated ID and initial timestamps.
// This is a helper to prepare the struct before insertion.
func NewBusiness(
	name, category, address, city, state, country, postalCode, taxID,
	about string, lat, long float64, ownerUserID uuid.UUID) *Business {

	id, err := uuid.NewV7() // Generate new UUID
	if err != nil {
		return nil // In case of error, return nil
	}
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
		CreatedAt:  time.Now().Format(time.RFC3339), // Store as string for simplicity, or use time.Time
		UpdatedAt:  time.Now().Format(time.RFC3339),
		IsActive:   true, // Default to active
		OwnerID:    ownerUserID,
	}
}

// CreateBusiness inserts a new business record into the database.
// It returns the created Business object with its ID and any error.
func CreateBusiness(db *pgxpool.Pool, business *Business) (*Business, error) {
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
	now := time.Now().Format(time.RFC3339) // Or just time.Now() if using time.Time type
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
        ) RETURNING id`

	_, err := db.Exec(context.Background(), query,
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

	business.UpdatedAt = time.Now().Format(time.RFC3339) // Update timestamp

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
            location_latitude = $11,  -- <<< Update these columns
            location_longitude = $12, -- <<< Update these columns
            updated_at = $13,
            is_active = $14
        WHERE
            id = $1
        RETURNING id`

	res, err := db.Exec(context.Background(), query,
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
		business.Location.Latitude,  // Value for location_latitude
		business.Location.Longitude, // Value for location_longitude
		business.UpdatedAt,
		business.IsActive,
	)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update business %s in database: %v", business.ID, err)
		return nil, fmt.Errorf("failed to update business: %w", err)
	}

	if res.RowsAffected() == 0 {
		return nil, fmt.Errorf("business with ID %s not found for update", business.ID)
	}

	logger.InfoLogger.Infof("Business with ID %s updated successfully", business.ID)
	return business, nil
}

// DeleteBusiness deletes a business record from the database by its ID.
func DeleteBusiness(db *pgxpool.Pool, id uuid.UUID) error {
	logger.InfoLogger.Infof("Attempting to delete business record with ID: %s", id)

	query := `DELETE FROM businesses WHERE id = $1`

	res, err := db.Exec(context.Background(), query, id)
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

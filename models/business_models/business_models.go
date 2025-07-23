package business_models

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/business_image_models"
)

// Location represents geographical coordinates
type Location struct {
	Latitude  float64 `json:"latitude" binding:"min=-90,max=90"`
	Longitude float64 `json:"longitude" binding:"min=-180,max=180"`
}

// Business represents a business entity in your system.
type Business struct {
	ID         uuid.UUID                              `json:"id"`
	Name       string                                 `json:"name"`
	Category   string                                 `json:"category"`
	Address    string                                 `json:"address"`
	City       string                                 `json:"city,omitempty"`
	State      string                                 `json:"state,omitempty"`
	Country    string                                 `json:"country"`
	PostalCode string                                 `json:"postalCode,omitempty"`
	TaxID      string                                 `json:"taxId,omitempty"`
	About      string                                 `json:"about,omitempty"`
	Latitude   float64                                `form:"latitude,omitempty"`
	Longitude  float64                                `form:"longitude,omitempty"`
	CreatedAt  time.Time                              `json:"createdAt"`
	UpdatedAt  time.Time                              `json:"updatedAt"`
	IsActive   bool                                   `json:"isActive"`
	OwnerID    uuid.UUID                              `json:"ownerId"`
	PublicId   *string                                `json:"publicId"`
	Images     []*business_image_models.BusinessImage `json:"images,omitempty"`
}

// NewBusiness creates a new Business struct with a generated ID and initial timestamps.
func NewBusiness(
	name, category, address, city, state, country, postalCode, taxID,
	about, publicId string, lat, long float64, ownerUserID uuid.UUID) (*Business, error) {

	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %w", err)
	}

	now := time.Now()
	var publicIdPtr *string
	if publicId != "" {
		publicIdPtr = &publicId
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
		Latitude:   lat,
		Longitude:  long,
		CreatedAt:  now,
		UpdatedAt:  now,
		IsActive:   false,
		OwnerID:    ownerUserID,
		PublicId:   publicIdPtr,
	}, nil
}

// CreateBusiness inserts a new business record into the database.
func CreateBusiness(ctx context.Context, db *pgxpool.Pool, business *Business) (*Business, error) {
	query := `
        INSERT INTO businesses (id, name, category, address, city, state, country, postal_code, tax_id, about, location_latitude, location_longitude, created_at, updated_at, is_active, owner_id, public_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
        RETURNING id, name, category, address, city, state, country, postal_code, tax_id, about, location_latitude, location_longitude, created_at, updated_at, is_active, owner_id, public_id
    `
	logger.InfoLogger.Infof("Executing query to create business: %s", business.Name)

	err := db.QueryRow(ctx, query,
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
		business.Latitude,
		business.Longitude,
		business.CreatedAt,
		business.UpdatedAt,
		business.IsActive,
		business.OwnerID,
		business.PublicId,
	).Scan(
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
		&business.Latitude,
		&business.Longitude,
		&business.CreatedAt,
		&business.UpdatedAt,
		&business.IsActive,
		&business.OwnerID,
		&business.PublicId,
	)

	if err != nil {
		logger.ErrorLogger.Errorf("Error creating business in DB: %v", err)
		return nil, err
	}

	logger.InfoLogger.Infof("Successfully created business %s in DB", business.ID)
	return business, nil
}

// GetBusinessByID fetches a business record by its UUID ID (internal use).
func GetBusinessByID(ctx context.Context, db *pgxpool.Pool, id uuid.UUID) (*Business, error) {
	logger.InfoLogger.Infof("Attempting to fetch business with ID: %s", id)

	business := &Business{}
	query := `SELECT
	            b.id,
	            b.name,
	            b.category,
	            b.address,
	            b.city,
	            b.state,
	            b.country,
	            b.postal_code,
	            b.tax_id,
	            b.about,
	            b.location_latitude,
	            b.location_longitude,
	            b.created_at,
	            b.updated_at,
	            b.is_active,
	            b.owner_id,
				b.public_id
			FROM
				businesses AS b
			WHERE
				b.id = $1;
	`

	err := db.QueryRow(ctx, query, id).Scan(
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
		&business.Latitude,
		&business.Longitude,
		&business.CreatedAt,
		&business.UpdatedAt,
		&business.IsActive,
		&business.OwnerID,
		&business.PublicId,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			logger.InfoLogger.Infof("Business with ID %s not found", id)
			return nil, fmt.Errorf("business not found")
		}
		logger.ErrorLogger.Errorf("Failed to fetch business %s: %v", id, err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	logger.InfoLogger.Infof("Business with ID %s fetched successfully", id)
	return business, nil
}

// GetBusinessByPublicId fetches a business record by its public ID (external use).
func GetBusinessIdOnly(ctx context.Context, db *pgxpool.Pool, publicId string) (uuid.UUID, error) {
	logger.InfoLogger.Infof("Attempting to fetch business with public ID: %s", publicId)

	var businessID uuid.UUID
	query := `SELECT id FROM businesses WHERE public_id = $1`

	err := db.QueryRow(ctx, query, publicId).Scan(&businessID)
	if err != nil {
		if err == pgx.ErrNoRows {
			logger.InfoLogger.Infof("Business with public ID %s not found", publicId)
			return uuid.Nil, fmt.Errorf("business not found") // Return uuid.Nil for not found
		}
		logger.ErrorLogger.Errorf("Failed to fetch business with public ID %s: %v", publicId, err)
		return uuid.Nil, fmt.Errorf("database error fetching business: %w", err) // Generic database error
	}

	logger.InfoLogger.Infof("Successfully fetched business ID: %s for public ID: %s", businessID, publicId)
	return businessID, nil
}

// GetBusinessByPublicId fetches a business record by its public ID (client-facing).
func GetBusinessByPublicId(ctx context.Context, db *pgxpool.Pool, publicId string) (*Business, error) {
	logger.InfoLogger.Infof("Attempting to fetch business with public ID: %s", publicId)

	business := &Business{}
	query := `SELECT
				b.id,
				b.name,
				b.category,
				b.address,
				b.city,
				b.state,
				b.country,
				b.postal_code,
				b.tax_id,
				b.about,
				b.location_latitude,
				b.location_longitude,
				b.created_at,
				b.updated_at,
				b.is_active,
				b.owner_id,
				b.public_id
			FROM
				businesses AS b
			WHERE
				b.public_id = $1;
	`

	err := db.QueryRow(ctx, query, publicId).Scan(
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
		&business.Latitude,
		&business.Longitude,
		&business.CreatedAt,
		&business.UpdatedAt,
		&business.IsActive,
		&business.OwnerID,
		&business.PublicId,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			logger.InfoLogger.Infof("Business with public ID %s not found", publicId)
			return nil, fmt.Errorf("business not found") // More specific error for not found
		}
		logger.ErrorLogger.Errorf("Failed to fetch business with public ID %s: %v", publicId, err)
		return nil, fmt.Errorf("database error fetching business: %w", err) // Generic database error
	}

	// Now, fetch the associated images for this business
	images, err := business_image_models.GetImagesByBusinessID(ctx, db, business.ID)
	if err != nil {
		// Log the error but don't necessarily return it as a fatal error for GetBusinessByPublicId.
		// It's often acceptable to return a business even if its images can't be loaded,
		// especially if images are not always mandatory.
		logger.ErrorLogger.Errorf("Failed to retrieve images for business %s (ID: %s): %v", publicId, business.ID, err)
		// Initialize Images to an empty slice to avoid nil pointer dereferences
		business.Images = []*business_image_models.BusinessImage{}
	} else {
		business.Images = images
	}

	logger.InfoLogger.Infof("Business with public ID %s fetched successfully (including images)", publicId)
	return business, nil
}

// GetNotActiveBusinessByUserModel fetches all inactive businesses for a given user ID.
func GetNotActiveBusinessByUserModel(ctx context.Context, db *pgxpool.Pool, userID uuid.UUID) ([]*Business, error) {
	logger.InfoLogger.Infof("Attempting to fetch all inactive businesses for user ID: %s", userID)

	var businesses []*Business
	query := `
        SELECT
            b.id,
            b.name,
            b.category,
            b.address,
            b.city,
            b.state,
            b.country,
            b.postal_code,
            b.tax_id,
            b.about,
            b.location_latitude,
            b.location_longitude,
            b.created_at,
            b.updated_at,
            b.is_active,
            b.owner_id,
            b.public_id
        FROM
            businesses AS b
        WHERE
            b.owner_id = $1 AND b.is_active = false;
    `

	rows, err := db.Query(ctx, query, userID)
	if err != nil {
		logger.ErrorLogger.Errorf("Database error querying inactive businesses for user ID %s: %v", userID, err)
		return nil, fmt.Errorf("database error querying inactive businesses: %w", err)
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
			&business.Latitude,
			&business.Longitude,
			&business.CreatedAt,
			&business.UpdatedAt,
			&business.IsActive,
			&business.OwnerID,
			&business.PublicId,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Error scanning business row for user ID %s: %v", userID, err)
			return nil, fmt.Errorf("error scanning business row: %w", err)
		}

		// Fetch associated images for each business
		images, err := business_image_models.GetImagesByBusinessID(ctx, db, business.ID)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to retrieve images for business ID %s: %v", business.ID, err)
			business.Images = []*business_image_models.BusinessImage{} // Ensure Images is an empty slice on error
		} else {
			business.Images = images
		}

		businesses = append(businesses, business)
	}

	if err := rows.Err(); err != nil {
		logger.ErrorLogger.Errorf("Error after iterating through rows for user ID %s: %v", userID, err)
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	if len(businesses) == 0 {
		logger.InfoLogger.Infof("No inactive businesses found for user ID %s", userID)
		return []*Business{}, nil // Return an empty slice if no rows are found
	}

	logger.InfoLogger.Infof("Successfully fetched %d inactive businesses for user ID %s", len(businesses), userID)

	return businesses, nil
}

// UpdateBusiness updates an existing business record in the database.
func UpdateBusiness(ctx context.Context, db *pgxpool.Pool, business *Business) (*Business, error) {
	logger.InfoLogger.Infof("Attempting to update business record with ID: %s", business.ID)

	business.UpdatedAt = time.Now()

	query := `
        UPDATE businesses
        SET
            name = $2, category = $3, address = $4, city = $5, state = $6,
            country = $7, postal_code = $8, tax_id = $9, about = $10,
            location_latitude = $11, location_longitude = $12, updated_at = $13, is_active = $14
        WHERE
            id = $1
        RETURNING id`

	var id uuid.UUID
	err := db.QueryRow(ctx, query,
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
		business.Latitude,
		business.Longitude,
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

// DeleteImageAndReferences deletes an image and all its references
func DeleteImageAndReferences(ctx context.Context, db *pgxpool.Pool, imageID uuid.UUID) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for image deletion: %w", err)
	}
	defer tx.Rollback(ctx)

	// Delete from business_images table
	_, err = tx.Exec(ctx, `DELETE FROM business_images WHERE image_id = $1`, imageID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete business image references for image %s: %v", imageID, err)
		return fmt.Errorf("failed to delete business image references: %w", err)
	}

	// Nullify the image_id in the 'services' table
	_, err = tx.Exec(ctx, `UPDATE services SET image_id = NULL WHERE image_id = $1`, imageID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to nullify image_id in services table for image %s: %v", imageID, err)
		return fmt.Errorf("failed to nullify service image_id: %w", err)
	}

	// Delete the image record from the 'images' table
	res, err := tx.Exec(ctx, `DELETE FROM images WHERE id = $1`, imageID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete image record %s: %v", imageID, err)
		return fmt.Errorf("failed to delete image record: %w", err)
	}

	if res.RowsAffected() == 0 {
		logger.WarnLogger.Warnf("Image with ID %s not found in images table for deletion.", imageID)
	} else {
		logger.InfoLogger.Infof("Successfully deleted image record %s from images table", imageID)
	}

	return tx.Commit(ctx)
}

func DeleteBusiness(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID) error {
	logger.InfoLogger.Infof("Attempting to delete business with ID: %s", businessID)

	query := `
        DELETE FROM businesses
        WHERE id = $1
        RETURNING id
    `

	var deletedID uuid.UUID
	err := db.QueryRow(ctx, query, businessID).Scan(&deletedID)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.ErrorLogger.Errorf("Business with ID %s not found for deletion", businessID)
			return fmt.Errorf("business not found")
		}
		logger.ErrorLogger.Errorf("Database error deleting business with ID %s: %v", businessID, err)
		return fmt.Errorf("database error: %w", err)
	}

	logger.InfoLogger.Infof("Successfully deleted business with ID: %s", businessID)
	return nil
}

// GetAllBusinesses fetches all business records from the database, with optional pagination.
func GetAllBusinesses(ctx context.Context, db *pgxpool.Pool, limit, offset int) ([]*Business, error) {
	logger.InfoLogger.Info("Attempting to fetch businesses from database with pagination")

	businesses := []*Business{}

	// Removed the LEFT JOIN LATERAL for primary_image_object_name
	// as it's no longer required by the Business struct for this query.
	baseQuery := `
        SELECT
            b.id,
            b.name,
            b.category,
            b.address,
            b.city,
            b.state,
            b.country,
            b.postal_code,
            b.tax_id,
            b.about,
            b.location_latitude,
            b.location_longitude,
            b.created_at,
            b.updated_at,
            b.is_active,
            b.owner_id,
            b.public_id
        FROM
            businesses AS b
        WHERE b.is_active = true
        ORDER BY b.created_at DESC`

	query := baseQuery
	args := []interface{}{}
	placeholderNum := 1

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", placeholderNum)
		args = append(args, limit)
		placeholderNum++
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", placeholderNum)
		args = append(args, offset)
		placeholderNum++
	}

	logger.InfoLogger.Infof("Executing query: %s with args: %v", query, args)

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to query businesses: %v", err)
		return nil, fmt.Errorf("failed to retrieve businesses: %w", err)
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
			&business.Latitude,
			&business.Longitude,
			&business.CreatedAt,
			&business.UpdatedAt,
			&business.IsActive,
			&business.OwnerID,
			&business.PublicId,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan business row: %v", err)
			return nil, fmt.Errorf("failed to scan business data: %w", err)
		}

		// The business.Images slice remains unpopulated by this query.
		// If you need images, you'd fetch them in a separate query or
		// use more advanced SQL aggregation for eager loading.

		businesses = append(businesses, business)
	}

	if err = rows.Err(); err != nil {
		logger.ErrorLogger.Errorf("Error after iterating rows for businesses: %v", err)
		return nil, fmt.Errorf("error during business row iteration: %w", err)
	}

	logger.InfoLogger.Infof("Fetched %d businesses successfully", len(businesses))
	return businesses, nil
}

package business_models

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
)

// Location represents geographical coordinates
type Location struct {
	Latitude  float64 `json:"latitude" binding:"min=-90,max=90"`
	Longitude float64 `json:"longitude" binding:"min=-180,max=180"`
}

// Business represents a business entity in your system.
type Business struct {
	ID         uuid.UUID   `json:"id"`
	Name       string      `json:"name"`
	Category   string      `json:"category"`
	Address    string      `json:"address"`
	City       string      `json:"city"`
	State      string      `json:"state"`
	Country    string      `json:"country"`
	PostalCode string      `json:"postalCode"`
	TaxID      string      `json:"taxId,omitempty"`
	About      string      `json:"about,omitempty"`
	ImageID    pgtype.UUID `json:"imageId,omitempty"` // <-- ADDED: To store the image reference
	Location   Location    `json:"location,omitempty"`
	CreatedAt  time.Time   `json:"createdAt"`
	UpdatedAt  time.Time   `json:"updatedAt"`
	IsActive   bool        `json:"isActive"`
	OwnerID    uuid.UUID   `json:"ownerId"`
	ObjectName *string     `db:"object_name,omitempty"`
	PublicId   *string     `json:"publicId"`
}

// NewBusiness creates a new Business struct with a generated ID and initial timestamps.
func NewBusiness(
	name, category, address, city, state, country, postalCode, taxID,
	about, publicId string, lat, long float64, ownerUserID, imageID uuid.UUID) (*Business, error) {

	id, err := uuid.NewV7()
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
		ImageID:    pgtype.UUID{Bytes: imageID, Valid: imageID != uuid.Nil}, // <-- ADDED: Assign imageID
		Location:   Location{Latitude: lat, Longitude: long},
		CreatedAt:  now,
		UpdatedAt:  now,
		IsActive:   true,
		OwnerID:    ownerUserID,
		PublicId:   &publicId,
	}, nil
}

// CreateBusiness inserts a new business record into the database.
func CreateBusiness(ctx context.Context, db *pgxpool.Pool, business *Business) (*Business, error) {
	query := `
        INSERT INTO businesses (id, name, category, address, city, state, country, postal_code, tax_id, about, image_id, location_latitude, location_longitude, created_at, updated_at, is_active, owner_id, public_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
        RETURNING id, name, category, address, city, state, country, postal_code, tax_id, about, image_id, location_latitude, location_longitude, created_at, updated_at, is_active, owner_id, public_id
    `
	logger.InfoLogger.Infof("Executing query to create business: %s", business.Name)

	// In your database schema, ensure the 'image_id' column exists and is of type UUID.
	// Also ensure 'latitude' and 'longitude' columns exist.
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
		business.ImageID, // Pass the new imageID field
		business.Location.Latitude,
		business.Location.Longitude,
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
		&business.ImageID,
		&business.Location.Latitude,
		&business.Location.Longitude,
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
func GetBusinessByID(db *pgxpool.Pool, id uuid.UUID) (*Business, error) {
	logger.InfoLogger.Infof("Attempting to fetch business with ID: %s", id)

	cloudflareImageBaseURL := os.Getenv("CLOUDFLARE_IMAGE_URL")

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
				b.public_id,
	            b.image_id,
	            CASE
					WHEN b.image_id IS NOT NULL THEN i.object_name
					ELSE NULL
				END AS object_name -- THIS IS THE EXTRA COLUMN!
			FROM
				businesses AS b
			LEFT JOIN
				images AS i ON b.image_id = i.id
			WHERE
				b.id = $1;
	`

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
		&business.PublicId,
		&business.ImageID,
		&business.ObjectName,
	)

	if business.ObjectName != nil {
		fullPath := cloudflareImageBaseURL + "/" + *business.ObjectName
		business.ObjectName = &fullPath
	} else {
		emptyStr := ""
		business.ObjectName = &emptyStr
	}

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s: %v", id, err)
		return nil, fmt.Errorf("business not found or database error: %w", err)
	}

	logger.InfoLogger.Infof("Business with ID %s fetched successfully", id)
	return business, nil
}

// GetBusinessByPublicId fetches a business record by its public ID (client-facing).
func GetBusinessByPublicId(db *pgxpool.Pool, publicId string) (*Business, error) {
	logger.InfoLogger.Infof("Attempting to fetch business with public ID: %s", publicId)

	cloudflareImageBaseURL := os.Getenv("CLOUDFLARE_IMAGE_URL")

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
				b.public_id,
	            b.image_id,
	            CASE
					WHEN b.image_id IS NOT NULL THEN i.object_name
					ELSE NULL
				END AS object_name -- THIS IS THE EXTRA COLUMN!
			FROM
				businesses AS b
			LEFT JOIN
				images AS i ON b.image_id = i.id
			WHERE
				b.public_id = $1;
	`

	err := db.QueryRow(context.Background(), query, publicId).Scan(
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
		&business.PublicId, // Need to process public ID before last ImageID(UUID)
		&business.ImageID,
		&business.ObjectName,
	)

	if business.ObjectName != nil {
		fullPath := cloudflareImageBaseURL + "/" + *business.ObjectName
		business.ObjectName = &fullPath
	} else {
		emptyStr := ""
		business.ObjectName = &emptyStr
	}

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business with public ID %s: %v", publicId, err)
		return nil, fmt.Errorf("business not found or database error: %w", err)
	}

	logger.InfoLogger.Infof("Business with public ID %s fetched successfully", publicId)
	return business, nil
}

// UpdateBusiness updates an existing business record in the database.
func UpdateBusiness(db *pgxpool.Pool, business *Business) (*Business, error) {
	logger.InfoLogger.Infof("Attempting to update business record with ID: %s", business.ID)

	business.UpdatedAt = time.Now()

	// Note: The column name for location in your query was location_latitude,
	// which is different from the CreateBusiness query (latitude).
	// I've standardized to latitude and longitude here for consistency.
	// Please ensure your DB schema matches.
	query := `
        UPDATE businesses
        SET
            name = $2, category = $3, address = $4, city = $5, state = $6,
            country = $7, postal_code = $8, tax_id = $9, about = $10,
            location_latitude = $11, location_longitude = $12, updated_at = $13, is_active = $14,
            image_id = $15
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
		business.ImageID,
	).Scan(&id)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update business %s in database: %v", business.ID, err)
		return nil, fmt.Errorf("failed to update business: %w", err)
	}

	logger.InfoLogger.Infof("Business with ID %s updated successfully", business.ID)
	return business, nil
}

// DeleteImageAndReferences deletes a business record from the database by its ID and from the image table if it exists.
func DeleteImageAndReferences(ctx context.Context, db *pgxpool.Pool, imageID uuid.UUID) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for image deletion: %w", err)
	}
	defer tx.Rollback(ctx) // Rollback on error, unless committed

	// 1. CRITICAL STEP: Nullify the image_id in the 'businesses' table
	// This removes the foreign key reference that is causing the error.
	_, err = tx.Exec(ctx, `
		UPDATE businesses
		SET image_id = NULL
		WHERE image_id = $1
	`, imageID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to nullify image_id in businesses table for image %s: %v", imageID, err)
		return fmt.Errorf("failed to nullify business image_id: %w", err)
	}
	logger.InfoLogger.Infof("Nullified image_id reference in businesses table for image %s", imageID)

	// 2. Nullify the image_id in the 'services' table
	// (Your logs show this is already happening, but it must be within this transaction)
	_, err = tx.Exec(context.Background(), `
		UPDATE services
		SET image_id = NULL
		WHERE image_id = $1
	`, imageID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to nullify image_id in services table for image %s: %v", imageID, err)
		return fmt.Errorf("failed to nullify service image_id: %w", err)
	}
	logger.InfoLogger.Infof("Nullified image_id reference in services table for image %s", imageID)

	// 3. Delete the image record from the 'images' table
	// This step will now succeed because no other table references it anymore.
	res, err := tx.Exec(context.Background(), `
		DELETE FROM images
		WHERE id = $1
	`, imageID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete image record %s: %v", imageID, err)
		return fmt.Errorf("failed to delete image record: %w", err)
	}

	if res.RowsAffected() == 0 {
		logger.WarnLogger.Warnf("Image with ID %s not found in images table for deletion.", imageID)
		// Consider returning an error if the image MUST exist for a successful deletion.
		// For example, return fmt.Errorf("image record not found")
	} else {
		logger.InfoLogger.Infof("Successfully deleted image record %s from images table", imageID)
	}

	// Commit the transaction if all steps were successful
	return tx.Commit(context.Background())
}

// GetAllBusinesses fetches all business records from the database, with optional pagination.
// If limit is 0, no limit is applied. If offset is 0, no offset is applied.
func GetAllBusinesses(ctx context.Context, db *pgxpool.Pool, limit, offset int) ([]*Business, error) {
	logger.InfoLogger.Info("Attempting to fetch businesses from database with pagination")

	businesses := []*Business{}

	// Base query including the LEFT JOIN and object_name
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
			b.public_id,
            b.image_id,
            CASE
                WHEN b.image_id IS NOT NULL THEN i.object_name
                ELSE NULL
            END AS object_name
        FROM
            businesses AS b
        LEFT JOIN
            images AS i ON b.image_id = i.id
        ORDER BY
            b.created_at DESC`

	query := baseQuery
	args := []interface{}{}
	placeholderNum := 1 // Start with $1 for first dynamic argument

	// Conditionally add LIMIT and OFFSET clauses
	// The controller ensures 'limit' will be > 0 (either user-defined or default).
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

	// Log the final query and arguments for debugging
	logger.InfoLogger.Infof("Executing query: %s with args: %v", query, args)

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to query businesses: %v", err)
		return nil, fmt.Errorf("failed to retrieve businesses: %w", err)
	}
	defer rows.Close()

	cloudflareImageBaseURL := os.Getenv("CLOUDFLARE_IMAGE_URL")

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
			&business.PublicId, // Need to process public ID before last ImageID(UUID)
			&business.ImageID,
			&business.ObjectName,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan business row: %v", err)
			return nil, fmt.Errorf("failed to scan business data: %w", err)
		}

		if business.ObjectName != nil {
			fullPath := cloudflareImageBaseURL + "/" + *business.ObjectName
			business.ObjectName = &fullPath
		} else {
			emptyStr := ""
			business.ObjectName = &emptyStr
		}

		businesses = append(businesses, business)
	}

	if err = rows.Err(); err != nil {
		logger.ErrorLogger.Errorf("Error after iterating rows for businesses: %v", err)
		return nil, fmt.Errorf("error during business row iteration: %w", err)
	}

	logger.InfoLogger.Infof("Fetched %d businesses successfully", len(businesses))
	return businesses, nil
}

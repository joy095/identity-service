package business_image_models

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger" // Assuming this path is correct for your logger
)

// BusinessImage represents a row in the business_images table.
// It no longer has an 'ID' column as business_id and image_id form the composite primary key.
type BusinessImage struct {
	BusinessID uuid.UUID `json:"businessId"`
	ImageID    uuid.UUID `json:"imageId"`
	Position   *int      `json:"position,omitempty"` // Added position field
	IsPrimary  bool      `json:"isPrimary"`
	ObjectName *string   `json:"objectName,omitempty"` // From the 'images' table
	R2URL      *string   `json:"r2Url,omitempty"`      // From the 'images' table
	CreatedAt  time.Time `json:"createdAt"`            // From the 'images' table (uploaded_at)
}

// GetAllImagesModel retrieves all images associated with a business.
func GetAllImagesModel(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID) ([]*BusinessImage, error) {
	query := `
        SELECT
            bi.image_id,
            bi.business_id,
            bi.position,
            bi.is_primary,
            i.object_name,
            i.r2_url,
            i.uploaded_at
        FROM
            business_images AS bi
        JOIN images AS i ON i.id = bi.image_id
        WHERE
            bi.business_id = $1
        ORDER BY
            bi.position ASC;
    `
	logger.InfoLogger.Infof("Executing query: %s", query)

	rows, err := db.Query(ctx, query, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to execute query: %v", err)
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	var images []*BusinessImage

	for rows.Next() {
		image := &BusinessImage{}
		err := rows.Scan(
			&image.ImageID,
			&image.BusinessID,
			&image.Position,
			&image.IsPrimary,
			&image.ObjectName,
			&image.R2URL,
			&image.CreatedAt,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan row: %v", err)
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		images = append(images, image)
	}

	return images, nil
}

// AddBusinessImages adds multiple image associations for a given business.
// It now includes a 'position' for each image.
func AddBusinessImages(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID, imageIDs []uuid.UUID, primaryImageID uuid.UUID) error {
	// Validate that primaryImageID exists in imageIDs
	primaryFound := slices.Contains(imageIDs, primaryImageID)
	if !primaryFound && len(imageIDs) > 0 {
		return fmt.Errorf("primaryImageID %s not found in imageIDs", primaryImageID)
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) // Rollback on error or if Commit fails

	// Delete existing associations for the business to handle potential position overlaps
	// or re-ordering if this function is used for full replacement/update.
	// If you only add new images, this might need different logic.
	_, err = tx.Exec(ctx, `DELETE FROM business_images WHERE business_id = $1`, businessID)
	if err != nil {
		return fmt.Errorf("failed to clear existing business images: %w", err)
	}

	query := `
		INSERT INTO business_images (business_id, image_id, is_primary, position)
		VALUES ($1, $2, $3, $4)
	`
	// Assuming position is assigned sequentially based on the order in imageIDs
	for i, imageID := range imageIDs {
		_, err := tx.Exec(ctx, query, businessID, imageID, imageID == primaryImageID, i+1) // Position starts from 1
		if err != nil {
			return fmt.Errorf("failed to insert business image (business_id: %s, image_id: %s): %w", businessID, imageID, err)
		}
	}

	return tx.Commit(ctx)
}

// GetImagesByBusinessID retrieves all images associated with a business,
// including their object names and uploaded_at from the 'images' table.
func GetImagesByBusinessID(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID) ([]*BusinessImage, error) {
	query := `
		SELECT 
			bi.business_id, 
			bi.image_id, 
			bi.is_primary, 
			bi.position,          -- Added position to SELECT
			i.uploaded_at, 
			i.object_name
		FROM business_images bi
		LEFT JOIN images i ON bi.image_id = i.id
		WHERE bi.business_id = $1
		ORDER BY bi.is_primary DESC, bi.position ASC, i.uploaded_at ASC -- Order by position if present
	`
	rows, err := db.Query(ctx, query, businessID)
	if err != nil {
		return nil, fmt.Errorf("failed to query business images: %w", err)
	}
	defer rows.Close()

	cloudflareImageBaseURL := os.Getenv("CLOUDFLARE_IMAGE_URL")
	var images []*BusinessImage
	for rows.Next() {
		var img BusinessImage
		// Scan order must match SELECT order
		err := rows.Scan(
			&img.BusinessID,
			&img.ImageID,
			&img.IsPrimary,
			&img.Position, // Scan position
			&img.CreatedAt,
			&img.ObjectName,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan business image row: %w", err)
		}

		// Set full image URL if object name exists
		if img.ObjectName != nil && cloudflareImageBaseURL != "" {
			// Ensure base URL doesn't end with slash and encode object name
			baseURL := strings.TrimRight(cloudflareImageBaseURL, "/")
			fullPath := baseURL + "/" + url.QueryEscape(*img.ObjectName)
			img.ObjectName = &fullPath
		}

		images = append(images, &img)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error after scanning rows: %w", err)
	}

	return images, nil
}

// DeleteBusinessImage removes a business-image relationship and optionally deletes the image
// if it's no longer referenced by any business_image or service.
func DeleteBusinessImage(ctx context.Context, db *pgxpool.Pool, businessID, imageID uuid.UUID) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for business image deletion: %w", err)
	}
	defer tx.Rollback(ctx) // Rollback on error or if Commit fails

	// Remove the business image relationship
	commandTag, err := tx.Exec(ctx, `
		DELETE FROM business_images
		WHERE business_id = $1 AND image_id = $2
	`, businessID, imageID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete business image relationship: %v", err)
		return fmt.Errorf("failed to delete business image relationship: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		logger.InfoLogger.Infof("No business image relationship found for business_id: %s, image_id: %s", businessID, imageID)
		return fmt.Errorf("business image relationship not found")
	}

	// Check if the image is still referenced by other business_images or services
	var count int
	err = tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM (
			SELECT 1 FROM business_images WHERE image_id = $1
			UNION ALL
			SELECT 1 FROM services WHERE image_id = $1 -- Assuming 'services' also has an image_id foreign key
		) as refs
	`, imageID).Scan(&count)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to check image references for image %s: %v", imageID, err)
		return fmt.Errorf("failed to check image references: %w", err)
	}

	// If no references exist, delete the image from the 'images' table
	if count == 0 {
		_, err = tx.Exec(ctx, `DELETE FROM images WHERE id = $1`, imageID)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to delete orphaned image %s: %v", imageID, err)
			return fmt.Errorf("failed to delete orphaned image: %w", err)
		}
		logger.InfoLogger.Infof("Deleted orphaned image %s from 'images' table", imageID)
	} else {
		logger.InfoLogger.Infof("Image %s is still referenced (%d times), not deleting from 'images' table.", imageID, count)
	}

	return tx.Commit(ctx)
}

// SetPrimaryImage sets a specific image as the primary image for a business.
// It ensures only one image is primary for a given business.
func SetPrimaryImage(ctx context.Context, db *pgxpool.Pool, businessID, imageID uuid.UUID) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) // Rollback on error or if Commit fails

	// First, set all images for this business to non-primary
	_, err = tx.Exec(ctx, `
		UPDATE business_images 
		SET is_primary = false 
		WHERE business_id = $1
	`, businessID)
	if err != nil {
		return fmt.Errorf("failed to reset primary images for business %s: %w", businessID, err)
	}

	// Then set the specified image as primary
	result, err := tx.Exec(ctx, `
		UPDATE business_images 
		SET is_primary = true 
		WHERE business_id = $1 AND image_id = $2
	`, businessID, imageID)
	if err != nil {
		return fmt.Errorf("failed to set primary image (business_id: %s, image_id: %s): %w", businessID, imageID, err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("image (ID: %s) not found for business (ID: %s) to set as primary", imageID, businessID)
	}

	return tx.Commit(ctx)
}

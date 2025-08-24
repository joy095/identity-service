package business_image_models

import (
	"context"
	"fmt"
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
	Position   *int      `json:"position,omitempty"`   // Added position field
	ObjectName *string   `json:"objectName,omitempty"` // From the 'images' table
	R2URL      *string   `json:"r2Url,omitempty"`      // From the 'images' table
	CreatedAt  time.Time `json:"createdAt"`            // From the 'images' table (uploaded_at)
}

// GetAllImagesModel retrieves all images associated with a business.
func GetAllImagesModel(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID) ([]map[string]interface{}, error) {
	// Modify query to select position explicitly
	// Ensure the SELECT order matches the Scan order
	query := `
        SELECT
            bi.image_id,      
            bi.position,     
            i.object_name    
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

	var images []map[string]interface{}

	for rows.Next() {
		// Declare variables matching the SELECT order and types
		var imageID uuid.UUID  // Assuming image_id is NOT NULL in the DB. Use uuid.NullUUID if it can be NULL.
		var position *int      // Position is already a pointer as it can be NULL
		var objectName *string // object_name can be NULL

		// Scan into ALL selected columns in the SAME ORDER as the SELECT statement
		err := rows.Scan(&imageID, &position, &objectName)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to scan row: %v", err)
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Determine if this is the primary image (position = 1)
		isPrimary := false
		if position != nil && *position == 1 {
			isPrimary = true
		}

		// Set full image URL if object name exists
		// if objectName != nil && cloudflareImageBaseURL != "" {
		// 	baseURL := strings.TrimRight(cloudflareImageBaseURL, "/")
		// 	fullPath := baseURL + "/" + *objectName
		// 	objectName = &fullPath // Update the objectName pointer to the full URL
		// }

		// Create the result map
		image := map[string]interface{}{
			"imageId":    imageID, // imageID is a uuid.UUID, convert if string needed: imageID.String()
			"position":   position,
			"isPrimary":  isPrimary, // Derived from position
			"objectName": objectName,
		}
		images = append(images, image)
	}

	if err = rows.Err(); err != nil {
		logger.ErrorLogger.Errorf("Error after scanning rows: %v", err)
		return nil, fmt.Errorf("error after scanning rows: %w", err)
	}
	return images, nil
}

// AddBusinessImages adds multiple image associations for a given business.
// It now includes a 'position' for each image.
func AddBusinessImages(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID, imageIDs []uuid.UUID /* , primaryImageID uuid.UUID - Remove if not used elsewhere */) error {
	// Optional: Validate that primaryImageID (if passed) exists in imageIDs
	// if slices.Contains(imageIDs, primaryImageID) { ... } else { ... }

	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Delete existing associations
	_, err = tx.Exec(ctx, `DELETE FROM business_images WHERE business_id = $1`, businessID)
	if err != nil {
		return fmt.Errorf("failed to clear existing business images: %w", err)
	}

	// Insert new associations with positions. Position 1 is implicitly primary.
	query := `
        INSERT INTO business_images (business_id, image_id, position)
        VALUES ($1, $2, $3)
    `

	for i, imageID := range imageIDs {
		position := i + 1 // Positions start from 1
		// is_primary is implicitly determined by position = 1
		_, err := tx.Exec(ctx, query, businessID, imageID, position)
		if err != nil {
			return fmt.Errorf("failed to insert business image (business_id: %s, image_id: %s): %w", businessID, imageID, err)
		}
	}

	if len(imageIDs) == 0 {
		return fmt.Errorf("imageIDs cannot be empty")
	}

	return tx.Commit(ctx)
}

// GetImagesByBusinessID retrieves all images associated with a business,
// including their object names and uploaded_at from the 'images' table.
func GetImagesByBusinessID(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID) ([]*BusinessImage, error) {
	// Modify query to remove is_primary from SELECT
	query := `
        SELECT 
            bi.business_id, 
            bi.image_id, 
            bi.position, -- Select position only
            i.uploaded_at, 
            i.object_name
        FROM business_images bi
        LEFT JOIN images i ON bi.image_id = i.id
        WHERE bi.business_id = $1
        ORDER BY bi.position ASC, i.uploaded_at ASC
    `
	rows, err := db.Query(ctx, query, businessID)
	if err != nil {
		return nil, fmt.Errorf("failed to query business images: %w", err)
	}
	defer rows.Close()

	var images []*BusinessImage

	for rows.Next() {
		var img BusinessImage
		// Scan order must match SELECT order (excluding is_primary)
		err := rows.Scan(
			&img.BusinessID,
			&img.ImageID,
			&img.Position, // Scan Position
			&img.CreatedAt,
			&img.ObjectName,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan business image row: %w", err)
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

// SetPrimaryImage moves the specified image to position 1, making it the primary image.
// Other images' positions are incremented accordingly.
func SetPrimaryImage(ctx context.Context, db *pgxpool.Pool, businessID, imageID uuid.UUID) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// 1. Check if the image belongs to the business
	var exists bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM business_images WHERE business_id = $1 AND image_id = $2)`, businessID, imageID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check image existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("image (ID: %s) not found for business (ID: %s)", imageID, businessID)
	}

	// 2. Get the current position of the image to be made primary
	var currentPos int
	err = tx.QueryRow(ctx, `SELECT position FROM business_images WHERE business_id = $1 AND image_id = $2`, businessID, imageID).Scan(&currentPos)
	if err != nil {
		return fmt.Errorf("failed to get current position: %w", err)
	}

	// 3. If it's already at position 1, nothing to do
	if currentPos == 1 {
		return tx.Commit(ctx) // Commit early if no change needed
	}

	// 4. Increment positions of images that currently have position >= 1 and < currentPos
	//    (This moves images "down" the list to make space at position 1)
	_, err = tx.Exec(ctx, `
        UPDATE business_images
        SET position = position + 1
        WHERE business_id = $1 AND position >= 1 AND position < $2
    `, businessID, currentPos)
	if err != nil {
		return fmt.Errorf("failed to shift image positions: %w", err)
	}

	// 5. Set the target image's position to 1
	_, err = tx.Exec(ctx, `
        UPDATE business_images
        SET position = 1
        WHERE business_id = $1 AND image_id = $2
    `, businessID, imageID)
	if err != nil {
		return fmt.Errorf("failed to set image position to 1: %w", err)
	}

	return tx.Commit(ctx)
}

// ReorderBusinessImages updates the positions of images for a business based on a provided order.
// imageIDsInOrder should be a slice of image UUIDs in the desired new sequence.
func ReorderBusinessImages(ctx context.Context, db *pgxpool.Pool, businessID uuid.UUID, imageIDsInOrder []uuid.UUID) error {
	if len(imageIDsInOrder) == 0 {
		// Nothing to reorder
		return nil
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for reordering: %w", err)
	}
	defer func() {
		if err != nil {
			// If an error occurred during the process, rollback
			rollbackErr := tx.Rollback(ctx)
			if rollbackErr != nil {
				// Log rollback error, don't override the original error
				logger.ErrorLogger.Errorf("Failed to rollback transaction during reorder: %v", rollbackErr)
			}
		}
	}()

	// 1. Verify all provided imageIDs belong to the business
	// Create a map for quick lookup of provided IDs
	providedIDMap := make(map[uuid.UUID]bool)
	for _, id := range imageIDsInOrder {
		providedIDMap[id] = true
	}

	// Fetch current images for the business (get IDs and current positions)
	currentImages, err := GetImagesByBusinessID(ctx, db, businessID) // Reuse existing function
	if err != nil {
		return fmt.Errorf("failed to fetch current images for verification: %w", err)
	}

	// Create a map of current image IDs for existence check
	currentImageIDMap := make(map[uuid.UUID]bool)
	for _, img := range currentImages {
		currentImageIDMap[img.ImageID] = true
	}

	// Check if all IDs in the order list exist for this business
	for _, providedID := range imageIDsInOrder {
		if !currentImageIDMap[providedID] {
			// Rollback handled by defer
			return fmt.Errorf("image ID %s does not belong to business %s or does not exist", providedID, businessID)
		}
	}

	// 2. Update positions based on the provided order
	// Prepare the update query. Using a VALUES clause can be efficient for batch updates.
	// This query joins the business_images table with a temporary set of (image_id, new_position) pairs.
	// It only updates images whose IDs are in the provided list for this business.
	query := `
        UPDATE business_images AS bi
        SET position = ordered_positions.new_position
        FROM (
            VALUES `

	// Add placeholders for each (image_id, position) pair
	args := make([]interface{}, 0, len(imageIDsInOrder)*2)
	for i, imageID := range imageIDsInOrder {
		if i > 0 {
			query += ", "
		}
		// Explicitly cast both uuid and integer types
		query += fmt.Sprintf("($%d::uuid, $%d::integer)", i*2+1, i*2+2)
		args = append(args, imageID, i+1) // Position starts at 1
	}

	query += `
        ) AS ordered_positions(image_id, new_position)
        WHERE bi.business_id = $` + fmt.Sprintf("%d", len(args)+1) + `::uuid
        AND bi.image_id = ordered_positions.image_id`

	// Append businessID to the args
	args = append(args, businessID)

	// logger.InfoLogger.Infof("Reorder Query: %s, Args: %v", query, args) // For debugging

	_, err = tx.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update image positions: %w", err)
	}

	// 3. Commit the transaction if everything went well
	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("failed to commit reorder transaction: %w", err)
	}

	logger.InfoLogger.Infof("Successfully reordered images for business %s", businessID)
	return nil
}

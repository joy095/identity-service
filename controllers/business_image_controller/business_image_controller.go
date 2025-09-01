package business_image_controller

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/handlers/image_handlers" // Assuming this path is correct
	"github.com/joy095/identity/logger"                  // Assuming this path is correct
	"github.com/joy095/identity/models/business_image_models"
	"github.com/joy095/identity/models/business_models" // Assuming this path is correct
	"github.com/joy095/identity/utils"                  // Assuming this path is correct for utility functions
)

type BusinessImageController struct {
	db *pgxpool.Pool
}

type ReorderRequest struct {
	Order []string `json:"order"` // List of image UUIDs (as strings) in the desired new order
}

// NewBusinessImageController creates a new instance of BusinessImageController.
func NewBusinessImageController(db *pgxpool.Pool) (*BusinessImageController, error) {
	if db == nil {
		return nil, errors.New("database pool cannot be nil")
	}

	return &BusinessImageController{
		db: db,
	}, nil
}

// GetAllImages retrieves all images associated with a business.
func (bc *BusinessImageController) GetAllImages(c *gin.Context) {
	logger.InfoLogger.Info("GetAllImages controller called")

	publicId := c.Param("publicId")

	businessId, err := business_models.GetBusinessIdOnly(c.Request.Context(), bc.db, publicId)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get business by publicId: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	businessImages, err := business_image_models.GetAllImagesModel(c.Request.Context(), bc.db, businessId)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get business images: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve images"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"images": businessImages,
	})
}

// AddBusinessImages handles adding multiple images to a business in a single request.
func (bc *BusinessImageController) AddBusinessImages(c *gin.Context) {
	logger.InfoLogger.Info("AddBusinessImages controller called")
	publicId := c.Param("publicId")

	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	business, err := business_models.GetBusinessByPublicId(c.Request.Context(), bc.db, publicId)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	if business.OwnerID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to modify this business"})
		return
	}

	accessToken, err := c.Cookie("access_token")
	if err != nil || accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication token missing in cookie"})
		return
	}

	// Use the new handler for multiple images
	uploadedImageIDs, err := image_handlers.HandleMultipleImageUpload(c, accessToken)
	if err != nil {
		// The handler now sets the JSON error response, so we just return.
		return
	}
	if len(uploadedImageIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No images uploaded"})
		return
	}

	// Note: AddBusinessImages now replaces all existing images for the business.
	// If you want to append, the model function needs adjustment.
	// The primary image is determined by position (position = 1).
	err = business_image_models.AddBusinessImages(c.Request.Context(), bc.db, business.ID, uploadedImageIDs)
	if err != nil {
		// Clean up uploaded images on database error
		var deletionErrors []string
		for _, uploadedID := range uploadedImageIDs {
			if err := image_handlers.DeleteImage(uploadedID, accessToken); err != nil {
				deletionErrors = append(deletionErrors, fmt.Sprintf("imageID=%s: %v", uploadedID, err))
			}
		}
		if len(deletionErrors) > 0 {
			logger.ErrorLogger.Errorf("Failed to clean up some uploaded images: %v", deletionErrors)
		}

		logger.ErrorLogger.Errorf("Failed to associate images with business %s: %v", business.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to associate images with business"})
		return
	}

	logger.InfoLogger.Infof("Successfully added %d images to business %s", len(uploadedImageIDs), publicId)
	c.JSON(http.StatusOK, gin.H{
		"message":    "Images added successfully!",
		"imageCount": len(uploadedImageIDs),
		"imageIds":   uploadedImageIDs,
	})
}

// ReplaceBusinessImage replaces an existing business image with a new one.
func (bc *BusinessImageController) ReplaceBusinessImage(c *gin.Context) {
	logger.InfoLogger.Info("ReplaceBusinessImage controller called")
	publicId := c.Param("publicId")
	imageIDStr := c.Param("imageId") // This is the OLD image ID to be replaced

	oldImageID, err := uuid.Parse(imageIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid image ID format"})
		return
	}

	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	business, err := business_models.GetBusinessByPublicId(c.Request.Context(), bc.db, publicId)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	if business.OwnerID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to modify this business"})
		return
	}

	// Find the old image and its properties (is_primary, position)
	var oldImage *business_image_models.BusinessImage
	for _, img := range business.Images {
		if img.ImageID == oldImageID {
			oldImage = img
			break
		}
	}
	if oldImage == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Image not found for this business"})
		return
	}

	accessToken, err := c.Cookie("access_token")
	if err != nil || accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication token missing in cookie"})
		return
	}

	// Handle the upload of the new image and deletion of the old one from the image service
	newImageID, err := image_handlers.HandleImageReplacement(c, accessToken, oldImageID)
	if err != nil {
		return // Error handled by image handler
	}

	// Start a transaction for database operations
	tx, err := bc.db.Begin(c.Request.Context())
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to begin transaction for image replacement: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to replace image"})
		return
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback(c.Request.Context())
			panic(p) // re-panic after rollback
		}
	}()

	// 1. Delete the old association from business_images
	_, err = tx.Exec(c.Request.Context(), `
		DELETE FROM business_images
		WHERE business_id = $1 AND image_id = $2
	`, business.ID, oldImageID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to remove old image association (old image ID: %s): %v", oldImageID, err)
		tx.Rollback(c.Request.Context())
		// Try to delete the newly uploaded image if DB operation fails
		image_handlers.DeleteImage(newImageID, accessToken)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove old image association"})
		return
	}

	// 2. Insert the new association with properties from the old one
	// Assuming the new image should inherit is_primary and position from the old image
	newPosition := oldImage.Position
	if newPosition == nil {
		// Get the next available position for this business
		// Use a single atomic operation to avoid race conditions
		err = tx.QueryRow(c.Request.Context(), `
			INSERT INTO business_images (business_id, image_id, position)
			VALUES ($1, $2, (SELECT COALESCE(MAX(position), 0) + 1 FROM business_images WHERE business_id = $1))
			RETURNING position
		`, business.ID, newImageID).Scan(&newPosition)
	}

	// Commit the transaction
	err = tx.Commit(c.Request.Context())
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to commit transaction for image replacement: %v", err)
		// Again, consider if you need to clean up new image here if commit fails
		image_handlers.DeleteImage(newImageID, accessToken)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to replace image (commit failed)"})
		return
	}

	logger.InfoLogger.Infof("Image %s replaced with %s for business %s", oldImageID, newImageID, publicId)
	c.JSON(http.StatusOK, gin.H{"message": "Image replaced successfully!", "oldImageId": oldImageID, "newImageId": newImageID})
}

// DeleteBusinessImage removes an image from a business and potentially from the image service.
func (bc *BusinessImageController) DeleteBusinessImage(c *gin.Context) {
	logger.InfoLogger.Info("DeleteBusinessImage controller called")
	publicId := c.Param("publicId")
	imageIDStr := c.Param("imageId")

	// Validate parameters
	if publicId == "" {
		logger.ErrorLogger.Error("publicId is missing")
		c.JSON(http.StatusBadRequest, gin.H{"error": "publicId is required"})
		return
	}

	if imageIDStr == "" || imageIDStr == "undefined" {
		logger.ErrorLogger.Error("imageId is missing or undefined")
		c.JSON(http.StatusBadRequest, gin.H{"error": "imageId is required"})
		return
	}

	logger.DebugLogger.Infof("DeleteBusinessImage - publicId: %s, imageId: %s", publicId, imageIDStr)

	imageID, err := uuid.Parse(imageIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid image ID format"})
		return
	}

	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	business, err := business_models.GetBusinessByPublicId(c.Request.Context(), bc.db, publicId)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	if business.OwnerID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to modify this business"})
		return
	}

	imageExists := false
	for _, img := range business.Images {
		if img.ImageID == imageID {
			imageExists = true
			break
		}
	}
	if !imageExists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Image not found for this business"})
		return
	}

	// Access token is needed for image service deletion, but not for DB deletion
	accessToken, err := c.Cookie("access_token")
	if err != nil || accessToken == "" {
		logger.ErrorLogger.Errorf("Authentication token missing in cookie for image service deletion (imageID: %s)", imageID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication token required for image deletion"})
		return
	}

	// Call the model function which handles both relationship deletion and conditional image service deletion
	err = business_image_models.DeleteBusinessImage(c.Request.Context(), bc.db, business.ID, imageID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete business image relationship or orphaned image: %v", err)
		if err.Error() == "business image relationship not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Image relationship not found or already deleted."})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete image association"})
		}
		return
	}

	logger.InfoLogger.Infof("Image %s deleted from business %s", imageID, publicId)
	c.JSON(http.StatusOK, gin.H{"message": "Image deleted successfully!", "imageId": imageID})
}

// SetPrimaryBusinessImage sets a specific image as the primary image for a business.
func (bc *BusinessImageController) SetPrimaryBusinessImage(c *gin.Context) {
	logger.InfoLogger.Info("SetPrimaryBusinessImage controller called")
	publicId := c.Param("publicId")
	imageIDStr := c.Param("imageId")

	imageID, err := uuid.Parse(imageIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid image ID format"})
		return
	}

	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	business, err := business_models.GetBusinessByPublicId(c.Request.Context(), bc.db, publicId)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	if business.OwnerID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to modify this business"})
		return
	}

	imageExists := false
	for _, img := range business.Images {
		if img.ImageID == imageID {
			imageExists = true
			break
		}
	}
	if !imageExists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Image not found for this business"})
		return
	}

	err = business_image_models.SetPrimaryImage(c.Request.Context(), bc.db, business.ID, imageID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to set primary image for business %s, image %s: %v", business.ID, imageID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set primary image"})
		return
	}

	logger.InfoLogger.Infof("Image %s set as primary for business %s", imageID, publicId)
	c.JSON(http.StatusOK, gin.H{"message": "Primary image set successfully!", "imageId": imageID})
}

// ReorderBusinessImages update the ordering for the current images
func (bc *BusinessImageController) ReorderBusinessImages(c *gin.Context) {
	logger.InfoLogger.Info("ReorderBusinessImages controller called")
	publicId := c.Param("publicId")

	// --- 1. Authentication & Authorization ---
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	business, err := business_models.GetBusinessByPublicId(c.Request.Context(), bc.db, publicId)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	if business.OwnerID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to modify this business"})
		return
	}

	// --- 2. Parse Request Body ---
	var req ReorderRequest
	if err := c.ShouldBindJSON(&req); err != nil { // Use ShouldBindJSON for JSON
		logger.ErrorLogger.Errorf("Failed to parse reorder request body for business %s: %v", business.ID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if len(req.Order) == 0 {
		logger.InfoLogger.Infof("Empty order list provided for business %s reorder", business.ID)
		// Not necessarily an error, just nothing to do. Return success.
		c.JSON(http.StatusOK, gin.H{
			"message": "No images specified for reordering. Order unchanged.",
		})
		return
	}

	// --- 3. Convert String IDs to UUIDs ---
	imageIDsInOrder := make([]uuid.UUID, 0, len(req.Order))
	seen := make(map[uuid.UUID]bool)
	for _, idStr := range req.Order {
		id, err := uuid.Parse(idStr)
		if err != nil {
			logger.WarnLogger.Warnf("Invalid UUID format in reorder list for business %s: %s", business.ID, idStr)
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid image ID format: %s", idStr)})
			return
		}
		if seen[id] {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Duplicate image ID in order: %s", idStr)})
			return
		}
		seen[id] = true
		imageIDsInOrder = append(imageIDsInOrder, id)
	}

	// --- 4. Call Model Function ---
	// Use the context from Gin
	ctx := c.Request.Context()
	err = business_image_models.ReorderBusinessImages(ctx, bc.db, business.ID, imageIDsInOrder)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to reorder images for business %s: %v", business.ID, err)
		// Determine error type if needed for specific status codes (e.g., 404 if image not found)
		// For simplicity, returning 500 for any model error
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reorder images"})
		return
	}

	// --- 5. Respond ---
	logger.InfoLogger.Infof("Successfully reordered %d images for business %s", len(imageIDsInOrder), business.ID)
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Successfully reordered %d images", len(imageIDsInOrder)),
		// "order":   req.Order, // Optional: echo back the order
	})
}

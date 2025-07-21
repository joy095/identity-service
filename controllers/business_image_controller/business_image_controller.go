package business_image_controller

import (
	"net/http"
	"strconv"

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
	DB *pgxpool.Pool
}

// NewBusinessImageController creates a new instance of BusinessImageController.
func NewBusinessImageController(db *pgxpool.Pool) *BusinessImageController {
	if db == nil {
		panic("database pool cannot be nil")
	}

	return &BusinessImageController{
		DB: db,
	}
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

	business, err := business_models.GetBusinessByPublicId(c.Request.Context(), bc.DB, publicId)
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

	var primaryImageID uuid.UUID
	if len(uploadedImageIDs) > 0 {
		primaryImageIndex := 0 // Default to first image
		if primaryIndexStr := c.PostForm("primaryImageIndex"); primaryIndexStr != "" {
			if idx, parseErr := strconv.Atoi(primaryIndexStr); parseErr == nil && idx >= 0 && idx < len(uploadedImageIDs) {
				primaryImageIndex = idx
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid primaryImageIndex provided"})
				// Clean up uploaded images
				for _, uploadedID := range uploadedImageIDs {
					image_handlers.DeleteImage(uploadedID, accessToken)
				}
				return
			}
		}
		primaryImageID = uploadedImageIDs[primaryImageIndex]
	}

	// Note: AddBusinessImages now replaces all existing images for the business.
	// If you want to append, the model function needs adjustment.
	err = business_image_models.AddBusinessImages(c.Request.Context(), bc.DB, business.ID, uploadedImageIDs, primaryImageID)
	if err != nil {
		// Clean up uploaded images on database error
		for _, uploadedID := range uploadedImageIDs {
			// This might also try to delete the primary image if it failed to set primary.
			// Consider if you want this cleanup to be more robust or handled differently.
			image_handlers.DeleteImage(uploadedID, accessToken) // Error from this is logged inside
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

	business, err := business_models.GetBusinessByPublicId(c.Request.Context(), bc.DB, publicId)
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
	tx, err := bc.DB.Begin(c.Request.Context())
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to begin transaction for image replacement: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to replace image"})
		return
	}
	defer tx.Rollback(c.Request.Context()) // Ensure rollback on error

	// 1. Delete the old association from business_images
	_, err = tx.Exec(c.Request.Context(), `
		DELETE FROM business_images
		WHERE business_id = $1 AND image_id = $2
	`, business.ID, oldImageID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to remove old image association (old image ID: %s): %v", oldImageID, err)
		// Try to delete the newly uploaded image if DB operation fails
		image_handlers.DeleteImage(newImageID, accessToken)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove old image association"})
		return
	}

	// 2. Insert the new association with properties from the old one
	// Assuming the new image should inherit is_primary and position from the old image
	newPosition := oldImage.Position
	if newPosition == nil {
		// Assign a default if old position was null, or handle as per your logic
		tempPos := 1 // Default to 1 if not specified
		newPosition = &tempPos
	}

	_, err = tx.Exec(c.Request.Context(), `
		INSERT INTO business_images (business_id, image_id, is_primary, position)
		VALUES ($1, $2, $3, $4)
	`, business.ID, newImageID, oldImage.IsPrimary, newPosition)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to associate new image (new image ID: %s) with business: %v", newImageID, err)
		// Clean up the new image if DB insertion fails
		image_handlers.DeleteImage(newImageID, accessToken)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to associate new image with business"})
		return
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

	business, err := business_models.GetBusinessByPublicId(c.Request.Context(), bc.DB, publicId)
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
		// Proceeding without accessToken for image service deletion, relying on DB cleanup.
		// Consider if this should be an outright error.
	}

	// Call the model function which handles both relationship deletion and conditional image service deletion
	err = business_image_models.DeleteBusinessImage(c.Request.Context(), bc.DB, business.ID, imageID)
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

	business, err := business_models.GetBusinessByPublicId(c.Request.Context(), bc.DB, publicId)
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

	err = business_image_models.SetPrimaryImage(c.Request.Context(), bc.DB, business.ID, imageID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to set primary image for business %s, image %s: %v", business.ID, imageID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set primary image"})
		return
	}

	logger.InfoLogger.Infof("Image %s set as primary for business %s", imageID, publicId)
	c.JSON(http.StatusOK, gin.H{"message": "Primary image set successfully!", "imageId": imageID})
}

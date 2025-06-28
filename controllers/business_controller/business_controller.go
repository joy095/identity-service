package business_controller

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/joy095/identity/badwords"
	"github.com/joy095/identity/handlers/image_handlers" // <-- IMPORT the shared image handler
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/business_models"
	"github.com/joy095/identity/utils"
)

// BusinessController holds dependencies for business-related operations.
type BusinessController struct {
	DB *pgxpool.Pool
}

// NewBusinessController creates a new instance of BusinessController.
func NewBusinessController(db *pgxpool.Pool) *BusinessController {
	return &BusinessController{
		DB: db,
	}
}

// CreateBusinessRequest represents the form data for creating a business.
// Tags are changed from `json` to `form` to support multipart/form-data binding.
type CreateBusinessRequest struct {
	Name       string  `form:"name" binding:"required,min=3,max=100"`
	Category   string  `form:"category" binding:"required,min=2,max=50"`
	Address    string  `form:"address,omitempty" binding:"omitempty,min=5,max=255"`
	City       string  `form:"city" binding:"required,min=2,max=50"`
	State      string  `form:"state" binding:"required,min=2,max=50"`
	Country    string  `form:"country" binding:"required,min=2,max=50"`
	PostalCode string  `form:"postalCode" binding:"required,min=3,max=20"`
	TaxID      string  `form:"taxId,omitempty"`
	About      string  `form:"about,omitempty"`
	Latitude   float64 `form:"latitude" binding:"omitempty,min=-90,max=90"`
	Longitude  float64 `form:"longitude" binding:"omitempty,min=-180,max=180"`
}

// UpdateBusinessRequest remains the same as it uses JSON.
type UpdateBusinessRequest struct {
	Name       *string                  `json:"name,omitempty" binding:"omitempty,min=3,max=100"`
	Category   *string                  `json:"category,omitempty" binding:"omitempty,min=2,max=50"`
	Address    *string                  `json:"address,omitempty" binding:"omitempty,min=5,max=255"`
	City       *string                  `json:"city,omitempty" binding:"omitempty,min=2,max=50"`
	State      *string                  `json:"state,omitempty" binding:"omitempty,min=2,max=50"`
	Country    *string                  `json:"country,omitempty" binding:"omitempty,min=2,max=50"`
	PostalCode *string                  `json:"postalCode,omitempty" binding:"omitempty,min=3,max=20"`
	TaxID      *string                  `json:"taxId,omitempty"`
	About      *string                  `json:"about,omitempty"`
	Location   business_models.Location `json:"location"`
	IsActive   *bool                    `json:"isActive,omitempty"`
}

// CreateBusiness handles the HTTP request to create a new business with an image.
func (bc *BusinessController) CreateBusiness(c *gin.Context) {
	logger.InfoLogger.Info("CreateBusiness controller called")

	var req CreateBusinessRequest
	// Use ShouldBind to handle multipart/form-data
	if err := c.ShouldBind(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid form data for CreateBusiness: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request data: %s", err.Error())})
		return
	}

	// --- Bad words check (no changes needed here) ---
	if badwords.ContainsBadWords(req.Name) || badwords.ContainsBadWords(req.Address) ||
		badwords.ContainsBadWords(req.About) || badwords.ContainsBadWords(req.City) ||
		badwords.ContainsBadWords(req.State) || badwords.ContainsBadWords(req.Country) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request contains inappropriate language."})
		return
	}

	// --- Handle Image Upload ---
	var imageID uuid.UUID
	authHeader := c.GetHeader("Authorization")
	// The `image_handlers.HandleImageUpload` function can be reused if you extract it to be public.
	// For now, we assume a similar internal function or call the shared one.
	// Let's create a temporary context to call the handler.
	file, err := c.FormFile("image")
	if err != nil && err != http.ErrMissingFile {
		// An actual error occurred with the file.
		image_handlers.HandleFileError(c, err) // Reuse error handler
		return
	}

	if file != nil {
		// An image was provided, so we process it.
		uploadedImageID, uploadErr := image_handlers.HandleImageUpload(c, authHeader)
		if uploadErr != nil {
			// Error is already handled by the image handler, just return.
			return
		}
		imageID = uploadedImageID
	}
	// If no file was provided, imageID remains uuid.Nil, which is handled by the model.

	// --- Extract OwnerUserID from context (no changes needed) ---
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required: user ID not found"})
		return
	}

	// Create a business_models.Business instance from the request data
	business, err := business_models.NewBusiness(
		req.Name,
		req.Category,
		req.Address,
		req.City,
		req.State,
		req.Country,
		req.PostalCode,
		req.TaxID,
		req.About,
		req.Latitude,
		req.Longitude,
		userID,
		imageID, // Pass the new imageID
	)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create business instance: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Call the model layer to create the business in the database
	createdBusiness, err := business_models.CreateBusiness(c.Request.Context(), bc.DB, business)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create business in database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create business"})
		return
	}

	logger.InfoLogger.Infof("Business %s created successfully by user %s", createdBusiness.ID, userID)
	c.JSON(http.StatusCreated, gin.H{
		"message":  "Business created successfully!",
		"business": createdBusiness,
	})
}

// GetBusinesses handles fetching all businesses or businesses owned by the authenticated user.
func (bc *BusinessController) GetBusinesses(c *gin.Context) {
	logger.InfoLogger.Info("GetBusinesses controller called")

	// Get the authenticated user's ID from the context
	ownerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get user ID from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	businesses, err := business_models.GetBusinessesByOwnerID(c.Request.Context(), bc.DB, ownerID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to retrieve businesses for user %s: %v", ownerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve businesses"})
		return
	}

	if len(businesses) == 0 {
		logger.InfoLogger.Infof("No businesses found for user %s", ownerID)
		c.JSON(http.StatusNotFound, gin.H{"message": "No businesses found for this user."})
		return
	}

	logger.InfoLogger.Infof("Successfully retrieved %d businesses for user %s", len(businesses), ownerID)
	c.JSON(http.StatusOK, gin.H{"businesses": businesses})
}

// GetBusiness handles fetching a single business by its ID.
func (bc *BusinessController) GetBusiness(c *gin.Context) {
	logger.InfoLogger.Info("GetBusiness controller called")

	businessIDStr := c.Param("id")
	businessID, err := uuid.Parse(businessIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid business ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
		return
	}

	// Get the authenticated user's ID from the context
	ownerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get user ID from context: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	business, err := business_models.GetBusinessByID(bc.DB, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to retrieve business %s: %v", businessID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	// Ensure the retrieved business belongs to the authenticated user
	if business.OwnerID != ownerID {
		logger.WarnLogger.Warnf("User %s attempted to access business %s not owned by them", ownerID, businessID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to view this business"})
		return
	}

	logger.InfoLogger.Infof("Successfully retrieved business %s for user %s", businessID, ownerID)
	c.JSON(http.StatusOK, gin.H{"business": business})
}

// UpdateBusiness handles the HTTP request to update an existing business.
func (bc *BusinessController) UpdateBusiness(c *gin.Context) {
	logger.InfoLogger.Info("UpdateBusiness controller called")

	businessIDStr := c.Param("id")
	businessID, err := uuid.Parse(businessIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid business ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
		return
	}

	var req UpdateBusinessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid request payload for UpdateBusiness: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request data: %s", err.Error())})
		return
	}

	// --- Bad words check for relevant fields in update request ---
	if req.Name != nil && badwords.ContainsBadWords(*req.Name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Business name contains inappropriate language."})
		return
	}
	if req.Address != nil && badwords.ContainsBadWords(*req.Address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Address contains inappropriate language."})
		return
	}
	if req.About != nil && badwords.ContainsBadWords(*req.About) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "About section contains inappropriate language."})
		return
	}
	// Add checks for other string fields as needed for updates
	if req.City != nil && badwords.ContainsBadWords(*req.City) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "City name contains inappropriate language."})
		return
	}
	if req.State != nil && badwords.ContainsBadWords(*req.State) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "State name contains inappropriate language."})
		return
	}
	if req.Country != nil && badwords.ContainsBadWords(*req.Country) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Country name contains inappropriate language."})
		return
	}

	// --- Extract and parse OwnerUserID from authenticated context ---
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		if err.Error() == "authentication required: user ID not found" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}
	// --- End of OwnerUserID extraction ---

	// Fetch the existing business to check ownership
	existingBusiness, err := business_models.GetBusinessByID(bc.DB, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s: %v", businessID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	if existingBusiness.OwnerID != userID {
		logger.ErrorLogger.Warnf("User %s attempted to update business %s without ownership", userID, businessID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to update this business"})
		return
	}

	// Apply updates from the request to the existing business
	if req.Name != nil {
		existingBusiness.Name = *req.Name
	}
	if req.Category != nil {
		existingBusiness.Category = *req.Category
	}
	if req.Address != nil {
		existingBusiness.Address = *req.Address
	}
	if req.City != nil {
		existingBusiness.City = *req.City
	}
	if req.State != nil {
		existingBusiness.State = *req.State
	}
	if req.Country != nil {
		existingBusiness.Country = *req.Country
	}
	if req.PostalCode != nil {
		existingBusiness.PostalCode = *req.PostalCode
	}
	if req.TaxID != nil {
		existingBusiness.TaxID = *req.TaxID
	}
	if req.About != nil {
		existingBusiness.About = *req.About
	}
	// Update location if coordinates are within valid ranges
	// Since the Location struct has validation, any provided values are valid
	if req.Location.Latitude >= -90 && req.Location.Latitude <= 90 &&
		req.Location.Longitude >= -180 && req.Location.Longitude <= 180 {
		existingBusiness.Location.Latitude = req.Location.Latitude
		existingBusiness.Location.Longitude = req.Location.Longitude
	}
	if req.IsActive != nil {
		existingBusiness.IsActive = *req.IsActive
	}

	updatedBusiness, err := business_models.UpdateBusiness(bc.DB, existingBusiness)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update business %s in database: %v", businessID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update business"})
		return
	}

	logger.InfoLogger.Infof("Business %s updated successfully by user %s", businessID, userID)
	c.JSON(http.StatusOK, gin.H{
		"message":  "Business updated successfully!",
		"business": updatedBusiness,
	})
}

// ReplaceBusinessImage handles replacing the image for an existing business.
func (bc *BusinessController) ReplaceBusinessImage(c *gin.Context) {
	logger.InfoLogger.Info("ReplaceBusinessImage controller called")
	authHeader := c.GetHeader("Authorization")

	businessID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
		return
	}

	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	existingBusiness, err := business_models.GetBusinessByID(bc.DB, businessID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	if existingBusiness.OwnerID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to update this business"})
		return
	}

	// The image either doesn't exist (Nil UUID) or is valid.
	existingImageID := existingBusiness.ImageID.Bytes

	var newImageID uuid.UUID
	var uploadErr error

	if existingBusiness.ImageID.Valid {
		// If an image already exists, call the replacement handler.
		newImageID, uploadErr = image_handlers.HandleImageReplacement(c, authHeader, existingImageID)
	} else {
		// If no image exists, call the standard upload handler.
		newImageID, uploadErr = image_handlers.HandleImageUpload(c, authHeader)
	}

	if uploadErr != nil {
		// Error is handled by the image handler, so we just return.
		return
	}

	// Update the business record with the new image ID.
	existingBusiness.ImageID = pgtype.UUID{Bytes: newImageID, Valid: true}
	updatedBusiness, err := business_models.UpdateBusiness(bc.DB, existingBusiness)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update business with new image"})
		return
	}

	logger.InfoLogger.Infof("Image for business %s replaced successfully by user %s", businessID, userID)
	c.JSON(http.StatusOK, gin.H{
		"message":  "Business image updated successfully!",
		"business": updatedBusiness,
	})
}

// DeleteBusiness handles the HTTP request to delete a business and its associated image.
func (bc *BusinessController) DeleteBusiness(c *gin.Context) {
	logger.InfoLogger.Info("DeleteBusiness controller called")

	// 1. Validate Business ID
	businessIDStr := strings.TrimSpace(c.Param("id"))
	if businessIDStr == "" {
		logger.ErrorLogger.Error("Business ID is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Business ID is required"})
		return
	}

	businessID, err := uuid.Parse(businessIDStr)
	if err != nil {
		logger.ErrorLogger.Error("Invalid business ID format: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
		return
	}

	// 2. Authenticate User and Authorize Access
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Error("Authentication required: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	// 3. Fetch Business Details
	existingBusiness, err := business_models.GetBusinessByID(bc.DB, businessID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.ErrorLogger.Errorf("Business not found for ID %s: %v", businessID, err)
			c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		} else {
			logger.ErrorLogger.Errorf("Failed to fetch business %s: %v", businessID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch business"})
		}
		return
	}

	// 4. Authorize Owner
	if existingBusiness.OwnerID != userID {
		logger.ErrorLogger.Errorf("User %s is not authorized to delete business %s (owner: %s)", userID, businessID, existingBusiness.OwnerID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to delete this business"})
		return
	}

	// --- 5. Delete the associated image from the image service FIRST ---
	if existingBusiness.ImageID.Valid {
		imageID := existingBusiness.ImageID

		url := os.Getenv("IMAGE_SERVICE_URL") + "/images/" + imageID.String()
		if url == "" {
			// Fallback in case IMAGE_SERVICE_URL is not set
			url = "http://localhost:8082/images/" + imageID.String()
		}

		req, err := http.NewRequest("DELETE", url, nil)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to create delete image request for image ID %s: %v", imageID, err)
			// Log the error but proceed with deleting the business record anyway.
			// This prevents the record from being orphaned if the image service is down.
		} else {
			authHeader := c.GetHeader("Authorization")
			req.Header.Set("Authorization", authHeader)

			client := &http.Client{Timeout: 15 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				logger.ErrorLogger.Errorf("Image service request failed for image ID %s: %v", imageID, err)
				// Log the error but proceed with deleting the business record anyway.
			} else {
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
					body, _ := io.ReadAll(resp.Body)
					logger.ErrorLogger.Errorf("Image service returned error for image ID %s: %s", imageID, string(body))
					// Log the error but proceed with deleting the business record anyway.
				} else {
					logger.InfoLogger.Infof("Successfully deleted image %s from image service for business %s", imageID, businessID)
				}
			}
		}
	}

	// --- 6. Now delete the business record from our database ---
	if existingBusiness.ImageID.Valid {
		err = business_models.DeleteImageAndReferences(c.Request.Context(), bc.DB, uuid.UUID(existingBusiness.ImageID.Bytes))
	}
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete image %s and its references in database: %v", existingBusiness.ImageID, err)
		// Check for specific errors from DeleteImageAndReferences if you want to customize HTTP status.
		if strings.Contains(err.Error(), "image not found for deletion") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Image record not found in database"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete image and its references in database"})
		}
		return
	}

	logger.InfoLogger.Infof("Image %s and its references successfully deleted from database", existingBusiness.ImageID)
	c.Status(http.StatusNoContent) // 204 No Content is a standard successful response for DELETE
}

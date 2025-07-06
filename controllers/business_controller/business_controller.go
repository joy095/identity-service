package business_controller

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
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
	"github.com/joy095/identity/utils/shared_utils"
)

const (
	DEFAULT_BUSINESS_FETCH_LIMIT = 50  // Default number of businesses to return if limit is not specified (for lazy fetching)
	MAX_BUSINESS_FETCH_LIMIT     = 100 // Maximum number of businesses allowed in a single request
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
	PublicId   string  `form:"publicId"`
}

// UpdateBusinessRequest remains the same as it uses JSON.
type UpdateBusinessRequest struct {
	Name       *string  `json:"name,omitempty" binding:"omitempty,min=3,max=100"`
	Category   *string  `json:"category,omitempty" binding:"omitempty,min=2,max=50"`
	Address    *string  `json:"address,omitempty" binding:"omitempty,min=5,max=255"`
	City       *string  `json:"city,omitempty" binding:"omitempty,min=2,max=50"`
	State      *string  `json:"state,omitempty" binding:"omitempty,min=2,max=50"`
	Country    *string  `json:"country,omitempty" binding:"omitempty,min=2,max=50"`
	PostalCode *string  `json:"postalCode,omitempty" binding:"omitempty,min=3,max=20"`
	TaxID      *string  `json:"taxId,omitempty"`
	About      *string  `json:"about,omitempty"`
	Latitude   *float64 `form:"latitude" binding:"omitempty,min=-90,max=90"`
	Longitude  *float64 `form:"longitude" binding:"omitempty,min=-180,max=180"`
	IsActive   *bool    `json:"isActive,omitempty"`
}

func (bc *BusinessController) CreateBusiness(c *gin.Context) {
	logger.InfoLogger.Info("CreateBusiness controller called")

	var req CreateBusinessRequest
	if err := c.ShouldBind(&req); err != nil {
		logger.ErrorLogger.WithFields(map[string]interface{}{
			"error": err.Error(),
		}).Error("Failed to bind form data in CreateBusiness")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid form data"})
		return
	}

	if badwords.ContainsBadWords(req.Name) || badwords.ContainsBadWords(req.Address) ||
		badwords.ContainsBadWords(req.About) || badwords.ContainsBadWords(req.City) ||
		badwords.ContainsBadWords(req.State) || badwords.ContainsBadWords(req.Country) {
		logger.WarnLogger.WithFields(map[string]interface{}{
			"name":    req.Name,
			"address": req.Address,
			"about":   req.About,
			"city":    req.City,
			"state":   req.State,
			"country": req.Country,
		}).Warn("Rejected request due to inappropriate content")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request contains inappropriate language"})
		return
	}

	// Get access_token from cookie
	accessToken, err := c.Cookie("access_token")
	if err != nil || accessToken == "" {
		logger.ErrorLogger.WithFields(map[string]interface{}{
			"error": err,
		}).Error("Missing access_token in cookie")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication token missing in cookie"})
		return
	}

	var imageID uuid.UUID
	file, err := c.FormFile("image")
	if err != nil && err != http.ErrMissingFile {
		logger.ErrorLogger.WithFields(map[string]interface{}{
			"error": err.Error(),
		}).Error("Failed to parse image file from form data")
		image_handlers.HandleFileError(c, err)
		return
	}

	if file != nil {
		uploadedImageID, uploadErr := image_handlers.HandleImageUpload(c, accessToken)
		if uploadErr != nil {
			logger.ErrorLogger.WithFields(map[string]interface{}{
				"error": uploadErr.Error(),
			}).Error("Image upload failed")
			// error already handled in HandleImageUpload
			return
		}
		imageID = uploadedImageID
	}

	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	sanitizedName := strings.ToLower(req.Name)
	sanitizedName = strings.ReplaceAll(sanitizedName, " ", "-")
	sanitizedName = regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(sanitizedName, "")
	PublicId := sanitizedName + "-" + shared_utils.GenerateTinyID(8)

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
		PublicId,
		req.Latitude,
		req.Longitude,
		userID,
		imageID,
	)
	if err != nil {
		logger.ErrorLogger.WithFields(map[string]interface{}{
			"error": err.Error(),
		}).Error("Failed to create business model instance")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business data"})
		return
	}

	createdBusiness, err := business_models.CreateBusiness(c.Request.Context(), bc.DB, business)
	if err != nil {
		logger.ErrorLogger.WithFields(map[string]interface{}{
			"error": err.Error(),
		}).Error("Failed to create business in database")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save business to database"})
		return
	}

	logger.InfoLogger.WithFields(map[string]interface{}{
		"business_id": createdBusiness.ID,
		"user_id":     userID,
	}).Info("Business created successfully")

	c.JSON(http.StatusCreated, gin.H{
		"message":  "Business created successfully!",
		"business": createdBusiness,
	})
}

// GetBusinesses handles fetching all businesses or businesses with pagination.
func (bc *BusinessController) GetAllBusinesses(c *gin.Context) {
	logger.InfoLogger.Info("GetBusinesses controller called")

	// Parse 'limit' from query parameter, default to DEFAULT_BUSINESS_FETCH_LIMIT
	limitStr := c.DefaultQuery("limit", strconv.Itoa(DEFAULT_BUSINESS_FETCH_LIMIT))
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid limit parameter: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid 'limit' parameter. Must be an integer."})
		return
	}

	// Enforce minimum limit (e.g., no negative or zero limits)
	if limit < 1 {
		logger.WarnLogger.Warnf("Limit parameter too low (%d). Setting to default limit (%d).", limit, DEFAULT_BUSINESS_FETCH_LIMIT)
		limit = DEFAULT_BUSINESS_FETCH_LIMIT
	}

	// Enforce maximum limit
	if limit > MAX_BUSINESS_FETCH_LIMIT {
		logger.ErrorLogger.Warnf("Limit parameter exceeds maximum allowed (%d > %d). Setting to max limit.", limit, MAX_BUSINESS_FETCH_LIMIT)
		limit = MAX_BUSINESS_FETCH_LIMIT
	}

	// Parse 'offset' from query parameter, default to 0
	offsetStr := c.DefaultQuery("offset", "0")
	offset, err := strconv.Atoi(offsetStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid offset parameter: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid 'offset' parameter. Must be an integer."})
		return
	}
	// Ensure offset is not negative
	if offset < 0 {
		logger.ErrorLogger.Warnf("Negative offset parameter received (%d). Setting to 0.", offset)
		offset = 0
	}

	businesses, err := business_models.GetAllBusinesses(c.Request.Context(), bc.DB, limit, offset)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to retrieve businesses: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve businesses"})
		return
	}

	logger.InfoLogger.Infof("Successfully retrieved %d businesses", len(businesses))
	c.JSON(http.StatusOK, gin.H{"businesses": businesses})
}

// GetBusiness handles fetching a single business by its ID.
func (bc *BusinessController) GetBusiness(c *gin.Context) {
	logger.InfoLogger.Info("GetBusiness controller called")

	businessID := c.Param("publicId") // Extract publicId
	// businessID, err := uuid.Parse(businessIDStr)
	// if err != nil {
	// 	logger.ErrorLogger.Errorf("Invalid business ID format: %v", err)
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
	// 	return
	// }

	business, err := business_models.GetBusinessByPublicId(bc.DB, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to retrieve business %s: %v", businessID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	logger.InfoLogger.Infof("Successfully retrieved business %s ", businessID)
	c.JSON(http.StatusOK, gin.H{"business": business})
}

// UpdateBusiness handles the HTTP request to update an existing business.
func (bc *BusinessController) UpdateBusiness(c *gin.Context) {
	logger.InfoLogger.Info("UpdateBusiness controller called")

	publicId := c.Param("publicId")

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
	existingBusiness, err := business_models.GetBusinessByPublicId(bc.DB, publicId)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s: %v", publicId, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	if existingBusiness.OwnerID != userID {
		logger.ErrorLogger.Warnf("User %s attempted to update business %s without ownership", userID, publicId)
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
	if req.Latitude != nil {
		existingBusiness.Latitude = *req.Latitude
	}
	if req.Longitude != nil {
		existingBusiness.Longitude = *req.Longitude
	}
	if req.IsActive != nil {
		existingBusiness.IsActive = *req.IsActive
	}

	updatedBusiness, err := business_models.UpdateBusiness(bc.DB, existingBusiness)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update business %s in database: %v", publicId, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update business"})
		return
	}

	logger.InfoLogger.Infof("Business %s updated successfully by user %s", publicId, userID)
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
	existingImageID := uuid.UUID(existingBusiness.ImageID.Bytes)

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

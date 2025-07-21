package business_controller

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/joy095/identity/badwords"
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
type CreateBusinessRequest struct {
	Name       string  `form:"name" binding:"required,min=3,max=100"`
	Category   string  `form:"category" binding:"required,min=2,max=50"`
	Address    string  `form:"address,omitempty" binding:"omitempty,min=5,max=255"`
	City       string  `form:"city" binding:"required,min=2,max=50"`
	State      string  `form:"state" binding:"required,min=2,max=50"`
	Country    string  `form:"country" binding:"required,min=2,max=50"`
	PostalCode string  `form:"postalCode" binding:"omitempty,min=3,max=20"`
	TaxID      string  `form:"taxId,omitempty"`
	About      string  `form:"about,omitempty"`
	Latitude   float64 `form:"latitude" binding:"omitempty,min=-90,max=90"`
	Longitude  float64 `form:"longitude" binding:"omitempty,min=-180,max=180"`
}

// UpdateBusinessRequest represents the JSON payload for updating a business.
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
	Latitude   *float64 `json:"latitude" binding:"omitempty,min=-90,max=90"`
	Longitude  *float64 `json:"longitude" binding:"omitempty,min=-180,max=180"`
	IsActive   *bool    `json:"isActive,omitempty"`
}

func (bc *BusinessController) CreateBusiness(c *gin.Context) {
	logger.InfoLogger.Info("CreateBusiness controller called")

	var req CreateBusinessRequest
	if err := c.ShouldBind(&req); err != nil {
		logger.ErrorLogger.WithFields(map[string]interface{}{"error": err.Error()}).Error("Failed to bind form data in CreateBusiness")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid form data"})
		return
	}

	if badwords.ContainsBadWords(req.Name) || badwords.ContainsBadWords(req.Address) ||
		badwords.ContainsBadWords(req.About) || badwords.ContainsBadWords(req.City) ||
		badwords.ContainsBadWords(req.State) || badwords.ContainsBadWords(req.Country) {
		logger.WarnLogger.Warn("Rejected request due to inappropriate content")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request contains inappropriate language"})
		return
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
	tinyID, err := shared_utils.GenerateTinyID(8)
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate tiny ID")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
		return
	}
	publicId := sanitizedName + "-" + tinyID

	business, err := business_models.NewBusiness(
		req.Name, req.Category, req.Address, req.City, req.State, req.Country,
		req.PostalCode, req.TaxID, req.About, publicId, req.Latitude, req.Longitude, userID,
	)
	if err != nil {
		logger.ErrorLogger.WithFields(map[string]interface{}{"error": err.Error()}).Error("Failed to create business model instance")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business data"})
		return
	}

	createdBusiness, err := business_models.CreateBusiness(c.Request.Context(), bc.DB, business)
	if err != nil {
		logger.ErrorLogger.WithFields(map[string]interface{}{"error": err.Error()}).Error("Failed to create business in database")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save business to database"})
		return
	}

	logger.InfoLogger.WithFields(map[string]interface{}{"business_id": createdBusiness.ID, "sub": userID}).Info("Business created successfully")
	c.JSON(http.StatusCreated, gin.H{"message": "Business created successfully!", "business": createdBusiness})
}

func (bc *BusinessController) GetAllBusinesses(c *gin.Context) {
	logger.InfoLogger.Info("GetBusinesses controller called")

	limitStr := c.DefaultQuery("limit", strconv.Itoa(DEFAULT_BUSINESS_FETCH_LIMIT))
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid 'limit' parameter. Must be an integer."})
		return
	}
	if limit < 1 {
		limit = DEFAULT_BUSINESS_FETCH_LIMIT
	}
	if limit > MAX_BUSINESS_FETCH_LIMIT {
		limit = MAX_BUSINESS_FETCH_LIMIT
	}

	offsetStr := c.DefaultQuery("offset", "0")
	offset, err := strconv.Atoi(offsetStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid 'offset' parameter. Must be an integer."})
		return
	}
	if offset < 0 {
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

func (bc *BusinessController) GetBusiness(c *gin.Context) {
	logger.InfoLogger.Info("GetBusiness controller called")
	businessID := c.Param("publicId")
	business, err := business_models.GetBusinessByPublicId(c.Request.Context(), bc.DB, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to retrieve business %s: %v", businessID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}
	logger.InfoLogger.Infof("Successfully retrieved business %s ", businessID)
	c.JSON(http.StatusOK, gin.H{"business": business})
}

// GetNotActiveBusinessByUser handles the request to get all inactive businesses for the authenticated user.
func (bc *BusinessController) GetNotActiveBusinessByUser(c *gin.Context) {
	logger.InfoLogger.Info("GetNotActiveBusinessByUser controller called")

	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Error(`{"level":"error","message":"User ID not found in context","service":"identity-service"}`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	// Call the model function to get all inactive businesses
	businesses, err := business_models.GetNotActiveBusinessByUserModel(c.Request.Context(), bc.DB, userID)
	if err != nil {
		logger.ErrorLogger.Errorf(`{"level":"error","message":"Failed to retrieve businesses for user: %v","service":"identity-service"}`, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve businesses"})
		return
	}

	// Log the number of businesses found
	logger.InfoLogger.Infof("Successfully retrieved %d inactive businesses for user ID %s", len(businesses), userID)

	// Send response back to client
	c.JSON(http.StatusOK, gin.H{
		"businesses": businesses, // Changed key from "business" to "businesses" to reflect multiple items
	})
}

func (bc *BusinessController) UpdateBusiness(c *gin.Context) {
	logger.InfoLogger.Info("UpdateBusiness controller called")
	publicId := c.Param("publicId")

	var req UpdateBusinessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request data: %s", err.Error())})
		return
	}

	if req.Name != nil && badwords.ContainsBadWords(*req.Name) ||
		req.Address != nil && badwords.ContainsBadWords(*req.Address) ||
		req.About != nil && badwords.ContainsBadWords(*req.About) ||
		req.City != nil && badwords.ContainsBadWords(*req.City) ||
		req.State != nil && badwords.ContainsBadWords(*req.State) ||
		req.Country != nil && badwords.ContainsBadWords(*req.Country) {
		logger.WarnLogger.Warn("Rejected update request due to inappropriate content")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request contains inappropriate language"})
		return
	}

	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	existingBusiness, err := business_models.GetBusinessByPublicId(c.Request.Context(), bc.DB, publicId)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	if existingBusiness.OwnerID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to update this business"})
		return
	}

	// Apply updates from the request
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

	updatedBusiness, err := business_models.UpdateBusiness(c.Request.Context(), bc.DB, existingBusiness)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update business"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Business updated successfully!", "business": updatedBusiness})
}

func (bc *BusinessController) DeleteBusiness(c *gin.Context) {
	logger.InfoLogger.Info("DeleteBusiness controller called")
	publicId := c.Param("publicId")
	if publicId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Business publicId is required"})
		return
	}

	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	existingBusiness, err := business_models.GetBusinessByPublicId(c.Request.Context(), bc.DB, publicId)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || strings.Contains(err.Error(), "not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch business"})
		}
		return
	}

	if existingBusiness.OwnerID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to delete this business"})
		return
	}

	accessToken, err := c.Cookie("access_token")
	if err != nil || accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication token missing in cookie"})
		return
	}

	// Delete associated data first (images, services, etc.)
	err = business_models.DeleteImageAndReferences(c.Request.Context(), bc.DB, existingBusiness.ID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete business %s: %v", publicId, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete business"})
		return
	}

	// Delete the business
	err = business_models.DeleteBusiness(c.Request.Context(), bc.DB, existingBusiness.ID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to delete business %s: %v", publicId, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete business"})
		return
	}

	logger.InfoLogger.Infof("Business %s and all data deleted by user %s", publicId, userID)
	c.JSON(http.StatusOK, gin.H{"message": "Business and all associated images deleted successfully!"})
}

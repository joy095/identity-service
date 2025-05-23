package controllers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/joy095/identity/badwords" // Import your badwords package
	"github.com/joy095/identity/logger"   // Adjust import path for your logger
	"github.com/joy095/identity/models"   // Import your models package
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

type Location struct {
	// Latitude should be between -90 and +90
	Latitude float64 `json:"latitude" binding:"required,min=-90,max=90"`
	// Longitude should be between -180 and +180
	Longitude float64 `json:"longitude" binding:"required,min=-180,max=180"`
}

// CreateBusinessRequest represents the expected JSON payload for creating a business.
// This is separate from the models.Business struct to allow for input validation rules
// and to exclude fields like ID, CreatedAt, UpdatedAt that are set by the server.
type CreateBusinessRequest struct {
	Name       string   `json:"name" binding:"required,min=3,max=100"`
	Category   string   `json:"category" binding:"required,min=2,max=50"`
	Address    string   `json:"address,omitempty,min=5,max=255"`
	City       string   `json:"city" binding:"required,min=2,max=50"`
	State      string   `json:"state" binding:"required,min=2,max=50"`
	Country    string   `json:"country" binding:"required,min=2,max=50"`
	PostalCode string   `json:"postalCode" binding:"required,min=3,max=20"`
	TaxID      string   `json:"taxId,omitempty"`
	About      string   `json:"about,omitempty"`
	Location   Location `json:"location"`
	// OwnerUserID will be extracted from the authenticated user's context, not from the request body.
}

// UpdateBusinessRequest represents the expected JSON payload for updating a business.
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
	Location   Location `json:"location"`
	IsActive   *bool    `json:"isActive,omitempty"`
}

// getUserIDFromContext extracts and parses the user ID from the Gin context.
// It returns the parsed UUID and an error if extraction or parsing fails.
func getUserIDFromContext(c *gin.Context) (uuid.UUID, error) {
	ownerUserID, exists := c.Get("user_id") // Use "user_id" as per your code
	if !exists {
		logger.ErrorLogger.Error("User ID not found in context.")
		return uuid.Nil, fmt.Errorf("authentication required: user ID not found")
	}

	// Attempt to cast to string first, as it's a common way user IDs are stored
	userIDStr, ok := ownerUserID.(string)
	if !ok {
		logger.ErrorLogger.Errorf("User ID in context is not a string, actual type: %T", ownerUserID)
		return uuid.Nil, fmt.Errorf("internal server error: invalid user ID format in context")
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse user ID string '%s' to UUID: %v", userIDStr, err)
		return uuid.Nil, fmt.Errorf("internal server error: invalid user ID format")
	}
	return userID, nil
}

// CreateBusiness handles the HTTP request to create a new business.
func (bc *BusinessController) CreateBusiness(c *gin.Context) {
	logger.InfoLogger.Info("CreateBusiness controller called")

	var req CreateBusinessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid request payload for CreateBusiness: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request data: %s", err.Error())})
		return
	}

	// --- Bad words check for relevant fields ---
	if badwords.ContainsBadWords(req.Name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Business name contains inappropriate language."})
		return
	}
	if req.Address != "" && badwords.ContainsBadWords(req.Address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Address contains inappropriate language."})
		return
	}
	if req.About != "" && badwords.ContainsBadWords(req.About) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "About section contains inappropriate language."})
		return
	}
	// Add checks for other string fields as needed (e.g., City, State, Country, etc.)
	if badwords.ContainsBadWords(req.City) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "City name contains inappropriate language."})
		return
	}
	if badwords.ContainsBadWords(req.State) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "State name contains inappropriate language."})
		return
	}
	if badwords.ContainsBadWords(req.Country) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Country name contains inappropriate language."})
		return
	}

	// --- Extract and parse OwnerUserID from authenticated context ---
	userID, err := getUserIDFromContext(c)
	if err != nil {
		if err.Error() == "authentication required: user ID not found" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}
	// --- End of OwnerUserID extraction ---

	// Create a models.Business instance from the request data
	business := models.NewBusiness(
		req.Name,
		req.Category,
		req.Address,
		req.City,
		req.State,
		req.Country,
		req.PostalCode,
		req.TaxID,
		req.About,
		req.Location.Longitude,
		req.Location.Longitude,
		userID, // Pass the extracted owner user ID
	)

	// Call the model layer to create the business in the database
	createdBusiness, err := models.CreateBusiness(bc.DB, business)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create business in database: %v", err)
		// Check for specific error types if needed (e.g., duplicate name)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create business"})
		return
	}

	logger.InfoLogger.Infof("Business %s created successfully by user %s", createdBusiness.ID, userID)
	c.JSON(http.StatusCreated, gin.H{
		"message":  "Business created successfully!",
		"business": createdBusiness, // Return the full created business object
	})
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

	ownerUserID, exists := c.Get("userID")
	if !exists {
		logger.ErrorLogger.Error("OwnerUserID not found in context for UpdateBusiness")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	userID, ok := ownerUserID.(uuid.UUID)
	if !ok {
		logger.ErrorLogger.Error("OwnerUserID in context is not of type uuid.UUID")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: Invalid user ID format"})
		return
	}

	// Fetch the existing business to check ownership
	existingBusiness, err := models.GetBusinessByID(bc.DB, businessID)
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
	existingBusiness.Location.Latitude = req.Location.Latitude
	existingBusiness.Location.Longitude = req.Location.Longitude
	if req.IsActive != nil {
		existingBusiness.IsActive = *req.IsActive
	}

	updatedBusiness, err := models.UpdateBusiness(bc.DB, existingBusiness)
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

// DeleteBusiness handles the HTTP request to delete a business.
func (bc *BusinessController) DeleteBusiness(c *gin.Context) {
	logger.InfoLogger.Info("DeleteBusiness controller called")

	businessIDStr := c.Param("id")
	businessID, err := uuid.Parse(businessIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid business ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
		return
	}

	ownerUserID, exists := c.Get("userID")
	if !exists {
		logger.ErrorLogger.Error("OwnerUserID not found in context for DeleteBusiness")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	userID, ok := ownerUserID.(uuid.UUID)
	if !ok {
		logger.ErrorLogger.Error("OwnerUserID in context is not of type uuid.UUID")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: Invalid user ID format"})
		return
	}

	// Fetch the existing business to check ownership
	existingBusiness, err := models.GetBusinessByID(bc.DB, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for deletion: %v", businessID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	if existingBusiness.OwnerID != userID {
		logger.ErrorLogger.Warnf("User %s attempted to delete business %s without ownership", userID, businessID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to delete this business"})
		return
	}

	if err := models.DeleteBusiness(bc.DB, businessID); err != nil {
		logger.ErrorLogger.Errorf("Failed to delete business %s from database: %v", businessID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete business"})
		return
	}

	logger.InfoLogger.Infof("Business %s deleted successfully by user %s", businessID, userID)
	c.JSON(http.StatusOK, gin.H{"message": "Business deleted successfully"})
}

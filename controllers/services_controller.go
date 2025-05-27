// controllers/service_controller.go
package controllers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/joy095/identity/badwords" // Adjust import path
	"github.com/joy095/identity/logger"   // Adjust import path
	"github.com/joy095/identity/models"   // Adjust import path
	"github.com/joy095/identity/utils"
)

// ServiceController holds dependencies for service-related operations.
type ServiceController struct {
	DB *pgxpool.Pool
}

// NewServiceController creates a new instance of ServiceController.
func NewServiceController(db *pgxpool.Pool) *ServiceController {
	return &ServiceController{
		DB: db,
	}
}

// CreateServiceRequest represents the expected JSON payload for creating a service.
type CreateServiceRequest struct {
	BusinessID      uuid.UUID `json:"businessId" binding:"required"`
	Name            string    `json:"name" binding:"required,min=3,max=100"`
	Description     string    `json:"description,omitempty"`
	DurationMinutes int       `json:"durationMinutes" binding:"required,min=15"` // Duration must be at least 15 minutes
	Price           float64   `json:"price" binding:"required,min=60"`           // Minimum price is 60
}

// UpdateServiceRequest represents the expected JSON payload for updating a service.
type UpdateServiceRequest struct {
	Name            *string  `json:"name,omitempty" binding:"omitempty,min=3,max=100"`
	Description     *string  `json:"description,omitempty"`
	DurationMinutes *int     `json:"durationMinutes,omitempty" binding:"omitempty,min=15"`
	Price           *float64 `json:"price,omitempty" binding:"omitempty,min=60"`
	IsActive        *bool    `json:"isActive,omitempty"`
}

// CreateService handles the HTTP request to create a new service.
func (sc *ServiceController) CreateService(c *gin.Context) {
	logger.InfoLogger.Info("CreateService controller called")

	var req CreateServiceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid request payload for CreateService: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request data: %s", err.Error())})
		return
	}

	// --- Bad words check for relevant fields ---
	if badwords.ContainsBadWords(req.Name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service name contains inappropriate language."})
		return
	}
	if req.Description != "" && badwords.ContainsBadWords(req.Description) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service description contains inappropriate language."})
		return
	}

	// Extract user ID from authenticated context (to ensure business ownership)
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		if err.Error() == "authentication required: user ID not found" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	// Verify that the business exists and belongs to the authenticated user
	business, err := models.GetBusinessByID(sc.DB, req.BusinessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for service creation: %v", req.BusinessID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Associated business not found"})
		return
	}

	if business.OwnerID != ownerUserID {
		logger.ErrorLogger.Warnf("User %s attempted to create service for unowned business %s", ownerUserID, req.BusinessID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to add services to this business"})
		return
	}

	// Create a models.Service instance
	service := models.NewService(
		req.BusinessID,
		req.Name,
		req.Description,
		req.DurationMinutes,
		req.Price,
	)

	createdService, err := models.CreateService(sc.DB, service)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create service in database: %v", err)
		// Check for specific errors, e.g., if business_id doesn't exist
		if strings.Contains(err.Error(), "foreign key constraint") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID provided"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create service"})
		}
		return
	}

	logger.InfoLogger.Infof("Service %s created successfully for business %s by user %s", createdService.ID, req.BusinessID, ownerUserID)
	c.JSON(http.StatusCreated, gin.H{
		"message": "Service created successfully!",
		"service": createdService,
	})
}

// GetServiceByID handles fetching a single service.
func (sc *ServiceController) GetServiceByID(c *gin.Context) {
	logger.InfoLogger.Info("GetServiceByID controller called")

	serviceIDStr := c.Param("id")
	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid service ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID format"})
		return
	}

	service, err := models.GetServiceByID(sc.DB, serviceID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch service %s: %v", serviceID, err)
		if strings.Contains(err.Error(), "service not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch service"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"service": service})
}

// GetServicesByBusinessID handles fetching all services for a specific business.
func (sc *ServiceController) GetServicesByBusinessID(c *gin.Context) {
	logger.InfoLogger.Info("GetServicesByBusinessID controller called")

	businessIDStr := c.Param("business_id") // Assuming /business/:business_id/services
	businessID, err := uuid.Parse(businessIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid business ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID format"})
		return
	}

	services, err := models.GetServicesByBusinessID(sc.DB, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch services for business %s: %v", businessID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch services"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"services": services})
}

// UpdateService handles the HTTP request to update an existing service.
func (sc *ServiceController) UpdateService(c *gin.Context) {
	logger.InfoLogger.Info("UpdateService controller called")

	serviceIDStr := c.Param("id")
	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid service ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID format"})
		return
	}

	var req UpdateServiceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid request payload for UpdateService: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid request data: %s", err.Error())})
		return
	}

	// --- Bad words check for relevant fields ---
	if req.Name != nil && badwords.ContainsBadWords(*req.Name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service name contains inappropriate language."})
		return
	}
	if req.Description != nil && badwords.ContainsBadWords(*req.Description) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service description contains inappropriate language."})
		return
	}

	// Extract user ID from authenticated context (to ensure business ownership)
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		if err.Error() == "authentication required: user ID not found" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	// Fetch the existing service to get its business_id and check ownership
	existingService, err := models.GetServiceByID(sc.DB, serviceID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch service %s for update: %v", serviceID, err)
		if strings.Contains(err.Error(), "service not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch service"})
		}
		return
	}

	// Verify that the business associated with this service belongs to the authenticated user
	business, err := models.GetBusinessByID(sc.DB, existingService.BusinessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for service %s ownership check: %v", existingService.BusinessID, serviceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: business lookup failed"})
		return
	}

	if business.OwnerID != ownerUserID {
		logger.ErrorLogger.Warnf("User %s attempted to update service %s for unowned business %s", ownerUserID, serviceID, existingService.BusinessID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to update this service"})
		return
	}

	// Apply updates from the request to the existing service
	if req.Name != nil {
		existingService.Name = *req.Name
	}
	if req.Description != nil {
		existingService.Description = *req.Description
	}
	if req.DurationMinutes != nil {
		existingService.DurationMinutes = *req.DurationMinutes
	}
	if req.Price != nil {
		existingService.Price = *req.Price
	}
	if req.IsActive != nil {
		existingService.IsActive = *req.IsActive
	}

	updatedService, err := models.UpdateService(sc.DB, existingService)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update service %s in database: %v", serviceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update service"})
		return
	}

	logger.InfoLogger.Infof("Service %s updated successfully by user %s", serviceID, ownerUserID)
	c.JSON(http.StatusOK, gin.H{
		"message": "Service updated successfully!",
		"service": updatedService,
	})
}

// DeleteService handles the HTTP request to delete a service.
func (sc *ServiceController) DeleteService(c *gin.Context) {
	logger.InfoLogger.Info("DeleteService controller called")

	serviceIDStr := c.Param("id")
	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid service ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID format"})
		return
	}

	// Extract user ID from authenticated context (to ensure business ownership)
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		if err.Error() == "authentication required: user ID not found" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	// Fetch the existing service to get its business_id and check ownership
	existingService, err := models.GetServiceByID(sc.DB, serviceID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch service %s for deletion: %v", serviceID, err)
		if strings.Contains(err.Error(), "service not found") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch service"})
		}
		return
	}

	// Verify that the business associated with this service belongs to the authenticated user
	business, err := models.GetBusinessByID(sc.DB, existingService.BusinessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for service %s ownership check: %v", existingService.BusinessID, serviceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: business lookup failed"})
		return
	}

	if business.OwnerID != ownerUserID {
		logger.ErrorLogger.Warnf("User %s attempted to delete service %s for unowned business %s", ownerUserID, serviceID, existingService.BusinessID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to delete this service"})
		return
	}

	if err := models.DeleteService(sc.DB, serviceID, existingService.BusinessID); err != nil {
		logger.ErrorLogger.Errorf("Failed to delete service %s from database: %v", serviceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete service"})
		return
	}

	logger.InfoLogger.Infof("Service %s deleted successfully by user %s", serviceID, ownerUserID)
	c.JSON(http.StatusOK, gin.H{"message": "Service deleted successfully"})
}

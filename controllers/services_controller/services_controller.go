package services_controller

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/service_models"
)

type ServiceController struct{}

// NewServiceController creates and returns a new instance of ServiceController
func NewServiceController() *ServiceController {
	return &ServiceController{}
}

type CreateServiceRequest struct {
	BusinessID      string  `form:"businessId" binding:"required"`
	Name            string  `form:"name" binding:"required"`
	Description     string  `form:"description,omitempty"`
	DurationMinutes int     `form:"durationMinutes" binding:"required"`
	Price           float64 `form:"price" binding:"required"`
	IsActive        bool    `form:"isActive,omitempty"`
}

type ImageUploadResponse struct {
	ImageID uuid.UUID `json:"image_id"`
}

func (sc *ServiceController) GetServiceByID(c *gin.Context) {
	logger.InfoLogger.Info("GetServiceByID controller called")

	serviceIDStr := strings.TrimSpace(c.Param("id"))
	if serviceIDStr == "" {
		logger.ErrorLogger.Error("Service ID is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service ID is required"})
		return
	}

	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		logger.ErrorLogger.Error("Invalid service ID format: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID format"})
		return
	}

	service, err := service_models.GetServiceByIDModel(db.DB, serviceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.ErrorLogger.Error("Service not found: " + err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": "Service not found"})

		} else {
			logger.ErrorLogger.Error("Failed to fetch service: " + err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to fetch service"})

		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"service": service})
}

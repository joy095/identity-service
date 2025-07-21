package services_controller

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
	"github.com/jackc/pgx/v5"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/service_models"
	"github.com/joy095/identity/models/shared_models"
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

func (sc *ServiceController) GetAllServiceByBusiness(c *gin.Context) {
	logger.InfoLogger.Info("GetAllServiceByBusiness controller called")

	businessIDStr := strings.TrimSpace(c.Param("businessId"))

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

	services, err := service_models.GetAllServicesModel(c.Request.Context(), db.DB, businessID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.ErrorLogger.Error("Service not found: " + err.Error())
			c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})

		} else {
			logger.ErrorLogger.Error("Failed to fetch service: " + err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch service"})

		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"service": services})
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

	service, err := service_models.GetServiceByIDModel(c.Request.Context(), db.DB, serviceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.ErrorLogger.Error("Service not found: " + err.Error())
			c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})

		} else {
			logger.ErrorLogger.Error("Failed to fetch service: " + err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch service"})

		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"service": service})
}

// --- Delete Service by ID ---
func (sc *ServiceController) DeleteService(c *gin.Context) {
	logger.InfoLogger.Info("DeleteService controller called")

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

	service, err := service_models.GetServiceByIDModel(c.Request.Context(), db.DB, serviceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.ErrorLogger.Error("Service not found: " + err.Error())
			c.JSON(http.StatusNotFound, gin.H{"error": "Service not found"})

		} else {
			logger.ErrorLogger.Error("Failed to fetch service: " + err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch service"})

		}
		logger.ErrorLogger.Error("Failed to delete service: " + err.Error())
		return
	}

	if service.ImageID.Bytes == uuid.Nil {
		logger.InfoLogger.Info("No image associated with service, skipping image deletion")
	} else {
		imageServiceURL := os.Getenv("IMAGE_SERVICE_URL")
		if imageServiceURL == "" {
			imageServiceURL = "http://localhost:8082"
		}
		url := fmt.Sprintf("%s/images/%s", strings.TrimRight(imageServiceURL, "/"), service.ImageID.String())

		req, err := http.NewRequest("DELETE", url, nil)
		if err != nil {
			logger.ErrorLogger.Error("Failed to create delete request: " + err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create image deletion request"})

			return
		}

		// authHeader := c.GetHeader("Authorization")
		// req.Header.Set("Authorization", authHeader)

		accessToken, err := c.Cookie("access_token")
		if err != nil || accessToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication token missing in cookie"})
			return
		}

		if err := shared_models.SetJWTCookie(c, "access_token", accessToken, shared_models.ACCESS_TOKEN_EXPIRY, "/"); err != nil {
			logger.ErrorLogger.Errorf("Failed to set access token cookie: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set access token cookie"})
			return
		}

		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			logger.ErrorLogger.Error("Failed to delete image: " + err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete image from image service"})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			body, _ := io.ReadAll(resp.Body)
			logger.ErrorLogger.Error("Image service returned error: " + string(body))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete associated image"})
			return
		}

		err = service_models.DeleteServiceByIDModel(req.Context(), db.DB, serviceID, service.BusinessID)
		if err != nil {
			logger.ErrorLogger.Error("Failed to delete service: " + err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to delete service"})
			logger.ErrorLogger.Error("Failed to delete service: " + err.Error())
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Service deleted successfully with ID " + serviceID.String()})
	}
}

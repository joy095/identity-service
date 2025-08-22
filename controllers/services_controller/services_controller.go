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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/business_models"
	"github.com/joy095/identity/models/service_models"
	"github.com/joy095/identity/models/shared_models"
)

type ServiceController struct{ db *pgxpool.Pool }

// NewServiceController creates and returns a new instance of ServiceController
func NewServiceController(db *pgxpool.Pool) (*ServiceController, error) {
	if db == nil {
		return nil, errors.New("database pool cannot be nil")
	}

	return &ServiceController{
		db: db,
	}, nil
}

type CreateServiceRequest struct {
	BusinessID  string  `form:"businessId" binding:"required"`
	Name        string  `form:"name" binding:"required"`
	Description string  `form:"description,omitempty"`
	Duration    int     `form:"duration" binding:"required"`
	Price       float64 `form:"price" binding:"required"`
	IsActive    bool    `form:"isActive,omitempty"`
}

type ImageUploadResponse struct {
	ImageID uuid.UUID `json:"image_id"`
}

func (sc *ServiceController) GetAllServiceByBusiness(c *gin.Context) {
	logger.InfoLogger.Info("GetAllServiceByBusiness controller called")

	publicId := c.Param("publicId")

	businessId, err := business_models.GetBusinessIdOnly(c.Request.Context(), sc.db, publicId)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get business by publicId: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	services, err := service_models.GetAllServicesModel(c.Request.Context(), sc.db, businessId)
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

	service, err := service_models.GetServiceByIDModel(c.Request.Context(), sc.db, serviceID)
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

func (sc *ServiceController) IsServiceBusiness(c *gin.Context) {
	logger.InfoLogger.Info("IsServiceBusiness controller called")

	publicId := strings.TrimSpace(c.Param("publicId"))
	if publicId == "" {
		logger.ErrorLogger.Error("Public ID is required")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Public ID is required"})
		return
	}

	// Get business ID from publicId
	businessId, err := business_models.GetBusinessIdOnly(c.Request.Context(), sc.db, publicId)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get business by publicId: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	// Check if service exists for this business
	exists, err := service_models.IsServiceBusiness(c.Request.Context(), sc.db, businessId)
	if err != nil {
		logger.ErrorLogger.Error("Failed to check service availability: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check service availability"})
		return
	}

	// Return only true/false
	c.JSON(http.StatusOK, gin.H{"available": exists})
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

	service, err := service_models.GetServiceByIDModel(c.Request.Context(), sc.db, serviceID)
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

		err = service_models.DeleteServiceByIDModel(c.Request.Context(), sc.db, serviceID, service.BusinessID)
		if err != nil {
			logger.ErrorLogger.Error("Failed to delete service: " + err.Error())
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to delete service"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Service deleted successfully with ID " + serviceID.String()})
	}
}

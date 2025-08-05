// handlers/service_handlers/service_handler.go
package service_handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/business_models"
	"github.com/joy095/identity/models/service_models"
)

type CreateServiceRequest struct {
	Name        string `form:"name" binding:"required"`
	Description string `form:"description,omitempty"`
	Duration    int    `form:"duration" binding:"required"`
	Price       int64  `form:"price" binding:"required"`
	IsActive    bool   `form:"isActive,omitempty"`
}

type UpdateServiceRequest struct {
	Name        *string `form:"name"`
	Description *string `form:"description"`
	Duration    *int    `form:"duration"`
	Price       *int64  `form:"price"`
	IsActive    *bool   `form:"isActive"`
}

type ImageUploadResponse struct {
	ImageID uuid.UUID `json:"image_id"`
}

func CreateService(c *gin.Context) {
	logger.InfoLogger.Info("Received new request for /create-service")

	var req CreateServiceRequest
	if err := c.ShouldBind(&req); err != nil {
		logger.ErrorLogger.Errorf("Failed to bind form data: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid form data", "details": err.Error()})
		return
	}

	publicId := c.Param("publicId")

	bc := db.DB
	if bc == nil {
		logger.ErrorLogger.Error("Database connection not initialized")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection error"})
		return
	}

	businessUUID, err := business_models.GetBusinessIdOnly(c.Request.Context(), bc, publicId)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get business by publicId: %s, %s", publicId, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Business not found"})
		return
	}

	// Log the business ID
	logger.InfoLogger.Infof("Creating service for business ID: %s", businessUUID)

	accessToken, err := c.Cookie("access_token")
	if err != nil || accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication token missing in cookie"})
		return
	}
	imageID, err := HandleImageUpload(c, accessToken)
	if err != nil {
		return
	}

	service := service_models.NewService(businessUUID, req.Name, req.Description, req.Duration, req.Price)
	service.IsActive = req.IsActive
	service.ImageID = pgtype.UUID{Bytes: imageID, Valid: true}

	createdService, err := service_models.CreateServiceModel(c.Request.Context(), db.DB, service)
	if err != nil {
		HandleServiceCreationError(c, err)
		return
	}

	logger.InfoLogger.Infof("Service '%s' created successfully for business ID: %s with image ID: %s",
		createdService.Name, businessUUID, imageID)
	c.JSON(http.StatusCreated, gin.H{
		"message": "Service created successfully!",
		"service": createdService,
	})
}

func HandleImageUpload(c *gin.Context, authHeader string) (uuid.UUID, error) {
	fileHeader, err := c.FormFile("image")
	if err != nil {
		handleFileError(c, err)
		return uuid.Nil, err
	}

	file, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open uploaded file"})
		return uuid.Nil, err
	}
	defer file.Close()

	body, contentType, err := prepareMultipartRequest(file, fileHeader)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare image upload"})
		return uuid.Nil, err
	}
	imageID, err := sendImageToService(body, contentType, authHeader)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return uuid.Nil, err
	}

	return imageID, nil
}

// Helper functions...
func handleFileError(c *gin.Context, err error) {
	if err == http.ErrMissingFile {
		logger.ErrorLogger.Error("Form file 'image' is missing from the request.")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Image file is required for service creation"})
		return
	}
	logger.ErrorLogger.Errorf("Could not get form file 'image': %v", err)
	c.JSON(http.StatusBadRequest, gin.H{"error": "Could not process image file"})
}

func HandleServiceCreationError(c *gin.Context, err error) {
	logger.ErrorLogger.Errorf("Failed to create service in database: %v", err)
	if strings.Contains(err.Error(), "duplicate key value") {
		c.JSON(http.StatusConflict, gin.H{"error": "A service with this name already exists for this business."})
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create service in the database."})
	}
}

func prepareMultipartRequest(file multipart.File, fileHeader *multipart.FileHeader) (*bytes.Buffer, string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	originalContentType := fileHeader.Header.Get("Content-Type")
	if originalContentType == "" {
		originalContentType = "application/octet-stream"
	}

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "image", fileHeader.Filename))
	h.Set("Content-Type", originalContentType)

	part, err := writer.CreatePart(h)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create multipart: %v", err)
		return nil, "", fmt.Errorf("failed to create multipart: %w", err)
	}
	if _, err := io.Copy(part, file); err != nil {
		logger.ErrorLogger.Errorf("Failed to copy file content: %v", err)
		return nil, "", fmt.Errorf("failed to copy file content: %w", err)
	}
	if err := writer.Close(); err != nil {
		logger.ErrorLogger.Errorf("Failed to close multipart writer: %v", err)
		return nil, "", fmt.Errorf("failed to copy file content: %w", err)
	}

	return body, writer.FormDataContentType(), nil
}

func sendImageToService(body *bytes.Buffer, contentType string, authHeader string) (uuid.UUID, error) {

	pythonServerURL := os.Getenv("IMAGE_SERVICE_URL") + "/upload-image/"
	if pythonServerURL == "" {
		pythonServerURL = "http://localhost:8082/upload-image/"
	}

	httpReq, err := http.NewRequest("POST", pythonServerURL, body)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", contentType)
	httpReq.AddCookie(&http.Cookie{
		Name:  "access_token",
		Value: authHeader,
	})

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to send request to image service")
	}
	defer resp.Body.Close()

	return processImageResponse(resp)
}

func updateImageToService(body *bytes.Buffer, contentType, authHeader string, imageID uuid.UUID) (uuid.UUID, error) {

	pythonServerURL := os.Getenv("IMAGE_SERVICE_URL") + "/replace-image/" + imageID.String()
	if pythonServerURL == "" {
		pythonServerURL = "http://localhost:8082/replace-image/" + imageID.String()
	}

	httpReq, err := http.NewRequest("PUT", pythonServerURL, body)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", contentType)
	httpReq.AddCookie(&http.Cookie{
		Name:  "access_token",
		Value: authHeader,
	})

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to send request to image service")
	}
	defer resp.Body.Close()

	return processImageResponse(resp)
}

func processImageResponse(resp *http.Response) (uuid.UUID, error) {
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to read response from image service")
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return uuid.Nil, fmt.Errorf("image service returned error: %s", string(responseBody))
	}

	var imgResp ImageUploadResponse
	if err := json.Unmarshal(responseBody, &imgResp); err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse response from image service")
	}

	if imgResp.ImageID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("image service returned invalid image ID")
	}

	return imgResp.ImageID, nil
}

// handlers/service_handlers.go
func UpdateService(c *gin.Context) {
	logger.InfoLogger.Info("Received new request for /update-service")

	serviceIDStr := c.Param("id")
	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid Service ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID format."})
		return
	}

	var req UpdateServiceRequest
	if err := c.ShouldBind(&req); err != nil {
		logger.ErrorLogger.Errorf("Failed to bind form data for update: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid form data", "details": err.Error()})
		return
	}

	existingService, err := service_models.GetServiceByIDModel(c.Request.Context(), db.DB, serviceID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			logger.ErrorLogger.Errorf("Service with ID %s not found", serviceIDStr)
			c.JSON(http.StatusNotFound, gin.H{"error": "Service not found."})
			return
		}
		logger.ErrorLogger.Errorf("Failed to retrieve service from database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve service."})
		return
	}

	if req.Name != nil {
		existingService.Name = *req.Name
	}
	if req.Description != nil {
		existingService.Description = *req.Description
	}
	if req.Duration != nil {
		existingService.Duration = *req.Duration
	}
	if req.Price != nil {
		existingService.Price = *req.Price
	}
	if req.IsActive != nil {
		existingService.IsActive = *req.IsActive
	}

	fileHeader, err := c.FormFile("image")
	if err == nil {
		// New image provided, upload it and update the ID

		file, err := fileHeader.Open()
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to open new image: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open image file."})
			return
		}
		defer file.Close()

		body, contentType, err := prepareMultipartRequest(file, fileHeader)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare image upload"})
			return
		}

		// Use the existing image ID
		imageID := existingService.ImageID.Bytes
		accessToken, err := c.Cookie("access_token")
		if err != nil || accessToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication token missing in cookie"})
			return
		}

		_, updateErr := updateImageToService(body, contentType, accessToken, imageID) //
		if updateErr != nil {
			logger.ErrorLogger.Errorf("Failed to update image for service %s: %v", serviceID, updateErr)
			c.JSON(http.StatusBadGateway, gin.H{"error": "Image update failed: " + updateErr.Error()})
			return
		}
		logger.InfoLogger.Infof("Replaced image for service %s (Image ID: %s)", serviceID, imageID)

	} else if err != http.ErrMissingFile {
		// An error other than "no file" occurred
		logger.ErrorLogger.Errorf("Error checking for new image file: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Could not process image file for update"})
		return
	}

	updatedService, err := service_models.UpdateServiceModel(c.Request.Context(), db.DB, existingService)
	if err != nil {
		HandleServiceCreationError(c, err) // Can reuse the same error handler for conflicts
		return
	}

	logger.InfoLogger.Infof("Service '%s' (ID: %s) updated successfully", updatedService.Name, serviceIDStr)
	c.JSON(http.StatusOK, gin.H{
		"message": "Service updated successfully!",
		"service": updatedService,
	})
}

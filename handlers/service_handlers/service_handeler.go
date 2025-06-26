// handlers/service_handlers/service_handlers.go
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
	"github.com/joy095/identity/models/service_models"
)

type CreateServiceRequest struct {
	BusinessID      string  `form:"businessId" binding:"required"`
	Name            string  `form:"name" binding:"required"`
	Description     string  `form:"description,omitempty"`
	DurationMinutes int     `form:"durationMinutes" binding:"required"`
	Price           float64 `form:"price" binding:"required"`
	IsActive        bool    `form:"isActive,omitempty"`
}

type UpdateServiceRequest struct {
	Name            *string  `form:"name"`
	Description     *string  `form:"description"`
	DurationMinutes *int     `form:"durationMinutes"`
	Price           *float64 `form:"price"`
	IsActive        *bool    `form:"isActive"`
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

	businessUUID, err := uuid.Parse(req.BusinessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid Business ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid format for businessId. Must be a valid UUID."})
		return
	}

	if !req.IsActive {
		req.IsActive = true
	}

	authHeader := c.GetHeader("Authorization")
	imageID, err := handleImageUpload(c, authHeader)
	if err != nil {
		return
	}

	service := service_models.NewService(businessUUID, req.Name, req.Description, req.DurationMinutes, req.Price)
	service.IsActive = req.IsActive
	service.ImageID = pgtype.UUID{Bytes: imageID, Valid: true}

	createdService, err := service_models.CreateServiceModel(db.DB, service)
	if err != nil {
		handleServiceCreationError(c, err)
		return
	}

	logger.InfoLogger.Infof("Service '%s' created successfully via test route with image ID: %s", createdService.Name, imageID)
	c.JSON(http.StatusCreated, gin.H{
		"message": "Service created successfully!",
		"service": createdService,
	})
}

func handleImageUpload(c *gin.Context, authHeader string) (uuid.UUID, error) {
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

	body, contentType := prepareMultipartRequest(file, fileHeader)
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

func handleServiceCreationError(c *gin.Context, err error) {
	logger.ErrorLogger.Errorf("Failed to create service in database: %v", err)
	if strings.Contains(err.Error(), "duplicate key value") {
		c.JSON(http.StatusConflict, gin.H{"error": "A service with this name already exists for this business."})
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create service in the database."})
	}
}

func prepareMultipartRequest(file multipart.File, fileHeader *multipart.FileHeader) (*bytes.Buffer, string) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	originalContentType := fileHeader.Header.Get("Content-Type")
	if originalContentType == "" {
		originalContentType = "application/octet-stream"
	}

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "image", fileHeader.Filename))
	h.Set("Content-Type", originalContentType)

	part, _ := writer.CreatePart(h)
	io.Copy(part, file)
	writer.Close()

	return body, writer.FormDataContentType()
}

func sendImageToService(body *bytes.Buffer, contentType string, authHeader string) (uuid.UUID, error) {

	pythonServerURL := os.Getenv("IMAGE_SERVICE_URL") + "/upload-image/"
	if pythonServerURL == "" {
		pythonServerURL = "http://localhost:8082/upload-image/"
	}

	httpReq, _ := http.NewRequest("POST", pythonServerURL, body)
	httpReq.Header.Set("Content-Type", contentType)
	httpReq.Header.Set("Authorization", authHeader)

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

	httpReq, _ := http.NewRequest("PUT", pythonServerURL, body)
	httpReq.Header.Set("Content-Type", contentType)
	httpReq.Header.Set("Authorization", authHeader)

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

	existingService, err := service_models.GetServiceByIDModel(db.DB, serviceID)
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
	if req.DurationMinutes != nil {
		existingService.DurationMinutes = *req.DurationMinutes
	}
	if req.Price != nil {
		existingService.Price = *req.Price
	}
	if req.IsActive != nil {
		existingService.IsActive = *req.IsActive
	}

	_, err = c.FormFile("image")
	if err == nil {
		// New image provided, upload it and update the ID
		// Open new image file from form
		fileHeader, err := c.FormFile("image")
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to get new image: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read image file."})
			return
		}

		file, err := fileHeader.Open()
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to open new image: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open image file."})
			return
		}
		defer file.Close()

		body, contentType := prepareMultipartRequest(file, fileHeader)

		// Use the existing image ID
		imageID := existingService.ImageID.Bytes
		authHeader := c.GetHeader("Authorization")

		_, updateErr := updateImageToService(body, contentType, authHeader, imageID) //
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

	updatedService, err := service_models.UpdateServiceModel(db.DB, existingService)
	if err != nil {
		handleServiceCreationError(c, err) // Can reuse the same error handler for conflicts
		return
	}

	logger.InfoLogger.Infof("Service '%s' (ID: %s) updated successfully", updatedService.Name, serviceIDStr)
	c.JSON(http.StatusOK, gin.H{
		"message": "Service updated successfully!",
		"service": updatedService,
	})
}

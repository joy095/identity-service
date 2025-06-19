// controllers/services_controller/services_controller.go
package services_controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/joy095/identity/badwords"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/business_models"
	"github.com/joy095/identity/models/service_models"
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
	BusinessID      uuid.UUID  `json:"businessId" binding:"required"`
	Name            string     `json:"name" binding:"required,min=3,max=100"`
	Description     string     `json:"description,omitempty"`
	DurationMinutes int        `json:"durationMinutes" binding:"required,min=15"`
	ImageID         *uuid.UUID `json:"imageId,omitempty"`
	Price           float64    `json:"price" binding:"required,min=60"`
}

// UpdateServiceRequest represents the expected JSON payload for updating a service.
type UpdateServiceRequest struct {
	Name            *string    `json:"name,omitempty" binding:"omitempty,min=3,max=100"`
	Description     *string    `json:"description,omitempty"`
	DurationMinutes *int       `json:"durationMinutes,omitempty" binding:"omitempty,min=15"`
	Price           *float64   `json:"price,omitempty" binding:"omitempty,min=60"`
	Image           *http.File `json:"image,omitempty"` // This should likely be *multipart.FileHeader if receiving
	IsActive        *bool      `json:"isActive,omitempty"`
}

// Define a struct to hold the response from the Python image service
type ImageServiceResponse struct {
	Message string    `json:"message"`
	ImageID uuid.UUID `json:"image_id"`
	URL     string    `json:"url"`
}

// CreateService handles the HTTP multipart/form-data request to create a new service.
// It validates service details, forwards the image to a Python service for analysis,
// and creates the service record if all checks pass.
func (sc *ServiceController) CreateService(c *gin.Context) {
	logger.InfoLogger.Info("CreateService controller called")

	// --- 1. Explicitly parse the multipart form ---
	// This will read the entire request body containing all form fields and files.
	// This is the primary diagnostic change.
	err := c.Request.ParseMultipartForm(10 << 20) // Use 10MB as default max memory
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse multipart form explicitly: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Failed to parse form data: %v", err)})
		return
	}

	// --- Now access fields from the parsed form data ---

	// Get the image file header
	imageFileHeaders := c.Request.MultipartForm.File["image"]
	if len(imageFileHeaders) == 0 {
		logger.ErrorLogger.Error("Missing required file field: 'image' after explicit form parse.")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required field: image"})
		return
	}
	imageFileHeader := imageFileHeaders[0] // Get the first file if multiple are uploaded under the same key

	originalFileContentType := imageFileHeader.Header.Get("Content-Type")
	if originalFileContentType == "" {
		logger.WarnLogger.Warnf("Original image Content-Type header missing for file %s. Defaulting to application/octet-stream.", imageFileHeader.Filename)
		originalFileContentType = "application/octet-stream"
	}
	logger.DebugLogger.Debugf("Original uploaded file Content-Type: %s", originalFileContentType)
	logger.DebugLogger.Debugf("Image file received: %s, size: %d", imageFileHeader.Filename, imageFileHeader.Size)

	// Get other text form fields
	businessIDStrVals := c.Request.MultipartForm.Value["businessId"]
	if len(businessIDStrVals) == 0 {
		logger.ErrorLogger.Error("Missing required form field: businessId after explicit parse.")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required field: businessId"})
		return
	}
	businessIDStr := businessIDStrVals[0]

	nameVals := c.Request.MultipartForm.Value["name"]
	if len(nameVals) == 0 {
		logger.ErrorLogger.Error("Missing required form field: name after explicit parse.")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required field: name"})
		return
	}
	name := nameVals[0]

	descriptionVals := c.Request.MultipartForm.Value["description"]
	var description string
	if len(descriptionVals) > 0 {
		description = descriptionVals[0]
	}

	durationStrVals := c.Request.MultipartForm.Value["durationMinutes"]
	if len(durationStrVals) == 0 {
		logger.ErrorLogger.Error("Missing required form field: durationMinutes after explicit parse.")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required field: durationMinutes"})
		return
	}
	durationStr := durationStrVals[0]

	priceStrVals := c.Request.MultipartForm.Value["price"]
	if len(priceStrVals) == 0 {
		logger.ErrorLogger.Error("Missing required form field: price after explicit parse.")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required field: price"})
		return
	}
	priceStr := priceStrVals[0]

	logger.DebugLogger.Debugf("Parsed businessId: %s, name: %s, durationStr: %s, priceStr: %s", businessIDStr, name, durationStr, priceStr)

	// Validate required fields (using the values extracted from MultipartForm)
	if businessIDStr == "" || name == "" || durationStr == "" || priceStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required fields after parsing: businessId, name, durationMinutes, price"})
		return
	}

	businessID, err := uuid.Parse(businessIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid businessId format"})
		return
	}

	durationMinutes, err := strconv.Atoi(durationStr)
	if err != nil || durationMinutes < 15 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid durationMinutes. Must be a number and at least 15."})
		return
	}

	price, err := strconv.ParseFloat(priceStr, 64)
	if err != nil || price < 60 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid price. Must be a number and at least 60."})
		return
	}

	// --- 2. Bad Words Check for Text Fields ---
	if badwords.ContainsBadWords(name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service name contains inappropriate language."})
		return
	}
	if description != "" && badwords.ContainsBadWords(description) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Service description contains inappropriate language."})
		return
	}

	// --- 3. Authentication and Business Ownership Verification ---
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required: user ID not found"})
		return
	}

	business, err := business_models.GetBusinessByID(sc.DB, businessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for service creation: %v", businessID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Associated business not found"})
		return
	}

	if business.OwnerID != ownerUserID {
		logger.ErrorLogger.Errorf("User %s attempted to create service for unowned business %s", ownerUserID, businessID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to add services to this business"})
		return
	}

	// --- 4. Handle Image File and Forward to Python Service ---
	var imageID uuid.UUID // Will hold the ID from the image service

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		logger.InfoLogger.Warn("Authorization header not found in incoming request. Not forwarding to image service.")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required to process image."})
		return
	}

	logger.InfoLogger.Info("Image file found, preparing to forward to image service.")

	imageServiceURL := os.Getenv("IMAGE_SERVICE_URL") + "/upload-image/"
	if imageServiceURL == "/upload-image/" || imageServiceURL == "" {
		logger.ErrorLogger.Error("IMAGE_SERVICE_URL environment variable is not set or misconfigured (missing protocol scheme).")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Image processing service is not configured correctly."})
		return
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add businessId field to the forwarded request
	if err := writer.WriteField("businessId", businessID.String()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare image request (businessId field)"})
		return
	}

	// Create the multipart part for the file, setting Content-Type explicitly
	partHeader := make(textproto.MIMEHeader)
	// FastAPI expects the file field name to be "image"
	partHeader.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "image", imageFileHeader.Filename))
	partHeader.Set("Content-Type", originalFileContentType)

	part, err := writer.CreatePart(partHeader)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare image for validation (create part)"})
		return
	}

	// Open the uploaded file from the original client request
	fileToRead, err := imageFileHeader.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open uploaded image for forwarding"})
		return
	}
	defer fileToRead.Close()

	// Copy the content of the uploaded file into the new multipart part
	if _, err := io.Copy(part, fileToRead); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read image data for forwarding"})
		return
	}
	writer.Close() // IMPORTANT: Close the writer to finalize the multipart body

	// Create and send the HTTP request to the Python service
	req, err := http.NewRequest("POST", imageServiceURL, body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request for image service"})
		return
	}

	req.Header.Set("Content-Type", writer.FormDataContentType()) // Set the overall Content-Type for the request
	req.Header.Set("Authorization", authHeader)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to send request to image service: %v", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Image validation service is unavailable"})
		return
	}
	defer resp.Body.Close()

	// --- 5. Process the response from the Python service ---
	if resp.StatusCode != http.StatusCreated {
		var errorResponse gin.H
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			c.JSON(resp.StatusCode, gin.H{"error": "Image validation failed with an unknown error or non-JSON response."})
			return
		}
		logger.ErrorLogger.Errorf("Image service returned error (status %d): %v", resp.StatusCode, errorResponse)
		c.JSON(resp.StatusCode, errorResponse) // Relay the error (e.g., "Adult content detected")
		return
	}

	// Decode the successful response to get the image ID
	var imageResponse ImageServiceResponse
	if err := json.NewDecoder(resp.Body).Decode(&imageResponse); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode image service response"})
		return
	}
	imageID = imageResponse.ImageID
	logger.InfoLogger.Infof("Image successfully processed by Python service. New image ID: %s", imageID)
	logger.DebugLogger.Debugf("Image ID received from Python service before DB save: %s", imageID.String())

	// --- 6. Create the Service in the Database ---
	service := service_models.NewService(
		businessID,
		name,
		description,
		durationMinutes,
		price,
	)

	// If an image was processed, set the image ID on the service
	if imageID != uuid.Nil {
		service.ImageID = imageID
	}

	createdService, err := service_models.CreateServiceModel(sc.DB, service)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create service in database: %v", err)
		if strings.Contains(err.Error(), "foreign key constraint") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid business ID provided"})
		} else if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
			c.JSON(http.StatusConflict, gin.H{"error": "A service with this name already exists for this business."})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create service"})
		}
		return
	}

	logger.InfoLogger.Infof("Service %s created successfully for business %s by user %s", createdService.ID, businessID, ownerUserID)
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

	service, err := service_models.GetServiceByIDModel(sc.DB, serviceID)
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
	existingService, err := service_models.GetServiceByIDModel(sc.DB, serviceID)
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
	business, err := business_models.GetBusinessByID(sc.DB, existingService.BusinessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for service %s ownership check: %v", existingService.BusinessID, serviceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: business lookup failed"})
		return
	}

	if business.OwnerID != ownerUserID {
		logger.ErrorLogger.Errorf("User %s attempted to update service %s for unowned business %s", ownerUserID, serviceID, existingService.BusinessID)
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

	updatedService, err := service_models.UpdateServiceModel(sc.DB, existingService)
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
	existingService, err := service_models.GetServiceByIDModel(sc.DB, serviceID)
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
	business, err := business_models.GetBusinessByID(sc.DB, existingService.BusinessID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch business %s for service %s ownership check: %v", existingService.BusinessID, serviceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error: business lookup failed"})
		return
	}

	if business.OwnerID != ownerUserID {
		logger.ErrorLogger.Errorf("User %s attempted to delete service %s for unowned business %s", ownerUserID, serviceID, existingService.BusinessID)
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to delete this service"})
		return
	}

	if err := service_models.DeleteServiceModel(sc.DB, serviceID, existingService.BusinessID); err != nil {
		logger.ErrorLogger.Errorf("Failed to delete service %s from database: %v", serviceID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete service"})
		return
	}

	logger.InfoLogger.Infof("Service %s deleted successfully by user %s", serviceID, ownerUserID)
	c.JSON(http.StatusOK, gin.H{"message": "Service deleted successfully"})
}

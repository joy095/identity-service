// controllers/services_controller/services_controller.go

package services_controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/joy095/identity/badwords"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/business_models"
	"github.com/joy095/identity/models/service_models"
	"github.com/joy095/identity/utils"
)

// Configuration constants
const (
	MaxMemorySize       = 32 << 20 // 32MB: Maximum memory to store multipart form data in RAM (less relevant now)
	MaxImageSize        = 10 << 20 // 10MB: Maximum allowed image file size for upload
	MinDurationMinutes  = 15
	MinPrice            = 1.0
	ImageServiceTimeout = 60 * time.Second

	MaxImageSizeMB = 10 // For user-friendly error messages
)

var (
	// Supported MIME types for images
	SupportedImageTypes = map[string]bool{
		"image/jpeg": true,
		"image/jpg":  true,
		"image/png":  true,
		"image/webp": true,
		"image/gif":  true,
	}
)

// ServiceController holds dependencies for service-related operations.
type ServiceController struct {
	DB              *pgxpool.Pool
	ImageServiceURL string
	HTTPClient      *http.Client
}

// Request/Response structs with better validation
type CreateServiceRequest struct {
	BusinessID      uuid.UUID  `json:"businessId" binding:"required"`
	Name            string     `json:"name" binding:"required,min=3,max=100"`
	Description     string     `json:"description,omitempty" binding:"omitempty,max=5000"` // Added max length
	DurationMinutes int        `json:"durationMinutes" binding:"required,min=15"`
	ImageID         *uuid.UUID `json:"imageId,omitempty"`
	Price           float64    `json:"price" binding:"required,min=1"`
}

type UpdateServiceRequest struct {
	Name            *string    `json:"name,omitempty" binding:"omitempty,min=3,max=100"`
	Description     *string    `json:"description,omitempty" binding:"omitempty,max=5000"` // Added max length
	DurationMinutes *int       `json:"durationMinutes,omitempty" binding:"omitempty,min=15"`
	Price           *float64   `json:"price,omitempty" binding:"omitempty,min=1"`
	Image           *http.File `json:"image,omitempty"` // Note: This field is unlikely to be directly populated by Gin's binding if you're using multipart forms. Gin's c.FormFile is preferred for file handling.
	IsActive        *bool      `json:"isActive,omitempty"`
	ImageID         *string    `json:"imageId,omitempty"`
}

type ImageServiceResponse struct {
	Message string    `json:"message"`
	ImageID uuid.UUID `json:"image_id"`
	URL     string    `json:"url"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
	Code    string `json:"code,omitempty"`
}

type ImageUploadResult struct {
	ImageID uuid.UUID
	Error   error
}

// Custom errors for better error handling
type ServiceError struct {
	Code    string
	Message string
	Err     error
}

func (e *ServiceError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func NewServiceError(code, message string, err error) *ServiceError {
	return &ServiceError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// validateImageFile validates the uploaded image file
func (sc *ServiceController) validateImageFile(fileHeader *multipart.FileHeader, imageContent []byte) error {
	// Check file size
	if fileHeader.Size > MaxImageSize {
		return NewServiceError("FILE_TOO_LARGE",
			fmt.Sprintf("Image file too large. Maximum size is %dMB", MaxImageSizeMB), nil)
	}

	// Check file extension
	filename := strings.ToLower(fileHeader.Filename)
	validExtensions := []string{".jpg", ".jpeg", ".png", ".webp", ".gif"}
	hasValidExtension := false
	for _, ext := range validExtensions {
		if strings.HasSuffix(filename, ext) {
			hasValidExtension = true
			break
		}
	}

	if !hasValidExtension {
		return NewServiceError("INVALID_FILE_TYPE",
			"Invalid file type. Supported formats: JPG, JPEG, PNG, WebP, GIF", nil)
	}

	// Check MIME type from header (client provided, not always reliable for security but good for initial check)
	contentType := fileHeader.Header.Get("Content-Type")
	if contentType != "" && !SupportedImageTypes[contentType] {
		return NewServiceError("INVALID_MIME_TYPE",
			fmt.Sprintf("Invalid MIME type: %s", contentType), nil)
	}

	// For more robust MIME type validation, read a portion of the file content
	// and use http.DetectContentType for verification
	if len(imageContent) > 0 {
		detectedType := http.DetectContentType(imageContent[:min(512, len(imageContent))])
		if !SupportedImageTypes[detectedType] {
			return NewServiceError("INVALID_FILE_CONTENT", "File content doesn't match expected image format", nil)
		}
	}

	return nil
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// NewServiceController creates a new instance of ServiceController with proper configuration.
func NewServiceController(db *pgxpool.Pool) *ServiceController {
	imageServiceURL := os.Getenv("IMAGE_SERVICE_URL")
	if imageServiceURL == "" {
		logger.WarnLogger.Warn("IMAGE_SERVICE_URL not set, using default http://localhost:8001")
		imageServiceURL = "http://localhost:8001" // Default fallback for local development
	}

	return &ServiceController{
		DB:              db,
		ImageServiceURL: imageServiceURL,
		HTTPClient: &http.Client{
			Timeout: ImageServiceTimeout, // Timeout for the call to the image service
		},
	}
}

// uploadImageToService handles image upload to the Python service
func (sc *ServiceController) uploadImageToService(ctx context.Context, imageContent []byte,
	filename, contentType string, businessID uuid.UUID, authHeader string) (*ImageUploadResult, error) {

	// Create multipart form data for the *outgoing* request to the image service
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add business ID field to the outgoing multipart request
	if err := writer.WriteField("businessId", businessID.String()); err != nil {
		return nil, NewServiceError("FORM_CREATION_ERROR", "Failed to create form field for image upload", err)
	}

	// Add image file to the outgoing multipart request
	partHeader := make(textproto.MIMEHeader)
	partHeader.Set("Content-Disposition", fmt.Sprintf(`form-data; name="image"; filename="%s"`, filename))
	partHeader.Set("Content-Type", contentType) // Use the original content type of the uploaded file

	part, err := writer.CreatePart(partHeader)
	if err != nil {
		return nil, NewServiceError("FORM_PART_ERROR", "Failed to create form file part for image upload", err)
	}

	if _, err := part.Write(imageContent); err != nil {
		return nil, NewServiceError("FORM_WRITE_ERROR", "Failed to write image data to form for upload", err)
	}

	if err := writer.Close(); err != nil {
		return nil, NewServiceError("FORM_CLOSE_ERROR", "Failed to finalize form data for image upload", err)
	}

	// Create HTTP request to the image service
	imageServiceUploadURL := sc.ImageServiceURL + "/upload-image/"
	req, err := http.NewRequestWithContext(ctx, "POST", imageServiceUploadURL, body)
	if err != nil {
		return nil, NewServiceError("REQUEST_CREATION_ERROR", "Failed to create HTTP request to image service", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType()) // Set the correct Content-Type for the multipart request
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader) // Forward authentication header
	}

	logger.DebugLogger.Debugf("Uploading image to service: %s", imageServiceUploadURL)

	// Send request to image service
	resp, err := sc.HTTPClient.Do(req)
	if err != nil {
		// Differentiate between network issues and timeouts
		if os.IsTimeout(err) {
			return nil, NewServiceError("IMAGE_SERVICE_TIMEOUT", "Image service response timed out", err)
		}
		return nil, NewServiceError("IMAGE_SERVICE_UNAVAILABLE", "Image service is unavailable or unreachable", err)
	}
	defer resp.Body.Close()

	// Read response body from image service
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewServiceError("RESPONSE_READ_ERROR", "Failed to read image service response body", err)
	}

	// Handle non-success status codes from the image service
	if resp.StatusCode != http.StatusCreated {
		var errorResp struct { // Attempt to parse common Python service error formats (FastAPI/Flask)
			Detail string `json:"detail"`
			Error  string `json:"error"`
		}

		if json.Unmarshal(respBody, &errorResp) == nil {
			message := errorResp.Detail
			if message == "" {
				message = errorResp.Error // Fallback to 'error' field
			}
			if message != "" {
				return nil, NewServiceError("IMAGE_SERVICE_ERROR", message, fmt.Errorf("status %d", resp.StatusCode))
			}
		}

		return nil, NewServiceError("IMAGE_SERVICE_ERROR",
			fmt.Sprintf("Image service returned unexpected status %d: %s", resp.StatusCode, string(respBody)), nil)
	}

	// Parse successful response from image service
	var imageServiceResp ImageServiceResponse
	if err := json.Unmarshal(respBody, &imageServiceResp); err != nil {
		return nil, NewServiceError("RESPONSE_PARSE_ERROR", "Failed to parse successful image service response", err)
	}

	logger.InfoLogger.Infof("Image uploaded successfully, ID: %s", imageServiceResp.ImageID)
	return &ImageUploadResult{ImageID: imageServiceResp.ImageID}, nil
}

// cleanupImage attempts to delete the image from the image service in case of a database error.
func (sc *ServiceController) cleanupImage(ctx context.Context, imageID uuid.UUID, authHeader string) {
	if imageID == uuid.Nil {
		return // Nothing to cleanup if imageID is nil
	}

	logger.InfoLogger.Infof("Attempting to cleanup image: %s due to service creation failure.", imageID)

	cleanupURL := fmt.Sprintf("%s/delete-image/%s", sc.ImageServiceURL, imageID)
	req, err := http.NewRequestWithContext(ctx, "DELETE", cleanupURL, nil)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create cleanup request for image %s: %v", imageID, err)
		return
	}

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := sc.HTTPClient.Do(req)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to send cleanup request for image %s: %v", imageID, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body) // Read body for detailed error logging
		logger.ErrorLogger.Errorf("Image cleanup failed for %s (status %d): %s",
			imageID, resp.StatusCode, string(respBody))
	} else {
		logger.InfoLogger.Infof("Image cleanup successful for image %s", imageID)
	}
}

// respondWithError sends a structured error response
func (sc *ServiceController) respondWithError(c *gin.Context, statusCode int, serviceErr *ServiceError) {
	// Log the error for server-side debugging
	logger.ErrorLogger.Errorf("Service error [%s] (HTTP %d): %v", serviceErr.Code, statusCode, serviceErr)

	response := ErrorResponse{
		Error: serviceErr.Message,
		Code:  serviceErr.Code,
	}

	if serviceErr.Err != nil {
		// Only include underlying error details in development/debug environments,
		// or if it's a safe error to expose.
		// For production, consider generic "internal server error" details.
		response.Details = serviceErr.Err.Error()
	}

	c.JSON(statusCode, response)
}

// CreateService handles the HTTP multipart/form-data request to create a new service with robust error handling.
func (sc *ServiceController) CreateService(c *gin.Context) {
	logger.InfoLogger.Info("CreateService controller called")

	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
	defer cancel()

	// --- 1. Validate Content Type ---
	// Removed redundant GetHeader call
	if !strings.Contains(strings.ToLower(c.Request.Header.Get("Content-Type")), "multipart/form-data") {
		sc.respondWithError(c, http.StatusBadRequest, NewServiceError("INVALID_CONTENT_TYPE", "Request must be multipart/form-data", nil))
		return
	}

	logger.InfoLogger.Infof("Processing multipart request - Content-Length: %d", c.Request.ContentLength)

	// --- 2. Check if request body is available ---
	if c.Request.Body == nil {
		sc.respondWithError(c, http.StatusBadRequest, NewServiceError("NO_REQUEST_BODY", "Request body is nil. Ensure the request contains multipart form data.", nil))
		return
	}

	// --- NEW APPROACH: Manually parse multipart form to stream file data ---
	// Create a multipart reader
	reader, err := c.Request.MultipartReader()
	if err != nil {
		serviceErr := NewServiceError("FORM_PARSE_ERROR", "Failed to create multipart reader. Ensure valid multipart/form-data request.", err)
		sc.respondWithError(c, http.StatusBadRequest, serviceErr)
		return
	}

	// Initialize form data and file header/content storage
	formData := make(map[string]string)
	var fileHeader *multipart.FileHeader
	var imageContent []byte // This will hold the entire image content in memory for validation/upload

	// Iterate over each part in the multipart form
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break // All parts read
		}
		if err != nil {
			logger.ErrorLogger.Errorf("Error reading multipart part: %v", err)
			serviceErr := NewServiceError("FORM_PARSE_ERROR", "Failed to read a part of the multipart form.", err)
			sc.respondWithError(c, http.StatusBadRequest, serviceErr)
			return
		}

		fieldName := part.FormName()
		if fieldName == "" {
			continue // Skip parts without a form name
		}

		if part.FileName() != "" { // This is a file part
			if fieldName == "image" {
				// Read image content directly
				imageData, readErr := io.ReadAll(part)
				if readErr != nil {
					logger.ErrorLogger.Errorf("Error reading image file part '%s': %v", fieldName, readErr)
					serviceErr := NewServiceError("FILE_READ_ERROR", "Failed to read image file content.", readErr)
					sc.respondWithError(c, http.StatusInternalServerError, serviceErr)
					return
				}
				imageContent = imageData

				// Manually create a FileHeader from the part.
				// This is a bit of a hack as multipart.Part doesn't directly expose FileHeader fields.
				// We populate essential fields for validation (Size, Filename, Header).
				fileHeader = &multipart.FileHeader{
					Filename: part.FileName(),
					Header:   part.Header,
					Size:     int64(len(imageContent)),
					// Faked content to match the behavior of c.FormFile,
					// as we've already read it into imageContent.
					// We'll open a bytes.Reader from imageContent if needed later.
				}
				logger.DebugLogger.Debugf("Image file part '%s' read. Size: %d bytes", fieldName, fileHeader.Size)
			} else {
				// Handle other file uploads if needed, or ignore them
				logger.WarnLogger.Warnf("Skipping unexpected file part: %s", fieldName)
				_, _ = io.Copy(io.Discard, part) // Discard content to prevent blocking
			}
		} else { // This is a regular form field
			fieldValue, readErr := io.ReadAll(part)
			if readErr != nil {
				logger.ErrorLogger.Errorf("Error reading form field '%s': %v", fieldName, readErr)
				serviceErr := NewServiceError("FORM_READ_ERROR", fmt.Sprintf("Failed to read form field '%s'.", fieldName), readErr)
				sc.respondWithError(c, http.StatusBadRequest, serviceErr)
				return
			}
			formData[fieldName] = strings.TrimSpace(string(fieldValue))
			logger.DebugLogger.Debugf("Form field '%s': '%s'", fieldName, formData[fieldName])
		}
	}

	// After parsing all parts, construct CreateServiceRequest from formData
	var req CreateServiceRequest
	var validationErrors []string

	// Populate req from formData and validate
	if idStr, ok := formData["businessId"]; ok {
		if id, err := uuid.Parse(idStr); err == nil {
			req.BusinessID = id
		} else {
			validationErrors = append(validationErrors, "Invalid business ID format")
		}
	} else {
		validationErrors = append(validationErrors, "Business ID is required")
	}

	if name, ok := formData["name"]; ok {
		req.Name = name
		if len(req.Name) < 3 || len(req.Name) > 100 {
			validationErrors = append(validationErrors, "Service name must be between 3 and 100 characters")
		}
		if badwords.ContainsBadWords(req.Name) {
			validationErrors = append(validationErrors, "Service name contains inappropriate language")
		}
	} else {
		validationErrors = append(validationErrors, "Service name is required")
	}

	if description, ok := formData["description"]; ok {
		req.Description = description
		if len(req.Description) > 5000 { // Enforce max length
			validationErrors = append(validationErrors, "Service description exceeds maximum allowed length")
		}
		if badwords.ContainsBadWords(req.Description) {
			validationErrors = append(validationErrors, "Service description contains inappropriate language")
		}
	}

	if durationStr, ok := formData["durationMinutes"]; ok {
		if duration, err := strconv.Atoi(durationStr); err == nil {
			req.DurationMinutes = duration
			if duration < MinDurationMinutes {
				validationErrors = append(validationErrors, fmt.Sprintf("Duration must be at least %d minutes", MinDurationMinutes))
			}
		} else {
			validationErrors = append(validationErrors, "Invalid duration format")
		}
	} else {
		validationErrors = append(validationErrors, "Duration is required")
	}

	if priceStr, ok := formData["price"]; ok {
		if price, err := strconv.ParseFloat(priceStr, 64); err == nil {
			req.Price = price
			if price < MinPrice {
				validationErrors = append(validationErrors, fmt.Sprintf("Price must be at least %.2f", MinPrice))
			}
		} else {
			validationErrors = append(validationErrors, "Invalid price format")
		}
	} else {
		validationErrors = append(validationErrors, "Price is required")
	}

	if len(validationErrors) > 0 {
		sc.respondWithError(c, http.StatusBadRequest, NewServiceError("VALIDATION_ERROR", strings.Join(validationErrors, "; "), nil))
		return
	}

	// Ensure image was provided
	if fileHeader == nil {
		sc.respondWithError(c, http.StatusBadRequest, NewServiceError("MISSING_IMAGE", "Image file is required for service creation", nil))
		return
	}

	// --- 4. Validate Image File (now with imageContent) ---
	if err := sc.validateImageFile(fileHeader, imageContent); err != nil {
		sc.respondWithError(c, http.StatusBadRequest, err.(*ServiceError))
		return
	}

	if len(imageContent) == 0 {
		serviceErr := NewServiceError("EMPTY_IMAGE", "Image file cannot be empty after reading.", nil)
		sc.respondWithError(c, http.StatusBadRequest, serviceErr)
		return
	}

	// Determine content type of the uploaded image
	imageContentType := fileHeader.Header.Get("Content-Type")
	if imageContentType == "" {
		// Fallback if Content-Type header is missing for the part (unlikely with well-formed multipart)
		imageContentType = "application/octet-stream"
	}
	logger.DebugLogger.Debugf("Image '%s' (%d bytes) with Content-Type '%s' ready for upload.",
		fileHeader.Filename, len(imageContent), imageContentType)

	// --- 6. Authentication & Authorization ---
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		sc.respondWithError(c, http.StatusUnauthorized, NewServiceError("AUTH_ERROR", "Authentication required: user ID not found in context.", err))
		return
	}

	business, err := business_models.GetBusinessByID(sc.DB, req.BusinessID)
	if err != nil {
		sc.respondWithError(c, http.StatusNotFound, NewServiceError("BUSINESS_NOT_FOUND", fmt.Sprintf("Associated business with ID %s not found.", req.BusinessID), err))
		return
	}

	if business.OwnerID != ownerUserID {
		sc.respondWithError(c, http.StatusForbidden, NewServiceError("UNAUTHORIZED_BUSINESS", "You are not authorized to add services to this business.", nil))
		return
	}

	// --- 7. Upload Image to Dedicated Image Service ---
	authHeader := c.GetHeader("Authorization") // Pass original auth header
	imageResult, err := sc.uploadImageToService(ctx, imageContent, fileHeader.Filename,
		imageContentType, req.BusinessID, authHeader)
	if err != nil {
		sc.respondWithError(c, http.StatusInternalServerError, err.(*ServiceError))
		return
	}

	// --- 8. Create Service in the Main Database ---
	service := service_models.NewService(req.BusinessID, req.Name, req.Description,
		req.DurationMinutes, req.Price)
	service.ImageID = imageResult.ImageID // Associate the uploaded image ID

	createdService, err := service_models.CreateServiceModel(sc.DB, service)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create service in database: %v", err)

		// Asynchronous cleanup of the uploaded image if DB creation fails
		go func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			sc.cleanupImage(cleanupCtx, imageResult.ImageID, authHeader)
		}()

		if strings.Contains(err.Error(), "duplicate key value") {
			sc.respondWithError(c, http.StatusConflict, NewServiceError("DUPLICATE_SERVICE", "A service with this name already exists for this business.", err))
		} else {
			sc.respondWithError(c, http.StatusInternalServerError, NewServiceError("DATABASE_ERROR", "Failed to create service in the database.", err))
		}
		return
	}

	logger.InfoLogger.Infof("Service '%s' (ID: %s) created successfully for business %s. Image ID: %s",
		createdService.Name, createdService.ID, req.BusinessID, createdService.ImageID)

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
	if req.ImageID != nil {
		imageUUID, err := uuid.Parse(*req.ImageID)
		if err != nil {
			logger.ErrorLogger.Errorf("Invalid image ID format: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid image ID format"})
			return
		}
		existingService.ImageID = imageUUID
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

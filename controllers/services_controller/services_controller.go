package services_controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
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
	MaxMemorySize       = 32 << 20 // 32MB - Gin's default for form parsing, files larger than this are stored on disk.
	MaxImageSize        = 10 << 20 // 10MB
	MinDurationMinutes  = 15
	MinPrice            = 1.0
	ImageServiceTimeout = 3 * time.Minute
	MaxImageSizeMB      = 10 // For error message clarity
)

var (
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

// Request/Response structs
type CreateServiceRequest struct {
	BusinessID      uuid.UUID `json:"businessId"`
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	DurationMinutes int       `json:"durationMinutes"`
	Price           float64   `json:"price"`
}

type UpdateServiceRequest struct {
	Name            *string  `json:"name,omitempty"`
	Description     *string  `json:"description,omitempty"`
	DurationMinutes *int     `json:"durationMinutes,omitempty"`
	Price           *float64 `json:"price,omitempty"`
	IsActive        *bool    `json:"isActive,omitempty"`
	ImageID         *string  `json:"imageId,omitempty"`
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

// Custom error type for structured error responses
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
	return &ServiceError{Code: code, Message: message, Err: err}
}

// NewServiceController creates a new instance of ServiceController
func NewServiceController(db *pgxpool.Pool) *ServiceController {
	imageServiceURL := os.Getenv("IMAGE_SERVICE_URL")
	if imageServiceURL == "" {
		logger.WarnLogger.Warn("IMAGE_SERVICE_URL not set, using default http://localhost:8082")
		imageServiceURL = "http://localhost:8082" // Align with main.go test endpoint
	}

	return &ServiceController{
		DB:              db,
		ImageServiceURL: imageServiceURL,
		HTTPClient: &http.Client{
			Timeout: ImageServiceTimeout,
		},
	}
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// validateImageFile checks image size, extension, and content type.
func (sc *ServiceController) validateImageFile(file multipart.File, fileHeader *multipart.FileHeader) error {
	if fileHeader.Size > MaxImageSize {
		return NewServiceError("FILE_TOO_LARGE",
			fmt.Sprintf("Image file too large. Maximum size is %dMB.", MaxImageSizeMB), nil)
	}

	// Read the first 512 bytes to detect the content type.
	headerBytes := make([]byte, 512)
	n, err := file.Read(headerBytes)
	if err != nil && err != io.EOF {
		return NewServiceError("FILE_READ_ERROR", "Could not read file header for validation.", err)
	}

	// Rewind the file reader back to the start so it can be read again for streaming.
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return NewServiceError("FILE_SEEK_ERROR", "Could not rewind file for streaming.", err)
	}

	if n == 0 {
		return NewServiceError("EMPTY_IMAGE", "Image file content is empty.", nil)
	}

	detectedType := http.DetectContentType(headerBytes[:n])
	if !SupportedImageTypes[detectedType] {
		return NewServiceError("INVALID_FILE_CONTENT",
			fmt.Sprintf("File content type '%s' is not a supported image format. Supported are: JPG, PNG, GIF, WebP.", detectedType), nil)
	}

	return nil
}

// uploadImageToService sends the image to the external image service.
func (sc *ServiceController) uploadImageToService(ctx context.Context, imageReader io.Reader,
	filename, contentType string, businessID uuid.UUID, authHeader string) (uuid.UUID, error) {

	// Use an io.Pipe to connect the multipart writer to the HTTP request body without buffering the whole file in memory.
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	// Use a goroutine to write the multipart data to the pipe.
	// This prevents blocking as the HTTP client reads from the other end of the pipe.
	go func() {
		defer pw.Close()     // Close the pipe writer to signal the end of data.
		defer writer.Close() // Finalize the multipart form.

		// Add business ID as a form field
		if err := writer.WriteField("businessId", businessID.String()); err != nil {
			// Closing the pipe with an error will cause the reader to fail.
			pw.CloseWithError(NewServiceError("FORM_CREATION_ERROR", "Failed to add business ID to form.", err))
			return
		}

		// Create form file part for the image
		partHeader := make(textproto.MIMEHeader)
		partHeader.Set("Content-Disposition", fmt.Sprintf(`form-data; name="image"; filename="%s"`, filename))
		partHeader.Set("Content-Type", contentType)

		part, err := writer.CreatePart(partHeader)
		if err != nil {
			pw.CloseWithError(NewServiceError("FORM_PART_ERROR", "Failed to create image form part.", err))
			return
		}

		// Stream the image data from the reader directly into the multipart part.
		// This is the key change to avoid loading the file into memory.
		if _, err := io.Copy(part, imageReader); err != nil {
			pw.CloseWithError(NewServiceError("FORM_WRITE_ERROR", "Failed to stream image data to form.", err))
			return
		}
	}()

	// Create and send the HTTP request. The request body is now the reading end of the pipe.
	imageServiceUploadURL := sc.ImageServiceURL + "/upload-image/"
	req, err := http.NewRequestWithContext(ctx, "POST", imageServiceUploadURL, pr)
	if err != nil {
		return uuid.Nil, NewServiceError("REQUEST_CREATION_ERROR", "Failed to create request to image service.", err)
	}

	// The Content-Type header now includes the multipart boundary from the writer.
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := sc.HTTPClient.Do(req)
	if err != nil {
		if os.IsTimeout(err) {
			return uuid.Nil, NewServiceError("IMAGE_SERVICE_TIMEOUT", "Image service request timed out.", err)
		}
		return uuid.Nil, NewServiceError("IMAGE_SERVICE_UNAVAILABLE", fmt.Sprintf("Image service is unavailable: %v", err), err)
	}
	defer resp.Body.Close()

	// Read and parse the response from the image service
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return uuid.Nil, NewServiceError("RESPONSE_READ_ERROR", "Failed to read response from image service.", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return uuid.Nil, NewServiceError("IMAGE_SERVICE_ERROR",
			fmt.Sprintf("Image service responded with error (status %d): %s", resp.StatusCode, string(respBody)), nil)
	}

	var imageServiceResp ImageServiceResponse
	if err := json.Unmarshal(respBody, &imageServiceResp); err != nil {
		return uuid.Nil, NewServiceError("RESPONSE_PARSE_ERROR", fmt.Sprintf("Failed to parse image service response: %v. Response: %s", err, string(respBody)), err)
	}

	return imageServiceResp.ImageID, nil
}

// cleanupImage attempts to delete the image from the image service (asynchronously).
func (sc *ServiceController) cleanupImage(ctx context.Context, imageID uuid.UUID, authHeader string) {
	if imageID == uuid.Nil {
		return
	}

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
		logger.ErrorLogger.Errorf("Failed to cleanup image %s from image service: %v", imageID, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body) // Read body for more detailed logging
		logger.ErrorLogger.Errorf("Image cleanup failed for %s (status %d). Response: %s", imageID, resp.StatusCode, string(bodyBytes))
	} else {
		logger.InfoLogger.Infof("Successfully cleaned up image %s from image service.", imageID)
	}
}

// respondWithError sends a structured JSON error response.
func (sc *ServiceController) respondWithError(c *gin.Context, statusCode int, serviceErr *ServiceError) {
	logger.ErrorLogger.Errorf("Service error [%s] (HTTP %d): %v", serviceErr.Code, statusCode, serviceErr.Err) // Log internal error

	response := ErrorResponse{
		Error: serviceErr.Message,
		Code:  serviceErr.Code,
	}

	if serviceErr.Err != nil {
		// Only expose internal error details if needed for debugging or development,
		// otherwise, keep it generic for production APIs.
		response.Details = serviceErr.Err.Error()
	}

	c.JSON(statusCode, response)
}

// CreateService handles service creation, including multipart form data and image upload.
func (sc *ServiceController) CreateService(c *gin.Context) {
	logger.InfoLogger.Info("CreateService controller called")

	// 1. Validate Content-Type
	if !strings.HasPrefix(strings.ToLower(c.GetHeader("Content-Type")), "multipart/form-data") {
		sc.respondWithError(c, http.StatusBadRequest, NewServiceError("INVALID_CONTENT_TYPE", "Request must be multipart/form-data.", nil))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
	defer cancel()

	// 2. Parse the multipart form
	if err := c.Request.ParseMultipartForm(MaxMemorySize); err != nil {
		logger.ErrorLogger.Errorf("Error parsing multipart form: %v", err)
		var errorMsg string
		var errorCode string
		if strings.Contains(err.Error(), "too large") {
			errorMsg = fmt.Sprintf("Request payload too large. Maximum allowed for form fields/small files is %dMB.", MaxMemorySize/(1<<20))
			errorCode = "PAYLOAD_TOO_LARGE"
		} else {
			errorMsg = fmt.Sprintf("Failed to parse multipart form data. Please check your request format: %v", err)
			errorCode = "FORM_PARSE_ERROR"
		}
		sc.respondWithError(c, http.StatusBadRequest, NewServiceError(errorCode, errorMsg, err))
		return
	}
	defer c.Request.MultipartForm.RemoveAll()

	form := c.Request.MultipartForm

	// Helper function to get form value safely and trim spaces
	getFormValue := func(key string) string {
		if values, ok := form.Value[key]; ok && len(values) > 0 {
			return strings.TrimSpace(values[0])
		}
		return ""
	}

	// 3. Extract and validate form fields
	var req CreateServiceRequest
	var validationErrors []string

	// BusinessID
	businessIDStr := getFormValue("businessId")
	if businessIDStr == "" {
		validationErrors = append(validationErrors, "Business ID is required.")
	} else {
		businessID, err := uuid.Parse(businessIDStr)
		if err != nil {
			validationErrors = append(validationErrors, "Invalid business ID format.")
		}
		req.BusinessID = businessID
	}

	// Name
	req.Name = getFormValue("name")
	if req.Name == "" {
		validationErrors = append(validationErrors, "Service name is required.")
	} else if len(req.Name) < 3 || len(req.Name) > 100 {
		validationErrors = append(validationErrors, "Service name must be between 3 and 100 characters.")
	} else if badwords.ContainsBadWords(req.Name) {
		validationErrors = append(validationErrors, "Service name contains inappropriate language.")
	}

	// Description
	req.Description = getFormValue("description")
	if len(req.Description) > 5000 {
		validationErrors = append(validationErrors, "Description must not exceed 5000 characters.")
	} else if req.Description != "" && badwords.ContainsBadWords(req.Description) {
		validationErrors = append(validationErrors, "Description contains inappropriate language.")
	}

	// DurationMinutes
	durationStr := getFormValue("durationMinutes")
	if durationStr == "" {
		validationErrors = append(validationErrors, "Duration in minutes is required.")
	} else {
		duration, err := strconv.Atoi(durationStr)
		if err != nil {
			validationErrors = append(validationErrors, "Invalid duration format. Must be a whole number.")
		} else if duration < MinDurationMinutes {
			validationErrors = append(validationErrors, fmt.Sprintf("Duration must be at least %d minutes.", MinDurationMinutes))
		}
		req.DurationMinutes = duration
	}

	// Price
	priceStr := getFormValue("price")
	if priceStr == "" {
		validationErrors = append(validationErrors, "Price is required.")
	} else {
		price, err := utils.ParseFloat(priceStr) // Assuming utils.ParseFloat exists and works
		if err != nil {
			validationErrors = append(validationErrors, "Invalid price format. Must be a number.")
		} else if price < MinPrice {
			validationErrors = append(validationErrors, fmt.Sprintf("Price must be at least %.2f.", MinPrice))
		}
		req.Price = price
	}

	if len(validationErrors) > 0 {
		sc.respondWithError(c, http.StatusBadRequest,
			NewServiceError("VALIDATION_ERROR", strings.Join(validationErrors, "; "), nil))
		return
	}

	// 4. Handle image file
	files, ok := form.File["image"]
	if !ok || len(files) == 0 {
		sc.respondWithError(c, http.StatusBadRequest,
			NewServiceError("MISSING_IMAGE", "Image file is required for service creation.", nil))
		return
	}
	fileHeader := files[0]

	// Open the multipart file. This gives us an io.ReadSeeker.
	file, err := fileHeader.Open()
	if err != nil {
		sc.respondWithError(c, http.StatusInternalServerError, NewServiceError("FILE_OPEN_ERROR", "Failed to open uploaded image file.", err))
		return
	}
	defer file.Close()

	// Validate the file without reading it all into memory.
	if err := sc.validateImageFile(file, fileHeader); err != nil {
		sc.respondWithError(c, http.StatusBadRequest, err.(*ServiceError))
		return
	}

	// 5. Authentication & Authorization
	ownerUserID, err := utils.GetUserIDFromContext(c) // This depends on your auth middleware
	if err != nil {
		sc.respondWithError(c, http.StatusUnauthorized, NewServiceError("AUTH_ERROR", "Authentication required to perform this action.", err))
		return
	}

	business, err := business_models.GetBusinessByID(sc.DB, req.BusinessID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") { // Specific check for "not found"
			sc.respondWithError(c, http.StatusNotFound, NewServiceError("BUSINESS_NOT_FOUND", "Associated business not found.", err))
		} else {
			sc.respondWithError(c, http.StatusInternalServerError, NewServiceError("DATABASE_ERROR", "Failed to retrieve business details for authorization.", err))
		}
		return
	}

	if business.OwnerID != ownerUserID {
		sc.respondWithError(c, http.StatusForbidden, NewServiceError("UNAUTHORIZED_BUSINESS", "You are not authorized to add services to this business.", nil))
		return
	}

	// 6. Upload image to external service
	imageContentType := fileHeader.Header.Get("Content-Type")
	// If the content type from the header is missing or generic, detect it.
	if imageContentType == "" || imageContentType == "application/octet-stream" {
		// We can't use http.DetectContentType here again without re-reading the header.
		// Instead, we rely on the extension as a fallback. The validation already confirmed the actual content.
		imageContentType = mime.TypeByExtension(filepath.Ext(fileHeader.Filename))
		if imageContentType == "" {
			imageContentType = "application/octet-stream" // Default fallback
		}
	}

	authHeader := c.GetHeader("Authorization")

	// Pass the 'file' reader directly. The upload function will stream from it.
	imageID, err := sc.uploadImageToService(ctx, file, fileHeader.Filename, imageContentType, req.BusinessID, authHeader)
	if err != nil {
		sc.respondWithError(c, http.StatusInternalServerError, err.(*ServiceError))
		return
	}

	// 7. Create service in database
	service := service_models.NewService(req.BusinessID, req.Name, req.Description, req.DurationMinutes, req.Price)
	service.ImageID = imageID

	createdService, err := service_models.CreateServiceModel(sc.DB, service)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create service in database: %v", err)

		// Cleanup uploaded image asynchronously if DB insertion fails
		go func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			sc.cleanupImage(cleanupCtx, imageID, authHeader) // Use the same authHeader for cleanup
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

// GetServiceByID handles fetching a single service
func (sc *ServiceController) GetServiceByID(c *gin.Context) {
	logger.InfoLogger.Info("GetServiceByID controller called")

	serviceIDStr := c.Param("id")
	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		sc.respondWithError(c, http.StatusBadRequest,
			NewServiceError("INVALID_ID", "Invalid service ID format.", err))
		return
	}

	service, err := service_models.GetServiceByIDModel(sc.DB, serviceID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			sc.respondWithError(c, http.StatusNotFound,
				NewServiceError("SERVICE_NOT_FOUND", "Service not found.", err))
		} else {
			sc.respondWithError(c, http.StatusInternalServerError,
				NewServiceError("DATABASE_ERROR", "Failed to fetch service.", err))
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"service": service})
}

// UpdateService handles service updates (expects JSON body, not multipart)
func (sc *ServiceController) UpdateService(c *gin.Context) {
	logger.InfoLogger.Info("UpdateService controller called")

	serviceIDStr := c.Param("id")
	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		sc.respondWithError(c, http.StatusBadRequest,
			NewServiceError("INVALID_ID", "Invalid service ID format.", err))
		return
	}

	var req UpdateServiceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sc.respondWithError(c, http.StatusBadRequest,
			NewServiceError("INVALID_REQUEST", "Invalid request data. Please provide valid JSON.", err))
		return
	}

	// Validate bad words for optional fields
	if req.Name != nil && badwords.ContainsBadWords(*req.Name) {
		sc.respondWithError(c, http.StatusBadRequest,
			NewServiceError("INAPPROPRIATE_CONTENT", "Service name contains inappropriate language.", nil))
		return
	}
	if req.Description != nil && badwords.ContainsBadWords(*req.Description) {
		sc.respondWithError(c, http.StatusBadRequest,
			NewServiceError("INAPPROPRIATE_CONTENT", "Service description contains inappropriate language.", nil))
		return
	}

	// Authentication
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		sc.respondWithError(c, http.StatusUnauthorized,
			NewServiceError("AUTH_ERROR", "Authentication required.", err))
		return
	}

	// Fetch existing service to check ownership
	existingService, err := service_models.GetServiceByIDModel(sc.DB, serviceID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			sc.respondWithError(c, http.StatusNotFound,
				NewServiceError("SERVICE_NOT_FOUND", "Service not found.", err))
		} else {
			sc.respondWithError(c, http.StatusInternalServerError,
				NewServiceError("DATABASE_ERROR", "Failed to fetch service for update.", err))
		}
		return
	}

	business, err := business_models.GetBusinessByID(sc.DB, existingService.BusinessID)
	if err != nil {
		sc.respondWithError(c, http.StatusInternalServerError,
			NewServiceError("DATABASE_ERROR", "Failed to verify business ownership.", err))
		return
	}

	if business.OwnerID != ownerUserID {
		sc.respondWithError(c, http.StatusForbidden,
			NewServiceError("UNAUTHORIZED", "You are not authorized to update this service.", nil))
		return
	}

	// Apply updates to the existing service model
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
			sc.respondWithError(c, http.StatusBadRequest,
				NewServiceError("INVALID_IMAGE_ID", "Invalid image ID format.", err))
			return
		}
		existingService.ImageID = imageUUID
	}

	updatedService, err := service_models.UpdateServiceModel(sc.DB, existingService)
	if err != nil {
		sc.respondWithError(c, http.StatusInternalServerError,
			NewServiceError("DATABASE_ERROR", "Failed to update service in the database.", err))
		return
	}

	logger.InfoLogger.Infof("Service %s updated successfully by user %s", serviceID, ownerUserID)
	c.JSON(http.StatusOK, gin.H{
		"message": "Service updated successfully!",
		"service": updatedService,
	})
}

// DeleteService handles service deletion
func (sc *ServiceController) DeleteService(c *gin.Context) {
	logger.InfoLogger.Info("DeleteService controller called")

	serviceIDStr := c.Param("id")
	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		sc.respondWithError(c, http.StatusBadRequest,
			NewServiceError("INVALID_ID", "Invalid service ID format.", err))
		return
	}

	// Authentication
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		sc.respondWithError(c, http.StatusUnauthorized,
			NewServiceError("AUTH_ERROR", "Authentication required.", err))
		return
	}

	// Fetch existing service to check ownership
	existingService, err := service_models.GetServiceByIDModel(sc.DB, serviceID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			sc.respondWithError(c, http.StatusNotFound,
				NewServiceError("SERVICE_NOT_FOUND", "Service not found.", err))
		} else {
			sc.respondWithError(c, http.StatusInternalServerError,
				NewServiceError("DATABASE_ERROR", "Failed to fetch service for deletion.", err))
		}
		return
	}

	business, err := business_models.GetBusinessByID(sc.DB, existingService.BusinessID)
	if err != nil {
		sc.respondWithError(c, http.StatusInternalServerError,
			NewServiceError("DATABASE_ERROR", "Failed to verify business ownership.", err))
		return
	}

	if business.OwnerID != ownerUserID {
		sc.respondWithError(c, http.StatusForbidden,
			NewServiceError("UNAUTHORIZED", "You are not authorized to delete this service.", nil))
		return
	}

	// Delete service
	if err := service_models.DeleteServiceModel(sc.DB, serviceID, existingService.BusinessID); err != nil {
		sc.respondWithError(c, http.StatusInternalServerError,
			NewServiceError("DATABASE_ERROR", "Failed to delete service from the database.", err))
		return
	}

	logger.InfoLogger.Infof("Service %s deleted successfully by user %s", serviceID, ownerUserID)
	c.JSON(http.StatusOK, gin.H{"message": "Service deleted successfully."})
}

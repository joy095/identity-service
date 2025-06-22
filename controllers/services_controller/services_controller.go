package services_controller

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/joy095/identity/badwords"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/business_models"
	"github.com/joy095/identity/models/service_models"
	"github.com/joy095/identity/utils"
)

// Configuration constants
const (
	MaxMemorySize        = 100 << 20 // 100MB - Gin's default for form parsing
	MaxImageSize         = 10 << 20  // 10MB
	MinDurationMinutes   = 15
	MaxDurationMinutes   = 1440 // 24 hours
	MinPrice             = 1.0
	MaxPrice             = 99999.99
	ImageServiceTimeout  = 3 * time.Minute
	MaxImageSizeMB       = 10 // For error message clarity
	MaxNameLength        = 100
	MinNameLength        = 3
	MaxDescriptionLength = 5000
	DefaultTimeout       = 5 * time.Minute
	CleanupTimeout       = 30 * time.Second
)

var (
	SupportedImageTypes = map[string]bool{
		"image/jpeg": true,
		"image/jpg":  true,
		"image/png":  true,
		"image/webp": true,
		"image/gif":  true,
	}

	// Common errors
	ErrInvalidUUID         = errors.New("invalid UUID format")
	ErrServiceNotFound     = errors.New("service not found")
	ErrBusinessNotFound    = errors.New("business not found")
	ErrUnauthorized        = errors.New("unauthorized access")
	ErrImageServiceTimeout = errors.New("image service timeout")
	ErrImageServiceDown    = errors.New("image service unavailable")
)

// ServiceController holds dependencies for service-related operations.
type ServiceController struct {
	DB              *pgxpool.Pool
	ImageServiceURL string
	HTTPClient      *http.Client
}

// Request/Response structs
type CreateServiceRequest struct {
	BusinessID      uuid.UUID `json:"businessId" binding:"required"`
	Name            string    `json:"name" binding:"required,min=3,max=100"`
	Description     string    `json:"description,omitempty" binding:"max=5000"`
	DurationMinutes int       `json:"durationMinutes" binding:"required,min=15,max=1440"`
	Price           float64   `json:"price" binding:"required,min=1,max=99999.99"`
}

type UpdateServiceRequest struct {
	Name            *string  `json:"name,omitempty" binding:"omitempty,min=3,max=100"`
	Description     *string  `json:"description,omitempty" binding:"omitempty,max=5000"`
	DurationMinutes *int     `json:"durationMinutes,omitempty" binding:"omitempty,min=15,max=1440"`
	Price           *float64 `json:"price,omitempty" binding:"omitempty,min=1,max=99999.99"`
	IsActive        *bool    `json:"isActive,omitempty"`
	ImageID         *string  `json:"imageId,omitempty"`
}

type ImageServiceResponse struct {
	Message string    `json:"message"`
	ImageID uuid.UUID `json:"image_id"`
	URL     string    `json:"url"`
}

type ErrorResponse struct {
	Error   string                 `json:"error"`
	Details map[string]interface{} `json:"details,omitempty"`
	Code    string                 `json:"code"`
}

type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"`
}

// Enhanced error types
type ServiceError struct {
	Code       string
	Message    string
	StatusCode int
	Err        error
	Details    map[string]interface{}
}

func (e *ServiceError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func NewServiceError(code, message string, statusCode int, err error) *ServiceError {
	return &ServiceError{
		Code:       code,
		Message:    message,
		StatusCode: statusCode,
		Err:        err,
		Details:    make(map[string]interface{}),
	}
}

func (e *ServiceError) WithDetail(key string, value interface{}) *ServiceError {
	e.Details[key] = value
	return e
}

// NewServiceController creates a new instance of ServiceController with validation
func NewServiceController(db *pgxpool.Pool) (*ServiceController, error) {
	if db == nil {
		return nil, errors.New("database connection pool cannot be nil")
	}

	imageServiceURL := os.Getenv("IMAGE_SERVICE_URL")
	if imageServiceURL == "" {
		logger.WarnLogger.Warn("IMAGE_SERVICE_URL not set, using default http://localhost:8082")
		imageServiceURL = "http://localhost:8082"
	}

	return &ServiceController{
		DB:              db,
		ImageServiceURL: imageServiceURL,
		HTTPClient: &http.Client{
			Timeout: ImageServiceTimeout,
		},
	}, nil
}

// validateImageFile checks image size, extension, and content type with enhanced validation
func (sc *ServiceController) validateImageFile(file multipart.File, fileHeader *multipart.FileHeader) error {
	if fileHeader == nil {
		return NewServiceError("MISSING_FILE_HEADER", "File header is missing", http.StatusBadRequest, nil)
	}

	if fileHeader.Size <= 0 {
		return NewServiceError("EMPTY_IMAGE", "Image file is empty", http.StatusBadRequest, nil)
	}

	if fileHeader.Size > MaxImageSize {
		return NewServiceError("FILE_TOO_LARGE",
			fmt.Sprintf("Image file too large. Maximum size is %dMB", MaxImageSizeMB),
			http.StatusBadRequest, nil).WithDetail("maxSize", MaxImageSizeMB).WithDetail("actualSize", fileHeader.Size/(1024*1024))
	}

	// Validate filename
	if fileHeader.Filename == "" {
		return NewServiceError("MISSING_FILENAME", "Filename is required", http.StatusBadRequest, nil)
	}

	// Check for potentially dangerous filenames
	if strings.Contains(fileHeader.Filename, "..") || strings.Contains(fileHeader.Filename, "/") || strings.Contains(fileHeader.Filename, "\\") {
		return NewServiceError("INVALID_FILENAME", "Filename contains invalid characters", http.StatusBadRequest, nil)
	}

	// Read the first 512 bytes to detect the content type
	headerBytes := make([]byte, 512)
	n, err := file.Read(headerBytes)
	if err != nil && !errors.Is(err, io.EOF) {
		return NewServiceError("FILE_READ_ERROR", "Could not read file header for validation", http.StatusInternalServerError, err)
	}

	// Rewind the file reader
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return NewServiceError("FILE_SEEK_ERROR", "Could not rewind file for streaming", http.StatusInternalServerError, err)
	}

	if n == 0 {
		return NewServiceError("EMPTY_IMAGE", "Image file content is empty", http.StatusBadRequest, nil)
	}

	detectedType := http.DetectContentType(headerBytes[:n])
	if !SupportedImageTypes[detectedType] {
		supportedTypes := make([]string, 0, len(SupportedImageTypes))
		for t := range SupportedImageTypes {
			supportedTypes = append(supportedTypes, t)
		}
		return NewServiceError("INVALID_FILE_CONTENT",
			fmt.Sprintf("File content type '%s' is not supported", detectedType),
			http.StatusBadRequest, nil).WithDetail("detectedType", detectedType).WithDetail("supportedTypes", supportedTypes)
	}

	return nil
}

// uploadImageToService with improved error handling and timeout management
func (sc *ServiceController) uploadImageToService(ctx context.Context, imageReader io.Reader,
	filename, contentType string, businessID uuid.UUID, authHeader string) (uuid.UUID, error) {

	// Add timeout to context if not already set
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ImageServiceTimeout)
		defer cancel()
	}

	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)
	errChan := make(chan error, 1)

	// Use goroutine with error channel for better error handling
	go func() {
		defer pw.Close()
		defer writer.Close()

		// Add business ID validation
		if businessID == uuid.Nil {
			errChan <- NewServiceError("INVALID_BUSINESS_ID", "Business ID cannot be nil", http.StatusBadRequest, nil)
			return
		}

		if err := writer.WriteField("businessId", businessID.String()); err != nil {
			errChan <- NewServiceError("FORM_CREATION_ERROR", "Failed to add business ID to form", http.StatusInternalServerError, err)
			return
		}

		partHeader := make(textproto.MIMEHeader)
		partHeader.Set("Content-Disposition", fmt.Sprintf(`form-data; name="image"; filename="%s"`, filename))
		partHeader.Set("Content-Type", contentType)

		part, err := writer.CreatePart(partHeader)
		if err != nil {
			errChan <- NewServiceError("FORM_PART_ERROR", "Failed to create image form part", http.StatusInternalServerError, err)
			return
		}

		if _, err := io.Copy(part, imageReader); err != nil {
			errChan <- NewServiceError("FORM_WRITE_ERROR", "Failed to stream image data to form", http.StatusInternalServerError, err)
			return
		}

		errChan <- nil // Success
	}()

	imageServiceUploadURL := sc.ImageServiceURL + "/upload-image/"
	req, err := http.NewRequestWithContext(ctx, "POST", imageServiceUploadURL, pr)
	if err != nil {
		return uuid.Nil, NewServiceError("REQUEST_CREATION_ERROR", "Failed to create request to image service", http.StatusInternalServerError, err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := sc.HTTPClient.Do(req)
	if err != nil {
		// Check for specific error types
		if errors.Is(err, context.DeadlineExceeded) {
			return uuid.Nil, NewServiceError("IMAGE_SERVICE_TIMEOUT", "Image service request timed out", http.StatusGatewayTimeout, err)
		}
		return uuid.Nil, NewServiceError("IMAGE_SERVICE_UNAVAILABLE", "Image service is unavailable", http.StatusServiceUnavailable, err)
	}
	defer resp.Body.Close()

	// Check for goroutine errors
	select {
	case goroutineErr := <-errChan:
		if goroutineErr != nil {
			return uuid.Nil, goroutineErr.(*ServiceError)
		}
	case <-ctx.Done():
		return uuid.Nil, NewServiceError("REQUEST_CANCELLED", "Request was cancelled", http.StatusRequestTimeout, ctx.Err())
	default:
		// Continue with response processing
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return uuid.Nil, NewServiceError("RESPONSE_READ_ERROR", "Failed to read response from image service", http.StatusInternalServerError, err)
	}

	if resp.StatusCode != http.StatusCreated {
		statusCode := http.StatusInternalServerError
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			statusCode = http.StatusBadRequest
		}
		return uuid.Nil, NewServiceError("IMAGE_SERVICE_ERROR",
			fmt.Sprintf("Image service responded with error (status %d)", resp.StatusCode),
			statusCode, nil).WithDetail("responseBody", string(respBody)).WithDetail("statusCode", resp.StatusCode)
	}

	var imageServiceResp ImageServiceResponse
	if err := json.Unmarshal(respBody, &imageServiceResp); err != nil {
		return uuid.Nil, NewServiceError("RESPONSE_PARSE_ERROR", "Failed to parse image service response", http.StatusInternalServerError, err).WithDetail("responseBody", string(respBody))
	}

	if imageServiceResp.ImageID == uuid.Nil {
		return uuid.Nil, NewServiceError("INVALID_IMAGE_ID", "Image service returned invalid image ID", http.StatusInternalServerError, nil)
	}

	return imageServiceResp.ImageID, nil
}

// cleanupImage with better error handling and logging
func (sc *ServiceController) cleanupImage(ctx context.Context, imageID uuid.UUID, authHeader string) {
	if imageID == uuid.Nil {
		logger.WarnLogger.Warn("Attempted to cleanup nil image ID")
		return
	}

	// Set cleanup timeout
	cleanupCtx, cancel := context.WithTimeout(ctx, CleanupTimeout)
	defer cancel()

	cleanupURL := fmt.Sprintf("%s/delete-image/%s", sc.ImageServiceURL, imageID)
	req, err := http.NewRequestWithContext(cleanupCtx, "DELETE", cleanupURL, nil)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create cleanup request for image %s: %v", imageID, err)
		return
	}

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := sc.HTTPClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			logger.ErrorLogger.Errorf("Cleanup timeout for image %s: %v", imageID, err)
		} else {
			logger.ErrorLogger.Errorf("Failed to cleanup image %s from image service: %v", imageID, err)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		bodyBytes, _ := io.ReadAll(resp.Body)
		logger.ErrorLogger.Errorf("Image cleanup failed for %s (status %d). Response: %s", imageID, resp.StatusCode, string(bodyBytes))
	} else {
		logger.InfoLogger.Infof("Successfully cleaned up image %s from image service", imageID)
	}
}

// Enhanced error response with detailed information
func (sc *ServiceController) respondWithError(c *gin.Context, serviceErr *ServiceError) {
	logger.ErrorLogger.Errorf("Service error [%s] (HTTP %d): %v", serviceErr.Code, serviceErr.StatusCode, serviceErr.Err)

	response := ErrorResponse{
		Error: serviceErr.Message,
		Code:  serviceErr.Code,
	}

	// Add details in development/debug mode
	if len(serviceErr.Details) > 0 {
		response.Details = serviceErr.Details
	}

	c.JSON(serviceErr.StatusCode, response)
}

// validateCreateServiceRequest with comprehensive validation
func (sc *ServiceController) validateCreateServiceRequest(req *CreateServiceRequest) []ValidationError {
	var validationErrors []ValidationError

	// Business ID validation
	if req.BusinessID == uuid.Nil {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "businessId",
			Message: "Business ID is required and cannot be empty",
		})
	}

	// Name validation
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "name",
			Message: "Service name is required",
		})
	} else if len(req.Name) < MinNameLength {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "name",
			Message: fmt.Sprintf("Service name must be at least %d characters", MinNameLength),
			Value:   req.Name,
		})
	} else if len(req.Name) > MaxNameLength {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "name",
			Message: fmt.Sprintf("Service name must not exceed %d characters", MaxNameLength),
			Value:   req.Name,
		})
	} else if badwords.ContainsBadWords(req.Name) {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "name",
			Message: "Service name contains inappropriate language",
		})
	}

	// Description validation
	req.Description = strings.TrimSpace(req.Description)
	if len(req.Description) > MaxDescriptionLength {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "description",
			Message: fmt.Sprintf("Description must not exceed %d characters", MaxDescriptionLength),
		})
	} else if req.Description != "" && badwords.ContainsBadWords(req.Description) {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "description",
			Message: "Description contains inappropriate language",
		})
	}

	// Duration validation
	if req.DurationMinutes < MinDurationMinutes {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "durationMinutes",
			Message: fmt.Sprintf("Duration must be at least %d minutes", MinDurationMinutes),
			Value:   strconv.Itoa(req.DurationMinutes),
		})
	} else if req.DurationMinutes > MaxDurationMinutes {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "durationMinutes",
			Message: fmt.Sprintf("Duration must not exceed %d minutes", MaxDurationMinutes),
			Value:   strconv.Itoa(req.DurationMinutes),
		})
	}

	// Price validation
	if req.Price < MinPrice {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "price",
			Message: fmt.Sprintf("Price must be at least %.2f", MinPrice),
			Value:   fmt.Sprintf("%.2f", req.Price),
		})
	} else if req.Price > MaxPrice {
		validationErrors = append(validationErrors, ValidationError{
			Field:   "price",
			Message: fmt.Sprintf("Price must not exceed %.2f", MaxPrice),
			Value:   fmt.Sprintf("%.2f", req.Price),
		})
	}

	return validationErrors
}

// CreateService with comprehensive error handling
func (sc *ServiceController) CreateService(c *gin.Context) {
	logger.InfoLogger.Info("CreateService controller called")

	// Validate Content-Type
	contentType := strings.ToLower(c.GetHeader("Content-Type"))
	if !strings.HasPrefix(contentType, "multipart/form-data") {
		sc.respondWithError(c, NewServiceError("INVALID_CONTENT_TYPE", "Request must be multipart/form-data", http.StatusBadRequest, nil))
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), DefaultTimeout)
	defer cancel()

	// Parse form data with validation
	businessIDStr := strings.TrimSpace(c.PostForm("businessId"))
	name := strings.TrimSpace(c.PostForm("name"))
	description := strings.TrimSpace(c.PostForm("description"))
	durationStr := strings.TrimSpace(c.PostForm("durationMinutes"))
	priceStr := strings.TrimSpace(c.PostForm("price"))

	var req CreateServiceRequest
	var parseErrors []ValidationError

	// Parse and validate BusinessID
	if businessIDStr == "" {
		parseErrors = append(parseErrors, ValidationError{
			Field:   "businessId",
			Message: "Business ID is required",
		})
	} else {
		businessID, err := uuid.Parse(businessIDStr)
		if err != nil {
			parseErrors = append(parseErrors, ValidationError{
				Field:   "businessId",
				Message: "Invalid business ID format",
				Value:   businessIDStr,
			})
		} else {
			req.BusinessID = businessID
		}
	}

	// Parse other fields
	req.Name = name
	req.Description = description

	// Parse duration
	if durationStr == "" {
		parseErrors = append(parseErrors, ValidationError{
			Field:   "durationMinutes",
			Message: "Duration in minutes is required",
		})
	} else {
		duration, err := strconv.Atoi(durationStr)
		if err != nil {
			parseErrors = append(parseErrors, ValidationError{
				Field:   "durationMinutes",
				Message: "Invalid duration format. Must be a whole number",
				Value:   durationStr,
			})
		} else {
			req.DurationMinutes = duration
		}
	}

	// Parse price
	if priceStr == "" {
		parseErrors = append(parseErrors, ValidationError{
			Field:   "price",
			Message: "Price is required",
		})
	} else {
		price, err := utils.ParseFloat(priceStr)
		if err != nil {
			parseErrors = append(parseErrors, ValidationError{
				Field:   "price",
				Message: "Invalid price format. Must be a number",
				Value:   priceStr,
			})
		} else {
			req.Price = price
		}
	}

	// Combine parsing and validation errors
	allErrors := append(parseErrors, sc.validateCreateServiceRequest(&req)...)
	if len(allErrors) > 0 {
		sc.respondWithError(c, NewServiceError("VALIDATION_ERROR", "Request validation failed", http.StatusBadRequest, nil).WithDetail("validationErrors", allErrors))
		return
	}

	// Handle image file
	fileHeader, err := c.FormFile("image")
	if err != nil {
		sc.respondWithError(c, NewServiceError("MISSING_IMAGE", "Image file is required for service creation", http.StatusBadRequest, err))
		return
	}

	file, err := fileHeader.Open()
	if err != nil {
		sc.respondWithError(c, NewServiceError("FILE_OPEN_ERROR", "Failed to open uploaded image file", http.StatusInternalServerError, err))
		return
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.WarnLogger.Warnf("Failed to close file: %v", closeErr)
		}
	}()

	// Validate image file
	if err := sc.validateImageFile(file, fileHeader); err != nil {
		sc.respondWithError(c, err.(*ServiceError))
		return
	}

	// Authentication & Authorization
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		sc.respondWithError(c, NewServiceError("AUTH_ERROR", "Authentication required to perform this action", http.StatusUnauthorized, err))
		return
	}

	// Verify business ownership with better error handling
	business, err := business_models.GetBusinessByID(sc.DB, req.BusinessID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			sc.respondWithError(c, NewServiceError("BUSINESS_NOT_FOUND", "Associated business not found", http.StatusNotFound, err))
		} else {
			sc.respondWithError(c, NewServiceError("DATABASE_ERROR", "Failed to retrieve business details", http.StatusInternalServerError, err))
		}
		return
	}

	if business.OwnerID != ownerUserID {
		sc.respondWithError(c, NewServiceError("UNAUTHORIZED_BUSINESS", "You are not authorized to add services to this business", http.StatusForbidden, nil))
		return
	}

	// Upload image to external service
	imageContentType := fileHeader.Header.Get("Content-Type")
	if imageContentType == "" || imageContentType == "application/octet-stream" {
		imageContentType = mime.TypeByExtension(filepath.Ext(fileHeader.Filename))
		if imageContentType == "" {
			imageContentType = "application/octet-stream"
		}
	}

	authHeader := c.GetHeader("Authorization")
	imageID, err := sc.uploadImageToService(ctx, file, fileHeader.Filename, imageContentType, req.BusinessID, authHeader)
	if err != nil {
		sc.respondWithError(c, err.(*ServiceError))
		return
	}

	// Create service in database with transaction-like behavior
	service := service_models.NewService(req.BusinessID, req.Name, req.Description, req.DurationMinutes, req.Price)
	service.ImageID = imageID

	createdService, err := service_models.CreateServiceModel(sc.DB, service)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create service in database: %v", err)

		// Cleanup image asynchronously
		go func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), CleanupTimeout)
			defer cleanupCancel()
			sc.cleanupImage(cleanupCtx, imageID, authHeader)
		}()

		if strings.Contains(err.Error(), "duplicate key value") {
			sc.respondWithError(c, NewServiceError("DUPLICATE_SERVICE", "A service with this name already exists for this business", http.StatusConflict, err))
		} else {
			sc.respondWithError(c, NewServiceError("DATABASE_ERROR", "Failed to create service in the database", http.StatusInternalServerError, err))
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

// GetServiceByID with enhanced error handling
func (sc *ServiceController) GetServiceByID(c *gin.Context) {
	logger.InfoLogger.Info("GetServiceByID controller called")

	serviceIDStr := strings.TrimSpace(c.Param("id"))
	if serviceIDStr == "" {
		sc.respondWithError(c, NewServiceError("MISSING_ID", "Service ID is required", http.StatusBadRequest, nil))
		return
	}

	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		sc.respondWithError(c, NewServiceError("INVALID_ID", "Invalid service ID format", http.StatusBadRequest, err).WithDetail("providedId", serviceIDStr))
		return
	}

	service, err := service_models.GetServiceByIDModel(sc.DB, serviceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			sc.respondWithError(c, NewServiceError("SERVICE_NOT_FOUND", "Service not found", http.StatusNotFound, err))
		} else {
			sc.respondWithError(c, NewServiceError("DATABASE_ERROR", "Failed to fetch service", http.StatusInternalServerError, err))
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"service": service})
}

// UpdateService with comprehensive validation and error handling
func (sc *ServiceController) UpdateService(c *gin.Context) {
	logger.InfoLogger.Info("UpdateService controller called")

	serviceIDStr := strings.TrimSpace(c.Param("id"))
	if serviceIDStr == "" {
		sc.respondWithError(c, NewServiceError("MISSING_ID", "Service ID is required", http.StatusBadRequest, nil))
		return
	}

	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		sc.respondWithError(c, NewServiceError("INVALID_ID", "Invalid service ID format", http.StatusBadRequest, err))
		return
	}

	var req UpdateServiceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		sc.respondWithError(c, NewServiceError("INVALID_REQUEST", "Invalid request data. Please provide valid JSON", http.StatusBadRequest, err))
		return
	}

	// Validate fields if provided
	var validationErrors []ValidationError

	if req.Name != nil {
		*req.Name = strings.TrimSpace(*req.Name)
		if len(*req.Name) < MinNameLength {
			validationErrors = append(validationErrors, ValidationError{
				Field:   "name",
				Message: fmt.Sprintf("Service name must be at least %d characters", MinNameLength),
			})
		} else if len(*req.Name) > MaxNameLength {
			validationErrors = append(validationErrors, ValidationError{
				Field:   "name",
				Message: fmt.Sprintf("Service name must not exceed %d characters", MaxNameLength),
			})
		} else if badwords.ContainsBadWords(*req.Name) {
			validationErrors = append(validationErrors, ValidationError{
				Field:   "name",
				Message: "Service name contains inappropriate language",
			})
		}
	}

	if req.Description != nil {
		*req.Description = strings.TrimSpace(*req.Description)
		if len(*req.Description) > MaxDescriptionLength {
			validationErrors = append(validationErrors, ValidationError{
				Field:   "description",
				Message: fmt.Sprintf("Description must not exceed %d characters", MaxDescriptionLength),
			})
		} else if *req.Description != "" && badwords.ContainsBadWords(*req.Description) {
			validationErrors = append(validationErrors, ValidationError{
				Field:   "description",
				Message: "Description contains inappropriate language",
			})
		}
	}

	if req.DurationMinutes != nil {
		if *req.DurationMinutes < MinDurationMinutes {
			validationErrors = append(validationErrors, ValidationError{
				Field:   "durationMinutes",
				Message: fmt.Sprintf("Duration must be at least %d minutes", MinDurationMinutes),
			})
		} else if *req.DurationMinutes > MaxDurationMinutes {
			validationErrors = append(validationErrors, ValidationError{
				Field:   "durationMinutes",
				Message: fmt.Sprintf("Duration must not exceed %d minutes", MaxDurationMinutes),
			})
		}
	}

	if req.Price != nil {
		if *req.Price < MinPrice {
			validationErrors = append(validationErrors, ValidationError{
				Field:   "price",
				Message: fmt.Sprintf("Price must be at least %.2f", MinPrice),
			})
		} else if *req.Price > MaxPrice {
			validationErrors = append(validationErrors, ValidationError{
				Field:   "price",
				Message: fmt.Sprintf("Price must not exceed %.2f", MaxPrice),
			})
		}
	}

	if req.ImageID != nil {
		if *req.ImageID != "" {
			if _, err := uuid.Parse(*req.ImageID); err != nil {
				validationErrors = append(validationErrors, ValidationError{
					Field:   "imageId",
					Message: "Invalid image ID format",
					Value:   *req.ImageID,
				})
			}
		}
	}

	if len(validationErrors) > 0 {
		sc.respondWithError(c, NewServiceError("VALIDATION_ERROR", "Request validation failed", http.StatusBadRequest, nil).WithDetail("validationErrors", validationErrors))
		return
	}

	// Authentication
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		sc.respondWithError(c, NewServiceError("AUTH_ERROR", "Authentication required", http.StatusUnauthorized, err))
		return
	}

	// Fetch existing service to check ownership
	existingService, err := service_models.GetServiceByIDModel(sc.DB, serviceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			sc.respondWithError(c, NewServiceError("SERVICE_NOT_FOUND", "Service not found", http.StatusNotFound, err))
		} else {
			sc.respondWithError(c, NewServiceError("DATABASE_ERROR", "Failed to fetch service for update", http.StatusInternalServerError, err))
		}
		return
	}

	// Verify business ownership
	business, err := business_models.GetBusinessByID(sc.DB, existingService.BusinessID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			sc.respondWithError(c, NewServiceError("BUSINESS_NOT_FOUND", "Associated business not found", http.StatusNotFound, err))
		} else {
			sc.respondWithError(c, NewServiceError("DATABASE_ERROR", "Failed to verify business ownership", http.StatusInternalServerError, err))
		}
		return
	}

	if business.OwnerID != ownerUserID {
		sc.respondWithError(c, NewServiceError("UNAUTHORIZED", "You are not authorized to update this service", http.StatusForbidden, nil))
		return
	}

	// Track changes for logging
	changes := make(map[string]interface{})

	// Apply updates to the existing service model
	if req.Name != nil && *req.Name != existingService.Name {
		changes["name"] = map[string]string{"from": existingService.Name, "to": *req.Name}
		existingService.Name = *req.Name
	}
	if req.Description != nil && *req.Description != existingService.Description {
		changes["description"] = map[string]string{"from": existingService.Description, "to": *req.Description}
		existingService.Description = *req.Description
	}
	if req.DurationMinutes != nil && *req.DurationMinutes != existingService.DurationMinutes {
		changes["durationMinutes"] = map[string]int{"from": existingService.DurationMinutes, "to": *req.DurationMinutes}
		existingService.DurationMinutes = *req.DurationMinutes
	}
	if req.Price != nil && *req.Price != existingService.Price {
		changes["price"] = map[string]float64{"from": existingService.Price, "to": *req.Price}
		existingService.Price = *req.Price
	}
	if req.IsActive != nil && *req.IsActive != existingService.IsActive {
		changes["isActive"] = map[string]bool{"from": existingService.IsActive, "to": *req.IsActive}
		existingService.IsActive = *req.IsActive
	}
	if req.ImageID != nil {
		var newImageID uuid.UUID
		if *req.ImageID != "" {
			newImageID, _ = uuid.Parse(*req.ImageID) // Already validated above
		}
		if newImageID != existingService.ImageID {
			changes["imageId"] = map[string]string{"from": existingService.ImageID.String(), "to": newImageID.String()}
			existingService.ImageID = newImageID
		}
	}

	// Check if any changes were made
	if len(changes) == 0 {
		sc.respondWithError(c, NewServiceError("NO_CHANGES", "No changes detected in the request", http.StatusBadRequest, nil))
		return
	}

	// Update service in database
	updatedService, err := service_models.UpdateServiceModel(sc.DB, existingService)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value") {
			sc.respondWithError(c, NewServiceError("DUPLICATE_SERVICE", "A service with this name already exists for this business", http.StatusConflict, err))
		} else {
			sc.respondWithError(c, NewServiceError("DATABASE_ERROR", "Failed to update service in the database", http.StatusInternalServerError, err))
		}
		return
	}

	logger.InfoLogger.Infof("Service %s updated successfully by user %s. Changes: %+v", serviceID, ownerUserID, changes)
	c.JSON(http.StatusOK, gin.H{
		"message": "Service updated successfully!",
		"service": updatedService,
		"changes": changes,
	})
}

// DeleteService with enhanced error handling and validation
func (sc *ServiceController) DeleteService(c *gin.Context) {
	logger.InfoLogger.Info("DeleteService controller called")

	serviceIDStr := strings.TrimSpace(c.Param("id"))
	if serviceIDStr == "" {
		sc.respondWithError(c, NewServiceError("MISSING_ID", "Service ID is required", http.StatusBadRequest, nil))
		return
	}

	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		sc.respondWithError(c, NewServiceError("INVALID_ID", "Invalid service ID format", http.StatusBadRequest, err))
		return
	}

	// Authentication
	ownerUserID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		sc.respondWithError(c, NewServiceError("AUTH_ERROR", "Authentication required", http.StatusUnauthorized, err))
		return
	}

	// Fetch existing service to check ownership and get image ID for cleanup
	existingService, err := service_models.GetServiceByIDModel(sc.DB, serviceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			sc.respondWithError(c, NewServiceError("SERVICE_NOT_FOUND", "Service not found", http.StatusNotFound, err))
		} else {
			sc.respondWithError(c, NewServiceError("DATABASE_ERROR", "Failed to fetch service for deletion", http.StatusInternalServerError, err))
		}
		return
	}

	// Verify business ownership
	business, err := business_models.GetBusinessByID(sc.DB, existingService.BusinessID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			sc.respondWithError(c, NewServiceError("BUSINESS_NOT_FOUND", "Associated business not found", http.StatusNotFound, err))
		} else {
			sc.respondWithError(c, NewServiceError("DATABASE_ERROR", "Failed to verify business ownership", http.StatusInternalServerError, err))
		}
		return
	}

	if business.OwnerID != ownerUserID {
		sc.respondWithError(c, NewServiceError("UNAUTHORIZED", "You are not authorized to delete this service", http.StatusForbidden, nil))
		return
	}

	// Store image ID for cleanup
	imageIDForCleanup := existingService.ImageID

	// Delete service from database
	if err := service_models.DeleteServiceModel(sc.DB, serviceID, existingService.BusinessID); err != nil {
		if strings.Contains(err.Error(), "foreign key constraint") {
			sc.respondWithError(c, NewServiceError("SERVICE_IN_USE", "Cannot delete service as it is currently in use (has active bookings)", http.StatusConflict, err))
		} else {
			sc.respondWithError(c, NewServiceError("DATABASE_ERROR", "Failed to delete service from the database", http.StatusInternalServerError, err))
		}
		return
	}

	// Clean up associated image asynchronously
	if imageIDForCleanup != uuid.Nil {
		go func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), CleanupTimeout)
			defer cleanupCancel()
			authHeader := c.GetHeader("Authorization")
			sc.cleanupImage(cleanupCtx, imageIDForCleanup, authHeader)
		}()
	}

	logger.InfoLogger.Infof("Service %s ('%s') deleted successfully by user %s", serviceID, existingService.Name, ownerUserID)
	c.JSON(http.StatusOK, gin.H{
		"message": "Service deleted successfully.",
		"deletedService": gin.H{
			"id":   serviceID,
			"name": existingService.Name,
		},
	})
}

// GetServicesByBusinessID retrieves all services for a specific business
// func (sc *ServiceController) GetServicesByBusinessID(c *gin.Context) {
// 	logger.InfoLogger.Info("GetServicesByBusinessID controller called")

// 	businessIDStr := strings.TrimSpace(c.Param("businessId"))
// 	if businessIDStr == "" {
// 		sc.respondWithError(c, NewServiceError("MISSING_BUSINESS_ID", "Business ID is required", http.StatusBadRequest, nil))
// 		return
// 	}

// 	businessID, err := uuid.Parse(businessIDStr)
// 	if err != nil {
// 		sc.respondWithError(c, NewServiceError("INVALID_BUSINESS_ID", "Invalid business ID format", http.StatusBadRequest, err))
// 		return
// 	}

// 	// Verify business exists
// 	_, err = business_models.GetBusinessByID(sc.DB, businessID)
// 	if err != nil {
// 		if errors.Is(err, pgx.ErrNoRows) {
// 			sc.respondWithError(c, NewServiceError("BUSINESS_NOT_FOUND", "Business not found", http.StatusNotFound, err))
// 		} else {
// 			sc.respondWithError(c, NewServiceError("DATABASE_ERROR", "Failed to verify business existence", http.StatusInternalServerError, err))
// 		}
// 		return
// 	}

// 	// Get services for the business
// 	services, err := service_models.GetServicesByBusinessIDModel(sc.DB, businessID)
// 	if err != nil {
// 		sc.respondWithError(c, NewServiceError("DATABASE_ERROR", "Failed to fetch services", http.StatusInternalServerError, err))
// 		return
// 	}

// 	// Handle empty results
// 	if len(services) == 0 {
// 		c.JSON(http.StatusOK, gin.H{
// 			"message":  "No services found for this business",
// 			"services": []interface{}{},
// 			"count":    0,
// 		})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{
// 		"services": services,
// 		"count":    len(services),
// 	})
// }

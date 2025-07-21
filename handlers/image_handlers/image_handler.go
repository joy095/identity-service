// Package image_handlers provides generic handlers for processing and forwarding image uploads.
package image_handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joy095/identity/logger" // Assuming a shared logger package
	"github.com/joy095/identity/models/shared_models"
)

// ImageUploadResult mirrors the successful or failed result for a single image from Python
type ImageUploadResult struct {
	Success  bool      `json:"success"`
	ImageID  uuid.UUID `json:"image_id,omitempty"` // Use omitempty as it might be missing on error
	Filename string    `json:"filename"`
	Detail   *string   `json:"detail,omitempty"` // For error details
}

// SingleImageUploadResponse defines the expected JSON structure for a single image upload.
type SingleImageUploadResponse struct {
	ImageID uuid.UUID `json:"image_id"`
}

// MultiImageUploadResponse defines the expected JSON structure for multiple image uploads.
type MultiImageUploadResponse struct {
	ImageIDs []uuid.UUID `json:"image_ids"`
}

// BulkUploadResponse mirrors the overall response structure from Python's /upload-multiple/
type BulkUploadResponse struct {
	Results []ImageUploadResult `json:"results"`
}

// processMultiImageResponse processes the HTTP response for a multiple image upload.
func processMultiImageResponse(c *gin.Context, resp *http.Response) ([]uuid.UUID, error) {
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.ErrorLogger.Error("failed to read multi-image response from image service: %w", err)
		return nil, fmt.Errorf("failed to read multi-image response from image service: %w", err)
	}

	// --- ADD THIS LINE TO SEE THE RAW RESPONSE Go RECEIVED ---
	logger.InfoLogger.Debugf("Raw Python Response received by Go: %s", string(responseBody))

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		errMessage := fmt.Sprintf("image service returned error (Status: %d, Body: %s)", resp.StatusCode, string(responseBody))
		logger.ErrorLogger.Error(errMessage)
		c.JSON(resp.StatusCode, gin.H{"error": errMessage})
		return nil, fmt.Errorf(errMessage)
	}

	var bulkResp BulkUploadResponse
	if err := json.Unmarshal(responseBody, &bulkResp); err != nil {
		errMessage := fmt.Sprintf("failed to parse multi-image response from image service: %v. Response body: %s", err, string(responseBody))
		logger.ErrorLogger.Error(errMessage)
		c.JSON(http.StatusInternalServerError, gin.H{"error": errMessage})
		return nil, fmt.Errorf(errMessage)
	}

	// --- ADD THIS LINE TO SEE THE UNMARSHALED GO STRUCT ---
	logger.InfoLogger.Debugf("Unmarshaled Go struct (bulkResp): %+v", bulkResp)

	var uploadedImageIDs []uuid.UUID
	for i, result := range bulkResp.Results {
		// --- ADD THESE LINES TO DEBUG EACH INDIVIDUAL RESULT ---
		logger.InfoLogger.Debugf("Processing result %d: Success=%t, ImageID=%s, ImageID_IsNil=%t, Filename=%s",
			i, result.Success, result.ImageID.String(), (result.ImageID == uuid.Nil), result.Filename)

		if result.Success && result.ImageID != uuid.Nil {
			uploadedImageIDs = append(uploadedImageIDs, result.ImageID)
		} else {
			detailMsg := "N/A"        // Default value if Detail is nil or empty
			if result.Detail != nil { // Now this check is valid
				// Check if the dereferenced string is empty before assigning
				if *result.Detail != "" {
					detailMsg = *result.Detail // Now this dereference is valid
				}
			}
			logger.ErrorLogger.Warnf("Image upload failed for file '%s'. Success: %t, ImageID valid: %t. Detail: %s",
				result.Filename, result.Success, (result.ImageID != uuid.Nil), detailMsg)
		}
	}

	if len(uploadedImageIDs) == 0 && len(bulkResp.Results) > 0 {
		errMessage := "image service processed images, but no valid image IDs were returned (all individual uploads might have failed or IDs were malformed)."
		logger.ErrorLogger.Error(errMessage)
		c.JSON(http.StatusInternalServerError, gin.H{"error": errMessage})
		return nil, fmt.Errorf(errMessage)
	} else if len(bulkResp.Results) == 0 {
		errMessage := "image service returned an empty 'results' array. No images processed or unknown error."
		logger.ErrorLogger.Error(errMessage)
		c.JSON(http.StatusInternalServerError, gin.H{"error": errMessage})
		return nil, fmt.Errorf(errMessage)
	}

	logger.InfoLogger.Infof("Successfully extracted %d image IDs.", len(uploadedImageIDs))
	return uploadedImageIDs, nil
}

// HandleMultipleImageUpload processes multiple files from a gin context
// and sends them to the image service in a single request.
func HandleMultipleImageUpload(c *gin.Context, accessToken string) ([]uuid.UUID, error) {
	form, err := c.MultipartForm()
	if err != nil {
		return nil, fmt.Errorf("invalid multipart form: %w", err)
	}
	files := form.File["images"] // "images" is the field name for multiple files
	if len(files) == 0 {
		HandleFileError(c, http.ErrMissingFile, "images")
		return nil, fmt.Errorf("form files 'images' not found")
	}

	// Prepare request body with multiple files
	body, contentType, err := prepareMultipleMultipartRequest(files)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare image request"})
		return nil, err
	}

	// Note: The endpoint should be designed to handle multiple uploads, e.g., "/images/upload-multiple/"
	pythonServerURL := getServiceURL() + "/images/upload-multiple/"
	httpReq, err := http.NewRequest("POST", pythonServerURL, body)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create HTTP request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upload request"})
		return nil, err
	}

	// Send request and process response
	resp, err := sendRequestToImageService(httpReq, contentType, accessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return nil, err
	}
	defer resp.Body.Close()

	return processMultiImageResponse(c, resp)
}

// HandleImageReplacement sends a file to replace an existing image.
func HandleImageReplacement(c *gin.Context, accessToken string, existingImageID uuid.UUID) (uuid.UUID, error) {
	fileHeader, err := c.FormFile("image")
	if err != nil {
		HandleFileError(c, err, "image")
		return uuid.Nil, fmt.Errorf("form file 'image' not found")
	}

	// Prepare request
	body, contentType, err := prepareSingleMultipartRequest(fileHeader)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare image request"})
		return uuid.Nil, err
	}

	pythonServerURL := getServiceURL() + "/replace-image/" + existingImageID.String()
	httpReq, err := http.NewRequest("PUT", pythonServerURL, body)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create HTTP request for image replacement: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create replacement request"})
		return uuid.Nil, err
	}

	// Send request and process response
	resp, err := sendRequestToImageService(httpReq, contentType, accessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return uuid.Nil, err
	}
	defer resp.Body.Close()

	return processSingleImageResponse(c, resp)
}

// DeleteImage sends a request to the image service to delete an image by its ID.
func DeleteImage(imageID uuid.UUID, accessToken string) error {
	if imageID == uuid.Nil {
		logger.InfoLogger.Info("No image ID provided, skipping deletion call.")
		return nil // Not an error, just nothing to do.
	}

	pythonServerURL := getServiceURL() + "/images/" + imageID.String()
	httpReq, err := http.NewRequest("DELETE", pythonServerURL, nil)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create DELETE request for image %s: %v", imageID, err)
		return fmt.Errorf("failed to create delete request")
	}

	// Send request
	resp, err := sendRequestToImageService(httpReq, "", accessToken)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		responseBody, _ := io.ReadAll(resp.Body)
		errMessage := fmt.Sprintf("image service returned an error on delete for ID %s. Status: %d, Body: %s", imageID, resp.StatusCode, string(responseBody))
		logger.ErrorLogger.Error(errMessage)
		return fmt.Errorf(errMessage)
	}

	logger.InfoLogger.Infof("Successfully requested deletion of image %s from image service.", imageID)
	return nil
}

// sendRequestToImageService executes a request and returns the response.
func sendRequestToImageService(req *http.Request, contentType, accessToken string) (*http.Response, error) {
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Add the access token as a cookie to be forwarded to the image service.
	req.AddCookie(&http.Cookie{
		Name:  "access_token",
		Value: accessToken,
		Path:  "/",
		// Consider adding Domain, Secure, HttpOnly, SameSite attributes for production
		Expires:  time.Now().Add(shared_models.ACCESS_TOKEN_EXPIRY),
		HttpOnly: true,
		Secure:   true, // Make this configurable as suggested in shared_models
		SameSite: http.SameSiteNoneMode,
	})

	client := &http.Client{Timeout: 90 * time.Second} // Increased timeout for multiple uploads
	resp, err := client.Do(req)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to send request to image service: %v", err)
		return nil, fmt.Errorf("failed to send request to image service")
	}

	return resp, nil
}

// getServiceURL retrieves the image service URL from environment variables with a fallback.
func getServiceURL() string {
	url := os.Getenv("IMAGE_SERVICE_URL")
	if url == "" {
		logger.WarnLogger.Warn("IMAGE_SERVICE_URL not set, using default localhost URL")
		return "http://localhost:8082" // Default URL
	}
	return url
}

// HandleFileError provides a standard way to handle file-related errors in Gin.
func HandleFileError(c *gin.Context, err error, fieldName string) {
	if err == http.ErrMissingFile {
		errMessage := fmt.Sprintf("Form file '%s' is missing from the request.", fieldName)
		logger.ErrorLogger.Error(errMessage)
		c.JSON(http.StatusBadRequest, gin.H{"error": errMessage})
		return
	}
	errMessage := fmt.Sprintf("Could not get form file '%s': %v", fieldName, err)
	logger.ErrorLogger.Error(errMessage)
	c.JSON(http.StatusBadRequest, gin.H{"error": "Could not process the provided image file(s)."})
}

// prepareSingleMultipartRequest creates a multipart request body for a single file.
func prepareSingleMultipartRequest(fileHeader *multipart.FileHeader) (*bytes.Buffer, string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	defer writer.Close()

	file, err := fileHeader.Open()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to open uploaded file: %v", err)
		return nil, "", err
	}
	defer file.Close()

	part, err := writer.CreateFormFile("image", fileHeader.Filename)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create form file for %s: %v", fileHeader.Filename, err)
		return nil, "", err
	}

	if _, err = io.Copy(part, file); err != nil {
		logger.ErrorLogger.Errorf("Failed to copy file data for %s: %v", fileHeader.Filename, err)
		return nil, "", err
	}

	return body, writer.FormDataContentType(), nil
}

// prepareMultipleMultipartRequest creates a multipart request body for multiple files.
func prepareMultipleMultipartRequest(files []*multipart.FileHeader) (*bytes.Buffer, string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to open uploaded file %s: %v", fileHeader.Filename, err)
			return nil, "", err
		}

		part, err := writer.CreateFormFile("images", fileHeader.Filename)
		if err != nil {
			file.Close()
			logger.ErrorLogger.Errorf("Failed to create form file for %s: %v", fileHeader.Filename, err)
			return nil, "", err
		}

		if _, err = io.Copy(part, file); err != nil {
			file.Close()
			logger.ErrorLogger.Errorf("Failed to copy file data for %s: %v", fileHeader.Filename, err)
			return nil, "", err
		}
		// Close file immediately after use
		file.Close()
	}

	// Close the writer to flush any buffered data
	if err := writer.Close(); err != nil {
		logger.ErrorLogger.Errorf("Failed to close multipart writer: %v", err)
		return nil, "", err
	}

	return body, writer.FormDataContentType(), nil
}

// processSingleImageResponse processes the HTTP response for a single image upload.
func processSingleImageResponse(c *gin.Context, resp *http.Response) (uuid.UUID, error) {
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		errMessage := "failed to read response from image service"
		logger.ErrorLogger.Error(errMessage)
		c.JSON(http.StatusInternalServerError, gin.H{"error": errMessage})
		return uuid.Nil, fmt.Errorf(errMessage)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		errMessage := fmt.Sprintf("image service returned error: %s", string(responseBody))
		logger.ErrorLogger.Error(errMessage)
		c.JSON(resp.StatusCode, gin.H{"error": errMessage})
		return uuid.Nil, fmt.Errorf(errMessage)
	}

	var imgResp SingleImageUploadResponse
	if err := json.Unmarshal(responseBody, &imgResp); err != nil {
		errMessage := fmt.Sprintf("failed to parse response from image service: %v", err)
		logger.ErrorLogger.Error(errMessage)
		c.JSON(http.StatusInternalServerError, gin.H{"error": errMessage})
		return uuid.Nil, fmt.Errorf(errMessage)
	}

	if imgResp.ImageID == uuid.Nil {
		errMessage := "image service returned invalid image ID"
		logger.ErrorLogger.Error(errMessage)
		c.JSON(http.StatusInternalServerError, gin.H{"error": errMessage})
		return uuid.Nil, fmt.Errorf(errMessage)
	}

	return imgResp.ImageID, nil
}

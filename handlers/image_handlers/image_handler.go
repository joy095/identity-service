// Package image_handlers provides generic handlers for processing and forwarding image uploads.
package image_handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joy095/identity/logger" // Assuming a shared logger package
)

// ImageUploadResponse defines the expected JSON structure of a successful response from the image service.
type ImageUploadResponse struct {
	ImageID uuid.UUID `json:"image_id"`
}

// HandleImageUpload is a reusable function that processes a file from a gin context
// and sends it to the image service for creation.
func HandleImageUpload(c *gin.Context, authHeader string) (uuid.UUID, error) {
	fileHeader, err := c.FormFile("image")
	if err != nil {
		HandleFileError(c, err)
		return uuid.Nil, fmt.Errorf("handled file error")
	}

	file, err := fileHeader.Open()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to open uploaded file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open uploaded file"})
		return uuid.Nil, err
	}
	defer file.Close()

	body, contentType := prepareMultipartRequest(file, fileHeader)

	// Build the request for the POST /upload-image/ endpoint
	pythonServerURL := getServiceURL() + "/upload-image/"
	httpReq, err := http.NewRequest("POST", pythonServerURL, body)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create HTTP request: %v", err)
		return uuid.Nil, fmt.Errorf("failed to create request")
	}

	return sendRequestToImageService(httpReq, contentType, authHeader)
}

// HandleImageReplacement is a reusable function that processes a file from a gin context
// and sends it to the image service to replace an existing image.
func HandleImageReplacement(c *gin.Context, authHeader string, existingImageID uuid.UUID) (uuid.UUID, error) {
	fileHeader, err := c.FormFile("image")
	if err != nil {
		HandleFileError(c, err)
		return uuid.Nil, err
	}

	file, err := fileHeader.Open()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to open uploaded file for replacement: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open uploaded file"})
		return uuid.Nil, err
	}
	defer file.Close()

	body, contentType := prepareMultipartRequest(file, fileHeader)

	// Build the request for the PUT /replace-image/{image_id} endpoint
	pythonServerURL := getServiceURL() + "/replace-image/" + existingImageID.String()
	httpReq, err := http.NewRequest("PUT", pythonServerURL, body)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create HTTP request for image replacement: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create replacement request"})
		return uuid.Nil, err
	}
	return sendRequestToImageService(httpReq, contentType, authHeader)
}

// HandleImageDeletion sends a request to the image service to delete an image by its ID.
func HandleImageDeletion(authHeader string, imageID uuid.UUID) error {
	if imageID == uuid.Nil {
		logger.InfoLogger.Info("No image ID provided, skipping deletion call.")
		return nil // Not an error, just nothing to do.
	}

	// Build the request for the DELETE /images/{image_id} endpoint
	pythonServerURL := getServiceURL() + "/images/" + imageID.String()
	httpReq, err := http.NewRequest("DELETE", pythonServerURL, nil)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create DELETE request for image %s: %v", imageID, err)
		return fmt.Errorf("failed to create delete request")
	}

	httpReq.AddCookie(&http.Cookie{
		Name:  "access_token",
		Value: authHeader,
		Path:  "/",
	})

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to send DELETE request to image service for ID %s: %v", imageID, err)
		return fmt.Errorf("failed to send delete request to image service")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		responseBody, _ := io.ReadAll(resp.Body)
		logger.ErrorLogger.Errorf("Image service returned an error on delete for ID %s. Status: %d, Body: %s", imageID, resp.StatusCode, string(responseBody))
		return fmt.Errorf("image service returned an error during deletion")
	}

	logger.InfoLogger.Infof("Successfully requested deletion of image %s from image service.", imageID)
	return nil
}

// --- PRIVATE HELPER FUNCTIONS ---

// sendRequestToImageService is a generic function to execute a request and process the response.
func sendRequestToImageService(req *http.Request, contentType, authHeader string) (uuid.UUID, error) {
	req.Header.Set("Content-Type", contentType)
	req.AddCookie(&http.Cookie{
		Name:  "access_token",
		Value: authHeader,
		Path:  "/",
	})

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to send request to image service: %v", err)
		return uuid.Nil, fmt.Errorf("failed to send request to image service")
	}
	defer resp.Body.Close()

	return processImageResponse(resp)
}

func getServiceURL() string {
	url := os.Getenv("IMAGE_SERVICE_URL")
	if url == "" {
		return "http://localhost:8082" // Default URL
	}
	return url
}

func HandleFileError(c *gin.Context, err error) {
	if err == http.ErrMissingFile {
		logger.ErrorLogger.Error("Form file 'image' is missing from the request.")
		c.JSON(http.StatusBadRequest, gin.H{"error": "An image file is required in the 'image' field."})
		return
	}
	logger.ErrorLogger.Errorf("Could not get form file 'image': %v", err)
	c.JSON(http.StatusBadRequest, gin.H{"error": "Could not process the provided image file."})
}

func prepareMultipartRequest(file multipart.File, fileHeader *multipart.FileHeader) (*bytes.Buffer, string) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "image", fileHeader.Filename))
	h.Set("Content-Type", fileHeader.Header.Get("Content-Type"))
	part, err := writer.CreatePart(h)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create multipart: %v", err)
		return nil, ""
	}
	_, err = io.Copy(part, file)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to copy file data: %v", err)
		return nil, ""
	}
	writer.Close()
	return body, writer.FormDataContentType()
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

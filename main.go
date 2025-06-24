package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/joy095/identity/badwords"
	"github.com/joy095/identity/config"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/middlewares/cors"
	"github.com/joy095/identity/models/service_models"
	"github.com/joy095/identity/routes"
	"github.com/joy095/identity/utils/mail"
)

//go:embed templates/email/*
var embeddedEmailTemplates embed.FS

func init() {
	logger.InitLoggers()
	config.LoadEnv()
}

// Updated request struct to make image required
type TestCreateServiceRequest struct {
	BusinessID      string  `form:"businessId" binding:"required"`
	Name            string  `form:"name" binding:"required"`
	Description     string  `form:"description,omitempty"`
	DurationMinutes int     `form:"durationMinutes" binding:"required"`
	Price           float64 `form:"price" binding:"required"`
	IsActive        bool    `form:"isActive,omitempty"`
}

// Corrected JSON tag to match Python's 'image_id'
type ImageUploadResponse struct {
	ImageID uuid.UUID `json:"image_id"`
}

func main() {
	db.Connect()
	defer db.Close()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	mail.InitTemplates(embeddedEmailTemplates)
	logger.InfoLogger.Info("Application: Email templates initialized.")

	badwords.LoadBadWords("badwords/en.txt")
	logger.InfoLogger.Info("Bad words loaded successfully!")

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(cors.CorsMiddleware())
	r.MaxMultipartMemory = 32 << 20 // 32 MB

	routes.RegisterUserRoutes(r)
	routes.RegisterCustomerRoutes(r)
	routes.RegisterBusinessRoutes(r)
	routes.RegisterServicesRoutes(r)
	routes.RegisterWorkingHoursRoutes(r, db.DB)

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok from identity service"})
	})

	r.POST("/create-service", func(c *gin.Context) {
		logger.InfoLogger.Info("Received new request for /create-service")

		var req TestCreateServiceRequest
		if err := c.ShouldBind(&req); err != nil {
			logger.ErrorLogger.Errorf("Failed to bind form data: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid form data", "details": err.Error()})
			return
		}

		logger.InfoLogger.Info("Step 1: Form data bound successfully.")

		// Parse the BusinessID string into a UUID (This part is still early as it's a direct input requirement)
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

		logger.InfoLogger.Info("Step 2: Business ID parsed successfully.")

		// **REQUIRED IMAGE CHECK** - Image file is mandatory
		fileHeader, err := c.FormFile("image")
		if err != nil {
			if err == http.ErrMissingFile {
				logger.ErrorLogger.Error("Form file 'image' is missing from the request.")

				c.JSON(http.StatusBadRequest, gin.H{"error": "Image file is required for service creation"})
				return
			}
			logger.ErrorLogger.Errorf("Could not get form file 'image': %v", err)

			c.JSON(http.StatusBadRequest, gin.H{"error": "Could not process image file"})
			return
		}

		logger.InfoLogger.Info("Step 3: Image file header retrieved successfully. Preparing to call Python service...")

		// Process the required image upload
		file, err := fileHeader.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open uploaded file"})
			return
		}
		defer file.Close()

		// Prepare a new request body buffer and multipart writer
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		// Get the original Content-Type from the file's header
		originalContentType := fileHeader.Header.Get("Content-Type")
		if originalContentType == "" {
			originalContentType = "application/octet-stream"
		}

		// Create the new part's header
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition",
			fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "image", fileHeader.Filename))
		h.Set("Content-Type", originalContentType)

		// Create the part with the correct headers
		part, err := writer.CreatePart(h)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create form part for proxying"})
			return
		}

		// Copy the file content into the new part
		_, err = io.Copy(part, file)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write file to form"})
			return
		}
		writer.Close()

		// Send to Python image service
		pythonServerURL := "http://localhost:8082/upload-image/"
		httpReq, _ := http.NewRequest("POST", pythonServerURL, body)
		httpReq.Header.Set("Content-Type", writer.FormDataContentType())
		httpReq.Header.Set("Authorization", authHeader)

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(httpReq)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to send request to image service or no response: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to send request to image service"})
			return
		}
		defer resp.Body.Close()

		responseBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			logger.ErrorLogger.Errorf("Failed to read response body from image service: %v", readErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response from image service"})
			return
		}

		// --- NEW LOGGING LINE TO CONFIRM RESPONSE AND SHOW CONTENT ---
		logger.InfoLogger.Infof("Received response from Python image service (Status: %d, Body: %s)", resp.StatusCode, string(responseBody))
		// --- END NEW LOGGING ---

		if resp.StatusCode != http.StatusCreated {
			logger.ErrorLogger.Errorf("Image service returned non-201 status: %d, response: %s", resp.StatusCode, string(responseBody))
			c.JSON(http.StatusBadGateway, gin.H{
				"error":                  "Image service returned an error",
				"image_service_status":   resp.StatusCode,
				"image_service_response": string(responseBody),
			})
			return
		}

		fmt.Print("Response from image service:", string(responseBody))

		var imgResp ImageUploadResponse
		// Enhanced error handling for JSON unmarshaling
		if err := json.Unmarshal(responseBody, &imgResp); err != nil {
			logger.ErrorLogger.Errorf("Failed to parse JSON response from image service: %v, raw body: %s", err, string(responseBody))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response from image service"})
			return
		}

		// Validate that we got a valid UUID from the image service
		if imgResp.ImageID == uuid.Nil {
			logger.ErrorLogger.Errorf("Image service returned a nil/invalid image ID. Raw body: %s", string(responseBody))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Image service returned invalid image ID"})
			return
		}

		fmt.Print("imgResp ", imgResp) // Debug print
		fmt.Printf("Image ID: %s\n", imgResp.ImageID)
		logger.InfoLogger.Info("Image ID: ", imgResp.ImageID)

		// --- MOVED: Create the service object *here*, after getting the image ID ---
		service := service_models.NewService(businessUUID, req.Name, req.Description, req.DurationMinutes, req.Price)
		service.IsActive = req.IsActive

		// Set the image ID as required (always valid since we validated it above)
		service.ImageID = pgtype.UUID{Bytes: imgResp.ImageID, Valid: true}

		// --- This part remains the same, as it's the database save ---
		createdService, err := service_models.CreateServiceModel(db.DB, service)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to create service in database: %v", err)
			if strings.Contains(err.Error(), "duplicate key value") {
				c.JSON(http.StatusConflict, gin.H{"error": "A service with this name already exists for this business."})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create service in the database."})
			}
			return
		}

		logger.InfoLogger.Infof("Service '%s' created successfully via test route with image ID: %s", createdService.Name, imgResp.ImageID)

		c.JSON(http.StatusCreated, gin.H{
			"message": "Service created successfully!",
			"service": createdService,
		})
	})

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	go func() {
		fmt.Printf("Go Server listening on :%s\n", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Server failed to listen: %v\n", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("Shutting down Go server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		fmt.Printf("Go Server forced to shutdown: %v\n", err)
	}

	fmt.Println("Go Server exited gracefully.")
}

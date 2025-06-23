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
	"github.com/joy095/identity/middlewares/auth"
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

// **FIX:** Changed BusinessID from uuid.UUID to string to fix binding error.
type TestCreateServiceRequest struct {
	BusinessID      string  `form:"businessId" binding:"required"`
	Name            string  `form:"name" binding:"required"`
	Description     string  `form:"description,omitempty"`
	DurationMinutes int     `form:"durationMinutes" binding:"required"`
	Price           float64 `form:"price" binding:"required"`
	IsActive        bool    `form:"isActive,omitempty"`
}

type ImageUploadResponse struct {
	ImageID uuid.UUID `json:"imageId"`
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
	// routes.RegisterServicesRoutes(r)
	routes.RegisterWorkingHoursRoutes(r, db.DB)

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok from identity service"})
	})

	testGroup := r.Group("/test")
	testGroup.Use(auth.AuthMiddleware())
	{
		testGroup.POST("/create-service", func(c *gin.Context) {
			var req TestCreateServiceRequest
			if err := c.ShouldBind(&req); err != nil {
				logger.ErrorLogger.Errorf("Failed to bind form data: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid form data", "details": err.Error()})
				return
			}

			// **FIX:** Manually parse the BusinessID string into a UUID.
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
			var imageID uuid.UUID

			fileHeader, err := c.FormFile("image")
			if err != nil && err != http.ErrMissingFile {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Could not process image file"})
				return
			}
			if fileHeader != nil {
				// Open the original file
				file, err := fileHeader.Open()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open uploaded file"})
					return
				}
				defer file.Close()

				// Prepare a new request body buffer and multipart writer
				body := &bytes.Buffer{}
				writer := multipart.NewWriter(body)

				// **FIX START**: Manually create the part to preserve the Content-Type
				// Get the original Content-Type from the file's header
				originalContentType := fileHeader.Header.Get("Content-Type")
				if originalContentType == "" {
					// As a fallback, use a generic stream type, though most uploads provide this.
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
				// **FIX END**

				// Copy the file content into the new part
				_, err = io.Copy(part, file)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write file to form"})
					return
				}
				writer.Close()

				// Now send to Python as before
				pythonServerURL := "http://localhost:8082/upload-image/"
				httpReq, _ := http.NewRequest("POST", pythonServerURL, body)
				httpReq.Header.Set("Content-Type", writer.FormDataContentType())
				httpReq.Header.Set("Authorization", authHeader)

				client := &http.Client{Timeout: 30 * time.Second}
				resp, err := client.Do(httpReq)
				if err != nil {
					c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to send request to image service"})
					return
				}
				defer resp.Body.Close()

				responseBody, _ := io.ReadAll(resp.Body)

				if resp.StatusCode != http.StatusCreated {
					c.JSON(http.StatusBadGateway, gin.H{
						"error":                  "Image service returned an error",
						"image_service_status":   resp.StatusCode,
						"image_service_response": string(responseBody),
					})
					return
				}

				var imgResp ImageUploadResponse
				if err := json.Unmarshal(responseBody, &imgResp); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response from image service"})
					return
				}
				imageID = imgResp.ImageID
			}

			// **FIX:** Use the parsed businessUUID here.
			service := service_models.NewService(businessUUID, req.Name, req.Description, req.DurationMinutes, req.Price)
			service.IsActive = req.IsActive

			if imageID != uuid.Nil {
				// If an image was uploaded, set the UUID and mark it as valid
				service.ImageID = pgtype.UUID{Bytes: imageID, Valid: true}
			}

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

			logger.InfoLogger.Infof("Service '%s' created successfully via test route.", createdService.Name)

			c.JSON(http.StatusCreated, gin.H{
				"message": "Service created successfully!",
				"service": createdService,
			})
		})
	}

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

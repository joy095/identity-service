package main

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/joy095/identity/badwords"
	"github.com/joy095/identity/config"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/middlewares/auth"
	"github.com/joy095/identity/middlewares/cors"
	"github.com/joy095/identity/routes"
	"github.com/joy095/identity/utils/mail"

	"github.com/gin-gonic/gin"
)

//go:embed templates/email/*
var embeddedEmailTemplates embed.FS

func init() {
	logger.InitLoggers()
	config.LoadEnv()
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
	fmt.Println("Bad words loaded successfully!")

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(cors.CorsMiddleware())

	// Set a maximum memory limit for parsing multipart forms.
	// Files larger than this will be stored on disk.
	r.MaxMultipartMemory = 32 << 20 // 32 MB

	routes.RegisterUserRoutes(r)
	routes.RegisterCustomerRoutes(r)
	routes.RegisterBusinessRoutes(r)
	routes.RegisterServicesRoutes(r)
	routes.RegisterWorkingHoursRoutes(r, db.DB)

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "ok from identity service",
		})
	})
	r.HEAD("/health", func(c *gin.Context) {
		c.Status(200)
	})

	r.Use(auth.AuthMiddleware())
	// This is the endpoint where your CLIENT (e.g., browser) will POST the image and token
	r.POST("/upload-image", func(c *gin.Context) {
		// 1. RECEIVE the image file from the client (e.g., browser, mobile app)
		// The form field name for the image file is expected to be "image"
		fileHeader, err := c.FormFile("image")
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to get image file from incoming request: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Failed to get image file: %v", err)})
			return
		}

		// Open the uploaded file for reading
		file, err := fileHeader.Open()
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to open uploaded file: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to open uploaded file: %v", err)})
			return
		}
		defer file.Close() // Ensure the file is closed after reading

		// 2. RECEIVE the Authorization token from the client's request
		// It's typically in the "Authorization" header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logger.ErrorLogger.Error("Authorization header missing from incoming request.")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required."})
			return
		}

		// Target Python server URL for image processing
		pythonServerURL := "http://localhost:8082/upload-image/"

		// 3. PREPARE the new multipart request body to FORWARD to the Python server
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		// Determine the MIME type of the uploaded file
		contentType := mime.TypeByExtension(filepath.Ext(fileHeader.Filename))
		if contentType == "" {
			contentType = "application/octet-stream" // Fallback
			logger.InfoLogger.Infof("Warning: Could not determine MIME type for %s, defaulting to %s", fileHeader.Filename, contentType)
		} else {
			logger.InfoLogger.Infof("Determined MIME type for %s: %s", fileHeader.Filename, contentType)
		}

		// Create a form file part for the image
		part, err := writer.CreatePart(map[string][]string{
			"Content-Disposition": {
				fmt.Sprintf(`form-data; name="image"; filename="%s"`, fileHeader.Filename),
			},
			"Content-Type": {contentType},
		})
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to create form file part for forwarding: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create form file part for forwarding: %v", err)})
			return
		}

		// Copy the content of the RECEIVED file into the new multipart part
		_, err = io.Copy(part, file)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to copy received image content for forwarding: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to write image content to form for forwarding: %v", err)})
			return
		}

		// IMPORTANT: Close the multipart writer to finalize the body
		err = writer.Close()
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to close multipart writer for forwarding: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to close multipart writer for forwarding: %v", err)})
			return
		}

		// 4. CREATE the HTTP POST request to send to the Python server
		req, err := http.NewRequest("POST", pythonServerURL, body)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to create request to Python server: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create request to Python server: %v", err)})
			return
		}

		// Set the Content-Type header for the outgoing request (including the multipart boundary)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		// FORWARD the Authorization token received from the client to the Python server
		req.Header.Set("Authorization", authHeader)

		// 5. SEND the request to the Python server
		client := &http.Client{Timeout: 30 * time.Second} // Set a timeout for the Python server response
		resp, err := client.Do(req)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to send request to Python server: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to send request to Python server: %v", err)})
			return
		}
		defer resp.Body.Close() // Ensure the response body from Python is closed

		// 6. READ the response from the Python server
		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to read response body from Python server: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to read response body from Python server: %v", err)})
			return
		}

		logger.InfoLogger.Infof("Response from Python server (Status %d): %s", resp.StatusCode, string(responseBody))

		// 7. FORWARD the Python server's response back to the original client
		// This uses Python's status code directly.
		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), responseBody)
		// Alternatively, if you want to encapsulate Python's response in your own JSON:
		/*
			c.JSON(http.StatusOK, gin.H{
				"message":    "Image received and forwarded for processing.",
				"forwarded_status": resp.Status,
				"forwarded_statusCode": resp.StatusCode,
				"python_response": string(responseBody), // Raw response from Python
			})
		*/
	})
	// --- END OF UPDATED HANDLER ---

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           r,
		ReadTimeout:       10 * time.Minute, // Allow ample time for large uploads to Go server
		WriteTimeout:      10 * time.Minute, // Allow ample time for forwarding + Python response
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 20 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB max header size
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

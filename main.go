package main

import (
	"context"
	"embed"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joy095/identity/badwords"
	"github.com/joy095/identity/config"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"           // Your combined logger/middleware package
	"github.com/joy095/identity/middlewares/cors" // Your CORS middleware
	"github.com/joy095/identity/routes"
	"github.com/joy095/identity/utils/mail"

	"github.com/gin-gonic/gin"
)

//go:embed templates/email/*
var embeddedEmailTemplates embed.FS

func init() {
	// Initialize loggers before using
	logger.InitLoggers()
	config.LoadEnv()
}

func main() {
	// Connect to database
	db.Connect()
	defer db.Close()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	mail.InitTemplates(embeddedEmailTemplates)
	logger.InfoLogger.Info("Application: Email templates initialized.")

	// Load bad words from a text file
	badwords.LoadBadWords("badwords/en.txt")
	logger.InfoLogger.Info("Bad words loaded successfully!")
	fmt.Println("Bad words loaded successfully!")

	// Use gin.New() instead of gin.Default()
	r := gin.New()

	// Add Gin's Recovery middleware FIRST
	r.Use(gin.Recovery())

	// Apply CORS Middleware
	r.Use(cors.CorsMiddleware())

	r.MaxMultipartMemory = 400 << 20 // 400 MB

	// Register all your application routes
	routes.RegisterUserRoutes(r)
	routes.RegisterCustomerRoutes(r)
	routes.RegisterBusinessRoutes(r)
	routes.RegisterServicesRoutes(r)
	routes.RegisterWorkingHoursRoutes(r, db.DB)

	// Health check endpoints
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "ok from identity service",
		})
	})
	r.HEAD("/health", func(c *gin.Context) {
		c.Status(200)
	})

	// r.GET("/send-test-image", func(c *gin.Context) {
	// 	// Target Python server URL
	// 	// Ensure this matches the port your Python server is running on (e.g., 8082)
	// 	pythonServerURL := "http://localhost:8082/upload-image/"

	// 	// --- CONFIGURATION: SET YOUR LOCAL IMAGE PATH HERE ---
	// 	imagePath := "C:\\Users\\Administrator\\Downloads\\10mb-example-jpg.jpg" // <--- *** CHANGE THIS PATH ***

	// 	// Open the image file from the local file system
	// 	file, err := os.Open(imagePath)
	// 	if err != nil {
	// 		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to open local image file '%s': %v", imagePath, err)})
	// 		return
	// 	}
	// 	defer file.Close() // Ensure the file is closed

	// 	// Create a buffer to write our multipart form data
	// 	body := &bytes.Buffer{}
	// 	writer := multipart.NewWriter(body)

	// 	// Get the filename from the path
	// 	filename := filepath.Base(imagePath)

	// 	// Determine the MIME type based on the file extension
	// 	contentType := mime.TypeByExtension(filepath.Ext(filename))
	// 	if contentType == "" {
	// 		// Fallback if MIME type cannot be determined (e.g., unknown extension)
	// 		contentType = "application/octet-stream"
	// 		fmt.Printf("Warning: Could not determine MIME type for %s, defaulting to %s\n", filename, contentType)
	// 	} else {
	// 		fmt.Printf("Determined MIME type for %s: %s\n", filename, contentType)
	// 	}

	// 	// Create a form file header with explicit Content-Type
	// 	part, err := writer.CreatePart(map[string][]string{
	// 		"Content-Disposition": {
	// 			fmt.Sprintf(`form-data; name="image"; filename="%s"`, filename),
	// 		},
	// 		"Content-Type": {contentType}, // Explicitly set the MIME type
	// 	})
	// 	if err != nil {
	// 		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create form file part: %v", err)})
	// 		return
	// 	}

	// 	// Copy the content of the local file to the form file part
	// 	_, err = io.Copy(part, file)
	// 	if err != nil {
	// 		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to write image content to form: %v", err)})
	// 		return
	// 	}

	// 	// Close the multipart writer to finalize the body
	// 	err = writer.Close()
	// 	if err != nil {
	// 		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to close multipart writer: %v", err)})
	// 		return
	// 	}

	// 	// Create the HTTP request
	// 	req, err := http.NewRequest("POST", pythonServerURL, body)
	// 	if err != nil {
	// 		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create request: %v", err)})
	// 		return
	// 	}

	// 	// Set the Content-Type header for the overall request (including the boundary)
	// 	req.Header.Set("Content-Type", writer.FormDataContentType())

	// 	// --- IMPORTANT: Include Authorization header ---
	// 	// Replace "your_actual_jwt_token_here" with your valid JWT token.
	// 	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTA1MDQ1MTAsImlhdCI6MTc1MDUwMDkxMCwiaXNzIjoiaWRlbnRpdHktc2VydmljZSIsImp0aSI6ImM1YmY0NDJlLTNkOWMtNGUzOC05YTlmLTVmODYxNTNjNzAyMCIsIm5iZiI6MTc1MDUwMDkxMCwic3ViIjoiMDE5NzNmZmYtYTZlYy03OGYxLTlhYTQtNWMyZTFhNzMzMTZlIiwidG9rZW5fdmVyc2lvbiI6NCwidHlwZSI6ImFjY2VzcyIsInVzZXJfaWQiOiIwMTk3M2ZmZi1hNmVjLTc4ZjEtOWFhNC01YzJlMWE3MzMxNmUifQ.ZjpgWMd7xUkW7iP4v59SD0GFCnfCJjsHKG6PnP7y08w")

	// 	// Send the request
	// 	client := &http.Client{Timeout: 30 * time.Second}
	// 	resp, err := client.Do(req)
	// 	if err != nil {
	// 		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to send request to Python server: %v", err)})
	// 		return
	// 	}
	// 	defer resp.Body.Close()

	// 	// Read the response from the Python server
	// 	responseBody, err := io.ReadAll(resp.Body)
	// 	if err != nil {
	// 		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to read response body: %v", err)})
	// 		return
	// 	}

	// 	fmt.Printf("Response from Python server (Status %d): %s\n", resp.StatusCode, string(responseBody))

	// 	c.JSON(http.StatusOK, gin.H{
	// 		"message":    "Test image sent to Python server from local file.",
	// 		"status":     resp.Status,
	// 		"statusCode": resp.StatusCode,
	// 		"response":   string(responseBody),
	// 	})
	// })

	// Graceful Shutdown for HTTP Server (from original code)
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           r,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 20 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB max header size
	}

	// Goroutine to start the server
	go func() {
		fmt.Printf("Go Server listening on :%s\n", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Server failed to listen: %v\n", err)
		}
	}()

	// Channel to listen for OS signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Block until a signal is received
	<-quit
	fmt.Println("Shutting down Go server...")

	// Create a context with a timeout for the shutdown process
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		fmt.Printf("Go Server forced to shutdown: %v\n", err)
	}

	fmt.Println("Go Server exited gracefully.")
}

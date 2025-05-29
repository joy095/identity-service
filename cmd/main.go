package main

import (
	"context" // Add for graceful shutdown
	"fmt"
	"log"
	"net/http" // Add for graceful shutdown
	"os"
	"os/signal" // Add for graceful shutdown
	"syscall"   // Add for graceful shutdown
	"time"      // Add for graceful shutdown

	"github.com/joy095/identity/badwords"
	"github.com/joy095/identity/config"
	"github.com/joy095/identity/config/db" // Corrected import for your db package
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/middlewares/cors"
	logger_middleware "github.com/joy095/identity/middlewares/logger"
	"github.com/joy095/identity/routes" // Your routes package

	"github.com/gin-gonic/gin"
)

func init() {
	// Initialize loggers before using
	logger.InitLoggers()
	config.LoadEnv()
	// db.Connect() is here, but db.Close() should NOT be here.
}

func main() {
	// Connect to database
	db.Connect()
	// --- IMPORTANT: Defer the closing of the database connection pool ---
	// This ensures db.Close() is called when main() function exits.
	defer db.Close()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	// Step 1: Load bad words from a text file
	badwords.LoadBadWords("badwords/en.txt")
	logger.InfoLogger.Info("Bad words loaded successfully!")
	fmt.Println("Bad words loaded successfully!")

	r := gin.Default()

	// Apply CORS Middleware
	r.Use(cors.CorsMiddleware())

	// Apply Logger Middleware
	r.Use(logger_middleware.GinLogger())

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

	// --- Graceful Shutdown for HTTP Server ---
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	// Goroutine to start the server
	go func() {
		logger.InfoLogger.Infof("Server listening on :%s", port)
		log.Printf("Starting server on port %s...", port) // Use log.Printf here as well
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.ErrorLogger.Fatalf("Server failed to listen: %v", err)
		}
	}()

	// Channel to listen for OS signals (e.g., Ctrl+C, kill command)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Block until a signal is received
	<-quit
	logger.InfoLogger.Info("Shutting down server...")

	// Create a context with a. timeout for the shutdown process
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel() // Release resources sooner

	if err := srv.Shutdown(ctx); err != nil {
		logger.ErrorLogger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.InfoLogger.Info("Server exited gracefully.")
	// The `defer db.Close()` will now execute here, after the HTTP server has shut down.
}

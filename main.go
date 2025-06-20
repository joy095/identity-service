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

	// Graceful Shutdown for HTTP Server
	srv := &http.Server{
		Addr:           ":" + port,
		Handler:        r,
		ReadTimeout:    5 * time.Minute,
		WriteTimeout:   5 * time.Minute,
		IdleTimeout:    10 * time.Minute,
		MaxHeaderBytes: 1 << 20, // 1 MB max header size
	}

	// Goroutine to start the server
	go func() {
		logger.InfoLogger.Infof("Server listening on :%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.ErrorLogger.Fatalf("Server failed to listen: %v", err)
		}
	}()

	// Channel to listen for OS signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Block until a signal is received
	<-quit
	logger.InfoLogger.Info("Shutting down server...")

	// Create a context with a timeout for the shutdown process
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.ErrorLogger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.InfoLogger.Info("Server exited gracefully.")
}

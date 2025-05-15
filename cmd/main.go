package main

import (
	"fmt"
	"log"
	"os"

	"github.com/joy095/identity/badwords"
	"github.com/joy095/identity/config"
	"github.com/joy095/identity/routes"

	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/middlewares/cors"
	logger_middleware "github.com/joy095/identity/middlewares/logger"

	"github.com/gin-gonic/gin"
)

func init() {
	// Initialize loggers before using
	logger.InitLoggers()

	config.LoadEnv()
	db.Connect()
}

func main() {

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

	routes.RegisterRoutes(r)

	routes.RegisterCustomerRoutes(r)

	r.GET("/health", func(c *gin.Context) {

		c.JSON(200, gin.H{
			"message": "ok from identity service",
		})
	})

	r.HEAD("/health", func(c *gin.Context) {
		c.Status(200)
	})

	logger.InfoLogger.Info("Server is started")

	log.Printf("Starting server on port %s...", port)

	r.Run(":" + port)
}

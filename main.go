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

	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/badwords"
	"github.com/joy095/identity/config"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/middlewares/cors"
	"github.com/joy095/identity/routes"
	"github.com/joy095/identity/utils/mail"
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

	r := gin.Default()
	r.Use(gin.Recovery())
	r.Use(cors.CorsMiddleware())

	// Set MaxMultipartMemory globally
	r.MaxMultipartMemory = 32 << 20 // 32 MB

	routes.RegisterUserRoutes(r)
	routes.RegisterBusinessRoutes(r)
	routes.RegisterBusinessImageRoutes(r)
	routes.RegisterServicesRoutes(r)
	routes.RegisterWorkingHoursRoutes(r, db.DB)
	routes.RegisterScheduleSlotRoutes(r)
	routes.RegisterBookingRoutes(r)

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok from identity service"})
	})
	r.HEAD("/health", func(c *gin.Context) {
		c.Status(200)
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

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
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

	if err := badwords.LoadBadWords("badwords/en.txt"); err != nil {
		logger.ErrorLogger.Fatalf("Failed to load bad words: %v", err)
	}
	logger.InfoLogger.Info("Bad words loaded successfully!")

	//

	webhookSecret := "your-sandbox-webhook-secret"
	timestamp := "1756915924"
	body := `{"data":{"test_object":{"test_key":"test_value"}},"type":"WEBHOOK","event_time":"2025-09-03T16:12:03.622Z"}`
	var temp interface{}
	json.Unmarshal([]byte(body), &temp)
	normalizedBody, _ := json.Marshal(temp)
	signStr := timestamp + string(normalizedBody)
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write([]byte(signStr))
	expectedSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	fmt.Printf("Computed signature: %s\n", expectedSignature)
	fmt.Printf("Received signature: rc+Ua7+2RCfZzx2awn2wn6FpIkYKbD+PtCo6J2f59+8=\n")
	//

	r := gin.Default()
	r.Use(cors.CorsMiddleware())

	// Set MaxMultipartMemory globally
	r.MaxMultipartMemory = 32 << 20 // 32 MB

	routes.RegisterUserRoutes(r)
	routes.RegisterBusinessRoutes(r)
	routes.RegisterBusinessImageRoutes(r)
	routes.RegisterServicesRoutes(r)
	routes.RegisterWorkingHoursRoutes(r)
	// routes.RegisterScheduleSlotRoutes(r)
	routes.RegisterBusinessPaymentRoutes(r)

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok from identity service"})
	})
	r.HEAD("/health", func(c *gin.Context) {
		c.Status(200)
	})

	srv := &http.Server{
		Addr:           ":" + port,
		Handler:        r,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
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

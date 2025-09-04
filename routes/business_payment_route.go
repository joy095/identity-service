package routes

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/business_payment_controller"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterBusinessPaymentRoutes(router *gin.Engine) error {
	paymentController, err := business_payment_controller.NewPaymentController(db.DB)
	if err != nil {
		logger.ErrorLogger.Errorf("payment routes init: %w", err)
		return fmt.Errorf("payment routes init: %w", err)
	}

	// Public webhook endpoints (no auth required)
	webhook := router.Group("/webhook")
	{
		webhook.POST("/payment", paymentController.PaymentWebhook)
		webhook.GET("/health", paymentController.WebhookHealthCheck)
	}

	// Protected payment endpoints (require authentication)
	api := router.Group("")
	api.Use(auth.AuthMiddleware())
	{
		// Order management
		api.POST("/orders", paymentController.CreateOrder)
		api.GET("/orders/history", paymentController.GetOrderHistory)
		api.GET("/orders/:order_id", paymentController.GetOrder)

		// Refunds (initiates refund, status updated via webhook)
		api.POST("/orders/:order_id/refunds", paymentController.CreateRefund)

		// Schedule slot availability
		api.GET("/public/services/:service_id/unavailable-times", paymentController.GetUnavailableTimes) // /public/services/abc12345-.../unavailable-times?date=2025-04-05&=1&limit=10
	}

	return nil
}

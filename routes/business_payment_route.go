package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/business_payment_controller"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterBusinessPaymentRoutes(router *gin.Engine) {
	paymentController, err := business_payment_controller.NewPaymentController(db.DB)
	if err != nil {
		panic("Failed to initialize PaymentController: " + err.Error())
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
		api.GET("/orders/:order_id/status", paymentController.GetOrderStatus)
		api.GET("/orders/history", paymentController.GetOrderHistory)

		// Payment processing
		api.POST("/payments/process", paymentController.ProcessPayment)

		// UPI payments
		upi := api.Group("/payments/upi")
		{
			upi.POST("/qr", paymentController.PayUPIQR)
			upi.POST("/intent", paymentController.PayUPIIntent)
			upi.POST("/collect", paymentController.PayUPICollect)
		}

		// Refunds
		api.POST("/orders/:order_id/refunds", paymentController.CreateRefund)
	}
}

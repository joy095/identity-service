package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/business_payment_controller"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterBusinessPaymentRoutes(router *gin.Engine) {
	businessPaymentController := business_payment_controller.NewBusinessPaymentController(db.DB)

	// Unprotected routes
	router.POST("/payment/webhook", businessPaymentController.PaymentWebhook)
	router.POST("/payment/webhook/upi", businessPaymentController.UPIWebhook)
	router.POST("/payment/webhook/card", businessPaymentController.CardWebhook)
	router.GET("/payment/health", businessPaymentController.WebhookHealthCheck)

	// Protected routes
	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware())
	{
		// Order and Booking routes
		protected.POST("/book", businessPaymentController.CreateOrders)
		protected.GET("/orders/:order_id", businessPaymentController.GetOrder)
		protected.GET("/bookings", businessPaymentController.GetBookings)
		protected.GET("/bookings/:booking_id", businessPaymentController.GetBooking)

		// Payment routes
		protected.POST("/pay", businessPaymentController.PayPayment)
		protected.POST("/pay/upi/qr", businessPaymentController.PayUPIQR)
		protected.POST("/pay/upi/intent", businessPaymentController.PayUPIIntent)
		protected.POST("/pay/upi/collect", businessPaymentController.PayUPICollect)
		protected.GET("/payment/status/:order_id", businessPaymentController.GetPaymentStatus)

		// Refund routes
		protected.POST("/orders/:order_id/refunds", businessPaymentController.CreateRefund)
		protected.GET("/orders/:order_id/refunds/:refund_id", businessPaymentController.GetRefund)

		// Payout routes
		protected.POST("/payouts", businessPaymentController.CreatePayout)
	}
}

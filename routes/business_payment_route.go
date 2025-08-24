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

	// Protected routes
	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware())
	{
		protected.POST("/book", businessPaymentController.CreateOrders)
		protected.POST("/pay", businessPaymentController.PayPayment)
		protected.POST("/pay/upi/qr", businessPaymentController.PayUPIQR)
		protected.POST("/pay/upi/intent", businessPaymentController.PayUPIIntent)
		protected.POST("/pay/upi/collect", businessPaymentController.PayUPICollect)
		protected.POST("/orders/:order_id/refunds", businessPaymentController.CreateRefund)
		protected.GET("/orders/:order_id/refunds/:refund_id", businessPaymentController.GetRefund)
		protected.GET("/orders/:order_id", businessPaymentController.GetOrder)
		protected.GET("/bookings", businessPaymentController.GetBookings)
		protected.GET("/bookings/:booking_id", businessPaymentController.GetBooking)
		protected.POST("/payouts", businessPaymentController.CreatePayout)
	}
}

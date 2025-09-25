package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/business_payout_controller"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/middlewares/auth"
)

// RegisterPayoutRoutes registers routes for payout-related operations
func RegisterPayoutRoutes(r *gin.Engine) {
	payoutController, err := business_payout_controller.NewPayoutController(db.DB)
	if err != nil {
		logger.ErrorLogger.Fatalf("failed to initialize payout controller: %v", err)
	}

	// Protected routes requiring authentication
	api := r.Group("/payouts")
	api.Use(auth.AuthMiddleware())
	{
		api.POST("/", payoutController.CreatePayout)             // Create a new payout
		api.GET("/balance", payoutController.GetBalance)         // Fetch account balance
		api.GET("/:payout_id", payoutController.GetPayoutStatus) // Get payout status
	}

	// Webhook route (no auth middleware, as it's called by Cashfree)
	r.POST("/payouts/webhook", payoutController.PayoutWebhook) // Handle Cashfree webhook
}

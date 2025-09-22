package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/controllers/business_payout_controller"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/middlewares/auth"
)

// RegisterPayoutRoutes registers routes for payout-related operations
func RegisterPayoutRoutes(r *gin.Engine, db *pgxpool.Pool) {
	payoutController, err := business_payout_controller.NewPayoutController(db)
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

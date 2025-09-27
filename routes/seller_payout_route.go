package routes

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/seller_payout_controller"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterSellerPayoutRoutes(router *gin.Engine) {

	controller, err := seller_payout_controller.NewSellerPaymentController(db.DB)
	if err != nil {
		panic(fmt.Errorf("failed to initialize service controller: %w", err))
	}

	// All routes within this group are protected by the auth middleware
	protected := router.Group("/user")
	protected.Use(auth.AuthMiddleware())
	{
		protected.POST("/bookings/cancel", controller.SellerPayout)
	}
}

package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/booking_controller"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterBookingRoutes(router *gin.Engine) {
	bookingController := booking_controller.NewBookingController(db.DB)

	// Protected routes
	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware())
	{
		protected.POST("/book", bookingController.Book)

	}
}

package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/business_controller"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterBusinessRoutes(router *gin.Engine) {
	businessController := business_controller.NewBusinessController(db.DB)

	// --- Public Routes ---
	// These routes are accessible without authentication.
	router.GET("/business", businessController.GetAllBusinesses)
	router.GET("/business/:publicId", businessController.GetBusiness)

	// --- Protected Routes ---
	// These routes require a valid authentication token.
	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware())
	{
		// --- Business Core Routes ---
		protected.POST("/business", businessController.CreateBusiness)
		protected.PUT("/business/:publicId", businessController.UpdateBusiness)
		// Corrected: Use :publicId to identify the business to delete.
		protected.DELETE("/business/:publicId", businessController.DeleteBusiness)
	}
}

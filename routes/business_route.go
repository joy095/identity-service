package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/business_controller"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterBusinessRoutes(router *gin.Engine) {
	businessController := business_controller.NewBusinessController(db.DB)

	// Public routes
	router.GET("/business", businessController.GetAllBusinesses)
	router.GET("/business/:id", businessController.GetBusiness)

	// Protected routes
	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware())
	{
		protected.POST("/business", businessController.CreateBusiness)
		protected.PUT("/business/:id", businessController.UpdateBusiness)
		protected.PUT("/business-image/:id", businessController.ReplaceBusinessImage)
		protected.DELETE("/business/:id", businessController.DeleteBusiness)
	}
}

package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterBusinessRoutes(router *gin.Engine) {
	businessController := controllers.NewBusinessController(db.DB)

	// Protected routes
	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware())
	{
		protected.GET("/business", businessController.GetBusinesses)
		protected.GET("/business/:id", businessController.GetBusiness)
		protected.POST("/business", businessController.CreateBusiness)
		protected.PUT("/business/:id", businessController.UpdateBusiness)
		protected.DELETE("/business/:id", businessController.DeleteBusiness)
	}
}

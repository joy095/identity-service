package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/services_controller"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterServicesRoutes(router *gin.Engine) {
	serviceController := services_controller.NewServiceController(db.DB)

	// This is a public route, no auth needed
	router.GET("/service/:id", serviceController.GetServiceByID)

	// All routes within this group are protected by the auth middleware
	protected := router.Group("/service")
	protected.Use(auth.AuthMiddleware())
	{
		protected.POST("/", serviceController.CreateService)
		protected.PATCH("/:id", serviceController.UpdateService)
		protected.DELETE("/:id", serviceController.DeleteService)
	}
}

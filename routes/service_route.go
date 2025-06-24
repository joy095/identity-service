package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/controllers/services_controller"
)

func RegisterServicesRoutes(router *gin.Engine) {
	serviceController := services_controller.NewServiceController()

	// This is a public route, no auth needed
	// router.GET("/service/:id", serviceController.GetServiceByID)

	// All routes within this group are protected by the auth middleware
	protected := router.Group("/service")
	// protected.Use(auth.AuthMiddleware())
	{
		protected.POST("/", serviceController.CreateService)
		// protected.PATCH("/:id", serviceController.UpdateService)
		// protected.DELETE("/:id", serviceController.DeleteService)
	}
}

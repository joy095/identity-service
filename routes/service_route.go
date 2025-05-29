package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterServicesRoutes(router *gin.Engine) {
	serviceController := controllers.NewServiceController(db.DB)

	router.GET("/service/:id", serviceController.GetServiceByID) // Get a single service by its own ID

	// Protected routes
	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware())
	{

		// Standalone service routes for creation, update, delete on a specific service ID
		// Note: CreateService requires business_id in payload, update/delete check ownership via business_id lookup
		serviceGroup := protected.Group("/service")
		{
			serviceGroup.POST("/", serviceController.CreateService)      // Create a service for a specific business_id (in payload)
			serviceGroup.PATCH("/:id", serviceController.UpdateService)  // Update a specific service by its own ID
			serviceGroup.DELETE("/:id", serviceController.DeleteService) // Delete a specific service by its own ID
		}

	}
}

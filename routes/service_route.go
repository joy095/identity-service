package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/services_controller"
	"github.com/joy095/identity/middlewares/auth"
	"github.com/joy095/identity/utils/jwt_parse"
)

func RegisterServicesRoutes(router *gin.Engine) {
	serviceController := services_controller.NewServiceController(db.DB)

	router.GET("/service/:id", serviceController.GetServiceByID) // Get a single service by its own ID

	// Protected routes
	router.Use(jwt_parse.ParseJWTToken())
	protected := router.Group("/service")
	protected.Use(auth.AuthMiddleware())
	{
		protected.POST("/", serviceController.CreateService)      // Create a service for a specific business_id (in payload)
		protected.PATCH("/:id", serviceController.UpdateService)  // Update a specific service by its own ID
		protected.DELETE("/:id", serviceController.DeleteService) // Delete a specific service by its own ID
	}

}

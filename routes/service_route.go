package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/services_controller"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterServicesRoutes(router *gin.Engine) {
	serviceController := services_controller.NewServiceController(db.DB)

	router.GET("/service/:id", serviceController.GetServiceByID) // Get a single service by its own ID

	// Protected routes
	protected := router.Group("/service")
	protected.Use(auth.AuthMiddleware())
	{
		protected.POST("/", serviceController.CreateService)      // Create a service for a specific business_id (in payload)
		protected.PATCH("/:id", serviceController.UpdateService)  // Update a specific service by its own ID
		protected.DELETE("/:id", serviceController.DeleteService) // Delete a specific service by its own ID

		protected.GET("/hello", func(c *gin.Context) {
			userID, _ := c.Get("user_id") // Should be set by your JWT parser
			c.JSON(http.StatusOK, gin.H{"message": "Authentication successful!", "user_id": userID})
		})

	}

}

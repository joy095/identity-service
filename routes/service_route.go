package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/controllers/services_controller"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterServicesRoutes(router *gin.Engine) {
	serviceController := services_controller.NewServiceController()

	// This is a public route, no auth needed
	router.GET("/service/:id", serviceController.GetServiceByID)

	// All routes within this group are protected by the auth middleware
	protected := router.Group("/service")
	protected.Use(auth.AuthMiddleware())
	{
		protected.DELETE("/:id", func(c *gin.Context) {
			if err := serviceController.DeleteService(c); err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
		})
	}
}

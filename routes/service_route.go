package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/controllers/services_controller"
	"github.com/joy095/identity/handlers/service_handlers"
	middleware "github.com/joy095/identity/middlewares"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterServicesRoutes(router *gin.Engine) {
	serviceController := services_controller.NewServiceController()

	// This is a public route, no auth needed
	router.GET("/services/:businessId", serviceController.GetAllServiceByBusiness) // Get all services for a business with businessId
	router.GET("/service/:id", serviceController.GetServiceByID)

	// All routes within this group are protected by the auth middleware
	protected := router.Group("")
	protected.Use(auth.AuthMiddleware())
	{
		protected.DELETE("/service/:id", middleware.CombinedRateLimiter("service/:id", "5-30s", "20-5m"), serviceController.DeleteService)
		protected.POST("/create-service", middleware.CombinedRateLimiter("create-service", "5-30s", "20-5m"), service_handlers.CreateService)
		protected.POST("/update-service/:id", middleware.CombinedRateLimiter("update-service/:id", "5-30s", "20-5m"), service_handlers.UpdateService)
	}
}

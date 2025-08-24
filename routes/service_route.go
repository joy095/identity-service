package routes

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/services_controller"
	"github.com/joy095/identity/handlers/service_handlers"
	middleware "github.com/joy095/identity/middlewares"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterServicesRoutes(router *gin.Engine) {

	serviceController, err := services_controller.NewServiceController(db.DB)
	if err != nil {
		panic(fmt.Errorf("failed to initialize service controller: %w", err))
	}

	// This is a public route, no auth needed
	router.GET("/services/:publicId", serviceController.GetAllServiceByBusiness) // Get all services for a business with publicId
	router.GET("/service/:id", serviceController.GetServiceByID)
	router.GET("/is-service-business/:publicId", serviceController.IsServiceBusiness) // Is business service available

	// All routes within this group are protected by the auth middleware
	protected := router.Group("")
	protected.Use(auth.AuthMiddleware())
	{
		protected.DELETE("/service/:id", middleware.CombinedRateLimiter("service/:id", "5-30s", "20-5m"), serviceController.DeleteService)
		protected.POST("/create-service/:publicId", middleware.CombinedRateLimiter("create-service", "5-30s", "20-5m"), service_handlers.CreateService)
		protected.PATCH("/update-service/:id", middleware.CombinedRateLimiter("update-service/:id", "5-30s", "20-5m"), service_handlers.UpdateService)
	}
}

package routes

import (
	"github.com/gin-gonic/gin"

	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/controllers/working_hour_controller"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterWorkingHoursRoutes(router *gin.Engine) {

	workingHourController := working_hour_controller.NewWorkingHourController(db.DB)

	public := router.Group("/public-working-hour")
	{
		// Use :businessPublicId to be explicit about the parameter type
		public.GET("/:businessPublicId", workingHourController.GetWorkingHoursByBusinessID)
	}

	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware())

	workingGroup := protected.Group("/working-hour")
	{
		// Use :businessId in the path and remove businessId from the JSON body expectation
		// The handler will extract businessId from the path parameter
		workingGroup.POST("/initialize/:businessPublicId", workingHourController.InitializeWorkingHours)
		workingGroup.POST("/bulk/:businessPublicId", workingHourController.BulkUpsertWorkingHours)

		// Keep individual create endpoint - businessId comes from JSON body
		workingGroup.POST("/", workingHourController.CreateWorkingHour)
		// Keep individual CRUD endpoints - :id refers to working hour ID
		workingGroup.GET("/:id", workingHourController.GetWorkingHourByID)
		workingGroup.PUT("/:id", workingHourController.UpdateWorkingHour)
		workingGroup.DELETE("/:id", workingHourController.DeleteWorkingHour)
	}
}

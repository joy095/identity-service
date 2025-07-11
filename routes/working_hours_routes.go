package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/joy095/identity/controllers/working_hour_controller"
	"github.com/joy095/identity/middlewares/auth"
)

func RegisterWorkingHoursRoutes(router *gin.Engine, db *pgxpool.Pool) {

	workingHourController := working_hour_controller.NewWorkingHourController(db)

	public := router.Group("/working-hour-business/:businessPublicId")

	{
		public.GET("/working-hours", workingHourController.GetWorkingHoursByBusinessID)
	}

	// Apply authentication middleware to all working hour routes
	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware()) // Apply AuthMiddleware here

	businessGroup := protected.Group("/working-hour-business/:businessId")
	{
		// New endpoint for initializing working hours with defaults and overrides
		businessGroup.POST("/working-hours/initialize", workingHourController.InitializeWorkingHours)
		businessGroup.POST("/working-hours/bulk", workingHourController.BulkUpsertWorkingHours)
	}

	workingGroup := protected.Group("/working-hour")
	{
		workingGroup.POST("/", workingHourController.CreateWorkingHour) // Can still create individual entries
		workingGroup.GET("/:id", workingHourController.GetWorkingHourByID)
		workingGroup.PUT("/:id", workingHourController.UpdateWorkingHour)
		workingGroup.DELETE("/:id", workingHourController.DeleteWorkingHour)
	}

}

// routes/schedule_slots_routes.go
package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/joy095/identity/controllers"
	"github.com/joy095/identity/middlewares/auth"
)

// RegisterScheduleSlotsRoutes registers the API routes for schedule slots.
func RegisterScheduleSlotsRoutes(r *gin.Engine, db *pgxpool.Pool) {
	scheduleSlotController := controllers.NewScheduleSlotController(db)

	protected := r.Group("/")
	protected.Use(auth.AuthMiddleware())

	// Nested route for getting all schedule slots for a specific business
	businessGroup := protected.Group("/business/:business_id")
	{
		businessGroup.GET("/schedule-slots", scheduleSlotController.GetScheduleSlotsByBusinessID)
	}

	scheduleGroup := protected.Group("/schedule-slot")
	// Standalone routes for individual schedule slot operations
	{

		scheduleGroup.POST("/", scheduleSlotController.CreateScheduleSlot)
		scheduleGroup.GET("/:id", scheduleSlotController.GetScheduleSlotByID)
		scheduleGroup.PUT("/:id", scheduleSlotController.UpdateScheduleSlot)
		scheduleGroup.DELETE("/:id", scheduleSlotController.DeleteScheduleSlot)
	}
}

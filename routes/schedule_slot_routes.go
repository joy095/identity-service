package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/controllers/schedule_slot_controller"
	middleware "github.com/joy095/identity/middlewares"
	"github.com/joy095/identity/middlewares/auth"
)

// RegisterScheduleSlotRoutes registers all schedule slot related routes
func RegisterScheduleSlotRoutes(router *gin.Engine) {
	// Create schedule slot controller instance
	scheduleSlotController := schedule_slot_controller.NewScheduleSlotController()

	// Protected routes - require authentication
	protected := router.Group("/schedule-slots")
	protected.Use(auth.AuthMiddleware())
	{
		// Create a new schedule slot (business owners only)
		protected.POST("/",
			middleware.CombinedRateLimiter("create-slot", "10-1m", "50-10m"),
			scheduleSlotController.CreateScheduleSlot)

		// Get a single schedule slot by ID
		protected.GET("/:slot_id",
			middleware.NewRateLimiter("get-slot", "30-1m"),
			scheduleSlotController.GetScheduleSlot)

		// Update an existing schedule slot
		protected.PATCH("/:slot_id",
			middleware.CombinedRateLimiter("update-slot", "10-1m", "30-10m"),
			scheduleSlotController.UpdateScheduleSlot)

		// Delete a schedule slot
		protected.DELETE("/:slot_id",
			middleware.CombinedRateLimiter("delete-slot", "5-1m", "20-10m"),
			scheduleSlotController.DeleteScheduleSlot)

	}

	public := router.Group("/public/business")
	{
		public.GET("/:service_id/unavailable-times",
			middleware.NewRateLimiter("public-unavailable-times", "20-1m"),
			scheduleSlotController.GetUnavailableTimes) // /business/abc12345-.../unavailable-times?date=2025-04-05&=1&limit=10
	}
}

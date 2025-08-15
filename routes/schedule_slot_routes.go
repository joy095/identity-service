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
			middleware.NewRateLimiter("30-1m", "get-slot"), 
			scheduleSlotController.GetScheduleSlot)

		// Update an existing schedule slot
		protected.PATCH("/:slot_id", 
			middleware.CombinedRateLimiter("update-slot", "10-1m", "30-10m"), 
			scheduleSlotController.UpdateScheduleSlot)

		// Delete a schedule slot
		protected.DELETE("/:slot_id", 
			middleware.CombinedRateLimiter("delete-slot", "5-1m", "20-10m"), 
			scheduleSlotController.DeleteScheduleSlot)

			
		// Toggle slot availability (quick enable/disable)
		protected.PATCH("/:slot_id/toggle-availability", 
			middleware.NewRateLimiter("20-1m", "toggle-availability"), 
			scheduleSlotController.ToggleSlotAvailability)
	}

	// Business-specific routes - for managing slots of a particular business
	businessSlots := router.Group("/businesses/:business_id/schedule-slots")
	businessSlots.Use(auth.AuthMiddleware())
	{
		// Get all schedule slots for a business (with pagination and filtering)
		businessSlots.GET("/", 
			middleware.NewRateLimiter("30-1m", "business-slots"), 
			scheduleSlotController.GetScheduleSlotsByBusiness)

		// Get only available slots for a business (for customer booking)
		businessSlots.GET("/available", 
			middleware.NewRateLimiter("50-1m", "available-slots"), 
			scheduleSlotController.GetAvailableSlots)

		// Bulk update slot availability (for business owners)
		businessSlots.PATCH("/bulk-availability", 
			middleware.CombinedRateLimiter("bulk-update", "5-1m", "20-10m"), 
			scheduleSlotController.BulkUpdateSlotAvailability)
	}

	// Public routes (no authentication required) - for customer browsing
	public := router.Group("/public/businesses/:business_id/schedule-slots")
	{
		// Get available slots for a business (public access for customers)
		// More restrictive rate limiting for public access
		public.GET("/available", 
			middleware.NewRateLimiter("20-1m", "public-available-slots"), 
			scheduleSlotController.GetAvailableSlots)
	}

	// Admin routes - for system administration
	admin := router.Group("/admin/schedule-slots")
	admin.Use(auth.AuthMiddleware()) // You might want an admin-specific middleware
	{
		// Bulk operations across all businesses (admin only)
		admin.PATCH("/bulk-availability", 
			middleware.CombinedRateLimiter("admin-bulk-update", "10-5m", "50-30m"), 
			scheduleSlotController.BulkUpdateSlotAvailability)
	}
}

package routes

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/controllers/booking_controller"
	"github.com/joy095/identity/controllers/slot_booking_controller"
	middleware "github.com/joy095/identity/middlewares"
	"github.com/joy095/identity/middlewares/auth"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/config/redis"
	"github.com/joy095/identity/clients"
	"os"
)

// RegisterBookingRoutes registers all booking-related routes
func RegisterBookingRoutes(router *gin.Engine) {
	// Initialize the booking service with dependencies
	appID := os.Getenv("CASHFREE_APP_ID")
	secretKey := os.Getenv("CASHFREE_SECRET_KEY")
	environment := os.Getenv("CASHFREE_ENVIRONMENT")
	if environment == "" {
		environment = "sandbox" // default to sandbox
	}
	cashfreeClient := clients.NewCashfreeClient(appID, secretKey, environment)
	webhookSecret := os.Getenv("CASHFREE_WEBHOOK_SECRET")
	
	// Get Redis client
	ctx := context.Background()
	redisClient := redis.GetRedisClient(ctx)
	
	bookingService := slot_booking_controller.NewSlotBookingService(
		db.DB,
		redisClient,
		cashfreeClient,
		webhookSecret,
	)

	// Create booking controller instance
	bookingController := &booking_controller.BookingController{
		Service: bookingService,
	}

	// Public routes (for webhooks)
	router.POST("/webhooks/cashfree/payment", bookingController.HandleCashfreeWebhook)
	
	// Protected routes - require authentication
	protected := router.Group("/bookings")
	protected.Use(auth.AuthMiddleware())
	{
		// Slot booking operations
		protected.POST("/reserve-slot", 
			middleware.CombinedRateLimiter("reserve-slot", "5-1m", "20-10m"), 
			bookingController.ReserveSlot)
		
		protected.POST("/book-slot", 
			middleware.CombinedRateLimiter("book-slot", "3-1m", "15-10m"), 
			bookingController.BookSlot)
		
		protected.DELETE("/cancel-reservation/:slot_id", 
			middleware.NewRateLimiter("10-1m", "cancel-reservation"), 
			bookingController.CancelSlotReservation)

		// Booking management
		protected.GET("/my-bookings", 
			middleware.NewRateLimiter("20-1m", "my-bookings"), 
			bookingController.GetMyBookings)
		
		protected.GET("/:booking_id", 
			middleware.NewRateLimiter("15-30s", "get-booking"), 
			bookingController.GetBookingDetails)
		
		protected.PATCH("/:booking_id/cancel", 
			middleware.CombinedRateLimiter("cancel-booking", "3-1m", "10-10m"), 
			bookingController.CancelBooking)
		
		// Booking history and filters
		protected.GET("/history", 
			middleware.NewRateLimiter("10-1m", "booking-history"), 
			bookingController.GetBookingHistory)
		
		protected.GET("/by-status/:status", 
			middleware.NewRateLimiter("15-1m", "bookings-by-status"), 
			bookingController.GetBookingsByStatus)
	}

	// Business owner routes - for managing bookings of their business
	businessOwner := router.Group("/business/bookings")
	businessOwner.Use(auth.AuthMiddleware()) // You might want a business owner specific middleware
	{
		businessOwner.GET("/:business_id/all", 
			middleware.NewRateLimiter("20-1m", "business-bookings"), 
			bookingController.GetBusinessBookings)
		
		businessOwner.GET("/:business_id/today", 
			middleware.NewRateLimiter("30-1m", "business-today-bookings"), 
			bookingController.GetTodayBookings)
		
		businessOwner.GET("/:business_id/upcoming", 
			middleware.NewRateLimiter("20-1m", "business-upcoming-bookings"), 
			bookingController.GetUpcomingBookings)
		
		businessOwner.PATCH("/:business_id/:booking_id/status", 
			middleware.CombinedRateLimiter("update-booking-status", "5-1m", "20-10m"), 
			bookingController.UpdateBookingStatus)
	}

	// Admin routes - for system administration
	admin := router.Group("/admin/bookings")
	admin.Use(auth.AuthMiddleware()) // You might want an admin-specific middleware
	{
		admin.GET("/all", 
			middleware.NewRateLimiter("10-1m", "admin-all-bookings"), 
			bookingController.GetAllBookings)
		
		admin.GET("/analytics", 
			middleware.NewRateLimiter("5-1m", "booking-analytics"), 
			bookingController.GetBookingAnalytics)
		
		admin.DELETE("/:booking_id/force-cancel", 
			middleware.CombinedRateLimiter("force-cancel", "3-5m", "10-30m"), 
			bookingController.ForceCancelBooking)
	}
}

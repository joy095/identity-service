package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/controllers"
	"github.com/joy095/identity/utils/mail"
)

func RegisterCustomerRoutes(router *gin.Engine) {
	customerController := controllers.NewUserController()

	customerGroup := router.Group("/customer")
	{

		// Public routes
		customerGroup.POST("/register", customerController.CustomerRegister)
		router.POST("/login", customerController.CustomerLogin)

		customerGroup.POST("/verify-otp", mail.VerifyCustomerOTP)

		// protectedCustomerRoutes := customerGroup.Group("/")
		// Apply your authentication middleware ONLY to this sub-group
		// protectedCustomerRoutes.Use(auth.AuthMiddleware())
		{
			// Examples of protected routes (will be prefixed with /customer):

			// POST /customer/logout
			// protectedCustomerRoutes.POST("/logout", userController.Logout)

			// GET /customer/profile (to get the logged-in user's profile)
			// protectedCustomerRoutes.GET("/profile", userController.GetCustomerProfile)

			// PUT /customer/profile (to update the logged-in user's profile)
			// protectedCustomerRoutes.PUT("/profile", userController.UpdateCustomerProfile)

			// Example: Get customer's bookings (requires auth)
			// protectedCustomerRoutes.GET("/bookings", userController.GetCustomerBookings)

			// Add other customer-specific routes that require authentication here...
		}
	}

}

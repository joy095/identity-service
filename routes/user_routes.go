package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/controllers"
	"github.com/joy095/identity/middlewares/auth"
	"github.com/joy095/identity/utils/mail" // Assuming mail package is correctly imported
)

func RegisterRoutes(router *gin.Engine) {
	userController := controllers.NewUserController()

	// Public routes
	router.POST("/register", userController.Register)
	router.POST("/login", userController.Login)
	router.POST("/refresh-token", userController.RefreshToken)

	router.POST("/username-availability", userController.UsernameAvailability)

	router.POST("/forgot-password", userController.ForgotPassword)
	router.POST("/forgot-password-otp", mail.VerifyForgotPasswordOTP) // Assuming mail.VerifyForgotPasswordOTP is a gin.HandlerFunc

	router.POST("/change-password", userController.ChangePassword)

	router.POST("/request-otp", mail.RequestOTP) // Assuming mail.RequestOTP is a gin.HandlerFunc
	router.POST("/verify-otp", mail.VerifyOTP)   // Assuming mail.VerifyOTP is a gin.HandlerFunc

	// Protected routes
	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware())
	{
		protected.POST("/logout", userController.Logout)

		// Profile Management
		protected.PATCH("/update-profile", userController.UpdateProfile)
		protected.POST("/send-profile-update-otp", userController.SendProfileUpdateOTP)
		protected.POST("/verify-profile-update-otp", userController.VerifyProfileUpdateOTP)
		protected.GET("/profile", userController.GetUserProfile) // Get profile for authenticated user

		// User retrieval by username (if authenticated)
		protected.GET("/user/:username", userController.GetUserByUsername)
	}
}

// Rate limit for /register: 10 requests per 2 minutes, unique to "register" route
// r.POST("/register", middleware.NewRateLimiter("10-2m", "register"), func(c *gin.Context) {
// 	c.JSON(200, gin.H{"message": "Registered"})
// })

// Rate limit for /api/other: 10 requests per 2 minutes, unique to "api/other" route
// r.GET("/api/other", middleware.NewRateLimiter("10-2m", "api/other"), func(c *gin.Context) {
// 	c.JSON(200, gin.H{"message": "Other route"})
// })

package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/controllers"
	middleware "github.com/joy095/identity/middlewares"
	"github.com/joy095/identity/middlewares/auth"
	"github.com/joy095/identity/utils/mail"
)

func RegisterUserRoutes(router *gin.Engine) {
	userController := controllers.NewUserController()

	// Public routes
	router.POST("/register", middleware.CombinedRateLimiter("register", "10-2m", "30-60m"), userController.Register)
	router.POST("/login", middleware.CombinedRateLimiter("login", "10-2m", "30-30m"), userController.Login)
	router.POST("/refresh-token", middleware.NewRateLimiter("10-60m", "refresh-token"), userController.RefreshToken)

	router.POST("/username-availability", middleware.NewRateLimiter("60-2m", "username-availability"), userController.UsernameAvailability)

	router.POST("/forgot-password", middleware.NewRateLimiter("10-5m", "forgot-password"), userController.ForgotPassword)
	router.POST("/forgot-password-otp", middleware.CombinedRateLimiter("forgot-password-otp", "5-1m", "20-10m"), mail.VerifyForgotPasswordOTP)

	router.POST("/change-password", middleware.CombinedRateLimiter("change-password", "5-1m", "20-10m"), userController.ChangePassword)

	router.POST("/resend-otp", middleware.CombinedRateLimiter("resend-otp", "5-1m", "20-10m"), mail.ResendOTP)
	router.POST("/verify-otp", middleware.CombinedRateLimiter("verify-otp", "5-1m", "20-10m"), mail.VerifyOTP)

	// Protected routes
	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware())
	{
		protected.POST("/logout", middleware.CombinedRateLimiter("logout", "5-1m", "20-10m"), userController.Logout)

		// Profile Management
		protected.PATCH("/update-profile", middleware.CombinedRateLimiter("update-profile", "5-1m", "10-5m"), userController.UpdateProfile)
		protected.POST("/update-email", middleware.CombinedRateLimiter("update-email", "5-1m", "30-60m"), userController.UpdateEmailWithPassword)
		protected.POST("/verify-email-update-otp", middleware.CombinedRateLimiter("verify-email-update-otp", "5-1m", "30-60m"), userController.VerifyEmailChangeOTP)

		// User retrieval by username (if authenticated)
		protected.GET("/user/:username", middleware.NewRateLimiter("30-1m", "user/:username"), userController.GetUserByUsername)

	}
}

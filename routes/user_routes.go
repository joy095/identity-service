package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/controllers"
	"github.com/joy095/identity/middlewares/auth"
	"github.com/joy095/identity/utils/mail"
)

func RegisterRoutes(router *gin.Engine) {
	userController := controllers.NewUserController()
	// relationController := relations.NewRelationController()

	// Public routes
	router.POST("/register", userController.Register)
	router.POST("/login", userController.Login)
	router.POST("/refresh-token", userController.RefreshToken)

	router.POST("/forgot-password", userController.ForgotPassword)
	router.POST("/forgot-password-otp", mail.VerifyForgotPasswordOTP)

	router.POST("/change-password", userController.ChangePassword)

	router.POST("/request-otp", mail.RequestOTP)
	router.POST("/verify-otp", mail.VerifyOTP)

	// Protected routes
	protected := router.Group("/")
	protected.Use(auth.AuthMiddleware())
	{
		protected.POST("/logout", userController.Logout)

		// Profile route
		protected.GET("/user/:username", userController.GetUserByUsername)

	}

	// Relationship routes using JWT by default to send accept and reject requests
	// router.POST("/relation/request", relationController.SendRequest)
	// router.POST("/relation/accept", relationController.AcceptRequest)
	// router.POST("/relation/reject", relationController.RejectRequest)
	// router.GET("/relation/pending", relationController.ListPendingRequests)
	// router.GET("/relation/connections", relationController.ListConnections)
	// router.GET("/relation/status/:username", relationController.CheckConnectionStatus)

}

// Rate limit for /register: 10 requests per 2 minutes, unique to "register" route
// r.POST("/register", middleware.NewRateLimiter("10-2m", "register"), func(c *gin.Context) {
// 	c.JSON(200, gin.H{"message": "Registered"})
// })

// Rate limit for /api/other: 10 requests per 2 minutes, unique to "api/other" route
// r.GET("/api/other", middleware.NewRateLimiter("10-2m", "api/other"), func(c *gin.Context) {
// 	c.JSON(200, gin.H{"message": "Other route"})
// })

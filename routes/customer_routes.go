// routes/customer_routes.go
package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/controllers/customer_controller"
	"github.com/joy095/identity/middlewares/auth"
	// Assuming mail.VerifyCustomerOTP is also a controller/handler
)

func RegisterCustomerRoutes(router *gin.Engine) {
	// Instantiate the CustomerController
	customerController := customer_controller.NewCustomerController()

	customerGroup := router.Group("/customer")
	{
		customerGroup.POST("/register", customerController.CustomerRegister)

		customerGroup.POST("/already-register", customerController.AlreadyRegistered)

		// Verify email when registering
		customerGroup.POST("/verify-email", customerController.VerifyCustomerEmail)

		// otp route for login
		customerGroup.POST("/request-login-otp", customerController.RequestCustomerLogin)

		// Login with email
		customerGroup.POST("/login", customerController.CustomerLogin)

		customerGroup.POST("/refresh-token", customerController.CustomerRefreshToken)

		customerGroup.Use(auth.AuthMiddleware())
		{

		}
	}
}

package controllers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models"
	"github.com/joy095/identity/utils/mail"
)

// Assuming UserController is defined elsewhere
type CustomerController struct{}

// Register handles user registration
func (uc *UserController) CustomerRegister(c *gin.Context) {

	logger.InfoLogger.Info("Register handler called")

	// Define and bind the incoming JSON request body
	var req struct {
		Email string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// Log the specific binding error
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON: %w", err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) // Return specific binding error to client
		return
	}

	user, _, _, err := models.CreateCustomer(db.DB, req.Email)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to create user in database: %w", err)) // Log the DB error

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"}) // Generic error for unexpected DB issues
		return
	}

	// Send OTP (Assuming this is part of your registration flow)
	otp := mail.GenerateSecureOTP() // Assuming this generates a random string and potentially stores it securely
	// Send email asynchronously using a goroutine to avoid blocking the response
	go func() {
		sendErr := mail.SendOTPCustomer(req.Email, otp) // Assuming SendOTPCustomer sends the email and logs internal errors
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send OTP email to %s: %w", req.Email, sendErr))
			// Decide if a mail sending failure should cause registration to fail or just log.
			// If critical, you might need transaction rollback or a retry mechanism.
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("OTP email sent successfully to: %s", req.Email))
		}
	}()

	// Return Success Response
	logger.InfoLogger.Info(fmt.Sprintf("User registered successfully with ID: %v", user.ID)) // Log success with the new user's ID

	c.JSON(http.StatusCreated, gin.H{"id": user.ID, "email": user.Email})

}

// CustomerLogin handles user login using Email and OTP
func (uc *CustomerController) CustomerLogin(c *gin.Context) {
	logger.InfoLogger.Info("CustomerLogin handler (OTP based) called")

	// Define and bind the incoming JSON request body expecting email and otp
	var req struct {
		Email string `json:"email" binding:"required,email"` // Added 'email' binding for basic format check
	}

	// Bind the JSON request body to the struct
	if err := c.ShouldBindJSON(&req); err != nil {
		// Log the specific binding error
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON for OTP login: %w", err))
		// Return specific binding error to client
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Call the models function to perform OTP verification and login
	// The models.LoginCustomer function should:
	// 1. Find the user by email.
	// 2. Verify the provided OTP against the one stored for the user.
	// 3. Check if the OTP is still valid (not expired).
	// 4. Invalidate the OTP after successful use.
	// 5. Generate access and refresh tokens if verification is successful.
	user, accessToken, refreshToken, err := models.LoginCustomer(db.DB, req.Email)
	if err != nil {
		// Log the login failure (e.g., invalid email, invalid OTP, expired OTP)
		// Be cautious about logging the specific reason (e.g., "invalid OTP") to prevent enumeration attacks.
		// Logging the email associated with the failed attempt might be acceptable internally.
		logger.ErrorLogger.Error(fmt.Errorf("OTP login failed for email %s: %w", req.Email, err))

		// Return an unauthorized status with a generic message for failed login attempts
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or OTP"}) // Generic error message
		return
	}

	// Return success response with user details and tokens
	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":        user.ID,
			"username":  user.Username, // Make sure your User model has these fields if you return them
			"email":     user.Email,
			"firstName": user.FirstName,
			"lastName":  user.LastName,
			// Include other relevant user fields here that you want to return
		},
		"tokens": gin.H{
			"accessToken":  accessToken,
			"refreshToken": refreshToken,
		},
	})

	// Log successful login
	// Use email as a reliable identifier if username might be empty
	loggedInIdentifier := user.Email
	if user.Username != "" {
		loggedInIdentifier = user.Username
	}
	logger.InfoLogger.Infof("User %s logged in successfully via OTP", loggedInIdentifier)
}

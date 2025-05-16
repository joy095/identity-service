package controllers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models"
	"github.com/joy095/identity/utils"
	"github.com/joy095/identity/utils/mail"
)

type CustomerController struct{} // This struct might be redundant if UserController handles everything

// Register handles user registration
func (uc *UserController) CustomerRegister(c *gin.Context) {
	logger.InfoLogger.Info("Register controller called")

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
	otp, err := utils.GenerateSecureOTP() // Assuming this generates a random string and potentially stores it securely
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}
	// Send email asynchronously using a goroutine to avoid blocking the response
	go func() {
		sendErr := mail.SendCustomerOTP(req.Email, otp, "templates/customer_otp.html")
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send OTP email to %s: %w", req.Email, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("OTP email sent successfully to: %s", req.Email))
		}
	}()

	// Return Success Response
	logger.InfoLogger.Info(fmt.Sprintf("User registered successfully with ID: %v", user.ID)) // Log success with the new user's ID

	c.JSON(http.StatusCreated, gin.H{"id": user.ID, "email": user.Email})

}

// Changed receiver from *CustomerController to *UserController
func (uc *UserController) RequestCustomerLogin(c *gin.Context) {
	logger.InfoLogger.Info("RequestCustomerLogin controller called")

	var req struct {
		Email string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON for OTP login: %w", err))

		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate OTP and send email
	otp, err := utils.GenerateSecureOTP() // Assuming this generates a random string and potentially stores it securely
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	go func() {
		sendErr := mail.SendCustomerOTP(req.Email, otp, "templates/customer_otp_login.html")
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send OTP email to %s: %w", req.Email, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("OTP email sent successfully to: %s", req.Email))
		}
	}()

	c.JSON(http.StatusOK, gin.H{"message": "If the email exists, an OTP has been sent"})
}

// CustomerLogin handles user login using Email and OTP
// Changed receiver from *CustomerController to *UserController
func (uc *UserController) CustomerLogin(c *gin.Context) {
	logger.InfoLogger.Info("CustomerLogin controller (OTP based) called")

	// Define and bind the incoming JSON request body expecting email and otp
	var req struct {
		Email string `json:"email" binding:"required"`
		OTP   string `json:"otp" binding:"required"`
	}

	// Bind the JSON request body to the struct
	if err := c.ShouldBindJSON(&req); err != nil {
		// Log the specific binding error
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON for OTP login: %w", err))
		// Return specific binding error to client
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, accessToken, refreshToken, err := models.LoginCustomer(db.DB, req.Email, req.OTP)
	if err != nil {

		logger.ErrorLogger.Error(fmt.Errorf("OTP login failed for email %s: %w", req.Email, err))

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":        user.ID,
			"email":     user.Email,
			"firstName": user.FirstName,
			"lastName":  user.LastName,
		},
		"tokens": gin.H{
			"accessToken":  accessToken,
			"refreshToken": refreshToken,
		},
	})

	loggedInIdentifier := user.Email
	logger.InfoLogger.Infof("User %s logged in successfully via OTP", loggedInIdentifier)
}

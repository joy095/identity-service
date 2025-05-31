// controllers/customer_controller.go
package customer_controller

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5" // Import pgx for specific error checking
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/customer_models" // Import the models package
	"github.com/joy095/identity/utils"
	"github.com/joy095/identity/utils/mail"
)

// CustomerController holds methods for customer-related operations
type CustomerController struct{}

// NewCustomerController creates and returns a new instance of CustomerController
func NewCustomerController() *CustomerController {
	return &CustomerController{}
}

// CustomerRegister handles user registration
func (uc *CustomerController) CustomerRegister(c *gin.Context) {
	logger.InfoLogger.Info("CustomerRegister controller called")

	var req struct {
		Email string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON: %w", err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if customer already exists using the models layer
	_, err := customer_models.GetCustomerByEmail(db.DB, req.Email)
	if err == nil { // This means a customer *was* found, so it's already registered
		logger.InfoLogger.Infof("Attempted to register with existing email: %s", req.Email)
		c.JSON(http.StatusConflict, gin.H{"error": "User with this email already registered. Please login or use a different email."})
		return
	}
	if err != nil && err != pgx.ErrNoRows { // A real database error occurred
		logger.ErrorLogger.Error(fmt.Errorf("database error when checking for existing user: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check user existence"})
		return
	}

	// Create a new customer via the models layer
	user, err := customer_models.CreateCustomer(db.DB, req.Email)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to create user in database: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	go func() {
		sendErr := mail.SendCustomerOTP(req.Email, otp, mail.CustomerVerifyEmailTemplate)
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send OTP email to %s: %w", req.Email, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("OTP email sent successfully to: %s", req.Email))
		}
	}()

	logger.InfoLogger.Info(fmt.Sprintf("User registered successfully with ID: %v", user.ID))
	c.JSON(http.StatusCreated, gin.H{"id": user.ID, "email": user.Email})
}

// AlreadyRegistered handles checking if a customer is already registered
func (uc *CustomerController) AlreadyRegistered(c *gin.Context) {
	logger.InfoLogger.Info("AlreadyRegistered controller called")

	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	isAvailable, err := customer_models.IsUsernameAvailable(db.DB, req.Email)
	if err != nil {
		logger.ErrorLogger.Error("Database error checking Email availability: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if !isAvailable {
		logger.InfoLogger.Info(fmt.Sprintf("Email '%s' is not available", req.Email))
		c.JSON(http.StatusOK, gin.H{"available": false, "message": "Email is already taken"})
	} else {
		logger.InfoLogger.Info(fmt.Sprintf("Email '%s' is available", req.Email))
		c.JSON(http.StatusOK, gin.H{"available": true})
	}
}

// RequestCustomerLogin handles requesting an OTP for login
func (uc *CustomerController) RequestCustomerLogin(c *gin.Context) {
	logger.InfoLogger.Info("RequestCustomerLogin controller called")

	var req struct {
		Email string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON for OTP login: %w", err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	go func() {
		sendErr := mail.SendCustomerOTP(req.Email, otp, mail.CustomerLoginTemplate)
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send OTP email to %s: %w", req.Email, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("OTP email sent successfully to: %s", req.Email))
		}
	}()

	c.JSON(http.StatusOK, gin.H{"message": "If the email exists, an OTP has been sent"})
}

// CustomerLogin handles user login using Email and OTP
func (uc *CustomerController) CustomerLogin(c *gin.Context) {
	logger.InfoLogger.Info("CustomerLogin controller (OTP based) called")

	var req struct {
		Email  string `json:"email" binding:"required"`
		OTP    string `json:"otp" binding:"required"`
		Device string `json:"device"` // Optional, but recommended for multi-device support
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON for OTP login: %w", err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Device == "" {
		req.Device = "web"
	}

	user, accessToken, refreshToken, err := customer_models.LoginCustomer(db.DB, req.Email, req.OTP, req.Device)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("OTP login failed for email %s: %w", req.Email, err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
			// Safely dereference pointers, provide empty string if nil
			"firstName": func() string {
				if user.FirstName != nil {
					return *user.FirstName
				}
				return ""
			}(),
			"lastName": func() string {
				if user.LastName != nil {
					return *user.LastName
				}
				return ""
			}(),
		},
		"tokens": gin.H{
			"accessToken":  accessToken,
			"refreshToken": refreshToken,
		},
	})

	loggedInIdentifier := user.Email
	logger.InfoLogger.Infof("User %s logged in successfully via OTP", loggedInIdentifier)
}

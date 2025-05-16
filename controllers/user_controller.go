package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/joy095/identity/badwords"
	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models"
	"github.com/joy095/identity/utils"

	"github.com/joy095/identity/utils/mail"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// UserController handles user-related requests
type UserController struct{}

// NewUserController creates a new UserController
func NewUserController() *UserController {
	return &UserController{}
}

var lowercaseUsernameRegex = regexp.MustCompile("^[a-z0-9_-]{3,20}$")

// Register handles user registration
func (uc *UserController) Register(c *gin.Context) {

	logger.InfoLogger.Info("Register handler called")

	// 1. Define and bind the incoming JSON request body
	var req struct {
		Username  string `json:"username" binding:"required"`
		FirstName string `json:"first_name" binding:"required"`
		LastName  string `json:"last_name" binding:"required"`
		Email     string `json:"email" binding:"required,email"`
		Password  string `json:"password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		// Log the specific binding error
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON: %w", err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) // Return specific binding error to client
		return
	}

	req.Username = strings.ToLower(req.Username)

	// --- Add Regex Validation Here ---
	if !lowercaseUsernameRegex.MatchString(req.Username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username must be 3-20 characters long, containing only lowercase letters, numbers, hyphens, or underscores."})
		return
	}

	// --- 2. Check if username contains bad words using the local badwords package ---

	// Call the local badwords package function
	// This assumes badwords.LoadBadWords has been called once at application startup
	logger.InfoLogger.Info(fmt.Sprintf("Checking username '%s' for bad words locally", req.Username))
	containsBadWords := badwords.CheckText(req.Username).ContainsBadWords

	if containsBadWords {
		logger.InfoLogger.Info(fmt.Sprintf("Username check failed for '%s': contains inappropriate words", req.Username)) // Log the specific username being rejected
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username contains inappropriate words"})
		return
	}
	// --- End Local Badwords Check Logic ---

	// --- 3. User Creation Logic ---
	// Assuming db.DB, models.CreateUser, utils.GenerateSecureOTP, mail.SendOTP exist and work

	user, _, _, err := models.CreateUser(db.DB, req.Username, req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to create user in database: %w", err)) // Log the DB error

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"}) // Generic error for unexpected DB issues
		return
	}

	// 4. Send OTP (Assuming this is part of your registration flow)
	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}
	go func() {
		sendErr := mail.SendOTP(req.Email, req.FirstName, req.LastName, otp) // Assuming SendOTP sends the email and logs internal errors
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send OTP email to %s: %w", req.Email, sendErr))
			// Decide if a mail sending failure should cause registration to fail or just log.
			// If critical, you might need transaction rollback or a retry mechanism.
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("OTP email sent successfully to: %s", req.Email))
		}
	}()

	// 5. Return Success Response
	logger.InfoLogger.Info(fmt.Sprintf("User registered successfully with ID: %v", user.ID)) // Log success with the new user's ID

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user": gin.H{
			"id":        user.ID,
			"username":  req.Username,
			"email":     user.Email,
			"firstName": user.FirstName,
			"lastName":  user.LastName,
		},
	})
	// No return needed here, JSON call ends the handler execution
}

// Login handles user login
func (uc *UserController) Login(c *gin.Context) {
	logger.InfoLogger.Info("Login handler called")

	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid login payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, accessToken, refreshToken, err := models.LoginUser(db.DB, req.Username, req.Password)
	if err != nil {
		logger.ErrorLogger.Error("Invalid credentials: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":        user.ID,
			"username":  user.Username,
			"email":     user.Email,
			"firstName": user.FirstName,
			"lastName":  user.LastName,
		},
		"tokens": gin.H{
			"accessToken":  accessToken,
			"refreshToken": refreshToken,
		},
	})

	logger.InfoLogger.Infof("User %s logged in successfully", user.Username)
}

// Forget Password
func (uc *UserController) ForgotPassword(c *gin.Context) {
	logger.InfoLogger.Info("ForgotPassword handler called")

	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Username string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid forgot password payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if user exists
	user, err := models.GetUserByUsername(db.DB, req.Username)
	if err != nil {
		logger.ErrorLogger.Error("User not found with email: " + req.Username)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.Email != req.Email {
		logger.ErrorLogger.Error("Email does not match the user's email")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Email does not match the user's email"})
		return
	}

	// Generate secure OTP
	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	err = mail.StoreOTP(req.Username+"-"+req.Email, otp)
	if err != nil {
		logger.ErrorLogger.Error("Failed to store OTP")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP"})
		return
	}

	// Send OTP via email
	if err := mail.SendForgotPasswordOTP(req.Email, otp); err != nil {
		logger.ErrorLogger.Error("Failed to send OTP: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP"})
		return
	}

	// TODO: Store OTP in Redis or DB with expiry, associate it with user.ID/email

	c.JSON(http.StatusOK, gin.H{
		"message": "OTP sent to email successfully",
	})

}

// Change Password function
func (uc *UserController) ChangePassword(c *gin.Context) {
	logger.InfoLogger.Info("ChangePassword handler called")

	var req struct {
		Username    string `json:"username" binding:"required"`
		Password    string `json:"password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}

	// Validate request body
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid change password payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Fetch user
	user, err := models.GetUserByUsername(db.DB, req.Username)
	if err != nil {
		logger.ErrorLogger.Error("User not found: " + err.Error())
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Compare existing password
	valid, err := models.ComparePasswords(db.DB, req.Password, req.Username)
	if err != nil {
		logger.ErrorLogger.Error("Error comparing passwords: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if !valid {
		logger.ErrorLogger.Error("Incorrect username or password")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
		return
	}

	// Hash new password
	hashedPassword, err := models.HashPassword(req.NewPassword)
	if err != nil {
		logger.ErrorLogger.Error("Failed to hash new password: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process new password"})
		return
	}

	// Update password in DB
	_, err = db.DB.Exec(context.Background(), `UPDATE users SET password_hash = $1 WHERE id = $2`, hashedPassword, user.ID)
	if err != nil {
		logger.ErrorLogger.Error("Failed to update password in DB: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	logger.InfoLogger.Infof("Password changed successfully for user: %s", user.Username)
	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// RefreshToken function
func (uc *UserController) RefreshToken(c *gin.Context) {
	logger.InfoLogger.Info("RefreshToken token function called")

	// Simulate refresh token API call
	time.Sleep(1 * time.Second) // Simulating network latency

	refreshToken := c.GetHeader("Refresh-Token")
	if refreshToken == "" {
		logger.ErrorLogger.Error("No refresh token provided in header")
		c.JSON(http.StatusBadRequest, gin.H{"error": "No refresh token provided"})
		return
	}

	// Remove 'Bearer ' prefix if present
	refreshToken = strings.TrimPrefix(refreshToken, "Bearer ")

	// Query the database to find the user with this refresh token
	var user models.User
	query := `SELECT id, username, email, refresh_token FROM users WHERE refresh_token = $1`
	err := db.DB.QueryRow(context.Background(), query, refreshToken).Scan(
		&user.ID, &user.Username, &user.Email, &user.RefreshToken,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Token not found in database
			logger.ErrorLogger.Error("error", "Invalid or expired refresh token")

			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})

		} else {
			// Database error
			logger.ErrorLogger.Error("error", "Database error")

			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	// Generate a new access token
	accessToken, err := models.GenerateAccessToken(user.ID, time.Minute*60) // Access Token for 1 hour
	if err != nil {
		logger.ErrorLogger.Error("error", "Failed to generate access token")

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// Generate a new refresh token (optional, for token rotation)
	newRefreshToken, err := models.GenerateRefreshToken(user.ID, time.Hour*24*30) // Stronger Refresh Token for 30 days
	if err != nil {
		logger.ErrorLogger.Error("error", "Failed to generate refresh token")

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	// Update the refresh token in the database
	_, err = db.DB.Exec(context.Background(), `UPDATE users SET refresh_token = $1 WHERE id = $2`, newRefreshToken, user.ID)
	if err != nil {
		logger.ErrorLogger.Error("error", "Failed to update refresh token")

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update refresh token"})
		return
	}

	// Return the new tokens
	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": newRefreshToken,
	})

	logger.InfoLogger.Info("RefreshToken is created successfully")
}

// Logout handles user logout
func (uc *UserController) Logout(c *gin.Context) {
	logger.InfoLogger.Info("Logout handler called")

	var req struct {
		UserID string `json:"user_id" binding:"required,uuid"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("error-message", err.Error())

		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format or missing fields"})
		return
	}

	// Get the user ID from the context
	userIDFromToken, exists := c.Get("user_id")
	if !exists {
		logger.ErrorLogger.Error("Unauthorized")

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Ensure the user can only log out their own account
	if userIDFromToken != req.UserID {
		logger.ErrorLogger.Error("You can only log out your own account")

		c.JSON(http.StatusForbidden, gin.H{"error": "You can only log out your own account"})
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		logger.ErrorLogger.Error("Invalid user ID format")

		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	if err := models.LogoutUser(db.DB, userID); err != nil {
		logger.ErrorLogger.Error("Failed to logout")

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	logger.InfoLogger.Info("Successfully logged out")

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

// GetUserByUsername retrieves a user by username
func (uc *UserController) GetUserByUsername(c *gin.Context) {
	logger.InfoLogger.Info("GetUserByUsername function called")

	username := c.Param("username")

	user, err := models.GetUserByUsername(db.DB, username)
	if err != nil {
		logger.ErrorLogger.Error("User not found")
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":         user.ID,
			"username":   user.Username,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
		},
	})

	logger.InfoLogger.Info("User retrieved successfully")
}

// GetUserByID retrieves a user by ID
func (uc *UserController) GetUserByID(c *gin.Context) {
	logger.InfoLogger.Info("GetUserByID function called")

	id := c.Param("id")

	user, err := models.GetUserByID(db.DB, id)
	if err != nil {
		logger.ErrorLogger.Errorf("User not found: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		},
	})

	logger.InfoLogger.Info("User retrieved successfully by ID")
}

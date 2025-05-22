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
	"github.com/joy095/identity/utils/mail" // Ensure this import is present

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

// validateUsername performs common username validation checks
func validateUsername(username string) error {
	// Ensure username is lowercase (already done before calling this, but good practice)
	username = strings.ToLower(username)

	// Regex Validation
	if !lowercaseUsernameRegex.MatchString(username) {
		return fmt.Errorf("username must be 3-20 characters long, containing only lowercase letters, numbers, hyphens, or underscores")
	}

	// Bad Words Check
	if badwords.CheckText(username).ContainsBadWords {
		return fmt.Errorf("username contains inappropriate words")
	}

	// No issues found
	return nil
}

// UsernameAvailability checks if a username is available
func (uc *UserController) UsernameAvailability(c *gin.Context) {
	logger.InfoLogger.Info("UsernameAvailability controller called")

	var req struct {
		Username string `json:"username" binding:"required,min=3,max=20"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Username = strings.ToLower(req.Username)

	if err := validateUsername(req.Username); err != nil {
		logger.InfoLogger.Info(fmt.Sprintf("Username validation failed for '%s': %v", req.Username, err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	isAvailable, err := models.IsUsernameAvailable(db.DB, req.Username)
	if err != nil {
		logger.ErrorLogger.Error("Database error checking username availability: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if !isAvailable {
		logger.InfoLogger.Info(fmt.Sprintf("Username '%s' is not available", req.Username))
		c.JSON(http.StatusOK, gin.H{"available": false, "message": "Username is already taken"})
	} else {
		logger.InfoLogger.Info(fmt.Sprintf("Username '%s' is available", req.Username))
		c.JSON(http.StatusOK, gin.H{"available": true})
	}
}

// UpdateProfile handles user profile updates
func (uc *UserController) UpdateProfile(c *gin.Context) {
	logger.InfoLogger.Info("UpdateProfile function called")

	userIDFromToken, exists := c.Get("user_id")
	if !exists {
		logger.ErrorLogger.Error("Unauthorized: User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userID, err := uuid.Parse(userIDFromToken.(string))
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid user ID from token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	var req struct {
		Username  *string `json:"username"`
		FirstName *string `json:"firstName"`
		LastName  *string `json:"lastName"`
		Email     *string `json:"email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid update profile payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUser, err := models.GetUserByID(db.DB, userID.String())
	if err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("User not found for ID %s: %v", userID, err))
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	updates := make(map[string]interface{})
	emailChanged := false
	var newEmail string

	if req.Username != nil && *req.Username != "" && strings.ToLower(*req.Username) != currentUser.Username {
		lowerCaseUsername := strings.ToLower(*req.Username)

		if err := validateUsername(lowerCaseUsername); err != nil {
			logger.InfoLogger.Info(fmt.Sprintf("Username validation failed for '%s': %v", lowerCaseUsername, err))
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		isAvailable, err := models.IsUsernameAvailable(db.DB, lowerCaseUsername)
		if err != nil {
			logger.ErrorLogger.Error("Database error checking new username availability: " + err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		if !isAvailable {
			logger.InfoLogger.Info(fmt.Sprintf("Update profile failed: username '%s' is already taken", lowerCaseUsername))
			c.JSON(http.StatusConflict, gin.H{"error": "Username is already taken"})
			return
		}
		updates["username"] = lowerCaseUsername
	}

	if req.FirstName != nil && *req.FirstName != "" && *req.FirstName != currentUser.FirstName {
		updates["first_name"] = *req.FirstName
	}

	if req.LastName != nil && *req.LastName != "" && *req.LastName != currentUser.LastName {
		updates["last_name"] = *req.LastName
	}

	// Handle email update - requires OTP verification
	if req.Email != nil && *req.Email != "" && *req.Email != currentUser.Email {
		// Basic email format validation (more thorough validation should be done by binding:"email")
		if !strings.Contains(*req.Email, "@") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
			return
		}
		emailChanged = true
		newEmail = *req.Email
	}

	if len(updates) == 0 && !emailChanged {
		c.JSON(http.StatusOK, gin.H{"message": "No changes detected for profile update"})
		return
	}

	// Apply immediate updates (username, first_name, last_name)
	if len(updates) > 0 {
		err = models.UpdateUserFields(db.DB, userID, updates)
		if err != nil {
			logger.ErrorLogger.Error(fmt.Sprintf("Failed to update user fields for ID %s: %v", userID, err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
			return
		}
	}

	// Handle email change with OTP verification
	if emailChanged {
		otp, err := utils.GenerateSecureOTP()
		if err != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP for email change for user %s: %w", userID, err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP for email verification"})
			return
		}

		// Store the OTP and the new email with the user's ID
		if err := mail.StoreEmailChangeOTP(userID.String(), newEmail, otp); err != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to store email change OTP for user %s: %w", userID, err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate email change verification"})
			return
		}

		// Send the OTP email asynchronously
		go func() {
			sendErr := mail.SendEmailChangeOTP(newEmail, currentUser.FirstName, currentUser.LastName, otp)
			if sendErr != nil {
				logger.ErrorLogger.Error(fmt.Errorf("failed to send email change OTP to %s for user %s: %w", newEmail, userID, sendErr))
			} else {
				logger.InfoLogger.Info(fmt.Sprintf("Email change OTP sent successfully to: %s for user %s", newEmail, userID))
			}
		}()

		c.JSON(http.StatusOK, gin.H{
			"message":              "Profile updated successfully. If email was changed, an OTP has been sent to the new email for verification.",
			"email_change_pending": true, // Indicate that email verification is pending
		})
	} else {
		// If only other fields were updated, or no changes
		c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
	}

	logger.InfoLogger.Info(fmt.Sprintf("User profile update process completed for ID: %s", userID))
}

// SendProfileUpdateOTP sends an OTP to a new email for verification during profile update.
func (uc *UserController) SendProfileUpdateOTP(c *gin.Context) {
	logger.InfoLogger.Info("SendProfileUpdateOTP controller called")

	userIDFromToken, exists := c.Get("user_id")
	if !exists {
		logger.ErrorLogger.Error("Unauthorized: User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userID, err := uuid.Parse(userIDFromToken.(string))
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid user ID from token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid payload for SendProfileUpdateOTP: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUser, err := models.GetUserByID(db.DB, userID.String())
	if err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("User not found for ID %s: %v", userID, err))
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Generate a new OTP
	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP for email change for user %s: %w", userID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	// Store the OTP with the user's ID and the target new email
	if err := mail.StoreEmailChangeOTP(userID.String(), req.Email, otp); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to store email change OTP for user %s: %w", userID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP. Please try again."})
		return
	}

	// Send the OTP email asynchronously
	go func() {
		sendErr := mail.SendEmailChangeOTP(req.Email, currentUser.FirstName, currentUser.LastName, otp)
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send email change OTP to %s for user %s: %w", req.Email, userID, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("Email change OTP sent successfully to: %s for user %s", req.Email, userID))
		}
	}()

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent to new email for verification."})
}

// VerifyProfileUpdateOTP verifies the OTP for an email change during profile update.
func (uc *UserController) VerifyProfileUpdateOTP(c *gin.Context) {
	logger.InfoLogger.Info("VerifyProfileUpdateOTP controller called")

	userIDFromToken, exists := c.Get("user_id")
	if !exists {
		logger.ErrorLogger.Error("Unauthorized: User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userID, err := uuid.Parse(userIDFromToken.(string))
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid user ID from token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	var req struct {
		Email string `json:"email" binding:"required,email"`
		OTP   string `json:"otp" binding:"required,len=6"` // Assuming 6-digit OTP
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid payload for VerifyProfileUpdateOTP: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Retrieve the stored OTP hash and the email it was sent to
	storedOTP, storedEmail, err := mail.RetrieveEmailChangeOTP(userID.String())
	if err != nil {
		if errors.Is(err, mail.ErrOTPNotFound) {
			logger.InfoLogger.Info(fmt.Sprintf("OTP not found or expired for user %s", userID))
			c.JSON(http.StatusBadRequest, gin.H{"error": "OTP not found or expired. Please request a new one."})
			return
		}
		logger.ErrorLogger.Error(fmt.Errorf("error retrieving stored OTP for user %s: %w", userID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during OTP verification"})
		return
	}

	// Check if the provided email matches the email stored for this verification
	if storedEmail != req.Email {
		logger.InfoLogger.Info(fmt.Sprintf("Email mismatch for user %s: requested %s, stored %s", userID, req.Email, storedEmail))
		c.JSON(http.StatusBadRequest, gin.H{"error": "The provided email does not match the email pending verification."})
		return
	}

	// Verify the OTP
	if utils.HashOTP(req.OTP) != storedOTP {
		logger.InfoLogger.Info(fmt.Sprintf("Invalid OTP for user %s, email %s", userID, req.Email))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OTP"})
		return
	}

	// If OTP is valid, update the user's email in the database
	updates := map[string]interface{}{"email": req.Email, "is_verified_email": true} // Set email as verified after change
	err = models.UpdateUserFields(db.DB, userID, updates)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("Failed to update user email for ID %s: %v", userID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update email in database"})
		return
	}

	// Clear the OTP from Redis after successful verification
	if err := mail.ClearEmailChangeOTP(userID.String()); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to clear OTP for user %s: %w", userID, err))
	}

	logger.InfoLogger.Info(fmt.Sprintf("User email updated successfully for ID: %s to %s", userID, req.Email))
	c.JSON(http.StatusOK, gin.H{"message": "Email updated successfully!"})
}

// GetUserProfile retrieves the profile information for the authenticated user.
func (uc *UserController) GetUserProfile(c *gin.Context) {
	logger.InfoLogger.Info("GetUserProfile function called")

	userIDFromToken, exists := c.Get("user_id")
	if !exists {
		logger.ErrorLogger.Error("Unauthorized: User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userID, err := uuid.Parse(userIDFromToken.(string))
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid user ID from token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	user, err := models.GetUserByID(db.DB, userID.String())
	if err != nil {
		logger.ErrorLogger.Errorf("User not found for ID %s: %v", userID, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User profile not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":              user.ID,
		"username":        user.Username,
		"firstName":       user.FirstName,
		"lastName":        user.LastName,
		"email":           user.Email,
		"isVerifiedEmail": user.IsVerifiedEmail, // Include email verification status
	})

	logger.InfoLogger.Info(fmt.Sprintf("User profile retrieved successfully for ID: %s", userID))
}

// isValidUsernameChar checks if the username contains only valid characters
func isValidUsernameChar(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// Register handles user registration
func (uc *UserController) Register(c *gin.Context) {
	logger.InfoLogger.Info("Register controller called")

	var req struct {
		Username  string `json:"username" binding:"required"`
		FirstName string `json:"firstName" binding:"required"`
		LastName  string `json:"lastName" binding:"required"`
		Email     string `json:"email" binding:"required,email"`
		Password  string `json:"password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON: %w", err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Username = strings.ToLower(req.Username)

	if err := validateUsername(req.Username); err != nil {
		logger.InfoLogger.Info(fmt.Sprintf("Username validation failed for '%s' during registration: %v", req.Username, err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	isAvailable, err := models.IsUsernameAvailable(db.DB, req.Username)
	if err != nil {
		logger.ErrorLogger.Error("Database error checking username availability during registration: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if !isAvailable {
		logger.InfoLogger.Info(fmt.Sprintf("Registration failed for '%s': username already taken", req.Username))
		c.JSON(http.StatusConflict, gin.H{"error": "Username is already taken"})
		return
	}

	user, _, _, err := models.CreateUser(db.DB, req.Username, req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to create user in database for '%s': %w", req.Username, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP for user %s: %w", req.Username, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	go func() {
		sendErr := mail.SendOTP(req.Email, req.FirstName, req.LastName, otp)
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send OTP email to %s for user %s: %w", req.Email, req.Username, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("OTP email sent successfully to: %s for user %s", req.Email, req.Username))
		}
	}()

	logger.InfoLogger.Info(fmt.Sprintf("User registered successfully with ID: %v, Username: %s", user.ID, user.Username))

	c.JSON(http.StatusCreated, gin.H{
		"id":        user.ID,
		"username":  req.Username,
		"email":     user.Email,
		"firstName": user.FirstName,
		"lastName":  user.LastName,
	})
}

// Login handles user login
func (uc *UserController) Login(c *gin.Context) {
	logger.InfoLogger.Info("Login controller called")

	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid login payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.Username = strings.ToLower(req.Username)

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

// ForgotPassword handles sending OTP for password reset
func (uc *UserController) ForgotPassword(c *gin.Context) {
	logger.InfoLogger.Info("ForgotPassword controller called")

	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Username string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid forgot password payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := models.GetUserByUsername(db.DB, req.Username)
	if err != nil {
		logger.ErrorLogger.Error("User not found with username: " + req.Username)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.Email != req.Email {
		logger.ErrorLogger.Error("Email does not match the user's email")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Email does not match the user's email"})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	// Using the provided mail.StoreOTP for password reset OTP, with a specific key
	err = mail.StoreOTP("forgot_password_otp:"+req.Username+"-"+req.Email, otp)
	if err != nil {
		logger.ErrorLogger.Error("Failed to store OTP: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP"})
		return
	}

	// Using the provided mail.SendForgotPasswordOTP
	if err := mail.SendForgotPasswordOTP(req.Email, otp); err != nil {
		logger.ErrorLogger.Error("Failed to send OTP: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "OTP sent to email successfully",
	})
}

// ChangePassword handles changing user's password
func (uc *UserController) ChangePassword(c *gin.Context) {
	logger.InfoLogger.Info("ChangePassword controller called")

	var req struct {
		Username    string `json:"username" binding:"required"`
		Password    string `json:"password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid change password payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := models.GetUserByUsername(db.DB, req.Username)
	if err != nil {
		logger.ErrorLogger.Error("User not found: " + err.Error())
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

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

	hashedPassword, err := models.HashPassword(req.NewPassword)
	if err != nil {
		logger.ErrorLogger.Error("Failed to hash new password: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process new password"})
		return
	}

	_, err = db.DB.Exec(context.Background(), `UPDATE users SET password_hash = $1 WHERE id = $2`, hashedPassword, user.ID)
	if err != nil {
		logger.ErrorLogger.Error("Failed to update password in DB: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	logger.InfoLogger.Infof("Password changed successfully for user: %s", user.Username)
	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// RefreshToken handles refreshing access tokens
func (uc *UserController) RefreshToken(c *gin.Context) {
	logger.InfoLogger.Info("RefreshToken token function called")

	time.Sleep(1 * time.Second)

	refreshToken := c.GetHeader("Refresh-Token")
	if refreshToken == "" {
		logger.ErrorLogger.Error("No refresh token provided in header")
		c.JSON(http.StatusBadRequest, gin.H{"error": "No refresh token provided"})
		return
	}

	refreshToken = strings.TrimPrefix(refreshToken, "Bearer ")

	var user models.User
	query := `SELECT id, username, email, refresh_token FROM users WHERE refresh_token = $1`
	err := db.DB.QueryRow(context.Background(), query, refreshToken).Scan(
		&user.ID, &user.Username, &user.Email, &user.RefreshToken,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.ErrorLogger.Error("error", "Invalid or expired refresh token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		} else {
			logger.ErrorLogger.Error("error", "Database error")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	accessToken, err := models.GenerateAccessToken(user.ID, time.Minute*60)
	if err != nil {
		logger.ErrorLogger.Error("error", "Failed to generate access token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	newRefreshToken, err := models.GenerateRefreshToken(user.ID, time.Hour*24*30)
	if err != nil {
		logger.ErrorLogger.Error("error", "Failed to generate refresh token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	_, err = db.DB.Exec(context.Background(), `UPDATE users SET refresh_token = $1 WHERE id = $2`, newRefreshToken, user.ID)
	if err != nil {
		logger.ErrorLogger.Error("error", "Failed to update refresh token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": newRefreshToken,
	})

	logger.InfoLogger.Info("RefreshToken is created successfully")
}

// Logout handles user logout
func (uc *UserController) Logout(c *gin.Context) {
	logger.InfoLogger.Info("Logout controller called")

	var req struct {
		UserID string `json:"user_id" binding:"required,uuid"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("error-message", err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format or missing fields"})
		return
	}

	userIDFromToken, exists := c.Get("user_id")
	if !exists {
		logger.ErrorLogger.Error("Unauthorized")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// This check should ideally be against the actual user_id from the token
	// `userIDFromToken` is an interface{}, req.UserID is a string. Need to convert userIDFromToken to string or uuid.
	// For now, assuming direct comparison intent if types were aligned.
	// A more robust check might involve parsing userIDFromToken to uuid.UUID.
	// parsedTokenUserID, ok := userIDFromToken.(uuid.UUID)
	// if !ok || parsedTokenUserID.String() != req.UserID {
	// 	logger.ErrorLogger.Error("You can only log out your own account")
	// 	c.JSON(http.StatusForbidden, gin.H{"error": "You can only log out your own account"})
	// 	return
	// }

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
			"id":        user.ID,
			"username":  user.Username,
			"email":     user.Email,
			"firstName": user.FirstName,
			"lastName":  user.LastName,
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

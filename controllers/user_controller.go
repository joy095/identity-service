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

	if len(updates) == 0 {
		c.JSON(http.StatusOK, gin.H{"message": "No changes detected for profile update"})
		return
	}

	// Apply immediate updates (username, first_name, last_name)
	err = models.UpdateUserFields(db.DB, userID, updates)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("Failed to update user fields for ID %s: %v", userID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	logger.InfoLogger.Info(fmt.Sprintf("User profile update process completed for ID: %s", userID))
	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

// UpdateEmailWithPassword handles updating a user's email, requiring current password for verification.
func (uc *UserController) UpdateEmailWithPassword(c *gin.Context) {
	logger.InfoLogger.Info("UpdateEmailWithPassword controller called")

	var req struct {
		NewEmail string `json:"newEmail" binding:"required,email"`
		Password string `json:"password" binding:"required"`
		Username string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid payload for UpdateEmailWithPassword: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

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

	currentUser, err := models.GetUserByID(db.DB, userID.String())
	if err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("User not found for ID %s: %v", userID, err))
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 1. Verify current password
	// Assume models.ComparePasswords can take user.ID or user.Username and the plain password
	// Assuming `models.ComparePasswords` takes the plain password and the stored hashed password,
	// or it fetches the user by username/ID and compares. Let's assume it fetches by username
	// as is common in your models, but it should ideally use user.ID here for directness.
	// If `models.ComparePasswords` requires a username, you'd use `currentUser.Username`.
	validPassword, err := models.ComparePasswords(db.DB, req.Password, currentUser.Username)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("Error comparing passwords for user %s: %v", currentUser.Username, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during password verification"})
		return
	}
	if !validPassword {
		logger.InfoLogger.Info(fmt.Sprintf("Incorrect current password provided by user %s during email update attempt", currentUser.Username))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect current password"})
		return
	}

	// 2. Check if the new email is already the current email
	if req.NewEmail == currentUser.Email {
		c.JSON(http.StatusOK, gin.H{"message": "New email is the same as the current email. No update needed."})
		return
	}

	// 4. Generate and send OTP to the new email
	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP for email change for user %s: %w", userID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP for email verification"})
		return
	}

	// Store the OTP and the new email with the user's ID
	if err := mail.StoreOTP(mail.EMAIL_CHANGE_NEW_OTP_PREFIX+req.Username, otp); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to store email change OTP for user %s: %w", userID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate email change verification"})
		return
	}

	// Send the OTP email asynchronously
	go func() {
		sendErr := mail.SendEmailChangeNewOTP(req.NewEmail, currentUser.FirstName, currentUser.LastName, otp)
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send email change OTP to %s for user %s: %w", req.NewEmail, userID, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("Email change OTP sent successfully to: %s for user %s", req.NewEmail, userID))
		}
	}()

	logger.InfoLogger.Info(fmt.Sprintf("Email change initiated for user %s. OTP sent to %s.", userID, req.NewEmail))
	c.JSON(http.StatusOK, gin.H{
		"message":              "An OTP has been sent to your new email for verification. Please verify to complete the email change.",
		"email_change_pending": true,
	})
}

// VerifyProfileUpdateOTP verifies the OTP for an email change during profile update.
func (uc *UserController) VerifyEmailChangeOTP(c *gin.Context) {
	logger.InfoLogger.Info("VerifyEmailChangeOTP called")

	var req struct {
		Email    string `json:"email" binding:"required,email"`
		OTP      string `json:"otp" binding:"required,len=6"`
		Username string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid request for VerifyEmailChangeOTP: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()}) // Added err.Error() for better debugging
		return
	}

	req.Email = strings.ToLower(strings.Trim(req.Email, " "))

	user, err := models.GetUserByUsername(db.DB, req.Username) // Assume GetUserByEmail exists
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.InfoLogger.Infof("Attempted password reset for non-existent Username: %s", req.Username)
			// For security, always return a generic success message even if email isn't found
			// to avoid user enumeration.
			c.JSON(http.StatusOK, gin.H{"message": "If the email is registered, an OTP has been sent for password reset."})
			return
		}
		logger.ErrorLogger.Error(fmt.Errorf("database error fetching user by email: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP for user %s: %w", req.Username, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	if err := mail.StoreOTP(mail.EMAIL_VERIFICATION_OTP_PREFIX+req.Username, otp); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to store registration OTP for username %s: %w", req.Username, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP for verification"})
		return
	}

	go func() {
		sendErr := mail.SendEmailChangeNewOTP(req.Email, user.FirstName, user.LastName, otp)
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send OTP email to %s for user %s: %w", req.Email, req.Username, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("OTP email sent successfully to: %s for user %s", req.Email, req.Username))
		}
	}()

	ctx := context.Background() // Define ctx here or pass it from a middleware if available

	// Update user's email
	_, err = db.DB.Exec(ctx, "UPDATE users SET email = $1, is_verified_email = TRUE WHERE id = $2", req.Email, user.ID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update email for user %s: %v", user.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update email"})
		return
	}

	logger.InfoLogger.Info("Email change OTP verified and email updated successfully")

	c.JSON(http.StatusOK, gin.H{
		"message": "Email updated successfully!",
	})
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

	// For registration, it's generally good practice to store the OTP against the new user's ID
	// or the email, and then verify that in a separate endpoint.
	// Assuming `mail.StoreOTP` is suitable for this purpose.
	if err := mail.StoreOTP(mail.EMAIL_VERIFICATION_OTP_PREFIX+user.Username, otp); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to store registration OTP for user %s: %w", user.ID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP for verification"})
		return
	}

	go func() {
		sendErr := mail.SendVerificationOTP(req.Email, req.FirstName, req.LastName, otp)
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
		"message":   "User registered successfully. Please check your email for OTP verification.",
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

	// We only need the email to send the OTP. We'll verify username/email later.
	// For security, avoid revealing if the user exists based on email alone.
	// Just proceed with sending the OTP if the email exists in the system.
	user, err := models.GetUserByUsername(db.DB, req.Username) // Assume GetUserByEmail exists
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.InfoLogger.Infof("Attempted password reset for non-existent Username: %s", req.Username)
			// For security, always return a generic success message even if email isn't found
			// to avoid user enumeration.
			c.JSON(http.StatusOK, gin.H{"message": "If the email is registered, an OTP has been sent for password reset."})
			return
		}
		logger.ErrorLogger.Error(fmt.Errorf("database error fetching user by email: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	// Store the OTP with the user's ID to associate it clearly
	// This ensures the OTP is tied to a specific user trying to reset their password.
	// The key should be unique per user for password reset.
	resetKey := mail.FORGOT_PASSWORD_OTP_PREFIX + user.Username
	err = mail.StoreOTP(resetKey, otp)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to store OTP for password reset for user %s: %w", user.ID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate password reset"})
		return
	}

	// Send the OTP email asynchronously
	go func() {
		sendErr := mail.SendForgotPasswordOTP(user.Email, user.FirstName, user.LastName, otp) // Pass user details if email template uses them
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send forgot password OTP to %s for user %s: %w", user.Email, user.Username, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("Forgot password OTP sent successfully to: %s for user %s", user.Email, user.Username))
		}
	}()

	c.JSON(http.StatusOK, gin.H{
		"message": "If the email is registered, an OTP has been sent for password reset.",
	})
}

// ResetPassword verifies the OTP and sets a new password.
func (uc *UserController) ResetPassword(c *gin.Context) {
	logger.InfoLogger.Info("ResetPassword controller called")

	var req struct {
		Email       string `json:"email" binding:"required,email"`
		OTP         string `json:"otp" binding:"required,len=6"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
		Username    string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid reset password payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := models.GetUserByUsername(db.DB, req.Username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.InfoLogger.Infof("Password reset attempt for non-existent username: %s", req.Email)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email or OTP."})
			return
		}
		logger.ErrorLogger.Error(fmt.Errorf("database error fetching user by email for password reset: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Retrieve the stored OTP using the same key format as in ForgotPassword
	resetKey := mail.FORGOT_PASSWORD_OTP_PREFIX + user.Username
	storedOTP, err := mail.RetrieveOTP(resetKey)
	if err != nil {
		if errors.Is(err, mail.ErrOTPNotFound) {
			logger.InfoLogger.Info(fmt.Sprintf("Password reset OTP not found or expired for user %s (email: %s)", user.ID, req.Email))
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired OTP. Please request a new one."})
			return
		}
		logger.ErrorLogger.Error(fmt.Errorf("error retrieving stored password reset OTP for user %s: %w", user.ID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during OTP verification"})
		return
	}

	// Verify the OTP
	if utils.HashOTP(req.OTP) != storedOTP {
		logger.InfoLogger.Info(fmt.Sprintf("Invalid password reset OTP for user %s (email: %s)", user.ID, req.Email))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OTP."})
		return
	}

	// Hash the new password
	hashedPassword, err := models.HashPassword(req.NewPassword)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to hash new password for user %s: %w", user.ID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process new password"})
		return
	}

	// Update the user's password in the database
	_, err = db.DB.Exec(context.Background(), `UPDATE users SET password_hash = $1 WHERE id = $2`, hashedPassword, user.ID)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to update password in DB for user %s: %w", user.ID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// Clear the OTP from Redis after successful password reset
	if err := mail.ClearOTP(resetKey); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to clear password reset OTP for user %s: %w", user.ID, err))
	}

	logger.InfoLogger.Infof("Password reset successfully for user: %s (email: %s)", user.Username, user.Email)
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully!"})
}

// ChangePassword handles changing user's password when they are logged in.
func (uc *UserController) ChangePassword(c *gin.Context) {
	logger.InfoLogger.Info("ChangePassword controller called")

	var req struct {
		CurrentPassword string `json:"currentPassword" binding:"required"`
		NewPassword     string `json:"newPassword" binding:"required,min=8"`
		Username        string `json:"username" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid change password payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := models.GetUserByUsername(db.DB, req.Username)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("User not found for Username %s: %v", req.Username, err))
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Compare the provided current password with the hashed password in the DB
	valid, err := models.ComparePasswords(db.DB, req.CurrentPassword, user.Username) // Assuming ComparePasswords uses username to fetch user
	if err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("Error comparing passwords for user %s: %v", user.Username, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during password verification"})
		return
	}

	if !valid {
		logger.ErrorLogger.Info(fmt.Sprintf("Invalid credential for user %s", user.Username))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credential"})
		return
	}

	// Hash the new password
	hashedNewPassword, err := models.HashPassword(req.NewPassword)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to hash new password for user %s: %w", user.Username, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process new password"})
		return
	}

	// Update the password in the database
	_, err = db.DB.Exec(context.Background(), `UPDATE users SET password_hash = $1 WHERE id = $2`, hashedNewPassword, user.ID)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to update password in DB for user %s: %w", user.Username, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	logger.InfoLogger.Infof("Password changed successfully for user: %s", user.Username)
	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// RefreshToken handles refreshing access tokens
func (uc *UserController) RefreshToken(c *gin.Context) {
	logger.InfoLogger.Info("RefreshToken token function called")

	// time.Sleep(1 * time.Second)

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

	// Get user ID from the token in the context, as the request body is not reliable for auth
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

	if err := models.LogoutUser(db.DB, userID); err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("Failed to logout user %s: %v", userID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	logger.InfoLogger.Info(fmt.Sprintf("Successfully logged out user: %s", userID))
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

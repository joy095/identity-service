package user_controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/joy095/identity/config/db"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/shared_models"
	"github.com/joy095/identity/models/user_models"
	"github.com/joy095/identity/utils"
	"github.com/joy095/identity/utils/mail"
	"github.com/joy095/identity/utils/shared_utils"

	redisclient "github.com/joy095/identity/config/redis"

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

// UpdateProfile handles user profile updates
func (uc *UserController) UpdateProfile(c *gin.Context) {
	logger.InfoLogger.Info("UpdateProfile function called")

	userIDFromToken, exists := c.Get("sub")
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
		FirstName *string `json:"firstName"`
		LastName  *string `json:"lastName"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid update profile payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentUser, err := user_models.GetUserByID(db.DB, userID)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("User not found for ID %s: %v", userID, err))
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	updates := make(map[string]interface{})

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
	err = user_models.UpdateUserFields(db.DB, userID, updates)
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
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid payload for UpdateEmailWithPassword: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userIDFromToken, exists := c.Get("sub")
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

	currentUser, err := user_models.GetUserByID(db.DB, userID)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("User not found for ID %s: %v", userID, err))
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 1. Verify current password
	// Assume user_models.ComparePasswords can take user.ID or user.email and the plain password
	// Assuming `user_models.ComparePasswords` takes the plain password and the stored hashed password,
	// or it fetches the user by email/ID and compares. Let's assume it fetches by email
	// as is common in your models, but it should ideally use user.ID here for directness.
	// If `user_models.ComparePasswords` requires a email, you'd use `currentUser.email`.
	validPassword, err := user_models.ComparePasswords(db.DB, req.Password, currentUser.Email)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("Error comparing passwords for user %s: %v", currentUser.Email, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if !validPassword {
		logger.InfoLogger.Info(fmt.Sprintf("Incorrect current password provided by user %s during email update attempt"))
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
		logger.ErrorLogger.Errorf("failed to generate OTP for email change for user %s: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP for email verification"})
		return
	}

	// Store the OTP and the new email with the user's ID
	if err := shared_utils.StoreOTP(context.Background(), shared_utils.EMAIL_CHANGE_NEW_OTP_PREFIX+req.NewEmail, otp); err != nil {
		logger.ErrorLogger.Errorf("failed to store email change OTP for user %s: %v", userID, err)
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
		Email string `json:"email" binding:"required,email"`
		OTP   string `json:"otp" binding:"required,len=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid request for VerifyEmailChangeOTP: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()}) // Added err.Error() for better debugging
		return
	}

	req.Email = strings.ToLower(strings.Trim(req.Email, " "))

	ctx := context.Background()
	user, err := user_models.GetUserByEmail(ctx, db.DB, req.Email) // Assume GetUserByEmail exists
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.InfoLogger.Infof("Attempted password reset for non-existent Username: %s")
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
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP for user %s: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	if err := shared_utils.StoreOTP(context.Background(), shared_utils.EMAIL_VERIFICATION_OTP_PREFIX+req.Email, otp); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to store registration OTP for username %s: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP for verification"})
		return
	}

	go func() {
		sendErr := mail.SendEmailChangeNewOTP(req.Email, user.FirstName, user.LastName, otp)
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send OTP email to %s for user %s: %w", req.Email, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("OTP email sent successfully to: %s for user %s", req.Email))
		}
	}()

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

// Check user status
func (uc *UserController) IsUserRegistered(c *gin.Context) {
	logger.InfoLogger.Info("IsUserRegistered called")

	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("Error binding JSON for IsUserRegistered: %w", err))
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload. Please provide a valid email address."})
		return
	}

	user, err := user_models.CheckUserStatus(context.Background(), db.DB, req.Email)

	if err != nil {
		// Handle unexpected database errors only
		logger.ErrorLogger.Error(fmt.Errorf("Database error checking user status for %s: %w", req.Email, err))
		c.JSON(http.StatusInternalServerError, gin.H{"message": "An internal server error occurred. Please try again later."})
		return
	}

	// Handle user status
	switch user.Status {
	case "Not found":
		logger.InfoLogger.Infof("IsUserRegistered: No user found with email %s. Email is available for new user creation.", req.Email)
		c.JSON(http.StatusOK, gin.H{"status": "Not found"}) // Use 200 and "status": "Not found"
	case "Verified":
		logger.InfoLogger.Infof("IsUserRegistered: User with email %s is verified.", req.Email)
		c.JSON(http.StatusOK, gin.H{"status": "Verified"})
	case "Pending":
		logger.InfoLogger.Infof("IsUserRegistered: User with email %s is pending verification.", req.Email)
		c.JSON(http.StatusOK, gin.H{"status": "Pending"})
	case "VerificationExpired":
		logger.InfoLogger.Infof("IsUserRegistered: User with email %s exists but verification expired.", req.Email)
		c.JSON(http.StatusOK, gin.H{"status": "Not Verified"})
	default:
		logger.ErrorLogger.Errorf("IsUserRegistered: Unexpected user status %s for email %s.", user.Status, req.Email)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "An unexpected error occurred."})
	}
}

// Register handles user registration
func (uc *UserController) Register(c *gin.Context) {
	logger.InfoLogger.Info("Register controller called")

	var req struct {
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

	user, err := user_models.CreateUser(db.DB, req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to create user in database for '%s': %w", req.Email, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP for user %s: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	// For registration, it's generally good practice to store the OTP against the new user's ID
	// or the email, and then verify that in a separate endpoint.
	// Assuming `shared_utils.StoreOTP` is suitable for this purpose.
	if err := shared_utils.StoreOTP(context.Background(), shared_utils.EMAIL_VERIFICATION_OTP_PREFIX+user.Email, otp); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to store registration OTP for user %s: %w", user.ID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP for verification"})
		return
	}

	go func() {
		sendErr := mail.SendVerificationOTP(req.Email, req.FirstName, req.LastName, otp)
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send OTP email to %s for user %s: %w", req.Email, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("OTP email sent successfully to: %s for user %s", req.Email))
		}
	}()

	logger.InfoLogger.Info(fmt.Sprintf("User registered successfully with ID: %v, %s", user.ID, user))

	c.JSON(http.StatusCreated, gin.H{
		"id":        user.ID,
		"email":     user.Email,
		"firstName": user.FirstName,
		"lastName":  user.LastName,
	})
}

// Login handles user login
func (uc *UserController) Login(c *gin.Context) {
	logger.InfoLogger.Info("Login controller called")

	var req struct {
		Password string `json:"password" binding:"required"`
		Email    string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid login payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, accessToken, refreshToken, err := user_models.LoginUser(db.DB, req.Email, req.Password)
	if err != nil {
		logger.ErrorLogger.Error("Invalid credentials: " + err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Set access token cookie
	if err := shared_models.SetJWTCookie(c, "access_token", accessToken, shared_models.ACCESS_TOKEN_EXPIRY, "/"); err != nil {
		logger.ErrorLogger.Errorf("Failed to set access token cookie: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set access token cookie"})
		return
	}

	// Set refresh token cookie
	if err := shared_models.SetJWTCookie(c, "refresh_token", refreshToken, shared_models.REFRESH_TOKEN_EXPIRY, "/"); err != nil {
		logger.ErrorLogger.Errorf("Failed to set refresh token cookie: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set refresh token cookie"})
		return
	}

	// Respond with user details (excluding tokens)
	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"email":     user.Email,
			"firstName": user.FirstName,
			"lastName":  user.LastName,
		},
	})

	logger.InfoLogger.Infof("User %s logged in successfully", user.ID)
}

// ForgotPassword handles sending OTP for password reset
func (uc *UserController) ForgotPassword(c *gin.Context) {
	logger.InfoLogger.Info("ForgotPassword controller called")

	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid forgot password payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()
	// We only need the email to send the OTP. We'll verify username/email later.
	// For security, avoid revealing if the user exists based on email alone.
	// Just proceed with sending the OTP if the email exists in the system.
	user, err := user_models.GetUserByEmail(ctx, db.DB, req.Email) // Assume GetUserByEmail exists
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.InfoLogger.Infof("Attempted password reset for non-existent Username: %s", req.Email)
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
	resetKey := shared_utils.FORGOT_PASSWORD_OTP_PREFIX + user.Email
	err = shared_utils.StoreOTP(context.Background(), resetKey, otp)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to store OTP for password reset for user %s: %w", user.ID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate password reset"})
		return
	}

	// Send the OTP email asynchronously
	go func() {
		sendErr := mail.SendForgotPasswordOTP(user.Email, user.FirstName, user.LastName, otp) // Pass user details if email template uses them
		if sendErr != nil {
			logger.ErrorLogger.Error(fmt.Errorf("failed to send forgot password OTP to %s for user %s: %w", user.Email, sendErr))
		} else {
			logger.InfoLogger.Info(fmt.Sprintf("Forgot password OTP sent successfully to: %s for user %s", user.Email))
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
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid reset password payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()
	user, err := user_models.GetUserByEmail(ctx, db.DB, req.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.InfoLogger.Infof("Password reset attempt for non-existent email: %s", req.Email)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email or OTP."})
			return
		}
		logger.ErrorLogger.Error(fmt.Errorf("database error fetching user by email for password reset: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Retrieve the stored OTP using the same key format as in ForgotPassword
	resetKey := shared_utils.FORGOT_PASSWORD_OTP_PREFIX + user.Email
	storedOTP, err := shared_utils.RetrieveOTP(context.Background(), resetKey)
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
	hashedPassword, err := user_models.HashPassword(req.NewPassword)
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
	if err := shared_utils.ClearOTP(context.Background(), resetKey); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to clear password reset OTP for user %s: %w", user.ID, err))
	}

	logger.InfoLogger.Infof("Password reset successfully for user: %s (email: %s)", user.Email)
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully!"})
}

// ChangePassword handles changing user's password when they are logged in.
func (uc *UserController) ChangePassword(c *gin.Context) {
	logger.InfoLogger.Info("ChangePassword controller called")

	var req struct {
		CurrentPassword string `json:"currentPassword" binding:"required"`
		NewPassword     string `json:"newPassword" binding:"required,min=8"`
		Email           string `json:"email" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid change password payload: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()
	user, err := user_models.GetUserByEmail(ctx, db.DB, req.Email)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("User not found for Email %s: %v", req.Email, err))
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Compare the provided current password with the hashed password in the DB
	// Assuming ComparePasswords correctly fetches/uses the hashed password for the user.
	// Ideally, ComparePasswords would take the 'user' object directly to avoid re-fetching.
	valid, err := user_models.ComparePasswords(db.DB, req.CurrentPassword, user.Email)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("Error comparing passwords for user %s: %v", user.Email, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during password verification"})
		return
	}

	if !valid {
		logger.ErrorLogger.Info(fmt.Sprintf("Invalid credential for user %s", user.Email))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credential"})
		return
	}

	// Hash the new password
	hashedNewPassword, err := user_models.HashPassword(req.NewPassword)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to hash new password for user %s: %w", user.Email, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process new password"})
		return
	}

	// --- Start Transaction for Atomicity ---
	tx, err := db.DB.Begin(context.Background())
	if err != nil {
		logger.ErrorLogger.Error("Failed to begin transaction for password change", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	defer tx.Rollback(context.Background()) // Rollback on error

	// 1. Update the password in the database
	_, err = tx.Exec(context.Background(), `UPDATE users SET password_hash = $1 WHERE id = $2`, hashedNewPassword, user.ID)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to update password in DB for user %s: %w", user.Email, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// 2. Increment the token_version
	_, err = tx.Exec(context.Background(), `UPDATE users SET token_version = token_version + 1 WHERE id = $1`, user.ID)
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to increment token version for user %s: %w", user.Email, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke old tokens"})
		return
	}

	// 3. Optionally, clear the refresh_token field in the database
	// This immediately invalidates the stored refresh token as well.
	key := shared_utils.USER_REFRESH_TOKEN_PREFIX + user.ID.String()
	err = redisclient.GetRedisClient(ctx).Del(ctx, key).Err()
	if err != nil {
		logger.WarnLogger.Warn(fmt.Errorf("failed to clear refresh token for user %s: %w", user.Email, err))
		// This is a warning because even if clearing fails, incrementing token_version still revokes.
		// But it's good practice to clear the old token too.
	}

	// --- Commit Transaction ---
	if err := tx.Commit(context.Background()); err != nil {
		logger.ErrorLogger.Error("Failed to commit password change transaction", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	logger.InfoLogger.Infof("Password changed successfully for user: %s. All old tokens revoked.", user.Email)
	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully. Please log in again."})
}

// RefreshToken handles refreshing access tokens
func (uc *UserController) RefreshToken(c *gin.Context) {
	logger.InfoLogger.Info("RefreshToken function called")

	// Extract refresh token from secure cookie
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil || refreshToken == "" {
		logger.ErrorLogger.Error("No refresh token provided in cookie")
		c.JSON(http.StatusBadRequest, gin.H{"error": "No refresh token provided"})
		return
	}

	// Parse token and fetch token_version from DB inside ParseToken callback
	claims, err := shared_models.ParseToken(refreshToken, func(userID uuid.UUID) (int, error) {
		var tokenVersion int
		err := db.DB.QueryRow(context.Background(),
			`SELECT token_version FROM users WHERE id = $1`, userID).Scan(&tokenVersion)
		return tokenVersion, err
	})
	if err != nil {
		logger.ErrorLogger.Error("Invalid or expired refresh token", "error", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		return
	}

	if claims.Type != "refresh" {
		logger.ErrorLogger.Error("Token type is not refresh")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token type"})
		return
	}

	userID := claims.UserID
	claimedVersion := claims.TokenVersion

	// Get user from DB and compare token version
	var user user_models.User
	err = db.DB.QueryRow(context.Background(),
		`SELECT id, email, token_version FROM users WHERE id = $1`, userID).
		Scan(&user.ID, &user.Email, &user.TokenVersion)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			logger.ErrorLogger.Error("User not found", "sub", userID)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user"})
			return
		}
		logger.ErrorLogger.Error("Database error while fetching user", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Compare token version
	if claimedVersion != user.TokenVersion {
		logger.ErrorLogger.Error("Token version mismatch",
			"stored_version", user.TokenVersion,
			"token_version", claimedVersion)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token revoked, please log in again"})
		return
	}

	// Check Redis if the refresh token is valid
	redisKey := shared_utils.USER_REFRESH_TOKEN_PREFIX + userID.String()
	storedToken, err := redisclient.GetRedisClient(c).Get(context.Background(), redisKey).Result()
	if err != nil || storedToken != refreshToken {
		logger.ErrorLogger.Error("Refresh token mismatch or not found in Redis", "sub", userID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// Generate new access & refresh tokens
	newAccessToken, err := shared_models.GenerateAccessToken(userID, user.TokenVersion, shared_models.ACCESS_TOKEN_EXPIRY)
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate access token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	newRefreshToken, err := shared_models.GenerateRefreshToken(userID, user.TokenVersion, shared_models.REFRESH_TOKEN_EXPIRY)
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate refresh token", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	// Update Redis with new refresh token (replaces old)
	err = redisclient.GetRedisClient(c).Set(
		context.Background(),
		redisKey,
		newRefreshToken,
		shared_models.REFRESH_TOKEN_EXPIRY,
	).Err()
	if err != nil {
		logger.ErrorLogger.Error("Failed to store new refresh token in Redis", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
		return
	}

	// Set new tokens in secure HttpOnly cookies
	if err := shared_models.SetJWTCookie(c, "access_token", newAccessToken, shared_models.ACCESS_TOKEN_EXPIRY, "/"); err != nil {
		logger.ErrorLogger.Errorf("Failed to set access token cookie: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set access token cookie"})
		return
	}
	if err := shared_models.SetJWTCookie(c, "refresh_token", newRefreshToken, shared_models.REFRESH_TOKEN_EXPIRY, "/"); err != nil {
		logger.ErrorLogger.Errorf("Failed to set refresh token cookie: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set refresh token cookie"})
		return
	}

	logger.InfoLogger.Infof("Tokens refreshed successfully for user %s", userID)

	c.JSON(http.StatusOK, gin.H{
		"message": "Tokens refreshed successfully",
	})
}

// Logout handles user logout
func (uc *UserController) Logout(c *gin.Context) {
	logger.InfoLogger.Info("Logout controller called")

	// Get user ID from the token in the context
	userIDFromToken, exists := c.Get("sub")
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

	// Clear the access token cookie
	shared_models.RemoveJWTCookie(c, "access_token", "/")

	// Clear the refresh token cookie
	shared_models.RemoveJWTCookie(c, "refresh_token", "/")

	// Remove refresh token from Redis
	if err := user_models.LogoutUser(db.DB, userID); err != nil {
		logger.ErrorLogger.Error(fmt.Sprintf("Failed to logout user %s: %v", userID, err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	logger.InfoLogger.Info(fmt.Sprintf("Successfully logged out user: %s", userID))
	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

// GetUserByID retrieves a user by ID
func (uc *UserController) GetUserByID(c *gin.Context) {
	logger.InfoLogger.Info("GetUserByID function called")

	id := c.Param("id")

	userID, err := uuid.Parse(id)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid user ID format: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	user, err := user_models.GetUserByID(db.DB, userID)
	if err != nil {
		logger.ErrorLogger.Errorf("User not found: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
		},
	})

	logger.InfoLogger.Info("User retrieved successfully by ID")
}

// GetMyProfile returns the authenticated user's own profile
func (uc *UserController) GetMyProfile(c *gin.Context) {
	logger.InfoLogger.Info("GetMyProfile called")

	// Get user ID from JWT token (set by AuthMiddleware)
	userIDFromToken, exists := c.Get("sub")
	if !exists {
		logger.ErrorLogger.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userIDStr, ok := userIDFromToken.(uuid.UUID)
	if !ok {
		logger.ErrorLogger.Error("Invalid user ID type in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Get user from database
	user, err := user_models.GetUserByID(db.DB, userIDStr)
	if err != nil {
		logger.ErrorLogger.Errorf("User not found: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Return user's own profile (can include sensitive info)
	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"email":     user.Email,
			"firstName": user.FirstName,
			"lastName":  user.LastName,
		},
	})
}

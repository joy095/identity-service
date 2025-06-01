package customer_controller

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/joy095/identity/config/db"
	redisclient "github.com/joy095/identity/config/redis" // Assuming this is your Redis client package
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/customer_models" // Assuming your customer model operations
	"github.com/joy095/identity/models/shared_models"
	"github.com/joy095/identity/utils"              // For OTP generation/hashing
	"github.com/joy095/identity/utils/mail"         // For sending emails
	"github.com/joy095/identity/utils/shared_utils" // For constants like prefixes and exp times
	"github.com/redis/go-redis/v9"                  // Correct Redis go-redis package
)

const MAX_ACTIVE_DEVICES = 5 // Define the maximum number of active devices a user can have

// CustomerController holds methods for customer-related operations
type CustomerController struct{}

// NewCustomerController creates and returns a new instance of CustomerController
func NewCustomerController() *CustomerController {
	return &CustomerController{}
}

// CustomerRegister handles user registration (OTP-based, sends OTP to email)
func (uc *CustomerController) CustomerRegister(c *gin.Context) {
	logger.InfoLogger.Info("CustomerRegister controller called")

	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON for registration: %w", err))
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

	// Store OTP in Redis
	otpKey := shared_utils.CUSTOMER_OTP_PREFIX + req.Email
	// OTP valid for 5 minutes
	if err := redisclient.GetRedisClient().Set(c.Request.Context(), otpKey, utils.HashOTP(otp), 5*time.Minute).Err(); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to store OTP in Redis: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP"})
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

	logger.InfoLogger.Infof("User registered successfully with ID: %v", user.ID)
	c.JSON(http.StatusCreated, gin.H{"id": user.ID, "email": user.Email, "message": "OTP sent to your email for verification."})
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

	// Invert the logic: IsUsernameAvailable typically means *true* if available (not taken)
	// So, if it's NOT available, the user is already registered.
	isAvailable, err := customer_models.IsUsernameAvailable(db.DB, req.Email)
	if err != nil {
		logger.ErrorLogger.Error("Database error checking Email availability: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	if !isAvailable { // If not available, means it's taken
		logger.InfoLogger.Info(fmt.Sprintf("Email '%s' is not available (already registered)", req.Email))
		c.JSON(http.StatusOK, gin.H{"available": false, "message": "Email is already taken"})
	} else {
		logger.InfoLogger.Info(fmt.Sprintf("Email '%s' is available (not registered)", req.Email))
		c.JSON(http.StatusOK, gin.H{"available": true})
	}
}

// RequestCustomerLogin handles requesting an OTP for login
func (uc *CustomerController) RequestCustomerLogin(c *gin.Context) {
	logger.InfoLogger.Info("RequestCustomerLogin controller called")

	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON for OTP login request: %w", err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if customer exists before sending OTP to prevent email enumeration
	_, err := customer_models.GetCustomerByEmail(db.DB, req.Email)
	if err != nil {
		if err == pgx.ErrNoRows {
			logger.InfoLogger.Infof("Attempted OTP login request for non-existent email: %s", req.Email)
			// Return a generic message to prevent email enumeration
			c.JSON(http.StatusOK, gin.H{"message": "If the email exists, an OTP has been sent"})
			return
		}
		logger.ErrorLogger.Error(fmt.Errorf("database error when checking for existing user during OTP request: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process OTP request"})
		return
	}

	otp, err := utils.GenerateSecureOTP()
	if err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to generate OTP: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP"})
		return
	}

	// Store OTP in Redis
	otpKey := shared_utils.CUSTOMER_OTP_PREFIX + req.Email
	// OTP valid for 5 minutes
	if err := redisclient.GetRedisClient().Set(c.Request.Context(), otpKey, utils.HashOTP(otp), 5*time.Minute).Err(); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("failed to store OTP in Redis: %w", err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store OTP"})
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

// processCustomerEmailVerification handles both initial verification (registration) and subsequent logins
func (uc *CustomerController) processCustomerEmailVerification(c *gin.Context, email, otp, device string) {
	logger.InfoLogger.Info("processCustomerEmailVerification called")

	email = strings.ToLower(strings.TrimSpace(email))
	if device == "" {
		device = "unknown" // Default device if not provided
	}

	// --- OTP Verification ---
	storedHash, err := redisclient.GetRedisClient().Get(c.Request.Context(), shared_utils.CUSTOMER_OTP_PREFIX+email).Result()
	if err != nil {
		if err == redis.Nil { // Use redis.Nil for "redis: nil" error check
			logger.ErrorLogger.Info(fmt.Sprintf("Customer OTP expired or not found for %s", email))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP expired or not found"})
			return
		}
		logger.ErrorLogger.Errorf("Failed to retrieve customer OTP from Redis: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error during OTP verification"})
		return
	}

	if utils.HashOTP(otp) != storedHash {
		logger.ErrorLogger.Info(fmt.Sprintf("Incorrect OTP for customer %s", email))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect OTP"})
		return
	}

	// --- Customer Retrieval ---
	customer, err := customer_models.GetCustomerByEmail(db.DB, email)
	if err != nil {
		logger.ErrorLogger.Errorf("Customer not found for email %s: %v", email, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Customer not found"})
		return
	}

	// --- Multi-Device Refresh Token Management ---
	refreshTokenKey := fmt.Sprintf("customer:%s:refresh_tokens", customer.ID.String())
	ctx := c.Request.Context()

	// Get current number of active sessions
	currentSessions, err := redisclient.GetRedisClient().ZCard(ctx, refreshTokenKey).Result()
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get session count for customer %s: %v", customer.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to manage sessions"})
		return
	}

	if currentSessions >= MAX_ACTIVE_DEVICES {
		// Remove the oldest session if limit is reached
		oldestMembers, err := redisclient.GetRedisClient().ZRange(ctx, refreshTokenKey, 0, 0).Result()
		if err != nil || len(oldestMembers) == 0 {
			logger.ErrorLogger.Errorf("Failed to retrieve oldest refresh token for customer %s: %v", customer.ID, err)
		} else {
			if _, err := redisclient.GetRedisClient().ZRem(ctx, refreshTokenKey, oldestMembers[0]).Result(); err != nil {
				logger.ErrorLogger.Errorf("Failed to remove oldest refresh token %s for customer %s: %v", oldestMembers[0], customer.ID, err)
			} else {
				logger.InfoLogger.Infof("Removed oldest refresh token %s for customer %s due to device limit", oldestMembers[0], customer.ID)
			}
		}
	}

	// Generate new access token
	accessToken, err := shared_models.GenerateAccessToken(customer.ID, 60*time.Minute)
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate access token for customer")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// Generate new refresh token (this must be the pure JWT)
	refreshToken, err := shared_models.GenerateRefreshToken(customer.ID, shared_utils.REFRESH_TOKEN_EXP_HOURS*time.Hour)
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate refresh token for customer")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	// Store refresh token in Redis Sorted Set as "pure_jwt_token:device_id"
	now := float64(time.Now().UnixNano())
	memberToStore := fmt.Sprintf("%s:%s", refreshToken, device) // CORRECTED: Use device here
	if err := redisclient.GetRedisClient().ZAdd(ctx, refreshTokenKey, redis.Z{
		Score:  now,
		Member: memberToStore, // Store the composite string here
	}).Err(); err != nil {
		logger.ErrorLogger.Errorf("Failed to store refresh token for customer %s in Redis: %v", customer.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
		return
	}

	// Set expiration for the ZSET key itself
	if err := redisclient.GetRedisClient().Expire(ctx, refreshTokenKey, shared_utils.REFRESH_TOKEN_EXP_HOURS*time.Hour).Err(); err != nil {
		logger.ErrorLogger.Warnf("Failed to set expiry for refresh token key %s: %v", refreshTokenKey, err)
	}

	logger.InfoLogger.Debugf("Refresh token stored in Redis for customer %s with key %s, member %s", customer.ID, refreshTokenKey, memberToStore)

	// --- Clean up OTP from Redis ---
	if err := redisclient.GetRedisClient().Del(ctx, shared_utils.CUSTOMER_OTP_PREFIX+email).Err(); err != nil {
		logger.ErrorLogger.Warnf("Failed to delete customer OTP from Redis for %s: %v", email, err)
	}

	// --- Update email verification status if not already true ---
	if !customer.IsVerifiedEmail {
		_, err = db.DB.Exec(ctx,
			"UPDATE customers SET is_verified_email = true WHERE id = $1 AND is_verified_email = false",
			customer.ID)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to update customer email verification status for %s: %v", customer.ID, err)
		}
	}

	logger.InfoLogger.Infof("Customer email verified and tokens generated successfully for customer %s", customer.ID)

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshToken, // Send the pure JWT refresh token back to the client
		"message":      "Customer email verified and logged in successfully!",
	})
}

// VerifyCustomerEmail (direct call)
func (uc *CustomerController) VerifyCustomerEmail(c *gin.Context) {
	logger.InfoLogger.Info("VerifyCustomerEmail (direct call) called")

	var request struct {
		Email  string `json:"email" binding:"required,email"`
		OTP    string `json:"otp" binding:"required,len=6"`
		Device string `json:"device"` // Added device field
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		logger.ErrorLogger.Error("Invalid request for VerifyCustomerEmail: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	uc.processCustomerEmailVerification(c, request.Email, request.OTP, request.Device)
}

// CustomerLogin handles user login using Email and OTP
func (uc *CustomerController) CustomerLogin(c *gin.Context) {
	logger.InfoLogger.Info("CustomerLogin (OTP based) controller called")

	var req struct {
		Email  string `json:"email" binding:"required,email"`
		OTP    string `json:"otp" binding:"required,len=6"`
		Device string `json:"device"` // Optional, but recommended for multi-device support
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error(fmt.Errorf("error binding JSON for OTP login: %w", err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Pass the already bound data to the unified verification function
	uc.processCustomerEmailVerification(c, req.Email, req.OTP, req.Device)
}

// CustomerLogout handles user logout by invalidating the refresh token
// Expects "refreshToken" in the request body (pure JWT)
func (uc *CustomerController) CustomerLogout(c *gin.Context) {
	logger.InfoLogger.Info("CustomerLogout controller called")

	var req struct {
		RefreshToken string `json:"refreshToken" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Error("Invalid request for CustomerLogout: " + err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Parse the refresh token to get the customer ID
	claims, err := shared_models.ParseToken(req.RefreshToken)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse refresh token during logout: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	customerID := claims.UserID
	refreshTokenKey := fmt.Sprintf("customer:%s:refresh_tokens", customerID.String())
	ctx := c.Request.Context()

	// To reliably remove, we iterate over the ZSET to find the specific member
	// that starts with the given pure refresh token.
	membersToRemove := []interface{}{}
	iter := redisclient.GetRedisClient().ZScan(ctx, refreshTokenKey, 0, req.RefreshToken+"*", 0).Iterator()
	for iter.Next(ctx) {
		memberStr := iter.Val()
		// Ensure it's an exact match for the JWT part
		parts := strings.SplitN(memberStr, ":", 2)
		if parts[0] == req.RefreshToken {
			membersToRemove = append(membersToRemove, memberStr)
		}
	}
	if err := iter.Err(); err != nil {
		logger.ErrorLogger.Errorf("Failed to scan for refresh token to remove for customer %s: %v", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	if len(membersToRemove) == 0 {
		logger.InfoLogger.Infof("Refresh token %s not found for customer %s, already logged out or invalid.", req.RefreshToken, customerID)
		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully (token not found or already invalid)"})
		return
	}

	if _, err := redisclient.GetRedisClient().ZRem(ctx, refreshTokenKey, membersToRemove...).Result(); err != nil {
		logger.ErrorLogger.Errorf("Failed to remove refresh token %s for customer %s from Redis: %v", req.RefreshToken, customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	logger.InfoLogger.Infof("Customer %s logged out successfully. Refresh token %s invalidated.", customerID, req.RefreshToken)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// CustomerRefreshToken handles refreshing access tokens using a refresh token
// Expects "Refresh-Token: Bearer <JWT_REFRESH_TOKEN>" in the header
func (uc *CustomerController) CustomerRefreshToken(c *gin.Context) {
	logger.InfoLogger.Info("CustomerRefreshToken controller called")

	// Get the Refresh-Token header
	refreshHeader := c.GetHeader("Refresh-Token")
	if refreshHeader == "" {
		logger.ErrorLogger.Error("Refresh-Token header missing")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh-Token header missing"})
		return
	}

	// Check if it starts with "Bearer " and extract the token
	if !strings.HasPrefix(refreshHeader, "Bearer ") {
		logger.ErrorLogger.Error("Invalid Refresh-Token header format")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Refresh-Token header format (expected 'Bearer ' prefix)"})
		return
	}
	// Extract the pure JWT refresh token (this should be the string from the client)
	refreshTokenFromHeader := strings.TrimPrefix(refreshHeader, "Bearer ")

	if refreshTokenFromHeader == "" {
		logger.ErrorLogger.Error("Refresh token is empty after stripping Bearer prefix")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token is empty"})
		return
	}

	// DEBUG: Verify the token received from the client header
	logger.DebugLogger.Debugf("DEBUG_CONTROLLER: Refresh Token from Header (should be pure JWT): %s", refreshTokenFromHeader)

	ctx := c.Request.Context()

	// Parse and validate the incoming refresh token (which should be just the pure JWT)
	claims, err := shared_models.ParseToken(refreshTokenFromHeader) // Use the token from the header
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to parse or validate refresh token: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		return
	}

	customerID := claims.UserID
	refreshTokenKey := fmt.Sprintf("customer:%s:refresh_tokens", customerID.String())

	found := false
	var actualMemberInRedis string // This will store the full "token:device" string from Redis

	// Use ZScan to find the member that starts with the *pure* refresh token.
	// This ensures we find the composite key in Redis (e.g., "jwt_token:device_name").
	// We search for "pure_jwt_token*" to match any device suffix.
	iter := redisclient.GetRedisClient().ZScan(ctx, refreshTokenKey, 0, refreshTokenFromHeader+"*", 0).Iterator()
	for iter.Next(ctx) {
		memberStr := iter.Val()
		// Double check to ensure it's an exact match for the JWT part
		parts := strings.SplitN(memberStr, ":", 2)
		if parts[0] == refreshTokenFromHeader { // Found a match for the pure JWT
			found = true
			actualMemberInRedis = memberStr // Store the complete "token:device" from Redis
			break
		}
	}
	if err := iter.Err(); err != nil {
		logger.ErrorLogger.Errorf("Failed to scan for refresh token during refresh for customer %s: %v", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh token"})
		return
	}

	if !found {
		logger.ErrorLogger.Infof("Refresh token %s not found in Redis for customer %s or already used", refreshTokenFromHeader, customerID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or revoked refresh token"})
		return
	}

	// Invalidate the old refresh token (single-use refresh token strategy)
	// Remove the *full composite member* from Redis using actualMemberInRedis.
	if _, err := redisclient.GetRedisClient().ZRem(ctx, refreshTokenKey, actualMemberInRedis).Result(); err != nil {
		logger.ErrorLogger.Warnf("Failed to remove used refresh token %s for customer %s: %v", actualMemberInRedis, customerID, err)
		// Don't fail the request, but log the warning as it's a cleanup task.
	}

	// Generate new access token
	newAccessToken, err := shared_models.GenerateAccessToken(customerID, 60*time.Minute)
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate new access token during refresh")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new access token"})
		return
	}

	// Generate new refresh token (this is a pure JWT)
	newRefreshToken, err := shared_models.GenerateRefreshToken(customerID, shared_utils.REFRESH_TOKEN_EXP_HOURS*time.Hour)
	if err != nil {
		logger.ErrorLogger.Error("Failed to generate new refresh token during refresh")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new refresh token"})
		return
	}

	// Extract device from the *actualMemberInRedis* string.
	// This ensures the new token is associated with the same device as the old one.
	device := "unknown_device"                           // Default fallback if no device found
	parts := strings.SplitN(actualMemberInRedis, ":", 2) // Split only on the first colon
	if len(parts) == 2 {
		device = parts[1] // The second part should be the device name
	} else {
		logger.WarnLogger.Warnf("Could not extract device from Redis member: %s. Defaulting to '%s'. This indicates a previous storage issue.", actualMemberInRedis, device)
	}

	// Add new refresh token to Redis Sorted Set as a composite key: "pure_jwt_token:device_id"
	var now = float64(time.Now().UnixNano())
	newMember := fmt.Sprintf("%s:%s", newRefreshToken, device) // CORRECTED: Use the 'device' variable here

	// DEBUG: Log the final Redis member string before ZAdd
	logger.DebugLogger.Debugf("DEBUG_CONTROLLER: Storing new Redis member: %s for customer %s", newMember, customerID)

	if err := redisclient.GetRedisClient().ZAdd(ctx, refreshTokenKey, redis.Z{
		Score:  now,
		Member: newMember, // Store the composite string here
	}).Err(); err != nil {
		logger.ErrorLogger.Errorf("Failed to store new refresh token for customer %s in Redis: %v", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store new refresh token"})
		return
	}

	// Update expiry for the ZSET key (ensures the entire set of refresh tokens expires if idle)
	if err := redisclient.GetRedisClient().Expire(ctx, refreshTokenKey, shared_utils.REFRESH_TOKEN_EXP_HOURS*time.Hour).Err(); err != nil {
		logger.ErrorLogger.Warnf("Failed to update expiry for refresh token key %s after refresh: %v", refreshTokenKey, err)
	}

	logger.InfoLogger.Infof("Access token refreshed successfully for customer %s. New refresh token issued.", customerID)
	c.JSON(http.StatusOK, gin.H{
		"accessToken":  newAccessToken,
		"refreshToken": newRefreshToken, // Send the new pure JWT refresh token back to the client
		"message":      "Tokens refreshed successfully!",
	})
}

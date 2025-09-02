package business_payment_controller

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/models/payment_models"
	"github.com/joy095/identity/models/service_models"
	"github.com/joy095/identity/models/user_models"
	"github.com/joy095/identity/utils"
)

// Refund status constants
const (
	StatusRefundPending  = "pending"
	StatusRefundSuccess  = "success"
	StatusRefundFailed   = "failed"
	StatusRefundReversed = "reversed"
)

// Order status constants
const (
	OrderStatusPending  = "pending"
	OrderStatusPaid     = "paid"
	OrderStatusRefunded = "refunded"
)

// PaymentController handles all payment operations
type PaymentController struct {
	DB            *pgxpool.Pool
	ClientID      string
	ClientSecret  string
	APIVersion    string
	BaseURL       string
	WebhookSecret string
	HttpClient    *http.Client // Shared HTTP client for performance
}

// NewPaymentController creates a new payment controller
func NewPaymentController(db *pgxpool.Pool) (*PaymentController, error) {
	clientID := os.Getenv("CASHFREE_CLIENT_ID")
	clientSecret := os.Getenv("CASHFREE_CLIENT_SECRET")
	apiVersion := os.Getenv("CASHFREE_API_VERSION")
	webhookSecret := os.Getenv("CASHFREE_WEBHOOK_SECRET")

	if clientID == "" || clientSecret == "" || apiVersion == "" || webhookSecret == "" {
		return nil, fmt.Errorf("required Cashfree environment variables not set")
	}

	baseURL := os.Getenv("CASHFREE_BASE_URL")
	if baseURL == "" {
		baseURL = "https://sandbox.cashfree.com/pg" // Default to sandbox
	}

	// Log webhook secret length for debugging (never log the actual secret!)
	logger.InfoLogger.Infof("Webhook secret configured with length: %d", len(webhookSecret))

	return &PaymentController{
		DB:            db,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		APIVersion:    apiVersion,
		BaseURL:       baseURL,
		WebhookSecret: webhookSecret,
		HttpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}, nil
}

// HTTP client helper
func (pc *PaymentController) makeRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, pc.BaseURL+path, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("x-client-id", pc.ClientID)
	req.Header.Set("x-client-secret", pc.ClientSecret)
	req.Header.Set("x-api-version", pc.APIVersion)

	return pc.HttpClient.Do(req)
}

// PaymentWebhook is the single entry point for all Cashfree webhooks.
func (pc *PaymentController) PaymentWebhook(c *gin.Context) {
	// Read the body once
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to read webhook body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	// Debug logging (remove in production)
	logger.InfoLogger.Infof("=== WEBHOOK DEBUG START ===")
	logger.InfoLogger.Infof("Headers - Timestamp: %s", c.GetHeader("x-webhook-timestamp"))
	logger.InfoLogger.Infof("Headers - Signature present: %v", c.GetHeader("x-webhook-signature") != "")
	logger.InfoLogger.Infof("Body length: %d", len(bodyBytes))
	logger.InfoLogger.Infof("Webhook secret configured: %v", pc.WebhookSecret != "")

	// Log first 100 chars of body for debugging
	if len(bodyBytes) > 100 {
		logger.InfoLogger.Infof("Body preview: %s...", string(bodyBytes[:100]))
	}

	// 1. Verify webhook signature FIRST (CRITICAL SECURITY STEP)
	if !pc.verifyWebhookSignature(c, bodyBytes) {
		logger.ErrorLogger.Errorf("Webhook signature verification failed")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
		return
	}

	logger.InfoLogger.Infof("✅ Webhook signature verified successfully")

	// 2. Parse generic event
	var event WebhookEvent
	if err := json.Unmarshal(bodyBytes, &event); err != nil {
		logger.ErrorLogger.Errorf("Invalid webhook payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	logger.InfoLogger.Infof("Webhook event type: %s", event.Type)

	ctx := c.Request.Context()

	// 3. Log event to database (with better error handling)
	var eventID int64
	err = pc.DB.QueryRow(ctx,
		`INSERT INTO webhook_events (event_type, raw_payload, processed, created_at) 
		 VALUES ($1, $2, $3, NOW()) RETURNING id`,
		event.Type, string(bodyBytes), false).Scan(&eventID)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to log webhook event to database: %v", err)
		// Don't return here - continue processing the webhook
	} else {
		logger.InfoLogger.Infof("Webhook event logged with ID: %d", eventID)

		// Mark as processed after handling
		defer func() {
			_, updateErr := pc.DB.Exec(ctx,
				`UPDATE webhook_events SET processed = true, updated_at = NOW() WHERE id = $1`, eventID)
			if updateErr != nil {
				logger.ErrorLogger.Errorf("Failed to mark webhook event %d as processed: %v", eventID, updateErr)
			}
		}()
	}

	// 4. Route event
	switch event.Type {
	case "PAYMENT_SUCCESS_WEBHOOK", "ORDER_PAID", "PAYMENT_CHARGES_WEBHOOK":
		logger.InfoLogger.Infof("Processing payment success event")
		pc.handlePaymentSuccess(ctx, event.Data)
	case "REFUND_SUCCESS_WEBHOOK":
		logger.InfoLogger.Infof("Processing refund success event")
		pc.handleRefundSuccess(ctx, event.Data)
	case "REFUND_FAILURE_WEBHOOK", "REFUND_REVERSED_WEBHOOK":
		logger.InfoLogger.Infof("Processing refund failure/reversal event")
		pc.handleRefundFailure(ctx, event.Data, event.Type)
	default:
		logger.InfoLogger.Infof("Unhandled webhook event type received: %s", event.Type)
	}

	c.JSON(http.StatusOK, gin.H{"status": "processed"})
}

// verifyWebhookSignature validates the incoming webhook signature from Cashfree.
func (pc *PaymentController) verifyWebhookSignature(c *gin.Context, bodyBytes []byte) bool {
	timestamp := c.GetHeader("x-webhook-timestamp")
	signature := c.GetHeader("x-webhook-signature")

	if timestamp == "" || signature == "" {
		logger.ErrorLogger.Errorf("Missing webhook headers - timestamp: %v, signature: %v", timestamp != "", signature != "")
		return false
	}

	// Validate timestamp format
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid timestamp format: %s, error: %v", timestamp, err)
		return false
	}

	// Check timestamp age (allow 5 minute window)
	timestampTime := time.UnixMilli(ts)
	timeDiff := time.Since(timestampTime)

	logger.InfoLogger.Infof("Timestamp validation - TS: %d, Time: %v, Diff: %v", ts, timestampTime, timeDiff)

	if timeDiff > 5*time.Minute || timeDiff < -1*time.Minute {
		logger.ErrorLogger.Errorf("Timestamp outside valid window: %v", timeDiff)
		return false
	}

	// Create the message to sign (timestamp + body)
	message := timestamp + string(bodyBytes)

	// Generate HMAC-SHA256 signature
	mac := hmac.New(sha256.New, []byte(pc.WebhookSecret))
	mac.Write([]byte(message))
	expectedSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Debug logging (remove in production)
	logger.InfoLogger.Infof("Signature debug - Message length: %d", len(message))
	logger.InfoLogger.Infof("Expected signature length: %d, Received signature length: %d",
		len(expectedSignature), len(signature))

	// Use constant-time comparison
	isValid := hmac.Equal([]byte(expectedSignature), []byte(signature))

	if !isValid {
		logger.ErrorLogger.Errorf("Signature mismatch - check webhook secret configuration")
		// In development, you might want to log partial signatures for debugging
		if len(expectedSignature) > 10 && len(signature) > 10 {
			logger.ErrorLogger.Errorf("Expected signature prefix: %s...", expectedSignature[:10])
			logger.ErrorLogger.Errorf("Received signature prefix: %s...", signature[:10])
		}
	}

	return isValid
}

// --- Webhook Handler Implementations ---

func (pc *PaymentController) handlePaymentSuccess(ctx context.Context, data json.RawMessage) {
	var webhookData PaymentWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse payment success data: %v", err)
		return
	}

	orderID := webhookData.Order.OrderID
	payment := webhookData.Payment

	logger.InfoLogger.Infof("Processing payment success for order: %s, payment_id: %d", orderID, payment.CfPaymentID)

	tx, err := pc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] PaymentSuccess for %s: %v", orderID, err)
		return
	}
	defer tx.Rollback(ctx)

	// Update order with payment details
	result, err := tx.Exec(ctx,
		`UPDATE orders 
		 SET cf_payment_id = $1, payment_method = $2, bank_reference = $3, status = $4, updated_at = NOW()
		 WHERE order_id = $5`,
		payment.CfPaymentID, payment.PaymentMethod, payment.BankReference, OrderStatusPaid, orderID)

	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update order for success failed for %s: %v", orderID, err)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		logger.ErrorLogger.Errorf("No order found with order_id: %s", orderID)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("[TX_COMMIT_FAIL] PaymentSuccess for %s: %v", orderID, err)
		return
	}

	logger.InfoLogger.Infof("✅ Payment success processed for order: %s (rows updated: %d)", orderID, rowsAffected)
}

type RefundWebhookData struct {
	Order  OrderData  `json:"order"`
	Refund RefundData `json:"refund"`
}

type RefundData struct {
	CfRefundID      string                   `json:"cf_refund_id"`
	RefundID        string                   `json:"refund_id"`
	RefundStatus    string                   `json:"refund_status"`
	RefundAmount    float64                  `json:"refund_amount"`
	RefundNote      string                   `json:"refund_note"`
	ProcessedAt     string                   `json:"processed_at"`
	RefundReversals []map[string]interface{} `json:"refund_reversals"`
}

func (pc *PaymentController) handleRefundSuccess(ctx context.Context, data json.RawMessage) {
	var webhookData RefundWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse refund success data: %v", err)
		return
	}

	refund := webhookData.Refund

	logger.InfoLogger.Infof("Processing refund success for refund_id: %s, order: %s",
		refund.RefundID, webhookData.Order.OrderID)

	tx, err := pc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] RefundSuccess for %s: %v", refund.RefundID, err)
		return
	}
	defer tx.Rollback(ctx)

	// Update refund status
	result, err := tx.Exec(ctx,
		`UPDATE refunds 
		 SET status = $1, cf_refund_id = $2, processed_at = $3, updated_at = NOW()
		 WHERE refund_id = $4`,
		StatusRefundSuccess, refund.CfRefundID, refund.ProcessedAt, refund.RefundID)

	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update refund for success failed for %s: %v", refund.RefundID, err)
		return
	}

	refundRowsAffected := result.RowsAffected()

	// Update order status
	result, err = tx.Exec(ctx,
		`UPDATE orders 
		 SET status = $1, updated_at = NOW()
		 WHERE order_id = $2`,
		OrderStatusRefunded, webhookData.Order.OrderID)

	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update order for refund success failed for %s: %v", webhookData.Order.OrderID, err)
		return
	}

	orderRowsAffected := result.RowsAffected()

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("[TX_COMMIT_FAIL] RefundSuccess for %s: %v", refund.RefundID, err)
		return
	}

	logger.InfoLogger.Infof("✅ Refund success processed - refund_id: %s (refund rows: %d, order rows: %d)",
		refund.RefundID, refundRowsAffected, orderRowsAffected)
}

func (pc *PaymentController) handleRefundFailure(ctx context.Context, data json.RawMessage, eventType string) {
	var webhookData RefundWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse refund failure/reversal data: %v", err)
		return
	}

	refundID := webhookData.Refund.RefundID
	newStatus := StatusRefundFailed
	if eventType == "REFUND_REVERSED_WEBHOOK" {
		newStatus = StatusRefundReversed
	}

	logger.InfoLogger.Infof("Processing refund %s for refund_id: %s", newStatus, refundID)

	tx, err := pc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] RefundFailure for %s: %v", refundID, err)
		return
	}
	defer tx.Rollback(ctx)

	result, err := tx.Exec(ctx,
		`UPDATE refunds SET status = $1, updated_at = NOW() WHERE refund_id = $2`,
		newStatus, refundID)

	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update refund for failure failed for %s: %v", refundID, err)
		return
	}

	rowsAffected := result.RowsAffected()

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("[TX_COMMIT_FAIL] RefundFailure for %s: %v", refundID, err)
		return
	}

	logger.InfoLogger.Infof("❌ Refund %s processed for refund_id: %s (rows: %d)",
		newStatus, refundID, rowsAffected)
}

// Rest of the controller methods remain the same...
// (CreateOrder, GetOrder, CreateRefund, GetOrderHistory, WebhookHealthCheck, GetUnavailableTimes)

// CreateOrderRequest represents the order creation request
type CreateOrderRequest struct {
	Currency      string                 `json:"currency" binding:"required,len=3"`
	ServiceID     uuid.UUID              `json:"service_id" binding:"required"`
	StartTime     time.Time              `json:"start_time" binding:"required"`
	EndTime       time.Time              `json:"end_time" binding:"required"`
	UpiID         string                 `json:"upi_id"`
	PaymentMethod map[string]interface{} `json:"payment_method"`
}

// CreateOrder creates a new payment order and optionally initiates payment
func (pc *PaymentController) CreateOrder(c *gin.Context) {
	// Get customer ID from JWT token
	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		if err.Error() == "unauthorized" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	ctx := c.Request.Context()

	// Get user details
	user, err := user_models.GetUserByID(ctx, pc.DB, customerID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
		return
	}

	if user.Phone == nil || *user.Phone == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user phone required"})
		return
	}

	// Parse request
	var req CreateOrderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Validate start time < end time
	if req.StartTime.After(req.EndTime) || req.StartTime.Equal(req.EndTime) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Start time must be before end time"})
		return
	}

	// Validate slot date/time is not in the past
	now := time.Now().UTC()
	if req.StartTime.Before(now) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Slot date/time cannot be in the past"})
		return
	}

	// Check for overlapping bookings
	hasOverlap, err := payment_models.HasBookingOverlap(ctx, pc.DB, req.ServiceID, req.StartTime, req.EndTime)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to check overlap: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check availability"})
		return
	}
	if hasOverlap {
		c.JSON(http.StatusConflict, gin.H{"error": "This time slot is already booked by another user"})
		return
	}

	// Handle UpiID as shortcut for UPI collect if no payment_method provided
	if req.UpiID != "" && len(req.PaymentMethod) == 0 {
		upiRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.\-_]*[a-zA-Z0-9])?@[a-zA-Z0-9][a-zA-Z0-9]*$`)
		if !upiRegex.MatchString(req.UpiID) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid UPI ID"})
			return
		}
		req.PaymentMethod = map[string]interface{}{
			"upi": map[string]string{
				"channel": "collect",
				"upi_id":  req.UpiID,
			},
		}
	}

	// Get service
	service, err := service_models.GetServiceByIDModel(ctx, pc.DB, req.ServiceID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get service: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get service"})
		return
	}

	// Create Cashfree order payload
	payload := map[string]interface{}{
		"order_amount":   service.Price,
		"order_currency": req.Currency,
		"customer_details": map[string]string{
			"customer_id":    customerID.String(),
			"customer_phone": *user.Phone,
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to marshal order payload: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to prepare order"})
		return
	}

	// Call Cashfree API to create order
	resp, err := pc.makeRequest(ctx, "POST", "/orders", bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.ErrorLogger.Errorf("Cashfree request failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "payment gateway error"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.ErrorLogger.Errorf("Cashfree error [%d]: %s", resp.StatusCode, string(body))
		c.JSON(http.StatusBadGateway, gin.H{"error": "payment gateway error"})
		return
	}

	var cfOrderResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfOrderResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid response from payment gateway"})
		return
	}

	// Extract Cashfree response values
	cfOrderID, _ := cfOrderResp["order_id"].(string)
	cfPaymentSessionID, _ := cfOrderResp["payment_session_id"].(string)

	// Insert order into DB using Cashfree's order_id
	var dbOrderID uuid.UUID
	err = pc.DB.QueryRow(ctx,
		`INSERT INTO orders (order_id, customer_id, service_id, start_time, end_time, amount, currency, cf_order_id, payment_session_id, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
         RETURNING id`,
		cfOrderID, customerID, req.ServiceID, req.StartTime.UTC(), req.EndTime.UTC(), service.Price, req.Currency,
		cfOrderID, cfPaymentSessionID, OrderStatusPending,
	).Scan(&dbOrderID)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to insert order in DB: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save order"})
		return
	}

	logger.InfoLogger.Infof("Order created: %s for customer: %s", cfOrderID, customerID)

	var response gin.H = gin.H{
		"order_id": cfOrderID,
		"payment":  cfOrderResp,
	}

	// If payment method provided, initiate payment immediately
	if len(req.PaymentMethod) > 0 {
		paymentPayload := map[string]interface{}{
			"payment_session_id": cfPaymentSessionID,
			"payment_method":     req.PaymentMethod,
		}

		jsonPaymentPayload, err := json.Marshal(paymentPayload)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to marshal payment payload: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to prepare payment"})
			return
		}

		paymentResp, err := pc.makeRequest(ctx, "POST", "/orders/sessions", bytes.NewBuffer(jsonPaymentPayload))
		if err != nil {
			logger.ErrorLogger.Errorf("Cashfree payment initiation failed: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "payment gateway error"})
			return
		}
		defer paymentResp.Body.Close()

		if paymentResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(paymentResp.Body)
			logger.ErrorLogger.Errorf("Cashfree payment error [%d]: %s", paymentResp.StatusCode, string(body))
			c.JSON(http.StatusBadGateway, gin.H{"error": "payment initiation failed", "details": string(body)})
			return
		}

		var cfPaymentResp map[string]interface{}
		if err := json.NewDecoder(paymentResp.Body).Decode(&cfPaymentResp); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": "invalid response from payment gateway"})
			return
		}

		// Override the payment in response with the initiation response
		response["payment"] = cfPaymentResp
	}

	// Respond with order_id + payment response
	c.JSON(http.StatusOK, response)
}

// Webhook structures based on Cashfree documentation
type WebhookEvent struct {
	Type      string          `json:"type"`
	EventTime string          `json:"event_time"`
	Data      json.RawMessage `json:"data"`
}

type PaymentWebhookData struct {
	Order   OrderData   `json:"order"`
	Payment PaymentData `json:"payment"`
}

type OrderData struct {
	OrderID       string  `json:"order_id"`
	OrderAmount   float64 `json:"order_amount"`
	OrderCurrency string  `json:"order_currency"`
	OrderStatus   string  `json:"order_status"`
}

type PaymentData struct {
	CfPaymentID     int64                  `json:"cf_payment_id"`
	PaymentStatus   string                 `json:"payment_status"`
	PaymentAmount   float64                `json:"payment_amount"`
	PaymentCurrency string                 `json:"payment_currency"`
	BankReference   string                 `json:"bank_reference"`
	PaymentMethod   map[string]interface{} `json:"payment_method"`
}

// CreateRefundRequest represents refund creation request
type CreateRefundRequest struct {
	Amount float64 `json:"amount" binding:"required,gt=0"`
	Note   string  `json:"note"`
}

// CreateRefund creates a refund for an order
func (pc *PaymentController) CreateRefund(c *gin.Context) {
	orderID := c.Param("order_id")
	if orderID == "" {
		logger.DebugLogger.Debug("Missing order_id in request path")
		c.JSON(http.StatusBadRequest, gin.H{"error": "order_id required"})
		return
	}

	var req CreateRefundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.DebugLogger.Debugf("Invalid refund request payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	logger.DebugLogger.Debugf("Refund request received for order %s: %+v", orderID, req)

	// Check if order exists and is paid
	ctx := c.Request.Context()
	var orderAmount float64
	err := pc.DB.QueryRow(ctx,
		`SELECT amount FROM orders WHERE order_id = $1 AND cf_payment_id IS NOT NULL`,
		orderID).Scan(&orderAmount)

	if err != nil {
		if err == pgx.ErrNoRows {
			logger.DebugLogger.Debugf("No paid order found for order_id=%s", orderID)
			c.JSON(http.StatusNotFound, gin.H{"error": "paid order not found"})
		} else {
			logger.ErrorLogger.Errorf("DB query error checking order %s: %v", orderID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		}
		return
	}
	logger.DebugLogger.Debugf("Order %s found with amount=%.2f", orderID, orderAmount)

	if req.Amount > orderAmount {
		logger.DebugLogger.Debugf("Refund amount %.2f exceeds order amount %.2f for order %s", req.Amount, orderAmount, orderID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "refund amount exceeds order amount"})
		return
	}

	// Generate refund ID
	refundID := "refund_" + uuid.New().String()
	logger.DebugLogger.Debugf("Generated refund_id=%s for order_id=%s", refundID, orderID)

	// Create refund with Cashfree
	payload := map[string]interface{}{
		"refund_amount": req.Amount,
		"refund_id":     refundID,
		"refund_note":   req.Note,
	}
	jsonPayload, _ := json.Marshal(payload)
	logger.DebugLogger.Debugf("Sending refund request to Cashfree for order %s: %s", orderID, string(jsonPayload))

	resp, err := pc.makeRequest(ctx, "POST", "/orders/"+orderID+"/refunds", bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.ErrorLogger.Errorf("Refund gateway error for order %s: %v", orderID, err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "refund gateway error"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.ErrorLogger.Errorf("Refund creation failed for order %s: status=%d body=%s", orderID, resp.StatusCode, string(body))
		c.JSON(http.StatusBadGateway, gin.H{"error": "refund creation failed"})
		return
	}

	var cfResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		logger.ErrorLogger.Errorf("Failed to decode refund response for order %s: %v", orderID, err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid refund response"})
		return
	}
	logger.DebugLogger.Debugf("Cashfree refund response for order %s: %+v", orderID, cfResp)

	// Save refund to database
	_, err = pc.DB.Exec(ctx,
		`INSERT INTO refunds (order_id, refund_id, amount, status, note, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
		orderID, refundID, req.Amount, StatusRefundPending, req.Note)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to save refund for order %s: %v", orderID, err)
	} else {
		logger.DebugLogger.Debugf("Refund record saved for order %s with refund_id=%s", orderID, refundID)
	}

	logger.InfoLogger.Infof("Refund created: %s for order: %s amount=%.2f", refundID, orderID, req.Amount)

	c.JSON(http.StatusOK, gin.H{
		"refund_id": refundID,
		"refund":    cfResp,
	})
}

// GetOrder retrieves an order by ID for the authenticated user
func (pc *PaymentController) GetOrder(c *gin.Context) {
	orderID := c.Param("order_id")
	if orderID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "order_id required"})
		return
	}

	// Get authenticated user ID
	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		if err.Error() == "unauthorized" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	ctx := c.Request.Context()
	var order struct {
		ID               uuid.UUID `db:"id"`
		OrderID          string    `db:"order_id"`
		ServiceID        uuid.UUID `db:"service_id"`
		StartTime        time.Time `db:"start_time"`
		EndTime          time.Time `db:"end_time"`
		Amount           float64   `db:"amount"`
		PaymentSessionID string    `db:"payment_session_id"`
		Currency         string    `db:"currency"`
		CreatedAt        time.Time `db:"created_at"`
	}

	err = pc.DB.QueryRow(ctx,
		`SELECT id, order_id, service_id, start_time, end_time, amount, payment_session_id, currency, created_at
         FROM orders 
         WHERE customer_id = $1 AND order_id = $2`,
		customerID, orderID).Scan(
		&order.ID, &order.OrderID, &order.ServiceID, &order.StartTime, &order.EndTime, &order.Amount, &order.PaymentSessionID,
		&order.Currency, &order.CreatedAt,
	)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			c.JSON(http.StatusNotFound, gin.H{"error": "order not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"order_id":           order.OrderID,
		"service_id":         order.ServiceID,
		"start_time":         order.StartTime,
		"end_time":           order.EndTime,
		"amount":             order.Amount,
		"currency":           order.Currency,
		"created_at":         order.CreatedAt,
		"payment_session_id": order.PaymentSessionID,
		"payment": gin.H{
			"order_amount":   order.Amount,
			"order_currency": order.Currency,
		},
	})
}

// GetOrderHistory gets order history for a customer
func (pc *PaymentController) GetOrderHistory(c *gin.Context) {

	customerID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		if err.Error() == "unauthorized" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	// Pagination
	limit := 20
	offset := 0
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 && parsed <= 100000 {
			offset = parsed
		}
	}

	ctx := c.Request.Context()
	rows, err := pc.DB.Query(ctx,
		`SELECT id, order_id, service_id, start_time, end_time, amount, currency, created_at
		 FROM orders 
		 WHERE customer_id = $1 
		 ORDER BY created_at DESC 
		 LIMIT $2 OFFSET $3`,
		customerID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}
	defer rows.Close()

	var orders []map[string]interface{}
	for rows.Next() {
		var id uuid.UUID
		var orderID string
		var serviceID uuid.UUID
		var startTime time.Time
		var endTime time.Time
		var amount float64
		var currency string
		var createdAt time.Time

		if err := rows.Scan(&id, &orderID, &serviceID, &startTime, &endTime, &amount, &currency, &createdAt); err != nil {
			continue
		}

		orders = append(orders, map[string]interface{}{
			"id":         id,
			"order_id":   orderID,
			"service_id": serviceID,
			"start_time": startTime,
			"end_time":   endTime,
			"amount":     amount,
			"currency":   currency,
			"created_at": createdAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"orders": orders,
		"limit":  limit,
		"offset": offset,
	})
}

// WebhookHealthCheck provides webhook system health status
func (pc *PaymentController) WebhookHealthCheck(c *gin.Context) {
	ctx := c.Request.Context()

	// Check last webhook received
	var lastEvent struct {
		EventType string    `json:"event_type"`
		CreatedAt time.Time `json:"created_at"`
		Processed bool      `json:"processed"`
	}

	err := pc.DB.QueryRow(ctx,
		`SELECT event_type, created_at, processed 
		 FROM webhook_events 
		 ORDER BY created_at DESC 
		 LIMIT 1`).Scan(&lastEvent.EventType, &lastEvent.CreatedAt, &lastEvent.Processed)

	if err != nil && err != pgx.ErrNoRows {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "health check failed"})
		return
	}

	// Count events in last 24 hours
	var count int
	err = pc.DB.QueryRow(ctx,
		`SELECT COUNT(*) FROM webhook_events WHERE created_at > NOW() - INTERVAL '24 hours'`).Scan(&count)
	if err != nil && err != pgx.ErrNoRows {
		logger.ErrorLogger.Errorf("Failed to count recent webhook events: %v", err)
	}

	// Count unprocessed events
	var unprocessed int
	err = pc.DB.QueryRow(ctx,
		`SELECT COUNT(*) FROM webhook_events WHERE NOT processed`).Scan(&unprocessed)
	if err != nil && err != pgx.ErrNoRows {
		logger.ErrorLogger.Errorf("Failed to count unprocessed events: %v", err)
	}

	response := gin.H{
		"status":             "healthy",
		"webhook_configured": pc.WebhookSecret != "",
		"events_24h":         count,
		"unprocessed_events": unprocessed,
	}

	if err != pgx.ErrNoRows {
		response["last_event"] = lastEvent
	}

	c.JSON(http.StatusOK, response)
}

// GetUnavailableTimes retrieves all confirmed (booked) time slots for a service on a specific date
func (pc *PaymentController) GetUnavailableTimes(c *gin.Context) {
	serviceIDStr := c.Param("service_id")
	serviceID, err := uuid.Parse(serviceIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID format"})
		return
	}

	dateStr := c.Query("date")
	if dateStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Query parameter 'date' is required in YYYY-MM-DD format"})
		return
	}

	// Parse date in YYYY-MM-DD format (UTC)
	bookingDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format, use YYYY-MM-DD"})
		return
	}

	// Get start of today in UTC
	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// Check if booking date is in the past (before today)
	if bookingDate.Before(today) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Booking date cannot be in the past"})
		return
	}

	// UTC day boundaries
	startOfDay := time.Date(bookingDate.Year(), bookingDate.Month(), bookingDate.Day(), 0, 0, 0, 0, time.UTC)
	endOfDay := startOfDay.Add(24 * time.Hour)

	logger.InfoLogger.Infof("Fetching unavailable times for service=%s, date=%s, UTC range=%s - %s",
		serviceID, dateStr, startOfDay.Format(time.RFC3339), endOfDay.Format(time.RFC3339))

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	times, err := payment_models.GetBookedTimesForServiceDate(ctx, pc.DB, serviceID, startOfDay, endOfDay)
	if err != nil {
		logger.ErrorLogger.Errorf("Query error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch unavailable times"})
		return
	}

	if len(times) == 0 {
		logger.InfoLogger.Infof("No unavailable slots found for service=%s on date=%s", serviceID, dateStr)
	}

	c.JSON(http.StatusOK, gin.H{"times": times})
}

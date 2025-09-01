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
	"github.com/joy095/identity/models/schedule_slot_models"
	"github.com/joy095/identity/models/service_models"
	"github.com/joy095/identity/models/user_models"
	"github.com/joy095/identity/utils"
)

// Order status constants
const (
	StatusPending = "pending"
	StatusPaid    = "paid"
	StatusFailed  = "failed"
	StatusExpired = "expired"
)

// Refund status constants
const (
	StatusRefundPending  = "pending"
	StatusRefundSuccess  = "success"
	StatusRefundFailed   = "failed"
	StatusRefundReversed = "reversed"
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
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to read webhook body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	// 1. Verify webhook signature FIRST (CRITICAL SECURITY STEP)
	if !pc.verifyWebhookSignature(c, bodyBytes) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
		return
	}
	// Restore body so Gin can re-use it if needed (optional but good practice)
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 2. Parse generic event
	var event WebhookEvent
	if err := json.Unmarshal(bodyBytes, &event); err != nil {
		logger.ErrorLogger.Errorf("Invalid webhook payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	ctx := c.Request.Context()

	// 3. Log event
	var eventID int64
	err = pc.DB.QueryRow(ctx,
		`INSERT INTO webhook_events (event_type, raw_payload, processed) VALUES ($1, $2, $3) RETURNING id`,
		event.Type, string(bodyBytes), false).Scan(&eventID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to log webhook event: %v", err)
	} else {
		_, err = pc.DB.Exec(ctx,
			`UPDATE webhook_events SET processed = true WHERE id = $1`, eventID)
		if err != nil {
			logger.ErrorLogger.Errorf("Failed to update webhook event as processed: %v", err)
		}
	}

	// 4. Route event
	switch event.Type {
	case "PAYMENT_SUCCESS_WEBHOOK", "ORDER_PAID":
		pc.handlePaymentSuccess(ctx, event.Data)
	case "PAYMENT_FAILED_WEBHOOK", "PAYMENT_USER_DROPPED_WEBHOOK":
		pc.handlePaymentFailure(ctx, event.Data)
	case "ORDER_EXPIRED", "LINK_EXPIRED":
		pc.handleOrderExpired(ctx, event.Data)
	case "LINK_CANCELLED":
		pc.handleOrderCancelled(ctx, event.Data)
	case "REFUND_SUCCESS_WEBHOOK":
		pc.handleRefundSuccess(ctx, event.Data)
	case "REFUND_FAILURE_WEBHOOK", "REFUND_REVERSED_WEBHOOK":
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

	// Validate timestamp format and age to prevent replay attacks
	if ts, err := strconv.ParseInt(timestamp, 10, 64); err == nil {
		timestampTime := time.Unix(ts, 0)
		timeDiff := time.Since(timestampTime)

		// Webhooks should only come from the past, allow 5 minutes window
		if timeDiff > 5*time.Minute || timeDiff < 0 {
			logger.ErrorLogger.Errorf("Invalid timestamp age: %v", timeDiff)
			return false
		}
	} else {
		logger.ErrorLogger.Errorf("Invalid timestamp format: %s", timestamp)
		return false
	}

	// Message is timestamp concatenated with the body (NO DOT)
	message := timestamp + string(bodyBytes)

	// Generate the expected HMAC-SHA256 signature using WebhookSecret
	mac := hmac.New(sha256.New, []byte(pc.WebhookSecret))
	mac.Write([]byte(message))
	expectedSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Use a secure constant-time comparison to prevent timing attacks
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
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

	tx, err := pc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] PaymentSuccess for %s: %v", orderID, err)
		return
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`UPDATE orders 
		 SET status = $1, cf_payment_id = $2, payment_method = $3, bank_reference = $4, updated_at = NOW()
		 WHERE order_id = $5`,
		StatusPaid, payment.CfPaymentID, payment.PaymentMethod, payment.BankReference, orderID)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update order for success failed for %s: %v", orderID, err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("[TX_COMMIT_FAIL] PaymentSuccess for %s: %v", orderID, err)
		return
	}

	logger.InfoLogger.Infof("Payment success processed for order: %s", orderID)
}

func (pc *PaymentController) handlePaymentFailure(ctx context.Context, data json.RawMessage) {
	var webhookData PaymentWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse payment failure data: %v", err)
		return
	}

	orderID := webhookData.Order.OrderID
	if err := updateOrderStatus(ctx, pc.DB, orderID, StatusFailed, "Payment failure/dropped processed for order: %s"); err != nil {
		logger.ErrorLogger.Errorf("Failed to update order status: %v", err)
	}

}

type OrderOnlyWebhookData struct {
	Order OrderData `json:"order"`
}

func (pc *PaymentController) handleOrderExpired(ctx context.Context, data json.RawMessage) {
	var webhookData OrderOnlyWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse order expired data: %v", err)
		return
	}

	orderID := webhookData.Order.OrderID
	updateOrderStatus(ctx, pc.DB, orderID, StatusExpired, "⌛ Order expired for: %s")
}

func (pc *PaymentController) handleOrderCancelled(ctx context.Context, data json.RawMessage) {
	var webhookData OrderOnlyWebhookData
	if err := json.Unmarshal(data, &webhookData); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse order cancelled data: %v", err)
		return
	}

	orderID := webhookData.Order.OrderID
	updateOrderStatus(ctx, pc.DB, orderID, StatusFailed, "🚫 Order cancelled for: %s")
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
	tx, err := pc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] RefundSuccess for %s: %v", refund.RefundID, err)
		return
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`UPDATE refunds 
		 SET status = $1, cf_refund_id = $2, processed_at = $3, updated_at = NOW()
		 WHERE refund_id = $4`,
		StatusRefundSuccess, refund.CfRefundID, refund.ProcessedAt, refund.RefundID)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update refund for success failed for %s: %v", refund.RefundID, err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("[TX_COMMIT_FAIL] RefundSuccess for %s: %v", refund.RefundID, err)
		return
	}
	logger.InfoLogger.Infof("✅ Refund success processed for refund_id: %s", refund.RefundID)
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

	tx, err := pc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] RefundFailure for %s: %v", refundID, err)
		return
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`UPDATE refunds SET status = $1, updated_at = NOW() WHERE refund_id = $2`,
		newStatus, refundID)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update refund for failure failed for %s: %v", refundID, err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("[TX_COMMIT_FAIL] RefundFailure for %s: %v", refundID, err)
		return
	}
	logger.InfoLogger.Infof("❌ Refund %s processed for refund_id: %s", newStatus, refundID)
}

// Helper function to update only the status of an order within a transaction.
func updateOrderStatus(ctx context.Context, db *pgxpool.Pool, orderID, status, logMessage string) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_BEGIN_FAIL] UpdateOrderStatus for %s: %v", orderID, err)
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`UPDATE orders SET status = $1, updated_at = NOW() WHERE order_id = $2 AND status = 'pending'`,
		status, orderID)
	if err != nil {
		logger.ErrorLogger.Errorf("[TX_EXEC_FAIL] Update order status failed for %s: %v", orderID, err)
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("[TX_COMMIT_FAIL] UpdateOrderStatus for %s: %v", orderID, err)
		return err
	}

	logger.InfoLogger.Infof(logMessage, orderID)

	return nil
}

// CreateOrderRequest represents the order creation request
type CreateOrderRequest struct {
	Currency      string                 `json:"currency" binding:"required,len=3"`
	SlotID        uuid.UUID              `json:"slot_id" binding:"required"`
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

	Slot, err := schedule_slot_models.GetScheduleSlotByID(c.Request.Context(), pc.DB, req.SlotID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get slot: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get slot"})
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
	service, err := service_models.GetServiceByIDModel(ctx, pc.DB, Slot.ServiceID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get service: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get service"})
		return
	}

	// Validate schedule slot
	_, err = schedule_slot_models.GetScheduleSlotByID(ctx, pc.DB, req.SlotID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get slot: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get slot"})
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
		`INSERT INTO orders (order_id, customer_id, slot_id, amount, currency, status, cf_order_id, payment_session_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id`,
		cfOrderID, customerID, req.SlotID, service.Price, req.Currency, StatusPending,
		cfOrderID, cfPaymentSessionID,
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

// syncOrderStatus syncs order status with Cashfree
func (pc *PaymentController) syncOrderStatus(ctx context.Context, orderID string) {
	resp, err := pc.makeRequest(ctx, "GET", "/orders/"+orderID, nil)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to sync order status: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var cfResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		return
	}

	orderStatus, ok := cfResp["order_status"].(string)
	if !ok {
		return
	}

	// Map Cashfree status to internal status
	var dbStatus string
	switch orderStatus {
	case "PAID":
		dbStatus = StatusPaid
	case "EXPIRED", "TERMINATED":
		dbStatus = StatusExpired
	default:
		return // No update needed
	}

	// Update database
	_, err = pc.DB.Exec(ctx,
		`UPDATE orders SET status = $1, updated_at = NOW() WHERE order_id = $2`,
		dbStatus, orderID)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update order status for %s: %v", orderID, err)
		return
	}

	logger.InfoLogger.Infof("Order status synced: %s -> %s", orderID, dbStatus)
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "order_id required"})
		return
	}

	var req CreateRefundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Check if order exists and is paid
	ctx := c.Request.Context()
	var orderAmount float64
	err := pc.DB.QueryRow(ctx,
		`SELECT amount FROM orders WHERE order_id = $1 AND status = $2`,
		orderID, StatusPaid).Scan(&orderAmount)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "paid order not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		}
		return
	}

	if req.Amount > orderAmount {
		c.JSON(http.StatusBadRequest, gin.H{"error": "refund amount exceeds order amount"})
		return
	}

	// Generate refund ID
	refundID := "refund_" + uuid.New().String()

	// Create refund with Cashfree
	payload := map[string]interface{}{
		"refund_amount": req.Amount,
		"refund_id":     refundID,
		"refund_note":   req.Note,
	}

	jsonPayload, _ := json.Marshal(payload)
	resp, err := pc.makeRequest(ctx, "POST", "/orders/"+orderID+"/refunds", bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "refund gateway error"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.ErrorLogger.Errorf("Refund creation failed: %s", string(body))
		c.JSON(http.StatusBadGateway, gin.H{"error": "refund creation failed"})
		return
	}

	var cfResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid refund response"})
		return
	}

	// Save refund to database
	_, err = pc.DB.Exec(ctx,
		`INSERT INTO refunds (order_id, refund_id, amount, status, note)
		 VALUES ($1, $2, $3, $4, $5)`,
		orderID, refundID, req.Amount, StatusRefundPending, req.Note)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to save refund: %v", err)
	}

	logger.InfoLogger.Infof("Refund created: %s for order: %s", refundID, orderID)

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
		Amount           float64   `db:"amount"`
		PaymentSessionID string    `db:"payment_session_id"`
		Currency         string    `db:"currency"`
		Status           string    `db:"status"`
		CreatedAt        time.Time `db:"created_at"`
	}

	err = pc.DB.QueryRow(ctx,
		`SELECT id, order_id, amount, payment_session_id, currency, status, created_at
         FROM orders 
         WHERE customer_id = $1 AND order_id = $2`,
		customerID, orderID).Scan(
		&order.ID, &order.OrderID, &order.Amount, &order.PaymentSessionID,
		&order.Currency, &order.Status, &order.CreatedAt,
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
		"amount":             order.Amount,
		"currency":           order.Currency,
		"status":             order.Status,
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
		`SELECT id, order_id, amount, currency, status, created_at
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
		var amount float64
		var currency string
		var status string
		var createdAt time.Time

		if err := rows.Scan(&id, &orderID, &amount, &currency, &status, &createdAt); err != nil {
			continue
		}

		orders = append(orders, map[string]interface{}{
			"id":         id,
			"order_id":   orderID,
			"amount":     amount,
			"currency":   currency,
			"status":     status,
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

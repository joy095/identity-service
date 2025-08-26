package business_payment_controller

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/joy095/identity/models/user_models"
)

// Constants for reused variables
const (
	OrderIDPrefix        = "order_"
	BookingStatusPending = "pending"
	BookingStatusPaid    = "paid"
	BookingStatusFailed  = "failed"
	PaymentStatusPending = "pending"
	PaymentStatusPaid    = "paid"
	PaymentStatusFailed  = "failed"
	RefundStatusPending  = "pending"
	RefundStatusSuccess  = "success"
	RefundStatusFailed   = "failed"
)

// BusinessPaymentController holds dependencies for business-related operations.
type BusinessPaymentController struct {
	DB                 *pgxpool.Pool
	ClientID           string
	ClientSecret       string
	APIVersion         string
	BaseURL            string
	PayoutClientID     string
	PayoutClientSecret string
	PayoutBaseURL      string
	WebhookSecret      string
}

// NewBusinessPaymentController creates a new instance of BusinessPaymentController.
func NewBusinessPaymentController(db *pgxpool.Pool) *BusinessPaymentController {
	clientID := os.Getenv("CASHFREE_CLIENT_ID")
	clientSecret := os.Getenv("CASHFREE_CLIENT_SECRET")
	apiVersion := os.Getenv("X_API_VERSION")

	if clientID == "" || clientSecret == "" || apiVersion == "" {
		panic("Required Cashfree environment variables not set: CASHFREE_CLIENT_ID, CASHFREE_CLIENT_SECRET, X_API_VERSION")
	}

	baseURL := os.Getenv("CASHFREE_BASE_URL")
	if baseURL == "" {
		baseURL = "https://sandbox.cashfree.com/pg"
	}

	payoutClientID := os.Getenv("CASHFREE_PAYOUT_CLIENT_ID")
	payoutClientSecret := os.Getenv("CASHFREE_PAYOUT_CLIENT_SECRET")
	payoutBaseURL := os.Getenv("CASHFREE_PAYOUT_BASE_URL")
	if payoutBaseURL == "" {
		payoutBaseURL = "https://payout-sandbox.cashfree.com"
	}

	webhookSecret := os.Getenv("CASHFREE_WEBHOOK_SECRET")
	if webhookSecret == "" {
		panic("Required Cashfree webhook secret not set: CASHFREE_WEBHOOK_SECRET")
	}

	return &BusinessPaymentController{
		DB:                 db,
		ClientID:           clientID,
		ClientSecret:       clientSecret,
		APIVersion:         apiVersion,
		BaseURL:            baseURL,
		PayoutClientID:     payoutClientID,
		PayoutClientSecret: payoutClientSecret,
		PayoutBaseURL:      payoutBaseURL,
		WebhookSecret:      webhookSecret,
	}
}

func (bc *BusinessPaymentController) callCashfree(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, bc.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("x-client-id", bc.ClientID)
	req.Header.Set("x-client-secret", bc.ClientSecret)
	req.Header.Set("x-api-version", bc.APIVersion)

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

func (bc *BusinessPaymentController) callPayout(ctx context.Context, method, path string, body io.Reader, useBearer bool, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, bc.PayoutBaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if useBearer {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("X-Client-Id", bc.PayoutClientID)
		req.Header.Set("X-Client-Secret", bc.PayoutClientSecret)
	}
	req.Header.Set("x-api-version", bc.APIVersion)

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

func (bc *BusinessPaymentController) getPayoutToken(ctx context.Context) (string, error) {
	resp, err := bc.callPayout(ctx, "POST", "/payout/v1/authorize", nil, false, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return "", fmt.Errorf("authorize returned non-200: %d, body: %s", resp.StatusCode, string(b))
	}

	var cfResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		return "", err
	}

	status, ok := cfResp["status"].(string)
	if !ok || status != "SUCCESS" {
		return "", fmt.Errorf("authorize failed: %v", cfResp)
	}

	data, ok := cfResp["data"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("missing data in response")
	}

	token, ok := data["token"].(string)
	if !ok {
		return "", fmt.Errorf("missing token in response")
	}

	return token, nil
}

type CreatePaymentRequest struct {
	OrderCurrency string  `json:"order_currency" binding:"required,len=3"`
	OrderAmount   float64 `json:"order_amount" binding:"required,gt=0"`
}

func (bc *BusinessPaymentController) CreateOrders(c *gin.Context) {
	logger.InfoLogger.Info("CreateOrders function called")

	customerIDFromToken, exists := c.Get("sub")
	if !exists {
		logger.ErrorLogger.Error("Unauthorized: User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	customerID, err := uuid.Parse(customerIDFromToken.(string))
	if err != nil {
		logger.ErrorLogger.Errorf("Invalid user ID from token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	user, err := user_models.GetUserByID(c.Request.Context(), bc.DB, customerID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to fetch user data for ID %s: %v", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user data"})
		return
	}

	if user.Phone == nil {
		logger.ErrorLogger.Errorf("User phone not found for ID %s", customerID)
		c.JSON(http.StatusNotFound, gin.H{"error": "user phone not found"})
		return
	}

	var req CreatePaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid request payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if bc.ClientID == "" || bc.ClientSecret == "" || bc.APIVersion == "" {
		logger.ErrorLogger.Error("Cashfree credentials not configured")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cashfree credentials not configured"})
		return
	}

	orderID := OrderIDPrefix + uuid.New().String()
	payload := map[string]interface{}{
		"order_id":       orderID,
		"order_amount":   req.OrderAmount,
		"order_currency": req.OrderCurrency,
		"customer_details": map[string]string{
			"customer_id":    customerID.String(),
			"customer_phone": *user.Phone,
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to serialize Cashfree payload: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize cashfree payload"})
		return
	}

	// POST /orders
	resp, err := bc.callCashfree(c.Request.Context(), "POST", "/orders", bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.ErrorLogger.Errorf("Cashfree request failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		logger.ErrorLogger.Errorf("Cashfree returned error [%d]: %s", resp.StatusCode, string(b))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned non-2xx", "status": resp.StatusCode})
		return
	}

	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		logger.ErrorLogger.Errorf("Invalid Cashfree response: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	ctx := c.Request.Context()
	tx, err := bc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to start DB transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start transaction"})
		return
	}
	defer tx.Rollback(ctx)

	var bookingID uuid.UUID
	err = tx.QueryRow(ctx,
		`INSERT INTO bookings (customer_id, status) 
     VALUES ($1, $2) 
     RETURNING id`,
		customerID,
		BookingStatusPending,
	).Scan(&bookingID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create booking for customer %s: %v", customerID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create booking"})
		return
	}

	cfOrderID, _ := cfResp["cf_order_id"].(string)
	paymentSessionID, _ := cfResp["payment_session_id"].(string)

	var paymentID uuid.UUID
	err = tx.QueryRow(ctx,
		`INSERT INTO payments (booking_id, order_id, amount, currency, status, cf_order_id, payment_session_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id`,
		bookingID,
		orderID,
		req.OrderAmount,
		req.OrderCurrency,
		PaymentStatusPending,
		cfOrderID,
		paymentSessionID,
	).Scan(&paymentID)

	if err != nil {
		logger.ErrorLogger.Errorf("Failed to create payment for booking %s: %v", bookingID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create payment"})
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("Failed to commit transaction for booking %s: %v", bookingID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to commit transaction"})
		return
	}

	logger.InfoLogger.Infof("Order created successfully: booking_id=%s, order_id=%s", bookingID, orderID)

	c.JSON(http.StatusOK, gin.H{
		"booking_id": bookingID,
		"order_id":   orderID,
		"payment":    cfResp,
	})
}

type PayPaymentRequest struct {
	PaymentSessionId string                 `json:"payment_session_id" binding:"required"`
	PaymentMethod    map[string]interface{} `json:"payment_method" binding:"required"`
}

func (bc *BusinessPaymentController) PayPayment(c *gin.Context) {
	var req PayPaymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Failed to bind JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	payload := map[string]interface{}{
		"payment_session_id": req.PaymentSessionId,
		"payment_method":     req.PaymentMethod,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize cashfree payload"})
		return
	}

	resp, err := bc.callCashfree(c.Request.Context(), "POST", "/orders/sessions", bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned non-2xx", "status": resp.StatusCode, "body": string(b)})
		return
	}
	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"payment": cfResp})
}

type PayUPIRequest struct {
	PaymentSessionId string `json:"payment_session_id" binding:"required"`
	UPIID            string `json:"upi_id"`
}

func (bc *BusinessPaymentController) processUPIPayment(c *gin.Context, channel string, responseKey string, requireUPIID bool) {
	var req PayUPIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	reUPI := regexp.MustCompile(`^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}$`)
	if requireUPIID && !reUPI.MatchString(req.UPIID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid upi_id"})
		return
	}

	upiData := map[string]string{"channel": channel}
	if req.UPIID != "" {
		upiData["upi_id"] = req.UPIID
	}

	payload := map[string]interface{}{
		"payment_session_id": req.PaymentSessionId,
		"payment_method": map[string]interface{}{
			"upi": upiData,
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize cashfree payload"})
		return
	}

	resp, err := bc.callCashfree(c.Request.Context(), "POST", "/orders/sessions", bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned non-2xx", "status": resp.StatusCode, "body": string(b)})
		return
	}
	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	c.JSON(http.StatusOK, gin.H{responseKey: cfResp})
}

func (bc *BusinessPaymentController) PayUPIQR(c *gin.Context) {
	bc.processUPIPayment(c, "qrcode", "qr_payment", false)
}

func (bc *BusinessPaymentController) PayUPIIntent(c *gin.Context) {
	bc.processUPIPayment(c, "link", "intent_payment", false)
}

func (bc *BusinessPaymentController) PayUPICollect(c *gin.Context) {
	bc.processUPIPayment(c, "collect", "collect_payment", true)
}

// Enhanced webhook payload structures for all event types
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
	PaymentMessage  string                 `json:"payment_message"`
	PaymentTime     string                 `json:"payment_time"`
	BankReference   string                 `json:"bank_reference"`
	AuthID          string                 `json:"auth_id"`
	PaymentMethod   map[string]interface{} `json:"payment_method"`
	PaymentGroup    string                 `json:"payment_group"`
}

type RefundWebhookData struct {
	Refund RefundData `json:"refund"`
}

type RefundData struct {
	CfRefundID     string  `json:"cf_refund_id"`
	RefundID       string  `json:"refund_id"`
	RefundAmount   float64 `json:"refund_amount"`
	RefundCurrency string  `json:"refund_currency"`
	RefundNote     string  `json:"refund_note"`
	RefundStatus   string  `json:"refund_status"`
	RefundType     string  `json:"refund_type"`
	RefundTime     string  `json:"refund_time"`
	RefundArn      string  `json:"refund_arn"`
}

type SettlementWebhookData struct {
	Settlement SettlementData `json:"settlement"`
}

type SettlementData struct {
	CfSettlementID int64   `json:"cf_settlement_id"`
	SettlementID   int64   `json:"settlement_id"`
	Amount         float64 `json:"amount"`
	Status         string  `json:"status"`
	UTR            string  `json:"utr"`
	Time           string  `json:"time"`
}

// Enhanced webhook handler with support for all event types
func (bc *BusinessPaymentController) PaymentWebhook(c *gin.Context) {
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to read webhook body: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	// Verify webhook signature
	timestamp := c.GetHeader("x-webhook-timestamp")
	signature := c.GetHeader("x-webhook-signature")

	if timestamp == "" || signature == "" {
		logger.ErrorLogger.Error("Missing webhook headers")
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing webhook headers"})
		return
	}

	// Check timestamp tolerance
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || time.Since(time.Unix(ts, 0)) > 5*time.Minute {
		logger.ErrorLogger.Error("Invalid or expired webhook timestamp")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid timestamp"})
		return
	}

	msg := timestamp + "." + string(bodyBytes)
	key := []byte(bc.WebhookSecret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	expectedSig := hex.EncodeToString(h.Sum(nil)) // FIX: hex, not base64

	if expectedSig != signature {
		logger.ErrorLogger.Errorf("Invalid webhook signature: expected=%s got=%s", expectedSig, signature)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid signature"})
		return
	}

	// Parse webhook event
	var event WebhookEvent
	if err := json.Unmarshal(bodyBytes, &event); err != nil {
		logger.ErrorLogger.Errorf("Invalid webhook payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	logger.InfoLogger.Infof("Received webhook event: type=%s, time=%s", event.Type, event.EventTime)

	// Store raw webhook event
	ctx := c.Request.Context()
	_, err = bc.DB.Exec(ctx,
		`INSERT INTO webhook_events (event_type, event_time, raw_payload, processed_at)
		 VALUES ($1, $2, $3, NOW())`,
		event.Type, event.EventTime, string(bodyBytes))
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store webhook event: %v", err)
	}

	// Process based on event type
	switch event.Type {
	case "PAYMENT_SUCCESS_WEBHOOK", "PAYMENT_FAILED_WEBHOOK", "PAYMENT_USER_DROPPED_WEBHOOK":
		bc.handlePaymentWebhook(ctx, event)
	case "REFUND_STATUS_WEBHOOK":
		bc.handleRefundWebhook(ctx, event)
	case "SETTLEMENT_STATUS_WEBHOOK":
		bc.handleSettlementWebhook(ctx, event)
	case "PAYMENT_REMINDER_WEBHOOK":
		bc.handlePaymentReminderWebhook(ctx, event)
	default:
		logger.InfoLogger.Printf("Unhandled webhook event type: %s", event.Type)
	}

	c.JSON(http.StatusOK, gin.H{"message": "webhook processed", "event_type": event.Type})
}

func (bc *BusinessPaymentController) handlePaymentWebhook(ctx context.Context, event WebhookEvent) {
	var data PaymentWebhookData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse payment webhook data: %v", err)
		return
	}

	orderID := data.Order.OrderID
	paymentStatus := data.Payment.PaymentStatus

	// Map Cashfree status to internal status
	statusMap := map[string]string{
		"SUCCESS":      PaymentStatusPaid,
		"FAILED":       PaymentStatusFailed,
		"USER_DROPPED": PaymentStatusFailed,
		"PENDING":      PaymentStatusPending,
		"CANCELLED":    PaymentStatusFailed,
	}

	dbStatus, exists := statusMap[paymentStatus]
	if !exists {
		logger.InfoLogger.Printf("Unknown payment status: %s for order: %s", paymentStatus, orderID)
		return
	}

	tx, err := bc.DB.Begin(ctx)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to start transaction: %v", err)
		return
	}
	defer tx.Rollback(ctx)

	// Update payment record
	var paymentID uuid.UUID
	var bookingID uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT id, booking_id FROM payments WHERE order_id = $1 FOR UPDATE`,
		orderID).Scan(&paymentID, &bookingID)
	if err != nil {
		if err == pgx.ErrNoRows {
			logger.ErrorLogger.Errorf("Payment not found for order: %s", orderID)
		} else {
			logger.ErrorLogger.Errorf("Failed to query payment: %v", err)
		}
		return
	}

	// Update payment with detailed information
	_, err = tx.Exec(ctx,
		`UPDATE payments 
		 SET status = $1, 
		     cf_payment_id = $2,
		     payment_time = $3,
		     bank_reference = $4,
		     payment_method = $5,
		     updated_at = NOW()
		 WHERE id = $6`,
		dbStatus,
		data.Payment.CfPaymentID,
		data.Payment.PaymentTime,
		data.Payment.BankReference,
		data.Payment.PaymentMethod,
		paymentID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update payment: %v", err)
		return
	}

	// Update booking status
	_, err = tx.Exec(ctx,
		`UPDATE bookings SET status = $1, updated_at = NOW() WHERE id = $2`,
		dbStatus, bookingID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update booking: %v", err)
		return
	}

	// Log payment event
	_, err = tx.Exec(ctx,
		`INSERT INTO payment_events (payment_id, event_type, event_data, created_at)
		 VALUES ($1, $2, $3, NOW())`,
		paymentID, event.Type, event.Data)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to log payment event: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorLogger.Errorf("Failed to commit transaction: %v", err)
		return
	}

	logger.InfoLogger.Infof("Payment webhook processed: order=%s, status=%s", orderID, dbStatus)

	// Trigger notification to user if payment successful
	if dbStatus == PaymentStatusPaid {
		bc.notifyPaymentSuccess(ctx, bookingID, orderID, data.Payment.PaymentAmount)
	}
}

func (bc *BusinessPaymentController) handleRefundWebhook(ctx context.Context, event WebhookEvent) {
	var data RefundWebhookData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse refund webhook data: %v", err)
		return
	}

	refundID := data.Refund.RefundID
	refundStatus := data.Refund.RefundStatus

	// Map Cashfree refund status to internal status
	statusMap := map[string]string{
		"SUCCESS":   RefundStatusSuccess,
		"FAILED":    RefundStatusFailed,
		"PENDING":   RefundStatusPending,
		"CANCELLED": RefundStatusFailed,
	}

	dbStatus, exists := statusMap[refundStatus]
	if !exists {
		logger.InfoLogger.Printf("Unknown refund status: %s for refund: %s", refundStatus, refundID)
		return
	}

	// Update refund record
	_, err := bc.DB.Exec(ctx,
		`UPDATE refunds 
		 SET status = $1,
		     cf_refund_id = $2,
		     refund_arn = $3,
		     refund_time = $4,
		     updated_at = NOW()
		 WHERE refund_id = $5`,
		dbStatus,
		data.Refund.CfRefundID,
		data.Refund.RefundArn,
		data.Refund.RefundTime,
		refundID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to update refund: %v", err)
		return
	}

	logger.InfoLogger.Infof("Refund webhook processed: refund=%s, status=%s", refundID, dbStatus)

	// Notify user about refund status
	if dbStatus == RefundStatusSuccess {
		bc.notifyRefundSuccess(ctx, refundID, data.Refund.RefundAmount)
	}
}

func (bc *BusinessPaymentController) handleSettlementWebhook(ctx context.Context, event WebhookEvent) {
	var data SettlementWebhookData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse settlement webhook data: %v", err)
		return
	}

	// Store settlement information
	_, err := bc.DB.Exec(ctx,
		`INSERT INTO settlements (cf_settlement_id, settlement_id, amount, status, utr, settlement_time, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NOW())
		 ON CONFLICT (cf_settlement_id) 
		 DO UPDATE SET status = $4, utr = $5, updated_at = NOW()`,
		data.Settlement.CfSettlementID,
		data.Settlement.SettlementID,
		data.Settlement.Amount,
		data.Settlement.Status,
		data.Settlement.UTR,
		data.Settlement.Time)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store settlement: %v", err)
		return
	}

	logger.InfoLogger.Infof("Settlement webhook processed: settlement=%d, status=%s", data.Settlement.CfSettlementID, data.Settlement.Status)
}

func (bc *BusinessPaymentController) handlePaymentReminderWebhook(ctx context.Context, event WebhookEvent) {
	var data PaymentWebhookData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		logger.ErrorLogger.Errorf("Failed to parse payment reminder data: %v", err)
		return
	}

	orderID := data.Order.OrderID

	// Send reminder notification to user
	var bookingID uuid.UUID
	var customerID uuid.UUID
	err := bc.DB.QueryRow(ctx,
		`SELECT b.id, b.customer_id 
		 FROM bookings b
		 JOIN payments p ON p.booking_id = b.id
		 WHERE p.order_id = $1 AND p.status = $2`,
		orderID, PaymentStatusPending).Scan(&bookingID, &customerID)
	if err != nil {
		if err != pgx.ErrNoRows {
			logger.ErrorLogger.Errorf("Failed to get booking for reminder: %v", err)
		}
		return
	}

	bc.notifyPaymentReminder(ctx, customerID, orderID, data.Order.OrderAmount)
	logger.InfoLogger.Infof("Payment reminder sent for order: %s", orderID)
}

// Notification helper functions
func (bc *BusinessPaymentController) notifyPaymentSuccess(ctx context.Context, bookingID uuid.UUID, orderID string, amount float64) {
	// Implement your notification logic here
	// This could be email, SMS, push notification, etc.
	logger.InfoLogger.Infof("Payment success notification: booking=%s, order=%s, amount=%.2f", bookingID, orderID, amount)

	// Example: Store notification record
	_, err := bc.DB.Exec(ctx,
		`INSERT INTO notifications (booking_id, type, message, sent_at)
		 VALUES ($1, 'payment_success', $2, NOW())`,
		bookingID,
		fmt.Sprintf("Payment of %.2f received for order %s", amount, orderID))
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store notification: %v", err)
	}
}

func (bc *BusinessPaymentController) notifyRefundSuccess(ctx context.Context, refundID string, amount float64) {
	logger.InfoLogger.Infof("Refund success notification: refund=%s, amount=%.2f", refundID, amount)

	// Get booking details for the refund
	var bookingID uuid.UUID
	err := bc.DB.QueryRow(ctx,
		`SELECT p.booking_id 
		 FROM refunds r
		 JOIN payments p ON p.order_id = r.order_id
		 WHERE r.refund_id = $1`,
		refundID).Scan(&bookingID)
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get booking for refund notification: %v", err)
		return
	}

	_, err = bc.DB.Exec(ctx,
		`INSERT INTO notifications (booking_id, type, message, sent_at)
		 VALUES ($1, 'refund_success', $2, NOW())`,
		bookingID,
		fmt.Sprintf("Refund of %.2f processed successfully", amount))
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store notification: %v", err)
	}
}

func (bc *BusinessPaymentController) notifyPaymentReminder(ctx context.Context, customerID uuid.UUID, orderID string, amount float64) {
	logger.InfoLogger.Infof("Payment reminder notification: customer=%s, order=%s, amount=%.2f", customerID, orderID, amount)

	// Store reminder notification
	_, err := bc.DB.Exec(ctx,
		`INSERT INTO notifications (customer_id, type, message, sent_at)
		 VALUES ($1, 'payment_reminder', $2, NOW())`,
		customerID,
		fmt.Sprintf("Reminder: Pending payment of %.2f for order %s", amount, orderID))
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to store reminder notification: %v", err)
	}
}

// Additional webhook endpoints for specific payment methods

// UPI webhook handler
func (bc *BusinessPaymentController) UPIWebhook(c *gin.Context) {
	// UPI-specific webhook handling
	bc.PaymentWebhook(c) // Reuse main webhook handler with UPI-specific logic if needed
}

// Card webhook handler
func (bc *BusinessPaymentController) CardWebhook(c *gin.Context) {
	// Card-specific webhook handling
	bc.PaymentWebhook(c) // Reuse main webhook handler with card-specific logic if needed
}

// Get payment status with real-time sync
func (bc *BusinessPaymentController) GetPaymentStatus(c *gin.Context) {
	orderID := c.Param("order_id")
	if orderID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing order_id"})
		return
	}

	// First check database
	ctx := c.Request.Context()
	var payment struct {
		ID            uuid.UUID `json:"id"`
		Status        string    `json:"status"`
		Amount        float64   `json:"amount"`
		Currency      string    `json:"currency"`
		PaymentTime   *string   `json:"payment_time"`
		BankReference *string   `json:"bank_reference"`
	}

	err := bc.DB.QueryRow(ctx,
		`SELECT id, status, amount, currency, payment_time, bank_reference 
		 FROM payments WHERE order_id = $1`,
		orderID).Scan(&payment.ID, &payment.Status, &payment.Amount,
		&payment.Currency, &payment.PaymentTime, &payment.BankReference)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "payment not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query payment"})
		}
		return
	}

	// If payment is still pending, sync with Cashfree
	if payment.Status == PaymentStatusPending {
		// Call Cashfree to get latest status
		resp, err := bc.callCashfree(ctx, "GET", "/orders/"+orderID, nil)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			var cfResp map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&cfResp); err == nil {
				// Update status if changed
				if orderStatus, ok := cfResp["order_status"].(string); ok && orderStatus != "ACTIVE" {
					newStatus := PaymentStatusPending
					if orderStatus == "PAID" {
						newStatus = PaymentStatusPaid
					} else if orderStatus == "EXPIRED" || orderStatus == "TERMINATED" {
						newStatus = PaymentStatusFailed
					}

					if newStatus != PaymentStatusPending {
						_, err = bc.DB.Exec(ctx,
							`UPDATE payments SET status = $1, updated_at = NOW() WHERE order_id = $2`,
							newStatus, orderID)
						if err == nil {
							payment.Status = newStatus
						}
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"payment": payment})
}

// Webhook health check endpoint
func (bc *BusinessPaymentController) WebhookHealthCheck(c *gin.Context) {
	ctx := c.Request.Context()

	// Check last webhook received
	var lastWebhook struct {
		EventType   string    `json:"event_type"`
		EventTime   string    `json:"event_time"`
		ProcessedAt time.Time `json:"processed_at"`
	}

	err := bc.DB.QueryRow(ctx,
		`SELECT event_type, event_time, processed_at 
		 FROM webhook_events 
		 ORDER BY processed_at DESC 
		 LIMIT 1`).Scan(&lastWebhook.EventType, &lastWebhook.EventTime, &lastWebhook.ProcessedAt)

	if err != nil && err != pgx.ErrNoRows {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check webhook health"})
		return
	}

	// Count webhooks in last 24 hours
	var count int
	err = bc.DB.QueryRow(ctx,
		`SELECT COUNT(*) FROM webhook_events WHERE processed_at > NOW() - INTERVAL '24 hours'`).Scan(&count)
	if err != nil {
		count = 0
	}

	c.JSON(http.StatusOK, gin.H{
		"status":         "healthy",
		"last_webhook":   lastWebhook,
		"webhooks_24h":   count,
		"webhook_secret": bc.WebhookSecret != "",
	})
}

// Existing methods continue below...

type CreateRefundRequest struct {
	RefundAmount float64 `json:"refund_amount" binding:"required,gt=0"`
	RefundID     string  `json:"refund_id" binding:"required"`
	RefundNote   string  `json:"refund_note"`
	RefundSpeed  string  `json:"refund_speed"` // STANDARD or INSTANT
}

func (bc *BusinessPaymentController) CreateRefund(c *gin.Context) {
	orderID := c.Param("order_id")
	if orderID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing order_id"})
		return
	}

	var req CreateRefundRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	payload := map[string]interface{}{
		"refund_amount": req.RefundAmount,
		"refund_id":     req.RefundID,
		"refund_note":   req.RefundNote,
		"refund_speed":  req.RefundSpeed,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize cashfree payload"})
		return
	}

	resp, err := bc.callCashfree(c.Request.Context(), "POST", "/orders/"+orderID+"/refunds", bytes.NewBuffer(jsonPayload))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned non-2xx", "status": resp.StatusCode, "body": string(b)})
		return
	}
	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	// Save refund to DB
	ctx := c.Request.Context()
	_, err = bc.DB.Exec(ctx, `INSERT INTO refunds (order_id, refund_id, amount, status, note, created_at)
								VALUES ($1, $2, $3, $4, $5, NOW())
								ON CONFLICT (refund_id) DO NOTHING`,
		orderID, req.RefundID, req.RefundAmount, RefundStatusPending, req.RefundNote)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refund"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"refund": cfResp})
}

func (bc *BusinessPaymentController) GetRefund(c *gin.Context) {
	orderID := c.Param("order_id")
	refundID := c.Param("refund_id")
	if orderID == "" || refundID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing order_id or refund_id"})
		return
	}

	resp, err := bc.callCashfree(c.Request.Context(), "GET", "/orders/"+orderID+"/refunds/"+refundID, nil)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned error", "status": resp.StatusCode, "body": string(b)})
		return
	}

	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"refund": cfResp})
}

func (bc *BusinessPaymentController) GetOrder(c *gin.Context) {
	orderID := c.Param("order_id")
	if orderID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing order_id"})
		return
	}

	resp, err := bc.callCashfree(c.Request.Context(), "GET", "/orders/"+orderID, nil)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned error", "status": resp.StatusCode, "body": string(b)})
		return
	}

	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"order": cfResp})
}

type Booking struct {
	ID         uuid.UUID `json:"id"`
	CustomerID uuid.UUID `json:"customer_id"`
	Status     string    `json:"status"`
}

func (bc *BusinessPaymentController) GetBookings(c *gin.Context) {
	limit := 50
	offset := 0
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 1000 {
			limit = parsedLimit
		}
	}
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	ctx := c.Request.Context()
	rows, err := bc.DB.Query(ctx, `SELECT id, customer_id, status FROM bookings ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query bookings"})
		return
	}
	defer rows.Close()

	var bookings []Booking
	for rows.Next() {
		var b Booking
		if err := rows.Scan(&b.ID, &b.CustomerID, &b.Status); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to scan booking"})
			return
		}
		bookings = append(bookings, b)
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error iterating bookings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"bookings": bookings, "limit": limit, "offset": offset})
}

func (bc *BusinessPaymentController) GetBooking(c *gin.Context) {
	bookingIDStr := c.Param("booking_id")
	bookingID, err := uuid.Parse(bookingIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid booking_id"})
		return
	}

	ctx := c.Request.Context()
	var b Booking
	err = bc.DB.QueryRow(ctx, `SELECT id, customer_id, status FROM bookings WHERE id = $1`, bookingID).Scan(&b.ID, &b.CustomerID, &b.Status)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "booking not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query booking"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"booking": b})
}

type CreatePayoutRequest struct {
	Amount       float64 `json:"amount" binding:"required,gt=0"`
	TransferID   string  `json:"transfer_id" binding:"required"`
	TransferMode string  `json:"transfer_mode" binding:"required"`
	BeneDetails  struct {
		BankAccount string `json:"bank_account" binding:"required"`
		IFSC        string `json:"ifsc" binding:"required"`
		Name        string `json:"name" binding:"required"`
		Phone       string `json:"phone" binding:"required"`
		Email       string `json:"email"`
		VPA         string `json:"vpa"`
		Address1    string `json:"address1"`
	} `json:"bene_details" binding:"required"`
}

func (bc *BusinessPaymentController) CreatePayout(c *gin.Context) {
	if bc.PayoutClientID == "" || bc.PayoutClientSecret == "" {
		logger.ErrorLogger.Error("Cashfree payout credentials not configured")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cashfree payout credentials not configured"})
		return
	}

	var req CreatePayoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("Invalid request payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	token, err := bc.getPayoutToken(c.Request.Context())
	if err != nil {
		logger.ErrorLogger.Errorf("Failed to get payout token: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to authenticate with cashfree payouts"})
		return
	}

	payload := map[string]interface{}{
		"amount":       req.Amount,
		"transferId":   req.TransferID,
		"transferMode": req.TransferMode,
		"beneDetails":  req.BeneDetails,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize cashfree payload"})
		return
	}

	resp, err := bc.callPayout(c.Request.Context(), "POST", "/payout/v1/directTransfer", bytes.NewBuffer(jsonPayload), true, token)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree payout request failed"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		c.JSON(http.StatusBadGateway, gin.H{"error": "cashfree returned non-2xx", "status": resp.StatusCode, "body": string(b)})
		return
	}

	var cfResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid cashfree response"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"payout": cfResp})
}

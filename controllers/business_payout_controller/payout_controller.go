package business_payout_controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joy095/identity/logger"
	"github.com/joy095/identity/utils"
)

// Payout status constants
const (
	PayoutStatusPending   = "pending"
	PayoutStatusProcessed = "processed"
	PayoutStatusFailed    = "failed"
	PayoutStatusReversed  = "reversed"
)

// PayoutController handles all payout operations
type PayoutController struct {
	DB           *pgxpool.Pool
	ClientID     string
	ClientSecret string
	BaseURL      string
	HttpClient   *http.Client
}

// NewPayoutController initializes payout controller
func NewPayoutController(db *pgxpool.Pool) (*PayoutController, error) {
	clientID := os.Getenv("CASHFREE_PAYOUT_ID")
	clientSecret := os.Getenv("CASHFREE_PAYOUT_SECRET")
	baseURL := os.Getenv("CASHFREE_PAYOUT_URL")
	if baseURL == "" {
		baseURL = "https://sandbox.cashfree.com/payout/v1"
	}

	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("payout: required Cashfree credentials not set")
	}

	return &PayoutController{
		DB:           db,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		BaseURL:      baseURL,
		HttpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}, nil
}

// makeRequest is an HTTP client helper
func (pc *PayoutController) makeRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, pc.BaseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Client-Id", pc.ClientID)
	req.Header.Set("X-Client-Secret", pc.ClientSecret)

	resp, err := pc.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}

	return resp, nil
}

// ----------- API Handlers ------------

// CreatePayout initiates a payout request
func (pc *PayoutController) CreatePayout(c *gin.Context) {
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Errorf("unauthorized access: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req struct {
		Amount   float64 `json:"amount" binding:"required,gt=0"`
		Currency string  `json:"currency" binding:"required,oneof=INR USD"`
		BankID   string  `json:"bank_id" binding:"required,uuid"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.ErrorLogger.Errorf("invalid request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	// Validate bank_id exists in the database
	var exists bool
	err = pc.DB.QueryRow(c.Request.Context(),
		`SELECT EXISTS (SELECT 1 FROM bank_accounts WHERE bank_id = $1 AND user_id = $2)`,
		req.BankID, userID).Scan(&exists)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to verify bank_id: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify bank details"})
		return
	}
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid bank_id"})
		return
	}

	payoutID := uuid.NewString()

	payload := map[string]interface{}{
		"payoutId":     payoutID,
		"amount":       req.Amount,
		"currency":     req.Currency,
		"transferMode": "banktransfer",
		"beneficiaryDetails": map[string]interface{}{
			"bank_id": req.BankID,
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to marshal payload: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	resp, err := pc.makeRequest(c.Request.Context(), "POST", "/payouts", bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.ErrorLogger.Errorf("payout request failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "gateway error"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		logger.ErrorLogger.Errorf("payout failed [%d]: %s", resp.StatusCode, string(body))
		c.JSON(http.StatusBadGateway, gin.H{"error": "payout failed"})
		return
	}

	// Save payout request in DB
	_, err = pc.DB.Exec(c.Request.Context(),
		`INSERT INTO payouts (payout_id, user_id, amount, currency, bank_id, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
		payoutID, userID, req.Amount, req.Currency, req.BankID, PayoutStatusPending,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to save payout: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save payout"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"payout_id": payoutID,
		"status":    PayoutStatusPending,
	})
}

// GetBalance fetches Cashfree account balance
func (pc *PayoutController) GetBalance(c *gin.Context) {
	resp, err := pc.makeRequest(c.Request.Context(), "GET", "/getBalance", nil)
	if err != nil {
		logger.ErrorLogger.Errorf("balance request failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "gateway error"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logger.ErrorLogger.Errorf("balance error [%d]: %s", resp.StatusCode, string(body))
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch balance"})
		return
	}

	var cfResp struct {
		Currency         string  `json:"currency"`
		AvailableBalance float64 `json:"availableBalance"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		logger.ErrorLogger.Errorf("failed to decode balance response: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid response from gateway"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"balance":  cfResp.AvailableBalance,
		"fetched":  true,
		"currency": cfResp.Currency,
	})
}

// GetPayoutStatus fetches payout status from Cashfree
func (pc *PayoutController) GetPayoutStatus(c *gin.Context) {
	payoutID := c.Param("payout_id")
	if payoutID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "valid payout_id required"})
		return
	}

	// Verify payout belongs to user
	userID, err := utils.GetUserIDFromContext(c)
	if err != nil {
		logger.ErrorLogger.Errorf("unauthorized access: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var exists bool
	err = pc.DB.QueryRow(c.Request.Context(),
		`SELECT EXISTS (SELECT 1 FROM payouts WHERE payout_id = $1 AND user_id = $2)`,
		payoutID, userID).Scan(&exists)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to verify payout: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify payout"})
		return
	}
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "payout not found"})
		return
	}

	resp, err := pc.makeRequest(c.Request.Context(), "GET", "/payouts/"+payoutID, nil)
	if err != nil {
		logger.ErrorLogger.Errorf("payout status request failed: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "gateway error"})
		return
	}
	defer resp.Body.Close()

	var cfResp struct {
		PayoutID string `json:"payoutId"`
		Status   string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		logger.ErrorLogger.Errorf("failed to decode payout status: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid response from gateway"})
		return
	}

	// Update DB
	if cfResp.Status != "" {
		_, err = pc.DB.Exec(c.Request.Context(),
			`UPDATE payouts SET status=$1, updated_at=NOW() WHERE payout_id=$2`,
			strings.ToLower(cfResp.Status), payoutID,
		)
		if err != nil {
			logger.ErrorLogger.Errorf("failed to update payout status: %v", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"payout_id": cfResp.PayoutID,
		"status":    strings.ToLower(cfResp.Status),
	})
}

// PayoutWebhook handles async callbacks from Cashfree
func (pc *PayoutController) PayoutWebhook(c *gin.Context) {
	var payload struct {
		PayoutID string `json:"payoutId"`
		Status   string `json:"status"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		logger.ErrorLogger.Errorf("invalid webhook payload: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid webhook payload"})
		return
	}

	if payload.PayoutID == "" {
		logger.ErrorLogger.Errorf("invalid payout_id in webhook: %s", payload.PayoutID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "valid payout_id required"})
		return
	}

	if payload.Status == "" {
		logger.ErrorLogger.Errorf("missing status in webhook for payout_id: %s", payload.PayoutID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "status required"})
		return
	}

	// Update payout status
	_, err := pc.DB.Exec(c.Request.Context(),
		`UPDATE payouts SET status=$1, updated_at=NOW() WHERE payout_id=$2`,
		strings.ToLower(payload.Status), payload.PayoutID,
	)
	if err != nil {
		logger.ErrorLogger.Errorf("failed to update webhook status for payout_id %s: %v", payload.PayoutID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process webhook"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

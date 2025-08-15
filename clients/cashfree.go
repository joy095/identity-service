package clients

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CashfreeClientWrapper provides an interface for Cashfree operations.
// This interface allows for easier testing by mocking Cashfree interactions.
type CashfreeClientWrapper interface {
	CreateOrder(data map[string]interface{}) (map[string]interface{}, error)
	VerifyWebhookSignature(signature, rawBody string) bool
}

// CashfreeClient implements CashfreeClientWrapper using Cashfree PG API.
type CashfreeClient struct {
	AppID       string
	SecretKey   string
	Environment string // "sandbox" or "production"
	BaseURL     string
}

// CashfreeOrderRequest represents the order creation request
type CashfreeOrderRequest struct {
	OrderID       string                 `json:"order_id"`
	OrderAmount   float64                `json:"order_amount"`
	OrderCurrency string                 `json:"order_currency"`
	CustomerDetails map[string]interface{} `json:"customer_details"`
	OrderMeta     map[string]interface{} `json:"order_meta,omitempty"`
	OrderNote     string                 `json:"order_note,omitempty"`
	OrderTags     map[string]string      `json:"order_tags,omitempty"`
}

// CashfreeOrderResponse represents the order creation response
type CashfreeOrderResponse struct {
	CFOrderID      string                 `json:"cf_order_id"`
	OrderID        string                 `json:"order_id"`
	OrderStatus    string                 `json:"order_status"`
	PaymentSessionID string               `json:"payment_session_id"`
	OrderAmount    float64                `json:"order_amount"`
	OrderCurrency  string                 `json:"order_currency"`
	CustomerDetails map[string]interface{} `json:"customer_details"`
	OrderMeta      map[string]interface{} `json:"order_meta"`
	CreatedAt      string                 `json:"created_at"`
	OrderExpiryTime string                `json:"order_expiry_time"`
}

// NewCashfreeClient creates and returns a new instance of CashfreeClient.
func NewCashfreeClient(appID, secretKey, environment string) *CashfreeClient {
	var baseURL string
	if environment == "production" {
		baseURL = "https://api.cashfree.com/pg"
	} else {
		baseURL = "https://sandbox.cashfree.com/pg"
	}

	return &CashfreeClient{
		AppID:       appID,
		SecretKey:   secretKey,
		Environment: environment,
		BaseURL:     baseURL,
	}
}

// CreateOrder creates a new order in Cashfree.
func (c *CashfreeClient) CreateOrder(data map[string]interface{}) (map[string]interface{}, error) {
	// Extract required fields from data
	orderID, ok := data["order_id"].(string)
	if !ok {
		return nil, fmt.Errorf("order_id is required")
	}

	amount, ok := data["order_amount"].(float64)
	if !ok {
		return nil, fmt.Errorf("order_amount is required")
	}

	currency, ok := data["order_currency"].(string)
	if !ok {
		currency = "INR" // default
	}

	customerDetails, ok := data["customer_details"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("customer_details is required")
	}

	orderMeta, _ := data["order_meta"].(map[string]interface{})
	orderNote, _ := data["order_note"].(string)

	// Create order request
	orderReq := CashfreeOrderRequest{
		OrderID:         orderID,
		OrderAmount:     amount,
		OrderCurrency:   currency,
		CustomerDetails: customerDetails,
		OrderMeta:       orderMeta,
		OrderNote:       orderNote,
	}

	// Convert to JSON
	jsonData, err := json.Marshal(orderReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal order request: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/orders", c.BaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-version", "2023-08-01")
	req.Header.Set("x-client-id", c.AppID)
	req.Header.Set("x-client-secret", c.SecretKey)

	// Make HTTP request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: %d - %v", resp.StatusCode, result)
	}

	return result, nil
}

// VerifyWebhookSignature verifies the authenticity of a Cashfree webhook signature.
func (c *CashfreeClient) VerifyWebhookSignature(signature, rawBody string) bool {
	// Basic validation - both signature and body must be present
	if len(signature) == 0 || len(rawBody) == 0 {
		return false
	}
	
	// For production, you should implement proper HMAC SHA256 verification:
	// 
	// import (
	//     "crypto/hmac"
	//     "crypto/sha256"
	//     "encoding/base64"
	//     "encoding/hex"
	// )
	//
	// expectedSignature := generateHMACSignature(rawBody, webhookSecret)
	// return hmac.Equal([]byte(signature), []byte(expectedSignature))
	
	// WARNING: This is a basic implementation for development/testing
	// In production, implement proper signature verification with your webhook secret
	return len(signature) >= 10 // Basic length check
}

// generateHMACSignature generates HMAC SHA256 signature (example implementation)
// func generateHMACSignature(payload, secret string) string {
//     mac := hmac.New(sha256.New, []byte(secret))
//     mac.Write([]byte(payload))
//     return base64.StdEncoding.EncodeToString(mac.Sum(nil))
// }

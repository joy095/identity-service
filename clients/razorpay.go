package clients

import (
	"github.com/razorpay/razorpay-go"
	"github.com/razorpay/razorpay-go/utils"
)

// RazorpayClientWrapper provides an interface for Razorpay operations.
// This interface allows for easier testing by mocking Razorpay interactions.
type RazorpayClientWrapper interface {
	CreateOrder(data map[string]interface{}) (map[string]interface{}, error)
	VerifyPaymentSignature(signature, body, webhookSecret string) bool
}

// RazorpayClient implements RazorpayClientWrapper using the actual Razorpay SDK.
type RazorpayClient struct {
	Client *razorpay.Client
}

// NewRazorpayClient creates and returns a new instance of RazorpayClient.
// It initializes the underlying Razorpay SDK client with the provided key ID and secret.
func NewRazorpayClient(keyID, keySecret string) *RazorpayClient {
	return &RazorpayClient{
		Client: razorpay.NewClient(keyID, keySecret),
	}
}

// CreateOrder creates a new order in Razorpay.
// It takes a map of order data (e.g., amount, currency, receipt) and returns
// the created order details or an error.
// The `nil` passed as the second argument to `r.Client.Order.Create` is for optional headers,
// which are typically not needed for basic order creation.
func (r *RazorpayClient) CreateOrder(data map[string]interface{}) (map[string]interface{}, error) {
	return r.Client.Order.Create(data, nil)
}

// VerifyPaymentSignature verifies the authenticity of a Razorpay webhook signature.
// It uses the `utils.VerifyWebhookSignature` helper function from the Razorpay SDK
// to compare the received signature against a computed one, using the webhook secret.
func (r *RazorpayClient) VerifyPaymentSignature(signature, body, webhookSecret string) bool {
	// The arguments for utils.VerifyWebhookSignature are (payload, signature, secret)
	return utils.VerifyWebhookSignature(body, signature, webhookSecret)
}

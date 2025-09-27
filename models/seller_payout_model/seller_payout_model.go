package seller_payout_model

import (
	"time"
)

type SellerPayout struct {
	ID              int        `json:"id" db:"id"`
	SellerID        int        `json:"seller_id" db:"seller_id"`
	Amount          float64    `json:"amount" db:"amount"`
	Status          string     `json:"status" db:"status"` // pending, approved, rejected, processed
	PaymentMethod   string     `json:"payment_method" db:"payment_method"`
	ReferenceNumber string     `json:"reference_number" db:"reference_number"`
	ProcessedAt     *time.Time `json:"processed_at,omitempty" db:"processed_at"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
	ProcessedBy     *int       `json:"processed_by,omitempty" db:"processed_by"`
	Notes           *string    `json:"notes,omitempty" db:"notes"`
}

type SellerPayoutRequest struct {
	SellerID      int     `json:"seller_id" binding:"required"`
	Amount        float64 `json:"amount" binding:"required,gt=0"`
	PaymentMethod string  `json:"payment_method" binding:"required"`
	Notes         *string `json:"notes,omitempty"`
}

type SellerPayoutResponse struct {
	ID              int        `json:"id"`
	SellerID        int        `json:"seller_id"`
	Amount          float64    `json:"amount"`
	Status          string     `json:"status"`
	PaymentMethod   string     `json:"payment_method"`
	ReferenceNumber string     `json:"reference_number"`
	CreatedAt       time.Time  `json:"created_at"`
	ProcessedAt     *time.Time `json:"processed_at,omitempty"`
	Notes           *string    `json:"notes,omitempty"`
}

const (
	PayoutStatusPending   = "pending"
	PayoutStatusApproved  = "approved"
	PayoutStatusRejected  = "rejected"
	PayoutStatusProcessed = "processed"
)

// Payout status validation
func IsValidPayoutStatus(status string) bool {
	switch status {
	case PayoutStatusPending, PayoutStatusApproved, PayoutStatusRejected, PayoutStatusProcessed:
		return true
	default:
		return false
	}
}

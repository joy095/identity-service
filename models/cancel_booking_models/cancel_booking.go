package cancel_booking_models

import (
	"time"

	"github.com/google/uuid"
)

type Booking struct {
	ID                 uuid.UUID  `json:"id"`
	OrderId            uuid.UUID  `json:"order_id"`
	Status             string     `json:"status"`
	CancelledAt        *time.Time `json:"cancelled_at,omitempty"`
	CancellationReason *string    `json:"cancellation_reason,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

type CancelBookingRequest struct {
	OrderId uuid.UUID `json:"order_id" binding:"required"`
	Reason  string    `json:"reason,omitempty"`
}

type CancelBookingResponse struct {
	Success bool     `json:"success"`
	Message string   `json:"message"`
	Data    *Booking `json:"data,omitempty"`
}
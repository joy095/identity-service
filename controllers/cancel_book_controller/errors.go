package cancel_book_controller

import "errors"

var (
	ErrBookingNotFound         = errors.New("booking not found")
	ErrBookingAlreadyCancelled = errors.New("booking is already cancelled")
	ErrBookingNotOwnedByUser   = errors.New("booking does not belong to this user")
	ErrInvalidOrderID          = errors.New("invalid order ID")
	ErrInvalidUserID           = errors.New("invalid user ID")
)

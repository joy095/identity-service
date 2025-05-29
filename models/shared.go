package models

// Location represents geographical coordinates
// type Location struct {
// 	// Latitude should be between -90 and +90
// 	Latitude float64 `json:"latitude" binding:"required,min=-90,max=90"`
// 	// Longitude should be between -180 and +180
// 	Longitude float64 `json:"longitude" binding:"required,min=-180,max=180"`
// }

// Define constants for booking status
const (
	BookingStatusPending   = "pending"
	BookingStatusConfirmed = "confirmed"
	BookingStatusCancelled = "cancelled"
	BookingStatusFailed    = "failed"
	BookingStatusRefunded  = "refunded"
)

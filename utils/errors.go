// utils/errors.go
package utils

import "errors"

var (
	ErrUserIDNotFound = errors.New("authentication required: user ID not found")
	ErrUnauthorized   = errors.New("unauthorized access")
)

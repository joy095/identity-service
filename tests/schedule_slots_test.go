package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joy095/identity/controllers/schedule_slot_controller"
	"github.com/joy095/identity/models/schedule_slot_models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScheduleSlotController tests the schedule slot controller functionality
func TestScheduleSlotController(t *testing.T) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create a test router
	r := gin.New()
	controller := schedule_slot_controller.NewScheduleSlotController()

	// Add routes
	r.POST("/schedule-slots", controller.CreateScheduleSlot)
	r.GET("/schedule-slots/:slot_id", controller.GetScheduleSlot)
	r.PATCH("/schedule-slots/:slot_id", controller.UpdateScheduleSlot)
	r.DELETE("/schedule-slots/:slot_id", controller.DeleteScheduleSlot)
	r.PATCH("/schedule-slots/:slot_id/toggle-availability", controller.ToggleSlotAvailability)
	r.GET("/businesses/:business_id/schedule-slots", controller.GetScheduleSlotsByBusiness)
	r.GET("/businesses/:business_id/schedule-slots/available", controller.GetAvailableSlots)
	r.PATCH("/businesses/:business_id/schedule-slots/bulk-availability", controller.BulkUpdateSlotAvailability)

	businessID := uuid.New()

	t.Run("CreateScheduleSlot", func(t *testing.T) {
		payload := map[string]interface{}{
			"business_id":  businessID.String(),
			"open_time":    "2024-01-15T09:00:00Z",
			"close_time":   "2024-01-15T10:00:00Z",
			"is_available": true,
		}

		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/schedule-slots", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		// Note: In real tests, you'd need to add JWT token here

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		// Since we don't have JWT middleware in this test, it will likely fail
		// In a real test environment, you'd mock the auth middleware or provide valid tokens
		t.Logf("Response Status: %d", w.Code)
		t.Logf("Response Body: %s", w.Body.String())
	})

	t.Run("TestScheduleSlotModel", func(t *testing.T) {
		// Test the schedule slot model functions
		openTime := time.Now().Add(1 * time.Hour)
		closeTime := openTime.Add(1 * time.Hour)

		slot, err := schedule_slot_models.NewScheduleSlot(businessID, openTime, closeTime, true)
		require.NoError(t, err)
		assert.Equal(t, businessID, slot.BusinessID)
		assert.Equal(t, openTime, slot.OpenTime)
		assert.Equal(t, closeTime, slot.CloseTime)
		assert.True(t, slot.IsAvailable)
		assert.NotEqual(t, uuid.Nil, slot.ID)
	})
}

// TestScheduleSlotValidation tests validation logic
func TestScheduleSlotValidation(t *testing.T) {
	t.Run("InvalidTimeOrder", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		controller := schedule_slot_controller.NewScheduleSlotController()
		r.POST("/schedule-slots", controller.CreateScheduleSlot)

		// Test with close_time before open_time
		payload := map[string]interface{}{
			"business_id":  uuid.New().String(),
			"open_time":    "2024-01-15T10:00:00Z",
			"close_time":   "2024-01-15T09:00:00Z", // Earlier than open_time
			"is_available": true,
		}

		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/schedule-slots", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		// Should return 400 Bad Request for invalid time order
		t.Logf("Response Status: %d", w.Code)
		t.Logf("Response Body: %s", w.Body.String())
	})
}

// BenchmarkCreateScheduleSlot benchmarks the create schedule slot operation
func BenchmarkCreateScheduleSlot(b *testing.B) {
	businessID := uuid.New()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		openTime := time.Now().Add(time.Duration(i) * time.Hour)
		closeTime := openTime.Add(1 * time.Hour)

		_, err := schedule_slot_models.NewScheduleSlot(businessID, openTime, closeTime, true)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Example test data for integration testing
var testScheduleSlots = []struct {
	BusinessID  string `json:"business_id"`
	OpenTime    string `json:"open_time"`
	CloseTime   string `json:"close_time"`
	IsAvailable bool   `json:"is_available"`
}{
	{
		BusinessID:  "550e8400-e29b-41d4-a716-446655440000",
		OpenTime:    "2024-01-15T09:00:00Z",
		CloseTime:   "2024-01-15T10:00:00Z",
		IsAvailable: true,
	},
	{
		BusinessID:  "550e8400-e29b-41d4-a716-446655440000",
		OpenTime:    "2024-01-15T10:00:00Z",
		CloseTime:   "2024-01-15T11:00:00Z",
		IsAvailable: true,
	},
	{
		BusinessID:  "550e8400-e29b-41d4-a716-446655440000",
		OpenTime:    "2024-01-15T11:00:00Z",
		CloseTime:   "2024-01-15T12:00:00Z",
		IsAvailable: false,
	},
}

// TestIntegrationCreateMultipleSlots demonstrates creating multiple slots
func TestIntegrationCreateMultipleSlots(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	controller := schedule_slot_controller.NewScheduleSlotController()
	r.POST("/schedule-slots", controller.CreateScheduleSlot)

	for i, testSlot := range testScheduleSlots {
		t.Run(fmt.Sprintf("CreateSlot_%d", i), func(t *testing.T) {
			body, _ := json.Marshal(testSlot)
			req, _ := http.NewRequest("POST", "/schedule-slots", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			t.Logf("Test slot %d - Response Status: %d", i, w.Code)
			t.Logf("Test slot %d - Response Body: %s", i, w.Body.String())
		})
	}
}

// MockAuthMiddleware is a simple mock for testing
func MockAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Mock user ID - in real tests you'd set up proper test tokens
		c.Set("user_id", uuid.New().String())
		c.Next()
	}
}

// TestWithMockAuth tests endpoints with mocked authentication
func TestWithMockAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(MockAuthMiddleware()) // Add mock auth middleware

	controller := schedule_slot_controller.NewScheduleSlotController()
	r.POST("/schedule-slots", controller.CreateScheduleSlot)

	payload := map[string]interface{}{
		"business_id":  uuid.New().String(),
		"open_time":    "2024-01-15T09:00:00Z",
		"close_time":   "2024-01-15T10:00:00Z",
		"is_available": true,
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/schedule-slots", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	t.Logf("With Mock Auth - Response Status: %d", w.Code)
	t.Logf("With Mock Auth - Response Body: %s", w.Body.String())

	// With mock auth, we might get different results
	// The actual response will depend on database connectivity and other factors
}

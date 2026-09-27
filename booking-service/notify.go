package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Booking events Notification Service accepts on POST /internal/events
// (see notification-service/EVENTS.md). There is no cancel event there yet.
const (
	EventBookingCreated  = "booking.created"
	EventBookingApproved = "booking.approved"
	EventBookingRejected = "booking.rejected"
)

// notify sends a booking event to Notification Service's internal endpoint.
// This stands in for a real event bus (Kafka/RabbitMQ) for this project:
// it's a direct, best-effort HTTP call inside the Docker network (not via
// Kong), so a down Notification Service never blocks a booking action.
// Call it with `go notify(...)` after the DB write succeeds.
func notify(event string, b Booking, facilityName string) {
	baseURL := strings.TrimRight(os.Getenv("NOTIFICATION_SERVICE_URL"), "/")
	if baseURL == "" {
		return // Notification Service not wired up yet; skip silently.
	}

	rejectReason := ""
	if b.RejectReason != nil {
		rejectReason = *b.RejectReason
	}
	payload := map[string]interface{}{
		"event":         event,
		"booking_id":    b.ID,
		"user_id":       b.UserID, // booking owner, not the STAFF who approved
		"facility_id":   b.FacilityID,
		"facility_name": facilityName,
		"date":          normalizeDate(b.Date),
		"start_time":    normalizeTimeOfDay(b.StartTime),
		"end_time":      normalizeTimeOfDay(b.EndTime),
		"reject_reason": rejectReason,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("notify %s: failed to encode payload: %v", event, err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/internal/events", bytes.NewReader(body))
	if err != nil {
		log.Printf("notify %s: %v", event, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", os.Getenv("INTERNAL_API_KEY"))

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("notify %s: notification service unreachable: %v", event, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("notify %s: notification service returned status %d", event, resp.StatusCode)
	}
}

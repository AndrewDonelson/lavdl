package api

import (
	"testing"
	"time"
)

// TestIPCounter_MinuteReset covers the minute-reset branch in allow():
// when now.After(c.minuteReset), the minute counter and reset time are refreshed.
func TestIPCounter_MinuteReset(t *testing.T) {
	c := &ipCounter{
		minuteReset: time.Now().Add(-2 * time.Second),
		hourReset:   time.Now().Add(time.Hour),
		minuteCount: 50,
	}

	ok, _ := c.allow()
	if !ok {
		t.Error("expected allow() to return true after minute reset")
	}
}

// TestIPCounter_HourReset covers the hour-reset branch in allow():
// when now.After(c.hourReset), the hour counter and reset time are refreshed.
func TestIPCounter_HourReset(t *testing.T) {
	c := &ipCounter{
		minuteReset: time.Now().Add(time.Minute),
		hourReset:   time.Now().Add(-2 * time.Second),
		hourCount:   500,
	}

	ok, _ := c.allow()
	if !ok {
		t.Error("expected allow() to return true after hour reset")
	}
}

// TestIPCounter_HourLimit covers the hour-limit branch in allow():
// when hourCount >= ratePerHour, allow() returns false with a retry duration.
func TestIPCounter_HourLimit(t *testing.T) {
	c := &ipCounter{
		minuteReset: time.Now().Add(time.Minute),
		hourReset:   time.Now().Add(time.Hour),
		minuteCount: 0,
		hourCount:   ratePerHour,
	}

	ok, retryAfter := c.allow()
	if ok {
		t.Error("expected allow() to return false when hourCount >= ratePerHour")
	}
	if retryAfter <= 0 {
		t.Errorf("expected positive retry duration, got %v", retryAfter)
	}
}

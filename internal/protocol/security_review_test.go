package protocol

import "testing"

// TestLogsAreSubscriptionOnly prevents log-opt-in arguments from crossing into
// unrelated helper operations while allowing both ordinary and diagnostic subscribers.
func TestLogsAreSubscriptionOnly(t *testing.T) {
	for _, r := range []Request{{ID: "1", Op: "subscribe"}, {ID: "1", Op: "subscribe", Logs: true}} {
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if (Request{ID: "1", Op: "status", Logs: true}).Validate() == nil {
		t.Fatal("logs flag accepted for status")
	}
}

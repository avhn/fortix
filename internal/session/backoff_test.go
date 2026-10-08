package session

import (
	"math"
	"testing"
	"time"
)

// TestBackoffDelay checks exponential steps, jitter extremes, invalid samples, custom
// bounds, and integer saturation. All outcomes must remain in the 1s..60s interval.
func TestBackoffDelay(t *testing.T) {
	cases := []struct {
		name   string
		policy BackoffPolicy
		retry  uint32
		sample float64
		want   time.Duration
	}{
		{"first", BackoffPolicy{}, 0, 0.5, time.Second},
		{"second", BackoffPolicy{}, 1, 0.5, 2 * time.Second},
		{"third", BackoffPolicy{}, 2, 0.5, 4 * time.Second},
		{"jitter low", BackoffPolicy{}, 2, 0, 3200 * time.Millisecond},
		{"jitter high", BackoffPolicy{}, 2, 1, 4800 * time.Millisecond},
		{"minimum", BackoffPolicy{}, 0, 0, time.Second},
		{"saturation", BackoffPolicy{}, 20, 0.5, 60 * time.Second},
		{"saturation high", BackoffPolicy{}, ^uint32(0), 1, 60 * time.Second},
		{"saturation jitter low", BackoffPolicy{}, ^uint32(0), 0, 48 * time.Second},
		{"nan sample", BackoffPolicy{}, 1, math.NaN(), 2 * time.Second},
		{"infinite sample", BackoffPolicy{}, 1, math.Inf(1), 2 * time.Second},
		{"negative sample", BackoffPolicy{}, 1, -1, 2 * time.Second},
		{"invalid policy", BackoffPolicy{-time.Second, -time.Second, math.NaN()}, 1, 0.5, 2 * time.Second},
		{"huge policy", BackoffPolicy{time.Hour, time.Hour, 2}, 1, 0.5, 2 * time.Second},
		{"custom", BackoffPolicy{2 * time.Second, 10 * time.Second, 0.5}, 1, 1, 6 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.Delay(tc.retry, tc.sample); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
	for retry := uint32(0); retry < 100; retry++ {
		for _, sample := range []float64{0, 0.25, 0.5, 0.75, 1} {
			if delay := (BackoffPolicy{}).Delay(retry, sample); delay < time.Second || delay > 60*time.Second {
				t.Fatalf("unsafe delay %s", delay)
			}
		}
	}
}

package session

import (
	"math"
	"time"
)

// BackoffPolicy specifies exponential transport retry bounds and symmetric jitter.
// Its zero value means 1s minimum, 60s maximum, and 20 percent jitter. Invalid fields
// are replaced or clamped to these safety bounds, so retries cannot busy-loop.
type BackoffPolicy struct {
	Minimum time.Duration
	Maximum time.Duration
	Jitter  float64
}

// normalized returns a valid policy confined to the 1s..60s safety interval.
// Zero jitter selects the default; positive jitter up to one adjusts its fraction.
// NaN and infinite values are defaulted, avoiding invalid duration conversions.
func (p BackoffPolicy) normalized() BackoffPolicy {
	if p.Minimum < time.Second || p.Minimum > 60*time.Second {
		p.Minimum = time.Second
	}
	if p.Maximum < p.Minimum || p.Maximum > 60*time.Second {
		p.Maximum = 60 * time.Second
	}
	if p.Jitter <= 0 || p.Jitter > 1 || math.IsNaN(p.Jitter) {
		p.Jitter = 0.2
	}
	return p
}

// Delay returns the zero-based retry's exponential delay with sample in [0,1].
// It clamps invalid samples to neutral jitter and the final result to policy bounds.
// retry saturates before shifting, so even the largest integer cannot overflow.
func (p BackoffPolicy) Delay(retry uint32, sample float64) time.Duration {
	p = p.normalized()
	if sample < 0 || sample > 1 || math.IsNaN(sample) {
		sample = 0.5
	}
	base := p.Minimum
	for i := uint32(0); i < retry && base < p.Maximum; i++ {
		if base > p.Maximum/2 {
			base = p.Maximum
			break
		}
		base *= 2
	}
	delay := float64(base) * (1 + (2*sample-1)*p.Jitter)
	if delay < float64(p.Minimum) {
		return p.Minimum
	}
	if delay > float64(p.Maximum) {
		return p.Maximum
	}
	return time.Duration(delay)
}

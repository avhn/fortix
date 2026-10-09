package helper

import (
	"context"
	"errors"

	"github.com/avhn/fortix/internal/backend"
)

// openfortivpnUnavailable is shared by admission and transport refusal paths.
const openfortivpnUnavailable = "openfortivpn is not available on Windows; use the native backend"

// openfortivpnBackend retains the shared actor construction surface without spawning a process.
type openfortivpnBackend struct{ actor *supervisor }

// Start always refuses before credential exchange or operating-system mutation.
func (openfortivpnBackend) Start(context.Context, backend.Attempt) (backend.Tunnel, error) {
	return nil, errors.New(openfortivpnUnavailable)
}

// Package tray forwards desktop clicks with explicit per-item cancellation.
package tray

import "context"

// forwardClicks relays an item's literal action ID until shutdown, removal, or
// toolkit channel closure. Removal also unblocks a pending send to a busy controller;
// the caller joins this worker before destroying desktop resources. It cannot fail.
func forwardClicks(ctx context.Context, removed <-chan struct{}, clicked <-chan struct{}, actions chan<- string, id string) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-removed:
			return
		case _, ok := <-clicked:
			if !ok {
				return
			}
			select {
			case actions <- id:
			case <-removed:
				return
			case <-ctx.Done():
				return
			}
		}
	}
}

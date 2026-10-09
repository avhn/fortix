package tray

import (
	"context"
	"errors"
)

// runDesktop refuses the Unix tray; Windows uses its separate native desktop application.
func runDesktop(context.Context, Options) error {
	return errors.New("fortix-tray is not available on Windows; use FortixApp.exe")
}

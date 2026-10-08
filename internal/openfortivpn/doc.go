// Package openfortivpn builds bounded commands and interprets VPN and pinentry output.
// It never executes a child, modifies networking, or stores account credentials.
// Malformed commands return errors; unknown stdout remains diagnostic event data.
package openfortivpn

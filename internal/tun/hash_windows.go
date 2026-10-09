package tun

import "io"

// VerifyWintunHash lets the installer enforce the same release pin as the runtime loader.
// The reader is bounded by the verifier and no DLL code is loaded during installation.
func VerifyWintunHash(reader io.Reader, arch string) error { return verifyWintunHash(reader, arch) }

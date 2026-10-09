module github.com/avhn/fortix/windows/vectors

go 1.26.0

require github.com/avhn/fortix v0.0.0

require (
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/zalando/go-keyring v0.2.8 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/avhn/fortix => ../..

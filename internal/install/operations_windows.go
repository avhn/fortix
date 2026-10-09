package install

import (
	"context"
	"os"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/winfs"
)

// installOps keeps transaction mutations and their compensations injectable without global overrides.
type installOps struct {
	createDirectory   func(string, winfs.Policy) (*winfs.Root, bool, error)
	closeRoot         func(*winfs.Root) error
	removeDirectory   func(string) error
	removePrivateTree func(string, winfs.Policy) error
	protectedBytes    func(*winfs.Root, string, winfs.Policy) ([]byte, bool, error)
	saveManifest      func(*winfs.Root, context.Context, string, []byte, winfs.Policy) error
	removeProtected   func(*winfs.Root, string, string, winfs.Policy) error
	publish           func(context.Context, *winfs.Root, string, string, []byte, winfs.Policy) error
	ensureGroup       func() (bool, error)
	deleteGroup       func() error
	changeMember      func(*windows.SID, bool) (bool, error)
	createService     func(windows.Handle, string) (windows.Handle, error)
	configureService  func(windows.Handle) error
	deleteService     func(windows.Handle) error
	closeService      func(windows.Handle) error
	startService      func(context.Context, windows.Handle) error
	stopService       func(context.Context, windows.Handle) error
	queryService      func(windows.Handle) (windows.SERVICE_STATUS, error)
	readDirectory     func(string) ([]os.DirEntry, error)
}

// nativeInstallOps binds the production transaction to protected filesystem and least-access SCM calls.
func nativeInstallOps() installOps {
	return installOps{
		createDirectory:   createDirectory,
		closeRoot:         (*winfs.Root).Close,
		removeDirectory:   os.Remove,
		removePrivateTree: removePrivateTree,
		protectedBytes:    protectedBytes,
		saveManifest:      (*winfs.Root).AtomicWrite,
		removeProtected:   removeProtected,
		publish:           publish,
		ensureGroup:       ensureGroup,
		deleteGroup:       deleteGroup,
		changeMember:      changeMember,
		createService: func(manager windows.Handle, directory string) (windows.Handle, error) {
			return createHelperService(nativeSCM{}, manager, directory)
		},
		configureService: configureService,
		deleteService:    windows.DeleteService,
		closeService:     windows.CloseServiceHandle,
		startService:     startService,
		stopService:      stopService,
		queryService:     queryService,
		readDirectory:    os.ReadDir,
	}
}

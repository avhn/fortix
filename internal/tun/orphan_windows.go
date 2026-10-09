package tun

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// RemoveOrphan removes only a Net-class Wintun device with the recorded instance
// GUID. The caller must first validate its durable allocation ledger and finish
// DNS, route and address teardown. Absence succeeds; unreadable Wintun GUIDs fail.
// DIF_REMOVE removes the device instance, never the installed Wintun driver.
func RemoveOrphan(guid windows.GUID) error {
	if guid == (windows.GUID{}) {
		return errors.New("empty wintun allocation GUID")
	}
	netClass := windows.GUID{Data1: 0x4d36e972, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
	// Include nonpresent devices because a crash can leave an unstarted instance.
	devices, err := windows.SetupDiGetClassDevsEx(&netClass, `SWD\Wintun`, 0, 0, 0, "")
	if err != nil {
		return err
	}
	defer windows.SetupDiDestroyDeviceInfoList(devices)
	var match *windows.DevInfoData
	for i := 0; ; i++ {
		device, err := windows.SetupDiEnumDeviceInfo(devices, i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			break
		}
		if err != nil {
			return err
		}
		// Foreign or unreadable service entries cannot establish Wintun ownership.
		// Skip them before opening driver keys, including stale phantom devices.
		if err := verifyWintunInstance(devices, device); err != nil {
			continue
		}
		// Once Wintun ownership is known, an unreadable GUID must fail closed.
		id, err := adapterInstanceGUID(devices, device)
		if err != nil {
			return err
		}
		if id != guid {
			continue
		}
		if match != nil {
			return errors.New("ambiguous wintun allocation GUID")
		}
		match = device
	}
	if match == nil {
		return nil
	}
	// Recheck ownership immediately before the destructive device-instance call.
	id, err := adapterInstanceGUID(devices, match)
	if err != nil {
		return err
	}
	if id != guid {
		return errors.New("wintun instance identity changed")
	}
	if err := verifyWintunInstance(devices, match); err != nil {
		return err
	}
	params := windows.RemoveDeviceParams{ClassInstallHeader: *windows.MakeClassInstallHeader(windows.DIF_REMOVE), Scope: windows.DI_REMOVEDEVICE_GLOBAL}
	if err := windows.SetupDiSetClassInstallParams(devices, match, &params.ClassInstallHeader, uint32(unsafe.Sizeof(params))); err != nil {
		return err
	}
	return windows.SetupDiCallClassInstaller(windows.DIF_REMOVE, devices, match)
}

// adapterInstanceGUID reads the network configuration identity from the device's
// own driver key using query-only access and a bounded UTF-16 buffer.
func adapterInstanceGUID(devices windows.DevInfo, device *windows.DevInfoData) (windows.GUID, error) {
	key, err := windows.SetupDiOpenDevRegKey(devices, device, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
	if err != nil {
		return windows.GUID{}, err
	}
	defer windows.RegCloseKey(key)
	name, _ := windows.UTF16PtrFromString("NetCfgInstanceId")
	var value [128]uint16
	size := uint32(unsafe.Sizeof(value))
	var kind uint32
	err = windows.RegQueryValueEx(key, name, nil, &kind, (*byte)(unsafe.Pointer(&value[0])), &size)
	if err != nil {
		return windows.GUID{}, err
	}
	if kind != windows.REG_SZ || size < 2 || size > uint32(unsafe.Sizeof(value)) || size%2 != 0 || value[size/2-1] != 0 {
		return windows.GUID{}, errors.New("invalid network instance GUID value")
	}
	return windows.GUIDFromString(windows.UTF16ToString(value[:size/2]))
}

// verifyWintunInstance refuses to remove a matching GUID owned by another driver.
func verifyWintunInstance(devices windows.DevInfo, device *windows.DevInfoData) error {
	service, err := windows.SetupDiGetDeviceRegistryProperty(devices, device, windows.SPDRP_SERVICE)
	if err != nil {
		return err
	}
	name, ok := service.(string)
	if !ok || !strings.EqualFold(name, "wintun") {
		return fmt.Errorf("network instance is not driven by wintun")
	}
	return nil
}

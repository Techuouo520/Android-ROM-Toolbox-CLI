package hardware

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"unsafe"
)

// Native queries answer in milliseconds; the PowerShell CIM query they replace took 1.4 s on a desktop and hit its 5 s limit on a Windows ARM64 device.

const (
	digcfPresent                = 0x2
	digcfDeviceInterface        = 0x10
	spdrpDeviceDesc             = 0x0
	spdrpFriendlyName           = 0xC
	ioctlDiskGetDriveGeometryEx = 0x700A0
	ioctlStorageGetDeviceNumber = 0x2D1080
	// SP_DEVICE_INTERFACE_DETAIL_DATA_W is a DWORD and one WCHAR padded to 8 bytes on 64-bit Windows, the only kind artb targets.
	interfaceDetailSize = 8
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procGlobalMemoryStatus = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemDirectory = kernel32.NewProc("GetSystemDirectoryW")
	displayClass           = syscall.GUID{Data1: 0x4d36e968, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
	diskInterface          = syscall.GUID{Data1: 0x53f56307, Data2: 0xb6bf, Data3: 0x11d0, Data4: [8]byte{0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b}}
)

type memoryStatus struct {
	length    uint32
	load      uint32
	totalPhys uint64
	rest      [6]uint64
}

type devInfoData struct {
	size     uint32
	class    syscall.GUID
	instance uint32
	reserved uintptr
}

type interfaceData struct {
	size     uint32
	class    syscall.GUID
	flags    uint32
	reserved uintptr
}

type setupAPI struct {
	getClassDevs, enumDeviceInfo, enumInterfaces, interfaceDetail, registryProperty, destroyList *syscall.Proc
}

type numberedDisk struct {
	Disk
	number uint32
}

func Collect(ctx context.Context) (Info, error) {
	if err := ctx.Err(); err != nil {
		return Info{}, err
	}
	var info Info
	var errs []error
	info.CPUModel = cpuModel()
	status := memoryStatus{length: uint32(unsafe.Sizeof(memoryStatus{}))}
	if result, _, err := procGlobalMemoryStatus.Call(uintptr(unsafe.Pointer(&status))); result == 0 {
		errs = append(errs, fmt.Errorf("GlobalMemoryStatusEx: %w", err))
	} else {
		info.MemoryBytes = status.totalPhys
	}
	api, err := loadSetupAPI()
	if err != nil {
		return info, errors.Join(append(errs, err)...)
	}
	if info.GPUs, err = api.displayAdapters(); err != nil {
		errs = append(errs, err)
	}
	if info.Disks, err = api.disks(); err != nil {
		errs = append(errs, err)
	}
	return info, errors.Join(errs...)
}

// cpuModel reads the name Win32_Processor reports, once per distinct model across the logical processors.
func cpuModel() string {
	root, err := openKey(syscall.HKEY_LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor`)
	if err != nil {
		return ""
	}
	defer syscall.RegCloseKey(root)
	var names []string
	for index := uint32(0); ; index++ {
		name := make([]uint16, 64)
		length := uint32(len(name))
		if syscall.RegEnumKeyEx(root, index, &name[0], &length, nil, nil, nil, nil) != nil {
			break
		}
		key, err := openKey(root, syscall.UTF16ToString(name[:length]))
		if err != nil {
			continue
		}
		if model := CleanName(registryString(key, "ProcessorNameString")); model != "" && !slices.Contains(names, model) {
			names = append(names, model)
		}
		syscall.RegCloseKey(key)
	}
	return strings.Join(names, "; ")
}

func openKey(parent syscall.Handle, path string) (syscall.Handle, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var key syscall.Handle
	return key, syscall.RegOpenKeyEx(parent, name, 0, syscall.KEY_READ, &key)
}

func registryString(key syscall.Handle, value string) string {
	name, err := syscall.UTF16PtrFromString(value)
	if err != nil {
		return ""
	}
	var kind, size uint32
	if syscall.RegQueryValueEx(key, name, nil, &kind, nil, &size) != nil || kind != syscall.REG_SZ || size < 2 {
		return ""
	}
	buffer := make([]uint16, size/2)
	if syscall.RegQueryValueEx(key, name, nil, &kind, (*byte)(unsafe.Pointer(&buffer[0])), &size) != nil {
		return ""
	}
	return syscall.UTF16ToString(buffer)
}

// loadSetupAPI opens setupapi.dll by its System32 path so a same-named DLL next to artb is never loaded.
func loadSetupAPI() (*setupAPI, error) {
	directory := make([]uint16, syscall.MAX_PATH)
	length, _, err := procGetSystemDirectory.Call(uintptr(unsafe.Pointer(&directory[0])), uintptr(len(directory)))
	if length == 0 || length >= uintptr(len(directory)) {
		return nil, fmt.Errorf("GetSystemDirectory: %w", err)
	}
	dll, err := syscall.LoadDLL(filepath.Join(syscall.UTF16ToString(directory[:length]), "setupapi.dll"))
	if err != nil {
		return nil, err
	}
	api := &setupAPI{}
	for name, proc := range map[string]**syscall.Proc{"SetupDiGetClassDevsW": &api.getClassDevs, "SetupDiEnumDeviceInfo": &api.enumDeviceInfo, "SetupDiEnumDeviceInterfaces": &api.enumInterfaces, "SetupDiGetDeviceInterfaceDetailW": &api.interfaceDetail, "SetupDiGetDeviceRegistryPropertyW": &api.registryProperty, "SetupDiDestroyDeviceInfoList": &api.destroyList} {
		if *proc, err = dll.FindProc(name); err != nil {
			return nil, err
		}
	}
	return api, nil
}

func (api *setupAPI) deviceSet(class *syscall.GUID, flags uintptr) (uintptr, error) {
	set, _, err := api.getClassDevs.Call(uintptr(unsafe.Pointer(class)), 0, 0, flags)
	if set == uintptr(syscall.InvalidHandle) {
		return 0, fmt.Errorf("SetupDiGetClassDevs: %w", err)
	}
	return set, nil
}

// deviceName prefers the friendly name and falls back to the device description, matching Win32_PnPEntity.Name.
func (api *setupAPI) deviceName(set uintptr, device *devInfoData) string {
	for _, property := range []uintptr{spdrpFriendlyName, spdrpDeviceDesc} {
		buffer := make([]uint16, 512)
		if result, _, _ := api.registryProperty.Call(set, uintptr(unsafe.Pointer(device)), property, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)*2), 0); result != 0 {
			if name := CleanName(syscall.UTF16ToString(buffer)); name != "" {
				return name
			}
		}
	}
	return ""
}

func (api *setupAPI) displayAdapters() ([]string, error) {
	set, err := api.deviceSet(&displayClass, digcfPresent)
	if err != nil {
		return nil, fmt.Errorf("display adapters: %w", err)
	}
	defer api.destroyList.Call(set)
	var names []string
	for index := uintptr(0); ; index++ {
		device := devInfoData{size: uint32(unsafe.Sizeof(devInfoData{}))}
		if result, _, _ := api.enumDeviceInfo.Call(set, index, uintptr(unsafe.Pointer(&device))); result == 0 {
			return names, nil
		}
		if name := api.deviceName(set, &device); name != "" {
			names = append(names, name)
		}
	}
}

// disks lists present disks in PhysicalDrive order; sizes are the full capacity rather than Win32_DiskDrive's cylinder-rounded value.
func (api *setupAPI) disks() ([]Disk, error) {
	set, err := api.deviceSet(&diskInterface, digcfPresent|digcfDeviceInterface)
	if err != nil {
		return nil, fmt.Errorf("disks: %w", err)
	}
	defer api.destroyList.Call(set)
	var found []numberedDisk
	for index := uintptr(0); ; index++ {
		entry := interfaceData{size: uint32(unsafe.Sizeof(interfaceData{}))}
		if result, _, _ := api.enumInterfaces.Call(set, 0, uintptr(unsafe.Pointer(&diskInterface)), index, uintptr(unsafe.Pointer(&entry))); result == 0 {
			break
		}
		var required uint32
		api.interfaceDetail.Call(set, uintptr(unsafe.Pointer(&entry)), 0, 0, uintptr(unsafe.Pointer(&required)), 0)
		if required <= interfaceDetailSize {
			continue
		}
		detail := make([]uint64, (required+7)/8)
		*(*uint32)(unsafe.Pointer(&detail[0])) = interfaceDetailSize
		device := devInfoData{size: uint32(unsafe.Sizeof(devInfoData{}))}
		if result, _, _ := api.interfaceDetail.Call(set, uintptr(unsafe.Pointer(&entry)), uintptr(unsafe.Pointer(&detail[0])), uintptr(required), 0, uintptr(unsafe.Pointer(&device))); result == 0 {
			continue
		}
		path := unsafe.Slice((*uint16)(unsafe.Add(unsafe.Pointer(&detail[0]), 4)), (uintptr(required)-4)/2)
		model := api.deviceName(set, &device)
		number, size, ok := diskGeometry(&path[0])
		if model != "" && ok {
			found = append(found, numberedDisk{Disk{Model: model, SizeBytes: size}, number})
		}
	}
	slices.SortStableFunc(found, func(a, b numberedDisk) int { return cmp.Compare(a.number, b.number) })
	disks := make([]Disk, len(found))
	for i := range found {
		disks[i] = found[i].Disk
	}
	return disks, nil
}

// diskGeometry opens the disk without read or write access, which both IOCTLs accept without administrator rights.
func diskGeometry(path *uint16) (uint32, uint64, bool) {
	handle, err := syscall.CreateFile(path, 0, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return 0, 0, false
	}
	defer syscall.CloseHandle(handle)
	var geometry [32]uint64
	var returned uint32
	// DISK_GEOMETRY_EX holds the 24-byte DISK_GEOMETRY followed by the DiskSize LARGE_INTEGER.
	if syscall.DeviceIoControl(handle, ioctlDiskGetDriveGeometryEx, nil, 0, (*byte)(unsafe.Pointer(&geometry[0])), uint32(unsafe.Sizeof(geometry)), &returned, nil) != nil || returned < 32 {
		return 0, 0, false
	}
	var number [3]uint32
	if syscall.DeviceIoControl(handle, ioctlStorageGetDeviceNumber, nil, 0, (*byte)(unsafe.Pointer(&number[0])), uint32(unsafe.Sizeof(number)), &returned, nil) != nil {
		number[1] = ^uint32(0)
	}
	return number[1], geometry[3], true
}

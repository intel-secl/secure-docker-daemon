package losetup

import (
	"fmt"
	"os"
	"bytes"
	"path/filepath"
	"golang.org/x/sys/unix"
	"github.com/Sirupsen/logrus"
)

// Add will add a loopback device if it does not exist already.
func (device Device) Add() error {
	ctrl, err := os.OpenFile(LoopControlPath, os.O_RDWR, 0660)
	if err != nil {
		return fmt.Errorf("could not open %v: %v", LoopControlPath, err)
	}
	defer ctrl.Close()
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, ctrl.Fd(), CtlAdd, uintptr(device.number))
	if errno == unix.EEXIST {
		return fmt.Errorf("device already exits")
	}
	if errno != 0 {
		return fmt.Errorf("could not add device (err: %d): %v", errno, errno)
	}
	return nil
}

// Remove will remove a loopback device if it is not busy.
func (device Device) Remove() error {
	ctrl, err := os.OpenFile(LoopControlPath, os.O_RDWR, 0660)
	if err != nil {
		return fmt.Errorf("could not open %v: %v", LoopControlPath, err)
	}
	defer ctrl.Close()
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, ctrl.Fd(), CtlRemove, uintptr(device.number))
	if errno == unix.EBUSY {
		return fmt.Errorf("could not remove, device in use")
	}
	if errno != 0 {
		return fmt.Errorf("could not remove (err: %d): %v", errno, errno)
	}
	return nil
}

// GetFree searches for the first free loopback device. If it cannot find one,
// it will attempt to create one. If anything fails, GetFree will return an
// error.
func GetFree() (Device, error) {
	ctrl, err := os.OpenFile(LoopControlPath, os.O_RDWR, 0660)
	if err != nil {
		return Device{}, fmt.Errorf("could not open %v: %v", LoopControlPath, err)
	}
	defer ctrl.Close()
	dev, _, errno := unix.Syscall(unix.SYS_IOCTL, ctrl.Fd(), CtlGetFree, 0)
	if dev < 0 {
		return Device{}, fmt.Errorf("could not get free device (err: %d): %v", errno, errno)
	}
	return Device{number: uint64(dev), flags: os.O_RDWR}, nil
}

// Attach attaches backingFile to the loopback device starting at offset. If ro
// is true, then the file is attached read only.
func Attach(backingFile string, offset uint64, ro bool) (Device, error) {
	var dev Device

	absPath, err := filepath.Abs(backingFile)
	if err != nil { return dev, err }

	// check if backing file is already mounted
	dev, err = GetDeviceFromBackingFilePath(absPath)
	if err == nil {
		// in such a case we might be tempted to return the same loop device (see below) but
		// this would almost certainly give problems on detach. This is better handled further up.
		// However, as some code might use GetDeviceFromBackingFilePath to find a device to detach, we
		// give corresponding warnings.
		// TODO: re-asses cost of this, might want to remove it eventually
		conflictPath := ""
		if info, err := dev.GetInfo(); err == nil {
			conflictPath = string(bytes.Trim(info.FileName[:], "\x00"))
		}
		logrus.Warningf("losetup: Attach of path %s might duplicate already attached (potentially truncated) path %s mapped to device %s  ", absPath, conflictPath, dev.Path())
 		// logrus.Debugf("losetup: Attach trying to reuse loop-device %s for path %s", dev.Path(), absPath)

		// flagCheck := os.O_RDWR
		// if ro { flagCheck = os.O_RDONLY }

		// if int(flagCheck) != dev.flags {
		// 	d := Device{}
		// 	e := fmt.Errorf("Flags mismatch! Device flags: %d, given flags: %d", dev.flags, flagCheck)
		// 	_, _ = d, e
		// 	return d, e
		// }
		// return dev, nil
	}

	flags := os.O_RDWR
	if ro {
		flags = os.O_RDONLY
	}

	back, err := os.OpenFile(absPath, flags, 0660)
	if err != nil {
		return dev, fmt.Errorf("could not open backing file: %v", err)
	}
	defer back.Close()

	dev, err = GetFree()
	if err != nil {
		return dev, err
	}
	dev.flags = flags

	loopFile, err := dev.open()
	if err != nil {
		return dev, fmt.Errorf("could not open loop device: %v", err)
	}
	defer loopFile.Close()

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, loopFile.Fd(), SetFd, back.Fd())
	if errno == 0 {
		info := Info{}
		copy(info.FileName[:], []byte(absPath))
		info.Offset = offset
		info.Flags = uint32(flags)
		if err := setInfo(loopFile.Fd(), info); err != nil {
			unix.Syscall(unix.SYS_IOCTL, loopFile.Fd(), ClrFd, 0)
			return dev, fmt.Errorf("could not set info")
		}
	}

	return dev, nil
}

// Detach removes the file backing the device.
func (device Device) Detach() error {

	loopFile, err := os.OpenFile(device.Path(), os.O_RDONLY, 0660)
	if err != nil {
		return fmt.Errorf("could not open loop device")
	}
	defer loopFile.Close()

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, loopFile.Fd(), ClrFd, 0)
	if errno != 0 {
		return fmt.Errorf("error clearing loopfile: %v", errno)
	}

	return nil
}

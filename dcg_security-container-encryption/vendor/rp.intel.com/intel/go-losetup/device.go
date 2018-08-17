//AUTHOR: Divya Desai <divyax.desai@intel.com>


/*Copyright © 2018 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package losetup

import (
	"strings"
	"fmt"
	"os"
	"io/ioutil"
	"path/filepath"
	"github.com/Sirupsen/logrus"
)

// Device represents a loop device /dev/loop#
type Device struct {
	// device number (i.e. 7 if /dev/loop7)
	number uint64

	// flags with which to open the device with
	flags int
}

// open returns a file handle to /dev/loop# and returns an error if it cannot
// be opened.
func (device Device) open() (*os.File, error) {
	return os.OpenFile(device.Path(), device.flags, 0660)
}

// Path returns the path to the loopback device
func (device Device) Path() string {
	return fmt.Sprintf(DeviceFormatString, device.number)
}

// search device using backing file path.
func GetDeviceFromBackingFilePath(backingFile string) (Device, error) {
	absPath, err := filepath.Abs(backingFile)
	if err != nil { return Device{}, err }

	// iterate through all the devices to match given backing file
	// we cannot use dev.GetInfo as it returns only 64 byte prefix, so we look for backing file
	// via /sys/dev/block/<lo-dev-maj-num>:<lo-dev-num>/loop/backing_file
	// Note and assumptions
	// - lo-dev-maj-num = 7 = Major in Constants.go
        // - /sys/dev/block/7:<lo-dev-num> always exists when loop device is created/used at least once
        //   - we assume there is no gap in assignement, i.e., everybody requests lowest-possible number
	//     and so we assume there is no loop device with higher <lo-dev-num> once we hit the
	//     first non-existing one
        // - suffix loop/backing_file exists only if loop-device is allocated
        //   - name in backing_file might have '(deleted)' suffix!
	//     This shouldn't happen in our case, though?

	for i:=0;; i++ {
		devDirInSys := fmt.Sprintf("/sys/dev/block/%d:%d", Major, i)
		if _, err := os.Stat(devDirInSys); os.IsNotExist(err) {
			// logrus.Debugf("losetup: GetDeviceFromBackingFilePath stopped searching with last device %d (%s)", i, devDirInSys)
			break
		}
		backFileFileName := fmt.Sprintf("%s/loop/backing_file", devDirInSys)
		if _, err := os.Stat(backFileFileName); os.IsNotExist(err) {
			// logrus.Debugf("losetup: GetDeviceFromBackingFilePath unallocated device %d (%s)", i, devDirInSys)
			continue
		}
		backFileNameBuf, err := ioutil.ReadFile(backFileFileName)
		if err != nil {
			logrus.Errorf("losetup: GetDeviceFromBackingFilePath failed to read %s to get backing file for allocated device %d (%s): err=%v", backFileFileName, i, devDirInSys, err)
			continue
		}
		backFileName := strings.TrimSuffix(string(backFileNameBuf), "\n")
		logrus.Debugf("losetup: GetDeviceFromBackingFilePath trying to match %s with %s", backFileName, absPath)
		if (absPath == backFileName) { // found the device mounted for the given backing file
			dev := Device{number:uint64(i), flags: os.O_RDWR} // note: we fix flags below ...
			info, err := dev.GetInfo()
			if err != nil {
				logrus.Errorf("losetup: GetDeviceFromBackingFilePath failed to get info for allocated loop device %d (%s): err=%v", i, err)
				break
			}
			// set proper flags from info
			dev.flags = int(info.Flags)
			logrus.Debugf("losetup: GetDeviceFromBackingFilePath found loop device %s matching path %s", dev.Path(), absPath)
			return dev, nil
		}
	}

	logrus.Debugf("losetup: GetDeviceFromBackingFilePath could not found loop device  matching path %s", absPath)
	return Device{}, fmt.Errorf("cannot find a device for backing file %s", backingFile)
}

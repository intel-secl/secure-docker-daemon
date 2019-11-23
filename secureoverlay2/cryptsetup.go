// +build linux

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package secureoverlay2

import (
	"errors"
	"encoding/base64"
	"fmt"
	"path"
	"path/filepath"
	"syscall"
	"runtime"
	"os/exec"
	"os"
	"bytes"
	"strings"
	"io"
	"io/ioutil"

	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/idtools"
	"github.com/sirupsen/logrus"
	"rp.intel.com/intel/go-losetup"
)

const (
	// ConstCryptsetupBin : Path to the cryptsetup binary
	ConstCryptsetupBin		= "/sbin/cryptsetup"
        // ConstDevMapperPrefix : Path to the mapper devices
	ConstDevMapperPrefix		= "/dev/mapper"
        // ConstMinImageSize : Minimum size for a Docker Image layer
	ConstMinImageSize		= 10 * 1024 * 1024 // 10 MB
        // ConstCryptsetupOverhead : Extra free space allocated to an image layer for any overruns
	ConstCryptsetupOverhead		= 2 * 1024 * 1024 // 4 MB
        // ConstFsOverhead : Percentage of layer size allocate for overhead
	ConstFsOverhead			= 50 // (in %) 5%
        // ConstLuksCmdFormat : Command for formatting dmcrypt devices
	ConstLuksCmdFormat		= "luks-format"
        // ConstLuksCmdOpen : Command for opening dmcrypt devices
	ConstLuksCmdOpen		= "luks-open"
        // ConstLuksCmdClose : Command for closing dmcrypt devices
	ConstLuksCmdClose		= "luks-close"
        // ConstLuksCmdRemove : Command for deleting dmcrypt devices
	ConstLuksCmdRemove		= "luks-remove"

        // ConstTypeCrypt : String denoting an dmcrypt encrypted device
	ConstTypeCrypt			= "type-crypt"

	// ConstFsBlockSize : Higher values of this setting e.g., 4096, will increase relative filesystem overhead
	// and increase likelihood the overhead estimation will to small resulting on overflow
	// of filesystem during securityTransform
        ConstFsBlockSize                = "1024"

        // ConstFsReservedBlocks : Number of FS blocks reserved per image layer mount
	ConstFsReservedBlocks		= "0"

        // ConstFsTypeExt4 : String denoting the ext4 filesystem
	ConstFsTypeExt4			= "ext4"

        // ConstBlockDevBasePath : Path to the block devices
	ConstBlockDevBasePath		= "/sys/dev/block"
        // ConstLoopMajorNum : Major device number for loopback device
	ConstLoopMajorNum		= 7
        // ConstBackingFilePath : Path within the loopback filesystem for backing_file storage
	ConstBackingFilePath		= "loop/backing_file"
        // ConstMaxLoopDevices : Ceiling on the number of loopback devices that can be opened simulataneously
	ConstMaxLoopDevices		= 256
)

// RawImage : This represents an image mount with a loopback device
type RawImage struct {
	ImagePath	string
	// TODO: this object can be removed after taking care of DevPath() API
	LoDev		losetup.Device
}

// CryptParams : Information passed to dmcrypt for encrypt/decrypt operations
type CryptParams struct {
	Cipher		string
	Key		string
	KeySize		string
	HashType	string
	ReadOnly	bool
}

// DeviceParams : Information required to tie the image to the dmcrypt mount device
type DeviceParams struct {
	FsType		string
	Mnt		string
	UIDMaps         []idtools.IDMap
	GIDMaps         []idtools.IDMap
}

// VirtualDevice : An encapsulation of an encrypted docker image
type VirtualDevice struct {
	Image		RawImage
	Name		string
	Type		string
	Deviceparams	DeviceParams
	Cryptparams	CryptParams
}

// DeviceAPI : Enumerates methods to be implemented by a encrypted mount store
type DeviceAPI interface {
	Create(size int64) error

	Get() error
	Put() error
	Remove() error

	ImportData(diffTar io.Reader) error
}

// **************************** helper functions ****************************************

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func runCmd(cmdStr string) (string, error) {
	logrus.Debugf("runCmd called w. cmd: %s", cmdStr)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command("/bin/bash", "-c", cmdStr)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	logrus.Debugf("runCmd returns w. stdout: %s, stderr: %s, err: %v", stdout.String(), stderr.String(), err)

	return stdout.String(), err
}

// compute dir size including some accounting of metadata
func dirPlusMetaSize(path string) (int64, error) {
        var size int64
        err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
                if !info.IsDir() {
                        size += info.Size()
                } else { // add size of directory entry(4K) to compute exact disk utilization
                        size += 4 * 1024
                }
                return err
        })
        return size, err
}

func mountDev(source, target, fsType string, readOnly bool) error {
	if rt, _ := exists(source); rt {

		flags := syscall.MS_REC
		if readOnly {
			flags = flags | syscall.MS_RDONLY
		}

		logrus.Debugf("secureoverlay2: mountDev -> ``mount -t %s '%s' '%s''' with flags %v", fsType, source, target, flags)
		if err := syscall.Mount(source, target, fsType, uintptr(flags), ""); err != nil {
			logrus.Errorf("failed to mount source: %s  at %s, error: %s", source, target, err.Error())
			return err
		}

		return nil
	}

	return fmt.Errorf("source path %s does not exists", source)
}

func readonlyMountDev(source, target, fsType string) error {
	return mountDev(source, target, fsType, true)
}

// FIXME: this is copy-pasted from the aufs driver.
// It should be moved into the core.

// Mounted returns true if a mount point exists.
func isMounted(mountpoint string) (bool, error) {
	mntpoint, err := os.Stat(mountpoint)
	if err != nil {
		// if os.IsNotExist(err) {
		// 	return false, nil
		// }
		return false, err
	}
	parent, err := os.Stat(filepath.Join(mountpoint, ".."))
	if err != nil {
		return false, err
	}
	mntpointSt := mntpoint.Sys().(*syscall.Stat_t)
	parentSt := parent.Sys().(*syscall.Stat_t)
	return mntpointSt.Dev != parentSt.Dev, nil
}

func unmountDev(target string) error {
	// check if mounted or not
	if m, err := isMounted(target); !m {
		logrus.Warningf("trying to to unmount already unmounted directory %s, err=%v", target, err)
		return nil
	}

	logrus.Debugf("secureoverlay2: unmountDev -> ``umount %s", target)
	if err := syscall.Unmount(target, 0); err != nil {
		logrus.Errorf("failed to unmount %s, error: %s", target, err.Error())
		return err
	}

	return nil
}

func createImageFile(filePath string, size int64) error {
	// create image file if does not exists
	if rt, _ := exists(filePath); !rt {
		os.Create(filePath)
	}

	// TODO: what uid, gid should be used for this file?? Docker
	//	daemon always startw with root on Linux, but it also has options
	//	for uid,gid. How they are used and do we need to add uid,gid for
	//	this file too for better access control??
	if err := os.Truncate(filePath, size); err != nil {
		logrus.Errorf("failed to create image file %s", filePath)
		return err
	}

	logrus.Infof("Image file %s is created with size: %d", filePath, size)
	return nil
}

func fsFormat(path, fsType, Options string) error {
	cmd := fmt.Sprintf("mkfs.%s -b %s -m %s %s", fsType, ConstFsBlockSize, ConstFsReservedBlocks, path)
	if out, err := runCmd(cmd); err != nil {
		logrus.Errorf("failed to format device %s, error: %s, out: %s", path, err.Error(), out)
		return err
	}
	return nil
}

func computeCryptOverhead(size int64) int64 {
	return int64(ConstCryptsetupOverhead)
}

func computeFsOverhead(size int64) int64 {
	return int64(size * ConstFsOverhead / 100)
}

func safeSize(size int64) int64 {
	// make sure that minimum required size
	if size < ConstMinImageSize {
		return int64(ConstMinImageSize)
	}

	return size
}

func executeLuksCommand(luksCmd, devPath, name string, params CryptParams) error {
	cmd := ""
	key := params.Key
	dev := devPath
	nm := name
	rd := params.ReadOnly

	// init params, use default values if not provided
	c := ConstDefaultCipher
	if params.Cipher != "" {
		c = params.Cipher
	}
	ks := ConstDefaultKeySize
	if params.KeySize != "" {
		ks = params.KeySize
	}
	ht := ConstDefaultHashType
	if params.HashType != "" {
		ht = params.HashType
	}

	tmpKeyFile, err := ioutil.TempFile("/tmp", "layerKey")
	if err != nil {
		return errors.New("cryptsetup: Error creating a temp key file")
	}

	defer os.Remove(tmpKeyFile.Name()) // clean up
	keyByte, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
                return errors.New("cryptsetup: Error while decoding key from  base64 string into bytes")
        }
	

	if _, err := tmpKeyFile.Write(keyByte); err != nil {
		return errors.New("error while writing key to a temp file")
	}

	if err := tmpKeyFile.Close(); err != nil {
		return errors.New("error closing the temp key file")
	}

	keyPath := tmpKeyFile.Name()
	

	switch(luksCmd) {
		case ConstLuksCmdFormat:
			cmd = fmt.Sprintf("cryptsetup -v -q luksFormat --key-file %s -c %s -h %s -s %s %s",
								keyPath, c, ht, ks, dev)
		case ConstLuksCmdOpen:
			if rd {
				cmd = fmt.Sprintf("cryptsetup -v --readonly --type luks open --key-file %s %s %s", keyPath, dev, nm)
			} else {
				cmd = fmt.Sprintf("cryptsetup -v --type luks open --key-file %s %s %s", keyPath, dev, nm)
			}
		case ConstLuksCmdClose:
			cmd = fmt.Sprintf("cryptsetup -v --type luks close %s", nm)

		default:
			return fmt.Errorf("invalid luks command: %s", luksCmd)
	}

	if out, err := runCmd(cmd); err != nil {
		// TODO: filter password from log message (or better, pass key/secret directly via a pipe to cryptsetup)
		// Note: runCmd also (debug) logs the whole command!!!!
		logrus.Errorf("failed to execute luks command %s, error: %s, out: %s", luksCmd, err.Error(), out)
		return err
	}

	return nil
}

func getRootHash(out string) string {
	// split lines
    lines := strings.Split(out, "\n")
	rootHashLine := ""

    for _, ln := range lines {
	if strings.Contains(ln, "Root hash") {
		rootHashLine = ln
		break
	}
    }

    rootHash := strings.Split(rootHashLine, ":")
    if len(rootHash) < 2 { return "" }

    return strings.TrimSpace(rootHash[1])
}

// *************** raw image management *************************************************

// Create : Creates the overlay image file
func (i RawImage) Create(size int64) error {
	logrus.Debugf("secureoverlay2: RawImage Create called w. image file %s and size: %d", i.ImagePath, size)
	sz := safeSize(size)
	err := createImageFile(i.ImagePath, sz)
	logrus.Debugf("secureoverlay2: RawImage Create returns w. error: %v", err)
	return err
}

// Get : Creates the overlay image file
func (i *RawImage) Get() error {
	logrus.Debug("secureoverlay2: RawImage Get called")
	if rt, _ := exists(i.ImagePath); ! rt {
		return fmt.Errorf("Image file %s does not exists", i.ImagePath)
	}

	// attach raw image file to loop device
	dev, err := losetup.Attach(i.ImagePath, 0, false)
	// NOTE: iff same imagepath is passed in a separate Get call, the _same_ object is returned!
	if err != nil {
		logrus.Errorf("secureoverlay2: RawImage Get, attach failed for imagepath: %s w. err: %v", i.ImagePath, err)
		return err
	}
	i.LoDev = dev

	logrus.Debugf("secureoverlay2: RawImage Get returns, attached loop device %s for image file %s", dev.Path(), i.ImagePath)
	return nil
}

// Put : Detaches the image mount from the filesystem
func (i RawImage) Put() error {
	logrus.Debug("secureoverlay2: RawImage Put called")
	// get device using backingFile:
	// IMPORTANT: GetDeviceFromBackingFilePath compares only 64-byte prefixes, so we should make sure there is no collisions.
	// this should be fine with default paths and only one attached device per layer
	// TODO: very above!!!!
	dev, err := losetup.GetDeviceFromBackingFilePath(i.ImagePath)
	// skip detach if image is not attached to any loop device
	if err != nil {
		logrus.Debugf("secureoverlay2: RawImage Put, ignoring error that no loop device is attached for ImagePath %s (err: %v)", i.ImagePath, err)
		// See NOTE at end of ImportData() for reason why we ignore errors here
		return nil
	}
	logrus.Debugf("secureoverlay2: RawImage Put, detaching loop device %s for image file %s", dev.Path(), i.ImagePath)

	err = dev.Detach()
	logrus.Debugf("secureoverlay2: RawImage Put, returns w. err: %v", err)
	return err
}

// Remove : Removes the image file on deletion
func (i RawImage) Remove() error {
	logrus.Debug("secureoverlay2: RawImage Remove called")
	err := os.Remove(i.ImagePath)
	logrus.Debugf("secureoverlay2: RawImage Remove of image file %s returns w. err: %v", i.ImagePath, err)
	return err
}

// devPath : Returns the path to the loopback device
func (i RawImage) devPath() string {
	return i.LoDev.Path()
}


// *************** virtual device APIs ******************************************************

// Init : Initialize the virtual device
func (d *VirtualDevice) Init() {
	// set default crypt params
	d.Cryptparams.Cipher = ConstDefaultCipher
	d.Cryptparams.HashType = ConstDefaultHashType
	d.Cryptparams.Key = ""
	d.Cryptparams.KeySize = ConstDefaultKeySize
	d.Cryptparams.ReadOnly = true

	// set default device params
	d.Deviceparams.FsType = ConstFsTypeExt4
	d.Deviceparams.Mnt = ""

	// set default values
	d.Name = "test"
	d.Type = ConstTypeCrypt
}

// Create : Creates a virtual device with the specified properties
func (d *VirtualDevice) Create(size int64) error {
	logrus.Debugf("secureoverlay2: VirtualDevice Create called w. name %s, type %s, size: %d", d.Name, d.Type, size)

	// create raw image file
	var sz int64
	switch(d.Type) {
		case ConstTypeCrypt:
			sz = safeSize(size + computeFsOverhead(size) + computeCryptOverhead(size))
		default:
			return errors.New("Invalid device type")
	}
	err := d.Image.Create(sz)
	logrus.Debugf("secureoverlay2: VirtualDevice Create returns w. error: %v", err)
	return err
}

func (d *VirtualDevice) getCryptName() string {
	return fmt.Sprintf("%s-crypt", d.Name)
}

func (d *VirtualDevice) format() error {
	logrus.Debug("secureoverlay2: VirtualDevice format called")

	if err := d.Image.Get(); err != nil {return err}

	// detach loop device
	defer func(){
		if err := d.Image.Put(); err != nil {
			logrus.Errorf("secureoverlay2: VirtualDevice format, failed to put image back, error: %s", err.Error())
		}
	}()

	// device path
	dev := d.Image.devPath()

	// check if crypt setup required
	if d.Type == ConstTypeCrypt {
		// format encrypted device
		if err := executeLuksCommand( ConstLuksCmdFormat, dev,
					d.getCryptName(), d.Cryptparams); err != nil {return err}

		// open encrypted device
		d.Cryptparams.ReadOnly = false
		if err := executeLuksCommand( ConstLuksCmdOpen, dev,
					d.getCryptName(), d.Cryptparams); err != nil {return err}

		dev = path.Join(ConstDevMapperPrefix, d.getCryptName())

	}

	// format plain device
	if err := fsFormat(dev, d.Deviceparams.FsType, ""); err != nil {
		return err
	}

	// clean up crypt setup
	if d.Type == ConstTypeCrypt {
		// close encrypted device
		if err := executeLuksCommand( ConstLuksCmdClose, "", d.getCryptName(),
				d.Cryptparams); err != nil {
			logrus.Errorf("secureoverlay2: VirtualDevice format, failed to close encrypted device, error: %s", err.Error())
		}
	}

	logrus.Debug("secureoverlay2: VirtualDevice format, returns")

	return nil
}

// ImportData : Move data from a diff-tarball into a mount device
func (d *VirtualDevice) ImportData(diffTar io.Reader) error {
	logrus.Debugf("secureoverlay2: VirtualDevice ImportData called w. name %s, type %s", d.Name, d.Type)

	// format device before importing data
	//	(this will format luks and filesystem based on requirements)
	if err := d.format(); err != nil {return err}

	// mount image to loop device
	if err := d.Image.Get(); err != nil {return err}

	// device path
	dev := d.Image.devPath()

	// check if crypt setup required
	if d.Type == ConstTypeCrypt {
		// open encrypted device
		d.Cryptparams.ReadOnly = false
		if err := executeLuksCommand( ConstLuksCmdOpen, dev,
					d.getCryptName(), d.Cryptparams); err != nil {return err}

		dev = path.Join(ConstDevMapperPrefix, d.getCryptName())

	}

	// mount device in read-write mode
	if err := mountDev(dev, d.Deviceparams.Mnt, d.Deviceparams.FsType, false); err != nil {
		return err
	}

	// importing data to the device
	logrus.Debugf("secureoverlay2: VirtualDevice ImportData, unpacking to-be-secured data from archive to %s", d.Deviceparams.Mnt)
	tarOpts := &archive.TarOptions{
		UIDMaps: d.Deviceparams.UIDMaps,
		GIDMaps: d.Deviceparams.GIDMaps,
		WhiteoutFormat: archive.OverlayWhiteoutFormat,}
	if err := untar(diffTar, d.Deviceparams.Mnt, tarOpts); err != nil {
		return err
	}

	// unmount device
	if err := unmountDev(d.Deviceparams.Mnt); err != nil {
		logrus.Errorf("secureoverlay2: VirtualDevice ImportData, failed to unmount, error: %s", err.Error())
	}

	// clean up crypt setup
	if d.Type == ConstTypeCrypt {
		if err := executeLuksCommand( ConstLuksCmdClose, "",
			d.getCryptName(), d.Cryptparams); err != nil {
				logrus.Errorf("secureoverlay2: VirtualDevice ImportData, failed to close crypt device, error: %s", err.Error())
			}
	}

	// NOTE: After this import triggered by graphdriver securityTransform(), the daemon will issue a
	// graph-driver drv.Put() matching the drv.Get() done before whatever action triggered this securityTransform.
	// The previous drv.Get() of course didn't do any losetup or crypt operation in vDrv.Get(), but as the security state
	// has changed, the following drv.Put() will do call a vDev.Put() which does try to do crypto cleanup of something not initialized.
	// We could do try to call vDev.Get() in securityTransform to put the layer in a consistent state.
	// However, this itself also doesn't works as
	// - vDev.Get() with current object in securityTransform doesn't match the vDev.Name as defined by d.Put() but ..
	// - .. we also had to use a different name there as in case of squash there IS actualy a concurrent Get() with crypto!
        // skipping the image.Put here also doesn't work as then in the squash case there would be no cleanup
	// => so we just just ignore any other crypto-cleanup related errors in vDev.Put() ...

	if err := d.Image.Put(); err != nil {
		logrus.Errorf("secureoverlay2: VirtualDevice ImportData, failed to put image back, error: %s", err.Error())
		return err;
	}

	logrus.Debug("secureoverlay2: VirtualDevice ImportData returns")

	return nil
}

// Get : Open the encrypted mount for IO operations
func (d *VirtualDevice) Get() error {
	logrus.Debugf("secureoverlay2: VirtualDevice Get called w. name %s, type %s", d.Name, d.Type)

	if err := d.Image.Get(); err != nil {return err}

	// device path
	dev := d.Image.devPath()

	// check if crypt setup required
	if d.Type == ConstTypeCrypt {
		// open encrypted device
		d.Cryptparams.ReadOnly = true
		if err := executeLuksCommand( ConstLuksCmdOpen, dev,
					d.getCryptName(), d.Cryptparams); err != nil {return err}

		dev = path.Join(ConstDevMapperPrefix, d.getCryptName())

	}

	// mount device in readonly mode
	if err := readonlyMountDev(dev, d.Deviceparams.Mnt, d.Deviceparams.FsType); err != nil {
		return err
	}

	logrus.Debug("secureoverlay2: VirtualDevice Get returns")

	return nil
}

// Put : Unmount the encrypted mount
func (d *VirtualDevice) Put() error {
	logrus.Debugf("secureoverlay2: VirtualDevice Put called w. name %s, type %s", d.Name, d.Type)

	// unmount device
	if err := unmountDev(d.Deviceparams.Mnt); err != nil {
		logrus.Infof("secureoverlay2: VirtualDevice Put, ignoring %s unmount failure: %s", d.Deviceparams.Mnt, err.Error())
		// See NOTE at end of ImportData() for reason why we ignore errors here
	}

	// clean up crypt setup, if exists
	if d.Type == ConstTypeCrypt {
		if err := executeLuksCommand( ConstLuksCmdClose, "",
					d.getCryptName(), d.Cryptparams); err != nil {
			logrus.Debugf("secureoverlay2: VirtualDevice Put, ignoring luksClose failure: %s", err.Error())
		        // See NOTE at end of ImportData() for reason why we ignore errors here
		}
	}

	err := d.Image.Put()
	// in this case we do NOT ignore error as Image.Put already ignores errors related to NOTE at end of ImportData()
	logrus.Debugf("secureoverlay2: VirtualDevice Put, returns w. err: %v", err)
	return err
}

// Remove : Remove the encrypted mount from the filesystem on deletion
func (d *VirtualDevice) Remove() error {
	logrus.Debugf("secureoverlay2: VirtualDevice Remove called w. name %s, type %s", d.Name, d.Type)
	err := d.Image.Remove()
	logrus.Debugf("secureoverlay2: VirtualDevice Remove, returns w. err: %v", err)
	return err
}

// ***********************************************************

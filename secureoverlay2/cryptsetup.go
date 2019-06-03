//AUTHOR: Divya Desai <divyax.desai@intel.com>

/*
Copyright © 2018 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package secureoverlay2

import (
	"errors"
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

	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/idtools"
	"github.com/sirupsen/logrus"
	"rp.intel.com/intel/go-losetup"
)

const (
	ConstCryptsetupBin		= "/sbin/cryptsetup"
	ConstDevMapperPrefix		= "/dev/mapper"
	ConstMinImageSize		= 10 * 1024 * 1024 // 10 MB
	ConstCryptsetupOverhead		= 2 * 1024 * 1024 // 4 MB
	ConstFsOverhead			= 20 // (in %) 5%

	ConstLuksCmdFormat		= "luks-format"
	ConstLuksCmdOpen		= "luks-open"
	ConstLuksCmdClose		= "luks-close"
	ConstLuksCmdRemove		= "luks-remove"

	ConstVerityCmdFormat		= "verity-format"
	ConstVerityCmdCreate		= "verity-create"
	ConstVerityCmdRemove		= "verity-remove"
	ConstVerityCmdVerify		= "verity-verify"

	ConstTypeCrypt			= "type-crypt"
	ConstTypeVerity			= "type-verity"
	ConstTypeCryptVerity		= "type-crypt-verity"

	ConstFsBlockSize		= "1024"
	// Note: higher ConstFsBlockSize, e.g., 4096, will increase relative filesystem overhead
	// and increase likelihood the overhead estimation will to small resulting on overflow
	// of filesystem during securityTransform
	ConstFsReservedBlocks		= "0"

	ConstFsTypeExt4			= "ext4"

	ConstBlockDevBasePath		= "/sys/dev/block"
	ConstLoopMajorNum		= 7
	ConstBackingFilePath		= "loop/backing_file"
	ConstMaxLoopDevices		= 256
)

type RawImage struct {
	ImagePath	string
	// TODO: this object can be removed after taking care of DevPath() API
	LoDev		losetup.Device
}

type CryptParams struct {
	Cipher		string
	Key		string
	KeySize		string
	HashType	string
	ReadOnly	bool
}

type VerityParams struct {
	RootHash	string
	HashImage	string
}

type DeviceParams struct {
	FsType		string
	Mnt		string
	UIDMaps         []idtools.IDMap
	GIDMaps         []idtools.IDMap
}

type VirtualDevice struct {
	Image		RawImage
	Name		string
	Type		string
	Deviceparams	DeviceParams
	Cryptparams 	CryptParams
	Verityparams	VerityParams
}

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

	return errors.New(fmt.Sprintf("source path %s does not exists", source))
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
		logrus.Errorf("faild to create image file %s", filePath)
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

	switch(luksCmd) {
		case ConstLuksCmdFormat:
			cmd = fmt.Sprintf("printf %s | cryptsetup -q luksFormat -c %s -h %s -s %s %s -",
								key, c, ht, ks, dev)
		case ConstLuksCmdOpen:
			if rd {
				cmd = fmt.Sprintf("printf %s | cryptsetup --readonly --type luks open %s %s", key, dev, nm)
			} else {
				cmd = fmt.Sprintf("printf %s | cryptsetup --type luks open %s %s", key, dev, nm)
			}
		case ConstLuksCmdClose:
			cmd = fmt.Sprintf("cryptsetup --type luks close %s", nm)

		default:
			return errors.New(fmt.Sprintf("invalid luks command: %s", luksCmd))
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

func executeVerityCommand(verityCmd, devPath, name string, params VerityParams) (string, error) {
	cmd := ""
	dev := devPath
	hashDev := params.HashImage
	hash := params.RootHash
	nm := name

	switch(verityCmd) {
	case ConstVerityCmdFormat:
		cmd = fmt.Sprintf("veritysetup format --data-block-size %s %s %s", ConstFsBlockSize, dev, hashDev)
		// Note: it is crucial that format has same blocksize as filesystem or mount will fail later!!
	case ConstVerityCmdCreate:
		cmd = fmt.Sprintf("veritysetup create %s %s %s %s", nm, dev, hashDev, hash)
	case ConstVerityCmdRemove:
		cmd = fmt.Sprintf("veritysetup remove %s", nm)
	case ConstVerityCmdVerify:
		cmd = fmt.Sprintf("veritysetup verify %s %s %s", dev, hashDev, hash)
	default:
		return "", errors.New(fmt.Sprintf("invalid veritysetup command: %s", verityCmd))
	}

	out := ""
	var err error
	if out, err = runCmd(cmd); err != nil {
		logrus.Errorf("failed to execute verity command %s, error: %s, out: %s", verityCmd, err.Error(), out)
		return "", err
	}

	// parse output to read root hash and save it for future use
	if verityCmd == ConstVerityCmdFormat {
		hash = getRootHash(out)
		if hash == "" {
			return "", errors.New("Invalid root hash after verity format")
		}
	}

	return hash, nil
}

// **************************************************************************************

// *************** raw image management *************************************************
func (i RawImage) Create(size int64) error {
	logrus.Debugf("secureoverlay2: RawImage Create called w. image file %s and size: %d", i.ImagePath, size)
	sz := safeSize(size)
	err := createImageFile(i.ImagePath, sz)
	logrus.Debugf("secureoverlay2: RawImage Create returns w. error: %v", err)
	return err
}

func (i *RawImage) Get() error {
	logrus.Debug("secureoverlay2: RawImage Get called")
	if rt, _ := exists(i.ImagePath); ! rt {
		return errors.New(fmt.Sprintf("Image file %s does not exists", i.ImagePath))
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

func (i RawImage) Remove() error {
	logrus.Debug("secureoverlay2: RawImage Remove called")
	err := os.Remove(i.ImagePath)
	logrus.Debugf("secureoverlay2: RawImage Remove of image file %s returns w. err: %v", i.ImagePath, err)
	return err
}

func (i RawImage) devPath() string {
	return i.LoDev.Path()
}


// *************** virtual device APIs ******************************************************

func (d *VirtualDevice) Init() {
	// set default crypt params
	d.Cryptparams.Cipher = ConstDefaultCipher
	d.Cryptparams.HashType = ConstDefaultHashType
	d.Cryptparams.Key = ""
	d.Cryptparams.KeySize = ConstDefaultKeySize
	d.Cryptparams.ReadOnly = true

	// set default verity params
	d.Verityparams.HashImage = ""
	d.Verityparams.RootHash = ""

	// set default device params
	d.Deviceparams.FsType = ConstFsTypeExt4
	d.Deviceparams.Mnt = ""

	// set default values
	d.Name = "test"
	d.Type = ConstTypeCrypt
}

func (d *VirtualDevice) Create(size int64) error {
	logrus.Debugf("secureoverlay2: VirtualDevice Create called w. name %s, type %s, size: %d", d.Name, d.Type, size)

	// create raw image file
	var sz int64
	switch(d.Type) {
		case ConstTypeCrypt:
			sz = safeSize(size + computeFsOverhead(size) + computeCryptOverhead(size))
		case ConstTypeVerity:
			sz = safeSize(size + computeFsOverhead(size))
		case ConstTypeCryptVerity:
			sz = safeSize(size + computeFsOverhead(size) + computeCryptOverhead(size))
		default:
			return errors.New("Invalid device type")
	}
	err := d.Image.Create(sz)
 	logrus.Debugf("secureoverlay2: VirtualDevice Create returns w. error: %v", err)
	return err
}

func (d *VirtualDevice) setRootHash(hash string) {
	d.Verityparams.RootHash = hash
}

func (d *VirtualDevice) getRootHash() string{
	return d.Verityparams.RootHash
}

func (d *VirtualDevice) getCryptName() string {
	return fmt.Sprintf("%s-crypt", d.Name)
}

func (d *VirtualDevice) getVerityName() string {
	return fmt.Sprintf("%s-verity", d.Name)
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
	if d.Type == ConstTypeCrypt || d.Type == ConstTypeCryptVerity {
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
	if d.Type == ConstTypeCrypt || d.Type == ConstTypeCryptVerity {
		// close encrypted device
		if err := executeLuksCommand( ConstLuksCmdClose, "", d.getCryptName(),
				d.Cryptparams); err != nil {
			logrus.Errorf("secureoverlay2: VirtualDevice format, failed to close encrypted device, error: %s", err.Error())
		}
	}

	logrus.Debug("secureoverlay2: VirtualDevice format, returns")

	return nil
}

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
	if d.Type == ConstTypeCrypt || d.Type == ConstTypeCryptVerity {
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
	if d.Type == ConstTypeCrypt || d.Type == ConstTypeCryptVerity {
		if err := executeLuksCommand( ConstLuksCmdClose, "",
			d.getCryptName(), d.Cryptparams); err != nil {
				logrus.Errorf("secureoverlay2: VirtualDevice ImportData, failed to close crypt device, error: %s", err.Error())
			}
	}

	// compute device integrity
	if d.Type == ConstTypeVerity || d.Type == ConstTypeCryptVerity {
		h := ""
		var err error
		if h, err = executeVerityCommand(ConstVerityCmdFormat, d.Image.devPath(),
				d.getVerityName(), d.Verityparams); err != nil {
					return err
				}
		d.setRootHash(h)
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

func (d *VirtualDevice) Get() error {
	logrus.Debugf("secureoverlay2: VirtualDevice Get called w. name %s, type %s", d.Name, d.Type)

	if err := d.Image.Get(); err != nil {return err}

	// device path
	dev := d.Image.devPath()

	// check if verity setup required
	if d.Type == ConstTypeVerity || d.Type == ConstTypeCryptVerity {
		_, err := executeVerityCommand(ConstVerityCmdCreate, dev,
			d.getVerityName(), d.Verityparams)
		if err != nil {return err}

		dev = path.Join(ConstDevMapperPrefix, d.getVerityName())
	}

	// check if crypt setup required
	if d.Type == ConstTypeCrypt || d.Type == ConstTypeCryptVerity {
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

func (d *VirtualDevice) Put() error {
	logrus.Debugf("secureoverlay2: VirtualDevice Put called w. name %s, type %s", d.Name, d.Type)

	// unmount device
	if err := unmountDev(d.Deviceparams.Mnt); err != nil {
		logrus.Infof("secureoverlay2: VirtualDevice Put, ignoring %s unmount failure: %s", d.Deviceparams.Mnt, err.Error())
		// See NOTE at end of ImportData() for reason why we ignore errors here
	}

	// clean up crypt setup, if exists
	if d.Type == ConstTypeCrypt || d.Type == ConstTypeCryptVerity {
		if err := executeLuksCommand( ConstLuksCmdClose, "",
					d.getCryptName(), d.Cryptparams); err != nil {
			logrus.Debugf("secureoverlay2: VirtualDevice Put, ignoring luksClose failure: %s", err.Error())
		        // See NOTE at end of ImportData() for reason why we ignore errors here
		}
	}

	// clean up verity setup, if exists
	if d.Type == ConstTypeVerity || d.Type == ConstTypeCryptVerity {
		if _, err := executeVerityCommand(ConstVerityCmdRemove, "",
				d.getVerityName(), d.Verityparams); err != nil {
			logrus.Debugf("secureoverlay2: VirtualDevice Put, ignoring verityRemove failure: %s", err.Error())
		        // See NOTE at end of ImportData() for reason why we ignore errors here
		}
	}

	err := d.Image.Put()
	// in this case we do NOT ignore error as Image.Put already ignores errors related to NOTE at end of ImportData()
	logrus.Debugf("secureoverlay2: VirtualDevice Put, returns w. err: %v", err)
	return err
}

func (d *VirtualDevice) Remove() error {
	logrus.Debugf("secureoverlay2: VirtualDevice Remove called w. name %s, type %s", d.Name, d.Type)
	err := d.Image.Remove()
	logrus.Debugf("secureoverlay2: VirtualDevice Remove, returns w. err: %v", err)
	return err
}

// ***********************************************************

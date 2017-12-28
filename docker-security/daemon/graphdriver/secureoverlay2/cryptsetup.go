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
	"strings"
	
	"github.com/Sirupsen/logrus"
//	"github.com/freddierice/go-losetup"
	"rp.intel.com/intel/go-losetup"
	"github.com/docker/docker/pkg/chrootarchive"
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
	
	ConstFsBlockSize		= "4096"
	ConstFsReservedBlocks		= "0"
	
	ConstFsTypeExt4			= "ext4"
	
	ConstDefaultHashType = "sha256"
	ConstDefaultCipher		= "aes-xts-plain"
	ConstDefaultKeySize		= "256"

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

type PlainDevice struct {
	DevPath		string
	FsType		string
	Mnt			string
}

type CryptParams struct {
	Cipher		string
	Key			string
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
	Mnt			string
}

type VirtualDevice struct {
	Image			RawImage
	Name			string
	Type			string
	Deviceparams	DeviceParams
	Cryptparams 	CryptParams
	Verityparams	VerityParams
}

type DeviceAPI interface {
	Create(size int64) error
	
	Get() error
	Put() error
	Remove() error
	
	ImportData(dataPath string) error
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

func runCmd(cmd string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	out, err := exec.Command("/bin/bash", "-c", cmd).Output()
	logrus.Infof("runCmd => cmd: %s, output: %s", cmd, out)
	return string(out), err
}

func dirSize(path string) (int64, error) {
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
		if os.IsNotExist(err) {
			return false, nil
		}
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
	if m, _ := isMounted(target); !m { return nil}

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

func importData(source, target string) error {
	logrus.Infof("importing data from %s to %s", source, target)
	if err := chrootarchive.CopyWithTar(source, target); err != nil {
		logrus.Errorf("error in importing data from %s to %s", source, target)
		return err
	}

	return nil
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
				cmd = fmt.Sprintf("printf %s | cryptsetup --readonly luksOpen %s %s -", key, dev, nm)
			} else {
				cmd = fmt.Sprintf("printf %s | cryptsetup luksOpen %s %s -", key, dev, nm)
			}
		case ConstLuksCmdClose:
			cmd = fmt.Sprintf("cryptsetup luksClose %s -", nm)
			
		default:
			return errors.New(fmt.Sprintf("invalid luks command: %s", luksCmd))	
	}
	
	if out, err := runCmd(cmd); err != nil {
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
			cmd = fmt.Sprintf("veritysetup format %s %s", dev, hashDev)
		case ConstVerityCmdCreate:
			cmd = fmt.Sprintf("veritysetup create %s %s %s %s", nm, dev, hashDev, hash)
		case ConstVerityCmdRemove:
			cmd = fmt.Sprintf("veritysetup remove %s", nm)
		case ConstVerityCmdVerify:
			cmd = fmt.Sprintf("veritysetup verify %s %s %s", dev, hashDev, hash)
		default:
			return "", errors.New(fmt.Sprintf("invalid luks command: %s", verityCmd))	
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
	sz := safeSize(size)
	return createImageFile(i.ImagePath, sz)
}

func (i *RawImage) Get() error {
	if rt, _ := exists(i.ImagePath); ! rt {
		return errors.New(fmt.Sprintf("Image file %s does not exists", i.ImagePath))
	}
	
	// attach raw image file to loop device
	dev, err := losetup.Attach(i.ImagePath, 0, false)
	if err != nil {return err}
	i.LoDev = dev

	return nil
}

func (i RawImage) Put() error {
	// get device using backingFile
	dev, err := losetup.GetDeviceFromBackingFilePath(i.ImagePath)
	// skipp detach if image is not attached to any loop device
	if err != nil {return nil}
	logrus.Infof("loop device detached for the image file %s", i.ImagePath)
	
	return dev.Detach()
}

func (i RawImage) Remove() error {
	return os.Remove(i.ImagePath)
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
	
	return d.Image.Create(sz)
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
	if err := d.Image.Get(); err != nil {return err}
	
	// detach loop device
	defer func(){
		if err := d.Image.Put(); err != nil { 
			logrus.Errorf("failed to put image back, error: %s", err.Error())
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
			logrus.Errorf("failed to close encrypted device, error: %s", err.Error())
		}
	}
	
	return nil	
}

func (d *VirtualDevice) ImportData(dataPath string) error {
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
	if err := importData(dataPath, d.Deviceparams.Mnt); err != nil {return err}

	// unmount device
	if err := unmountDev(d.Deviceparams.Mnt); err != nil {
		logrus.Errorf("failed to unmount, error: %s", err.Error())
	}

	// clean up crypt setup
	if d.Type == ConstTypeCrypt || d.Type == ConstTypeCryptVerity {
		if err := executeLuksCommand( ConstLuksCmdClose, "",
			d.getCryptName(), d.Cryptparams); err != nil {
				logrus.Errorf("failed to close crypt device, error: %s", err.Error())
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

	if err := d.Image.Put(); err != nil { 
		logrus.Errorf("failed to put image back, error: %s", err.Error())
	}

	return nil
}

func (d *VirtualDevice) Get() error {
	
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
		
	return nil
}

func (d *VirtualDevice) Put() error {
	// unmount device
	if err := unmountDev(d.Deviceparams.Mnt); err != nil {
		logrus.Warnf("unmount faild for %s, error: %s", d.Deviceparams.Mnt, err.Error())
		//return err
	}
	
	// clean up crypt setup, if exists
	if d.Type == ConstTypeCrypt || d.Type == ConstTypeCryptVerity {
		if err := executeLuksCommand( ConstLuksCmdClose, "",
					d.getCryptName(), d.Cryptparams); err != nil {
			logrus.Warnf("luksClose failed with an error: %s", err.Error())
			//return err
		}
	}
	
	// clean up verity setup, if exists
	if d.Type == ConstTypeVerity || d.Type == ConstTypeCryptVerity {
		if _, err := executeVerityCommand(ConstVerityCmdRemove, "", 
				d.getVerityName(), d.Verityparams); err != nil {
			logrus.Warnf("verityRemove failed with an error: %s", err.Error())
			//return err
		}
	}
		
	return d.Image.Put()
}

func (d *VirtualDevice) Remove() error {
	return d.Image.Remove()
}

// ***********************************************************


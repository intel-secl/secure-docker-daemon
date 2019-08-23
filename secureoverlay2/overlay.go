// +build linux

//AUTHOR: Divya Desai <divyax.desai@intel.com>

/*
Copyright © 2018 Intel Corporation
SPDX-License-Identifier: BSD-3-Clause
*/

package secureoverlay2 // import "github.com/docker/docker/daemon/graphdriver/secureoverlay2"

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vbatts/tar-split/tar/storage"

	"github.com/docker/docker/daemon/graphdriver"
	"github.com/docker/docker/daemon/graphdriver/overlayutils"
	"github.com/docker/docker/daemon/graphdriver/quota"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/chrootarchive"
	"github.com/docker/docker/pkg/containerfs"
	"github.com/docker/docker/pkg/directory"
	"github.com/docker/docker/pkg/fsutils"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/locker"
	"github.com/docker/docker/pkg/mount"
	"github.com/docker/docker/pkg/parsers"
	"github.com/docker/docker/pkg/parsers/kernel"
	units "github.com/docker/go-units"
	"github.com/opencontainers/selinux/go-selinux/label"
	"golang.org/x/sys/unix"
)

var (
	// untar defines the untar method
	untar = chrootarchive.UntarUncompressed
)

//the key will be polled from kernel keyring maximum 90 times till get the key from kernel keying.
//if the count reaches 90 and not able to get key from kernel keyring the error will be thrown
const (
	MAXKEYPOLL = 90
)

// This backend uses the overlay union filesystem for containers
// with diff directories for each layer.

// This version of the overlay driver requires at least kernel
// 4.0.0 in order to support mounting multiple diff directories.

// Each container/image has at least a "diff" directory and "link" file.
// If there is also a "lower" file when there are diff layers
// below as well as "merged" and "work" directories. The "diff" directory
// has the upper layer of the overlay and is used to capture any
// changes to the layer. The "lower" file contains all the lower layer
// mounts separated by ":" and ordered from uppermost to lowermost
// layers. The overlay itself is mounted in the "merged" directory,
// and the "work" dir is needed for overlay to work.

// The "link" file for each layer contains a unique string for the layer.
// Under the "l" directory at the root there will be a symbolic link
// with that unique string pointing the "diff" directory for the layer.
// The symbolic links are used to reference lower layers in the "lower"
// file and on mount. The links are used to shorten the total length
// of a layer reference without requiring changes to the layer identifier
// or root directory. Mounts are always done relative to root and
// referencing the symbolic links in order to ensure the number of
// lower directories can fit in a single page for making the mount
// syscall. A hard upper limit of 128 lower layers is enforced to ensure
// that mounts do not fail due to length.

const (
	driverName    = "secureoverlay2"
	linkDir       = "l"
	lowerFile     = "lower"
	diffDirName   = "diff"
	workDirName   = "work"
	mergedDirName = "merged"

	maxDepth = 128

	// idLength represents the number of random characters
	// which can be used to create the unique link identifer
	// for every layer. If this value is too long then the
	// page size limit for the mount command may be exceeded.
	// The idLength should be selected such that following equation
	// is true (512 is a buffer for label metadata).
	// ((idLength + len(linkDir) + 1) * maxDepth) <= (pageSize - 512)
	idLength = 26

	// ConstDefaultStringKeyLength represents the number of random characters
	// which can be used to set a default string key if the KeyType is
	// set to key-type-string and no value is passed for KeyHandle
	ConstDefaultStringKeyLength = 12

	// security transform related options passed to dmcrypt

        // ConstDefaultHashType : set the hashing algorithm used by dmcrypt
	ConstDefaultHashType = "sha256"
        // ConstDefaultCipher : set the crypt cipher used by dmcrypt
	ConstDefaultCipher   = "aes-xts-plain"
        // ConstDefaultKeySize : set the key size in bits used by dmcrypt
	ConstDefaultKeySize  = "256"

	// security storage related options
	constMetaDataFileName      = "security.meta"
	constImageName             = "base.img"
	constHashImageName         = "hash.img"
	constSecureBaseDirName     = "secure"
	constSecureCryptMntDirName = "crypt-mnt"

	constKeyTypeString   = "key-type-string"
	constKeyTypeKeyrings = "key-type-keyrings"
	constKeyTypeAPI      = "key-type-api"
	constKeyTypeKMS      = "key-type-kms"
)

// meta-data related to storage security settings
// options:
//	RequiresConfidentiality: set to true if encryption is required for the storage, false otherwise
//	RequiresIntegrity: set to true if integrity protection is needed, false otherwise
//	KeyHandle: handle for the key fetching mechanism (empty string if not undefined)
//	KeyType: different mechanisms to retrieve keying information
//	- constKeyTypeString: 	keyHandle string as key for encrypiton (DO NOT USE IN PRODUCTION, THIS IS FOR TESTING ONLY)
//	- constKeyTypeKeyrings	use kernel keyrings to fetch key using signature provided via keyHandle
//	- constKeyTypeAPI: 	use rest APIs to fetch key using URL provided via keyHandle
//      KeyTypeOption: KeyType dependend option (empty string means undefined/absent)
//       - KeyType = constKeyTypeKeyrings:	no option
//       - KeyType = constKeyTypeAPI:		url-prefix (actual URL will be url-prefix||key-handle
//       - KeyType = constKeyTypeString:	key/secret to encrypt
//	-  KeyType = constKeyTypeKMS 		key/secret to encrypt/decrypt
//	KeyDesc: free text description, can be used securely embed additional information into image (visible via
//	  'docker history' or metadata extract from registry) to give context to keyhandle
//	KeySize: size of the key to be used for encryption (in bits)
//	CryptCipher: type of the cipher to be used for LUKS encryption
//	CryptHashType: hash type to be used for LUKS encrytion
//	RootHash: root hash of the integrity hash device
//	IsDiffed: true if layer was successfully securityTransformed

type secureImgCryptOptions struct {
	RequiresConfidentiality bool   `json:"RequiresConfidentiality"`
	RequiresIntegrity       bool   `json:"RequiresIntegrity"`
	KeyHandle               string `json:"KeyHandle,omitempty"`
	KeySize                 string `json:"KeySize,omitempty"`
	KeyType                 string `json:"KeyType,omitempty"`
	KeyTypeOption           string `json:"KeyTypeOption,omitempty"`
	KeyDesc                 string `json:"KeyDesc,omitempty"`
	CryptCipher             string `json:"CryptCipher,omitempty"`
	CryptHashType           string `json:"CryptHashType,omitempty"`
	RootHash                string `json:"RootHash,omitempty"`
	KeyFilePath             string `json:"KeyFilePath,omitempty"`
	IsEmptyLayer            bool   `json:"IsEmptyLayer"`
	IsSecurityTransformed   bool   `json:"IsSecurityTransformed"`
}

// driver-specific driver options, specifiable via cmd-line
type overlayOptions struct {
	overrideKernelCheck bool
	remoteDir           string
	quota               quota.Quota
	defaultSecOpts      secureImgCryptOptions
}

// Driver contains information about the home directory and the list of active mounts that are created using this driver.
type Driver struct {
	home          string
	uidMaps       []idtools.IDMap
	gidMaps       []idtools.IDMap
	ctr           *graphdriver.RefCounter
	quotaCtl      *quota.Control
	options       overlayOptions
	naiveDiff     graphdriver.DiffDriver
	supportsDType bool
	locker        *locker.Locker
}

var (
	backingFs             = "<unknown>"
	projectQuotaSupported = false

	useNaiveDiffLock sync.Once
	useNaiveDiffOnly bool
)

var encryptContainerImage bool

func init() {
	logrus.Debug("secureoverlay2: init called")
	graphdriver.Register(driverName, Init)
	logrus.Debugf("secureoverlay2: driver registered")
	encryptContainerImage = false
}

// Init returns the a native diff driver for overlay filesystem.
// If overlay filesystem is not supported on the host, graphdriver.ErrNotSupported is returned as error.
// If an overlay filesystem is not supported over an existing filesystem then error graphdriver.ErrIncompatibleFS is returned.
func Init(home string, options []string, uidMaps, gidMaps []idtools.IDMap) (graphdriver.Driver, error) {
	logrus.Debugf("secureoverlay2: Init called w. home: %s, options:%s, uidMaps: %v, gidMaps: %v", home, options, uidMaps, gidMaps)
	opts, err := parseOptions(options)
	if err != nil {
		return nil, err
	}
	logrus.Info("secureoverlay2: Init: parsed options: ", opts)

	if err := supportsOverlay(); err != nil {
		return nil, graphdriver.ErrNotSupported
	}
	// require kernel 4.0.0 to ensure multiple lower dirs are supported
	v, err := kernel.GetKernelVersion()
	if err != nil {
		return nil, err
	}
	if kernel.CompareKernelVersion(*v, kernel.VersionInfo{Kernel: 4, Major: 0, Minor: 0}) < 0 {
		if !opts.overrideKernelCheck {
			return nil, graphdriver.ErrNotSupported
		}
		logrus.Warn("Using pre-4.0.0 kernel for overlay2, mount failures may require kernel update")
	}

	// Perform feature detection on /var/lib/docker/overlay2 if it's an existing directory.
	// This covers situations where /var/lib/docker/overlay2 is a mount, and on a different
	// filesystem than /var/lib/docker.
	// If the path does not exist, fall back to using /var/lib/docker for feature detection.
	testdir := home
	if _, err := os.Stat(testdir); os.IsNotExist(err) {
		testdir = filepath.Dir(testdir)
	}

	fsMagic, err := graphdriver.GetFSMagic(testdir)
	if err != nil {
		logrus.Errorf("secureoverlay2: %s", err.Error())
		return nil, err
	}
	if fsName, ok := graphdriver.FsNames[fsMagic]; ok {
		backingFs = fsName
	}
	// check if they are running over btrfs, aufs, zfs, overlay, or ecryptfs
	switch fsMagic {
	case graphdriver.FsMagicBtrfs, graphdriver.FsMagicAufs, graphdriver.FsMagicZfs, graphdriver.FsMagicOverlay, graphdriver.FsMagicEcryptfs:
		logrus.Errorf("'overlay2' is not supported over %s", backingFs)
		return nil, graphdriver.ErrIncompatibleFS
	}

	rootUID, rootGID, err := idtools.GetRootUIDGID(uidMaps, gidMaps)
	if err != nil {
		return nil, err
	}
	// Create the driver home dir
	if err := idtools.MkdirAllAndChown(path.Join(home, linkDir), 0700, idtools.Identity{UID: rootUID, GID: rootGID}); err != nil {
		return nil, err
	}
	if err := mount.MakePrivate(testdir); err != nil {
		return nil, err
	}

	supportsDType, err := fsutils.SupportsDType(testdir)
	if err != nil {
		return nil, err
	}
	if !supportsDType {
		// not a fatal error until v17.12 (#27443)
		logrus.Warn(overlayutils.ErrDTypeNotSupported("secureoverlay2", backingFs))
	}

	d := &Driver{
		home:          home,
		uidMaps:       uidMaps,
		gidMaps:       gidMaps,
		ctr:           graphdriver.NewRefCounter(graphdriver.NewFsChecker(graphdriver.FsMagicOverlay)),
		supportsDType: supportsDType,
		locker:        locker.New(),
		options:       *opts,
	}
	d.naiveDiff = graphdriver.NewNaiveDiffDriver(d, uidMaps, gidMaps)
	if backingFs == "xfs" {
		// Try to enable project quota support over xfs.
		if d.quotaCtl, err = quota.NewControl(home); err == nil {
			projectQuotaSupported = true
		}
	}
	logrus.Debugf("secureoverlay2: Init return, backingFs=%s,  projectQuotaSupported=%v driver-options=%v", backingFs, projectQuotaSupported, d.options)

	return d, nil
}

func parseOptions(options []string) (*overlayOptions, error) {
	o := &overlayOptions{}
	o.remoteDir = "" // set default value in case not provided

	for _, option := range options {
		key, val, err := parsers.ParseKeyValueOpt(option)
		if err != nil {
			return nil, err
		}
		key = strings.ToLower(key)
		switch key {
		case "overlay2.override_kernel_check":
			o.overrideKernelCheck, err = strconv.ParseBool(val)
			if err != nil {
				return nil, err
			}
		case "secureoverlay2.remote_dir":
			o.remoteDir = val
		case "secureoverlay2.defaultrequiresconfidentiality":
			o.defaultSecOpts.RequiresConfidentiality, err = strconv.ParseBool(val)
			if err != nil {
				return nil, fmt.Errorf("secureoverlay2: %s not a boolean value for option secureoverlay2.defaultRequiresConfidentiality", val)
			}
		case "secureoverlay2.defaultrequiresintegrity":
			o.defaultSecOpts.RequiresIntegrity, err = strconv.ParseBool(val)
			if err != nil {
				return nil, fmt.Errorf("secureoverlay2: %s not a boolean value for option secureoverlay2.defaultRequiresIntegrity", val)
			}
		case "secureoverlay2.defaultkeytype":
			lcVal := strings.ToLower(val)
			switch lcVal {
			case constKeyTypeString, constKeyTypeKeyrings, constKeyTypeAPI, constKeyTypeKMS:
				o.defaultSecOpts.KeyType = lcVal
			default:
				return nil, fmt.Errorf("secureoverlay2: %s not a valid value for option secureoverlay2.defaultKeyType", val)
			}
		case "secureoverlay2.defaultkeysize":
			o.defaultSecOpts.KeySize = val
		case "secureoverlay2.defaultcryptcipher":
			o.defaultSecOpts.CryptCipher = val
		case "secureoverlay2.defaultcrypthashtype":
			o.defaultSecOpts.CryptHashType = val
			// following values do in general make less sense as defaults but will come
			// handy in enabling integration test-framework to also test secure variants
		case "secureoverlay2.defaultkeyhandle":
			o.defaultSecOpts.KeyHandle = val
		case "secureoverlay2.defaultkeytypeoption":
			o.defaultSecOpts.KeyTypeOption = val
		case "secureoverlay2.defaultkeydesc":
			o.defaultSecOpts.KeyDesc = val
		default:
			return nil, fmt.Errorf("secureoverlay2: Unknown option %s", key)
		}
	}
	return o, nil
}

func supportsOverlay() error {
	// We can try to modprobe overlay first before looking at
	// proc/filesystems for when overlay is supported
	exec.Command("modprobe", "overlay").Run()

	f, err := os.Open("/proc/filesystems")
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		if s.Text() == "nodev\toverlay" {
			return nil
		}
	}
	logrus.Error("'overlay' not found as a supported filesystem on this host. Please ensure kernel is new enough and has overlay support loaded.")
	return graphdriver.ErrNotSupported
}

func useNaiveDiff(home string) bool {
	useNaiveDiffLock.Do(func() {
		if err := doesSupportNativeDiff(home); err != nil {
			logrus.Warnf("Not using native diff for secureoverlay2: %v", err)
			useNaiveDiffOnly = true
		}
	})
	return useNaiveDiffOnly
}

func (d *Driver) String() string {
	return driverName
}

// Status returns current driver information in a two dimensional string array.
// Output contains "Backing Filesystem" used in this implementation.
func (d *Driver) Status() [][2]string {
	logrus.Debug("secureoverlay2: Status called")

	return [][2]string{
		{"Backing Filesystem", backingFs},
		{"Supports d_type", strconv.FormatBool(d.supportsDType)},
		{"Native Overlay Diff", strconv.FormatBool(!useNaiveDiff(d.home))},
	}
}

// GetMetadata returns meta data about the overlay driver such as
// LowerDir, UpperDir, WorkDir and MergeDir used to store data.
func (d *Driver) GetMetadata(id string) (map[string]string, error) {
	logrus.Debugf("secureoverlay2: GetMetadata called w. id: %s", id)
	dir := d.dir(id)
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}

	metadata := map[string]string{
		"WorkDir":   path.Join(dir, "work"),
		"MergedDir": path.Join(dir, "merged"),
		"UpperDir":  path.Join(dir, "diff"),
	}

	lowerDirs, err := d.getLowerDirs(id)
	if err != nil {
		return nil, err
	}
	if len(lowerDirs) > 0 {
		metadata["LowerDir"] = strings.Join(lowerDirs, ":")
	}

	// additional data
	s, err := d.getSecurityMetaDataForID(id, "")
	switch {
	case err == nil:
		if s.RequiresConfidentiality || s.RequiresIntegrity {
			// embedd security meta-data if it is a secured image.
			// Note: only including it for secured images allows non-secured images still
			// to work with Manifest Schema 1 of registry. For secured images, in particular with
			// integrity, Schema 2 is essential to get the secure content-addressable nature of the image.

			// do some clean-up of unneeded params to declutter config/docker history
			if !s.RequiresConfidentiality {
				s.KeyHandle = ""
				s.KeyType = ""
				s.KeyTypeOption = ""
				s.KeyDesc = ""
				s.KeySize = ""
				s.KeyFilePath = ""
				s.CryptCipher = ""
			}
			if !s.RequiresIntegrity {
				s.CryptHashType = ""
				s.RootHash = ""
			}
			bytes, _ := s.Encode()
			logrus.Debugf("secureoverlay2: GetMetadata, adding (encoded) security meta-data %s", s)
			metadata["security-meta-data"] = string(bytes)
		} else {
			logrus.Debug("secureoverlay2: GetMetadata, security meta-data indicates unsecured layer, skip security meta data addition")
		}
	case os.IsNotExist(err):
		logrus.Debugf("secureoverlay2: GetMetadata, no security meta-data found to be added: %v", err)
	default:
		return nil, err
	}

	logrus.Debugf("secureoverlay2: GetMetadata return w. metadata: %v", metadata)

	return metadata, nil
}

// Cleanup any state created by overlay which should be cleaned when daemon
// is being shutdown. For now, we just have to unmount the bind mounted
// we had created.
func (d *Driver) Cleanup() error {
	logrus.Debug("secureoverlay2: Cleanup called")
	return mount.RecursiveUnmount(d.home)
}

// CreateReadWrite creates a layer that is writable for use as a container
// file system.
func (d *Driver) CreateReadWrite(id, parent string, opts *graphdriver.CreateOpts) error {
	logrus.Debugf("secureoverlay2: CreateReadWrite called w. id: %s, parent: %s, opts: %v", id, parent, opts)
	return d.Create(id, parent, opts)
}

// Create is used to create the upper, lower, and merge directories required for overlay fs for a given id.
// The parent filesystem is used to configure these directories for the overlay.
func (d *Driver) Create(id, parent string, opts *graphdriver.CreateOpts) (retErr error) {
	logrus.Debugf("secureoverlay2: Create called w. id: %s, parent: %s, opts: %s", id, parent, opts)
	imgCryptOpts := &secureImgCryptOptions{}
	imgCryptOpts.init(d.options.defaultSecOpts)
	driver := &Driver{}
	err := errors.New("")

	if opts != nil && len(opts.ImgCryptOpt) != 0 {
		err = d.parseImgCryptOpt(opts.ImgCryptOpt, imgCryptOpts, driver)
		if err != nil {
			return fmt.Errorf("--storage-opt parsing error: %s", err.Error())
		}
	}

	// create all directories
	// - standard ones
	dir := d.dir(id)
	rootUID, rootGID, err := idtools.GetRootUIDGID(d.uidMaps, d.gidMaps)
	if err != nil {
		return err
	}
	root := idtools.Identity{UID: rootUID, GID: rootGID}
	if err := idtools.MkdirAllAndChown(path.Dir(dir), 0700, root); err != nil {
		return err
	}
	if err := idtools.MkdirAndChown(dir, 0700, root); err != nil {
		return err
	}
	// unclear why couldn't just have done MkDirAllAs of dir in one go but that's what overlay2 did, so left it ..

	defer func() {
		// Clean up on failure
		if retErr != nil {
			os.RemoveAll(dir)
		}
	}()
	if opts != nil && len(opts.ImgCryptOpt) > 0 && projectQuotaSupported {
		if driver.options.quota.Size > 0 {
			// Set container disk quota limit
			if err := d.quotaCtl.SetQuota(dir, driver.options.quota); err != nil {
				return err
			}
		}
	}

	if err := idtools.MkdirAndChown(path.Join(dir, "diff"), 0755, root); err != nil {
		return err
	}
	lid := generateID(idLength)
	if err := os.Symlink(path.Join("..", id, "diff"), path.Join(d.home, linkDir, lid)); err != nil {
		return err
	}

	// Write link id to link file
	if err := ioutil.WriteFile(path.Join(dir, "link"), []byte(lid), 0644); err != nil {
		return err
	}
	// if no parent directory, done

	if parent != "" {
		if err := idtools.MkdirAndChown(path.Join(dir, "work"), 0700, root); err != nil {
			return err
		}
		if err := idtools.MkdirAndChown(path.Join(dir, "merged"), 0700, root); err != nil {
			return err
		}

		lower, err := d.getLower(parent)
		if err != nil {
			return err
		}
		if lower != "" {
			if err := ioutil.WriteFile(path.Join(dir, lowerFile), []byte(lower), 0666); err != nil {
				return err
			}
		}
	}
	// create secure dirs
	secureDir := path.Join(dir, constSecureBaseDirName)

	if err := idtools.MkdirAndChown(secureDir, 0755, root); err != nil {
		return err
	}
	if err := d.createSecureDiffDir(id, ""); err != nil {
		return err
	}

	if err := idtools.MkdirAndChown(path.Join(secureDir, constSecureCryptMntDirName), 0755, root); err != nil {
		return err
	}
	// initialize secure storage space
	if err := d.initSecureStorage(id, *imgCryptOpts); err != nil {
		logrus.Debugf("secureoverlay2: Create w. id: %s, failed to initalize secure storage %s", id, err.Error())
		return err
	}

	logrus.Debug("secureoverlay2: Create returns")

	return nil
}

func (d *Driver) initSecureStorage(id string, opts secureImgCryptOptions) error {
	logrus.Debugf("secureoverlay2: initSecureStorage called w. id: %s, opts: %v", id, opts)
	// -init layers are ephemeral for parameter passing, ..
	if strings.HasSuffix(id, "-init") {
		// .. and as we anyway have to trust integrity of local filesystem and these params are not secret,
		// just disable any encryption/integrity ...
		opts.init(constNoSecurityOption)
		// .. but still continue and write (modified) secopts
	}

	return d.putSecurityMetaDataForID(id, "", opts)
}

// Parse overlay storage options
func (d *Driver) parseImgCryptOpt(imgCryptOpt map[string]string, opts *secureImgCryptOptions, driver *Driver) error {
	logrus.Debugf("secureoverlay2: parseImgCryptOpt called w. imgCryptOpt: %s", imgCryptOpt)
	// Read size to set the disk project quota per container
	for key, val := range imgCryptOpt {
		lcKey := strings.ToLower(key)
		switch lcKey {
		case "size":
			size, e := units.RAMInBytes(val)
			if e != nil {
				return e
			}
			driver.options.quota.Size = uint64(size)
		case "requiresconfidentiality":
			if v, e := strconv.ParseBool(val); e == nil {
				opts.RequiresConfidentiality = v
			} else {
				return fmt.Errorf("secureoverlay2: %s not a boolean value for option RequiresConfidentiality", val)
			}
		case "requiresintegrity":
			if v, e := strconv.ParseBool(val); e == nil {
				opts.RequiresIntegrity = v
			} else {
				return fmt.Errorf("secureoverlay2: %s not a boolean value for option RequiresIntegrity", val)
			}
		case "keyhandle":
			opts.KeyHandle = val
		case "keytype":
			lcVal := strings.ToLower(val)
			switch lcVal {
			case constKeyTypeString, constKeyTypeKeyrings, constKeyTypeAPI, constKeyTypeKMS:
				opts.KeyType = lcVal
			default:
				return fmt.Errorf("secureoverlay2: %s not a valid value for option KeyType", val)
			}
		case "keytypeoption":
			opts.KeyTypeOption = val
		case "keydesc":
			opts.KeyDesc = val
		case "keysize":
			opts.KeySize = val
		case "keyfilepath":
			opts.KeyFilePath = val
		case "cryptcipher":
			opts.CryptCipher = val
		case "crypthashtype":
			opts.CryptHashType = val
		default:
			return fmt.Errorf("Unknown option %s", key)
		}
	}

	logrus.Debugf("secureoverlay2: parseImgCryptOpt returns secureImgCryptOptions: %s", opts)

	return nil
}

func (d *Driver) getLower(parent string) (string, error) {
	logrus.Debugf("secureoverlay2: getLower called w. parent: %s", parent)

	parentDir := d.dir(parent)

	// Ensure parent exists
	if _, err := os.Lstat(parentDir); err != nil {
		return "", err
	}

	// Read Parent link fileA
	parentLink, err := ioutil.ReadFile(path.Join(parentDir, "link"))
	if err != nil {
		return "", err
	}
	lowers := []string{path.Join(linkDir, string(parentLink))}

	parentLower, err := ioutil.ReadFile(path.Join(parentDir, lowerFile))
	if err == nil {
		parentLowers := strings.Split(string(parentLower), ":")
		lowers = append(lowers, parentLowers...)
	}
	if len(lowers) > maxDepth {
		return "", errors.New("max depth exceeded")
	}

	lowersStr := strings.Join(lowers, ":")
	logrus.Debugf("secureoverlay2: returns: %s", lowersStr)

	return lowersStr, nil
}

func (d *Driver) dir(id string) string {
	return path.Join(d.home, id)
}

func (d *Driver) getLowerDirs(id string) ([]string, error) {
	logrus.Debugf("secureoverlay2: getLowerDirs called w. id: %s", id)

	var lowersArray []string
	lowers, err := ioutil.ReadFile(path.Join(d.dir(id), lowerFile))
	if err == nil {
		for _, s := range strings.Split(string(lowers), ":") {
			lp, err := os.Readlink(path.Join(d.home, s))
			if err != nil {
				return nil, err
			}
			lowersArray = append(lowersArray, path.Clean(path.Join(d.home, linkDir, lp)))

			logrus.Debugf("secureoverlay2: getLowerDirs w. id: %s, link-dir: %s, lp: %s", id, linkDir, lp)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	logrus.Debugf("secureoverlay2: getLowerDirs returns: %v", lowersArray)

	return lowersArray, nil
}

// get an array filled with id(s) of all lower layers
func (d *Driver) getDiffChain(id string) ([]string, error) {
	logrus.Debugf("secureoverlay2: getDiffChain called w. id: %s", id)

	var chain []string
	lowers, err := ioutil.ReadFile(path.Join(d.dir(id), lowerFile))
	if err == nil {
		for _, s := range strings.Split(string(lowers), ":") {
			lp, err := os.Readlink(path.Join(d.home, s))
			if err != nil {
				return nil, err
			}
			temp := strings.Split(string(lp), "/")
			chain = append(chain, temp[1])
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	logrus.Debugf("secureoverlay2: getDiffChain returns chain: %s", chain)

	return chain, nil
}

// mount all lower layers for given id
func (d *Driver) mountAllLowers(id string) error {
	logrus.Debugf("secureoverlay2: mountAllLowers called w. id: %s", id)

	// get graph id of all lower layers
	lowers, err := d.getDiffChain(id)
	if err != nil {
		return err
	}

	logrus.Debugf("secureoverlay2: mountAllLowers for id %s do umount lowers: %s", id, lowers)

	// mount all layers
	for _, lyr := range lowers {
		if err := d.mountLayersFor(lyr); err != nil {
			logrus.Errorf("secureoverlay2: mountAllLowers for id: %s, failed with an error: %s", id, err.Error())
			return err
		}
	}

	logrus.Debug("secureoverlay2: mountAllLowers returns")

	return nil
}

// unmount all lower layers for given id
func (d *Driver) umountAllLowers(id string) error {
	logrus.Debugf("secureoverlay2: umountAllLowers called w. id: %s", id)

	// get graph id of all lower layers
	lowers, err := d.getDiffChain(id)
	if err != nil {
		return err
	}

	logrus.Debugf("secureoverlay2: umountAllLowers for id: %s do unmount lowers: %s", id, lowers)

	// unmount all layers
	for _, lyr := range lowers {
		if err := d.umountLayersFor(lyr); err != nil {
			logrus.Errorf("secureoverlay2: unmountAllLowers for id: %s, failed with an error: %s", id, err.Error())
			return err
		}
	}

	logrus.Debug("secureoverlay2: umountAllLowers returns")

	return nil
}

// mount given layer on the diff path
func (d *Driver) mountLayersFor(id string) (err error) {
	logrus.Debugf("secureoverlay2: mountLayersFor called w. id: %s", id)

	// paths
	source := d.getSecureDiffPath(id, "", true)
	target := d.getDiffPath(id)

	// check reference counter, if layer is already mounted or not
	// Notes:
	// - locking is handled by lock on Get/Put, so no separate lock required.
	// - We do increment right away but do decrement if there is an error based on 'err' variables
	//   (i.e., DON'T DO err := BELOW!!). We keep track via recoveryState variables one what cleanup we
	//   will have to do and then do best effort clean-up
	type recoveryStateType int
	const ( // sorted so that a state implies any following ones as well
		vDevRS recoveryStateType = iota
		noRS
	)
	recoveryState := noRS
	refCount := fmt.Sprintf("%s-secure", id)
	if count := d.ctr.Increment(refCount); count > 1 {
		logrus.Debugf("secureoverlay2: mountLayersFor w. id: %s, skip mount due to reference count: %d", id, count)
		// ecryptfs is already mounted, skip mounting same layer again
		return nil
	}
	var vDev VirtualDevice
	defer func() {
		if err != nil {
			if c := d.ctr.Decrement(refCount); c <= 0 {
				switch recoveryState {
				case vDevRS:
					vDev.Put()
					fallthrough
				case noRS:
				}
			}
		}
	}()

	// check for security meta-data
	var s secureImgCryptOptions
	s, err = d.getSecurityMetaDataForID(id, "")
	switch {
	case err == nil:
		// we found it
	case os.IsNotExist(err):
		logrus.Debugf("secureoverlay2: mountLayersFor for id: %s, No meta-data file found. Skipping security initialization", id)
		return nil
	default:
		return err
	}

	if strings.HasSuffix(id, "-init") {
		logrus.Debugf("secureoverlay2: mountLayersFor return w. id: %s, init layer", id)
		return nil
	}

	// check for required security method
	if !(s.RequiresConfidentiality || s.RequiresIntegrity) {
		logrus.Infof("secureoverlay2: mountLayersFor, no security required for the layer id: %s", id)
		return nil
	}

	if !s.IsSecurityTransformed {
		logrus.Warnf("secureoverlay2: mountLayersFor, Security Device file is not initialized for id: %s. Skipping mounting", id)
		return nil
	}

	if s.IsEmptyLayer {
		logrus.Warnf("secureoverlay2: mountLayersFor, Security Device file is empty for id: %s. Skipping mounting", id)
		return nil
	}

	key := ""
	if s.RequiresConfidentiality && s.KeyType == constKeyTypeKMS {
		key, _, err = getKey(s.KeyFilePath, s.KeyHandle)
		if err != nil {
			logrus.Debugf("secureoverlay2: mountLayersFor key %s retrieved from WLA, err %v", key, err)
			return err
		}
	} else if s.RequiresConfidentiality && s.KeyType == constKeyTypeString {
		key = s.KeyTypeOption
		logrus.Debugf("secureoverlay2: mountLayersFor key %s passed as string", key)
	}

	cp := CryptParams{}
	if s.RequiresConfidentiality {
		cp.Cipher = s.CryptCipher
		cp.Key = key
		cp.KeySize = s.KeySize
		cp.HashType = s.CryptHashType
	}

	vp := VerityParams{}
	if s.RequiresIntegrity {
		vp.RootHash = s.RootHash
		vp.HashImage = path.Join(source, constHashImageName)
	}

	dp := DeviceParams{
		FsType:  ConstFsTypeExt4,
		Mnt:     target,
		UIDMaps: d.uidMaps,
		GIDMaps: d.gidMaps,
	}

	ri := RawImage{
		ImagePath: path.Join(source, constImageName),
	}

	devType := ""
	if s.RequiresConfidentiality {
		devType = ConstTypeCrypt
	}
	if s.RequiresIntegrity {
		devType = ConstTypeVerity
	}
	if s.RequiresConfidentiality && s.RequiresIntegrity {
		devType = ConstTypeCryptVerity
	}

	// mount crypt device
	vDev = VirtualDevice{
		Image:        ri,
		Name:         id,
		Type:         devType,
		Deviceparams: dp,
		Cryptparams:  cp,
		Verityparams: vp,
	}

	if err = vDev.Get(); err != nil {
		logrus.Errorf("secureoverlay2: mountLayersFor w. id: %s, failed to mount layer, error: %s", id, err.Error())
		return err
	}

	// successful return
	logrus.Debug("secureoverlay2: mountLayersFor returns")

	return nil
}

func (d *Driver) umountLayersFor(id string) (err error) {
	logrus.Debugf("secureoverlay2: umountLayersFor called w. id: %s", id)

	// paths
	source := d.getSecureDiffPath(id, "", true)
	target := d.getDiffPath(id)

	// check counter for this mount point:
	// Notes:
	// - locking is handled by lock on Get/Put, so no separate lock required.
	// - We do decrement right away and do no increment-on-error but just try to clean up as good as we can
	refCount := fmt.Sprintf("%s-secure", id)
	if count := d.ctr.Decrement(refCount); count > 0 {
		// mount point is used by another container, so return without unmount
		logrus.Debugf("secureoverlay2: umountLayersFor w. id: %s, reference count: %d, skipping unmount as still referenced", id, count)
		return nil
	}

	// check for security meta-data
	var s secureImgCryptOptions
	s, err = d.getSecurityMetaDataForID(id, "")
	switch {
	case err == nil:
		// we found it
	case os.IsNotExist(err):
		logrus.Debugf("secureoverlay2: umountLayersFor w. id: %s, No meta-data file found. Skipping unmount", id)
		return nil
	default:
		return err
	}

	if strings.HasSuffix(id, "-init") {
		logrus.Debugf("secureoverlay2: umountLayersFor return w. id: %s, init layer", id)
		return nil
	}

	// check for required security method
	if !(s.RequiresConfidentiality || s.RequiresIntegrity) {
		logrus.Infof("secureoverlay2: umountLayersFor w. id: %s, no security required for the layer", id)
		return nil
	}

	if !s.IsSecurityTransformed {
		logrus.Warnf("secureoverlay2: umountLayersFor w. id: %s, Security Device file is not initiliazed. Skipping unmounting", id)
		return nil
	}

	if s.IsEmptyLayer {
		logrus.Warnf("secureoverlay2: umountLayersFor w. id: %s, Security Device file is empty. Skipping unmounting", id)
		return nil
	}

	dp := DeviceParams{
		FsType:  ConstFsTypeExt4,
		Mnt:     target,
		UIDMaps: d.uidMaps,
		GIDMaps: d.gidMaps,
	}

	ri := RawImage{
		ImagePath: path.Join(source, constImageName),
	}

	devType := ""
	if s.RequiresConfidentiality {
		devType = ConstTypeCrypt
	}
	if s.RequiresIntegrity {
		devType = ConstTypeVerity
	}
	if s.RequiresConfidentiality && s.RequiresIntegrity {
		devType = ConstTypeCryptVerity
	}

	// mount crypt device
	vDev := VirtualDevice{
		Image:        ri,
		Name:         id,
		Type:         devType,
		Deviceparams: dp,
		Cryptparams:  CryptParams{},
		Verityparams: VerityParams{},
	}

	if err = vDev.Put(); err != nil {
		logrus.Errorf("secureoverlay2: umountLayersFor w. id: %s, failed to unmount layer, error: %s", id, err.Error())
		return err
	}

	// successful return
	logrus.Debug("secureoverlay2: umountLayersFor returns")
	return nil
}

// Remove cleans the directories that are created for this id.
func (d *Driver) Remove(id string) error {
	logrus.Debugf("secureoverlay2: Remove called w. id: %s", id)
	d.locker.Lock(id)
	defer d.locker.Unlock(id)
	dir := d.dir(id)
	lid, err := ioutil.ReadFile(path.Join(dir, "link"))
	if err == nil {
		if err := os.RemoveAll(path.Join(d.home, linkDir, string(lid))); err != nil {
			logrus.Errorf("secureoverly2: Failed to remove link: %v", err)
		}
	}

	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	logrus.Debug("secureoverlay2: Remove returns")
	return nil
}

// Get creates and mounts the required file system for the given id and returns the mount path.
func (d *Driver) Get(id string, mountLabel string) (_ containerfs.ContainerFS, err error) {
	var (
		dir, diffDir, mergedDir, workDir, mountOptionsFmt string
		lowers                                            []byte
		s                                                 secureImgCryptOptions
	)

	logrus.Debugf("secureoverlay2: Get called w. id: %s, mountLabel: %s", id, mountLabel)

	// driver level locking
	d.locker.Lock(id)
	defer d.locker.Unlock(id)

	// various directory variables
	dir = d.dir(id)
	if _, err = os.Stat(dir); err != nil {
		return nil, err
	}

	diffDir = path.Join(dir, "diff")
	mergedDir = path.Join(dir, "merged")
	workDir = path.Join(dir, "work")

	// reference counting so we do not try to remount
	// Note: we do increment right away but do decrement if there is an error based on 'err' variables
	// (i.e., DON'T DO err := BELOW!!). We keep track via recoveryState variables one what cleanup we
	// will have to do and then do best effort clean-up
	type recoveryStateType int
	const ( // sorted so that a state implies any following ones as well
		umountMergeRS recoveryStateType = iota
		umountAllLowersRS
		umountLayerRS
		noRS
	)
	recoveryState := noRS
	if count := d.ctr.Increment(mergedDir); count > 1 {
		logrus.Debugf("secureoverlay2: Get w. id: %s, reference count: %d, returning existing mounted dir", id, count)
		return containerfs.NewLocalContainerFS(mergedDir), nil
	}
	defer func() {
		if err != nil {
			if c := d.ctr.Decrement(mergedDir); c <= 0 {
				switch recoveryState {
				case umountMergeRS:
					syscall.Unmount(mergedDir, 0)
					fallthrough
				case umountAllLowersRS:
					d.umountAllLowers(id)
					fallthrough
				case umountLayerRS:
					d.umountLayersFor(id)
					fallthrough
				case noRS:
				}
			}
		}
	}()

	//***************** security related per-layer device setup and mounting
	if err = d.mountLayersFor(id); err != nil {
		logrus.Errorf("secureoverlay2: Get w. id: %s, failed to mount ecryptfs, error: %s", id, err.Error())
		return nil, err
	}
	recoveryState = umountLayerRS

	if err = d.mountAllLowers(id); err != nil {
		return nil, err
	}
	recoveryState = umountAllLowersRS

	//******************* overlay mount related stuff
	lowers, err = ioutil.ReadFile(path.Join(dir, lowerFile))
	if err != nil {
		// If no lower, just return diff directory
		if os.IsNotExist(err) {
			logrus.Debugf("secureoverlay2: Get returns w. id: %s, dir: %s, no lower", diffDir, id)
			return containerfs.NewLocalContainerFS(diffDir), nil
		}
		return nil, err
	}

	splitLowers := strings.Split(string(lowers), ":")
	absLowers := make([]string, len(splitLowers))
	for i, s := range splitLowers {
		absLowers[i] = path.Join(d.home, s)
	}

	// if we are already securityTransformed with security enabled, we can only mount read-only!
	s, err = d.getSecurityMetaDataForID(id, "")
	if err != nil {
		return nil, fmt.Errorf("Missing security meta data (err=%v)", err)
	}
	if !s.IsSecurityTransformed || s.IsEmptyLayer || (!s.RequiresConfidentiality && !s.RequiresIntegrity) {
		mountOptionsFmt = "upperdir=%s,lowerdir=%s,workdir=%s"
	} else {
		logrus.Infof("secureoverlay2: Mounting layer %s read-only!", id) // in common use-cases this should be fine but put a default log to be on safe side
		mountOptionsFmt = "lowerdir=%s:%s%0.0s"
		// Note:
		// - in read-only case, we do not need workdir but fmt requires 3 parameters, hence add zero-length third param
		// - also important that upperdir is before lowerdir as we will have to prefix in read-only case!!
		// - we don't have to pass read-only flag, it will be automatic once upper dir is missing
		//   (note adding, "ro," doesn't work, would have to be encoded as flag ...)
	}

	opts := fmt.Sprintf(mountOptionsFmt, path.Join(dir, "diff"), strings.Join(absLowers, ":"), path.Join(dir, "work"))
	mountData := label.FormatMountLabel(opts, mountLabel)
	mount := syscall.Mount
	mountTarget := mergedDir

	pageSize := syscall.Getpagesize()

	// Go can return a larger page size than supported by the system
	// as of go 1.7. This will be fixed in 1.8 and this block can be
	// removed when building with 1.8.
	// See https://github.com/golang/go/commit/1b9499b06989d2831e5b156161d6c07642926ee1
	// See https://github.com/docker/docker/issues/27384
	if pageSize > 4096 {
		pageSize = 4096
	}

	// Use relative paths and mountFrom when the mount data has exceeded
	// the page size. The mount syscall fails if the mount data cannot
	// fit within a page and relative links make the mount data much
	// smaller at the expense of requiring a fork exec to chroot.
	if len(mountData) > pageSize {
		opts = fmt.Sprintf(mountOptionsFmt, path.Join(id, "diff"), string(lowers), path.Join(id, "work"))
		mountData = label.FormatMountLabel(opts, mountLabel)
		if len(mountData) > pageSize {
			return nil, fmt.Errorf("cannot mount layer, mount label too large %d", len(mountData))
		}

		mount = func(source string, target string, mType string, flags uintptr, label string) error {
			return mountFrom(d.home, source, target, mType, flags, label)
		}
		mountTarget = path.Join(id, "merged")
	}

	logrus.Debugf("secureoverlay2: Get -> overlay mount: mount -t overlay -o %s none %s", mountData, mountTarget)

	if err = mount("overlay", mountTarget, "overlay", 0, mountData); err != nil {
		return nil, fmt.Errorf("error creating overlay mount to %s: %v", mergedDir, err)
	}
	recoveryState = umountMergeRS

	if !s.IsSecurityTransformed || s.IsEmptyLayer || (!s.RequiresConfidentiality && !s.RequiresIntegrity) {
		// chown "workdir/work" to the remapped root UID/GID. Overlay fs inside a
		// user namespace requires this to move a directory from lower to upper.
		var rootUID, rootGID int
		rootUID, rootGID, err = idtools.GetRootUIDGID(d.uidMaps, d.gidMaps)
		if err != nil {
			return nil, err
		}

		if err = os.Chown(path.Join(workDir, "work"), rootUID, rootGID); err != nil {
			return nil, err
		}
	}

	logrus.Debugf("secureoverlay2: Get returns, mergedDir: %s", mergedDir)

	return containerfs.NewLocalContainerFS(mergedDir), nil
}

// Put unmounts the mount path created for the give id.
func (d *Driver) Put(id string) error {
	logrus.Debugf("secureoverlay2: Put called w. id: %s", id)

	// driver level locking
	d.locker.Lock(id)
	defer d.locker.Unlock(id)

	// various directory variables
	dir := d.dir(id)
	mountpoint := path.Join(dir, "merged")

	// reference counting so we do not try to remount
	// Note: no clean-up on errors with post-increment or alike but try best effort to clean-up
	if count := d.ctr.Decrement(mountpoint); count > 0 {
		logrus.Debugf("secureoverlay2: Put w. id: %s, reference count: %d, still referenced, not unmounting", id, count)
		return nil
	}

	var err1, err2, err3 error
	//******************* overlay mount related stuff
	_, err := ioutil.ReadFile(path.Join(dir, lowerFile))
	if err != nil {
		// If no lower, no mount happened and just return directly
		if !os.IsNotExist(err) {
			logrus.Errorf("secureoverlay2: Put returns w. id: %s, error=%v", id, err)
			return err
		}
		logrus.Debugf("secureoverlay2: Put, no lower")
		err1 = nil
	} else {
		logrus.Debugf("secureoverlay2: Put, do overlay unmount: umount %s", mountpoint)
		if err1 = unix.Unmount(mountpoint, unix.MNT_DETACH); err1 != nil {
			logrus.Errorf("secureoverlay2: Put w. id: %s, failed to unmount %s overlay with error: %s - %v", id, mountpoint, err1.Error(), err1)
			// still continue and try to unmount lower layers ...
		}
	}
	//***************** security related per-layer device setup and mounting
	if err2 := d.umountLayersFor(id); err2 != nil {
		logrus.Errorf("secureoverlay2: Put w. id: %s, failed to unmount ecryptfs, error: %s", id, err2.Error())
		// still continue and try to unmount lower layers ...
	}
	if err3 := d.umountAllLowers(id); err3 != nil {
		logrus.Errorf("secureoverlay2: Put w. id: %s, failed to unmount all lowers, error: %s", id, err3.Error())
	}

	//********************************************************************************************
	err = nil
	switch {
	case err1 != nil:
		err = err1
	case err2 != nil:
		err = err2
	case err3 != nil:
		err = err3
	}
	logrus.Debugf("secureoverlay2: Put w. id: %s returns with err=%v", id, err)
	return err
}

// Exists checks to see if the id is already mounted.
func (d *Driver) Exists(id string) bool {
	logrus.Debugf("secureoverlay2: Exists called w. id: %s", id)

	// TODO: below is implementation from overlay2 but doesn't really mesh with the function description (also from overlay2)
	//   as this should be true as soon as layer is created using Create, regardless of mount (call of Get)?!
	_, err := os.Stat(d.dir(id))
	return err == nil
}

// isParent returns if the passed in parent is the direct parent of the passed in layer
func (d *Driver) isParent(id, parent string) bool {
	// TODO (maybe): this function is called a lot and does lots of sub-routine calls and I/O.
	//  One might want to cache parent but should first be confirmed via profiling that really noticable performance cost
	logrus.Debugf("secureoverlay2: isParent called w. id: %s, parent: %s", id, parent)
	lowers, err := d.getLowerDirs(id)
	if err != nil {
		return false
	}
	if parent == "" && len(lowers) > 0 {
		return false
	}

	parentDir := d.dir(parent)
	var ld string
	if len(lowers) > 0 {
		ld = filepath.Dir(lowers[0])
	}
	if ld == "" && parent == "" {
		return true
	}
	return ld == parentDir
}

// ApplyDiff applies the new layer into a root
// ASSUMPTIONS:
// - either that layer didn't have any security options (and hence no meta-data file) or
//   there is a security meta-data file and the security transform was already applied
func (d *Driver) ApplyDiff(id string, parent string, diff io.Reader) (size int64, err error) {
	logrus.Debugf("secureoverlay2: ApplyDiff called w. id: %s, parent: %s", id, parent)

	if parent != "" && !d.isParent(id, parent) {
		return -1, fmt.Errorf("secureoverlay2: ApplyDiff for non-parent diffs is not supported for secureoverlay2 for an existing parent %s which is not immediate parent of %s ", id, parent)
		// Note: secureoverlay2 runs ..
		//   size, err = d.naiveDiff.ApplyDiff(id, parent, diff)
		//   if (err != nil) { return  size, err }
		// .. regardless of having a parent (parent != "") but naiveDiff.ApplyDiff ignores parent which
		// doesn't really make sense unless isParent is false because there is none (parent == "").
		// Presumably, naiveDiff.ApplyDiff is called even for base layers because of whiteouts.
		// However, whiteouts should be so that it's very unlikely to exist anyway as there is no
		// fundamental difference between base layers and upper layers and doing untar ourselves simplifies
		// so we don't use naiveDiff.ApplyDiff at all
	}

	// We do that to secure diff so we can find meta-data (if existing) where it usually is.
	// If there was none (because it's a legacy layer or there is no security), though, we will
	// have to move the files back later to the non-secure path so the data is found
	diffCryptPath := d.getSecureDiffPath(id, "", false)

	// Remove any pre-existing security meta-data so we know when we get a legacy layer
	secureDiffMetaFile := path.Join(diffCryptPath, constMetaDataFileName)
	if err := os.Remove(secureDiffMetaFile); err != nil {
		logrus.Errorf("secureoverlay2: ApplyDiff w. id: %s, failed to remove old security meta data file %s", id, secureDiffMetaFile)
		return -1, err
	}

	logrus.Debugf("secureoverlay2: ApplyDiff, applying tar in %s", diffCryptPath)
	if err := untar(diff, diffCryptPath, &archive.TarOptions{
		UIDMaps:        d.uidMaps,
		GIDMaps:        d.gidMaps,
		WhiteoutFormat: archive.OverlayWhiteoutFormat,
	}); err != nil {
		return -1, err
	}

	s, err := d.getSecurityMetaDataForID(id, "")
	switch {
	case os.IsNotExist(err):
		// Note: there might be layers created by other drivers which do not have any security meta-data.
		// This is fine for encryption, for integrity you would need integrity all-the-way down to make
		// sense but this is handled elsewhere
		logrus.Debugf("secureoverlay2: ApplyDiff w. id: %s, No meta-data file found. Assuming it is a legacy layer", id)
		// create an apprirate security metadata file (or below move back will fail)
		s = secureImgCryptOptions{}
		s.init(constNoSecurityOption)
		if err := d.putSecurityMetaDataForID(id, "", s); err != nil {
			logrus.Errorf("secureoverlay2: ApplyDiff w. id: %s, error in updating device status for legacy layer, error: %s", id, err.Error())
			return -1, err
		}
	case err != nil:
		logrus.Errorf("secureoverlay2: ApplyDiff w. id: %s, meta-data exists but is corrupted", id)
		return -1, err
	case s.RequiresConfidentiality || s.RequiresIntegrity:
		size, err := directory.Size(context.TODO(), diffCryptPath)
		logrus.Debugf("secureoverlay2: ApplyDiff w. id: %s & secured layer, return size: %d, err: %v", id, size, err)
		return size, err

	case !s.RequiresConfidentiality && !s.RequiresIntegrity:
		logrus.Debugf("secureoverlay2: ApplyDiff w. id: %s, layer with no security", id)
	}

	logrus.Debugf("secureoverlay2: ApplyDiff w. id: %s, fixing date location for non-secured data layer", id)
	diffPath := d.getDiffPath(id)

	// remove diffPath
	if err := os.Remove(diffPath); err != nil {
		logrus.Errorf("secureoverlay2: ApplyDiff w. id: %s, failed to remove %s before move secure->insecure", id, diffPath)
		return -1, err
	}

	// rename diffCryptPath to diffPath
	if err := os.Rename(diffCryptPath, diffPath); err != nil {
		logrus.Errorf("secureoverlay2: ApplyDiff w. id: %s, error in moving data from %s to secure area %s", id, diffCryptPath, diffPath)
		return -1, err
	}

	// recreate diffCryptPath
	rootUID, rootGID, err := idtools.GetRootUIDGID(d.uidMaps, d.gidMaps)
	root := idtools.Identity{UID: rootUID, GID: rootGID}
	if err != nil {
		return -1, err
	}
	if err := idtools.MkdirAndChown(diffCryptPath, 0755, root); err != nil {
		logrus.Errorf("secureoverlay2: ApplyDiff w. id: %s, error in creating secure directory %s", id, diffCryptPath)
		return -1, err
	}

	// move back security meta data which was "wrongly" moved
	diffMetaFile := path.Join(diffPath, constMetaDataFileName)
	if err := os.Rename(diffMetaFile, secureDiffMetaFile); err != nil {
		logrus.Errorf("secureoverlay2: ApplyDiff w. id: %s, error in moving security metadata back from %s to secure area %s", id, diffPath, diffCryptPath)
		return -1, err
	}

	size, err = directory.Size(context.TODO(), diffPath)
	logrus.Debugf("secureoverlay2: ApplyDiff returns w. id: %s & non-secured layer, return size: %d, err: %v", id, size, err)
	return size, err
}

func (d *Driver) getDiffPath(id string) string {
	dir := d.dir(id)

	return path.Join(dir, "diff")
}

// DiffSize calculates the changes between the specified id
// and its parent and returns the size in bytes of the changes
// relative to its base filesystem directory.
// Notes
// - will current report different size before and after security transform is done!
//   If called early the reported size will be smaller than it eventually will be due to transform overhead.
//   This will violate some tests in test suite: graphtest.DriverTestDiffApply DOES test for equality of this
//   with size returned by ApplyDiff (graphtest.BenchamrkDiffN also tests but does not enforce; For now these
//   tests are disabled (as they are when naivediff is used!).
func (d *Driver) DiffSize(id, parent string) (size int64, err error) {
	logrus.Debugf("secureoverlay2: DiffSize called w. id: %s, parent: %s", id, parent)

	// read security meta data to see whether we are already initialized
	s, err := d.getSecurityMetaDataForID(id, parent)
	switch {
	case err == nil:
		// good ...
	case os.IsNotExist(err):
		// this could be because there is either
		// (a) a legacy layer (implicitly with no security) or
		// (b) there is security but the parent is not immediate parent of id and hasn't been diffed/transformed yet
		// The case (a) will be handled properly but for now we treat
		// case (b) as it would have also no security and do underreport size
		// TODO: do on-demand securityTransform (as in Diff()) for case (b)
		s = secureImgCryptOptions{}
		s.init(constNoSecurityOption)
		// do _not_ persist for now but might have to reconsider this?
	default:
		return -1, fmt.Errorf("secureoverlay2: DiffSize w. id %s/parent %s, error in reading security options (err=%s)", id, parent, err.Error())
	}

	if s.IsSecurityTransformed && !s.IsEmptyLayer && (s.RequiresConfidentiality || s.RequiresIntegrity) {
		size, err = directory.Size(context.TODO(), d.getSecureDiffPath(id, parent, false))
	} else {
		if useNaiveDiff(d.home) || !d.isParent(id, parent) {
			size, err = d.naiveDiff.DiffSize(id, parent)
		} else {
			size, err = directory.Size(context.TODO(), d.getDiffPath(id))
		}
	}

	logrus.Debugf("secureoverlay2: DiffSize, return size: %d, err: %v", size, err)
	return size, err
}

//********************* DiffGetter Implementation *************************************
// Note: this is called if split-tars are used which in turn is used of driver does not
// implement Capabilitiies.ReproducesExactDiffs.
// It is called _after_ a commit (and hence security transform), e.g., on push

type fileGetNilCloser struct {
	storage.FileGetter
}

func (f fileGetNilCloser) Close() error {
	return nil
}

// DiffGetter : Get the diff of the two layers
func (d *Driver) DiffGetter(id string) (graphdriver.FileGetCloser, error) {
	logrus.Debugf("secureoverlay2: DiffGetter called w. id: %s", id)

	diffPath := d.getDiffPath(id)

	// check for security meta-data
	s, err := d.getSecurityMetaDataForID(id, "")
	switch {
	case err == nil:
		if s.RequiresConfidentiality || s.RequiresIntegrity {
			diffPath = d.getSecureDiffPath(id, "", false)
		}
	case os.IsNotExist(err):
	default:
		return nil, err
	}

	logrus.Debugf("secureoverlay2: DiffGetter called w. id: %s", id)

	return fileGetNilCloser{storage.NewPathFileGetter(diffPath)}, nil
}

//*************************************************************************************

// Diff produces an archive of the changes between the specified
// layer and its parent layer which may be "".  It will apply the
// security transformation as specified in security meta data
// ASSUMPTIONS:
// - Diff is called only on frozen layers (i.e, no file state will ever change after first call to Diff())
// - if parent passed is not immediate parent of id/self,
//   then all layers between id/self and (excluding) parent must have
//   consisten security settings (including same key(id)!)
//   If above is not true security transformations might be lost
//   as-of-now that should be true as Diff is only called only once per layer as
//   part of commit and multi-layer happens in the case of SquashImage which
//   should operates on a per-dockerfile level which always should imply consistent security meta data
func (d *Driver) Diff(id, parent string) (io.ReadCloser, error) {
	logrus.Debugf("secureoverlay2: Diff called w. id: %s, parent: %s", id, parent)

	// 1.) read security meta data
	s, err := d.getSecurityMetaDataForID(id, parent)
	if err != nil {
		// we might not find it as it's for a parent which is not immediate parent  ..
		if !d.isParent(id, parent) {
			// .. so try default
			s, err = d.getSecurityMetaDataForID(id, "")
			if err != nil {
				// Note: this should be only called by Diff from a layer we created, so it should always have
				// metadata regardless of security settings contrary to, say lower layers which were potentially created
				// without security
				return nil, fmt.Errorf("secureoverlay2: Diff w. id %s/parent %s, error in reading security options (err=%s)", id, parent, err.Error())
			}
		}
		// we get here for non-immediate parents which haven't been diffed before ..
		// .. so we have to create corresponding diff dir ..
		if err := d.createSecureDiffDir(id, parent); err != nil {
			return nil, err
		}
		// .. and (unintialized!) metadata
		s.IsSecurityTransformed = false
		d.putSecurityMetaDataForID(id, parent, s)
	}

	// 2.) read clear-text diff stream ...
	var (
		clearDiffTar  io.ReadCloser
		clearDiffSize int64
	)
	// .. either we have to do a security transform or the device is already initialized but unsecured
	if !s.IsSecurityTransformed || s.IsEmptyLayer || (!s.RequiresConfidentiality && !s.RequiresIntegrity) {
		if useNaiveDiff(d.home) || !d.isParent(id, parent) {
			logrus.Debugf("secureoverlay2: Diff w. id %s/parent %s, doing naiveDiff.Diff", id, parent)
			// Note: the latter expression covers both the case where id is base (and hence parent=="")
			// and where parent is a non-immediate parent. The latter case we definitely have to do using naive;
			// the former is less essential as using naive only makes sure that name clashes with whiteout files
			// will handled properly but this should be very unlikely (as otherwise would happen also on upper layers)
			clearDiffTar, err = d.naiveDiff.Diff(id, parent)
			if err != nil {
				logrus.Errorf("secureoverlay2: Diff returns w. id %s/parent %s, error in doing naiveDiff.Diff: %s", id, parent, err.Error())
				return nil, err
			}
			clearDiffSize, err = d.DiffSize(id, parent)
			if err != nil {
				logrus.Errorf("secureoverlay2: Diff returns w. id %s/parent %s, error in computing size: %s", id, parent, err.Error())
				return nil, err
			}
		} else {
			logrus.Debugf("secureoverlay2: Diff w. id %s/parent %s, doing own Diff", id, parent)
			diffPath := d.getDiffPath(id)
			// get the diff size in bytes
			// Note: we use our own function instead of directory.Size(diffPath) to also account for filesystem overhead
			clearDiffSize, err = dirPlusMetaSize(diffPath)
			if err != nil {
				logrus.Errorf("secureoverlay2: Diff w. id %s/parent %s, error in computing size: %s", id, parent, err.Error())
				return nil, err
			}

			// Test whether is an empty layer (which will be suppressed by daemon). In that case we have to skip
			// security transform to keep it empty. We force it by turning declaring securityTransform as done
			// (and count on that docker will never try to mount an empty directory).  Note though that we must _not_
			// return the secure diff directory as this hosts the meta-data file and would result in a non-empty layer
			// from a docker daemon perspective!)
			// Alternatively, we could just turn security off completely (which also will skip securityTransform) but
			// while this makes less assumption on docker it wouldn't cause privacy clean-up for the meta-data of these layers.
			// NOTE: right now even the first approach doesn't clear privacy meta-data for layer as the on-disk security-meta-data
			// file gets lost -- by necessity as we have to return an empty disk to convince daemon that it is an empty-layer.
			// However, for strong integrity we will eventually have to work with in-memory sec-options and this might take care of it
			children, err := ioutil.ReadDir(diffPath)
			if err != nil {
				logrus.Errorf("secureoverlay2: Diff returns w. id %s/parent %s, failure to read diff directory %s (err=%s)", id, parent, diffPath, err.Error())
				return nil, err
			}
			if len(children) == 0 {
				logrus.Debug("secureoverlay2: Diff found empty layer")
				s.IsEmptyLayer = true
				s.IsSecurityTransformed = true
				if err := d.putSecurityMetaDataForID(id, parent, s); err != nil {
					logrus.Errorf("secureoverlay2: Diff returns w. id: %s/parent: %s, error in updating metadata for empty layer, error: %s", id, parent, err.Error())
					return nil, err
				}
			}
			// note: do tar at end to minimize window to deferred close (which we can only do iff we have securityTransform!)
			clearDiffTar, err = archive.TarWithOptions(diffPath, &archive.TarOptions{
				Compression:    archive.Uncompressed,
				UIDMaps:        d.uidMaps,
				GIDMaps:        d.gidMaps,
				WhiteoutFormat: archive.OverlayWhiteoutFormat,
			})
			if err != nil {
				logrus.Errorf("secureoverlay2: Diff returns w. id %s/parent %s, error in tarring clear data: %s", id, parent, err.Error())
				return nil, err
			}
		}
	}

	// 3.) handle the no-security or empty case
	if (!s.RequiresConfidentiality && !s.RequiresIntegrity) || s.IsEmptyLayer {
		logrus.Debugf("secureoverlay2: Diff returns on successful Diff with unsecured date and directory size: %d", clearDiffSize)
		return clearDiffTar, nil
	}

	// 4.) handle the security case ...

	// .. by doing transformation ...
	if !s.IsSecurityTransformed {
		defer clearDiffTar.Close()

		if err := d.securityTransform(id, parent, s, clearDiffTar, clearDiffSize); err != nil {
			logrus.Errorf("secureoverlay2: Diff returns w. id: %s/parent: %s, security transform failed with error: %s", id, parent, err.Error())
			return nil, err
		}
		// Note: we are NOT cleaning up non-secure version of the files.
		// This layer will should be removed anyway after the diff and
		// for the naiveDiff/squash case it's also complicated :-)
	}

	// .. and then tar the crypt diff
	diffCryptPath := d.getSecureDiffPath(id, parent, false)
	diffCryptTarOptions := archive.TarOptions{
		Compression:    archive.Uncompressed,
		UIDMaps:        d.uidMaps,
		GIDMaps:        d.gidMaps,
		WhiteoutFormat: archive.OverlayWhiteoutFormat,
	}
	logrus.Debugf("secureoverlay2: Diff tar of %s with options %v", diffCryptPath, diffCryptTarOptions)
	diffCryptTar, diffCryptTarErr := archive.TarWithOptions(diffCryptPath, &diffCryptTarOptions)

	logrus.Debugf("secureoverlay2: Diff returns, secured data, error: %v", diffCryptTarErr)
	return diffCryptTar, diffCryptTarErr
}

// Changes produces a list of changes between the specified layer
// and its parent layer. If parent is "", then all changes will be ADD changes.
// ASSUMPTIONS:
//   - will not be called with passed parent not being id's immediate parent
//     iff the involved layers have security options implying transformations.
func (d *Driver) Changes(id, parent string) ([]archive.Change, error) {
	logrus.Debugf("secureoverlay2: Changes called w. id: %s, parent: %s", id, parent)

	if useNaiveDiff(d.home) || !d.isParent(id, parent) {
		return d.naiveDiff.Changes(id, parent)
	}
	// Overlay doesn't have snapshots, so we need to get changes from all parent
	// layers.
	diffPath := d.getDiffPath(id)
	layers, err := d.getLowerDirs(id)
	if err != nil {
		return nil, err
	}

	c, cErr := archive.Changes(layers, diffPath)
	logrus.Debugf("secureoverlay2: Changes returns w error: %v", cErr)
	return c, cErr
}

// ############ Security Options ##################33

// - main functions to get and store

//   Get security related meta-data from image id and parent
//   - parent is optional and can be "", in which case the immediate parent, if existing is taken.
//   - Note that for non-secured layers (either legacy or explicitly no security) this might not find meta data
//     check with os.IsNotExist(err) to (potentially legitimate) absence of meta-data (vs a retrieval/decoding problem)
func (d *Driver) getSecurityMetaDataForID(id, parent string) (secureImgCryptOptions, error) {
	logrus.Debugf("secureoverlay2: getSecurityMetaDataForID called w. id: %s, parent: %s", id, parent)

	dir := d.getSecureDiffPath(id, parent, false)
	metaFile := path.Join(dir, constMetaDataFileName)

	s := secureImgCryptOptions{}
	err := s.load(metaFile)
	logrus.Debugf("secureoverlay2: getSecurityMetaDataForID returns with security opts %s (err=%v)", s, err)
	return s, err
}

//    Store security related meta-data from image id
func (d *Driver) putSecurityMetaDataForID(id, parent string, s secureImgCryptOptions) error {
	logrus.Debugf("secureoverlay2: putSecurityMetaDataForID called w. id: %s, parent: %s, data %s", id, parent, s)

	dir := d.getSecureDiffPath(id, parent, false)
	metaFile := path.Join(dir, constMetaDataFileName)

	err := s.save(metaFile)
	logrus.Debugf("secureoverlay2: putSecurityMetaDataForID returns, err=%v", err)
	return err
}

var ( // really should be a const but golang doesn't support const structs ...
	constNoSecurityOption = secureImgCryptOptions{
		RequiresConfidentiality: false,
		RequiresIntegrity:       false,
		KeyHandle:               "",
		KeySize:                 ConstDefaultKeySize,
		KeyType:                 constKeyTypeKeyrings,
		KeyTypeOption:           "",
		KeyDesc:                 "",
		CryptCipher:             ConstDefaultCipher,
		CryptHashType:           ConstDefaultHashType,
		RootHash:                "",
		IsEmptyLayer:            false,
		IsSecurityTransformed:   false,
	}
)

// - utility functions

func (s *secureImgCryptOptions) init(defaults secureImgCryptOptions) {
	*s = defaults
}

func (s secureImgCryptOptions) Encode() ([]byte, error) {
	return json.Marshal(s)
}

func (s *secureImgCryptOptions) Decode(bytes []byte) error {
	s.init(constNoSecurityOption)
	return json.Unmarshal(bytes, &s)
}

func (s secureImgCryptOptions) String() string {
	bytes, _ := s.Encode()
	return string(bytes)
}

func (s *secureImgCryptOptions) load(metaDataFile string) error {
	bytes, err := ioutil.ReadFile(metaDataFile)
	if err != nil {
		// no error as file might not exist for legitimate reasons
		// check with os.IsNotExist(err) to test for absence (rather than decode error or alike)
		logrus.Debugf("secureoverlay2: load failed to find meta-data, error: %s", err.Error())
		return err
	}
	if err := s.Decode(bytes); err != nil {
		logrus.Debugf("secureoverlay2: load failed to decode meta-data, error: %s", err.Error())
		return err
	}
	logrus.Debugf("secureoverlay2: load meta-data read successfully from %s: encoded %s -> meta-data %v", metaDataFile, bytes, s)
	return nil
}

func (s secureImgCryptOptions) save(metaDataFile string) error {
	bytes, err := s.Encode()
	if err != nil {
		logrus.Errorf("secureoverlay2: save, failed to encode meta-data, error: %s", err.Error())
		return err
	}
	if err := ioutil.WriteFile(metaDataFile, bytes, 0644); err != nil {
		logrus.Errorf("secureoverlay2: save, failed to write meta-data, error: %s", err.Error())
		return err
	}

	logrus.Debugf("secureoverlay2: save, meta-data write successfully to %s: meta-data %v -> encoded %s ", metaDataFile, s, bytes)
	return nil
}

// ############ Key Management ##################

//get key from kernel keyring using keyhandle
//if key found in kernel keyring the key will be returned
//timeout period will set on key in the kernel keyring.
//key will not be accessible from keyring after the timeout period.

func getKeyFromKeyCache(keyHandle string) (string, string, error) {
	//TODO Get timeout for Key in Workload agent KeyCache
	//_,keyExpireTime := getenv()
	// search for the key in keycache
	out, err := exec.Command("wlagent", "get-key-from-keycache", keyHandle).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("Could not open user-session-key ring for key-handle %s (err=%v)", keyHandle, err)
	}
	wrappedKey := string(out)
	wrappedKey = strings.TrimSuffix(wrappedKey, "\n")
	wrappedKey = strings.TrimSuffix(wrappedKey, " ")

	key, err := exec.Command("wlagent", "unwrap-key", wrappedKey).Output()
	if err != nil {
		return "", "", fmt.Errorf("Could not unwrap the key using tpm")
	}

	//TODO reset timeout after reading the key
	unwrappedKey := string(key)
	unwrappedKey = string(unwrappedKey)
	unwrappedKey = strings.TrimSuffix(unwrappedKey, "\n")
	unwrappedKey = strings.TrimSpace(unwrappedKey)

	return unwrappedKey, "", nil
}

// Interface to retrive encryption key for the layer, using layerid as key

func getKey(keyFilePath, keyHandle string) (string, string, error) {
        var rKey string
        var rKeyInfo string
        var rErr error
	if keyHandle == "" || encryptContainerImage {
		encryptContainerImage = true
		logrus.Debugf("secureoverlay2: getting key for encryption: %s ", keyHandle)
		if keyFilePath != "" {
			unwrappedKey, err := exec.Command("wpm", "unwrap-key", "-i", keyFilePath).CombinedOutput()
			if err != nil {
				return "", "", fmt.Errorf("secureoverlay2: Could not get unwrapped key from the wrapped key %v", err)
			}
			key := string(unwrappedKey)
			key = strings.TrimSuffix(key, "\n")
			key = strings.TrimSpace(key)
			keyInfo := strings.Split(keyFilePath, "_")
                        rKey, rKeyInfo, rErr = key, keyInfo[1], nil
		} else {
                        rKey, rKeyInfo, rErr = "", "", fmt.Errorf("secureoverlay2: keyFilePath empty")
		}

	} else {
                //fetch the key for encrypting/decrypting the image
                logrus.Debugf("secureoverlay2:  getting key for decryption on : %s ", keyHandle)
                rKey, rKeyInfo, rErr  = getKmsKeyFromKeyCache(keyHandle)
        }

        return rKey, rKeyInfo, rErr
}

//get kms key from keyring by polling on keyring every 100 milliseconds
//polling will happen maximum MAXKEYPOLL times on keyring
//if able to get key from keyring within poll time key will be returned else error will thrown

func getKmsKeyFromKeyCache(keyHandle string) (string, string, error) {
	counter := 0
	goto GetKey
GetKey:
	//search for the key in keyring
	data, _, err := getKeyFromKeyCache(keyHandle)
	if err != nil {
		logrus.Debugf("secureoverlay2: Error: Not able to get the key from keyring - %s, counter = %d", err.Error(), counter)
		if counter < MAXKEYPOLL {
			goto WaitForKey
		}
		return "", "", err
	}
	logrus.Debugf("secureoverlay2: Got the key in the keyring")
	return data, "", nil

WaitForKey:
	logrus.Debugf("secureoverlay2: Waiting for the key")
	time.Sleep(250 * time.Millisecond)
	counter++
	goto GetKey
}

// perform any security transforms as specified by security options
// this assumes either or both of confidentiality or integrity is required!
func (d *Driver) securityTransform(id, parent string, s secureImgCryptOptions, clearDiffTar io.ReadCloser, clearDiffSize int64) error {
	logrus.Debugf("secureoverlay2: securityTransform called w. id: %s/parent: %s, secopts: %v, clearDiffSize: %d", id, parent, s, clearDiffSize)
	var (
		key         string
		kmstranskey string
		err         error
	)

	// secure diff path for dm-crypt and dm-verity
	diffCryptPath := d.getSecureDiffPath(id, parent, false)
	// Note: while we could write securely remote (assuming integrity is enabled) we assume by
	// default remote is mounted read-only, so write local no matter what
	diffMntPath := d.getSecureCryptMntPath(id)

	logrus.Debugf("secureoverlay2: securityTransform w. id: %s, do security transformation w. sec-opts: %s, crypt path: %s, mnt path: %s", id, s, diffCryptPath, diffMntPath)

	if s.RequiresConfidentiality {
		// when key is stored in KMS
		if s.KeyType == constKeyTypeKMS {
			key, kmstranskey, err = getKey(s.KeyFilePath, s.KeyHandle)
			//Update the keyhandle only when we have created a new key from KMS
	                if kmstranskey != "" {
				s.KeyHandle = kmstranskey
				logrus.Infof("secureoverlay2: securityTransform  kms handle is: %s ", kmstranskey)
			}
		}

		// when key is passed via command line - used for TESTING ONLY
		if s.KeyType == constKeyTypeString {
			if len(strings.TrimSpace(s.KeyTypeOption)) == 0 {
				s.KeyTypeOption  = generateID(ConstDefaultStringKeyLength)
			}

			key = s.KeyTypeOption

			logrus.Infof("secureoverlay2: securityTransform using string key: %s ", key)
			err = nil
		}

		if err != nil {
			return err
		}

	}

	// create base image to hold encrypted diff contents
	cp := CryptParams{}
	if s.RequiresConfidentiality {
		cp.Cipher = s.CryptCipher
		cp.Key = key
		cp.KeySize = s.KeySize
		cp.HashType = s.CryptHashType
	}

	vp := VerityParams{}
	if s.RequiresIntegrity {
		vp.RootHash = s.RootHash
		vp.HashImage = path.Join(diffCryptPath, constHashImageName)
	}

	dp := DeviceParams{
		FsType:  ConstFsTypeExt4,
		Mnt:     diffMntPath,
		UIDMaps: d.uidMaps,
		GIDMaps: d.gidMaps,
	}

	ri := RawImage{
		ImagePath: path.Join(diffCryptPath, constImageName),
	}

	devType := ""
	if s.RequiresConfidentiality {
		devType = ConstTypeCrypt
	}
	if s.RequiresIntegrity {
		devType = ConstTypeVerity
	}
	if s.RequiresConfidentiality && s.RequiresIntegrity {
		devType = ConstTypeCryptVerity
	}

	// create device ...
	vDev := VirtualDevice{
		Image: ri,
		Name:  fmt.Sprintf("%s-%s", id, parent[:10]),
		// Note:
		// - for naive diff in case of squash, we might have a pending Get for immediate parent
		//   (whereas this might be security-transform for grand-parent). Hence the different id or devicemapper will clash
		// - just concatenating complete id will cause too long strings, so truncate parent
		Type:         devType,
		Deviceparams: dp,
		Cryptparams:  cp,
		Verityparams: vp,
	}

	if err := vDev.Create(clearDiffSize); err != nil {
		return err
	}

	// .. and import data onto it
	if err := vDev.ImportData(clearDiffTar); err != nil {
		return err
	}

	// update device status (and optionally dm-verity root hash) in meta-data
	if s.RequiresIntegrity {
		s.RootHash = vDev.getRootHash()
	}
	s.IsSecurityTransformed = true

	if err := d.putSecurityMetaDataForID(id, parent, s); err != nil {
		logrus.Errorf("secureoverlay2: securityTransform w. id: %s, error in updating device status, error: %s", id, err.Error())
		return err
	}

	logrus.Debug("secureoverlay2: securityTransform returns")

	return nil
}

// security directory handling

//   Get the secure diff directory path
//   - parent is optional and can be "", in which case the immediate parent, if existing is taken.
//   - If canBeRemote is true the returned path might be remote
//     (iff remoteDir is specified in daemon, remote dir exists and is not superceed by an existing local dir)
func (d Driver) getSecureDiffPath(id, parent string, canBeRemote bool) string {
	var diffDirName string

	if parent == "" || d.isParent(id, parent) {
		diffDirName = "diff"
	} else {
		diffDirName = fmt.Sprintf("%s-%s", "diff", parent)
	}

	localSecureDiffPath := path.Join(d.dir(id), constSecureBaseDirName, diffDirName)
	remoteSecureDiffPath := path.Join(d.options.remoteDir, id, constSecureBaseDirName, diffDirName)
	logrus.Debugf("secureoverlay2: getSecureDiffPath %s. localSecureDiffPath %s remoteSecureDiffPath", localSecureDiffPath, remoteSecureDiffPath)
	diffPath := localSecureDiffPath
	// remote only "wins" if local does not exist and remote exists
	if canBeRemote && d.options.remoteDir != "" {
		if b, _ := exists(localSecureDiffPath); !b {
			if b, _ := exists(remoteSecureDiffPath); b {
				diffPath = remoteSecureDiffPath
			}
		}
	}
	logrus.Debugf("secureoverlay2: getSecureDiffPath w. id: %s, parent: %s, canBeRemote: %v returns %s",
		id, parent, canBeRemote, diffPath)

	return diffPath
}

//   Create security diff directory
//   - see getSecureDiffPath for notes on parent parameter
//   - contrary to getSecureDiffPath, we only consider local directores (remote dirs are read-only
func (d Driver) createSecureDiffDir(id, parent string) error {
	var diffDirName string

	if parent == "" || d.isParent(id, parent) {
		diffDirName = "diff"
	} else {
		diffDirName = fmt.Sprintf("%s-%s", "diff", parent)
	}

	localSecureDiffPath := path.Join(d.dir(id), constSecureBaseDirName, diffDirName)

	rootUID, rootGID, err := idtools.GetRootUIDGID(d.uidMaps, d.gidMaps)
	if err != nil {
		return err
	}
	root := idtools.Identity{UID: rootUID, GID: rootGID}

	return idtools.MkdirAllAndChown(localSecureDiffPath, 0755, root)
}

//   Get a mount point for crypto-protected filesystems.
//   This should be used only for temporary operations such as security transforms
//   as usually the dm-crypt and/or dm-verity protected filesystem will be mounted on normal "diff" directory
func (d Driver) getSecureCryptMntPath(id string) string {
	return path.Join(d.dir(id), constSecureBaseDirName, constSecureCryptMntDirName)
}


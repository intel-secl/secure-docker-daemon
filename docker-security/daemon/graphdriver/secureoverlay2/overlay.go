// +build linux

package secureoverlay2

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/vbatts/tar-split/tar/storage"

	"github.com/docker/docker/daemon/graphdriver"
	"github.com/docker/docker/daemon/graphdriver/overlayutils"
	"github.com/docker/docker/daemon/graphdriver/quota"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/chrootarchive"
	"github.com/docker/docker/pkg/directory"
	"github.com/docker/docker/pkg/fsutils"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/locker"
	"github.com/docker/docker/pkg/mount"
	"github.com/docker/docker/pkg/parsers"
	"github.com/docker/docker/pkg/parsers/kernel"
	units "github.com/docker/go-units"

	"github.com/jsipprell/keyctl"
	"github.com/opencontainers/runc/libcontainer/label"
)

var (
	// untar defines the untar method
	untar = chrootarchive.UntarUncompressed
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
	driverName = "secureoverlay2"
	linkDir    = "l"
	lowerFile  = "lower"
	maxDepth   = 128

	// idLength represents the number of random characters
	// which can be used to create the unique link identifer
	// for every layer. If this value is too long then the
	// page size limit for the mount command may be exceeded.
	// The idLength should be selected such that following equation
	// is true (512 is a buffer for label metadata).
	// ((idLength + len(linkDir) + 1) * maxDepth) <= (pageSize - 512)
	idLength = 26

	// security related options
	constLocalCryptDiffDir         = "crypt-diff"
	constLocalOrRemoteCryptDiffDir = "remote-crypt-diff"
	constCryptMntDir               = "crypt-mnt"
	constSecureBaseDir             = "secure-base-dir"
	constIntegrityMntDir           = "int-mnt"
	constMetaDataFileName          = "security.meta"
	constKeyTypeString             = "key-type-string"
	constKeyTypeKeyrings           = "key-type-keyrings"
	constKeyTypeAPI                = "key-type-api"
	ConstImageName                 = "base.img"
	ConstHashImageName             = "hash.img"
	constKeySize                   = "128"
)

type overlayOptions struct {
	overrideKernelCheck bool
	remoteDir           string
	quota               quota.Quota
}

// meta-data related to storage security settings
// options:
//	IsSecure: set to true if security requires, false otherwise (regular overlay fallback)
//	IsConfidential: set to true if encryption is required for the storage, false otherwise
//	RequiresIntegrity: set to true if integrity protection is needed, false otherwise
//	KeyHandle: hanle for the key fetching mechanism (it can be key id for rest apis,
//			key signature for keyrings or plain key for testing purpose)
//	KeyType: "plain" => use keyHandle string as key for encrypiton (DO NOT USE IN PRODUCTION, THIS IS FOR TESTING ONLY)
//		 "keyrings" => use kernel keyrings to fetch key using signature provided via keyHandle
//		 "REST" => use rest APIs to fetch key using URL provided via keyHandle
//	KeySize: size of the key to be used for encryption (in bits)
//	CryptCipher: type of the cipher to be used for LUKS encryption
//	CryptHashType: hash type to be used for LUKS encrytion
//	RootHash: root hash of the integrity hash device
//	DeviceStatus: true if device is created, false otherwise

type secureStorageOptions struct {
	IsConfidential    bool   `json:"IsConfidential"`
	RequiresIntegrity bool   `json:"RequiresIntegrity"`
	KeyHandle         string `json:"KeyHandle"`
	KeySize           string `json:"KeySize"`
	KeyType           string `json:"KeyType"`
	CryptCipher       string `json:"CryptCipher"`
	CryptHashType     string `json:"CryptHashType"`
	RootHash          string `json:"RootHash"`
	DeviceStatus      bool   `json:"DeviceStatus"`
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
	secopts       map[string]secureStorageOptions
}

var (
	backingFs             = "<unknown>"
	projectQuotaSupported = false

	useNaiveDiffLock sync.Once
	useNaiveDiffOnly bool
)

func init() {
	logrus.Debugf("secureoverlay2: init called")
	graphdriver.Register(driverName, Init)
	logrus.Debugf("secureoverlay2: driver registered")
}

// Init returns the a native diff driver for overlay filesystem.
// If overlay filesystem is not supported on the host, graphdriver.ErrNotSupported is returned as error.
// If an overlay filesystem is not supported over an existing filesystem then error graphdriver.ErrIncompatibleFS is returned.
func Init(home string, options []string, uidMaps, gidMaps []idtools.IDMap) (graphdriver.Driver, error) {
	logrus.Debugf("secureoverlay2: Init function called. home: %s, options:%s", home, options)
	opts, err := parseOptions(options)
	if err != nil {
		return nil, err
	}
	logrus.Info("secureoverlay2: options: ", opts)

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

	fsMagic, err := graphdriver.GetFSMagic(home)
	if err != nil {
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
	if err := idtools.MkdirAllAs(path.Join(home, linkDir), 0700, rootUID, rootGID); err != nil && !os.IsExist(err) {
		return nil, err
	}

	if err := mount.MakePrivate(home); err != nil {
		return nil, err
	}

	supportsDType, err := fsutils.SupportsDType(home)
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
		secopts:       make(map[string]secureStorageOptions),
		options:       *opts,
	}

	d.naiveDiff = graphdriver.NewNaiveDiffDriver(d, uidMaps, gidMaps)

	if backingFs == "xfs" {
		// Try to enable project quota support over xfs.
		if d.quotaCtl, err = quota.NewControl(home); err == nil {
			projectQuotaSupported = true
		}
	}

	logrus.Debugf("backingFs=%s,  projectQuotaSupported=%v", backingFs, projectQuotaSupported)

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
		case "remoteroot":
			o.remoteDir = path.Join(val, driverName)

		default:
			return nil, fmt.Errorf("secureoverlay2: Unknown option %s\n", key)
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
		if err := hasOpaqueCopyUpBug(home); err != nil {
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
	return [][2]string{
		{"Backing Filesystem", backingFs},
		{"Supports d_type", strconv.FormatBool(d.supportsDType)},
		{"Native Overlay Diff", strconv.FormatBool(!useNaiveDiff(d.home))},
	}
}

// GetMetadata returns meta data about the overlay driver such as
// LowerDir, UpperDir, WorkDir and MergeDir used to store data.
func (d *Driver) GetMetadata(id string) (map[string]string, error) {
	logrus.Debugf("secureoverlay2: GetMetadata => id: %s", id)
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
	m, err := d.getSecMetaInfo(id)
	if err == nil {
		for k, v := range m {
			metadata[k] = v
		}
	} else {
		logrus.Errorf("error while adding security meta-data: %v", err)
	}

	// add remote dir in meta data
	metadata["remotedir"] = d.options.remoteDir
	return metadata, nil
}

// save metadata for the given id
func (d *Driver) saveMetaForID(id string, s secureStorageOptions) {
	d.secopts[id] = s
	logrus.Debugf("secureoverlay2: saveMetaForID => id: %s, meta: %v", id, d.secopts[id])
}

// load metadata for the given id
func (d *Driver) loadMetaForID(id string) secureStorageOptions {
	var s secureStorageOptions
	//s = d.metamap[id]
	if len(d.secopts) > 0 {
		s = d.secopts[id]
	}

	logrus.Debugf("secureoverlay2: loadMetaForID => id: %s, meta: %v", id, s)

	return s
}

// Cleanup any state created by overlay which should be cleaned when daemon
// is being shutdown. For now, we just have to unmount the bind mounted
// we had created.
func (d *Driver) Cleanup() error {
	return mount.Unmount(d.home)
}

// CreateReadWrite creates a layer that is writable for use as a container
// file system.
func (d *Driver) CreateReadWrite(id, parent string, opts *graphdriver.CreateOpts) error {
	logrus.Debugf("secureoverlay2: CreateReadWrite => id: %s, parent: %s", id, parent)
	return d.Create(id, parent, opts)
}

// Create is used to create the upper, lower, and merge directories required for overlay fs for a given id.
// The parent filesystem is used to configure these directories for the overlay.
func (d *Driver) Create(id, parent string, opts *graphdriver.CreateOpts) (retErr error) {
	logrus.Debugf("secureoverlay2: Create => id: %s, parent: %s, opts: %s", id, parent, opts)

	driver := &Driver{}
	err := errors.New("")

	if opts != nil && len(opts.StorageOpt) != 0 {
		err = d.parseStorageOpt(opts.StorageOpt, driver, id)
		if err != nil {
			return fmt.Errorf("--storage-opt parsing error: %s", err.Error())
		}
	}

	// REFACTOR
	// - (inside parseStorageOpt/d.secOpts) maintain order by added a parent field in d.secOpts-per-layer
	//    => this will ensure that the order of mounts is correct (assuming directly or indirectly (getLowerDirs) we get the list from d.secOpts
	// - get rid of parent/lower files on disk

	// - create a CreateFilesAndDirs function from
	// BEGIN
	dir := d.dir(id)

	rootUID, rootGID, err := idtools.GetRootUIDGID(d.uidMaps, d.gidMaps)
	if err != nil {
		return err
	}
	if err := idtools.MkdirAllAs(path.Dir(dir), 0700, rootUID, rootGID); err != nil {
		return err
	}
	if err := idtools.MkdirAs(dir, 0700, rootUID, rootGID); err != nil {
		return err
	}

	defer func() {
		// Clean up on failure
		if retErr != nil {
			os.RemoveAll(dir)
		}
	}()

	if opts != nil && len(opts.StorageOpt) > 0 && projectQuotaSupported {
		//driver := &Driver{}
		//if err := d.parseStorageOpt(opts.StorageOpt, driver); err != nil {
		//	return err
		//}

		if driver.options.quota.Size > 0 {
			// Set container disk quota limit
			if err := d.quotaCtl.SetQuota(dir, driver.options.quota); err != nil {
				return err
			}
		}
	}

	if err := idtools.MkdirAs(path.Join(dir, "diff"), 0755, rootUID, rootGID); err != nil {
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
	if parent == "" {
		return nil
	}

	if err := idtools.MkdirAs(path.Join(dir, "work"), 0700, rootUID, rootGID); err != nil {
		return err
	}
	if err := idtools.MkdirAs(path.Join(dir, "merged"), 0700, rootUID, rootGID); err != nil {
		return err
	}
	// ( also create, based on security opts, the secure directors which simplifies (obsoletes?) getSecureDir() function
	// END

	// for layers (top-down)
	//    continue if exists locally
	//    if top or exist remote
	//       CreateFilesAndDirs
	//       => we have to make sure that for remote files the mount-points and the link-files are local (and hence trusted), so we have
	//    else
	//       error
	/// drop below code
	// - drop getLower function
	// - change getLowerDirs to get list from d.secopts
	// END REFACTOR
	lower, err := d.getLower(parent)
	if err != nil {
		return err
	}
	if lower != "" {
		if err := ioutil.WriteFile(path.Join(dir, lowerFile), []byte(lower), 0666); err != nil {
			return err
		}
	}

	return nil
}

func (d *Driver) initSecureStorage(id string, opts secureStorageOptions) error {
	logrus.Debugf("secureoverlay2: initSecureStorage => id: %s, opts: %v", id, opts)
	// keep init layer of the container out of encryption/integrity
	if strings.HasSuffix(id, "-init") {
		return nil
	}

	if opts.IsConfidential || opts.RequiresIntegrity {
		cryptDiffDir := d.getSecureDir(id, constLocalCryptDiffDir)
		metaDataFile := path.Join(cryptDiffDir, constMetaDataFileName)
		if err := opts.save(metaDataFile); err != nil {
			return err
		}
		d.saveMetaForID(id, opts)
	}

	// if security is not required, return OK from this function
	return nil
}

// Parse overlay storage options
func (d *Driver) parseStorageOpt(storageOpt map[string]string, driver *Driver, id string) error {
	// set default values for secure storage options
	// return default values for options, in case of error in parsing the options

	// Read size to set the disk project quota per container
	logrus.Debugf("secureoverlay2: parseStorageOpt => storageOpt: %s", storageOpt)

	for key, val := range storageOpt {
		key := strings.ToLower(key)
		switch key {
		case "size":
			size, err := units.RAMInBytes(val)
			if err != nil {
				return err
			}
			driver.options.quota.Size = uint64(size)
		case "securityopts":
			if err := d.setupSecurityOpts(id, val); err == nil {
				logrus.Debugf("secureoverlay2: parseStorageOpt => %v", d.secopts)
			} else {
				logrus.Errorf("secureoverlya2: error in parsing sec opts, error: %v", err)
			}
		default:
			return fmt.Errorf("Unknown option %s", key)
		}
	}

	logrus.Debugf("secureoverlay2: parseStorageOpt => secureStorageOptions: %v", d.secopts)
	return nil
}

func (d *Driver) setupSecurityOpts(id, opts string) error {
	var o map[string]map[string]string
	//var s []secureStorageOptions

	if opts != "" {

		if err := json.Unmarshal([]byte(opts), &o); err != nil {
			return err
		}

		logrus.Debugf("secureoverlay2: setupSecurityOpts => id: %s, opts: %v", id, o)
		for k, val := range o {
			var t secureStorageOptions
			t.init()
			t.fromMap(val)
			d.secopts[k] = t
		}

		//d.secopts[id] = s
	}

	return nil
}

// REFACTOR: should be obsolete now with changes outlined in Create
func (d *Driver) getLower(parent string) (string, error) {
	logrus.Debugf("secureoverlay2: getLower => parent: %s", parent)

	parentDir := d.getDir(parent)
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
	return strings.Join(lowers, ":"), nil
}

func (d *Driver) dir(id string) string {
	return path.Join(d.home, id)
}

// return cache directory for id: will return any existing directory, with local over remote if both exist or local one if none exists
func (d *Driver) getDir(id string) string {
	// 1st priority: return local if exists
	ld := path.Join(d.home, id)
	
	if b, _ := exists(ld); b {
		return ld
	}
	
	// 2nd priority: return remote if local does not exists
	if d.options.remoteDir != "" { // check for remote only if getDir set
		rd := path.Join(d.options.remoteDir, id)
		if b, _ := exists(rd); b {
			return rd
		}
	}
	
	// fallback: return local if remote does not exists or not set
	return ld
}

// REFACTOR: return path from d.secOpts (with changes outlined in Create)
func (d *Driver) getLowerDirs(id string) ([]string, error) {
	logrus.Debugf("secureoverlay2: getLowerDirs => id: %s", id)

	dir := d.dir(id)
	
	// Ensure parent exists
	if _, err := os.Lstat(dir); err != nil {
		return nil, err
	}
	var lowersArray []string
	lowers, err := ioutil.ReadFile(path.Join(dir, lowerFile))
	if err == nil {
		for _, s := range strings.Split(string(lowers), ":") {
			lp, err := os.Readlink(path.Join(d.home, s))
			if err != nil {
				return nil, err
			}
			lowersArray = append(lowersArray, path.Clean(path.Join(d.home, linkDir, lp)))
			
			logrus.Debugf("secureoverlay2: getLowerDirs => id: %s, link-dir: %s, lp: %s", id, linkDir, lp)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return lowersArray, nil
}

// get an array filled with id(s) of all lower layers
func (d *Driver) getDiffChain(id string) ([]string, error) {
	var chain []string
	dir := d.getDir(id)
	
	// Ensure parent exists
	if _, err := os.Lstat(dir); err != nil {
		return nil, err
	}
	
	lowers, err := ioutil.ReadFile(path.Join(dir, lowerFile))
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

	logrus.Debugf("secureoverlay2: getDiffChain => id: %s, chain: %s", id, chain)
	return chain, nil
}

// get security related meta-data
func (d *Driver) getSecMetaInfo(id string) (map[string]string, error) {
	logrus.Debugf("secureoverlay2: get security opts for %s", id)
	//dir := d.getSecureDir(id, constLocalCryptDiffDir)
	//meta_file := path.Join(dir, constMetaDataFileName)
	//s, err := getSecurityMetaData(meta_file)
	//s, err := getSecurityMetaData(id)
	s := d.loadMetaForID(id)

	return s.toMap(), nil
}

// mount all lower layers for given id
func (d *Driver) mountAllLowers(id string) error {
	logrus.Debugf("secureoverlay2: mountAllLowers => id: %s", id)

	// get graph id of all lower layers
	lowers, err := d.getDiffChain(id)
	if err != nil {
		return err
	}

	logrus.Debugf("secureoverlay2: mountAllLowers => id: %s, lowers: %s", id, lowers)

	// load security options
	//opts := d.secopts[id]
	//logrus.Debugf("secureoverlay2: mountAllLowers => id: %s, opts: %v", id, opts)

	// mount all layers
	//length := len(opts)
	for _, lyr := range lowers {
		s := d.loadMetaForID(lyr)
		if err := d.mountLayersFor(lyr, s); err != nil {
			logrus.Debugf("secureoverlay2: mountAllLowers => id: %s, failed with an error: %s", id, err.Error())
			return err
		}
	}

	return nil
}

// unmount all lower layers for given id
func (d *Driver) umountAllLowers(id string) error {
	logrus.Debugf("secureoverlay2: umountAllLowers => id: %s", id)

	// get graph id of all lower layers
	lowers, err := d.getDiffChain(id)
	if err != nil {
		return err
	}

	logrus.Debugf("secureoverlay2: umountAllLowers => id: %s, lowers: %s", id, lowers)

	// load security options
	//opts := d.secopts[id]
	//logrus.Debugf("secureoverlay2: umountAllLowers => id: %s, opts: %v", id, opts)

	// unmount all layers
	for _, lyr := range lowers {
		s := d.loadMetaForID(lyr)
		if err := d.umountLayersFor(lyr, s); err != nil {
			logrus.Debugf("secureoverlay2: unmountAllLowers => id: %s, failed with an error: %s", id, err.Error())
			return err
		}
	}

	return nil
}

// mount given layer on the diff path
func (d *Driver) mountLayersFor(id string, s secureStorageOptions) error {
	logrus.Debugf("secureoverlay2: mountLayersFor => id: %s, opts: %v", id, s)

	if strings.HasSuffix(id, "-init") {
		return nil
	}

	// mount ecryptfs for the layer
	source := d.getSecureDir(id, constLocalOrRemoteCryptDiffDir)
	target := d.getDiffPath(id)

	// check for required security method
	if !(s.IsConfidential || s.RequiresIntegrity) {
		logrus.Infof("secureoverlay2: mountLayersFor => no security required for the layer")
		return nil
	}

	if !s.DeviceStatus {
		logrus.Warnf("secureoverlay2: mountLayersFor => Device file is not initialized. Skipping mounting")
		return nil
	}

	// check reference counter, if layer is already mounted or not
	if count := d.ctr.Increment(fmt.Sprintf("%s-secure", id)); count > 1 {
		logrus.Debugf("secureoverlay2: mountLayersFor => id: %s, count: %s", id, count)
		// ecryptfs is already mounted, skip mounting same layer again
		return nil
	}

	key := ""
	var err error
	if s.IsConfidential {
		key, err = getKey(s.KeyHandle, s.KeyType)
		if err != nil {
			return err
		}
	}

	cp := CryptParams{}
	if s.IsConfidential {
		cp.Cipher = s.CryptCipher
		cp.Key = key
		cp.KeySize = s.KeySize
		cp.HashType = s.CryptHashType
	}

	vp := VerityParams{}
	if s.RequiresIntegrity {
		vp.RootHash = s.RootHash
		vp.HashImage = path.Join(source, ConstHashImageName)
	}

	dp := DeviceParams{
		FsType: ConstFsTypeExt4,
		Mnt:    target,
	}

	ri := RawImage{
		ImagePath: path.Join(source, ConstImageName),
	}

	devType := ""
	if s.IsConfidential {
		devType = ConstTypeCrypt
	}
	if s.RequiresIntegrity {
		devType = ConstTypeVerity
	}
	if s.IsConfidential && s.RequiresIntegrity {
		devType = ConstTypeCryptVerity
	}

	// mount crypt device
	vDev := VirtualDevice{
		Image:        ri,
		Name:         id,
		Type:         devType,
		Deviceparams: dp,
		Cryptparams:  cp,
		Verityparams: vp,
	}

	if err := vDev.Get(); err != nil {
		logrus.Errorf("secureoverlay2: mountLayersFor => id: %s, failed to mount layer, error: %s", id, err.Error())
		return err
	}

	// successful return
	return nil
}

func (d *Driver) umountLayersFor(id string, s secureStorageOptions) error {
	logrus.Debugf("secureoverlay2: umountLayersFor => id: %s, opts: %v", id, s)

	if strings.HasSuffix(id, "-init") {
		return nil
	}

	// get mount point for the layer
	target := d.getDiffPath(id)

	// check counter for this mount point
	if count := d.ctr.Decrement(fmt.Sprintf("%s-secure", id)); count > 0 {
		// mount point is used by another container, so return without unmount
		logrus.Debugf("secureoverlay2: umountLayersFor => id: %s, count: %s, skipping unmount", id, count)
		return nil
	}

	source := d.getSecureDir(id, constLocalOrRemoteCryptDiffDir)
	
	// check for required security method
	if !(s.IsConfidential || s.RequiresIntegrity) {
		logrus.Infof("secureoverlay2: umountLayersFor => no security required for the layer")
		return nil
	}

	if !s.DeviceStatus {
		logrus.Warnf("secureoverlay2: umountLayersFor => Device file is not initiliazed. Skipping unmounting")
		return nil
	}

	dp := DeviceParams{
		FsType: ConstFsTypeExt4,
		Mnt:    target,
	}

	ri := RawImage{
		ImagePath: path.Join(source, ConstImageName),
	}

	devType := ""
	if s.IsConfidential {
		devType = ConstTypeCrypt
	}
	if s.RequiresIntegrity {
		devType = ConstTypeVerity
	}
	if s.IsConfidential && s.RequiresIntegrity {
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

	if err := vDev.Put(); err != nil {
		logrus.Errorf("secureoverlay2: umountLayersFor => id: %s, failed to unmount layer, error: %s", id, err.Error())
		return err
	}

	// successful return
	return nil
}

// Remove cleans the directories that are created for this id.
func (d *Driver) Remove(id string) error {
	logrus.Debugf("secureoverlay2: Remove => id: %s", id)
	d.locker.Lock(id)
	defer d.locker.Unlock(id)
	dir := d.dir(id)
	lid, err := ioutil.ReadFile(path.Join(dir, "link"))
	if err == nil {
		if err := os.RemoveAll(path.Join(d.home, linkDir, string(lid))); err != nil {
			logrus.Debugf("Failed to remove link: %v", err)
		}
	}

	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return err
	}

	// remote container meta data
	delete(d.secopts, id)

	return nil
}

// Get creates and mounts the required file system for the given id and returns the mount path.
func (d *Driver) Get(id string, mountLabel string) (s string, err error) {
	logrus.Debugf("secureoverlay2: Get => id: %s, mountLable: %s", id, mountLabel)
	d.locker.Lock(id)
	defer d.locker.Unlock(id)
	dir := d.dir(id)
	if _, err := os.Stat(dir); err != nil {
		return "", err
	}

	diffDir := path.Join(dir, "diff")

	//***************** security related options **********************************************
	if err1 := d.mountLayersFor(id, d.secopts[id]); err1 != nil {
		logrus.Debugf("secureoverlay2: Get => id: %s, failed to mount ecryptfs, error: %s", id, err1.Error())
		return "", err1
	}

	// mount all lower layers
	if err1 := d.mountAllLowers(id); err1 != nil {
		return "", err1
	}
	//********************************************************************************************

	lowers, err := ioutil.ReadFile(path.Join(dir, lowerFile))
	if err != nil {
		// If no lower, just return diff directory
		if os.IsNotExist(err) {
			return diffDir, nil
		}
		return "", err
	}

	mergedDir := path.Join(dir, "merged")
	if count := d.ctr.Increment(mergedDir); count > 1 {
		return mergedDir, nil
	}
	defer func() {
		if err != nil {
			if c := d.ctr.Decrement(mergedDir); c <= 0 {
				syscall.Unmount(mergedDir, 0)
			}
		}
	}()

	workDir := path.Join(dir, "work")
	splitLowers := strings.Split(string(lowers), ":")
	absLowers := make([]string, len(splitLowers))
	for i, s := range splitLowers {
		absLowers[i] = path.Join(d.home, s)
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", strings.Join(absLowers, ":"), path.Join(dir, "diff"), path.Join(dir, "work"))
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
		opts = fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", string(lowers), path.Join(id, "diff"), path.Join(id, "work"))
		mountData = label.FormatMountLabel(opts, mountLabel)
		if len(mountData) > pageSize {
			return "", fmt.Errorf("cannot mount layer, mount label too large %d", len(mountData))
		}

		mount = func(source string, target string, mType string, flags uintptr, label string) error {
			return mountFrom(d.home, source, target, mType, flags, label)
		}
		mountTarget = path.Join(id, "merged")
	}

	if err := mount("overlay", mountTarget, "overlay", 0, mountData); err != nil {
		return "", fmt.Errorf("error creating overlay mount to %s: %v", mergedDir, err)
	}

	// chown "workdir/work" to the remapped root UID/GID. Overlay fs inside a
	// user namespace requires this to move a directory from lower to upper.
	rootUID, rootGID, err := idtools.GetRootUIDGID(d.uidMaps, d.gidMaps)
	if err != nil {
		return "", err
	}

	if err := os.Chown(path.Join(workDir, "work"), rootUID, rootGID); err != nil {
		return "", err
	}

	return mergedDir, nil
}

// Put unmounts the mount path created for the give id.
func (d *Driver) Put(id string) error {
	logrus.Debugf("secureoverlay2: Put => id: %s", id)
	d.locker.Lock(id)
	defer d.locker.Unlock(id)
	dir := d.dir(id)
	_, err := ioutil.ReadFile(path.Join(dir, lowerFile))
	if err != nil {
		// If no lower, no mount happened and just return directly
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	mountpoint := path.Join(dir, "merged")
	if count := d.ctr.Decrement(mountpoint); count > 0 {
		return nil
	}
	if err := syscall.Unmount(mountpoint, 0); err != nil {
		logrus.Debugf("Failed to unmount %s overlay: %s - %v", id, mountpoint, err)
	}

	//***************** security related options **********************************************
	if err1 := d.umountLayersFor(id, d.secopts[id]); err1 != nil {
		logrus.Debugf("secureoverlay2: Put => id: %s, failed to unmount ecryptfs, error: %s", id, err1.Error())
		return err1
	}

	// unmount all lower layers
	if err1 := d.umountAllLowers(id); err1 != nil {
		return err1
	}
	//********************************************************************************************

	logrus.Debugf("secureoverlay2: Put => id: %s, exiting from Put", id)
	return nil
}

// Exists checks to see if the id is already mounted.
func (d *Driver) Exists(id string) bool {
	_, err := os.Stat(d.dir(id))
	return err == nil
}

// isParent returns if the passed in parent is the direct parent of the passed in layer
func (d *Driver) isParent(id, parent string) bool {
	logrus.Debugf("secureoverlay2: isParent => id: %s, parent: %s", id, parent)
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
func (d *Driver) ApplyDiff(id string, parent string, diff io.Reader) (size int64, err error) {
	var retVal int64 = 0
	logrus.Debugf("secureoverlay2: ApplyDiff => id: %s, parent: %s", id, parent)

	// ??? : need to figure out when this path is executed
	if !d.isParent(id, parent) {
		logrus.Debugf("secureoverlay2: ApplyDiff => id: %s, parent: %s, calling naiveDiff", id, parent)
		return d.naiveDiff.ApplyDiff(id, parent, diff)
	}

	applyDir := d.getDiffPath(id)

	logrus.Debugf("Applying tar in %s", applyDir)
	// Overlay doesn't need the parent id to apply the diff
	if err := untar(diff, applyDir, &archive.TarOptions{
		UIDMaps:        d.uidMaps,
		GIDMaps:        d.gidMaps,
		WhiteoutFormat: archive.OverlayWhiteoutFormat,
	}); err != nil {
		return retVal, err
	}

	// check for security meta-data
	s, err := d.loadMetaForID(id), nil
	// try to load from meta-data file if driver does not have it

	// additional check for meta-data files if driver does not have meta-data information
	if !(s.IsConfidential || s.RequiresIntegrity) {
		meta_data_path := fmt.Sprintf("%s", path.Join(applyDir, constMetaDataFileName))
		s, err = getSecurityMetaData(meta_data_path)
		d.saveMetaForID(id, s)
	}
	
	if err == nil {
		if s.IsConfidential || s.RequiresIntegrity {

			diffCryptPath := d.getSecureDir(id, constLocalCryptDiffDir)

			// move applyDir to encrypted dir
			if err := chrootarchive.CopyWithTar(applyDir, diffCryptPath); err != nil {
				logrus.Errorf("error in importing data from %s to %s", applyDir, diffCryptPath)
				return retVal, err
			}
			logrus.Debugf("secureoverlay2: ApplyDiff => id:%s, directory contents copied successfully", id)

			cmd := fmt.Sprintf("rm -rf %s", applyDir)
			if _, err := runCmd(cmd); err != nil {
				logrus.Debugf("secureoverlay2: ApplyDiff => id: %s, error in removing directory, error: %s", id, err.Error())
				return retVal, err
			}

			rootUID, rootGID, err := idtools.GetRootUIDGID(d.uidMaps, d.gidMaps)
			if err != nil {
				return retVal, err
			}

			if err := idtools.MkdirAs(applyDir, 0755, rootUID, rootGID); err != nil {
				logrus.Debugf("secureoverlay2: ApplyDiff => id: %s, error in creating directory", id)
				return retVal, err
			}

			sz, e := directory.Size(diffCryptPath)
			if e != nil {
				logrus.Debugf("secureoverlay2: ApplyDiff => id: %s, dir size: %d, error: %s", id, sz, e.Error())
			}
			return sz, e

		}
	}

	logrus.Debugf("secureoverlay2: ApplyDiff => exiting from, id: %s", id)
	return directory.Size(applyDir)
}

func (d *Driver) getDiffPath(id string) string {
	dir := d.dir(id)

	return path.Join(dir, "diff")
}

// DiffSize calculates the changes between the specified id
// and its parent and returns the size in bytes of the changes
// relative to its base filesystem directory.
func (d *Driver) DiffSize(id, parent string) (size int64, err error) {
	if useNaiveDiff(d.home) || !d.isParent(id, parent) {
		return d.naiveDiff.DiffSize(id, parent)
	}
	return directory.Size(d.getDiffPath(id))
}

//********************* DiffGetter Implementation *************************************

type fileGetNilCloser struct {
	storage.FileGetter
}

func (f fileGetNilCloser) Close() error {
	return nil
}

func (d *Driver) DiffGetter(id string) (graphdriver.FileGetCloser, error) {
	logrus.Debugf("secureoverlay2: DiffGetter => id: %s", id)

	diffPath := d.getDiffPath(id)

	// check for security meta-data
	//meta_data_path := path.Join(d.getSecureDir(id, constLocalCryptDiffDir), constMetaDataFileName)
	//s, err := getSecurityMetaData(meta_data_path)
	//s, err := getSecurityMetaData(id)
	s := d.loadMetaForID(id)

	//if err == nil {
	if s.IsConfidential || s.RequiresIntegrity {
		diffPath = d.getSecureDir(id, constLocalCryptDiffDir)
	}
	//}

	return fileGetNilCloser{storage.NewPathFileGetter(diffPath)}, nil
}

//*************************************************************************************

// Diff produces an archive of the changes between the specified
// layer and its parent layer which may be "".
func (d *Driver) Diff(id, parent string) (io.ReadCloser, error) {
	logrus.Debugf("secureoverlay2: Diff => id: %s, parent: %s", id, parent)

	if useNaiveDiff(d.home) || !d.isParent(id, parent) {
		logrus.Debugf("secureoverlay2: Diff => id: %s, parent: %s, calling naiveDiff", id, parent)
		return d.naiveDiff.Diff(id, parent)
	}

	//diffPath := d.getDiffPath(id)
	diffPath, err := d.handleEncryption(id)

	if err != nil {
		logrus.Debugf("secureoverlay2: Diff => id: %s, parent: %s, error: %s", id, parent, err.Error())
		return nil, err
	}

	logrus.Debugf("Tar with options on %s", diffPath)
	return archive.TarWithOptions(diffPath, &archive.TarOptions{
		Compression:    archive.Uncompressed,
		UIDMaps:        d.uidMaps,
		GIDMaps:        d.gidMaps,
		WhiteoutFormat: archive.OverlayWhiteoutFormat,
	})
}

// Changes produces a list of changes between the specified layer
// and its parent layer. If parent is "", then all changes will be ADD changes.
func (d *Driver) Changes(id, parent string) ([]archive.Change, error) {
	logrus.Debugf("secureoverlay2: Changes => id: %s, parent: %s", id, parent)

	if useNaiveDiff(d.home) || !d.isParent(id, parent) {
		logrus.Debugf("secureoverlay2: Changes => id: %s, parent: %s, calling naiveDiff", id, parent)
		return d.naiveDiff.Changes(id, parent)
	}
	// Overlay doesn't have snapshots, so we need to get changes from all parent
	// layers.
	diffPath := d.getDiffPath(id)
	layers, err := d.getLowerDirs(id)
	if err != nil {
		return nil, err
	}

	return archive.OverlayChanges(layers, diffPath)
}

// ############ Security Options ##################33

func (s secureStorageOptions) toString() string {
	return toJson(s)
}

func (s secureStorageOptions) toMap() map[string]string {
	m := make(map[string]string)
	if s.IsConfidential {
		m["IsConfidential"] = "true"
	} else {
		m["IsConfidential"] = "false"
	}
	if s.RequiresIntegrity {
		m["RequiresIntegrity"] = "true"
	} else {
		m["RequiresIntegrity"] = "false"
	}

	m["KeyHandle"] = s.KeyHandle
	m["KeySize"] = s.KeySize
	m["KeyType"] = s.KeyType
	m["CryptCipher"] = s.CryptCipher
	m["CryptHashType"] = s.CryptHashType
	m["RootHash"] = s.RootHash
	if s.DeviceStatus {
		m["DeviceStatus"] = "true"
	} else {
		m["DeviceStatus"] = "false"
	}

	return m
}

func (s *secureStorageOptions) fromMap(m map[string]string) {

	logrus.Debugf("secureoverlay2: fromMap => opts: %v", m)

	if strings.ToLower(m["IsConfidential"]) == "true" {
		s.IsConfidential = true
	} else {
		s.IsConfidential = false
	}
	if strings.ToLower(m["RequiresIntegrity"]) == "true" {
		s.RequiresIntegrity = true
	} else {
		s.RequiresIntegrity = false
	}
	if strings.ToLower(m["DeviceStatus"]) == "true" {
		s.DeviceStatus = true
	} else {
		s.DeviceStatus = false
	}

	if m["KeySize"] == "" {
		s.KeySize = ConstDefaultKeySize
	} else {
		s.KeySize = m["KeySize"]
	}
	if m["KeyType"] == "" {
		s.KeyType = constKeyTypeString
	} else {
		s.KeyType = m["KeyType"]
	}

	if m["CryptCipher"] == "" {
		s.CryptCipher = ConstDefaultCipher
	} else {
		s.CryptCipher = m["CryptCipher"]
	}
	if m["CryptHashType"] == "" {
		s.CryptHashType = ConstDefaultHashType
	} else {
		s.CryptHashType = m["CryptHashType"]
	}

	s.RootHash = m["RootHash"]
	s.KeyHandle = m["KeyHandle"]

	logrus.Debugf("secureoverlay2: fromMap => Exit opts: %v", s)
}

func (s *secureStorageOptions) load(metaDataFile string) error {
	raw, err := ioutil.ReadFile(metaDataFile)
	if err != nil {
		//logrus.Debugf("secureoverlay2: error in loading file %s => error: %s", metaDataFile, err.Error())
		return err
	}

	json.Unmarshal(raw, s)

	/*a := metamap[metaDataFile]
	s.IsConfidential = a.IsConfidential
	s.RequiresIntegrity = a.RequiresIntegrity
	s.KeyHandle = a.KeyHandle
	s.KeySize = a.KeySize
	s.KeyType = a.KeyType
	s.CryptCipher = a.CryptCipher
	s.CryptHashType = a.CryptHashType
	s.RootHash = a.RootHash
	s.DeviceStatus = a.DeviceStatus

	logrus.Debugf("secureoverlay2: load => metadata loaded for %s, meta: %s", metaDataFile, s.toString()) */

	return nil
}

func (s secureStorageOptions) save(metaDataFile string) error {
	// create meta-data file
	if err := ioutil.WriteFile(metaDataFile, []byte(s.toString()), 0644); err != nil {
		logrus.Debugf("secureoverlay2: save => failed to write meta-data, error: %s", err.Error())
		return err
	} else {
		logrus.Debugf("secureoverlay2: save => meta-data written successfully to %s, meta-data: %s", metaDataFile, s.toString())
	}

	/*metamap[metaDataFile] = s
	logrus.Debugf("secureoverlay2: save => metadata saved for %s, meta: %s", metaDataFile, metamap[metaDataFile].toString())*/

	return nil
}

func (s *secureStorageOptions) init() {
	s.IsConfidential = false
	s.RequiresIntegrity = false
	s.KeyHandle = ""
	s.KeySize = ConstDefaultKeySize
	s.KeyType = constKeyTypeString
	s.CryptCipher = ConstDefaultCipher
	s.CryptHashType = ConstDefaultHashType
	s.RootHash = ""
	s.DeviceStatus = false
}

func toJson(s secureStorageOptions) string {
	bytes, err := json.Marshal(s)
	if err != nil {
		logrus.Debugf("secureoverlay2: toJson => error: %s", err.Error())
		return ""
	}

	val := string(bytes)
	return val
}

func getSecurityMetaData(json_file string) (secureStorageOptions, error) {
	s := secureStorageOptions{}
	s.init()

	err := s.load(json_file)
	if err != nil {
		//logrus.Debugf("secureoverlay2: getSecurityMetaData => error: %s", err.Error())
		return s, err
	}

	return s, nil
}

// Interface to retrive encryption key for the layer, using layerid as key
func getKey(keyHandle, keyType string) (string, error) {

	if keyType == constKeyTypeString {
		return keyHandle, nil
	}

	if keyType == constKeyTypeKeyrings {
		return getKeyFromKeyrings(keyHandle)
	}
	
	if keyType == constKeyTypeAPI {
		return getKeyFromAPI(keyHandle)
	}

	return "", errors.New(fmt.Sprintf("invalid key type: %s", keyType))
}

// fetch key from kernel keyrings
func getKeyFromKeyrings(keyHandle string) (string, error) {
	// init session
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		return "", err
	}

	// search key for given keyID
	key, err := keyring.Search(keyHandle)
	if err != nil {
		return "", err
	}
	data, err := key.Get()
	if err != nil {
		return "", err
	}

	// return key fetched from keyrings
	return string(data), nil
}

//fetch key using REST/WEB API
func getKeyFromAPI(keyHandle string) (string, error) {
	// rest API must return JSON data with field key
	type apiResponse struct {
		Key string `json:"key"`
	}

	r, err := http.Get(keyHandle)
	if err != nil {
		return "", err
	}

	code := r.StatusCode
	if code != 200 {
		return "", fmt.Errorf("Invalid HTTP status code: %d", code)
	}

	defer r.Body.Close()

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", err
	}

	ar := apiResponse{
		Key: "",
	}

	err = json.Unmarshal([]byte(data), &ar)
	if err != nil {
		return "", err
	}

	if ar.Key == "" {
		return "", fmt.Errorf("No key found in the HTTP response")
	}

	return ar.Key, nil
}

func (d *Driver) handleEncryption(id string) (string, error) {
	var onErr string

	logrus.Debugf("secureoverlay2: handleEncryption => id: %s", id)

	// original overlay diff path
	diffPath := d.getDiffPath(id)

	// secure diff path for dm-crypt and dm-verity
	diffCryptPath := d.getSecureDir(id, constLocalCryptDiffDir)

	metaDataPath := path.Join(diffCryptPath, constMetaDataFileName)
	/*if flag, _ := exists(metaDataPath); !flag {
		// no meta data found, return original diffPath for the layer
		return fmt.Sprintf("%s", diffPath), nil
	}*/

	// load options from the meta data file
	//s, err := getSecurityMetaData(metaDataPath)
	s := d.loadMetaForID(id)

	/*if err != nil {
		logrus.Debugf("secureoverlay2: handleEncryption => id: %s, error in reading security options", id)
		return onErr, err
	}*/

	logrus.Debugf("secureoverlay2: handleEncryption => security options: %s", s.toString())

	diffMntPath := d.getSecureDir(id, constCryptMntDir)
	logrus.Infof("secureoverlay2: handleEncryption => crypt path: %s, mnt path: %s", diffCryptPath, diffMntPath)

	if s.IsConfidential || s.RequiresIntegrity {

		key := ""
		var err error
		if s.IsConfidential {
			key, err = getKey(s.KeyHandle, s.KeyType)

			if err != nil {
				return onErr, err
			}
		}

		// create base image to hold encrypted diff contents
		cp := CryptParams{}
		if s.IsConfidential {
			cp.Cipher = s.CryptCipher
			cp.Key = key
			cp.KeySize = s.KeySize
			cp.HashType = s.CryptHashType
		}

		vp := VerityParams{}
		if s.RequiresIntegrity {
			vp.RootHash = s.RootHash
			vp.HashImage = path.Join(diffCryptPath, ConstHashImageName)
		}

		dp := DeviceParams{
			FsType: ConstFsTypeExt4,
			Mnt:    diffMntPath,
		}

		ri := RawImage{
			ImagePath: path.Join(diffCryptPath, ConstImageName),
		}

		devType := ""
		if s.IsConfidential {
			devType = ConstTypeCrypt
		}
		if s.RequiresIntegrity {
			devType = ConstTypeVerity
		}
		if s.IsConfidential && s.RequiresIntegrity {
			devType = ConstTypeCryptVerity
		}

		// mount crypt device
		vDev := VirtualDevice{
			Image:        ri,
			Name:         id,
			Type:         devType,
			Deviceparams: dp,
			Cryptparams:  cp,
			Verityparams: vp,
		}

		// get the diff size in bytes
		//diff_size, err := directory.Size(diffPath)
		diff_size, err := dirSize(diffPath)
		if err != nil {
			logrus.Debugf("secureoverlay: handleEncryption => id: %s, error in computing size: %s", id, err.Error())
			return onErr, err
		}
		logrus.Debugf("secureoverlay: handleEncryption => id: %s, directory size: %d", id, diff_size)

		// initialize crypt device for the first time usage
		if err := vDev.Create(diff_size); err != nil {
			return onErr, err
		}

		// mount crypt device
		if err := vDev.ImportData(diffPath); err != nil {
			return onErr, err
		}

		// remove mnt directory
		if err := os.RemoveAll(diffMntPath); err != nil {
			logrus.Debugf("secureoverlay2: handleEncryption => id: %s, error in removing mount point: %s, error: %s", id, diffMntPath, err.Error())
		}

		// update device status in meta-data
		s.DeviceStatus = true
		s.RootHash = vDev.getRootHash()

		if err := s.save(metaDataPath); err != nil {
			logrus.Debugf("secureoverlay2: handleEncryption => id: %s, error in updating device status, error: %s", id, err.Error())
			return onErr, err
		}
		d.saveMetaForID(id, s)

	} else {
		// return original diff path, if security is not required for the layer
		return fmt.Sprintf("%s", diffPath), nil
	}

	// return encrypted directory path, instead of plain contents for the layer
	return diffCryptPath, nil

}

/*
func runCmd(cmd string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	logrus.Debugf("secureoverlay2: runCmd => cmd: %s", cmd)
	out, err := exec.Command("/bin/bash", "-c", cmd).Output()
	return string(out), err
}
*/

/*
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
*/

func (d Driver) getSecureDir(id, dir_type string) string {
	// get base directory for the layer
	diffPath := d.dir(id)

	// path to base directory for encryption/integrity
	base_dir := path.Join(diffPath, "secure")

	// create directory, if does not exists
	rootUID, rootGID, err := idtools.GetRootUIDGID(d.uidMaps, d.gidMaps)
	if err != nil {
		return ""
	}

	dir := ""
	switch dir_type {
	case constLocalCryptDiffDir:
		dir = path.Join(base_dir, "diff")
		err = idtools.MkdirAllAs(dir, 0755, rootUID, rootGID)
	case constLocalOrRemoteCryptDiffDir:
		if d.options.remoteDir != "" {
			dir = path.Join(d.options.remoteDir, id, "secure", "diff")
			if b, _ := exists(dir); !b {
				dir = path.Join(base_dir, "diff")
			}
		} else {
			dir = path.Join(base_dir, "diff")
		}
		err = idtools.MkdirAllAs(dir, 0755, rootUID, rootGID)
	case constCryptMntDir:
		dir = path.Join(base_dir, "crypt-mnt")
		err = idtools.MkdirAllAs(dir, 0755, rootUID, rootGID)
	case constSecureBaseDir:
		dir = base_dir
		err = idtools.MkdirAllAs(dir, 0755, rootUID, rootGID)
	case constIntegrityMntDir:
		dir = path.Join(base_dir, "int-mnt")
		err = idtools.MkdirAllAs(dir, 0755, rootUID, rootGID)
	default:
		logrus.Debugf("secureoverlay: getSecureDir => id: %s, invalid directory type: %s", id, dir_type)
	}

	if err != nil {
		logrus.Debugf("secureoverlay2: getSecureDir => id: %s, dir_type: %s, error: %s", id, dir_type, err.Error())
		return ""
	}

	return dir
}

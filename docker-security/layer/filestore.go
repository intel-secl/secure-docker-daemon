package layer

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/distribution"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/opencontainers/go-digest"
)

var (
	stringIDRegexp      = regexp.MustCompile(`^[a-f0-9]{64}(-init)?$`)
	supportedAlgorithms = []digest.Algorithm{
		digest.SHA256,
		// digest.SHA384, // Currently not used
		// digest.SHA512, // Currently not used
	}
)

type fileMetadataStore struct {
	root string
	remoteRoot string
}

type fileMetadataTransaction struct {
	store *fileMetadataStore
	ws    *ioutils.AtomicWriteSet
}

// NewFSMetadataStore returns an instance of a metadata store
// which is backed by files on disk using the provided root
// as the root of metadata files.
func NewFSMetadataStore(root, remoteRoot string) (MetadataStore, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	
	logrus.Debugf("layer store: NewFSMetadataStore => root: %s, remote root: %s", root, remoteRoot)
	
	return &fileMetadataStore{
		root: root,
		remoteRoot: remoteRoot,
	}, nil
}

func (fms *fileMetadataStore) getLayerDirectory(layer ChainID) string {
	dgst := digest.Digest(layer)
	
	lr := filepath.Join(fms.root, string(dgst.Algorithm()), dgst.Hex())
	
	// support remote root directory for layerDB
	if fms.remoteRoot != "" {
		// FIXME: if local exist, return it right away ...

		// return local root path if remote path does not exists for the layer
		//	remote path must exists otherwise switch back to local path, so new
		//	layer creation will always be on local and not on the remote path
		//	remote path will be over the network, so treat it as read-only location
		if rr, err := fms.getRemoteLayerDirectory(layer); err != nil {
			logrus.Debugf("layer store: getLayerDirectory => remote dir %s does not exists, switching back to local dir %s", rr, lr)
			return lr
		} else {
			return rr
		}
	}
	
	return lr
}

// support for remote layer directory
func (fms *fileMetadataStore) getRemoteLayerDirectory(layer ChainID) (string, error) {
	if fms.remoteRoot == "" {
		return "", fmt.Errorf("layer store: no remote root directory is set for layer store")
	}
	dgst := digest.Digest(layer)
	rr := filepath.Join(fms.remoteRoot, string(dgst.Algorithm()), dgst.Hex())
	if _, err := os.Stat(rr); os.IsNotExist(err) {
		return "", err
	}
	return string(rr), nil
}

func (fms *fileMetadataStore) SetRemoteRoot(root string) {
	fms.remoteRoot = root
}

func (fms *fileMetadataStore) getLayerFilename(layer ChainID, filename string) string {
	return filepath.Join(fms.getLayerDirectory(layer), filename)
}

func (fms *fileMetadataStore) getMountDirectory(mount string) string {
	return filepath.Join(fms.root, "mounts", mount)
}

func (fms *fileMetadataStore) getMountFilename(mount, filename string) string {
	return filepath.Join(fms.getMountDirectory(mount), filename)
}

func (fms *fileMetadataStore) StartTransaction() (MetadataTransaction, error) {
	tmpDir := filepath.Join(fms.root, "tmp")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return nil, err
	}
	ws, err := ioutils.NewAtomicWriteSet(tmpDir)
	if err != nil {
		return nil, err
	}

	return &fileMetadataTransaction{
		store: fms,
		ws:    ws,
	}, nil
}

func (fm *fileMetadataTransaction) SetSize(size int64) error {
	content := fmt.Sprintf("%d", size)
	return fm.ws.WriteFile("size", []byte(content), 0644)
}

func (fm *fileMetadataTransaction) SetParent(parent ChainID) error {
	return fm.ws.WriteFile("parent", []byte(digest.Digest(parent).String()), 0644)
}

func (fm *fileMetadataTransaction) SetDiffID(diff DiffID) error {
	return fm.ws.WriteFile("diff", []byte(digest.Digest(diff).String()), 0644)
}

func (fm *fileMetadataTransaction) SetCacheID(cacheID string) error {
	return fm.ws.WriteFile("cache-id", []byte(cacheID), 0644)
}

func (fm *fileMetadataTransaction) SetDescriptor(ref distribution.Descriptor) error {
	jsonRef, err := json.Marshal(ref)
	if err != nil {
		return err
	}
	return fm.ws.WriteFile("descriptor.json", jsonRef, 0644)
}

func (fm *fileMetadataTransaction) TarSplitWriter(compressInput bool) (io.WriteCloser, error) {
	f, err := fm.ws.FileWriter("tar-split.json.gz", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	var wc io.WriteCloser
	if compressInput {
		wc = gzip.NewWriter(f)
	} else {
		wc = f
	}

	return ioutils.NewWriteCloserWrapper(wc, func() error {
		wc.Close()
		return f.Close()
	}), nil
}

func (fm *fileMetadataTransaction) Commit(layer ChainID) error {
	finalDir := fm.store.getLayerDirectory(layer)
	if err := os.MkdirAll(filepath.Dir(finalDir), 0755); err != nil {
		return err
	}

	return fm.ws.Commit(finalDir)
}

func (fm *fileMetadataTransaction) Cancel() error {
	return fm.ws.Cancel()
}

func (fm *fileMetadataTransaction) String() string {
	return fm.ws.String()
}

func (fms *fileMetadataStore) GetSize(layer ChainID) (int64, error) {
	content, err := ioutil.ReadFile(fms.getLayerFilename(layer, "size"))
	if err != nil {
		return 0, err
	}

	size, err := strconv.ParseInt(string(content), 10, 64)
	if err != nil {
		return 0, err
	}

	return size, nil
}

func (fms *fileMetadataStore) GetParent(layer ChainID) (ChainID, error) {
	content, err := ioutil.ReadFile(fms.getLayerFilename(layer, "parent"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	dgst, err := digest.Parse(strings.TrimSpace(string(content)))
	if err != nil {
		return "", err
	}

	return ChainID(dgst), nil
}

func (fms *fileMetadataStore) GetDiffID(layer ChainID) (DiffID, error) {
	content, err := ioutil.ReadFile(fms.getLayerFilename(layer, "diff"))
	if err != nil {
		return "", err
	}

	dgst, err := digest.Parse(strings.TrimSpace(string(content)))
	if err != nil {
		return "", err
	}

	return DiffID(dgst), nil
}

func (fms *fileMetadataStore) GetCacheID(layer ChainID) (string, error) {
	contentBytes, err := ioutil.ReadFile(fms.getLayerFilename(layer, "cache-id"))
	if err != nil {
		return "", err
	}
	content := strings.TrimSpace(string(contentBytes))

	if !stringIDRegexp.MatchString(content) {
		return "", errors.New("invalid cache id value")
	}

	return content, nil
}

func (fms *fileMetadataStore) GetDescriptor(layer ChainID) (distribution.Descriptor, error) {
	content, err := ioutil.ReadFile(fms.getLayerFilename(layer, "descriptor.json"))
	if err != nil {
		if os.IsNotExist(err) {
			// only return empty descriptor to represent what is stored
			return distribution.Descriptor{}, nil
		}
		return distribution.Descriptor{}, err
	}

	var ref distribution.Descriptor
	err = json.Unmarshal(content, &ref)
	if err != nil {
		return distribution.Descriptor{}, err
	}
	return ref, err
}

func (fms *fileMetadataStore) TarSplitReader(layer ChainID) (io.ReadCloser, error) {
	fz, err := os.Open(fms.getLayerFilename(layer, "tar-split.json.gz"))
	if err != nil {
		return nil, err
	}
	f, err := gzip.NewReader(fz)
	if err != nil {
		return nil, err
	}

	return ioutils.NewReadCloserWrapper(f, func() error {
		f.Close()
		return fz.Close()
	}), nil
}

func (fms *fileMetadataStore) SetMountID(mount string, mountID string) error {
	if err := os.MkdirAll(fms.getMountDirectory(mount), 0755); err != nil {
		return err
	}
	return ioutil.WriteFile(fms.getMountFilename(mount, "mount-id"), []byte(mountID), 0644)
}

func (fms *fileMetadataStore) SetInitID(mount string, init string) error {
	if err := os.MkdirAll(fms.getMountDirectory(mount), 0755); err != nil {
		return err
	}
	return ioutil.WriteFile(fms.getMountFilename(mount, "init-id"), []byte(init), 0644)
}

func (fms *fileMetadataStore) SetMountParent(mount string, parent ChainID) error {
	if err := os.MkdirAll(fms.getMountDirectory(mount), 0755); err != nil {
		return err
	}
	return ioutil.WriteFile(fms.getMountFilename(mount, "parent"), []byte(digest.Digest(parent).String()), 0644)
}

func (fms *fileMetadataStore) GetMountID(mount string) (string, error) {
	contentBytes, err := ioutil.ReadFile(fms.getMountFilename(mount, "mount-id"))
	if err != nil {
		return "", err
	}
	content := strings.TrimSpace(string(contentBytes))

	if !stringIDRegexp.MatchString(content) {
		return "", errors.New("invalid mount id value")
	}

	return content, nil
}

func (fms *fileMetadataStore) GetInitID(mount string) (string, error) {
	contentBytes, err := ioutil.ReadFile(fms.getMountFilename(mount, "init-id"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	content := strings.TrimSpace(string(contentBytes))

	if !stringIDRegexp.MatchString(content) {
		return "", errors.New("invalid init id value")
	}

	return content, nil
}

func (fms *fileMetadataStore) GetMountParent(mount string) (ChainID, error) {
	content, err := ioutil.ReadFile(fms.getMountFilename(mount, "parent"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	dgst, err := digest.Parse(strings.TrimSpace(string(content)))
	if err != nil {
		return "", err
	}

	return ChainID(dgst), nil
}

func (fms *fileMetadataStore) List() ([]ChainID, []string, error) {
	var ids []ChainID
	for _, algorithm := range supportedAlgorithms {
		fileInfos, err := ioutil.ReadDir(filepath.Join(fms.root, string(algorithm)))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, nil, err
		}

		for _, fi := range fileInfos {
			if fi.IsDir() && fi.Name() != "mounts" {
				dgst := digest.NewDigestFromHex(string(algorithm), fi.Name())
				if err := dgst.Validate(); err != nil {
					logrus.Debugf("Ignoring invalid digest %s:%s", algorithm, fi.Name())
				} else {
					ids = append(ids, ChainID(dgst))
				}
			}
		}
	}

	// merge layers from remote DB to local DB
	logrus.Debugf("layer store: filestore => merge remote layerDB from %s", fms.remoteRoot)
	
	if fms.remoteRoot != "" {
		
		if rids, _, err := fms.remoteList(); err == nil {
			logrus.Debugf("layer store: filestore => rids: %v", rids)
			
			// add remote layer if it does not exists locally
			for _, i := range rids {
				if !searchIds(ids, i) {
					ids = append(ids, i)
				}
			}
		}	
	}
	
	fileInfos, err := ioutil.ReadDir(filepath.Join(fms.root, "mounts"))
	if err != nil {
		if os.IsNotExist(err) {
			return ids, []string{}, nil
		}
		return nil, nil, err
	}

	var mounts []string
	for _, fi := range fileInfos {
		if fi.IsDir() {
			mounts = append(mounts, fi.Name())
		}
	}

	// merge layers from remote DB to local DB
	if fms.remoteRoot != "" {
		
		if _, rmounts, err := fms.remoteList(); err == nil {
			logrus.Debugf("layer store: filestore => rmounts: %v", rmounts)
			
			// add remote mount if it does not exists locally
			for _, m := range rmounts {
				if !searchMounts(mounts, m) {
					mounts = append(mounts, m)
				}
			}
		}	
	}
	
	return ids, mounts, nil
}

func searchIds(arr []ChainID, item ChainID) bool {
	for _, itm := range arr {
		if itm == item {
			return true
		}
	}
	
	return false
}

func searchMounts(arr []string, item string) bool {
	for _, itm := range arr {
		if itm == item {
			return true
		}
	}
	
	return false
}

// read layerDB from remote location
func (fms *fileMetadataStore) remoteList() ([]ChainID, []string, error) { 
	var ids []ChainID
	for _, algorithm := range supportedAlgorithms {
		fileInfos, err := ioutil.ReadDir(filepath.Join(fms.remoteRoot, string(algorithm)))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, nil, err
		}

		for _, fi := range fileInfos {
			if fi.IsDir() && fi.Name() != "mounts" {
				dgst := digest.NewDigestFromHex(string(algorithm), fi.Name())
				if err := dgst.Validate(); err != nil {
					logrus.Debugf("Ignoring invalid digest %s:%s", algorithm, fi.Name())
				} else {
					ids = append(ids, ChainID(dgst))
				}
			}
		}
	}

	fileInfos, err := ioutil.ReadDir(filepath.Join(fms.remoteRoot, "mounts"))
	if err != nil {
		if os.IsNotExist(err) {
			return ids, []string{}, nil
		}
		return nil, nil, err
	}

	var mounts []string
	for _, fi := range fileInfos {
		if fi.IsDir() {
			mounts = append(mounts, fi.Name())
		}
	}

	return ids, mounts, nil
}

func (fms *fileMetadataStore) Remove(layer ChainID) error {
	return os.RemoveAll(fms.getLayerDirectory(layer))
}

func (fms *fileMetadataStore) RemoveMount(mount string) error {
	return os.RemoveAll(fms.getMountDirectory(mount))
}

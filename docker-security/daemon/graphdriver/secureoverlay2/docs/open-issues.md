Docker Security Open Issues
===========================

## Code review comments
* cryptsetup.ggo: LoDev from RawImage can be remove as no persistent object is required
* overlay.go: Do we need to use lock for meta-data update operations or map will do is it for us?
* overlay.go: add comment that XFS quota will not work after our modification
* overlay.go and layer_store.go: If remote location is enabled for docker layers, then add checks that layers must have integrity enabled
* overlay.go: Add comments for special handling of mount/unmount of "init layer" for any new read-write layer
* overlay.go: update error handling in ApplyDiff API
* overlay.go: analyze execution path for various NaiveDiff calls in Diff, ApplyDiff and Changes API calls. Whether we need to add our security changes to NaiveDiff or not? Is there any flaw that can be exploited to trigger this NaiveDiff execution path?
* overlay.go: rename handleEncryption method name to handleSecurity
* overlay.go re-factor handleEncryption code to have readable return paths from the method
* layer_store.go: rename SecurityOpts to some internal name to avoid any future conflicts with Docker SecurityOpts

## Test cases
* Run multiple containers from the same image to check that sharing of layers have no issues
*

## Others
* Merge our changes with latest docker upstream changes for Moby
* Analyze docker image building with "--rm" option. Does it make any impact on security of the layer that we support?
* Check whether docker build time caching has any impact on security
* Add unit test cases for secureoverlay2 driver
* Add stress test cases for secureoverlay2 driver

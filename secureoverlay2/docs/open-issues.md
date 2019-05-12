Docker Security Open Issues Heap
================================

(see also 'Known issues and limitations' and 'Future Work' sections of notes.md)


## Code review comments
* cryptsetup.go: LoDev from RawImage can be remove as no persistent object is required
* overlay.go: Do we need to use lock for meta-data update operations or map will do is it for us?
* overlay.go: add comment that XFS quota will not work after our modification
* overlay.go and layer_store.go: If remote location is enabled for docker layers, then add checks that layers must have integrity enabled
* layer_store.go: rename SecurityOpts to some internal name to avoid any future conflicts with Docker SecurityOpts

## Test cases
* Run multiple containers descending from the same image to check that sharing of layers have no issues
*

## Others
* history for private layers is cleanup only for non-zero layers but
  not empty layers (See comment in overlay.go::Diff around empty layer handling)
* Merge our changes with latest docker upstream changes for Moby
* Check whether docker build time caching has any impact on security
* Extend standard unit test-cases by running them with permutations of
  security options (similar to test/life-cycle-test.sh) exploiting
  that default options including keys can be set via daemon
  parameters passed as (optional 3rd parameter) to
  graphtest.GetDriver() in overlay_test.go::TestOverlaySetup() and alike.
* Add additional unit test cases for security corner cases

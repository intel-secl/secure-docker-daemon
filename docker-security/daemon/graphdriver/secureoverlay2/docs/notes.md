# Notes for Docker Security Feature

## Overview
The secureoverlay2 driver allows you to build and run docker images
containing _private encrypted layers_ and/or layers which provide
_strong runtime-integrity even when stored on untrusted storage_.
Encrypted layers will be protected by _dm-crypt_, integrity-protected
layers by _dm-verity_. Resulting images match the structure of
standard images but, by necessity as no other driver supports
encryption or the level of strong integrity, can be interpreted only
by a daemon configured with our secureoverlay2 driver.

### Key Management & Integrity
The unit of security (encryption and integrity) is the layers newly
built as specified in a Dockerfile. All new layers will share the same
security properties as defined with the build options (see below) and,
hence, also involve the same key.  Depending on the KeyType parameters
which selects the key-management service, the key will be fetched
either from the command-line, the kernel keyring or a web server and
then passed to dm-crypt to encrypt the corresponding layer as a
virtual device file.  Once the image content is built, the security
properties, the involved key-handles as well as the resulting
dm-verity integrity hashes of the layers will be securely embedded
into the (per-layer) history objects contained in the docker image
meta-data, i.e., they are frozen by the image id once an image is built.

At container run time, the daemon will read integrity-hashes and the
key-handles from the meta-data, enforce appropriate integrity by
passing the the reference hash to dm-verity and, for all encrypted
layers, requesting on-demand the corresponding keys from the
key-management service and pass them to dm-crypt.

To exploit integrity-protection, you will have to define the daemons
'--data-remote-root' option which enables a second untrusted storage
hierachy where we search for (raw) layer data (but not meta-data).
One scenario of its use is to export an NFS volume containing the
data-root directory of an (untrusted) docker daemon running
secureoverlay2 which prefetches and chaches desired images which then
can be shared with TEEs mounting onto their data-remote-root
directory. The TEE then would pull shared images as before with docker
pull but would effectively only pull the meta-data but re-use the
prefetched data layers.


### Security Guarantees & Assumptions
We assume that the node (OS, Hypervisor) on which the daemon runs is
trusted. Furthermore, we require trusted (integrity-protected) storage
on which resides the daemon SW, its configuration data and the
layer-store data with image-meta-data.  However, for
integrity-protected and encrypted (read-only) layer data we do _not_
require integrity and confidentiality^1 protection, respectively.

Note, though. that for newly-created layers, e.g., during build or the
scratchpad layer during run, will not be encrypted or
integrity-protected at build or run time as for technical reasons --
no writeable storage with integrity protection and difficulty of
sizing the necessary block devices -- the security for new layers is
applied only after the layers are built.

We do not put any trust into either integrity or confidentiality on
the communication medium, e.g., docker registry, by which images are
exchanged.

^1: no attempt is made though to hide block access pattern, so
corresponding side-channels would be available to an attacker but in
general should be non-trivial to exploit on a TEE with read-aheads and
caching.


## Usage

### Setup

Start daemon with --storage-driver secureoverlay2 (e.g., on ubuntu
with systemd you would have to modify the ExecStart option in
'/lib/systemd/system/docker.service').  Additionally, make sure that
you have enough loop-back device files, e.g., by running
  'for i in $(seq 1 255); do { dev="/dev/loop${i}"; if [ ! -e ${dev} ]; then echo "creating device $dev"; mknod $dev b 7 $i; chown root.disk $dev; chmod ug=rw,o-rwx $dev; fi } done;'


### Building secure images
New images are built by passing additional build options (see below)
which specify the security required for the new layers add in this
build.  Note no modification is required in the docker-files!

If the base image referenced in the Dockerfile has encrypted layers,
note that your key-management service also has to provide the keys for
the related key-handles, e.g., via the API, in linux keyrings or on
the commandline depending on the choosen KeyType.

If you require integrity, then you obviously want it all the way down
to the base-layer.  Securing a base image requires slightly different
steps as outline in separate section below.

Running 'docker history' on built image will tell you which security
options apply for each layer.

##### Docker build options
_NOTE: this is the version as implemented in the code right
now. However, it will be soon replaced by the version of subsequent
sub section_

  * --storage-opt IsConfidential=<value>
   *value* can be _true_ or _false_. If _true_, image layers will be protected using encryption(dm-crypt).
  * --storage-opt KeyHandle=<value>
   *value* is a key identifier used to fetch the key according to KeyType, see below.
  * --storage-opt KeyType=<value>
   *value* can be on of following:
      * _key-type-keyrings_: the key will be fetched from the the
        linux kernel from the docker daemon' user-session keyring with
        key-id <value> from the KeyHandle option
	  * _key-type-api_: the key will be retrieved on-demand by the
         daemon by issuing an HTTP GET request, treating the keyhandle
         as a URL.
	  * _key-type-string_:  the keyHandle passed is treated directly
        as key. Not an advisable type for production -- note the key
        is in clear in the image's meta-data!! -- but convenient for
        debugging/testing.

  * --storage-opt RequiresIntegrity=<value>
   *value* can be _true_ or _false_. If _true_, image layers will be
   protected using runtime integrity(dm-verity).
  * Notes: isConfidential and requiresIntegrity can be used
    indepently. Any one of them or both can be _true_. If both are
    _true_, then layer will have protecction using encryption as well
    as integrity.

##### Docker build options (as-planned)
  * --storage-opt IsConfidential=<value>
   *value* can be _true_ or _false_. If _true_, image layers will be protected using encryption(dm-crypt).
  * --storage-opt KeyHandle=<value>
   *value* is a key identifier used to fetch the key according to KeyType, see below.
  * --storage-opt KeyType=<value>
   *value* can be on of following:
      * _key-type-keyrings_: the key will be fetched from the the
        linux kernel from the docker daemon' user-session keyring with
        key-id <value> from the KeyHandle option
	  * _key-type-api_: the key will be retrieved on-demand by the
         daemon by issuing an HTTP GET request to an URL computed by
         appending the Keyhandle value to the URL as specified by
         option KeyURL.
         * --storage-opt KeyURL=<value>: the server URL used for
           KeyType _key-type-api_.
	  * _key-type-string_:  the key is passed directly on the
        command-line with option Key
         * --storage-opt Key=<key-handle>:<key-value>: the key and
           associated key-handle for keytype _key-type-string_

  * --storage-opt RequiresIntegrity=<value>
   *value* can be _true_ or _false_. If _true_, image layers will be
   protected using runtime integrity(dm-verity).
  * Notes: isConfidential and requiresIntegrity can be used
    indepently. Any one of them or both can be _true_. If both are
    _true_, then layer will have protecction using encryption as well
    as integrity.


### How to build secure base image?

The command `make_secure.sh` is a wrapper script to convert regular
image into secure image. The script can be found at
`daemon/graphdriver/secureoverlay2/docs/make_secure.sh`and is invoked
as `make_secure.sh [-s <sec-ops> <existing-image> <new-image>` with `existing-image`
the docker image name in standard format <repo>:[tag] to be converted
and the `new-image` the new image name in standard format
<repo>:[tag]. By default it will add integrity but not
confidentiality. To change the defaults, use option -s to pass the
desired security options passed to the build.
Note that right now the conversion involves an export and re-import
which loses meta-data such as cmd, entrypoint, env, workingdir and
labels! As you would usually convert a base level, these values would
be often overriden later but if not for now you might have to add an
additional Dockerfile with these values on top of the base layer.


### Distribution of secure docker images

Use docker pull/push work as before for image distribution: While the
docker daemons building and running secure images need to be modifed
with secureoverlay2 driver, it will work with "vanilla" docker
registry.  If encryption is involved, we assume there is an
out-of-band mechanism to pass the key-handles and corresponding keys.
Of course there must also be an authentic way to authentically
transmit an identifier to the image if it passed via an untrusted
registry. This could be simply the image-id or could make use of
docker trust/docker notary.


### Running secure docker images

The images will contain the security properties and key handles,
if encrypted, embeded in its meta-data (visible by running 'docker
history').  Hence you will run the image as you would any image. The
only thing you have to make sure that the key-management service
according to KeyType is properly set up and keys for _all_ layers and
related KeyHandles are provided by the service.


## External dependencies
#### Shell commands or external programs

* cryptsetup: used for encrypting the disk image for docker layer. Assumed to be in the standard path.
* veritysetup: used to compute/verify disk image integrity for docker layer. Assumed to be in standard path.

#### GO Packages

* [go-losetup](https://github.com/freddierice/go-losetup): used to loop mount the disk images for docker layer
* [keyctl](https://github.com/jsipprell/keyctl): Linux kernel keyrings library for GO. Key management for encrypted image is offloaded to kernel keyrings

## Known issues
  * the caching logic does not yet realize when you change security
    options when building for dockerfiles which haven't changed.  If
    you use same dockerfile with different security options you will
    have right now to call docker build with option --no-cache
  * option -rm/--remove-intermediate-layer is not yet supported and
    will result in insecure images
  * losetup: secure images for docker layers are mounted using _Linux losetup_. With latest Linux kernel only 256 loop devices can be created. This adds limitation to the docker daemon that it can not mount more than 256 layers at a time. For production, this is very small number. **This can be eliminated using iscsi like shared block devices to store image layers, but that is something to be evaluated and implemented. There is no hard dependency of the current security solution on loop devices, it can be any block device local or remote**
  * loop device leak: loop devices are not cleaned up for secure layers after container is terminated. This needs to be analyzed and fixed.
  * Export of the secure image: docker export always works on the top layer. If secure image is mounted on the given system and docker export is executed on such image, it will export plain contents of all they layers for the image. Even though security is enabled for image layers, they are not protected from **Docker Export**.


## Build & source
  * for source code access, see following [wiki page](https://wiki.ith.intel.com/display/reliancepoint/RP+Docker+Extensions)

  * The build process is as usual for docker, e.g., make binary to
    build the binaries into bundle latest. For more information see Docker's
	[Work with a development container](https://docs.docker.com/opensource/project/set-up-dev-env/)

## Design notes
  * for some background on graph drivers, look at following links:
	- https://docs.docker.com/engine/userguide/storagedriver/imagesandcontainers/
    - https://docs.docker.com/engine/userguide/storagedriver/selectadriver/
	- https://integratedcode.us/2016/08/30/storage-drivers-in-docker-a-deep-dive/
    Also useful could be information on the image exchange formats and alike
	- https://github.com/moby/moby/blob/master/image/spec/v1.2.md
    - https://www.opencontainers.org/

  * We've tried to locate all of our logic as much as possible behind the
    standard graph driver api. That said, we also did do a few changes
    to the main daemon code to (a) allow passing of security options
    (disguised as storage options) from the command-line to the graph
    drivers -- something which could be useful also for other graph
    drivers – and -- more specifically for us -- also some changes to
    (b) embed the security choices into the history objects.

    (b) is the more invasive change and is primarily necessary for the
    integrity case and for a way to inspect an image to find it’s
    security options.  If only encryption is required, then (b) could
    probably be dropped. However, for (a) I’m not sure on a good
    alternative to the (fairly minimal changes to) pass the security
    options short of either hard-coding and freezing them or require
    that there are no concurrently started or built containers and
    then pass them a bit kludgily through some global service.  (At
    build time, the graph driver by default doesn’t really have much
    information which would allow it to correlate it with anything
    visible to the outside caller). 

    To see changes in non-driver code,  following git command should
    give you the changes _outside_ of the graph driver itself
    "git diff --ignore-all-space --word-diff=color master...HEAD ':!daemon/graphdriver/secureoverlay2'."
    Unfortunately there is not a good way to split (a) from (b) (and
    from any additional logging code we added as the daemon code is
    not really well equipped with logging code out of the box …)

  * Our graphdriver is a clone of the overlay2 graph driver, so a
    'diff -r daemon/graphdriver/overlay2 daemon/graphdriver/secureoverlay2'
	can also be helpful to understand the code.

    We started with overlay as initially we were thinking of using
    ecryptfs which ultimately did not work due to filesystem stacking
    problems which forced us to switch to dm-crypt.  Given that one
    might want to reconsider whether maybe a derivation from the
    devmapper driver might be a better alternative

  * representation-wise, an encrypted layer will consist of a single
    file which contains dm-crypt encrypted logical block device on
    which there is a filesystem which contains the delta-files for
    this layer. An inegrity-protected layer consists of two files, on
    containing the dm-verity meta-data (hash-tree) and the other one
    containing the delta-files. Depending on whether the layer is also
    encrypted it will be a dm-crypted device with a filesystem or
    directly a logical block device with the filesystem on it. The
    secured files are maintained in a sub-directory 'secure' in the
    graph-drivers cache directory of that layer.

	When a new layer is created, all changes (in clear/unprotected)
    will be stored in the "diff" as done by other graph drivers. Once
    docker commits the layer, more specifically in the Diff()
    graphdriver function, we generate above device files from the
    content in the "diff" directory. As we know the complete delta
    state at this point in time, we can correspondingly compute
    required device size without wasting space (or running out of
    space if an apriori estimate would have been too optimistic).

    At runtime when the layers should be mounted (Get() function of
    graph driver) the files are exposed as loopback devices (using
    losetup) and subsequently device-mapped via cryptsetup and/or
    veritysetup for dm-crypt and dm-verity, respectively. The
    filesystem on these devices is then mounted onto the "standard"
    diff directory of a graph driver and then finally the overlay
    filesystem is mounted in the usual way.

	Besides mentioned Diff() and Get() functions, other critical
    graphdriver functions are ApplyDiff() -- which is called when a
    new layer is registered, either after a commit/Diff() or via a
    load or pull, in either case by getting the exportable files as a
    tar stream --, Put() -- the reverse of Get(), i.e., umount --,
    Create()/CreateReadWrite -- for initialization new
    read-only/read-write layers -- and Remove() -- which purges a
    layer.

  * We use dm-crypt and dm-verity as overlay filesystem stack badly
    with encrypted filesystems and no filesystem provides a desired
    level of integrity (most of them only weak integrity of files and
    no integrity of meta-data such as directories). The
    confidentiality provided by dm-crypt is also stronger as it
    obfuscates also meta-data much better (although of course
    block-level patterns still will be leaked as mentioned
    above). Furthermore, various performance studies seem to indicate
    that block level security should not harm
    performance. Additionally, block level security is conceptually
    much simpler and hence also reduces TCB.

  * We currently apply security only _after_ the layers are built.
    The reason for this is two-fold: there does not exist a writeable
    storage with desired integrity protection (but see below for
    possible extensions) and with block-level security there is the
    issue that we cannot estimate as a build starts how much storage
    is required, something we know only at commit time. However, as
    anyway the overall storage where daemon code and image meta-data
    resides has to be trusted, the corresponding security is more
    easily applied at the system level.

## Future Work
### Improvements
  * Decouple keyType from image meta data so it can be different at
    build and run time. (Will require (a) removing keyType from
    history data, (b) separate key-id and (base) server-URL for
    key-type _key-type-api_ (via an additional parameter) and (c)
    passing keyType to docker run.
  * Adding a new security option at build-time which allows tieing
    some free text description to the image to, e.g., tie some
    policy-id to the image.
  * make_secure which retains the meta data such as CMD, ENTRYPOINT,
    ENV, ... 
  * performance analysis and potential optimizations such as mount
    caching.
  * we currently build against the local Go graph driver API and hence
    the daemon overall has to be rebuilt overall to enable this
    driver. Once the (web-based/remote) plugin API leaves the
    experimental state and assuming the APIs don't change much it
    should be an easy effort to convert the driver to plugin API, if
    not even somebody have written general scaffolding code which
    would transform any graph driver implementing the local api into
    one which implements the remote one.  For that to be truly
    meaningful the changes in the main daemon would have to be
    upstreamed. If only encryption but not integrity (or security
    option introspection) is necessary, this could be limited to
    passing security options (masked as storage options) to the driver
    at build time, i.e., part (a) of the discussion up in the design
    section. At least this change should hopefully also be
    uncontroversial as generally useful (and from a general
    code consistency perspective anyway the right option).


### Extensions
  * **Security for Docker Volumes:** Investigate encryption and
    integrity options for Docker volumes. Docker volumes are writable,
    so supporting (strong) integrity with DM-verity will not be
    possible.  One of the possible solution to that is use snapshots
    for volumes and keep deltas on trusted storage and recompute
    "exportable" overall integrity once the container has successfully
    finished and hence has committed to data. If you can forgo
    detectable integrity violations and roll-back integrity, e.g., you
    are not concerned in fault-injection attacks or alike, a
    low-hanging fruit would be to just encrypt the volume with
    dm-crypt.
  * **strong integrity protected writable block storage** a
    modification of dm-verity to allow also for writing would enable
    that all files could be on untrusted storage. The challenge would
    be to support this on thin-provisioning given the difficulty of
    apriori sizing space requirements. We have a design with some
    tricks in hash-function design to make this possible but no steps
    towards an implementation has been done yet and would be
    non-trivial given the kernel work and the performance implications
    of caching and alike. 



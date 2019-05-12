#!/bin/bash

TEMPDIR=`mktemp -d`
DFILE=Dockerfile

SECURITY_OPTIONS="--storage-opt RequiresConfidentiality=false --storage-opt RequiresIntegrity=true"


# argument parsing and help messages
usage="$(basename "$0") [-h|--help] [-s <ec-ops] <image> <new-image> -- build secure base image from an existing docker images

where:
    -h  show this help text
    <image>  existing image (name must be in standard format REPO:TAG)
    <new-image>  name of the secure image to be created (name must be in standard format REPO:TAG)
    -s <sec-ops> security options (by default ${SECURITY_OPTIONS}
    Note that right now the conversion involves an export and re-import
    which loses meta-data such as cmd, entrypoint, env, workingdir and
    labels! As you would usually convert a base level, these values would
    be often overriden later but if not for now you might have to add an
    additional Dockerfile with these values on top of the base layer.

    Note: the existing image will have to exported into a temp-directory. So make sure that either
    the directory defined by the TMPDIR environment variable (or if undefined, /tmp) has sufficient space.
"

if [ "$1" == "-h" ] ; then
	echo "${usage}"
	exit 0
fi

if [ "$1" == "--help" ] ; then
	echo "${usage}"
	exit 0
fi

if [ "$1" == "-s" ] ; then
    shift
    if [ "$#" -le 0 ]; then
	echo "missing value for option -s"
	exit 1
    fi
    SECURITY_OPTIONS="${1}"
    shift
fi

if [ "$#" -ne 2 ]; then
    echo "Illegal number of parameters"
    exit 1
fi

IMAGE=$1
NEWIMAGE=$2

echo "creating secure base image ..."

echo "using temp directory: ${TEMPDIR}"
cd ${TEMPDIR}
echo "exporting plain container for an image ${IMAGE} "
imageid=`docker run -d -t ${IMAGE} echo`
echo "container id: ${imageid}"
echo "packaging the container ${imageid}"
docker export ${imageid} > exported.tar || exit 1
# FIXME: retain meta-data such as Env, Cmd, Entrypoint, WorkingDir, Volumes, Labels from source, maybe extracted from Config sub-element from docker inspect?
echo "building secure image ${NEWIMAGE} ..."
echo "FROM scratch" > ${DFILE}
echo "ADD exported.tar /" >> ${DFILE}
docker build ${SECURITY_OPTIONS} -t ${NEWIMAGE} . || exit 1
echo "SUCCESSFUL"
exit 0

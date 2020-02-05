#!/bin/bash

GRAPHDRIVER=`pwd`/graphdriver/
SECURE_OVERLAY_DIR=`pwd`/secureoverlay2/
SECURE_OVERLAY_INTEGRATION=`pwd`/integration/
DOCKER_BUILD=`pwd`/out/
DEPS_DIR=`pwd`/vendor/
DOCKER_CE=`pwd`/docker-ce
BUILD_DIR=`pwd`
DOCKER_CE_ENGINE_SECUREOVERLAY_INTTESTSDIR=$DOCKER_CE_ENGINE/integration/secureoverlay/
VERSION=19.03.0

git clone https://github.com/docker/docker-ce.git
cd $DOCKER_CE
git checkout v19.03.5

if [ $? -ne 0 ];
then
  echo "Error while pulling docker engine, exiting .."
  exit 1
fi

echo "Applying diff for secureoverlay2 driver"
git apply $BUILD_DIR/support-for-secure-overlay.diff

# In-place patches for CLI

# Patches for Engine
DOCKER_CE_ENGINE=$DOCKER_CE/components/engine
DOCKER_CE_CLI=$DOCKER_CE/components/cli

if [[ ! -z "${http_proxy}" && ! -z "${https_proxy}" ]]; then
  echo "Applying http_proxy and https_proxy to client and engine Dockerfiles"
  sed -i "/golang/a ENV http_proxy ${http_proxy}\nENV https_proxy ${http_proxy}\n" $DOCKER_CE_ENGINE/Dockerfile
  sed -i "/golang/a ENV http_proxy ${https_proxy}\nENV https_proxy ${https_proxy}\n" $DOCKER_CE_CLI/dockerfiles/Dockerfile.binary-native
fi

sed -i '/FROM dev AS final/a RUN apt-get -y update && DEBIAN_FRONTEND=noninteractive apt-get install -y cryptsetup\n' $DOCKER_CE_ENGINE/Dockerfile
sed -i 's/docker run --rm -i/docker run --rm -t/g' $DOCKER_CE_ENGINE/Makefile
echo ${VERSION} >  $DOCKER_CE_CLI/VERSION
cp -f $GRAPHDRIVER/register_secureoverlay2.go $DOCKER_CE_ENGINE/daemon/graphdriver/register/register_secureoverlay2.go
cp -rf $SECURE_OVERLAY_DIR $DOCKER_CE_ENGINE/daemon/graphdriver/
cp -rf $DEPS_DIR/rp.intel.com $DOCKER_CE_ENGINE/vendor/
mkdir -p $DOCKER_CE_ENGINE_SECUREOVERLAY_INTTESTSDIR && cp -f $SECURE_OVERLAY_INTEGRATION/* $DOCKER_CE_ENGINE_SECUREOVERLAY_INTTESTSDIR

echo "Building docker client"

cd $BUILD_DIR

# Build CLI
make -C $DOCKER_CE_CLI -f docker.Makefile binary
sudo chown -R `whoami`:`whoami` $DOCKER_CE_CLI/build
if [ $? -ne 0 ];
then
  echo "Error while building docker cli, exiting"
  exit 1
fi

# Build Daemon
VERSION=${VERSION} make -C $DOCKER_CE_ENGINE binary
sudo chown -R `whoami`:`whoami` $DOCKER_CE_ENGINE/bundles/binary-daemon

if [ $? -ne 0 ];
then
  echo "Error while building docker daemon, exiting"
  exit 1
fi

echo "Successfully built docker binaries"

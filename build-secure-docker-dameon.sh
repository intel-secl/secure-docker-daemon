#!/bin/bash

DOCKER_CLI=`pwd`/docker-cli/
GRAPHDRIVER=`pwd`/graphdriver/
SECURE_OVERLAY_DIR=`pwd`/secureoverlay2/
SECURE_OVERLAY_INTEGRATION=`pwd`/integration/
DOCKER_BUILD=`pwd`/out/
DEPS_DIR=`pwd`/vendor/
DOCKER_CE=`pwd`/docker-ce/
DOCKER_ENGINE=`pwd`/docker-engine/
BUILD_DIR=`pwd`
DOCKER_CE_ENGINE=$DOCKER_CE/components/engine/
DOCKER_CE_CLI=$DOCKER_CE/components/cli/
DOCKER_CE_ENGINE_SECUREOVERLAY_INTTESTSDIR=$DOCKER_CE_ENGINE/integration/secureoverlay/
VERSION=19.03.0

git clone https://github.com/docker/docker-ce.git
cd $DOCKER_CE
git checkout 19.03
git pull

if [ $? -ne 0 ];
then
  echo "Error while pulling docker engine, exiting .."
  exit 1
fi


echo "Applying diff for secureoverlay2 driver"
git apply $BUILD_DIR/support-for-secure-overlay.diff

cd $BUILD_DIR
# In-place patches for CLI
sed -i 's/golang:1.12.7/golang:1.12.5/g' $DOCKER_CE_ENGINE/Dockerfile
sed -i '/golang/a ENV http_proxy http://proxy-us.intel.com:911\nENV https_proxy http://proxy-us.intel.com:911\n' $DOCKER_CE_ENGINE/Dockerfile
sed -i '/golang/a ENV HTTP_PROXY http://proxy-us.intel.com:911\nENV HTTPS_PROXY http://proxy-us.intel.com:911\n' $DOCKER_CE_ENGINE/Dockerfile
sed -i '/golang/a ENV NO_PROXY 127.0.0.1,localhost\nENV no_proxy 127.0.0.1,localhost\n' $DOCKER_CE_ENGINE/Dockerfile
sed -i '/FROM dev AS final/a RUN apt-get -y update && DEBIAN_FRONTEND=noninteractive apt-get install -y cryptsetup\n' $DOCKER_CE_ENGINE/Dockerfile
sed -i '/golang/a ENV http_proxy http://proxy-us.intel.com:911\nENV https_proxy http://proxy-us.intel.com:911\nENV no_proxy locahost,127.0.0.1,reg-name.io\nENV NO_PROXY locahost,127.0.0.1,reg-name.io' $DOCKER_CE_CLI/dockerfiles/Dockerfile.binary-native
sed -i 's/docker run --rm -i/docker run --rm -t/g' $DOCKER_CE_ENGINE/Makefile
echo ${VERSION} >  $DOCKER_CE_CLI/VERSION 

# Patches for Engine
cp -f $GRAPHDRIVER/register_secureoverlay2.go $DOCKER_CE_ENGINE/daemon/graphdriver/register/register_secureoverlay2.go
cp -rf $SECURE_OVERLAY_DIR $DOCKER_CE_ENGINE/daemon/graphdriver/
cp -rf $DEPS_DIR/rp.intel.com $DOCKER_CE_ENGINE/vendor/
mkdir -p $DOCKER_CE_ENGINE_SECUREOVERLAY_INTTESTSDIR && cp -f $SECURE_OVERLAY_INTEGRATION/* $DOCKER_CE_ENGINE_SECUREOVERLAY_INTTESTSDIR


# Build CLI
#sudo chown -R `whoami`:`whoami` $DOCKER_CE_CLI/build
make -C $DOCKER_CE_CLI -f docker.Makefile binary
if [ $? -ne 0 ];
then
  echo "Error while building docker CLI, exiting"
  exit 1
fi

#sudo chown -R `whoami`:`whoami` $DOCKER_CE_ENGINE/bundles/binary-daemon
VERSION=${VERSION} make -C $DOCKER_CE_ENGINE binary

if [ $? -ne 0 ];
then
  echo "Error while building docker Engine, exiting"
  exit 1
fi

echo "Successfully built docker binaries"

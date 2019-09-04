#!/bin/bash

DOCKER_CLI=`pwd`/docker-cli/
GRAPHDRIVER=`pwd`/graphdriver
SECURE_OVERLAY_DIR=`pwd`/secureoverlay2
SECURE_OVERLAY_INTEGRATION=`pwd`/integration
DOCKER_BUILD=`pwd`/out
DEPS_DIR=`pwd`/vendor
DOCKER_CE=`pwd`/docker-ce
DOCKER_ENGINE=`pwd`/docker-engine
BUILD_DIR=`pwd`

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

DOCKER_CE_ENGINE=$DOCKER_CE/components/engine
DOCKER_CE_CLI=$DOCKER_CE/components/cli

sed -i 's/golang:1.12.7/golang:1.12.5/g' $DOCKER_CE_ENGINE/Dockerfile
sed -i '/golang/a ENV http_proxy http://proxy-us.intel.com:911\nENV https_proxy http://proxy-us.intel.com:911\n' $DOCKER_CE_ENGINE/Dockerfile
sed -i '/golang/a ENV HTTP_PROXY http://proxy-us.intel.com:911\nENV HTTPS_PROXY http://proxy-us.intel.com:911\n' $DOCKER_CE_ENGINE/Dockerfile
sed -i '/golang/a ENV NO_PROXY 127.0.0.1,localhost\nENV no_proxy 127.0.0.1,localhost\n' $DOCKER_CE_ENGINE/Dockerfile
sed -i '/golang/a ENV http_proxy http://proxy-us.intel.com:911\nENV https_proxy http://proxy-us.intel.com:911\n' $DOCKER_CE_CLI/dockerfiles/Dockerfile.binary-native
sed -i '$a RUN apt-get -y update && apt-get install -y cryptsetup\n'
echo "Building docker client"

cd $BUILD_DIR

make --directory=$DOCKER_CE_CLI -f docker.Makefile binary
sudo chown -R `whoami`:`whoami` $DOCKER_CE_CLI/build
if [ $? -ne 0 ];
then
  echo "Error while building docker cli, exiting"
  exit 1
fi

cp -f $GRAPHDRIVER/register_secureoverlay2.go $DOCKER_CE_ENGINE/daemon/graphdriver/register/register_secureoverlay2.go
cp -rf $SECURE_OVERLAY_DIR $DOCKER_CE_ENGINE/daemon/graphdriver/
cp -rf $DEPS_DIR/rp.intel.com $DOCKER_CE_ENGINE/vendor/
cp -rf $SECURE_OVERLAY_INTEGRATION $DOCKER_CE_ENGINE/integration/
echo "Building secure docker daemon.."
make --directory=$DOCKER_CE_ENGINE
sudo chown -R `whoami`:`whoami` $DOCKER_CE_ENGINE/bundles/binary-daemon

if [ $? -ne 0 ];
then
  echo "Error while building docker daemon, exiting"
  exit 1
fi

# Change ownership on binaries
#chown -R `whoami`:`whoami` $DOCKER_CE_CLI/build
#chown -R `whoami`:`whoami` $DOCKER_CE_ENGINE/bundles/binary-daemon

echo "Successfully built docker binaries"

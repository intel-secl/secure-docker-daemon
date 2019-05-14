#!/bin/bash

DOCKER_CLI=`pwd`/docker-cli/
GRAPHDRIVER=`pwd`/graphdriver
SECURE_OVERLAY_DIR=`pwd`/secureoverlay2
DOCKER_BUILD=`pwd`/out
DEPS_DIR=`pwd`/vendor
DOCKER_CE=`pwd`/docker-ce
BUILD_DIR=`pwd`

git clone https://github.com/docker/docker-ce.git
cd docker-ce
git checkout 17.06
git pull
cd $BUILD_DIR

if [ $? -ne 0 ];
then
  echo "Error while pulling docker engine, exiting .."
  exit 1
fi

echo "Building docker client"
DOCKER_CE_CLI=docker-ce/components/cli
DOCKER_CE_ENGINE=docker-ce/components/engine

cp -f $DOCKER_CLI/build.go $DOCKER_CE_CLI/cli/command/image/ 
cp -f $DOCKER_CLI/client.go $DOCKER_CE_CLI/vendor/github.com/docker/docker/api/types/
cp -f $DOCKER_CLI/Dockerfile.dev $DOCKER_CE_CLI/dockerfiles/Dockerfile.dev

make --directory=$DOCKER_CE_CLI -f docker.Makefile binary

if [ $? -ne 0 ];
then
  echo "Error while building docker cli, exiting"
  exit 1
fi

cp -f $GRAPHDRIVER/register_overlay.go $DOCKER_CE_ENGINE/daemon/graphdriver/register/register_overlay.go
cp -f $GRAPHDRIVER/driver_linux.go $DOCKER_CE_ENGINE/daemon/graphdriver/driver_linux.go
cp -f docker-engine/Dockerfile $DOCKER_CE_ENGINE/
cp -f docker-engine/Makefile $DOCKER_CE_ENGINE/
cp -rf $SECURE_OVERLAY_DIR $DOCKER_CE_ENGINE/daemon/graphdriver/
cp -rf $DEPS_DIR/rp.intel.com $DOCKER_CE_ENGINE/vendor/

echo "Building docker daemon.."
make --directory=$DOCKER_CE_ENGINE

if [ $? -ne 0 ];
then
  echo "Error while building docker daemon, exiting"
  exit 1
fi

echo "Successfully built docker binaries"

#!/bin/bash

#set -x

echo "Building and installing docker binaries ........."
hack/make.sh binary || exit 1
cp bundles/latest/binary-client/docker* /usr/bin/ || exit 1 
cp bundles/latest/binary-daemon/docker* /usr/bin/ || exit 1
echo "************* COMPILATION IS COMPLETED **************"

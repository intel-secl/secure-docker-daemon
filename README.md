##### Intel<sup>®</sup> Security Libraries for Data Center  - Secure Docker Daemon
Secure docker daemon is built by applying the patch which includes the secureoverlay2 graphdriver on docker-ce with 19.03 version.
This is currently supported for 19.03 version.
Provides additional ability encrypt and decrypt containers using ISecL Key Management Service.
The secure docker daemon is bundled along with ISecl components workload-agent and worload policy manager.

## System Requirements
- RHEL 7.5/7.6
- Epel 7 Repo
- Proxy settings if applicable

## Software requirements
- git
- `go` version >= `go1.12.12` & <= `go1.12.17`

# Step By Step Build Instructions

## Install required shell commands

### Install tools from `yum`
```shell
sudo yum install -y git wget makeself
```

### Install `go` version >= `go1.12.12` & <= `go1.12.17`
The `Secure docker daemon` requires Go version 1.12.12 that has support for `go modules`. The build was validated with the latest version 1.12.17 of `go`. It is recommended that you use 1.12.17 version of `go`. More recent versions may introduce compatibility issues. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.12.17.linux-amd64.tar.gz
tar -xzf go1.12.17.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build Secure Docker Daemon

- Git clone the Secure Docker Daemon

```shell
cd secure-docker-daemon
make
```

*Intel® Security Libraries for Data Center v1.6 Release Update:
Due to a recent change in an externally supported repository, namely Docker github; customers may see issues in compiling the latest released version of Intel® SecL-DC v1.6. Intel is working on a resolution and we plan to provide a minor release to address this issue shortly. Regular update to this communication will be shared to customers accordingly.

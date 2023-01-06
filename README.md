DISCONTINUATION OF PROJECT

This project will no longer be maintained by Intel.

Intel has ceased development and contributions including, but not limited to, maintenance, bug fixes, new releases, or updates, to this project.  

Intel no longer accepts patches to this project.

If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the open source software community, please create your own fork of this project.  
##### Intel<sup>®</sup> Security Libraries for Data Center  - Secure Docker Daemon
Secure docker daemon is built by applying the patch which includes the secureoverlay2 graphdriver on docker-ce with 19.03.13 version.
This is currently supported for 19.03 version.
Provides additional ability encrypt and decrypt containers using ISecL Key Management Service.
The secure docker daemon is bundled along with ISecl components workload-agent and worload policy manager.

## System Requirements
- RHEL 8.2
- Epel 8 Repo
## Software requirements
- git
- `go` version >= `go1.13` & <= `go1.14.4`

# Step By Step Build Instructions

## Install required shell commands

### Install tools from `yum`
```shell
sudo yum install -y git wget makeself
```

### Install `go` version >= `go1.13` & <= `go1.14.4`
The `Secure docker daemon` requires Go version 1.13 that has support for `go modules`. It is recommended that you use 1.14.4 version of `go`. More recent versions may introduce compatibility issues. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz
tar -xzf go1.14.4.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build Secure Docker Daemon

- Git clone the Secure Docker Daemon

```shell
cd secure-docker-daemon
make all
```


##### Intel<sup>®</sup> Security Libraries for Data Center  - Secure Docker Daemon
Secure docker daemon is built by applying the patch which includes the secureoverlay2 graphdriver on docker-ce with 19.03 version.
This is currently supported for 19.03 version
Provides additional ability encrypt and decrypt containers using ISecL Key Management Service.
The secure docker daemon is bundled along with ISecl components workload-agent and worload policy manager.

## System Requirements
- RHEL 7.5/7.6
- Epel 7 Repo
- Proxy settings if applicable

## Software requirements
- git
- Go 11.4 or newer

# Step By Step Build Instructions

## Install required shell commands

### Install tools from `yum`
```shell
sudo yum install -y git wget makeself
```

### Install `go 1.11.4` or newer
The `Secure docker daemon` requires Go version 11.4. The build was validated with version 11.4 version of `go`. It is recommended that you use a newer version of `go` - but please keep in mind that the product has been validated with 1.11.4 and newer versions of `go` may introduce compatibility issues. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.11.4.linux-amd64.tar.gz
tar -xzf go1.11.4.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build Secure Docker Daemon

- Git clone the Secure Docker Daemon
- Run scripts to build the Secure Docker Daemon

```shell
cd secure-docker-daemon
make
```

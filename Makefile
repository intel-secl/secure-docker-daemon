VERSION := v1.0
GITCOMMIT := $(shell git describe --always)
GITBRANCH := $(shell git rev-parse --abbrev-ref HEAD)
TIMESTAMP := $(shell date --iso=seconds)
DOCKER_CE_CLI := docker-ce/components/cli
DOCKER_CE_ENGINE := docker-ce/components/engine
DOCKER_BUILD := out

.PHONY: all clean

installer:
	mkdir -p out
	chmod +x build-secure-docker-dameon.sh
	./build-secure-docker-dameon.sh
	cp -f $(DOCKER_CE_CLI)/build/docker-linux-amd64 $(DOCKER_BUILD)/docker
	cp -f $(DOCKER_CE_ENGINE)/bundles/17.06.2-ce/binary-daemon/dockerd $(DOCKER_BUILD)/
	cp -f $(DOCKER_CE_ENGINE)/bundles/17.06.2-ce/binary-daemon/docker-init $(DOCKER_BUILD)/
	cp -f $(DOCKER_CE_ENGINE)/bundles/17.06.2-ce/binary-daemon/docker-proxy $(DOCKER_BUILD)/
	cp -f $(DOCKER_CE_ENGINE)/bundles/17.06.2-ce/binary-daemon/docker-runc $(DOCKER_BUILD)/
	cp -f $(DOCKER_CE_ENGINE)/bundles/17.06.2-ce/binary-daemon/docker-containerd $(DOCKER_BUILD)/
	cp -f $(DOCKER_CE_ENGINE)/bundles/17.06.2-ce/binary-daemon/docker-containerd-shim $(DOCKER_BUILD)/
	cp -f $(DOCKER_CE_ENGINE)/bundles/17.06.2-ce/binary-daemon/docker-containerd-ctr $(DOCKER_BUILD)/

all: installer

clean:
	rm -rf out/
	rm -rf docker-ce/

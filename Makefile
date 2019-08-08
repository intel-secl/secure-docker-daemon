VERSION := v1.0
GITCOMMIT := $(shell git describe --always)
GITBRANCH := $(shell git rev-parse --abbrev-ref HEAD)
TIMESTAMP := $(shell date --iso=seconds)
DOCKER_CE_CLI := docker-ce/components/cli
DOCKER_CE_ENGINE := docker-ce/components/engine
DOCKER_BUILD := out

.PHONY: all clean

installer: clean
	mkdir -p out
	chmod +x build-secure-docker-dameon.sh
	./build-secure-docker-dameon.sh
	cp -f $(DOCKER_CE_CLI)/build/docker-linux-amd64 $(DOCKER_BUILD)/docker
	cp -f $(DOCKER_CE_ENGINE)/bundles/binary-daemon/dockerd-dev $(DOCKER_BUILD)/dockerd-ce

all: installer

clean:
	rm -rf out/
	sudo rm -rf docker-ce/

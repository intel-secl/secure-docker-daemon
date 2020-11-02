VERSION := 19.03.13
GITCOMMIT := $(shell git describe --always)
GITBRANCH := $(shell git rev-parse --abbrev-ref HEAD)
TIMESTAMP := $(shell date --iso=seconds)
DOCKER_CE_CLI := docker-ce/components/cli
DOCKER_CE_ENGINE := docker-ce/components/engine
DOCKER_BUILD := out

.PHONY: all

installer:
	mkdir -p out
	chmod +x build-secure-docker-dameon.sh
	./build-secure-docker-dameon.sh
	cp -f $(DOCKER_CE_CLI)/build/docker-linux-amd64 $(DOCKER_BUILD)/docker
	cp -f $(DOCKER_CE_ENGINE)/bundles/binary-daemon/dockerd-${VERSION} $(DOCKER_BUILD)/dockerd-ce

unittest:
	 DOCKER_EXPERIMENTAL="0" DOCKER_STORAGE_OPTS="overlay2.override_kernel_check=1" DOCKERDEBUG="y" DOCKER_GRAPHDRIVER="secureoverlay2" make -C ${DOCKER_CE_ENGINE} test-unit

all: clean installer

.PHONY: testintegrationengine
testintegrationengine:
	 DOCKER_EXPERIMENTAL="0" DOCKER_STORAGE_OPTS="overlay2.override_kernel_check=1" DOCKER_GRAPHDRIVER="secureoverlay2" TESTFLAGS='-test.run TestBuild' make -C ${DOCKER_CE_ENGINE} test-integration && \
	 DOCKER_EXPERIMENTAL="0" DOCKER_STORAGE_OPTS="overlay2.override_kernel_check=1" DOCKER_GRAPHDRIVER="secureoverlay2" TESTFLAGS='-test.run TestRun' make -C ${DOCKER_CE_ENGINE} test-integration && \
	 DOCKER_EXPERIMENTAL="0" DOCKER_STORAGE_OPTS="overlay2.override_kernel_check=1" DOCKER_GRAPHDRIVER="secureoverlay2" TESTFLAGS='-test.run TestSecureOverlay' make -C ${DOCKER_CE_ENGINE} test-integration

.PHONY: clean
clean:
	sudo rm -rf out/ docker-ce/

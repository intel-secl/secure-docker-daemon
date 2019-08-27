VERSION := 19.03.0
GITCOMMIT := $(shell git describe --always)
GITBRANCH := $(shell git rev-parse --abbrev-ref HEAD)
DOCKER_CE_CLI := docker-ce/components/cli
DOCKER_CE_ENGINE := docker-ce/components/engine
DOCKER_BUILD := out

.PHONY: all

.PHONY: build
build:
	mkdir -p out
	chmod +x build-secure-docker-dameon.sh
	./build-secure-docker-dameon.sh
	cp -f $(DOCKER_CE_CLI)/build/docker-linux-amd64 $(DOCKER_BUILD)/docker
	cp -f $(DOCKER_CE_ENGINE)/bundles/binary-daemon/dockerd-${VERSION} $(DOCKER_BUILD)/dockerd

.PHONY: testcli
testcli:
	make -C ${DOCKER_CE_CLI} -f docker.Makefile test

.PHONY: testunitengine
testunitengine:
	make -C ${DOCKER_CE_ENGINE} test-unit

.PHONY: testintegrationengine
testintegrationengine:
	DOCKER_GRAPHDRIVER="secureoverlay2" TESTFLAGS='-test.run TestBuild' make -C ${DOCKER_CE_ENGINE} test-integration && \
	DOCKER_GRAPHDRIVER="secureoverlay2" TESTFLAGS='-test.run TestRun' make -C ${DOCKER_CE_ENGINE} test-integration && \
	DOCKER_GRAPHDRIVER="secureoverlay2" TESTFLAGS='-test.run TestSecureOverlay' make -C ${DOCKER_CE_ENGINE} test-integration

.PHONY: clean
clean:
	if [ -d "${DOCKER_CE_CLI}" ]; then  DISABLE_WARN_OUTSIDE_CONTAINER=1 make -C ${DOCKER_CE_CLI} clean; fi; if  [ -d "${DOCKER_CE_ENGINE}" ]; then make -C ${DOCKER_CE_ENGINE} clean; fi;  sudo rm -rf ${DOCKER_BUILD} docker-ce/

all: clean build testcli testunitengine testintegrationengine

